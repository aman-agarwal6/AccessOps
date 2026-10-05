"""Automated leaver intake: a signed HR event opens the departure case and, once
the departure is effective, contains access without waiting for a person.

Requests are signed per Standard Webhooks: HMAC-SHA256 over
"<webhook-id>.<webhook-timestamp>.<body>" with the shared secret, sent as
"v1,<base64>" in webhook-signature. The feed acts as its own service principal,
so every effect is attributed to it and authorized by the same policy gate as
an operator's. It can open and contain a departure only; owner statements and
independent closure stay with people. The webhook ID is the idempotency key, so
a redelivered event returns the original result.
"""

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from . import audit, rate_limit
from . import services as svc
from .errors import DomainError
from .models import ADEnrollment, AuditEvent, EntraEnrollment, OffboardingCase, Principal
from .offboarding import UTCField, contain, json_value
from .serializers import StrictSerializer, validate

SOURCE_LABEL = "HR feed (signed webhook)"
TOLERANCE_SECONDS = 300
MAX_BODY = 16384


class HREventInput(StrictSerializer):
    type = serializers.ChoiceField(choices=["worker.departed"])
    eventId = serializers.RegexField(r"^[A-Za-z0-9._:-]{8,64}$")
    workerId = serializers.UUIDField()
    employmentType = serializers.ChoiceField(choices=["employee", "contractor"])
    effectiveAt = UTCField()
    reason = serializers.CharField(min_length=8, max_length=255)

    def validate(self, data):
        if abs((data["effectiveAt"] - timezone.now()).total_seconds()) > 366 * 86400:
            raise serializers.ValidationError("Departure date must be within a year.")
        return data


def rejected():
    # One answer for every authentication failure; the cause is not disclosed.
    return DomainError("signature_invalid", "The event signature was not accepted.", 401)


def verify_signature(headers, body, secret, now):
    """Return the webhook ID of a correctly signed, fresh request or raise."""
    message_id = headers.get("webhook-id", "")
    stamp = headers.get("webhook-timestamp", "")
    signatures = headers.get("webhook-signature", "")
    if (
        not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", message_id)
        or not re.fullmatch(r"[0-9]{1,12}", stamp)
        or not 1 <= len(signatures) <= 1024
    ):
        raise rejected()
    if abs(now - int(stamp)) > TOLERANCE_SECONDS:
        raise rejected()
    try:
        key = base64.b64decode(secret.removeprefix("whsec_"), validate=True)
    except (binascii.Error, ValueError):
        raise DomainError("intake_not_configured", "HR intake is not configured.", 503) from None
    expected = base64.b64encode(
        hmac.new(key, f"{message_id}.{stamp}.".encode() + body, hashlib.sha256).digest()
    ).decode()
    candidates = [part[3:] for part in signatures.split(" ")[:5] if part.startswith("v1,")]
    if not any(hmac.compare_digest(expected, value) for value in candidates):
        raise rejected()
    return message_id


def outcome(case):
    """Minimal answer for the HR system: no access details leave AccessOps."""
    return {
        "caseId": str(case.pk),
        "state": "contained" if case.containment_request_id else "scheduled",
        "effectiveAt": case.effective_at.isoformat(),
    }


def owner_for(source, identity):
    owner = source.sponsor
    try:
        if not owner or owner.kind != "human" or "operator" not in owner.roles:
            raise DomainError("owner", "", 409)
        svc.active(owner)
        svc.scope_offboarding(owner, identity)
    except DomainError:
        raise DomainError(
            "intake_owner_unavailable",
            "The HR feed has no active operator in scope to own this departure.",
            409,
        ) from None
    if identity.pk == owner.workforce_identity_id:
        raise DomainError(
            "independent_owner_required",
            "The feed's owner is the departing person; open this departure manually.",
            409,
        )
    return owner


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def receive(request):
    secret = settings.HR_WEBHOOK_SECRET
    if len(secret) < 40:
        raise DomainError("intake_not_configured", "HR intake is not configured.", 503)
    if not rate_limit.allowed(request, "hr-intake", limit=60):
        raise DomainError("rate_limited", "Too many HR events. Retry later.", 429)
    body = request.body
    if len(body) > MAX_BODY:
        raise DomainError("payload_too_large", "HR events are limited to 16 KB.", 413)
    message_id = verify_signature(request.headers, body, secret, time.time())
    try:
        data = validate(HREventInput, json.loads(body))
    except (ValueError, UnicodeDecodeError):
        raise DomainError("invalid_json", "The event body must be a JSON object.", 400) from None
    source = Principal.objects.filter(
        issuer=settings.HR_INTAKE_ISSUER, subject=settings.HR_INTAKE_SOURCE, kind="service"
    ).first()
    if source is None:
        raise DomainError("intake_not_configured", "HR intake is not configured.", 503)
    identity = Principal.objects.filter(
        pk=data["workerId"], issuer=settings.WORKFORCE_ISSUER, kind="human"
    ).first()
    if identity is None:
        raise DomainError("worker_unknown", "No enrolled workforce person has this ID.", 404)

    def check(feed):
        projects = svc.scope_offboarding(feed, Principal.objects.get(pk=identity.pk))
        svc.require_policy(
            feed, "departure_intake", context={"identity_project_ids": sorted(projects)}
        )

    def handle(feed):
        existing = OffboardingCase.objects.filter(
            hr_source=SOURCE_LABEL, hr_event_id=data["eventId"]
        ).first()
        if existing:
            if (
                existing.identity_id != identity.pk
                or existing.effective_at != data["effectiveAt"]
                or existing.employment_type != data["employmentType"]
            ):
                raise DomainError(
                    "event_conflict", "This HR event ID was already used for another change.", 409
                )
            return {"result": outcome(existing)}, 200
        if OffboardingCase.objects.filter(identity=identity, closed_at__isnull=True).exists():
            raise DomainError(
                "departure_open", "An open departure case already covers this person.", 409
            )
        enrollment = ADEnrollment.objects.filter(identity_id=identity.pk).first()
        entra = EntraEnrollment.objects.filter(identity_id=identity.pk).first()
        case = OffboardingCase.objects.create(
            identity=identity,
            owner=owner_for(feed, identity),
            intake_source=feed,
            employment_type=data["employmentType"],
            hr_event_id=data["eventId"],
            hr_source=SOURCE_LABEL,
            effective_at=data["effectiveAt"],
            due_at=data["effectiveAt"] + timedelta(hours=4),
            reason=data["reason"],
            bindings=[],
            ad_binding=enrollment.binding if enrollment else {},
            entra_binding=entra.binding if entra else {},
        )
        audit.append(
            feed,
            "departure.intake",
            case.pk,
            {
                "identityId": str(identity.pk),
                "hrEventId": case.hr_event_id,
                "webhookId": message_id,
            },
        )
        if case.effective_at <= timezone.now():
            contain_now(feed, case)
        return {"result": outcome(case)}, 201

    result, status = svc.mutation(
        source, message_id, "departure.intake", json_value(data), check, handle
    )
    return Response(result, status=status)


def contain_now(feed, case):
    contain(feed, case)
    case.revision += 1
    case.save()
    audit.append(
        feed, "departure.contained", case.pk, {"automatic": True, "hrEventId": case.hr_event_id}
    )


def contain_due_departures(limit=20):
    """Contain intake departures that have become effective, as their HR feed.

    A refused containment is recorded once and retried after ten minutes; the
    case meanwhile shows "Contain local access" to its human owner.
    """
    now = timezone.now()
    due = list(
        OffboardingCase.objects.filter(
            intake_source__isnull=False,
            containment_request__isnull=True,
            closed_at__isnull=True,
            effective_at__lte=now,
        )
        .order_by("effective_at")
        .values_list("pk", flat=True)[:limit]
    )
    contained = 0
    for case_id in due:
        if AuditEvent.objects.filter(
            target_id=str(case_id),
            action="departure.auto_contain_failed",
            at__gt=now - timedelta(minutes=10),
        ).exists():
            continue
        try:
            with transaction.atomic():
                svc.policy_state(lock=True)
                case = OffboardingCase.objects.select_for_update().get(pk=case_id)
                if case.containment_request_id or case.closed_at:
                    continue
                feed = Principal.objects.select_for_update().get(pk=case.intake_source_id)
                svc.active(feed)
                svc.scope_offboarding(feed, case.identity)
                contain_now(feed, case)
                contained += 1
        except DomainError as error:
            with transaction.atomic():
                svc.policy_state(lock=True)
                audit.append(
                    "worker", "departure.auto_contain_failed", case_id, {"reason": error.code}
                )
    return contained
