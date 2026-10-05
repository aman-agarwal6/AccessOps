"""Shared Signals transmitter: signed leaver signals for the SOC.

Containment and any sign-in after departure become Security Event Tokens
(RFC 8417, typ secevent+jwt, ES256) with an SSF iss_sub subject in sub_id:
RISC account-disabled and CAEP session-revoked when containment is verified, and
CAEP session-established for each sign-in observed after departure. A receiver
collects them by polling (RFC 8936) with its bearer token and acknowledges what
it processed; anything unacknowledged is offered again. Tokens carry the
account's issuer and subject only: no names, emails or IP addresses.
"""

import base64
import hashlib
import hmac
import json
import time
import uuid
from functools import lru_cache
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from . import audit, rate_limit
from .errors import DomainError
from .models import SecurityEvent
from .serializers import StrictSerializer, validate
from .services import policy_state

RISC = "https://schemas.openid.net/secevent/risc/event-type/"
CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
EVENT_TYPES = {
    "account-disabled": RISC + "account-disabled",
    "session-revoked": CAEP + "session-revoked",
    "session-established": CAEP + "session-established",
}
POLL = "urn:ietf:rfc:8936"


@lru_cache(maxsize=1)
def signing_key():
    """(private key, public JWK) or None when no key is configured."""
    path = Path(settings.SSF_SIGNING_KEY_FILE)
    if not path.is_file():
        return None
    private = serialization.load_pem_private_key(path.read_bytes(), password=None)
    public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private.public_key()))
    material = json.dumps(
        {k: public[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True
    )
    kid = base64.urlsafe_b64encode(hashlib.sha256(material.encode()).digest()).rstrip(b"=")
    public.update(kid=kid.decode(), use="sig", alg="ES256")
    return private, public


def emit(kind, subject, source_ref, *, case=None, at=None, details=None):
    """Queue one signed event; the same source_ref never produces a second one."""
    key = signing_key()
    if key is None or SecurityEvent.objects.filter(source_ref=source_ref).exists():
        return None
    jti = uuid.uuid4().hex
    claims = {
        "iss": settings.SSF_ISSUER,
        "jti": jti,
        "iat": int(time.time()),
        "aud": settings.SSF_AUDIENCE,
        "txn": hashlib.sha256(source_ref.encode()).hexdigest()[:32],
        "sub_id": {"format": "iss_sub", "iss": settings.WORKFORCE_ISSUER, "sub": subject},
        "events": {
            EVENT_TYPES[kind]: {
                "event_timestamp": int((at or timezone.now()).timestamp()),
                **(details or {}),
            }
        },
    }
    token = jwt.encode(
        claims,
        key[0],
        algorithm="ES256",
        headers={"typ": "secevent+jwt", "kid": key[1]["kid"]},
    )
    event = SecurityEvent.objects.create(
        jti=jti,
        source_ref=source_ref,
        event_type=kind,
        subject=subject,
        case=case,
        token=token,
    )
    audit.append("worker", "ssf.queued", jti, {"eventType": kind, "sourceRef": source_ref})
    return event


def signal_containment(job, subject):
    """A verified containment: the account is disabled and its sessions ended."""
    from .models import OffboardingCase

    case = OffboardingCase.objects.filter(containment_request_id=job.request_id).first()
    for kind, details in (
        ("account-disabled", {}),
        (
            "session-revoked",
            {"initiating_entity": "policy", "reason_admin": {"en": "Departure containment"}},
        ),
    ):
        emit(kind, subject, f"containment:{job.pk}:{kind}", case=case, details=details)


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def jwks(request):
    key = signing_key()
    return Response({"keys": [key[1]] if key else []})


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def configuration(request):
    return Response(
        {
            "spec_version": "1_0",
            "issuer": settings.SSF_ISSUER,
            "jwks_uri": settings.SSF_ISSUER + "/api/v1/ssf/jwks",
            "delivery_methods_supported": [POLL],
            "authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6750"}],
        }
    )


class SetError(StrictSerializer):
    err = serializers.RegexField(r"^[a-z_]{1,40}$")
    description = serializers.CharField(max_length=200, required=False)


class PollInput(StrictSerializer):
    maxEvents = serializers.IntegerField(min_value=0, max_value=50, default=10)
    returnImmediately = serializers.BooleanField(default=True)
    ack = serializers.ListField(
        child=serializers.RegexField(r"^[a-f0-9]{32}$"), max_length=100, default=list
    )
    setErrs = serializers.DictField(child=SetError(), default=dict)

    def validate(self, data):
        if len(data["setErrs"]) > 100 or any(
            not isinstance(jti, str) or len(jti) != 32 for jti in data["setErrs"]
        ):
            raise serializers.ValidationError("Report at most 100 SET errors by jti.")
        return data


def authorized(request):
    expected = settings.SSF_RECEIVER_TOKEN
    if len(expected) < 32:
        raise DomainError("ssf_not_configured", "Signal delivery is not configured.", 503)
    header = request.headers.get("Authorization", "")
    supplied = header[7:] if header.startswith("Bearer ") else ""
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise DomainError("receiver_unauthorized", "The receiver token was not accepted.", 401)


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def poll(request):
    """RFC 8936 poll: acknowledge processed SETs and fetch undelivered ones."""
    if not rate_limit.allowed(request, "ssf-poll", limit=120):
        raise DomainError("rate_limited", "Too many polls. Retry later.", 429)
    authorized(request)
    data = validate(PollInput, request.data)
    now = timezone.now()
    with transaction.atomic():
        policy_state(lock=True)
        acked = SecurityEvent.objects.filter(jti__in=data["ack"], delivered_at__isnull=True)
        acked_count = acked.update(delivered_at=now)
        for jti, error in data["setErrs"].items():
            SecurityEvent.objects.filter(jti=jti, delivered_at__isnull=True).update(
                delivered_at=now, receiver_error=error["err"]
            )
        if acked_count or data["setErrs"]:
            audit.append(
                "ssf-receiver",
                "ssf.acknowledged",
                "ssf",
                {"acknowledged": acked_count, "errors": sorted(data["setErrs"])},
            )
        pending = list(
            SecurityEvent.objects.filter(delivered_at__isnull=True).order_by("created_at")[
                : data["maxEvents"] + 1
            ]
        )
    offered = pending[: data["maxEvents"]]
    return Response(
        {
            "sets": {event.jti: event.token for event in offered},
            "moreAvailable": len(pending) > len(offered),
        }
    )
