"""Leaver assurance: watch a departed account's Keycloak sign-ins after departure.

After containment the worker reads the account's sign-in and token events since
the effective time and keeps every reading. A successful sign-in after departure
adds a required "Investigate sign-in after departure" task to the case and sends
the SOC a CAEP session-established event; refused attempts are only counted.
Keycloak keeps events for one day in this lab, so the watch stops after that.
"""

from datetime import UTC, datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from . import audit, ssf
from .models import ActivityCheck, OffboardingCase
from .services import policy_state

WINDOW = timedelta(hours=24)
INTERVAL = timedelta(seconds=30)
POST_DEPARTURE_TASK = (
    "post-departure-access",
    "keycloak",
    "sessions",
    "Investigate sign-in after departure",
)


def due_cases(now, limit):
    cases = OffboardingCase.objects.filter(
        containment_request__isnull=False,
        closed_at__isnull=True,
        effective_at__lte=now,
        effective_at__gt=now - WINDOW,
    ).select_related("identity")
    due = []
    for case in cases.order_by("effective_at")[:200]:
        latest = case.activity_checks.order_by("-checked_at").first()
        if latest is None or latest.checked_at <= now - INTERVAL:
            due.append(case)
        if len(due) == limit:
            break
    return due


def watch_departures(reader=None, limit=10):
    """Read each due case once. Returns the number of readings recorded."""
    if reader is None:
        if len(settings.EVENTS_CLIENT_SECRET) < 32:
            return 0
        from integrations.keycloak import KeycloakConnector

        reader = KeycloakConnector.events_reader()
    from integrations.errors import ConnectorError
    from integrations.keycloak import SIGN_IN_REFUSED, SIGN_IN_SUCCESS

    recorded = 0
    for case in due_cases(timezone.now(), limit):
        read_at = timezone.now()
        try:
            events = reader.sign_in_events(
                case.identity.subject, int(case.effective_at.timestamp() * 1000)
            )
            status = "observed"
        except ConnectorError:
            events, status = [], "unavailable"
        successes = [
            {key: event[key] for key in ("time", "type", "clientId")}
            for event in events
            if event["type"] in SIGN_IN_SUCCESS
        ]
        with transaction.atomic():
            policy_state(lock=True)
            new = [item for item in successes if item not in post_departure_successes(case)]
            ActivityCheck.objects.create(
                case=case,
                checked_at=read_at,
                status=status,
                successes=successes,
                refused=sum(event["type"] in SIGN_IN_REFUSED for event in events),
            )
            for item in new:
                ssf.emit(
                    "session-established",
                    case.identity.subject,
                    f"activity:{case.pk}:{item['time']}:{item['type']}:{item['clientId']}",
                    case=case,
                    at=datetime.fromtimestamp(item["time"] / 1000, tz=UTC),
                )
            if new:
                audit.append(
                    "worker",
                    "departure.access_after_departure",
                    case.pk,
                    {"count": len(new), "firstAt": min(item["time"] for item in new)},
                )
        recorded += 1
    return recorded


def post_departure_successes(case):
    """Every distinct successful sign-in or token use ever read after departure."""
    seen = []
    for check in case.activity_checks.filter(status="observed").order_by("checked_at"):
        for item in check.successes:
            if item not in seen:
                seen.append(item)
    return seen


def latest_reading(case):
    return case.activity_checks.filter(status="observed").order_by("-checked_at").first()
