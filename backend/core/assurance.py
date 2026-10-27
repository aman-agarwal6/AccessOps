"""Leaver assurance: watch a departed account's Keycloak sign-ins after departure.

After containment the worker reads the account's sign-in and token events since
the effective time and keeps every reading. A successful sign-in after departure
adds a required "Investigate sign-in after departure" task to the case and sends
the SOC a CAEP session-established event; refused attempts are only counted.
Keycloak keeps events for one day in this lab, so the watch covers that day,
closed cases included, and closure waits until it is current. After closure a
sign-in is still signalled and shown on the case; the closed packet never changes.
"""

import logging
from datetime import UTC, datetime, timedelta
from functools import cache

from django.conf import settings
from django.db import transaction
from django.db.models import Exists, F, OuterRef
from django.utils import timezone

from . import audit, ssf
from .models import ActivityCheck, OffboardingCase
from .services import policy_state

logger = logging.getLogger(__name__)
WINDOW = timedelta(hours=24)
INTERVAL = timedelta(seconds=30)
# Closure needs a successful reading at least this recent during the window.
FRESH = timedelta(seconds=90)
# After the window, the final reading is retried for this long; then it is missed.
GRACE = timedelta(hours=24)
POST_DEPARTURE_TASK = (
    "post-departure-access",
    "keycloak",
    "sessions",
    "Investigate sign-in after departure",
)
# Fixed text: a blocker changes only when the watch's state does, not per reading.
BLOCKERS = {
    "not_configured": (
        "Sign-ins after departure can't be checked: the read-only Keycloak events client"
        " isn't configured."
    ),
    "pending": "Waiting for the first sign-in check after departure.",
    "unavailable": (
        "The latest sign-in check after departure failed; closure waits for a successful one."
    ),
    "stale": "No successful sign-in check in the last 90 seconds; closure waits for a current one.",
    "finishing": "Waiting for the final sign-in check covering the full day after departure.",
}
MISSED = "The sign-in watch never completed a reading covering the full day after departure."


def watch_configured():
    return len(settings.EVENTS_CLIENT_SECRET) >= 32


@cache
def warn_unconfigured():
    # Once per process; every contained case also shows it as a closure blocker.
    logger.warning("Sign-in watch is off: the read-only Keycloak events client is not configured.")


def due_cases(now, limit):
    """Contained cases, open or closed, that need a reading: every INTERVAL during
    the window, then until one reading at or after its end, for at most GRACE."""
    final = ActivityCheck.objects.filter(
        case=OuterRef("pk"),
        status="observed",
        checked_at__gte=OuterRef("effective_at") + WINDOW,
    )
    cases = (
        OffboardingCase.objects.filter(
            containment_request__isnull=False,
            effective_at__lte=now,
            effective_at__gt=now - WINDOW - GRACE,
        )
        .exclude(Exists(final))
        .select_related("identity")
    )
    due = []
    # Open cases first, so closed ones never delay a pending closure.
    for case in cases.order_by(F("closed_at").asc(nulls_first=True), "effective_at")[:200]:
        latest = case.activity_checks.order_by("-checked_at").first()
        if latest is None or latest.checked_at <= now - INTERVAL:
            due.append(case)
        if len(due) == limit:
            break
    return due


def watch_departures(reader=None, limit=10):
    """Read each due case once. Returns the number of readings recorded."""
    if reader is None:
        if not watch_configured():
            warn_unconfigured()
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
            closed_at = OffboardingCase.objects.values_list("closed_at", flat=True).get(pk=case.pk)
            if closed_at and closed_at >= read_at:
                # The case closed while this reading was in flight, so its reviewer
                # never saw it. Drop it: the next one reads the same events.
                continue
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
                    "departure.access_after_closure"
                    if closed_at
                    else "departure.access_after_departure",
                    case.pk,
                    {"count": len(new), "firstAt": min(item["time"] for item in new)},
                )
        recorded += 1
    return recorded


def successes_read(case):
    """Every distinct successful sign-in or token use ever read after departure,
    with the time of the first reading that saw it."""
    seen = []
    for checked_at, successes in (
        case.activity_checks.filter(status="observed")
        .exclude(successes=[])
        .order_by("checked_at")
        .values_list("checked_at", "successes")
    ):
        for item in successes:
            if all(item != known for known, _ in seen):
                seen.append((item, checked_at))
    return seen


def post_departure_successes(case):
    return [item for item, _ in successes_read(case)]


def latest_reading(case):
    return case.activity_checks.filter(status="observed").order_by("-checked_at").first()


def watch_state(case, now, read=None):
    """The watch's live state. Its times change with every reading, so the case
    keeps it outside the packet hash, which takes only findings and fixed text."""
    read = successes_read(case) if read is None else read
    end = case.effective_at + WINDOW
    last = latest_reading(case)
    attempt = case.activity_checks.order_by("-checked_at").first()
    # Fail closed on a tie: a failed attempt at the last good reading's time wins.
    failed = attempt is not None and (
        last is None
        or case.activity_checks.exclude(status="observed")
        .filter(checked_at__gte=last.checked_at)
        .exists()
    )
    if not case.containment_request_id or case.effective_at > now:
        status = "not_started"
    elif last and last.checked_at >= end:
        status = "complete"
    elif now >= end + GRACE:
        # Not a blocker, or a late containment could never close; the case says so.
        status = "missed"
    elif not watch_configured():
        status = "not_configured"
    elif attempt is None:
        status = "pending"
    elif failed:
        status = "unavailable"
    elif now < end:
        status = "stale" if now - last.checked_at > FRESH else "watching"
    else:
        status = "finishing"
    return {
        "status": status,
        "windowEndsAt": end.isoformat(),
        "lastReadAt": last.checked_at.isoformat() if last else None,
        "lastAttemptAt": attempt.checked_at.isoformat() if attempt else None,
        "refused": last.refused if last else None,
        "successes": len(read),
        "afterClosure": sum(
            1 for _, at in read if case.closed_at is not None and at > case.closed_at
        ),
    }
