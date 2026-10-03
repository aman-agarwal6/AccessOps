import hashlib
import json

from django.db import transaction
from django.utils import timezone

from .models import AuditEvent, AuditHead


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


@transaction.atomic
def append(actor, action, target, detail=None):
    head, _ = AuditHead.objects.get_or_create(pk=1)
    head = AuditHead.objects.select_for_update().get(pk=1)
    at = timezone.now()
    data = {
        "sequence": head.sequence + 1,
        "at": at.isoformat(),
        "actor_id": str(getattr(actor, "pk", actor)),
        "action": action,
        "target_id": str(target),
        "detail": detail or {},
        "previous_hash": head.last_hash,
    }
    event = AuditEvent.objects.create(**data, hash=digest(data))
    head.sequence = event.sequence
    head.last_hash = event.hash
    head.save(update_fields=["sequence", "last_hash"])
    return event


def verify_chain():
    previous = "0" * 64
    sequence = 0
    for event in AuditEvent.objects.order_by("sequence").iterator():
        data = {
            "sequence": event.sequence,
            "at": event.at.isoformat(),
            "actor_id": event.actor_id,
            "action": event.action,
            "target_id": event.target_id,
            "detail": event.detail,
            "previous_hash": event.previous_hash,
        }
        if (
            event.sequence != sequence + 1
            or event.previous_hash != previous
            or event.hash != digest(data)
        ):
            return False
        previous, sequence = event.hash, event.sequence
    head = AuditHead.objects.filter(pk=1).first()
    return (
        head is None
        and sequence == 0
        or bool(head and head.last_hash == previous and head.sequence == sequence)
    )
