from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import F
from django.utils import timezone

from core import audit
from core.models import AssistantTask, Grant, OutboxJob, Principal, SessionBinding
from core.services import policy_state, revoke_for


class Command(BaseCommand):
    help = "Local-console containment only: freeze, revoke or disable. Never grants access."

    def add_arguments(self, parser):
        parser.add_argument("action", choices=["freeze", "revoke", "disable"])
        parser.add_argument("--target", help="Identity UUID, required for revoke/disable")
        parser.add_argument("--incident", required=True)
        parser.add_argument("--reason", required=True)

    @transaction.atomic
    def handle(self, *args, **options):
        if not 3 <= len(options["incident"]) <= 80 or not 8 <= len(options["reason"]) <= 255:
            raise CommandError("Supply a bounded incident reference and meaningful reason.")
        state = policy_state(lock=True)
        action = options["action"]
        target = "all"
        if action == "freeze":
            state.frozen = True
            state.save(update_fields=["frozen"])
            AssistantTask.objects.filter(status="active").update(status="revoked")
        else:
            try:
                identity = Principal.objects.select_for_update().get(pk=options["target"])
            except (Principal.DoesNotExist, ValueError, TypeError):
                raise CommandError("An existing identity UUID is required.") from None
            target = str(identity.pk)
            ids = [
                identity.pk,
                *Principal.objects.filter(sponsor=identity).values_list("pk", flat=True),
            ]
            revoke_for(ids)
            SessionBinding.objects.filter(principal_id__in=ids).update(revoked=True)
            if action == "disable":
                Principal.objects.filter(pk__in=ids).update(
                    status="suspended", revision=F("revision") + 1
                )
                for identity_id in ids:
                    OutboxJob.objects.create(
                        kind="suspend",
                        desired={"identityId": str(identity_id), "active": False},
                        available_at=timezone.now(),
                    )
            else:
                for grant in Grant.objects.filter(identity_id__in=ids, status="revoked"):
                    OutboxJob.objects.create(
                        kind="revoke",
                        desired={
                            "identityId": str(grant.identity_id),
                            "resourceId": str(grant.resource_id),
                            "action": "revoke",
                        },
                        available_at=timezone.now(),
                    )
        # Any audit failure rolls back every local containment change.
        audit.append(
            "local-console",
            "containment." + action,
            target,
            {"incident": options["incident"], "reason": options["reason"]},
        )
        self.stdout.write(
            "Containment committed; remote provider changes remain queued for verification."
        )
