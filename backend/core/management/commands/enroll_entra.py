"""Server-local explicit Entra enrollment; there is deliberately no browser equivalent."""

import uuid

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction

from core import audit
from core.models import EntraEnrollment, OffboardingCase, Principal
from core.services import policy_state
from integrations.entra import EntraConnector, normalize_binding
from integrations.errors import ConnectorError


class Command(BaseCommand):
    help = "Enroll one exact workforce human and its Entra test user and group, by object ID."

    def add_arguments(self, parser):
        parser.add_argument("--identity-id", required=True, type=uuid.UUID)
        parser.add_argument("--user-id", required=True)
        parser.add_argument("--group-id", required=True, action="append")

    def handle(self, *args, **options):
        connector = None
        try:
            connector = EntraConnector()
            binding = normalize_binding(
                {
                    "tenantId": connector.config["tenantId"],
                    "userId": options["user_id"],
                    "groupIds": options["group_id"],
                }
            )
            # Read-only: scope, tenant, directory roles and current state.
            observed = connector.validate_binding(binding)
            if observed["active"] is not True or not all(g["member"] for g in observed["groups"]):
                raise CommandError(
                    "Enrollment requires an enabled Entra test user in every mapped group."
                )
            with transaction.atomic():
                policy_state(lock=True)
                identity = Principal.objects.select_for_update().get(pk=options["identity_id"])
                if (
                    identity.kind != "human"
                    or identity.issuer != settings.WORKFORCE_ISSUER
                    or identity.status != "active"
                    or identity.subject.startswith("pending:")
                    or identity.roles
                    or OffboardingCase.objects.filter(identity=identity).exists()
                ):
                    raise CommandError(
                        "Enrollment requires an active bound workforce human without a case."
                    )
                earlier = EntraEnrollment.objects.filter(
                    tenant_id=binding["tenantId"], user_id=binding["userId"]
                ).select_related("identity")
                if any(item.identity.status != "offboarded" for item in earlier):
                    raise CommandError("Another active identity is enrolled to this Entra user.")
                EntraEnrollment.objects.create(
                    identity=identity,
                    tenant_id=binding["tenantId"],
                    user_id=binding["userId"],
                    group_ids=binding["groupIds"],
                )
                audit.append(
                    "management",
                    "directory.enrolled",
                    identity.pk,
                    {"provider": "entra", "binding": binding},
                )
        except (ConnectorError, Principal.DoesNotExist, ValueError, IntegrityError):
            raise CommandError("Entra enrollment rejected; no binding was changed.") from None
        finally:
            if connector is not None:
                connector.close()
        self.stdout.write("Exact Entra enrollment recorded; no Entra change was made.")
