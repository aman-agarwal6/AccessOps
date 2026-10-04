"""Server-local explicit enrollment; there is deliberately no browser equivalent."""

import uuid

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction

from core import audit
from core.models import ADEnrollment, OffboardingCase, Principal
from core.services import policy_state
from integrations.ad import ADDirectoryConnector, normalize_binding
from integrations.errors import ConnectorError


class Command(BaseCommand):
    help = "Enroll one exact workforce human and scoped lab directory GUID mapping."

    def add_arguments(self, parser):
        parser.add_argument("--identity-id", required=True, type=uuid.UUID)
        parser.add_argument("--domain-guid", required=True)
        parser.add_argument("--user-guid", required=True)
        parser.add_argument("--group-guid", required=True, action="append")

    def handle(self, *args, **options):
        try:
            binding = normalize_binding(
                {
                    "domainGuid": options["domain_guid"],
                    "userGuid": options["user_guid"],
                    "groupGuids": options["group_guid"],
                }
            )
            connector = ADDirectoryConnector()
            try:
                observed = connector.validate_binding(binding)
            finally:
                connector.close()
            if observed["active"] is not True:
                raise CommandError("Enrollment requires an active scoped directory fixture.")
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
                ADEnrollment.objects.create(
                    identity=identity,
                    domain_guid=binding["domainGuid"],
                    user_guid=binding["userGuid"],
                    group_guids=binding["groupGuids"],
                )
                audit.append(
                    "management",
                    "directory.enrolled",
                    identity.pk,
                    {"provider": "samba_ad", "binding": binding},
                )
        except (ConnectorError, Principal.DoesNotExist, ValueError, IntegrityError):
            raise CommandError("Directory enrollment rejected; no binding was changed.") from None
        self.stdout.write(
            "Exact scoped directory enrollment recorded; no directory mutation performed."
        )
