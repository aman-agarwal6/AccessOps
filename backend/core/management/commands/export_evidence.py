import json

from django.core.management.base import BaseCommand, CommandError

from core.models import EvidenceRun
from core.presentation import run


class Command(BaseCommand):
    help = "Export a stored real run; never create synthetic passing evidence."

    def add_arguments(self, parser):
        parser.add_argument("run_id")

    def handle(self, *args, **options):
        try:
            evidence = EvidenceRun.objects.get(pk=options["run_id"])
        except (EvidenceRun.DoesNotExist, ValueError):
            raise CommandError("An existing run UUID is required.") from None
        if evidence.status == "pending":
            raise CommandError("The run has not completed.")
        self.stdout.write(json.dumps(run(evidence), indent=2))
