import time

from django.core.management.base import BaseCommand

from core.assurance import watch_departures
from core.intake import contain_due_departures
from core.worker import process_one


class Command(BaseCommand):
    help = "Process durable jobs; no provider changes without previously authorized local intent."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")

    def handle(self, *args, **options):
        while True:
            # Effective HR-intake departures are contained before provider jobs run.
            contain_due_departures()
            worked = process_one()
            # Departed accounts are read for sign-ins after departure.
            watch_departures()
            if options["once"]:
                return
            if not worked:
                time.sleep(2)
