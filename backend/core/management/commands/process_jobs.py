import time

from django.core.management.base import BaseCommand

from core.worker import process_one


class Command(BaseCommand):
    help = "Process durable jobs; no provider changes without previously authorized local intent."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")

    def handle(self, *args, **options):
        while True:
            worked = process_one()
            if options["once"]:
                return
            if not worked:
                time.sleep(2)
