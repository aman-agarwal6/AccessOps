"""One bounded outbox batch at a time; durable retries remain in PostgreSQL."""

import signal
import subprocess
import sys
import time

running = True


def stop(*_args):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
while running:
    result = subprocess.run(
        [sys.executable, "/app/backend/manage.py", "process_jobs", "--once"], timeout=120
    )
    if result.returncode:
        print("Worker batch failed; durable jobs remain pending", file=sys.stderr)
    time.sleep(3)
