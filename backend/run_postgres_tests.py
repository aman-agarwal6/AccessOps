"""Create and remove only a labeled, disposable PostgreSQL test environment.

No host ports, production database credentials, shared database volumes or lab
containers are used. Docker must already be running. Run from any directory.
"""

import json
import secrets
import shutil
import subprocess
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POSTGRES = (
    "postgres:17-bookworm@sha256:91eb910c44c7ed13f7f1a4ccadaa9ca72ef14cddc04cacb6e070e48eb44731a3"
)
LABEL = "io.accessops.disposable-test"


def docker(*args, capture=False, check=True):
    return subprocess.run(
        ["docker", *args],
        cwd=ROOT,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def owned(kind, name, run_id):
    result = docker(kind, "inspect", name, capture=True, check=False)
    if result.returncode:
        return False
    document = json.loads(result.stdout)[0]
    labels = (
        document.get("Labels", {})
        if kind == "network"
        else document.get("Config", {}).get("Labels", {})
    )
    return labels.get(LABEL) == run_id


def main():
    run_id = uuid.uuid4().hex
    network = "accessops-test-" + run_id
    database = network + "-db"
    runner = network + "-runner"
    secret_dir = ROOT / ".local" / "backend-tests" / run_id
    secret_dir.mkdir(parents=True, exist_ok=False)
    output = ROOT / "output"
    report_dir = output / "postgresql" / run_id
    report_dir.mkdir(parents=True, exist_ok=False)
    password = secrets.token_urlsafe(40)
    db_env, test_env = secret_dir / "database.env", secret_dir / "runner.env"
    db_env.write_text(
        "POSTGRES_USER=accessops_test\nPOSTGRES_DB=accessops_test\nPOSTGRES_PASSWORD="
        + password
        + "\n",
        encoding="utf-8",
    )
    test_env.write_text(
        "ACCESSOPS_TEST_DATABASE_URL=postgresql://accessops_test:"
        + password
        + "@"
        + database
        + ":5432/accessops_test\n",
        encoding="utf-8",
    )
    result = 1
    try:
        docker(
            "build",
            "--file",
            "backend/Dockerfile.tests",
            "--tag",
            "accessops-backend-tests:local",
            ".",
        )
        docker(
            "network",
            "create",
            "--internal",
            "--label",
            LABEL + "=" + run_id,
            network,
            capture=True,
        )
        docker(
            "run",
            "--detach",
            "--name",
            database,
            "--label",
            LABEL + "=" + run_id,
            "--network",
            network,
            "--env-file",
            str(db_env),
            "--memory",
            "256m",
            "--pids-limit",
            "100",
            POSTGRES,
            capture=True,
        )
        for _ in range(60):
            status = docker(
                "exec",
                database,
                "pg_isready",
                "-U",
                "accessops_test",
                "-d",
                "accessops_test",
                capture=True,
                check=False,
            )
            if status.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Disposable test database did not become ready.")
        test = docker(
            "run",
            "--name",
            runner,
            "--label",
            LABEL + "=" + run_id,
            "--network",
            network,
            "--env-file",
            str(test_env),
            "--mount",
            "type=bind,source=" + str(report_dir) + ",target=/reports",
            "--read-only",
            "--tmpfs",
            "/tmp",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--memory",
            "512m",
            "--pids-limit",
            "128",
            "accessops-backend-tests:local",
            "python",
            "-m",
            "pytest",
            "-q",
            "--tb=short",
            "-p",
            "no:cacheprovider",
            "--junitxml=/reports/results.xml",
            check=False,
        )
        # A tmpfs disappears when its container stops. Persist the report in a
        # dedicated output-only bind, never expose credentials or sibling data.
        report = report_dir / "results.xml"
        if not report.is_file() or report.stat().st_size == 0:
            raise RuntimeError("PostgreSQL report was not persisted; result cannot be published.")
        shutil.copyfile(report, output / "postgresql-tests.xml")
        result = test.returncode
    finally:
        # Exact named resources must still carry this invocation's random label.
        for name in (runner, database):
            if owned("container", name, run_id):
                docker("container", "rm", "--force", "--volumes", name, capture=True)
        if owned("network", network, run_id):
            docker("network", "rm", network, capture=True)
        for path in (db_env, test_env):
            checked = path.resolve()
            checked.relative_to((ROOT / ".local" / "backend-tests").resolve())
            checked.unlink(missing_ok=True)
        secret_dir.rmdir()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
