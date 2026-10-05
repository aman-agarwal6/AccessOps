from unittest.mock import Mock

import pytest
from core.models import EvidenceRun, Grant, OutboxJob
from core.worker import finish_reconciliation, run_reconcile
from django.utils import timezone

from integrations.errors import ConnectorError

pytestmark = pytest.mark.django_db


def job_for(org):
    run = EvidenceRun.objects.create(
        name="Synthetic drift coverage", scenario="provider-drift", project_ids=["Atlas"]
    )
    return OutboxJob.objects.create(
        kind="reconcile",
        status="running",
        attempts=1,
        desired={"projects": ["Atlas"], "runId": str(run.pk)},
        available_at=timezone.now(),
    )


def test_unavailable_principal_preserves_measured_drift_without_grant(org):
    job = job_for(org)
    before = list(Grant.objects.values_list("id", "status"))

    def observe(identity, resource):
        if identity["providerSubject"] == org["agent"].subject:
            raise ConnectorError("Synthetic service-account scope unavailable")
        return {"drift": True, "observed": {"active": True, "sessions": 0, "member": True}}

    result = run_reconcile(job, Mock(reconcile=observe))
    assert result["verified"] is False
    assert result["observed"]["unknownCount"] > 0
    assert result["observed"]["driftCount"] > 0
    assert any(o["drift"] is True for o in result["observed"]["observations"])
    assert any(o["drift"] is None for o in result["observed"]["observations"])
    assert list(Grant.objects.values_list("id", "status")) == before
    job.observed, job.status = result["observed"], "failed"
    finish_reconciliation(job)
    run = EvidenceRun.objects.get(pk=job.desired["runId"])
    assert run.status == "failed"
    assert run.manifest["adoptedChanges"] == 0
    assert run.manifest["unknownCount"] > 0


def test_pending_binding_is_unknown_not_measured_drift(org):
    job = job_for(org)
    org["employee"].subject = "pending:synthetic-reference"
    org["employee"].save(update_fields=["subject"])
    result = run_reconcile(
        job,
        Mock(
            reconcile=lambda *a: {
                "drift": False,
                "observed": {"active": True, "sessions": 1, "member": False},
            }
        ),
    )
    assert result["verified"] is False
    assert result["observed"]["driftCount"] == 0
    assert result["observed"]["unknownCount"] > 0


def test_malformed_observation_cannot_be_verified(org):
    result = run_reconcile(
        job_for(org), Mock(reconcile=lambda *a: {"drift": False, "observed": {"active": "true"}})
    )
    assert result["verified"] is False
    assert result["observed"]["driftCount"] == 0
    assert result["observed"]["unknownCount"] == len(result["observed"]["observations"])


def test_complete_matching_observation_can_pass(org):
    job = job_for(org)
    result = run_reconcile(
        job,
        Mock(
            reconcile=lambda *a: {
                "drift": False,
                "observed": {"active": True, "sessions": 1, "member": False},
            }
        ),
    )
    assert result["verified"] is True
    assert result["observed"]["unknownCount"] == 0
    job.observed, job.status = result["observed"], "verified"
    finish_reconciliation(job)
    assert EvidenceRun.objects.get(pk=job.desired["runId"]).status == "passed"


def test_empty_scope_cannot_be_passing_evidence(org):
    job = job_for(org)
    job.desired["projects"] = ["unconfigured-project"]
    result = run_reconcile(job, Mock())
    assert result["verified"] is False
    assert result["observed"]["observations"] == []
    job.observed, job.status = result["observed"], "verified"
    finish_reconciliation(job)
    assert EvidenceRun.objects.get(pk=job.desired["runId"]).status == "failed"
