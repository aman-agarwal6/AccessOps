import uuid

from django.conf import settings
from django.db import models


class Principal(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    issuer = models.URLField(max_length=500)
    subject = models.CharField(max_length=255)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT
    )
    name = models.CharField(max_length=120)
    kind = models.CharField(
        max_length=10, choices=[("human", "human"), ("agent", "agent"), ("service", "service")]
    )
    department = models.CharField(max_length=80, blank=True)
    email = models.EmailField(blank=True)
    status = models.CharField(max_length=16, default="active")
    roles = models.JSONField(default=list)
    project_ids = models.JSONField(default=list)
    sponsor = models.ForeignKey(
        "self", null=True, blank=True, related_name="sponsored_agents", on_delete=models.PROTECT
    )
    workforce_identity = models.ForeignKey(
        "self", null=True, blank=True, related_name="operator_identities", on_delete=models.PROTECT
    )
    revision = models.PositiveIntegerField(default=1)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["issuer", "subject"], name="unique_issuer_subject")
        ]


class Resource(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    project = models.CharField(max_length=80)
    owner = models.ForeignKey(Principal, on_delete=models.PROTECT)
    description = models.TextField(blank=True)
    sensitivity = models.CharField(max_length=30, default="internal")
    provider_group = models.CharField(max_length=255, blank=True)
    evidence = models.TextField(blank=True)


class PolicyState(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1)
    version = models.CharField(max_length=128)
    frozen = models.BooleanField(default=False)


class ChangeRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey(
        Principal, on_delete=models.PROTECT, related_name="change_requests"
    )
    resource = models.ForeignKey(Resource, null=True, on_delete=models.PROTECT)
    requester = models.ForeignKey(
        Principal, on_delete=models.PROTECT, related_name="submitted_requests"
    )
    payload = models.JSONField()
    payload_hash = models.CharField(max_length=64)
    policy_version = models.CharField(max_length=128)
    status = models.CharField(max_length=16, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    applied_at = models.DateTimeField(null=True)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            old = type(self).objects.get(pk=self.pk)
            if any(
                getattr(old, key) != getattr(self, key)
                for key in (
                    "identity_id",
                    "resource_id",
                    "requester_id",
                    "payload",
                    "payload_hash",
                    "policy_version",
                )
            ):
                raise ValueError("Request intent is immutable; create a new request.")
        super().save(*args, **kwargs)


class Approval(models.Model):
    request = models.OneToOneField(
        ChangeRequest, primary_key=True, related_name="approval", on_delete=models.PROTECT
    )
    approver = models.ForeignKey(Principal, on_delete=models.PROTECT)
    payload_hash = models.CharField(max_length=64)
    policy_version = models.CharField(max_length=128)
    approved_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Approvals are immutable.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("Approvals are retained for audit.")


class Grant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey(Principal, on_delete=models.PROTECT)
    resource = models.ForeignKey(Resource, on_delete=models.PROTECT)
    permission = models.CharField(max_length=40, default="read")
    status = models.CharField(max_length=12, default="active")
    expires_at = models.DateTimeField(null=True)
    source_request = models.ForeignKey(ChangeRequest, null=True, on_delete=models.PROTECT)
    purpose = models.CharField(max_length=255, blank=True)
    max_calls = models.PositiveIntegerField(null=True)
    calls_used = models.PositiveIntegerField(default=0)


class SponsorAcceptance(models.Model):
    request = models.OneToOneField(ChangeRequest, primary_key=True, on_delete=models.PROTECT)
    sponsor = models.ForeignKey(Principal, on_delete=models.PROTECT)
    payload_hash = models.CharField(max_length=64)
    accepted_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Acceptance is immutable.")
        super().save(*args, **kwargs)


class Review(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    resources = models.ManyToManyField(Resource)
    assigned_to = models.ForeignKey(Principal, on_delete=models.PROTECT)
    status = models.CharField(max_length=20, default="open")
    due_at = models.DateTimeField()
    findings = models.JSONField(default=list)


class EvidenceRun(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    scenario = models.CharField(max_length=80)
    status = models.CharField(max_length=12, default="pending")
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True)
    summary = models.CharField(max_length=255, blank=True)
    checks = models.JSONField(default=list)
    manifest = models.JSONField(default=dict)
    project_ids = models.JSONField(default=list)


class AssistantTask(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    review = models.ForeignKey(Review, on_delete=models.PROTECT)
    run = models.OneToOneField(EvidenceRun, on_delete=models.PROTECT)
    agent = models.ForeignKey(Principal, on_delete=models.PROTECT)
    requester = models.ForeignKey(
        Principal, on_delete=models.PROTECT, related_name="assistant_tasks"
    )
    expires_at = models.DateTimeField()
    status = models.CharField(max_length=16, default="active")
    calls_used = models.PositiveIntegerField(default=0)
    drafts_created = models.PositiveIntegerField(default=0)
    policy_version = models.CharField(max_length=128)
    resource_ids = models.JSONField(default=list)


class OutboxJob(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    request = models.OneToOneField(ChangeRequest, null=True, on_delete=models.PROTECT)
    assistant_task = models.OneToOneField(AssistantTask, null=True, on_delete=models.PROTECT)
    kind = models.CharField(max_length=24)
    status = models.CharField(max_length=20, default="pending")
    desired = models.JSONField(default=dict)
    observed = models.JSONField(default=dict)
    attempts = models.PositiveIntegerField(default=0)
    available_at = models.DateTimeField()
    lease_until = models.DateTimeField(null=True)
    last_error = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class IdempotencyRecord(models.Model):
    principal = models.ForeignKey(Principal, on_delete=models.PROTECT)
    key = models.CharField(max_length=128)
    fingerprint = models.CharField(max_length=64)
    response = models.JSONField()
    status_code = models.PositiveSmallIntegerField(default=200)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["principal", "key"], name="unique_principal_idempotency"
            )
        ]


class AuditHead(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1)
    last_hash = models.CharField(max_length=64, default="0" * 64)
    sequence = models.PositiveBigIntegerField(default=0)


class AuditEvent(models.Model):
    sequence = models.PositiveBigIntegerField(primary_key=True)
    at = models.DateTimeField()
    actor_id = models.CharField(max_length=100)
    action = models.CharField(max_length=80)
    target_id = models.CharField(max_length=100)
    detail = models.JSONField(default=dict)
    previous_hash = models.CharField(max_length=64)
    hash = models.CharField(max_length=64)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Audit events are append-only in the application.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("Audit events are retained.")


class SessionBinding(models.Model):
    session_key = models.CharField(max_length=40, primary_key=True)
    principal = models.ForeignKey(Principal, on_delete=models.CASCADE)
    oidc_sid = models.CharField(max_length=255, blank=True)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)


class LogoutReplay(models.Model):
    jti = models.CharField(max_length=255, unique=True)
    expires_at = models.DateTimeField()


class RateBucket(models.Model):
    key = models.CharField(max_length=64, primary_key=True)
    count = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField()


class OffboardingCase(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey(
        Principal, on_delete=models.PROTECT, related_name="departure_cases"
    )
    owner = models.ForeignKey(Principal, on_delete=models.PROTECT, related_name="owned_departures")
    employment_type = models.CharField(max_length=12)
    hr_event_id = models.CharField(max_length=64)
    hr_source = models.CharField(max_length=64)
    effective_at = models.DateTimeField()
    due_at = models.DateTimeField()
    reason = models.CharField(max_length=255)
    bindings = models.JSONField(default=list)
    ad_binding = models.JSONField(default=dict)
    attestations = models.JSONField(default=dict)
    containment_request = models.ForeignKey(ChangeRequest, null=True, on_delete=models.PROTECT)
    # Set when a signed HR feed opened the case; that feed contains it once effective.
    intake_source = models.ForeignKey(
        Principal, null=True, on_delete=models.PROTECT, related_name="intake_departures"
    )
    revision = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    closed_at = models.DateTimeField(null=True)
    closed_by = models.ForeignKey(
        Principal, null=True, on_delete=models.PROTECT, related_name="closed_departures"
    )
    closed_packet = models.JSONField(default=dict)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["hr_source", "hr_event_id"], name="unique_departure_event"
            )
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            old = type(self).objects.get(pk=self.pk)
            if old.closed_at:
                raise ValueError("Closed departure packets are immutable.")
            if any(
                getattr(old, key) != getattr(self, key)
                for key in (
                    "identity_id",
                    "owner_id",
                    "employment_type",
                    "hr_event_id",
                    "hr_source",
                    "effective_at",
                    "due_at",
                    "reason",
                    "bindings",
                    "ad_binding",
                    "intake_source_id",
                )
            ):
                raise ValueError("Departure intent is immutable; create a new event.")
        super().save(*args, **kwargs)


class ActivityCheck(models.Model):
    """One reading of a departed account's Keycloak sign-ins since departure."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(
        OffboardingCase, on_delete=models.PROTECT, related_name="activity_checks"
    )
    checked_at = models.DateTimeField()
    status = models.CharField(max_length=12)  # observed | unavailable
    successes = models.JSONField(default=list)  # [{time, type, clientId}], no IPs
    refused = models.PositiveIntegerField(default=0)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Activity readings are append-only.")
        super().save(*args, **kwargs)


class SecurityEvent(models.Model):
    """A signed Security Event Token waiting for, or acknowledged by, the receiver."""

    jti = models.CharField(max_length=64, primary_key=True)
    source_ref = models.CharField(max_length=200, unique=True)
    event_type = models.CharField(max_length=40)
    subject = models.CharField(max_length=255)
    case = models.ForeignKey(
        OffboardingCase, null=True, on_delete=models.PROTECT, related_name="security_events"
    )
    token = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(null=True)
    receiver_error = models.CharField(max_length=64, blank=True)


class ADEnrollment(models.Model):
    """Trusted local enrollment, never accepted from a browser mutation."""

    identity = models.OneToOneField(
        Principal, primary_key=True, on_delete=models.PROTECT, related_name="ad_enrollment"
    )
    domain_guid = models.UUIDField()
    user_guid = models.UUIDField()
    group_guids = models.JSONField(default=list)
    enrolled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["domain_guid", "user_guid"], name="unique_ad_directory_person"
            )
        ]

    @property
    def binding(self):
        return {
            "domainGuid": str(self.domain_guid),
            "userGuid": str(self.user_guid),
            "groupGuids": self.group_guids,
        }

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Directory enrollment is immutable; review a new identity enrollment.")
        super().save(*args, **kwargs)


class PlatformImport(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(
        OffboardingCase, on_delete=models.PROTECT, related_name="platform_imports"
    )
    actor = models.ForeignKey(Principal, on_delete=models.PROTECT)
    captured_at = models.DateTimeField()
    imported_at = models.DateTimeField(auto_now_add=True)
    report = models.JSONField()
    sha256 = models.CharField(max_length=64)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Platform snapshots are immutable evidence.")
        super().save(*args, **kwargs)
