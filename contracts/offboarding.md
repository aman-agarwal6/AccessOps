# Enterprise departure case contract

Business job: turn an employee/contractor departure event into a reviewed closure
packet with explicit system coverage, owners, deadlines and remaining gaps.
This extends the original local authorization system; it never equates a disabled
directory account with every token, application session or local copy being gone.

All routes use the enrolled operator session, CSRF, current project scope, policy
and the existing idempotency/rate/transaction gate. Agents cannot manage cases.
The source event and explicit stable account bindings are immutable. No email or
display-name matching, tenant writes, automatic grants or destructive cleanup.

- `POST /api/v1/offboarding-cases`: identityId, employmentType employee|contractor,
  hrEventId (8–64), hrSource (3–64), effectiveAt (UTC), reason (8–255), bindings
  (max 2, one per provider). Owner is the submitting operator; dueAt is effectiveAt
  plus four calendar hours. This reference SLA is configurable in a future profile.
- `POST /api/v1/offboarding-cases/{id}/import`: `{report: normalizedReport}`.
- `POST /api/v1/offboarding-cases/{id}/contain`: `{}`; creates/executes the actual
  local offboard request, linking its durable provisioning job. Future departures
  cannot use this action. Earlier emergency containment remains a separate route.
- `POST /api/v1/offboarding-cases/{id}/tasks/{taskId}/attest`: reference (8–120),
  summary (20–500). Owner records the external work; this is not provider proof.
- `POST /api/v1/offboarding-cases/{id}/close`: expectedRevision + packetHash.
  Independent approver must review current exact evidence and all closure blockers.
- `GET /api/v1/offboarding-cases/{id}/packet`: draft until closed; immutable
  administrative closure packet afterward. It has no signature/conformance claim.
- `POST /api/v1/offboarding-cases/{id}/observe-directory`: `{}`; queues a read-only
  refresh for an effective, locally contained, server-enrolled directory case.
  An already pending directory job is reused rather than duplicated.

Mutation responses are `{result: CaseDTO}`. Snapshot adds `offboardingCases`.
Cases contain event, workforce identity, owner, effective/due dates, revision, current policyVersion,
bindings, task status/evidence source, import receipts, blockers and packetHash.
Only the latest fifty scope-visible cases are included in this reference snapshot.

Fixed required task keys:
`local-containment`, `keycloak-directory`, `entra-directory`, `entra-sessions`,
`github-org`, `github-repositories`, `credentials`, `m365-handover`, `legacy-scope`.
Task status is pending|observed|attested, separately from evidenceKind
none|provider_observation|imported_snapshot|owner_attestation. The owner can document
a scope exclusion with a reason; an independent reviewer decides whether it is
adequate for administrative closure. No exclusion grants or preserves access.

Normalized report:

```json
{
  "schemaVersion": 1,
  "collectionMethod": "synthetic_fixture",
  "collectedAt": "2026-10-03T06:00:00Z",
  "observations": [{
    "provider": "entra",
    "tenantId": "11111111-1111-4111-8111-111111111111",
    "subjectId": "22222222-2222-4222-8222-222222222222",
    "observedAt": "2026-10-03T06:00:00Z",
    "capability": "account_enabled",
    "status": "observed",
    "value": false,
    "scope": "tenant-account",
    "reasonCode": "account_state_read"
  }],
  "limitations": ["Synthetic fixture; no Microsoft tenant was contacted."]
}
```

Other capabilities: organization_membership, outside_collaborator,
repository_collaborator, session_revocation, credential_revocation. Status is
observed|unknown; value is a strict boolean for observed or null for unknown.
Reports are at most 100 KB/100 observations; strings and lists are bounded.
Each provider/tenant/subject must match the case's explicit binding. Duplicated
capability+scope readings, unexpected fields, future timestamps and mismatched
bindings are rejected. Reports before departure or older than two hours remain
dated evidence but cannot complete an observed task. New imports invalidate
external owner attestations and prevent closure against stale evidence.

Platform snapshots remain imported evidence, even when a collector reports API
collection. All latest Entra account readings must agree and be fresh; conflicting
scopes cannot complete an observed task. GitHub access tasks require an owner
statement: absence from a caller-visible API list is unknown.

Keycloak observation comes from the existing actual durable worker or a later
reconciliation reading of that workforce account. It must be post-departure and
no older than two hours. Later unknown or enabled readings reopen the task, even
after an earlier successful disable. A partial inventory may still contain valid
independent readings; unrelated unavailable accounts do not erase those facts.
Unknown or incomplete reads never prove absence. Closure records its evidence
basis and remaining platform limitations. Closed packets cannot be overwritten.

Offboarding queues one durable membership removal per distinct known managed
grant pair, including retained historical grants and sponsored agents. A fresh
disabled-account reading cannot replace membership evidence. Exact per-pair
negative observations are required; later positive, incomplete or unknown reads
reopen the gate. Reconciliation can refresh old proof. A second HR event cannot
skip remaining memberships merely because an earlier case revoked local grants.

Actual read timestamps determine ordering and freshness, independently of audit
completion order. Conflicting ties fail closed. Pending/retry scoped observations
block reuse of old proof. A new failed attempt cannot reuse its retained earlier
reading to appear fresh. Reconciliation outcome selection is bounded to 500
recent events in the two-hour window; exceeding that bound fails closed.

An optional server-local `enroll_ad` command validates and stores immutable
domain/user/group GUIDs for a workforce identity. Browser inputs cannot supply
`adBinding`. Case creation captures the current trusted mapping and adds required
task `ad-directory`; cases without enrollment retain nine tasks. A durable job
acts only after local containment, checks the exact enrollment before and after
delivery, disables the account and removes only mapped memberships. Owner
statements cannot replace its complete native provider observation. GUID targets,
atomic old-value account-flag updates, strict LDAPS and object-specific delegated
rights constrain the optional [Samba lab](../docs/directory-lab.md). This does not
prove Microsoft AD interoperability or revoke existing tickets/sessions.
