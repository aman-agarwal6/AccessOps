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
`signals` and `watch` are added after packetHash and are not part of it.

## Sign-in watch

After containment the worker reads the workforce account's Keycloak sign-in and
token events since the effective time, every 30 seconds for 24 hours, whether the
case is open or closed. Each case carries the watch's live state:

```json
"watch": {
  "status": "watching",
  "windowEndsAt": "2026-10-28T18:25:00+00:00",
  "lastReadAt": "2026-10-27T18:40:12.104233+00:00",
  "lastAttemptAt": "2026-10-27T18:40:12.104233+00:00",
  "refused": 1,
  "successes": 0,
  "afterClosure": 0
}
```

| Status | When | Blocks closure |
| --- | --- | --- |
| `not_started` | Not contained, or the departure is not effective yet | No (other blockers apply) |
| `not_configured` | The read-only events client secret is missing | Yes |
| `pending` | No reading since containment | Yes |
| `unavailable` | The latest attempt failed, including a reading of more than 200 events | Yes |
| `stale` | During the window, the latest successful reading is over 90 seconds old | Yes |
| `watching` | During the window, with a current successful reading | No |
| `finishing` | The window has ended; waiting for a successful reading at or after its end, retried for 24 hours | Yes |
| `complete` | A successful reading at or after the end of the window exists | No |
| `missed` | 24 hours after the window with no such reading; the Keycloak task states it | No |

`windowEndsAt` is the effective time plus 24 hours. `lastReadAt` is the latest
successful reading and `lastAttemptAt` the latest of any outcome (both null before
the first). `refused` is the latest successful reading's count of refused attempts,
or null. `successes` counts distinct successful sign-ins or token uses read so far;
`afterClosure` counts those first read after closure, and is 0 while the case is
open. Each blocking status adds one fixed blocker line.

Only findings enter packetHash: the refused count, any sign-in after departure, the
blocker lines and, for `missed`, a fixed sentence on the Keycloak task. No read
time is hashed: a reading with the same result as the last leaves the packet
unchanged, so a reviewer's hash stays valid while the watch runs. Closure records
the watch in the closed packet as `watchAtClosure`, inside the closed packet's
hash but not `reviewedInputHash`. After closure the watch continues: a sign-in
read then is sent to the SOC as `session-established`, audited as
`departure.access_after_closure` and counted in `watch.afterClosure`, and the
closed packet never changes. A reading that began before closure and finished
after it is discarded and taken again.

Fixed required task keys:
`local-containment`, `keycloak-directory`, `entra-directory`, `entra-sessions`,
`github-org`, `github-repositories`, `credentials`, `m365-handover`, `legacy-scope`.
`keycloak-directory` is observed only from fresh provider readings that show the
workforce account disabled with zero Keycloak sessions after containment ended
them; a reading without a counted session total stays pending.
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
