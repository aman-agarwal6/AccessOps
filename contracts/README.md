# AccessOps v1 interface

All human lab APIs use the Django server session and CSRF protection. The browser
does not retain OAuth tokens. Simulation uses the same domain shapes in memory.
All time fields are UTC ISO-8601 strings. IDs are opaque strings. Synthetic org:
Northstar Systems, departments Engineering and Operations, projects Atlas/Pulse.

GET /api/v1/session: {authenticated, principal?: {id,name,roles}, mode:'connected', csrfToken}
GET /api/v1/snapshot: {identities,services,resources,requests,grants,reviews,runs,audit,policies,health}
GET /api/v1/health: minimal liveness, no internal details.
POST /api/v1/requests: {identityId,resourceId,action:'grant'|'revoke'|'offboard'|'transfer',reason,permission?,newSponsorId?}
POST /api/v1/requests/{id}/approve: {} with Idempotency-Key, server principal supplies approver.
POST /api/v1/requests/{id}/execute: {} with Idempotency-Key, may return pending connector verification.
POST /api/v1/requests/{id}/accept: {} with Idempotency-Key; exact intent accepted by the enrolled successor.
POST /api/v1/identities: {name,email?,kind:'human'|'agent',department,projectIds,sponsorId?}; inventory only, no grants or machine credentials.
POST /api/v1/identities/{id}/transfer-department: {department,reason}; creates an independently approved change.
POST /api/v1/reviews/{id}/run: {mode:'deterministic'} runs bounded review assistant.
POST /api/v1/reviews/{id}/propose: {identityId,resourceId,reason} creates an unapproved request.
POST /api/v1/reconcile: {} detects provider drift, never silently adopts it.
GET /api/v1/evidence/{id}: sanitized real run manifest (read-only).
POST /api/v1/resources/{id}/read: {} with Idempotency-Key; actual protected synthetic records, current grant and sponsor checked before replay.
POST /api/v1/agent/tasks/{id}/tools: {tool:'list_entitlements'|'read_evidence'|'create_draft',resourceId?}; executor token, current task, fixed scope and budget required.
GET /auth/login, GET /auth/callback, POST /auth/logout: OIDC code+PKCE server flow.
POST /auth/backchannel-logout: verified OIDC logout token only.
POST /api/v1/hr-events: signed HR leaver event, no session (see below).

Mutations return {result:<domain object>, snapshot?:<snapshot>}.
Errors: {error:{code,message}} with correct non-2xx status; never credentials.
Idempotency keys required for writes, replay exact operation returns same result;
reuse with different input returns 409. Authorization is evaluated server-side.
Keys use 8–128 characters from A–Z, a–z, 0–9, period, underscore, colon and
hyphen. Cookie-authenticated mutations additionally require the session's
`X-CSRFToken`. Unknown input fields are rejected at the server.

V1 resource grants support **read only**. Grant/revoke require a resource;
offboard/transfer may omit it. Transfer requires an agent and `newSponsorId`.
Reasons are 8–255 characters. Department transfers use the dedicated endpoint;
clients cannot inject their internal payload into generic requests.

Human inventory belongs to Engineering/Atlas or Operations/Pulse. Human
registration must match department scope; agents need an active sponsor owning
their project scope. Optional emails must use `.test` or `.example` domains.
Registration creates role-empty inventory and queues a provider binding.
Registered agents remain suspended pending reviewed credential binding.

Approval lasts fifteen minutes and remains valid only for the exact intent,
current policy, identity revision and approver authority. Authorized revocation
and offboarding do not wait for approval. Sponsorship transfer requires successor
acceptance and independent approval, then revokes old grants and suspends the
agent. Department transfer revokes access outside the destination and contains
affected sponsored agents. Neither operation creates new access or automatically
reactivates credentials.

The protected read API accepts a live operator session explicitly mapped to a
workforce identity, or a workforce executor bearer token. Executor authentication
validates signature, issuer, audience, client and live introspection. Database
grant/sponsor gates apply even when an OAuth token is otherwise valid and even
when a successful operation is replayed. Application task grants are separate
from OAuth token claims. Each task lasts ten minutes, has six tool calls and one
draft; proposals never become approvals or provider effects.

Domain fields (extensions allowed):
- identity: id,name,kind human|agent,department,status active|suspended|offboarded,
  sponsorId (agents),email (synthetic),role,providerSubject,updatedAt
- resource: id,name,project,ownerId,description,sensitivity
- grant: id,identityId,resourceId,permission,status active|revoked|expired,
  expiresAt,sourceRequestId,purpose,maxCalls,callsUsed
- request: id,identityId,resourceId,action,reason,permission,status pending|approved|applied|verified|failed|expired,
  requesterId,approverId,createdAt,approvalExpiresAt,policyVersion,events:[{at,label,status,detail}],newSponsorId
- review: id,name,resourceIds,assignedTo,status,dueAt,findings:[{id,identityId,resourceId,severity,title,detail,evidence,proposedRequestId?}]
- run: id,name,scenario,status passed|failed|pending,origin connected|recorded,
  startedAt,finishedAt,summary,checks:[{name,status passed|failed|skipped,detail}],manifest?
- audit: id,at,actorId,action,targetId,detail,hash
- policy: id,name,version,description,rules:[string]
- health: [{name,status healthy|pending|unavailable,detail}]

HR leaver intake accepts `{type:'worker.departed',eventId,workerId,employmentType,
effectiveAt,reason}` signed per Standard Webhooks: `webhook-id`,
`webhook-timestamp` (within five minutes) and `webhook-signature`
(`v1,<base64 HMAC-SHA256 of id.timestamp.body>`). The webhook ID is the
idempotency key; a redelivery returns the original answer, and a reused event ID
with a different departure returns 409. `workerId` is the AccessOps identity ID;
names and emails are never matched. The feed is a service principal that may
only open and contain departures; its sponsor, an active operator, owns the case.
An effective event is contained in the same transaction; a future one is
contained by the worker once effective. The answer is only
`{result:{caseId,state:'contained'|'scheduled',effectiveAt}}`. Every
authentication failure returns 401 `signature_invalid`.

Revocation is immediate in AccessOps within a DB transaction. Provider effects
are durable jobs, with observed state separate from approval/application. Token
and session revocation is separately measured. Denial must occur before effects.
Read [standards](../docs/standards.md) and the
[verification ledger](../docs/verification.md) for exact protocol support and
which checks used actual providers. The public simulation cannot contact the
connected API; recorded runs are presentation data and cannot be executed.
