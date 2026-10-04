# Approved build contract

AccessOps is a portfolio reference system for employee and sponsored-agent access
governance. Its central demonstration is offboarding: disable local access,
suspend sponsored automation, apply directory changes, and prove what completed
and what remains pending. A polished dashboard is only useful if these effects
can be inspected and independently reproduced.

## Product boundaries

- Public, login-free browser simulation, with synthetic data and explicit labels.
- Authenticated local lab with real Django, PostgreSQL, Keycloak and OPA services.
- Read-only recorded verification evidence with source revision and actual results.
- One fictional organization, two departments and separate project resources.
- Seven destinations: overview/work queue, offboarding cases, requests, identities, access reviews,
  policies/resources, runs/evidence. Approval, application and verification are
  separate states. Every visible action must work or explain its prerequisite.
- Deterministic bounded review assistant is required. Local LLM is optional and
  cannot approve, provision, modify policy, or gain its own authority.
- Free static hosting and reproducible local services; no required SaaS, API
  credit, commercial identity-provider subscription, or always-on cloud database.

## Required security behavior

| Requirement | Acceptance evidence |
| --- | --- |
| Offboard employee and suspend sponsored agents | Atomic local state change; protected action denied; independent observed provider state |
| Independent approval | Requester cannot approve own request; ownership and roles checked server-side |
| Approval integrity | Exact change fingerprint + policy version + 15-minute expiry checked at execution |
| Safe asynchronous execution | Durable outbox, operation idempotency, reconcile unknown remote outcome before retry |
| Bounded agent task | Fixed records and purpose; ten minutes, six calls, one draft; proposals remain unapproved |
| Policy outage | Timeout, stale policy, missing result and undefined rule deny before side effects |
| Provider outage | Local containment succeeds; connector remains pending/failed with retry evidence |
| Identity integrity | Principal key is issuer + subject; email/display name cannot establish privilege |
| Emergency containment | Local console only, reason + incident, transaction audit; cannot create grants |
| Out-of-band access | Direct directory membership is unbacked drift, never silently adopted |
| Token edge cases | Wrong issuer/audience, expiry, unknown kid, key rotation, none/confused algorithms, bounded clock skew |
| Revocation edges | Old token use, new token issuance and existing app session checked separately |
| Evidence integrity | Exact-byte manifest, SBOM and detached CI attestations with trust policy |

## Implementation sequence

1. Shared domain contract, isolated repository and secure runtime setup.
2. Working local governance and browser simulation using the same domain shapes.
3. Keycloak authentication/provisioning and OPA authorization with real denial tests.
4. Recruiter journey, accessible interface and recorded verification export.
5. Reproducible checks, threat model, standards matrix and signed release workflow.
6. GitHub and portfolio handoff after review of source, evidence and public build.

Optional protocol profiles are separately gated. An implementation or unit test
is never reported as real-provider verification; skipped checks remain visible.

The September 2026 updates were incorporated: SCIM semantics, AuthZEN requests,
explicit agent authentication and sponsor records, logout/introspection, optional
CAEP/DPoP/token exchange, control mapping, threat methods, approval expiry,
break-glass, JWT edge cases, drift, SBOM and signed evidence.

## Approved enterprise application extension — October 2026

The user selected employee/contractor offboarding across systems and has no paid
test tenant. The concrete job is to close an HR departure ticket with accountable
work and reviewed evidence. Each case binds stable Entra/GitHub account IDs,
has an owner and a four-hour reference deadline, and tracks directory containment,
sessions, collaboration, shared credentials, data/license handover and legacy scope.

The existing transactional containment and real local Keycloak connector remain
the operational core. Vendor-shaped offline fixtures plus optional bounded
read-only Graph/GitHub collectors extend coverage without requiring a tenant.
Imported observations never become authenticated provider proof. Unknown absence,
stale timestamps and incomplete visibility keep work unresolved. Owner statements
record external work explicitly; independent reviewers close the exact current
packet. Closed packets remain immutable through application paths.

This extension adds a practical case queue and service-desk artifact, while keeping
the original standards/control mappings, agent restrictions and free deployment.
The separately supplied Samba AD-compatible lab is an optional local integration
target; its independent tests do not establish AccessOps integration or Microsoft
AD/Entra interoperability. Actual integration results must be recorded separately.

The supplied lab is integrated through an opt-in connector with immutable
server-enrolled GUIDs, object-specific delegated permissions, verified LDAPS,
atomic stale-value account flag protection and explicit group readback. Existing
tickets/sessions and Microsoft interoperability remain unverified. Offboarding
also queues removals for known managed Keycloak grant history, so an earlier
local revocation or a repeated HR event cannot conceal unfinished remote work.

## Interface redesign — October 2026

The user rejected the earlier light interface as hard to read and follow. The
console was rebuilt around the offboarding job: a dark graphite default with a
matching light theme, a 16px type scale, an urgency-ranked departure queue, one
explicit next step per case that names the role able to take it, actions grouped
by phase, and a closure-readiness rail. The seven destinations remain, grouped as
Offboarding, Access governance and Evidence. The five evidence kinds (signed CI
evidence, provider observation, imported snapshot, owner attestation, simulated)
each keep a fixed icon, label and color. Server rules did not change; the UI only
explains them. Automated axe checks run on every route in both themes.