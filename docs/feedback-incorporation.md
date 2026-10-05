# Incorporation of the approved feedback

The standards feedback changed both the build contract and the implementation.
This table is the traceable handoff. “Implemented” describes a code boundary;
the [verification ledger](verification.md) separately records actual execution.

| Feedback | Current decision and location |
| --- | --- |
| Agent credential and delegation | Independent executor client, `private_key_jwt` (RFC 7523), issuer/audience/client validation and server task grant. Sponsor accountability is explicit, but is not an OAuth `act` claim. RFC 8693 delegation is a future isolated profile. |
| JWT profile and resource indicators | RFC 9068/RFC 8707 mapped to claim/audience tests. No full JWT-profile or resource-parameter wire conformance claim. |
| DPoP | RFC 9449 design/watch list. Not shipped or sender-constrained in this version. |
| Rich Authorization Requests | RFC 9396 concepts mapped to fixed records, purpose, actions, expiry and budget. The grant is server-side; no native RAR wire claim. |
| Revocation signaling | RFC 7662 live introspection and dedicated OIDC Back-Channel Logout receiver implemented. SSF/CAEP/RISC are future profiles; the protected API currently enforces live app state rather than receiving CAEP. |
| Swappable policy interface | Actual Django → AuthZEN single evaluation → OPA, authenticated TLS, strict boolean result, exact bundle hash and fail-closed responses. |
| Provisioning | Native Keycloak SCIM Users/Groups, `active:false`, membership PATCH, observation and retry. Separate operator/workforce realms; no connector administration in the executor. |
| Concrete NIST controls | AC-2, AC-5, AC-6, AU-2, AU-9 and AU-12 mapped to named tests in [control-map.md](control-map.md). |
| AI and agent risks | LLM01:2025, agentic goal/tool/identity risks, AI RMF and AI 600-1 included. The shipped assistant is deterministic; generative-model claims require a separately evaluated local profile. |
| Threat method and abuse tags | STRIDE + CSA MAESTRO in [threat-model.md](threat-model.md); indirect record-injection test tagged MITRE ATLAS AML.T0051.001. |
| Emerging identity work | Exact IETF draft, OpenID agentic identity whitepaper and NIST rolling resource hub linked in [standards.md](standards.md). No unfinished-standard conformance. |
| NIST framing | Its first SDLC use case differs from this access-governance demonstration; tracking is rolling, not a fixed comment deadline. |
| Supply chain / evidence | Locked dependencies, CycloneDX 1.6, allowlisted frozen archive, isolated manual GitHub provenance/SBOM signing. A local unsigned report is never presented as an attestation. |
| Break-glass | Console-only containment, incident/reason and transactional audit. No HTTP counterpart or grant/unfreeze action. No shared emergency password or automated recovery account. |
| Approval expiry | Fifteen minutes; exact intent, policy version, identity revision and current approver authority checked at execution. |
| Token edges | Issuer/audience/client, expiry, `alg:none`, confusion, unknown `kid`, bounded refresh, rotation and skew tested in isolated boundaries; live rotation in both realms, including removal of a leaked key, by `Test-KeyRotation.ps1`. |
| Out-of-band drift | Direct SCIM membership without a backed grant, authenticated reconciliation and no adoption. Unobservable service-account records are unknown, never matches. |
| Interface readability (October 2026) | Rebuilt console: dark and light themes from one token set, 16px type scale, urgency-ranked queue, one next step per case with role explanations, phase-grouped actions and fixed provenance labels. See [approved-plan.md](approved-plan.md). |

New agent inventory has no credential or privilege; sponsor transfer leaves it
suspended; v1 grants are read-only. Operator sign-in requires a password and a
time-based one-time code, enforced by Keycloak and again by the backend; a
software authenticator is not phishing-resistant and does not establish a NIST
assurance level. Production enrollment, automated
recovery, multi-tenancy and arbitrary delegation are outside this release.

Future profiles need actual provider evidence and non-expansion/replay tests.
They cannot replace independent approvals, current-state revocation gates, or
the free deterministic walkthrough.
