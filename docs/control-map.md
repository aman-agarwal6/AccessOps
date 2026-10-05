# Controls and verification

This is a selected engineering mapping, not a statement of full ASVS, NIST, or
regulatory compliance. A test can demonstrate one behavior without establishing
that the whole control is satisfied. Parameterized cases count independently;
mock transport and real provider results have different scopes.

| Control or threat | Implementation | Repeatable evidence |
| --- | --- | --- |
| SP 800-53 AC-2, account lifecycle | Exact issuer/subject enrollment, durable SCIM jobs, department transfer and immediate offboarding | `backend/tests/test_enrollment.py`; `test_sponsor_offboard_suspends_agent_and_tasks`; connected SCIM checks |
| AC-5, separation of duties | Current independent approver, immutable intent and successor acceptance | `test_self_approval_denied_even_with_role`; `test_successor_acceptance_independent_approval_and_suspend`; real OIDC/business suite |
| AC-6, least privilege | Read-only grants, per-project object checks, role-free introspection client, narrow workforce connector | `test_scope_offboard_cannot_ignore_other_project`; integration realm/credential tests; connected executor SCIM denial |
| Approval integrity | Fifteen-minute expiry, exact input digest, current policy and approver authority | Parameterized `test_stale_approval_denies_no_effect` |
| AU-2 / AU-12, audit generation | Transactional structured audit records, no token logging | `test_policy_outage_and_audit_failure_rollback`; console containment tests |
| AU-9, audit protection | Serialized SHA-256 chain and append-only application paths | `test_audit_chain_detects_tampering`; a DB administrator can still rewrite the chain and head |
| ASVS authentication/session scope | Authlib code + S256 PKCE, state, nonce, signature and issuer; exact enrollment; secure CSRF/session gates | `backend/tests/test_oidc_flow.py`; `test_session_requires_live_binding_and_csrf`; real provider OIDC flow |
| Token confusion / replay | Narrow RS256 verification, issuer/audience/client bounds, bounded key refresh; dedicated logout-token rules | `integrations/tests/test_boundaries.py`; `test_logout_jti_replay_deduplicated_and_session_revoked` |
| AC-2(6)/AC-12, session termination on departure | Containment ends the workforce account's Keycloak sessions (not-before plus back-channel logout) and counts sessions back; zero is required for provider proof | `integrations/tests/test_sessions.py`; `test_containment_ends_sessions_even_when_the_account_is_already_disabled`; `test_keycloak_proof_requires_a_counted_zero_sessions`; live `sessions` suite |
| PS-4 and PS-4(2), personnel termination with automated action | A signed HR event opens the departure case and contains access in the same transaction, or at the effective time through the worker, as a narrowly authorized service principal | `backend/tests/test_hr_intake.py`; HR feed policy cases in `policies/accessops_test.rego`; live `hr-intake` suite |
| AU-6 and SI-4, post-termination activity review and monitoring | A watch reads the departed account's Keycloak sign-ins after the effective time, records every reading, blocks closure on any success and signals the SOC with signed CAEP and RISC events | `backend/tests/test_leaver_assurance.py`; event-reader boundaries in `integrations/tests/test_sessions.py`; live `leaver-assurance` suite |
| Revocation under concurrency | PostgreSQL transaction gate, replay reauthorization, local containment before remote convergence | `test_postgresql_gate_serializes_competing_revocations`; `backend/tests/test_grant_boundary.py`; live protected-read replay denial |
| Policy availability | Missing, malformed, stale, undefined and unavailable policy results deny | AuthZEN boundary tests; OPA policy cases; actual OPA outage |
| Provider availability / stale jobs | Observe before retry; late remote effects checked against current local intent | `test_connector_ambiguous_retry_reconciles_before_repeat`; `test_stale_queued_grant_cannot_restore_revoked_access`; enrollment race tests |
| OWASP LLM01:2025 / ATLAS AML.T0051.001 | Untrusted record prose cannot select tools, approvals or provider changes; structured deterministic findings | `test_mitre_aml_t0051_001_indirect_injection_cannot_approve`; no LLM was evaluated |
| Agent authority and budget | Active sponsor, fixed resources, ten minutes, six calls, one draft | `test_task_six_calls_expiry_scope_and_sponsor`; cross-task/tool injection tests |
| Drift | Provider membership without an active backed grant is flagged and never adopted | OPA drift cases, reconciliation and the browser drift walkthrough; see ledger for provider scope |
| Build/evidence integrity | Pinned image/action revisions, hash-locked Python/npm inputs, staged-source scan, CycloneDX, exact-byte archive | `tools/test_evidence.py`; release signing job; signer trust verified separately |

STRIDE covers system trust boundaries; CSA MAESTRO organizes agent-layer risks in
the [threat model](threat-model.md). AI RMF/AI 600-1 guide prospective generative
model evaluation. The shipped assistant is deterministic: an LLM injection test,
model performance result, or AI standard conformance is not claimed.

See [verification](verification.md) for passed, skipped, and unrun scopes. Tests
use synthetic fixtures and disposable databases. No security test targets an
external organization or production identity system.

Enterprise departure cases extend AC-2 with source events, stable account bindings,
owners, deadlines and required lifecycle tasks. AC-5 is enforced by owner-only
external statements and independent closure of an exact current packet. AU-2,
AU-9 and AU-12 map to departure/import/attestation/closure audit events, immutable
application packet paths and retained evidence origins. See
`backend/tests/test_offboarding_cases.py` and the actual connected case driver;
cloud fixtures are not provider verification or evidence of control certification.
