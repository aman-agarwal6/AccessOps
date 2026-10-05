# Standards: implement, map, track

This is a reference implementation, not a certification claim. Supported code,
mock/unit verification and connected-provider verification are separate entries
in the verification ledger. Preview features do not define the default lab.

## Implement in the core

| Specification | Implementation boundary |
| --- | --- |
| [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [PKCE RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), [OAuth Security BCP RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) | Authorization code + PKCE, server session, state/nonce validation; no tokens stored in the browser |
| [JWT assertions RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) | Executor client authentication with private_key_jwt; model never receives the private key or token |
| [Introspection RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) | Active-token check plus current app grant/sponsor state; introspection failure denies |
| [Standard Webhooks](https://www.standardwebhooks.com/) | HR leaver events signed with HMAC-SHA256 over id, timestamp and body; five-minute window; webhook ID as idempotency key; several `v1` signatures accepted for secret rotation |
| [OIDC Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) | Dedicated verified logout-token receivers for the console and the Atlas lab app; containment triggers the workforce realm's logout tokens and the Atlas session ending is measured |
| [SCIM RFC 7643](https://www.rfc-editor.org/rfc/rfc7643), [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) | Narrow Users/Groups client, PATCH membership and active:false suspension; suspension alone is not session revocation, so containment adds Keycloak's per-user logout |
| [AuthZEN Authorization API 1.0 Final](https://openid.net/specs/authorization-api-1_0-final.html) | Single subject/action/resource/context evaluation adapter to OPA; boolean decision required; transport or policy failure denies |

Keycloak [26.8 release](https://www.keycloak.org/2026/10/keycloak-2680-released)
is the researched baseline. Operator authentication and workforce provisioning
use separate realms and credentials. Principal identity is `(issuer, subject)`.

## Map controls and concepts

| Guidance | What the project demonstrates |
| --- | --- |
| [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) | Selected authentication, authorization, validation, session and logging requirements tied to denial tests |
| [NIST SP 800-63-4](https://pages.nist.gov/800-63-4/) | Authentication/session design rationale; no claimed assurance level |
| [NIST SP 800-53 Rev.5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | AC-2 lifecycle; AC-5 independent approval; AC-6 constrained grants; AU-2/AU-12 audit generation; AU-9 app-layer integrity limitations |
| [NIST CSF 2.0](https://www.nist.gov/cyberframework) | Governance outcomes, not individual executable test requirements |
| [JWT access-token profile RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) | Validate configured issuer, audience, signature, timestamps and key handling; claim full profile only when typ and every mandatory claim are verified |
| [Resource Indicators RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) | Resource/audience boundary; audience mappers are not proof of wire-level resource-parameter support |
| [RAR RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) | Server task grants record fixed records, purpose, typed actions and budget; no claim of native RAR wire support |
| [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework), [AI 600-1](https://doi.org/10.6028/NIST.AI.600-1) | Bounded authority and human decisions; GenAI evaluation applies to a future local model profile, not a claim that an LLM runs in the shipped assistant |
| [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/) and [Agentic Top 10, December 2025 release](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) | LLM01:2025 indirect injection; ASI01 goal hijack, ASI02 tool misuse, ASI03 identity/privilege abuse; selected controls, not comprehensive coverage |

An agent's sponsor is a governance relationship, not an OAuth delegated actor by
itself. The stable core uses an independent service identity and approval-bound
task authorization. It must not fabricate an `act` claim from the sponsor field.
`private_key_jwt` authenticates a client; it does not sender-constrain its tokens.

## Optional profiles and tracking

- [Token Exchange RFC 8693](https://www.rfc-editor.org/rfc/rfc8693): internal
  exchange/downscoping with explicit non-expansion tests. Keycloak delegation and
  parameterized scopes are preview features; any `act` demonstration belongs in
  an isolated profile with actual actor/subject authorization.
- [DPoP RFC 9449](https://www.rfc-editor.org/rfc/rfc9449): proof validation must
  include method, URI, access-token hash, key binding, freshness and replay.
  Keycloak 26.8 exchange constraints depend on original client and binding key;
  do not generalize the older blanket subject-token limitation.
- [SSF 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html),
  [CAEP 1.0](https://openid.net/specs/openid-caep-1_0-final.html),
  [RISC 1.0](https://openid.net/specs/openid-risc-1_0-final.html),
  [SET delivery RFC 8935](https://www.rfc-editor.org/rfc/rfc8935): optional
  experimental Keycloak transmitter profile and narrow CAEP receiver. Durable
  inbox before acknowledgment; dedicated SET validation, replay identity and
  bounded event scope. Credential change does not automatically mean logout.
- [NIST agent identity resource hub](https://pages.nist.gov/nccoe-ai-identity/):
  rolling resources and feedback; its first SDLC use case complements this
  access-governance scenario. No unfinished agent-standard conformance claim.
- [IETF agent-auth draft](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/)
  and [OpenID Identity Management for Agentic AI whitepaper](https://openid.net/wp-content/uploads/2025/10/Identity-Management-for-Agentic-AI.pdf): track draft/adoption
  status and guidance separately from finalized implemented specifications.

## Supply chain and evidence

CycloneDX JSON SBOM describes dependencies; vulnerability and license reports
are separate evidence. [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
use Sigstore to bind exact release bytes to the producing workflow and source.
The SBOM and SLSA provenance attest the same frozen evidence archive. Detached
bundles stay outside that archive. Verification pins the expected repository,
workflow, ref and commit; trusted roots come from an independent trusted source.
Attestation proves provenance/integrity, not application security or compliance.

The [control-to-test mapping](control-map.md) and
[verification ledger](verification.md) record the implemented scope and actual
results. Optional profiles listed above are design/watch-list items: the current
code does not provide token exchange, DPoP proof validation, or a CAEP receiver.
