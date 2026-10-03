# Portfolio presentation

## Project card

**AccessOps — Employee and AI-agent access governance**

An operations console that tracks access from request and independent approval
through application and observed verification. The local reference system
connects Django, PostgreSQL, Keycloak and OPA; the public synthetic simulation
lets recruiters explore the same lifecycle workflows without creating an account.

Skills: IAM lifecycle, Python APIs, React/TypeScript, authorization policy,
security automation, reproducible testing, evidence integrity.

Source: [aman-agarwal6/AccessOps](https://github.com/aman-agarwal6/AccessOps).
Demo: [AccessOps operations console](https://aman-agarwal6.github.io/AccessOps/).
The verification ledger links actual completed checks. The demo is a synthetic
browser simulation; the documented local lab exercises the real integrations.

## Ninety-second walkthrough

1. Start on the overview and explain the distinction between simulation and
   connected verification.
2. Open the departing employee and show the sponsored assistant and active grants.
3. Apply authorized offboarding. Show local denial immediately and remote
   provisioning as a separate pending/verified state.
4. Attempt an assistant action after containment and show the reason for denial.
5. Open an actual recorded test receipt; identify its source revision and limits.

## Interview discussion

Explain why approvals expire and bind to exact inputs, why an agent proposal
cannot approve itself, why issuer/subject is used instead of email, how remote
outcomes are reconciled before retry, and why directory suspension is distinct
from session/token revocation. Discuss an OPA outage, direct directory drift,
and the local containment command. Describe preview protocols separately from
the supported core.

## Resume wording

After the corresponding connected checks pass, a truthful project bullet is:

“Built AccessOps, an employee and sponsored-agent access-governance reference
system with Django, PostgreSQL, React, Keycloak and OPA; implemented expiring
independent approvals, transactional offboarding, durable provisioning and
reproducible authorization-denial tests.”

Add measured test counts or revocation timings only from a published receipt.
Do not invent an enterprise user count, reduction percentage, certification,
production deployment or AI performance claim.
