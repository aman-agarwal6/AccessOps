# Portfolio presentation

## Project card

**AccessOps: employee and contractor offboarding, closed with evidence**

An HR departure becomes a case with an owner, a four-hour target and a required
action for every system the person could still reach. Local access is contained
immediately; the case closes only when an independent reviewer accepts the exact
evidence packet. A local lab runs it against real Keycloak, OPA and a Samba
directory; the public demo is a browser simulation with synthetic data.

Skills: IAM lifecycle, authorization policy, Python and Django APIs,
React/TypeScript, LDAP and SCIM integration, security testing, accessible UI design.

[Live demo](https://aman-agarwal6.github.io/AccessOps/) ·
[Source](https://github.com/aman-agarwal6/AccessOps) ·
[Verification ledger](verification.md)

## Ninety-second walkthrough

1. **Overview:** the queue is ranked by urgency; one contractor is already past
   the four-hour target.
2. **Mara's case:** apply local containment. Two actions turn green, labeled as
   simulated observations, because this is the browser demo.
3. **Import the after-departure report:** Entra sign-in clears as an imported
   snapshot. GitHub stays open, because absence from a list proves nothing.
4. **Owner statements:** record the remaining external work. Each stays labeled
   as an attestation.
5. **Close:** the owner cannot close their own case. Act as the reviewer, close
   it and export the frozen packet.
6. **Runs & evidence:** open the 28-check Samba directory run, then a failed
   attempt and the fix it led to.

## Talking points

- Why a disabled account is not proof that group memberships, sessions or shared
  credentials are gone, and how the case keeps those open.
- Why approvals bind to the exact change and policy version and expire after 15
  minutes, and why an assistant's proposal can never approve itself.
- How retries read before writing, and how actual observation times (not job
  completion times) decide freshness.
- Why the directory connector targets immutable GUIDs and updates account flags
  atomically.
- What the live run caught: account disable left a managed group membership
  behind, so offboarding now removes every known managed grant.

## Resume wording

Verified by the recorded runs:

“Built AccessOps, an employee-offboarding and access-governance system (Django,
PostgreSQL, React, Keycloak, OPA). Departure cases track every system with an
owner and deadline, contain access immediately and close only on independent
review; verified end to end against real Keycloak and a Samba directory, including
denial of new LDAPS and Kerberos logins after offboarding.”

Use only counts from the [verification ledger](verification.md). Do not claim
users, percentages, certification, production use or Microsoft tenant testing.

## Screenshots

All show synthetic data in the public browser simulation.

| View | File |
| --- | --- |
| Overview: urgency-ranked departures and next steps | [overview.png](assets/overview.png) |
| Case in progress, dark theme | [offboarding.png](assets/offboarding.png) |
| Case in progress, light theme | [offboarding-light.png](assets/offboarding-light.png) |
| Case on a phone | [offboarding-mobile.png](assets/offboarding-mobile.png) |
| Evidence: provenance ladder and recorded runs | [evidence.png](assets/evidence.png) |