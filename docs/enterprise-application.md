# The departure problem

An IAM analyst receives an HR event: an employee leaves or a contractor's
engagement expires. With the signed HR feed connected, AccessOps opens the case
and contains access itself, so the analyst starts from a contained case. Disabling the central account leaves a practical question:
what else can they still access, who owns the remaining work, and what evidence
supports closing the departure ticket?

AccessOps turns that event into a case with an effective date, accountable owner,
deadline, explicit stable account bindings and nine required actions. The work
queue highlights overdue and blocked cases. It distinguishes observed directory
state from imported snapshots, application-owner attestations and unknown coverage.

The reference scope is Microsoft Entra sign-in access, GitHub organization and
repository access, Keycloak workforce access, shared automation credentials,
Microsoft 365 data/license handover and legacy/AD inventory confirmation. Data
retention, mailbox/OneDrive handover and legal holds are work to record and review;
the application does not delete a mailbox or remove a license automatically.

The local system can actually contain its enrolled workforce identity and
sponsored automation, including ending the identity's Keycloak sessions so apps
registered for back-channel logout sign the person out. An optional Samba AD-compatible directory adds a tenth
required task: disable the explicitly enrolled account and remove mapped group
memberships through verified LDAPS with object-specific delegated permissions.
New sign-ins and new Kerberos tickets are refused afterwards; connections and
tickets already held keep working until they close or expire, and the case says
when that is. Samba results do not establish Microsoft interoperability. An opt-in
Microsoft Entra connector disables an enrolled test user, removes its group and
revokes its sessions through Graph in the lab's own test tenant. Optional
read-only Graph and GitHub collectors gather minimal observations for explicit
accounts in an authorized tenant.
No tenant is required: vendor-shaped synthetic fixtures exercise normalization,
residual-access assessment, action tracking and closure using free local tools.
Those fixtures are not measurements of Microsoft or GitHub.

A newer snapshot may reopen work. Missing accounts, partial permissions and stale
reads stay unknown. Removing GitHub organization membership does not prove local
clones, outside collaboration or every credential is gone. Entra directory state
does not prove application-owned sessions have ended. Owner actions remain visible
as attestations; an independent reviewer closes only the current exact packet.

The output is a draft or immutable reviewed closure packet that an IAM team can
attach to its HR/service-desk ticket. Its value is the unresolved-work inventory,
clear ownership and evidence traceability. It does not claim universal termination
of every remote access path. The same workflow can be demonstrated without paid
Microsoft subscriptions, a test organization or an always-running cloud service.

The [case contract](../contracts/offboarding.md),
[platform connector guide](platform-connectors.md) and
[optional real directory walkthrough](directory-lab.md) and
[verification ledger](verification.md) describe implementation and actual test
scope separately.
