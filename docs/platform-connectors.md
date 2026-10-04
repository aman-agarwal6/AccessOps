# Enterprise offboarding snapshots

AccessOps can assess Entra and GitHub observations without a paid service or a
test tenant. The included vendor-response fixtures are synthetic and work
offline. The optional collector performs bounded, read-only API requests in a
user-owned tenant. This release has **no live Entra or GitHub tenant measurement**
and performs no vendor revocation writes.

A snapshot can identify an enabled Entra account or observed GitHub membership
as residual access. It cannot independently prove complete departure handling.
Session and credential revocation always remain unknown in these collectors.
Import evidence remains an imported snapshot, including a report collected by
API; collection method is separate from verification and action completion.

## Use the offline fixtures now

Use the existing hashed Python environment described in [lab setup](../infra/README.md).
From the repository root in PowerShell:

```powershell
& ./backend/.venv/Scripts/python.exe tools/collect_enterprise_snapshot.py --provider entra --fixture before --output output/enterprise/entra-before.json
& ./backend/.venv/Scripts/python.exe tools/collect_enterprise_snapshot.py --provider entra --fixture after --output output/enterprise/entra-after.json
& ./backend/.venv/Scripts/python.exe tools/collect_enterprise_snapshot.py --provider github --fixture before --output output/enterprise/github-before.json
& ./backend/.venv/Scripts/python.exe tools/collect_enterprise_snapshot.py --provider github --fixture after --output output/enterprise/github-after.json
```

Each command emits a canonical report with a real UTC collection timestamp and
`collectionMethod: synthetic_fixture`. It never constructs an HTTP client or
reads an environment token. Choose a new output filename when repeating a run;
the collector refuses to replace an existing report.

Bind these exact fictional IDs to the offboarding case before importing the
reports. Mapping by email, display name, or GitHub login is unsupported:

| Provider | Stable tenant / organization ID | Stable subject ID |
| --- | --- | --- |
| `entra` | `11111111-1111-4111-8111-111111111111` | `22222222-2222-4222-8222-222222222222` |
| `github` | `424242` | `1001` |

The Entra before fixture has `accountEnabled: true`; its after fixture has
`false`. GitHub before contains organization and repository membership. GitHub
after has empty lists, which intentionally produce **unknown**, since this
collector cannot prove complete caller visibility. Both phases retain unknown
session and credential observations. Fixture output is useful for exercising
case assessment, residual-access tasks, and closure blockers. It is not evidence
of a real disabled account or completed enterprise offboarding.

Raw synthetic vendor responses are versioned under `integrations/fixtures/`.
Reports contain only stable object IDs, capability, Boolean or unknown state,
scope, timestamps, and safe reason codes. No vendor names, email addresses,
logins, raw records, authentication headers, or token values are copied.

In **Offboarding cases**, open a departure case with the explicit bindings above
and an effective date no later than the fixture capture. Choose **Import platform
report**, select the generated JSON, and choose **Assess & import report**. The
public simulation also supplies before/after fixture buttons; use synthetic data
there only. Repeat the after capture after the case is effective, so its dated
evidence can be assessed. Reports older than two hours, from before departure,
or with a different binding cannot complete an observed task. Importing a new
report invalidates prior external owner attestations. The remaining session,
credential, data-handover, and legacy scope tasks stay visible for review.

The authenticated import endpoint accepts `{report: normalizedReport}` at
`POST /api/v1/offboarding-cases/{id}/import`; the exported file itself is the
normalized report. The browser supplies the authenticated session and CSRF
controls. See the [case contract](../contracts/offboarding.md) for exact input and
closure requirements.

## Optional collection in an authorized tenant

Only use the live collector after choosing an exact user-owned scope and
obtaining a narrowly scoped read token through that tenant's approved process.
No tenant, app registration, account, paid license, token acquisition, or consent
grant is created automatically. The application does not use existing `gh`
credentials or discover connected organizations. API access and tenant licensing
are subject to the vendor's terms; the offline fixture workflow needs neither.

Inject a short-lived token in the collector process environment through a local
secret-management process. The only accepted names are
`ACCESSOPS_GRAPH_READ_TOKEN` and `ACCESSOPS_GITHUB_READ_TOKEN`. Do not paste token
values into shell history, source files, chat, command arguments, or reports.
No token is sent to the AccessOps browser or stored by the collector.

Commands below use nonfunctional placeholders for the target IDs and paths:

```powershell
& ./backend/.venv/Scripts/python.exe tools/collect_enterprise_snapshot.py --provider entra --tenant-id YOUR-TENANT-UUID --subject-id YOUR-MAPPED-USER-UUID --authorized-read-only-scope --output .local/enterprise/entra-observation.json
& ./backend/.venv/Scripts/python.exe tools/collect_enterprise_snapshot.py --provider github --tenant-id YOUR-NUMERIC-ORG-ID --subject-id YOUR-NUMERIC-USER-ID --organization YOUR-ORG --repository YOUR-REPO --authorized-read-only-scope --output .local/enterprise/github-observation.json
```

One invocation handles one explicitly mapped subject. Omit `--repository` for
organization membership only; repeat it for up to ten selected repositories.
Actual reports must stay under ignored `.local/enterprise/` and should inherit
the private `.local/` permissions established by local setup. Review the
minimized report locally before importing it; stable user IDs and tenant access
observations are still private organizational data. Do not commit, publish, or
copy them into demonstration fixtures. Existing files and paths containing
symlinks or junctions are refused.

### Microsoft Entra / Microsoft Graph

The collector supports the global `https://graph.microsoft.com` origin and
stable v1.0 APIs only. It first reads `/v1.0/organization?$select=id` and requires
exactly the configured tenant UUID before reading any user. Application access
requires `Organization.Read.All` or a documented higher read permission for this
organization lookup. [Microsoft organization API](https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0)

It then reads `/v1.0/users/{stable-UUID}?$select=id,accountEnabled`, validates the
exact mapped ID, and requires a strictly Boolean enabled state. Application
`User.Read.All` is the documented least-privileged user-profile permission. This
collector does not request account-disable write permissions.
[Microsoft user API](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0)

Group memberships, directory roles, PIM eligibility, guest relationships,
application grants, and inherited access are not collected. The direct
`memberOf` API is not transitive and has separate permissions and visibility
requirements, so no group or role completeness claim follows from the user
read. [Microsoft direct memberships API](https://learn.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0)

`accountEnabled=false` records only the disabled account state at the observed
time. It does not prove session, refresh-token, credential, or application-owned
session revocation. No sign-in-activity, audit-log, license, MFA, or authentication
assurance claim is made. National-cloud Graph origins are unsupported.

### GitHub organizations

Requests use `https://api.github.com` and explicitly pin REST version
`2026-03-10`. Enterprise Server origins are unsupported.
[GitHub versioning](https://docs.github.com/en/rest/about-the-rest-api/api-versions)

The collector validates `/orgs/{organization}` against the expected numeric
organization ID, then reads `/orgs/{organization}/members` and
`/orgs/{organization}/outside_collaborators`. Fine-grained tokens require the
organization **Members: read** permission. Concealed members depend on caller
visibility; a public or empty list does not prove absence.
[GitHub members API](https://docs.github.com/en/rest/orgs/members),
[GitHub outside collaborators API](https://docs.github.com/en/rest/orgs/outside-collaborators)

For each explicitly selected repository, `/repos/{organization}/{repository}`
must return the configured organization as its stable owner before
`/collaborators?affiliation=all` is read. Output scope uses the numeric repository
ID. Fine-grained tokens need **Metadata: read**; GitHub also documents applicable
caller privileges. Collaborator results combine repository, team, organization,
and enterprise grants and cannot distinguish their source. Only positive
presence of the mapped numeric user ID becomes observed access; missing access
remains unknown. [GitHub collaborators API](https://docs.github.com/en/rest/collaborators/collaborators)

Invitations, additional organizations, team details, deploy keys, personal
tokens, OAuth grants, existing sessions, local clones, and downstream data copies
are outside the collected scope. The collector does not remove memberships,
revoke credentials, or alter repositories.

## Bounds and failure behavior

The transport verifies TLS using the standard public trust context, ignores
ambient proxy variables, follows no redirects, and sends only GET requests to
the fixed vendor origins. Tokens are never taken from page links. GitHub next
links must preserve the exact endpoint, original query parameters, and vendor
origin; only the page number may change. Invalid links, duplicate IDs, malformed
fields, HTTP denial, rate limits, and incomplete pagination produce unknown
observations with safe reason codes, without copying provider error bodies.

Default limits are ten pages, 1,000 records per membership collection, 32 total
requests, 256 KiB per decoded response, a five-second request timeout (three for
connect), and a 60-second collection deadline. Partial pages are never labeled
complete. The canonical import accepts at most 100 observations and 100 KB per
report; the collector checks both before writing. These limits intentionally
favor a bounded targeted assessment over a whole-tenant inventory.

Run the offline boundary suite with a fresh project-local temporary directory:

```powershell
$enterpriseTemp = Join-Path (Get-Location) ('output/enterprise-pytest-' + [guid]::NewGuid().ToString('N'))
& ./backend/.venv/Scripts/python.exe -m pytest integrations/tests/test_enterprise.py -q -p no:cacheprovider --basetemp $enterpriseTemp --junitxml=output/enterprise-tests.xml
```

These tests measure synthetic response parsing and denial behavior. They are
separate from live provider protocol evidence and from the connected local
Keycloak lab. A successful fixture run or minimized import cannot change that
distinction or satisfy an unresolved session/credential closure task.

After rebuilding and migrating the connected local lab, `Test-Lab.ps1` also runs
`scripts/live_cases.py`. It verifies the actual authenticated case lifecycle,
unique worker containment, native Keycloak SCIM observation, denied self-review
and stale closure, and an immutable administrative closure packet. Its external
imports and owner scope exclusions remain synthetic. JSON/JUnit results are
`output/connected/cases.*`; the optional public DTO capture is
`output/connected/connected-cases-snapshot.json`.
