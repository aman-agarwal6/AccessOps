import { useState } from "react";
import {
  ArrowRight,
  Bot,
  Check,
  ChevronRight,
  Clock3,
  Database,
  FileSearch,
  GitBranch,
  KeyRound,
  LogOut,
  Network,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Sparkles,
  Users,
} from "lucide-react";
import type { AccessRequest } from "../domain";
import {
  Empty,
  Panel,
  SearchField,
  Segmented,
  Status,
  Who,
  formatDate,
  timeAgo,
} from "../ui";
import type { Workspace } from "../workspace";

export const actionNames: Record<AccessRequest["action"], string> = {
  grant: "Grant access",
  revoke: "Revoke access",
  offboard: "Employee departure",
  transfer: "Transfer sponsorship",
  department_transfer: "Department transfer",
};
const activeGrant = (ws: Workspace, identityId: string) =>
  ws.data.grants.filter(
    (grant) =>
      grant.identityId === identityId &&
      grant.status === "active" &&
      (!grant.expiresAt || Date.parse(grant.expiresAt) > ws.now),
  ).length;

/* ================= Requests ================= */
type RequestFilter =
  "all" | "pending" | "approved" | "applied" | "verified" | "closed";
export function RequestsPage({ ws }: { ws: Workspace }) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<RequestFilter>(
    (["pending", "approved", "applied", "verified"] as string[]).includes(
      ws.initialFilter,
    )
      ? (ws.initialFilter as RequestFilter)
      : "all",
  );
  const matches = (request: AccessRequest, value: RequestFilter) =>
    value === "all" ||
    (value === "closed"
      ? ["failed", "expired"].includes(request.status)
      : request.status === value);
  const rows = ws.data.requests.filter(
    (request) =>
      matches(request, filter) &&
      `${request.id} ${ws.name(request.identityId)} ${ws.resource(request.resourceId)?.name} ${request.reason}`
        .toLowerCase()
        .includes(query.trim().toLowerCase()),
  );
  const count = (value: RequestFilter) =>
    ws.data.requests.filter((request) => matches(request, value)).length;
  return (
    <section className="panel" aria-labelledby="requests-title">
      <header className="panel-head">
        <div>
          <h2 id="requests-title">Change requests</h2>
          <p>
            Approval, enforcement and verification are separate states. A
            request never changes access by being submitted.
          </p>
        </div>
      </header>
      <div className="toolbar">
        <Segmented<RequestFilter>
          label="Filter requests by status"
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: "All", count: count("all") },
            { value: "pending", label: "Pending", count: count("pending") },
            { value: "approved", label: "Approved", count: count("approved") },
            { value: "applied", label: "Applied", count: count("applied") },
            { value: "verified", label: "Verified", count: count("verified") },
            {
              value: "closed",
              label: "Failed or expired",
              count: count("closed"),
            },
          ]}
        />
        <SearchField
          value={query}
          onChange={setQuery}
          label="Search people, requests or reasons"
        />
      </div>
      {rows.length ? (
        <div className="table-wrap">
          <table className="data">
            <caption className="sr-only">Access change requests</caption>
            <thead>
              <tr>
                <th scope="col">Identity</th>
                <th scope="col">Change</th>
                <th scope="col" className="hide-sm">
                  Resource
                </th>
                <th scope="col">Status</th>
                <th scope="col" className="hide-sm">
                  Requested
                </th>
                <th scope="col">
                  <span className="sr-only">Open</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((request) => (
                <tr key={request.id}>
                  <td>
                    <Who identity={ws.person(request.identityId)} />
                    <span className="id-chip">{request.id}</span>
                  </td>
                  <td>
                    <span className="change">
                      {request.action === "offboard" ? (
                        <LogOut size={15} aria-hidden="true" />
                      ) : request.action === "grant" ? (
                        <KeyRound size={15} aria-hidden="true" />
                      ) : (
                        <GitBranch size={15} aria-hidden="true" />
                      )}
                      {actionNames[request.action]}
                    </span>
                    {request.action === "offboard" && (
                      <span className="sub">Includes sponsored agents</span>
                    )}
                  </td>
                  <td className="hide-sm">
                    {ws.resource(request.resourceId)?.name ??
                      request.resourceId}
                  </td>
                  <td>
                    <Status value={request.status} />
                  </td>
                  <td className="hide-sm">
                    {ws.name(request.requesterId)}
                    <span className="sub">
                      {timeAgo(request.createdAt, ws.now)}
                    </span>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() =>
                        ws.select({ kind: "request", id: request.id })
                      }
                      aria-label={`Open request ${request.id}`}
                    >
                      Open
                      <ChevronRight size={15} aria-hidden="true" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty
          title="No requests match"
          action={
            <button
              className="btn btn-secondary"
              onClick={() => ws.openModal("request")}
              disabled={!ws.authenticated}
            >
              <Plus size={16} aria-hidden="true" />
              New request
            </button>
          }
        >
          Try another filter, or start an access change. Every change begins as
          a reviewable request.
        </Empty>
      )}
      <footer className="panel-foot">
        <span>Approved ≠ applied ≠ verified</span>
        <span>
          {rows.length} of {ws.data.requests.length} shown
        </span>
      </footer>
    </section>
  );
}

/* ================= Identities ================= */
type IdentityFilter = "all" | "human" | "agent";
export function IdentitiesPage({ ws }: { ws: Workspace }) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<IdentityFilter>(
    ws.initialFilter === "agent" || ws.initialFilter === "human"
      ? ws.initialFilter
      : "all",
  );
  const [probeIdentity, setProbeIdentity] = useState("atlas-agent");
  const [probeResource, setProbeResource] = useState("atlas");
  const rows = ws.data.identities.filter(
    (identity) =>
      (filter === "all" || identity.kind === filter) &&
      `${identity.name} ${identity.role} ${identity.department}`
        .toLowerCase()
        .includes(query.trim().toLowerCase()),
  );
  const attempt = ws.simulation.attempts[0];
  return (
    <div className="sections">
      <section className="panel" aria-labelledby="directory-title">
        <header className="panel-head">
          <div>
            <h2 id="directory-title">Directory</h2>
            <p>
              Status, access and sponsorship are evaluated together. Every agent
              has an accountable human sponsor.
            </p>
          </div>
        </header>
        <div className="toolbar">
          <Segmented<IdentityFilter>
            label="Identity type"
            value={filter}
            onChange={setFilter}
            options={[
              {
                value: "all",
                label: "Everyone",
                count: ws.data.identities.length,
              },
              {
                value: "human",
                label: "People",
                count: ws.data.identities.filter((i) => i.kind === "human")
                  .length,
              },
              {
                value: "agent",
                label: "Agents",
                count: ws.data.identities.filter((i) => i.kind === "agent")
                  .length,
              },
            ]}
          />
          <SearchField
            value={query}
            onChange={setQuery}
            label="Search names, roles or departments"
          />
        </div>
        {rows.length ? (
          <div className="table-wrap">
            <table className="data">
              <caption className="sr-only">Identity directory</caption>
              <thead>
                <tr>
                  <th scope="col">Identity</th>
                  <th scope="col" className="hide-sm">
                    Department
                  </th>
                  <th scope="col" className="hide-sm">
                    Accountable owner
                  </th>
                  <th scope="col">Active grants</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((identity) => (
                  <tr key={identity.id}>
                    <td>
                      <button
                        className="who"
                        onClick={() =>
                          ws.select({ kind: "identity", id: identity.id })
                        }
                      >
                        <Who identity={identity} />
                      </button>
                    </td>
                    <td className="hide-sm">{identity.department}</td>
                    <td className="hide-sm">
                      {identity.kind === "agent" ? (
                        <button
                          className="link-btn"
                          onClick={() =>
                            ws.select({
                              kind: "identity",
                              id: identity.sponsorId!,
                            })
                          }
                        >
                          {ws.name(identity.sponsorId)}
                        </button>
                      ) : (
                        <span className="muted">Self</span>
                      )}
                    </td>
                    <td>
                      <span className="count-chip">
                        {activeGrant(ws, identity.id)}
                      </span>
                    </td>
                    <td>
                      <Status value={identity.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No identities match" icon={<Users size={24} />}>
            Try a different name, role or identity type.
          </Empty>
        )}
      </section>
      {!ws.connected && (
        <Panel
          title="Try a protected read"
          description="The model checks identity status, sponsorship, grant expiry and policy before any simulated effect."
        >
          <div className="probe">
            <label className="field">
              Identity
              <select
                value={probeIdentity}
                onChange={(event) => setProbeIdentity(event.target.value)}
              >
                {ws.data.identities.map((identity) => (
                  <option key={identity.id} value={identity.id}>
                    {identity.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              Resource
              <select
                value={probeResource}
                onChange={(event) => setProbeResource(event.target.value)}
              >
                {ws.data.resources.map((resource) => (
                  <option key={resource.id} value={resource.id}>
                    {resource.name}
                  </option>
                ))}
              </select>
            </label>
            <button
              className="btn btn-primary"
              style={{ minHeight: 44 }}
              onClick={() =>
                void ws.perform({
                  type: "access",
                  identityId: probeIdentity,
                  resourceId: probeResource,
                })
              }
            >
              <Play size={15} aria-hidden="true" />
              Try simulated read
            </button>
          </div>
          {attempt && (
            <div
              className={`decision ${attempt.allowed ? "" : "deny"}`}
              role="status"
            >
              {attempt.allowed ? (
                <ShieldCheck size={20} aria-hidden="true" />
              ) : (
                <ShieldOff size={20} aria-hidden="true" />
              )}
              <div>
                <strong>
                  {attempt.allowed ? "Allowed" : "Denied before effect"} ·{" "}
                  {ws.name(attempt.identityId)}
                </strong>
                <p>{attempt.reason}</p>
              </div>
              <span>{attempt.effects} simulated effects</span>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}

/* ================= Reviews ================= */
export function ReviewsPage({ ws }: { ws: Workspace }) {
  return (
    <div className="sections">
      <div className="principle">
        <Sparkles size={22} aria-hidden="true" />
        <div>
          <strong>The assistant can propose. It cannot approve.</strong>
          <p>
            A bounded, deterministic review treats record contents as untrusted
            data. Grant and transfer proposals still need independent approval;
            containment needs an authorized human operator.
          </p>
        </div>
      </div>
      {ws.data.reviews.map((review) => (
        <Panel
          key={review.id}
          title={review.name}
          description={`${review.id} · assigned to ${ws.name(review.assignedTo)} · due ${formatDate(review.dueAt)}`}
          action={
            <button
              className="btn btn-primary"
              disabled={ws.busy}
              onClick={() => void ws.perform({ type: "review", id: review.id })}
            >
              <Sparkles size={15} aria-hidden="true" />
              {review.findings.length
                ? "Refresh review draft"
                : "Run bounded review"}
            </button>
          }
        >
          <div className="review-meta">
            <span>
              <Database size={15} aria-hidden="true" />
              {review.resourceIds.length} resources in scope
            </span>
            <span>
              <FileSearch size={15} aria-hidden="true" />
              {review.findings.length} findings
            </span>
            <Status value={review.status} />
          </div>
          {review.findings.length ? (
            <div className="findings">
              {review.findings.map((finding) => (
                <article className="finding" key={finding.id}>
                  <div className="row">
                    <Status value={finding.severity} />
                    <span
                      className="muted"
                      style={{ fontSize: "var(--fs-sm)" }}
                    >
                      {ws.name(finding.identityId)} ·{" "}
                      {ws.resource(finding.resourceId)?.name}
                    </span>
                  </div>
                  <h3>{finding.title}</h3>
                  <p>{finding.detail}</p>
                  <details className="task-evidence">
                    <summary>Inspect the supporting record</summary>
                    <blockquote>
                      {Array.isArray(finding.evidence)
                        ? finding.evidence.join("\n")
                        : finding.evidence}
                    </blockquote>
                    <p className="muted" style={{ marginTop: 8 }}>
                      Record contents are data, never instructions or approval
                      authority.
                    </p>
                  </details>
                  <div className="finding-foot">
                    {finding.id === "untrusted-note" ? (
                      <span className="safe-label">
                        <ShieldCheck size={15} aria-hidden="true" />
                        Excluded from the approval path
                      </span>
                    ) : finding.proposedRequestId ? (
                      <button
                        className="link-btn"
                        onClick={() =>
                          ws.select({
                            kind: "request",
                            id: finding.proposedRequestId!,
                          })
                        }
                      >
                        Inspect unapproved proposal {finding.proposedRequestId}
                        <ArrowRight size={15} aria-hidden="true" />
                      </button>
                    ) : (
                      <button
                        className="btn btn-secondary btn-sm"
                        disabled={ws.busy}
                        onClick={() =>
                          void ws.perform({
                            type: "propose",
                            reviewId: review.id,
                            findingId: finding.id,
                          })
                        }
                      >
                        <Plus size={14} aria-hidden="true" />
                        Draft revocation request
                      </button>
                    )}
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <Empty
              title="Ready for a bounded review"
              icon={<FileSearch size={24} />}
            >
              Run the review to compare grants and surface findings. The
              assistant has no approval or execution capability.
            </Empty>
          )}
        </Panel>
      ))}
      <Panel
        title="Provider drift"
        description="A membership that exists only in the provider is an observation, never an approved grant."
        action={
          <div className="row">
            {!ws.connected && (
              <button
                className="btn btn-secondary"
                onClick={() => void ws.perform({ type: "drift" })}
              >
                <Plus size={15} aria-hidden="true" />
                Inject synthetic drift
              </button>
            )}
            <button
              className="btn btn-primary"
              disabled={ws.busy}
              onClick={() => void ws.perform({ type: "reconcile" })}
            >
              <RefreshCw size={15} aria-hidden="true" />
              Reconcile access
            </button>
          </div>
        }
      >
        <p className="text-2">
          {ws.connected
            ? "Reconciliation records mismatches from the configured provider without silently authorizing them."
            : "Add an unapproved membership to the provider model, then detect it. AccessOps still denies a read without an active grant."}
        </p>
      </Panel>
    </div>
  );
}

/* ================= Policies ================= */
export function PoliciesPage({ ws }: { ws: Workspace }) {
  const outage = ws.data.health.some((entry) => entry.status === "unavailable");
  const icons = [Users, Bot, ShieldCheck];
  return (
    <div className="sections">
      <section aria-labelledby="rules-title">
        <div className="section-title">
          <h2 id="rules-title">Rules</h2>
          <p>Evaluated by OPA through an AuthZEN request on every action.</p>
        </div>
        <div className="policy-grid">
          {ws.data.policies.map((policy, index) => {
            const Icon = icons[index] ?? ShieldCheck;
            return (
              <article className="card policy-card" key={policy.id}>
                <header>
                  <span>
                    <Icon size={20} aria-hidden="true" />
                  </span>
                  <span className="pill">{policy.version}</span>
                </header>
                <h3>{policy.name}</h3>
                <p>{policy.description}</p>
                <ul className="rules">
                  {policy.rules.map((rule) => (
                    <li key={rule}>
                      <Check size={15} aria-hidden="true" />
                      <span>{rule}</span>
                    </li>
                  ))}
                </ul>
              </article>
            );
          })}
        </div>
      </section>
      <Panel
        title="Resources"
        description="Every permission names a resource, a purpose and an accountable owner."
      >
        <div className="resource-grid">
          {ws.data.resources.map((resource) => (
            <article className="resource" key={resource.id}>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
                  {resource.project}
                </span>
                <Status
                  value={
                    resource.sensitivity === "Restricted" ? "medium" : "neutral"
                  }
                >
                  {resource.sensitivity}
                </Status>
              </div>
              <h3>{resource.name}</h3>
              <p>{resource.description}</p>
              <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
                Owner · {ws.name(resource.ownerId)}
              </span>
            </article>
          ))}
        </div>
      </Panel>
      <Panel
        title={ws.connected ? "Service health" : "Failure behavior"}
        description={
          ws.connected
            ? "As reported by the connected backend."
            : "These controls change only the in-memory scenario."
        }
      >
        <ul className="health">
          {ws.data.health.map((entry) => (
            <li key={entry.name}>
              <span>
                <Network size={18} aria-hidden="true" />
              </span>
              <div>
                <strong>{entry.name}</strong>
                <p>{entry.detail}</p>
              </div>
              <Status value={entry.status} />
            </li>
          ))}
        </ul>
        {!ws.connected && (
          <div className="scenario-controls">
            <button
              className="btn btn-secondary"
              onClick={() =>
                void ws.perform({ type: "outage", enabled: !outage })
              }
            >
              <ShieldOff size={15} aria-hidden="true" />
              {outage ? "Restore policy service" : "Simulate policy outage"}
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => void ws.perform({ type: "advance" })}
            >
              <Clock3 size={15} aria-hidden="true" />
              Advance clock 16 minutes
            </button>
            <span>
              Scenario time: {formatDate(new Date(ws.now).toISOString())}
            </span>
          </div>
        )}
      </Panel>
    </div>
  );
}
