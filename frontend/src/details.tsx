import {
  ArrowDownToLine,
  ArrowRight,
  Check,
  ChevronRight,
  CircleAlert,
  FileCheck2,
  GitBranch,
  KeyRound,
  Network,
  Play,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  UserRound,
} from "lucide-react";
import { downloadJson } from "./api";
import {
  isContainment,
  type AccessRequest,
  type Identity,
  type Run,
} from "./domain";
import { actionNames } from "./pages/Governance";
import {
  Avatar,
  Callout,
  Drawer,
  FormError,
  Provenance,
  StateIcon,
  Status,
  formatDate,
} from "./ui";
import type { Workspace } from "./workspace";

export function RequestDrawer({
  ws,
  request,
  error,
  modal,
  onClose,
  refresh,
}: {
  ws: Workspace;
  request?: AccessRequest;
  error: string;
  modal: boolean;
  onClose: () => void;
  refresh: () => void;
}) {
  const containment = request ? isContainment(request) : false;
  const actor = ws.principal;
  return (
    <Drawer
      open={!!request}
      modal={modal}
      onClose={onClose}
      title={
        request ? `${request.id} · ${actionNames[request.action]}` : "Request"
      }
      description={
        ws.connected
          ? "Current server state. Approval and verification are separate."
          : "Browser simulation · the exact change and its decision trail"
      }
      wide
    >
      {request && (
        <>
          <div className="detail-head">
            <Avatar identity={ws.person(request.identityId)} />
            <div>
              <h3>{ws.name(request.identityId)}</h3>
              <p>{ws.person(request.identityId)?.role}</p>
            </div>
            <Status value={request.status} />
          </div>
          <div className="detail-section">
            <h3>Requested change</h3>
            <p className="reason">{request.reason}</p>
          </div>
          <dl className="kv">
            <div>
              <dt>Resource</dt>
              <dd>{ws.resource(request.resourceId)?.name}</dd>
            </div>
            <div>
              <dt>Permission</dt>
              <dd>
                {request.action === "offboard"
                  ? "All active grants revoked"
                  : (request.permission ?? "Existing permission")}
              </dd>
            </div>
            <div>
              <dt>Requested by</dt>
              <dd>{ws.name(request.requesterId)}</dd>
            </div>
            <div>
              <dt>Policy version</dt>
              <dd className="mono">{request.policyVersion}</dd>
            </div>
            {request.approverId && (
              <div>
                <dt>Approved by</dt>
                <dd>{ws.name(request.approverId)}</dd>
              </div>
            )}
            {request.approvalExpiresAt && (
              <div>
                <dt>Approval expires</dt>
                <dd>{formatDate(request.approvalExpiresAt)}</dd>
              </div>
            )}
            {request.newSponsorId && (
              <div>
                <dt>New sponsor</dt>
                <dd>{ws.name(request.newSponsorId)}</dd>
              </div>
            )}
            {request.action === "transfer" && (
              <div>
                <dt>Successor acceptance</dt>
                <dd>
                  {request.acceptedBy === request.newSponsorId
                    ? `Accepted by ${ws.name(request.acceptedBy)}`
                    : "Awaiting the named successor"}
                </dd>
              </div>
            )}
            {request.targetDepartment && (
              <div>
                <dt>Target department</dt>
                <dd>
                  {request.targetDepartment} · old department grants removed
                </dd>
              </div>
            )}
          </dl>
          {request.action === "offboard" && (
            <div className="detail-section">
              <h3>
                <Network
                  size={16}
                  aria-hidden="true"
                  style={{ verticalAlign: "-2px", marginRight: 6 }}
                />
                Linked identities
              </h3>
              <p
                className="text-2"
                style={{ fontSize: "var(--fs-sm)", marginBottom: 12 }}
              >
                A departure also suspends sponsored agents and revokes their
                grants. Reassigning them takes another reviewed change.
              </p>
              <div className="stack" style={{ gap: 8 }}>
                {ws.data.identities
                  .filter(
                    (identity) => identity.sponsorId === request.identityId,
                  )
                  .map((identity) => (
                    <button
                      className="linked"
                      key={identity.id}
                      onClick={() =>
                        ws.select({ kind: "identity", id: identity.id })
                      }
                    >
                      <Avatar identity={identity} size="sm" />
                      <span>
                        {identity.name}
                        <small>{identity.role}</small>
                      </span>
                      <Status value={identity.status} />
                      <ChevronRight size={15} aria-hidden="true" />
                    </button>
                  ))}
              </div>
            </div>
          )}
          <ol className="stages" aria-label="Request progress">
            {(containment
              ? ["authorized", "applied", "verified"]
              : ["approved", "applied", "verified"]
            ).map((stage, index) => {
              const order = ["pending", "approved", "applied", "verified"];
              const done = containment
                ? index < 2
                  ? ["applied", "verified"].includes(request.status)
                  : request.status === "verified"
                : order.indexOf(request.status) >= index + 1;
              return (
                <li key={stage} className={done ? "done" : ""}>
                  <span aria-hidden="true">
                    {done ? <Check size={14} /> : index + 1}
                  </span>
                  {stage}
                  <span className="sr-only">
                    {done ? " (done)" : " (not yet)"}
                  </span>
                </li>
              );
            })}
          </ol>
          <div className="detail-section">
            <h3>Decision timeline</h3>
            <ol className="timeline">
              {request.events.map((entry, index) => (
                <li key={`${entry.label}-${index}`}>
                  <span aria-hidden="true">
                    <StateIcon status={entry.status} />
                  </span>
                  <div>
                    <strong>{entry.label}</strong>
                    <p>{entry.detail}</p>
                    <small>{formatDate(entry.at)}</small>
                  </div>
                </li>
              ))}
            </ol>
          </div>
          <div className="decision-box">
            <FormError message={error} />
            <h3>
              {request.status === "pending"
                ? containment
                  ? "Authorized containment"
                  : "Independent review required"
                : request.status === "approved"
                  ? "Approved, ready to apply"
                  : request.status === "applied"
                    ? "Applied, awaiting observation"
                    : request.status === "verified"
                      ? "Verification recorded"
                      : "A fresh decision is needed"}
            </h3>
            <p>
              {request.status === "pending"
                ? containment
                  ? "An authorized operator can remove access immediately. Containment is audited and does not wait for a second approval."
                  : "Approval covers the exact identity, resource, action, reason and policy version for 15 minutes."
                : request.status === "approved"
                  ? "Applying rechecks the approval, identity and policy. Access has not changed yet."
                  : request.status === "applied"
                    ? "AccessOps authorization has changed. Provider delivery and revocation evidence are still separate."
                    : request.status === "verified"
                      ? ws.connected
                        ? "Inspect the run record for the actual checks and their limits."
                        : "Only the browser provider model was checked. Real token and session revocation needs local-run evidence."
                      : "Expired or failed requests cannot silently regain approval."}
            </p>
            <div className="row">
              {request.status === "pending" && containment && (
                <button
                  className="btn btn-primary"
                  disabled={ws.busy}
                  onClick={() =>
                    void ws.perform({ type: "execute", id: request.id })
                  }
                >
                  <ShieldOff size={16} aria-hidden="true" />
                  Apply containment
                </button>
              )}
              {request.status === "pending" && !containment && (
                <>
                  {request.action === "transfer" &&
                    request.acceptedBy !== request.newSponsorId && (
                      <button
                        className="btn btn-secondary"
                        disabled={ws.busy}
                        onClick={() =>
                          void ws.perform({ type: "accept", id: request.id })
                        }
                      >
                        <UserRound size={16} aria-hidden="true" />
                        Accept sponsorship
                      </button>
                    )}
                  <button
                    className="btn btn-primary"
                    disabled={ws.busy}
                    onClick={() =>
                      void ws.perform({ type: "approve", id: request.id })
                    }
                  >
                    <ShieldCheck size={16} aria-hidden="true" />
                    Approve exact change
                  </button>
                </>
              )}
              {request.status === "approved" && (
                <button
                  className="btn btn-primary"
                  disabled={ws.busy}
                  onClick={() =>
                    void ws.perform({ type: "execute", id: request.id })
                  }
                >
                  <Play size={15} aria-hidden="true" />
                  Apply approved change
                </button>
              )}
              {request.status === "applied" &&
                (!ws.connected ? (
                  <button
                    className="btn btn-primary"
                    onClick={() =>
                      void ws.perform({ type: "verify", id: request.id })
                    }
                  >
                    <FileCheck2 size={16} aria-hidden="true" />
                    Check simulated provider
                  </button>
                ) : (
                  <button
                    className="btn btn-secondary"
                    onClick={refresh}
                    disabled={ws.busy}
                  >
                    <RefreshCw size={15} aria-hidden="true" />
                    Refresh provider outcome
                  </button>
                ))}
              {request.status === "verified" && (
                <button
                  className="btn btn-secondary"
                  onClick={() => {
                    onClose();
                    ws.go("runs");
                  }}
                >
                  Inspect evidence
                  <ArrowRight size={15} aria-hidden="true" />
                </button>
              )}
            </div>
            {ws.actAs &&
              request.status === "pending" &&
              !containment &&
              actor?.id !== "op-avery" && (
                <div className="role-hint">
                  <UserRound size={16} aria-hidden="true" />
                  <span>Approval needs an independent reviewer.</span>
                  <button
                    className="link-btn"
                    onClick={() => ws.actAs?.("op-avery")}
                  >
                    Switch to Avery, reviewer
                    <ArrowRight size={14} aria-hidden="true" />
                  </button>
                </div>
              )}
            {ws.actAs &&
              request.status === "pending" &&
              request.action === "transfer" &&
              request.newSponsorId === "nina" &&
              actor?.id !== "nina" && (
                <div className="role-hint">
                  <UserRound size={16} aria-hidden="true" />
                  <span>The named successor must accept responsibility.</span>
                  <button
                    className="link-btn"
                    onClick={() => ws.actAs?.("nina")}
                  >
                    Switch to Nina, successor
                    <ArrowRight size={14} aria-hidden="true" />
                  </button>
                </div>
              )}
          </div>
        </>
      )}
    </Drawer>
  );
}

export function IdentityDrawer({
  ws,
  identity,
  onClose,
  onTransfer,
}: {
  ws: Workspace;
  identity?: Identity;
  onClose: () => void;
  onTransfer: (id: string) => void;
}) {
  const grants = identity
    ? ws.data.grants.filter((grant) => grant.identityId === identity.id)
    : [];
  const sponsored = identity
    ? ws.data.identities.filter((entry) => entry.sponsorId === identity.id)
    : [];
  return (
    <Drawer
      open={!!identity}
      onClose={onClose}
      title={identity?.name ?? "Identity"}
      description="Current access, sponsorship and lifecycle state"
    >
      {identity && (
        <>
          <div className="detail-head">
            <Avatar identity={identity} size="lg" />
            <div>
              <h3>
                {identity.kind === "agent"
                  ? "Agent identity"
                  : "Human identity"}
              </h3>
              <p>{identity.role}</p>
            </div>
            <Status value={identity.status} />
          </div>
          <dl className="kv">
            <div>
              <dt>Department</dt>
              <dd>{identity.department}</dd>
            </div>
            <div>
              <dt>Accountable owner</dt>
              <dd>
                {identity.kind === "agent"
                  ? ws.name(identity.sponsorId)
                  : "Self"}
              </dd>
            </div>
            <div>
              <dt>Stable subject</dt>
              <dd className="mono">
                {identity.providerSubject ?? identity.id}
              </dd>
            </div>
            <div>
              <dt>Updated</dt>
              <dd>{formatDate(identity.updatedAt)}</dd>
            </div>
            {identity.projectIds && (
              <div>
                <dt>Projects</dt>
                <dd>{identity.projectIds.join(", ")}</dd>
              </div>
            )}
            {identity.providerBinding && (
              <div>
                <dt>Provider binding</dt>
                <dd>{identity.providerBinding}</dd>
              </div>
            )}
            {identity.kind === "agent" && identity.credentialBinding && (
              <div>
                <dt>Agent credential binding</dt>
                <dd>{identity.credentialBinding.replaceAll("-", " ")}</dd>
              </div>
            )}
          </dl>
          {identity.kind === "human" && identity.status === "active" && (
            <button
              className="btn btn-secondary"
              onClick={() => onTransfer(identity.id)}
            >
              <GitBranch size={15} aria-hidden="true" />
              Request department transfer
            </button>
          )}
          {identity.kind === "agent" && identity.status === "suspended" && (
            <Callout
              tone="warn"
              icon={<ShieldOff size={18} aria-hidden="true" />}
            >
              Recovery needs a reviewed credential binding and a separately
              approved grant. A sponsor change does not reactivate this agent.
            </Callout>
          )}
          <div className="detail-section">
            <h3>Access grants</h3>
            {grants.length ? (
              <div className="grant-list">
                {grants.map((grant) => (
                  <article className="grant" key={grant.id}>
                    <header>
                      <strong>{ws.resource(grant.resourceId)?.name}</strong>
                      <Status value={grant.status} />
                    </header>
                    {grant.purpose && <p>{grant.purpose}</p>}
                    <dl className="kv">
                      <div>
                        <dt>Permission</dt>
                        <dd>{grant.permission}</dd>
                      </div>
                      <div>
                        <dt>Expires</dt>
                        <dd>{formatDate(grant.expiresAt)}</dd>
                      </div>
                      {grant.maxCalls !== undefined && (
                        <div>
                          <dt>Call budget</dt>
                          <dd>
                            {grant.callsUsed ?? 0} / {grant.maxCalls} used
                          </dd>
                        </div>
                      )}
                      <div>
                        <dt>Approval source</dt>
                        <dd className="mono">
                          {!ws.connected &&
                          grant.sourceRequestId?.startsWith("baseline-")
                            ? `Baseline fixture · ${grant.sourceRequestId}`
                            : (grant.sourceRequestId ?? "Missing provenance")}
                        </dd>
                      </div>
                    </dl>
                    {!ws.connected && (
                      <button
                        className="link-btn"
                        onClick={() =>
                          void ws.perform({
                            type: "access",
                            identityId: identity.id,
                            resourceId: grant.resourceId,
                          })
                        }
                      >
                        <Play size={13} aria-hidden="true" />
                        Try a simulated read
                      </button>
                    )}
                  </article>
                ))}
              </div>
            ) : (
              <p className="quiet">
                <KeyRound size={18} aria-hidden="true" />
                No grants are assigned to this identity.
              </p>
            )}
          </div>
          {sponsored.length > 0 && (
            <div className="detail-section">
              <h3>Sponsored agents</h3>
              <div className="stack" style={{ gap: 8 }}>
                {sponsored.map((agent) => (
                  <button
                    key={agent.id}
                    className="linked"
                    onClick={() =>
                      ws.select({ kind: "identity", id: agent.id })
                    }
                  >
                    <Avatar identity={agent} size="sm" />
                    <span>
                      {agent.name}
                      <small>{agent.role}</small>
                    </span>
                    <Status value={agent.status} />
                    <ChevronRight size={15} aria-hidden="true" />
                  </button>
                ))}
              </div>
            </div>
          )}
          {!ws.connected && (
            <p className="muted" style={{ fontSize: "var(--fs-sm)" }}>
              Synthetic identity. No account credentials or real personal
              records exist in this demo.
            </p>
          )}
        </>
      )}
    </Drawer>
  );
}

export function RunDrawer({
  run,
  onClose,
}: {
  run?: Run;
  onClose: () => void;
}) {
  const manifest = run?.manifest;
  const limitations =
    manifest &&
    typeof manifest === "object" &&
    "limitations" in manifest &&
    Array.isArray(manifest.limitations)
      ? manifest.limitations
          .filter(
            (value): value is string =>
              typeof value === "string" &&
              value.trim().length > 0 &&
              value.length <= 4000,
          )
          .slice(0, 30)
      : [];
  const counts = run
    ? {
        passed: run.checks.filter((check) => check.status === "passed").length,
        failed: run.checks.filter((check) => check.status === "failed").length,
        skipped: run.checks.filter((check) => check.status === "skipped")
          .length,
      }
    : { passed: 0, failed: 0, skipped: 0 };
  return (
    <Drawer
      open={!!run}
      onClose={onClose}
      title={run?.name ?? "Run"}
      description={
        run
          ? `${run.origin === "recorded" ? "Recorded local execution" : "Connected execution"} · ${run.id}`
          : "Evidence"
      }
      wide
    >
      {run && (
        <>
          <div className="row">
            <Status value={run.status} />
            <Provenance
              kind="observed"
              label={
                run.origin === "recorded"
                  ? "Recorded lab run (unsigned)"
                  : "Connected lab run"
              }
            />
            <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
              {formatDate(run.startedAt)}
            </span>
          </div>
          <p className="reason">{run.summary}</p>
          <div className="row">
            <span className="pill ok">{counts.passed} passed</span>
            <span className={`pill ${counts.failed ? "danger" : ""}`}>
              {counts.failed} failed
            </span>
            <span className="pill">{counts.skipped} skipped</span>
          </div>
          {limitations.length > 0 && (
            <div className="detail-section">
              <h3>Scope and limitations</h3>
              <ul className="limits">
                {limitations.map((line, index) => (
                  <li key={index}>
                    <CircleAlert size={13} aria-hidden="true" />
                    <span>{line}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="detail-section">
            <h3>Executed checks</h3>
            <div className="checks">
              {run.checks.map((check, index) => (
                <div
                  className={`check ${check.status}`}
                  key={`${check.name}-${index}`}
                >
                  <span aria-hidden="true">
                    <StateIcon status={check.status} />
                  </span>
                  <div>
                    <strong>{check.name}</strong>
                    <p>{check.detail}</p>
                  </div>
                  <Status value={check.status} />
                </div>
              ))}
            </div>
          </div>
          <button
            className="btn btn-secondary"
            onClick={() =>
              downloadJson(
                `accessops-${run.id.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`,
                run,
              )
            }
          >
            <ArrowDownToLine size={15} aria-hidden="true" />
            Download this run record
          </button>
          <details className="disclosure">
            <summary>Inspect the serialized record</summary>
            <div className="disclosure-body">
              <pre
                className="code-block"
                tabIndex={0}
                role="region"
                aria-label="Serialized run record"
              >
                {JSON.stringify(run, null, 2)}
              </pre>
            </div>
          </details>
        </>
      )}
    </Drawer>
  );
}
