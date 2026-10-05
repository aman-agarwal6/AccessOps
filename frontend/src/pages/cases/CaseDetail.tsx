import {
  ArrowLeft,
  CalendarClock,
  Check,
  CheckCheck,
  CircleAlert,
  ClipboardCheck,
  Download,
  FileInput,
  Hourglass,
  Lock,
  PenLine,
  RefreshCw,
  ShieldOff,
  TriangleAlert,
  Upload,
  UserRound,
  Webhook,
} from "lucide-react";
import {
  isNative,
  nextStep,
  phaseTasks,
  progress,
  sla,
  taskProvenance,
  type NextStep,
  type StepAction,
} from "../../caseflow";
import { operators } from "../../domain";
import { platformNames, type OffboardingCase } from "../../offboarding";
import {
  Avatar,
  Callout,
  Provenance,
  Ring,
  Status,
  formatDate,
  provenance,
  type ProvenanceKind,
} from "../../ui";
import type { Workspace } from "../../workspace";
import { openCase } from "./route";

const stepIcons: Record<NextStep["stage"], typeof ShieldOff> = {
  closed: CheckCheck,
  scheduled: CalendarClock,
  contain: ShieldOff,
  observe: RefreshCw,
  import: FileInput,
  attest: PenLine,
  refresh: TriangleAlert,
  review: ClipboardCheck,
};
const platformMarks: Record<string, string> = {
  accessops: "AO",
  keycloak: "KC",
  entra: "EN",
  github: "GH",
  m365: "365",
  legacy: "AD",
};

export function CaseDetail({
  ws,
  item,
  notice,
  onAction,
}: {
  ws: Workspace;
  item: OffboardingCase;
  notice: string;
  onAction: (kind: StepAction, taskId?: string) => void;
}) {
  const person = ws.person(item.identityId);
  const due = sla(item, ws.now);
  const ownerName = ws.name(item.ownerId);
  const step = nextStep(item, ws.now, ws.principal, ownerName, ws.connected);
  const { done, total, remaining } = progress(item);
  const closed = item.status === "closed";
  const operator = !!ws.principal?.roles.includes("operator");
  const isOwner = ws.principal?.id === item.ownerId;
  const future = Date.parse(item.effectiveAt) > ws.now;
  const containment = item.tasks.find(
    (task) => task.id === "local-containment",
  );
  const legend: ProvenanceKind[] = [
    ws.connected ? "observed" : "simulated",
    "imported",
    "attested",
    "pending",
  ];
  const switchTarget =
    step.needs === "reviewer"
      ? operators.find(
          (entry) =>
            entry.roles.includes("reviewer") &&
            entry.id !== item.ownerId &&
            !item.tasks.some((task) => task.submittedById === entry.id),
        )
      : step.needs === "owner"
        ? operators.find((entry) => entry.id === item.ownerId)
        : operators.find((entry) => entry.roles.includes("operator"));
  const StepIcon = stepIcons[step.stage];

  return (
    <div>
      <a
        className="back-link"
        href="#/cases"
        onClick={(event) => {
          event.preventDefault();
          openCase();
        }}
      >
        <ArrowLeft size={16} aria-hidden="true" />
        All departure cases
      </a>

      <header className="case-head">
        <Avatar identity={person} name={item.title} size="lg" />
        <div className="case-head-main">
          <div className="row">
            <span className="eyebrow">
              {item.employmentType === "contractor" ? "Contractor" : "Employee"}{" "}
              departure · {item.hrEventId}
            </span>
            <span data-testid="case-status">
              <Status
                value={due.kind === "scheduled" ? "scheduled" : item.status}
              />
            </span>
            {!closed && (
              <span
                className={`pill ${due.kind === "overdue" ? "danger" : due.kind === "soon" ? "warn" : due.kind === "scheduled" ? "accent" : ""}`}
              >
                <Hourglass size={13} aria-hidden="true" />
                {due.label}
              </span>
            )}
          </div>
          <h1 style={{ marginTop: 6 }}>{person?.name ?? item.title}</h1>
          <div className="case-meta">
            <span>
              <CalendarClock size={15} aria-hidden="true" />
              Effective {formatDate(item.effectiveAt)}
            </span>
            <span>
              <Hourglass size={15} aria-hidden="true" />
              Target {formatDate(item.dueAt)}
            </span>
            <span>
              <UserRound size={15} aria-hidden="true" />
              Owner {ownerName}
            </span>
            {item.intakeSourceId && (
              <span>
                <Webhook size={15} aria-hidden="true" />
                Opened and contained automatically by{" "}
                {ws.name(item.intakeSourceId)}
              </span>
            )}
            <span className="muted">
              {item.hrSource} · revision {item.revision}
            </span>
          </div>
          {item.reason && <p className="case-reason">{item.reason}</p>}
        </div>
        <button
          className="btn btn-secondary"
          disabled={ws.busy}
          onClick={() => void ws.exportPacket(item.id)}
        >
          <Download size={16} aria-hidden="true" />
          {closed ? "Export closure packet" : "Export draft packet"}
        </button>
      </header>

      {notice && (
        <div style={{ marginBottom: 16 }}>
          <Callout
            tone="ok"
            role="status"
            icon={<Check size={18} aria-hidden="true" />}
          >
            {notice}
          </Callout>
        </div>
      )}

      <section
        className={`next-step ${step.tone === "done" ? "done" : step.tone === "waiting" ? "waiting" : ""}`}
        aria-labelledby="next-step-title"
      >
        <span className="next-icon" aria-hidden="true">
          <StepIcon size={24} />
        </span>
        <div>
          <span className="eyebrow">
            {step.tone === "done"
              ? "Complete"
              : step.tone === "waiting"
                ? "Waiting"
                : "Next step"}
          </span>
          <h2 id="next-step-title">{step.title}</h2>
          <p>{step.detail}</p>
          {step.blockedBy && (
            <p className="hint">
              <Lock size={14} aria-hidden="true" />
              {step.blockedBy}
            </p>
          )}
        </div>
        <div className="next-actions">
          {step.blockedBy && ws.actAs && switchTarget && (
            <button
              className="btn btn-secondary"
              onClick={() => ws.actAs?.(switchTarget.id)}
            >
              <UserRound size={16} aria-hidden="true" />
              Act as {switchTarget.name}
            </button>
          )}
          {step.action && (
            <button
              className={`btn ${step.blockedBy ? "btn-secondary" : "btn-primary"} btn-lg`}
              disabled={ws.busy || !!step.blockedBy}
              onClick={() => onAction(step.action!.kind, step.action!.taskId)}
            >
              {step.action.label}
            </button>
          )}
        </div>
      </section>

      <div className="case-layout">
        <section className="panel" aria-labelledby="actions-title">
          <header className="panel-head">
            <div>
              <h2 id="actions-title">Required actions</h2>
              <p>
                {done} of {total} accounted for. Every action keeps its owner,
                target and evidence source.
              </p>
            </div>
            <button
              className="btn btn-secondary"
              disabled={ws.busy || closed || !operator || !item.bindings.length}
              onClick={() => onAction("import")}
            >
              <Upload size={16} aria-hidden="true" />
              Import platform report
            </button>
          </header>
          {phaseTasks(item).map((phase, phaseIndex) => {
            const phaseDone = phase.tasks.filter(
              (task) => task.status !== "pending",
            ).length;
            return (
              <div className="phase" key={phase.id}>
                <div className="phase-head">
                  <span className="phase-no" aria-hidden="true">
                    {phaseIndex + 1}
                  </span>
                  <h3>{phase.title}</h3>
                  <span>
                    {phaseDone}/{phase.tasks.length}
                  </span>
                </div>
                <ul>
                  {phase.tasks.map((task) => {
                    const kind = taskProvenance(task, ws.connected);
                    const native = isNative(task.id);
                    const canAttest =
                      !native &&
                      !closed &&
                      task.status !== "observed" &&
                      operator &&
                      isOwner &&
                      !future;
                    return (
                      <li
                        key={task.id}
                        className={`task ${task.status === "observed" ? "done" : task.status === "attested" ? "attested" : ""}`}
                        style={{ listStyle: "none" }}
                      >
                        <span className="task-state" aria-hidden="true">
                          {task.status === "observed" ? (
                            <Check size={16} />
                          ) : task.status === "attested" ? (
                            <PenLine size={14} />
                          ) : null}
                        </span>
                        <div className="task-body">
                          <h4>{task.title}</h4>
                          <div className="task-meta">
                            <span>
                              {task.id === "ad-directory"
                                ? "Samba AD lab"
                                : platformNames[task.platform]}
                            </span>
                            <span className="dot-sep">{task.boundary}</span>
                            <span className="dot-sep">
                              {task.status === "pending"
                                ? "Unresolved"
                                : task.status === "attested"
                                  ? "Attested"
                                  : "Observed"}
                            </span>
                          </div>
                          <div>
                            <Provenance
                              kind={kind}
                              label={
                                kind === "simulated"
                                  ? "Simulated observation"
                                  : undefined
                              }
                            />
                          </div>
                          {task.evidenceSummary && (
                            <p className="task-summary">
                              {task.evidenceSummary}
                            </p>
                          )}
                          {task.evidenceReference && (
                            <details className="task-evidence">
                              <summary>
                                Evidence details
                                {task.observedAt
                                  ? ` · read ${formatDate(task.observedAt)}`
                                  : task.completedAt
                                    ? ` · recorded ${formatDate(task.completedAt)}`
                                    : ""}
                              </summary>
                              <div>
                                <span>Reference</span>
                                <code className="hash">
                                  {task.evidenceReference}
                                </code>
                                {task.submittedById && (
                                  <span>
                                    Statement by {ws.name(task.submittedById)}.
                                    Reviewed as an owner attestation, not
                                    provider proof.
                                  </span>
                                )}
                              </div>
                            </details>
                          )}
                        </div>
                        <div className="task-actions">
                          {task.id === "keycloak-directory" &&
                            item.containmentRequestId &&
                            !closed && (
                              <button
                                className="btn btn-ghost btn-sm"
                                disabled={ws.busy || !operator}
                                onClick={() => onAction("reconcile")}
                              >
                                <RefreshCw size={14} aria-hidden="true" />
                                Read again
                              </button>
                            )}
                          {task.id === "ad-directory" &&
                            ws.connected &&
                            item.adBinding &&
                            !closed && (
                              <button
                                className="btn btn-ghost btn-sm"
                                disabled={
                                  ws.busy ||
                                  !operator ||
                                  future ||
                                  containment?.status !== "observed"
                                }
                                onClick={() => onAction("observeDirectory")}
                              >
                                <RefreshCw size={14} aria-hidden="true" />
                                Refresh directory
                              </button>
                            )}
                          {canAttest && (
                            <button
                              className={`btn btn-sm ${step.stage === "attest" ? "btn-secondary" : "btn-ghost"}`}
                              disabled={ws.busy}
                              onClick={() => onAction("attest", task.id)}
                            >
                              <PenLine size={14} aria-hidden="true" />
                              {task.status === "pending"
                                ? "Record owner evidence"
                                : "Update owner evidence"}
                            </button>
                          )}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </div>
            );
          })}
        </section>

        <aside
          className="case-rail"
          aria-label="Closure readiness and evidence"
        >
          <section className="card rail-card" aria-labelledby="readiness-title">
            <div className="readiness">
              <Ring
                value={done}
                total={total}
                label={`${done} of ${total} actions accounted for`}
              />
              <div>
                <h3 id="readiness-title">
                  {closed ? "Closed" : "Closure readiness"}
                </h3>
                <p>
                  {closed
                    ? `Reviewed by ${ws.name(item.closedById)} · ${formatDate(item.closedAt)}`
                    : item.blockers.length
                      ? `${item.blockers.length} blocker${item.blockers.length === 1 ? "" : "s"} keep this case open`
                      : "No blockers. Ready for an independent reviewer."}
                </p>
              </div>
            </div>
            {!closed && item.blockers.length > 0 && (
              <ul className="blockers">
                {item.blockers.slice(0, 6).map((line) => (
                  <li key={line}>
                    <CircleAlert size={15} aria-hidden="true" />
                    <span>{line}</span>
                  </li>
                ))}
                {item.blockers.length > 6 && (
                  <li>
                    <span />
                    <span className="muted">
                      and {item.blockers.length - 6} more
                    </span>
                  </li>
                )}
              </ul>
            )}
            {!closed && (
              <p
                className="muted"
                style={{ marginTop: 12, fontSize: "var(--fs-xs)" }}
              >
                {remaining} unresolved
                {due.kind === "overdue" ? " · past the four-hour target" : ""}.
                The owner and evidence submitters cannot close their own case.
              </p>
            )}
          </section>

          <section className="card rail-card" aria-labelledby="legend-title">
            <h3 id="legend-title">How much each source proves</h3>
            <p>Strongest first. Labels never change once recorded.</p>
            <ul className="legend">
              {legend.map((kind) => (
                <li key={kind}>
                  <Provenance
                    kind={kind}
                    label={
                      kind === "simulated" ? "Simulated observation" : undefined
                    }
                  />
                  <p>{provenance[kind].meaning}</p>
                </li>
              ))}
            </ul>
          </section>

          <section className="card rail-card" aria-labelledby="coverage-title">
            <h3 id="coverage-title">Platform coverage</h3>
            <ul className="coverage">
              {(
                [
                  "accessops",
                  "keycloak",
                  "entra",
                  "github",
                  "m365",
                  "legacy",
                ] as const
              ).map((platform) => {
                const tasks = item.tasks.filter(
                  (task) => task.platform === platform,
                );
                if (!tasks.length) return null;
                const covered = tasks.filter(
                  (task) => task.status !== "pending",
                ).length;
                const binding = item.bindings.find(
                  (entry) => entry.provider === platform,
                );
                return (
                  <li key={platform}>
                    <span className="platform-mark" aria-hidden="true">
                      {platformMarks[platform]}
                    </span>
                    <span>
                      {platform === "legacy" && item.adBinding
                        ? "Samba AD lab & legacy apps"
                        : platformNames[platform]}
                      <small>
                        {platform === "keycloak" || platform === "accessops"
                          ? ws.connected
                            ? "Connected lab"
                            : "Simulated in this tab"
                          : binding
                            ? "Bound account · snapshot"
                            : platform === "legacy" && item.adBinding
                              ? "Trusted enrollment"
                              : "Owner evidence"}
                      </small>
                    </span>
                    <span className="num">
                      {covered}/{tasks.length}
                    </span>
                  </li>
                );
              })}
            </ul>
          </section>

          <details className="disclosure">
            <summary>Imported snapshots · {item.imports.length}</summary>
            <div className="disclosure-body import-list">
              {item.imports.length ? (
                item.imports.map((entry) => (
                  <div key={entry.id} className="stack" style={{ gap: 6 }}>
                    <strong style={{ color: "var(--text)" }}>
                      {entry.platform === "mixed"
                        ? "Entra + GitHub"
                        : platformNames[entry.platform]}{" "}
                      · {entry.recordCount} readings
                    </strong>
                    <span>
                      Captured {formatDate(entry.capturedAt)} ·{" "}
                      {entry.collectionMethod.replaceAll("_", " ")}
                    </span>
                    <code className="hash">{entry.sha256}</code>
                    <ul className="limits">
                      {entry.limitations.map((line) => (
                        <li key={line}>
                          <CircleAlert size={12} aria-hidden="true" />
                          <span>{line}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))
              ) : (
                <p>No platform report has been imported.</p>
              )}
            </div>
          </details>

          <details className="disclosure">
            <summary>
              Bound account IDs ·{" "}
              {item.bindings.length + (item.adBinding ? 1 : 0)}
            </summary>
            <div className="disclosure-body">
              <dl className="kv" style={{ gridTemplateColumns: "1fr" }}>
                {item.bindings.map((binding) => (
                  <div key={binding.provider}>
                    <dt>{platformNames[binding.provider]}</dt>
                    <dd className="hash">
                      {binding.provider === "entra" ? "Tenant" : "Org"}{" "}
                      {binding.tenantId}
                      <br />
                      Account {binding.subjectId}
                    </dd>
                  </div>
                ))}
                {item.adBinding && (
                  <div>
                    <dt>
                      {ws.connected
                        ? "Samba AD lab (server-enrolled)"
                        : "Simulated directory scope"}
                    </dt>
                    <dd className="hash">
                      Domain {item.adBinding.domainGuid}
                      <br />
                      Account {item.adBinding.userGuid}
                      <br />
                      {item.adBinding.groupGuids.length} enrolled group scopes ·
                      read only
                    </dd>
                  </div>
                )}
              </dl>
              <p style={{ marginTop: 12 }}>
                Accounts are matched only by immutable IDs, never by name or
                email.
              </p>
            </div>
          </details>

          <details className="disclosure">
            <summary>Evidence limits</summary>
            <div className="disclosure-body">
              <ul className="limits">
                {item.evidenceLimitations.map((line) => (
                  <li key={line}>
                    <CircleAlert size={12} aria-hidden="true" />
                    <span>{line}</span>
                  </li>
                ))}
              </ul>
            </div>
          </details>
        </aside>
      </div>
    </div>
  );
}
