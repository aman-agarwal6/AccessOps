import {
  Activity,
  AlarmClock,
  ArrowRight,
  BadgeCheck,
  ClipboardCheck,
  FileCheck2,
  ListChecks,
  Play,
  ShieldOff,
  UserMinus,
} from "lucide-react";
import { auditSummary } from "../presentation";
import { byUrgency, nextStep, progress, sla } from "../caseflow";
import { Avatar, Empty, Panel, Status, formatDate, timeAgo } from "../ui";
import type { Workspace } from "../workspace";
import { openCase } from "./cases/route";

export function Overview({ ws }: { ws: Workspace }) {
  const open = ws.cases.filter((item) => item.status !== "closed");
  const overdue = open.filter((item) => sla(item, ws.now).kind === "overdue");
  const unresolved = open.reduce(
    (count, item) => count + progress(item).remaining,
    0,
  );
  const ready = open.filter(
    (item) =>
      nextStep(item, ws.now, ws.principal, "", ws.connected).stage === "review",
  );
  const attention = [...open].sort(byUrgency(ws.now)).slice(0, 5);
  const guided = ws.cases.find((item) => item.id === "case-hr-1084");
  const inFlight = ws.data.requests.filter((request) =>
    ["pending", "approved", "applied", "failed"].includes(request.status),
  );
  const passed = ws.recorded.filter((run) => run.status === "passed").length;
  const failed = ws.recorded.filter((run) => run.status === "failed").length;

  return (
    <div className="sections">
      {!ws.connected && (
        <section className="hero" aria-labelledby="hero-title">
          <div>
            <span className="eyebrow">Employee and contractor offboarding</span>
            <h2 id="hero-title" style={{ marginTop: 8 }}>
              Someone leaves. Every system is accounted for.
            </h2>
            <p>
              AccessOps turns an HR departure into a case with an owner, a
              deadline and the evidence needed to close it. Containment is
              immediate; closure needs an independent reviewer.
            </p>
            <div className="hero-actions">
              <button
                className="btn btn-primary btn-lg"
                onClick={() => openCase(guided?.id)}
              >
                <UserMinus size={18} aria-hidden="true" />
                Work Mara's departure
                <ArrowRight size={18} aria-hidden="true" />
              </button>
              <button
                className="btn btn-secondary btn-lg"
                onClick={ws.startGuide}
              >
                <Play size={16} aria-hidden="true" />
                Containment walkthrough
              </button>
            </div>
            <p className="hero-note">
              Synthetic data, in this tab only. Reset anytime from the top bar.
            </p>
          </div>
          <ol className="lifecycle" aria-label="How a departure is closed">
            <li>
              <span>
                <ShieldOff size={20} aria-hidden="true" />
              </span>
              <div>
                <strong>Contain</strong>
                <small>
                  Revoke grants and suspend sponsored agents immediately.
                </small>
              </div>
            </li>
            <li>
              <span>
                <ListChecks size={20} aria-hidden="true" />
              </span>
              <div>
                <strong>Account for every system</strong>
                <small>
                  Directory reads, imported snapshots and owner statements stay
                  labeled by source.
                </small>
              </div>
            </li>
            <li>
              <span>
                <BadgeCheck size={20} aria-hidden="true" />
              </span>
              <div>
                <strong>Close independently</strong>
                <small>
                  A second person accepts the exact evidence packet.
                </small>
              </div>
            </li>
          </ol>
        </section>
      )}

      <section aria-label="Offboarding at a glance" className="stats">
        <button className="stat" onClick={() => ws.go("cases", "open")}>
          <span className="stat-label">
            Open departures
            <UserMinus size={18} aria-hidden="true" />
          </span>
          <strong>{open.length}</strong>
          <small>Cases awaiting closure</small>
        </button>
        <button
          className={`stat ${overdue.length ? "alert" : ""}`}
          onClick={() => ws.go("cases", "overdue")}
        >
          <span className="stat-label">
            Past the 4-hour target
            <AlarmClock size={18} aria-hidden="true" />
          </span>
          <strong>{overdue.length}</strong>
          <small>
            {overdue.length ? "Work these first" : "Nothing overdue"}
          </small>
        </button>
        <button className="stat" onClick={() => ws.go("cases", "open")}>
          <span className="stat-label">
            Unresolved actions
            <ListChecks size={18} aria-hidden="true" />
          </span>
          <strong>{unresolved}</strong>
          <small>Unknown access keeps a case open</small>
        </button>
        <button className="stat" onClick={() => ws.go("cases", "open")}>
          <span className="stat-label">
            Ready for review
            <ClipboardCheck size={18} aria-hidden="true" />
          </span>
          <strong>{ready.length}</strong>
          <small>Awaiting an independent reviewer</small>
        </button>
      </section>

      <Panel
        title="Needs attention"
        description="Open departures, most urgent first, with the next useful step."
        flush
        action={
          <button className="link-btn" onClick={() => ws.go("cases")}>
            All cases
            <ArrowRight size={15} aria-hidden="true" />
          </button>
        }
      >
        {attention.length ? (
          <ul className="attention">
            {attention.map((item) => {
              const person = ws.person(item.identityId);
              const due = sla(item, ws.now);
              const step = nextStep(
                item,
                ws.now,
                ws.principal,
                ws.name(item.ownerId),
                ws.connected,
              );
              const { done, total } = progress(item);
              return (
                <li className="attention-item" key={item.id}>
                  <Avatar identity={person} name={item.title} />
                  <div className="attention-main">
                    <div className="row">
                      <strong>{person?.name ?? item.title}</strong>
                      <span className="muted">
                        {item.employmentType} · {item.hrEventId}
                      </span>
                      <span
                        className={`pill ${due.kind === "overdue" ? "danger" : due.kind === "soon" ? "warn" : due.kind === "scheduled" ? "accent" : ""}`}
                      >
                        {due.label}
                      </span>
                    </div>
                    <span className="attention-next">
                      <ArrowRight size={15} aria-hidden="true" />
                      {step.title}
                      <span className="dot-sep num">
                        {done}/{total} actions
                      </span>
                    </span>
                  </div>
                  <button
                    className="btn btn-secondary"
                    onClick={() => openCase(item.id)}
                    aria-label={`Open ${person?.name ?? item.title} case`}
                  >
                    Open case
                  </button>
                </li>
              );
            })}
          </ul>
        ) : (
          <Empty
            title="No open departures"
            icon={<FileCheck2 size={24} />}
            action={
              <button
                className="btn btn-secondary"
                onClick={() => ws.go("cases")}
              >
                Go to offboarding cases
              </button>
            }
          >
            Every recorded departure is closed. New HR events will appear here.
          </Empty>
        )}
      </Panel>

      <div className="grid-even">
        <Panel
          title="Access changes in flight"
          description="Requests waiting for approval, enforcement or observation."
          flush
          action={
            <button className="link-btn" onClick={() => ws.go("requests")}>
              Requests
              <ArrowRight size={15} aria-hidden="true" />
            </button>
          }
        >
          {inFlight.length ? (
            <ul className="attention">
              {inFlight.slice(0, 4).map((request) => (
                <li className="attention-item" key={request.id}>
                  <Avatar identity={ws.person(request.identityId)} size="sm" />
                  <div className="attention-main">
                    <strong>{ws.name(request.identityId)}</strong>
                    <span className="muted">
                      {request.id} · {ws.resource(request.resourceId)?.name} ·{" "}
                      {timeAgo(request.createdAt, ws.now)}
                    </span>
                  </div>
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() =>
                      ws.select({ kind: "request", id: request.id })
                    }
                    aria-label={`Open request ${request.id}`}
                  >
                    <Status value={request.status} />
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <Empty title="Nothing in flight">
              New access requests appear here until they are verified.
            </Empty>
          )}
        </Panel>
        <Panel
          title="Evidence"
          description="Recorded local runs published with this build."
          action={
            <button className="link-btn" onClick={() => ws.go("runs")}>
              Runs & evidence
              <ArrowRight size={15} aria-hidden="true" />
            </button>
          }
        >
          <div className="stack">
            <div className="row">
              <span className="pill ok">{passed} passed</span>
              <span className={`pill ${failed ? "danger" : ""}`}>
                {failed} failed, kept on record
              </span>
            </div>
            <p className="text-2" style={{ fontSize: "var(--fs-sm)" }}>
              Lab acceptance runs exercise real Keycloak, OPA and a Samba
              directory; automated test suites are listed beside them. Browser
              actions never count as recorded evidence.
            </p>
            <h3 style={{ fontSize: "var(--fs-md)", marginTop: 4 }}>
              Recent activity
            </h3>
            {ws.data.audit.length ? (
              <ul className="activity">
                {ws.data.audit.slice(0, 3).map((entry) => (
                  <li key={entry.id}>
                    <span>
                      <Activity size={15} aria-hidden="true" />
                    </span>
                    <div>
                      <strong>{entry.action}</strong>
                      <p>{auditSummary(entry.detail)}</p>
                      <small>
                        {ws.name(entry.actorId)} · {formatDate(entry.at)}
                      </small>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="quiet">
                Actions you take appear here, with who did them and when.
              </p>
            )}
          </div>
        </Panel>
      </div>
    </div>
  );
}
