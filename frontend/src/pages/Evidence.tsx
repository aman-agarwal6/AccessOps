import { useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  BadgeCheck,
  ChevronRight,
  CircleAlert,
  FileCheck2,
  KeyRound,
  Play,
  RefreshCw,
  ShieldOff,
  Terminal,
  XCircle,
} from "lucide-react";
import type { Run } from "../domain";
import { auditSummary } from "../presentation";
import { signedRelease } from "../release";
import {
  Callout,
  Empty,
  External,
  Panel,
  Provenance,
  Segmented,
  Status,
  formatDate,
  provenance,
  type ProvenanceKind,
} from "../ui";
import type { Workspace } from "../workspace";

const ladder: ProvenanceKind[] = [
  "signed",
  "observed",
  "imported",
  "attested",
  "simulated",
];

function RunList({ runs, ws }: { runs: Run[]; ws: Workspace }) {
  return (
    <ul className="run-list">
      {runs.map((run) => {
        const failed = run.checks.filter(
          (check) => check.status === "failed",
        ).length;
        return (
          <li key={run.id}>
            <button
              className={`run-row ${run.status}`}
              onClick={() => ws.select({ kind: "run", id: run.id })}
            >
              <span aria-hidden="true">
                {run.status === "failed" ? (
                  <XCircle size={20} />
                ) : (
                  <FileCheck2 size={20} />
                )}
              </span>
              <span>
                <strong>{run.name}</strong>
                <small>
                  {run.id} · {formatDate(run.startedAt)} · {run.checks.length}{" "}
                  checks{failed ? ` · ${failed} failed` : ""}
                </small>
              </span>
              <Status value={run.status} />
              <ChevronRight size={18} aria-hidden="true" />
            </button>
          </li>
        );
      })}
    </ul>
  );
}

export function EvidencePage({ ws }: { ws: Workspace }) {
  const [filter, setFilter] = useState<"all" | "passed" | "failed">("all");
  const runs = ws.recorded.filter(
    (run) => filter === "all" || run.status === filter,
  );
  const sim = ws.simulation;
  return (
    <div className="sections">
      <section aria-labelledby="ladder-title">
        <div className="section-title">
          <h2 id="ladder-title">What each kind of evidence can prove</h2>
          <p>Strongest first. AccessOps never upgrades a label.</p>
        </div>
        <ol className="evidence-ladder">
          {ladder.map((kind) => (
            <li key={kind}>
              <Provenance kind={kind} />
              <p>{provenance[kind].meaning}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="card signed-card" aria-labelledby="signed-title">
        <span aria-hidden="true">
          <BadgeCheck size={24} />
        </span>
        <div>
          <h2 id="signed-title" style={{ fontSize: "var(--fs-lg)" }}>
            Signed release {signedRelease.tag}
          </h2>
          <p>{signedRelease.scope}</p>
          <p className="muted" style={{ marginTop: 4 }}>
            Source {signedRelease.commit}. A signature proves where the bytes
            came from, not that the application is secure.
          </p>
        </div>
        <External href={signedRelease.url}>View release</External>
      </section>

      <Panel
        title="Recorded local runs"
        description="Sanitized reports from actual local runs: lab acceptance suites against real services, plus automated test suites. Failed attempts stay on record. Local hashes are not signatures."
        flush
        action={
          ws.recordedState === "ready" && ws.recorded.length ? (
            <Segmented<"all" | "passed" | "failed">
              label="Filter recorded runs"
              value={filter}
              onChange={setFilter}
              options={[
                { value: "all", label: "All", count: ws.recorded.length },
                {
                  value: "passed",
                  label: "Passed",
                  count: ws.recorded.filter((run) => run.status === "passed")
                    .length,
                },
                {
                  value: "failed",
                  label: "Failed",
                  count: ws.recorded.filter((run) => run.status === "failed")
                    .length,
                },
              ]}
            />
          ) : undefined
        }
      >
        {ws.recordedState === "loading" ? (
          <div
            className="panel-body stack"
            aria-busy="true"
            aria-label="Loading recorded runs"
          >
            {[0, 1, 2].map((row) => (
              <span key={row} className="skeleton" style={{ height: 44 }} />
            ))}
          </div>
        ) : ws.recordedState === "error" ? (
          <div className="panel-body">
            <Callout
              tone="danger"
              role="alert"
              icon={<CircleAlert size={18} aria-hidden="true" />}
              action={
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={ws.retryRecorded}
                >
                  <RefreshCw size={14} aria-hidden="true" />
                  Retry
                </button>
              }
            >
              {ws.recordedError} No results are assumed.
            </Callout>
          </div>
        ) : runs.length ? (
          <RunList runs={runs} ws={ws} />
        ) : (
          <Empty
            title="No recorded runs published"
            icon={<Terminal size={24} />}
            action={
              <button
                className="btn btn-secondary"
                onClick={() => ws.openModal("lab")}
              >
                How to run the lab
              </button>
            }
          >
            The public simulation cannot create connector evidence. Dated
            reports appear here after actual local runs are exported.
          </Empty>
        )}
      </Panel>

      {ws.connected && (
        <Panel
          title="Connected lab runs"
          description="Execution records from the authenticated backend."
          flush
        >
          {ws.data.runs.length ? (
            <RunList runs={ws.data.runs} ws={ws} />
          ) : (
            <Empty title="No connected runs yet">
              Run a lab scenario, then refresh to inspect its checks.
            </Empty>
          )}
        </Panel>
      )}

      {!ws.connected && (
        <Panel
          title="Browser scenario checks"
          description="Results of actions in this tab. No external service was exercised."
          action={
            (sim.attempts.length > 0 || sim.checks.length > 0) && (
              <button
                className="btn btn-secondary btn-sm"
                onClick={ws.exportSimulation}
              >
                <ArrowDownToLine size={14} aria-hidden="true" />
                Export simulation
              </button>
            )
          }
        >
          {sim.attempts.length || sim.checks.length ? (
            <div className="checks simulation-evidence">
              {sim.checks.map((check, index) => (
                <div className="check" key={`${check.name}-${index}`}>
                  <span aria-hidden="true">
                    <FileCheck2 size={15} />
                  </span>
                  <div>
                    <strong>{check.name}</strong>
                    <p>{check.detail}</p>
                  </div>
                  <Provenance kind="simulated" />
                </div>
              ))}
              {sim.attempts.map((attempt) => (
                <div
                  className={`check ${attempt.allowed ? "" : "denied"}`}
                  key={attempt.id}
                >
                  <span aria-hidden="true">
                    {attempt.allowed ? (
                      <KeyRound size={15} />
                    ) : (
                      <ShieldOff size={15} />
                    )}
                  </span>
                  <div>
                    <strong>
                      {ws.name(attempt.identityId)} →{" "}
                      {ws.resource(attempt.resourceId)?.name}
                    </strong>
                    <p>{attempt.reason}</p>
                    <small>
                      {formatDate(attempt.at)} · {attempt.effects} simulated
                      resource effects
                    </small>
                  </div>
                  <Status value={attempt.allowed ? "allowed" : "denied"} />
                </div>
              ))}
            </div>
          ) : (
            <Empty
              title="Run a scenario to inspect its decisions"
              icon={<Activity size={24} />}
              action={
                <button className="btn btn-secondary" onClick={ws.startGuide}>
                  <Play size={15} aria-hidden="true" />
                  Containment walkthrough
                </button>
              }
            >
              Allowed and denied reads appear here, labeled as simulation.
            </Empty>
          )}
        </Panel>
      )}

      <Panel
        title="Decision trail"
        description={
          ws.connected
            ? "Server-reported audit events, hash-chained by the backend."
            : "Browser actions in order. No integrity claim is made for the simulation."
        }
        flush
      >
        {ws.data.audit.length ? (
          <div
            className="table-wrap"
            role="region"
            aria-label="Decision trail"
            tabIndex={0}
          >
            <table className="data">
              <caption className="sr-only">Decision trail</caption>
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Actor</th>
                  <th scope="col">Action</th>
                  <th scope="col" className="hide-sm">
                    Target
                  </th>
                  <th scope="col">Detail</th>
                </tr>
              </thead>
              <tbody>
                {ws.data.audit.map((entry) => (
                  <tr key={entry.id}>
                    <td className="nowrap">{formatDate(entry.at)}</td>
                    <td>{ws.name(entry.actorId)}</td>
                    <td>
                      <strong>{entry.action}</strong>
                    </td>
                    <td className="hide-sm mono">{entry.targetId}</td>
                    <td style={{ minWidth: 220 }}>
                      {auditSummary(entry.detail)}
                      {typeof entry.detail === "object" && (
                        <details
                          className="task-evidence"
                          style={{ marginTop: 6 }}
                        >
                          <summary>Event record</summary>
                          <pre
                            className="code-block"
                            tabIndex={0}
                            role="region"
                            aria-label="Serialized event record"
                          >
                            {JSON.stringify(entry.detail, null, 2).slice(
                              0,
                              16000,
                            )}
                          </pre>
                        </details>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="panel-body">
            <p className="quiet">
              <Activity size={18} aria-hidden="true" />
              No actions have been recorded in this session yet.
            </p>
          </div>
        )}
      </Panel>
    </div>
  );
}
