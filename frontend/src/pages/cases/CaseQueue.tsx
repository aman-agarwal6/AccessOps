import { ChevronRight, Info, Plus, UserMinus } from "lucide-react";
import {
  byUrgency,
  inQueue,
  nextStep,
  progress,
  sla,
  type QueueFilter,
} from "../../caseflow";
import { Callout, Empty, Segmented, Status, Who, formatDate } from "../../ui";
import type { Workspace } from "../../workspace";
import { openCase } from "./route";

export function CaseQueue({
  ws,
  filter,
  setFilter,
  onCreate,
}: {
  ws: Workspace;
  filter: QueueFilter;
  setFilter: (filter: QueueFilter) => void;
  onCreate: () => void;
}) {
  const operator = !!ws.principal?.roles.includes("operator");
  const count = (value: QueueFilter) =>
    ws.cases.filter((item) => inQueue(item, value, ws.now)).length;
  const rows = ws.cases
    .filter((item) => inQueue(item, filter, ws.now))
    .sort(byUrgency(ws.now));
  return (
    <div className="sections">
      <section className="panel" aria-labelledby="queue-title">
        <header className="panel-head">
          <div>
            <h2 id="queue-title">Departure queue</h2>
            <p>
              Directory containment is one step. A case closes only when
              sessions, credentials and data ownership are accounted for too.
            </p>
          </div>
          <button
            className="btn btn-primary"
            disabled={ws.busy || !operator}
            onClick={onCreate}
            title={operator ? undefined : "Requires the operator role"}
          >
            <Plus size={16} aria-hidden="true" />
            New departure case
          </button>
        </header>
        <div className="toolbar">
          <Segmented<QueueFilter>
            label="Filter departures"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "open", label: "Open", count: count("open") },
              { value: "overdue", label: "Overdue", count: count("overdue") },
              {
                value: "scheduled",
                label: "Scheduled",
                count: count("scheduled"),
              },
              { value: "closed", label: "Closed", count: count("closed") },
              { value: "all", label: "All", count: count("all") },
            ]}
          />
          {!operator && (
            <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
              Opening a case requires the operator role.
            </span>
          )}
        </div>
        {rows.length ? (
          <div className="queue">
            <div className="queue-head" aria-hidden="true">
              <span>Person</span>
              <span>Status</span>
              <span>Next step</span>
              <span>Target</span>
              <span />
            </div>
            <ul aria-label="Departure cases" style={{ display: "grid" }}>
              {rows.map((item) => {
                const person = ws.person(item.identityId);
                const due = sla(item, ws.now);
                const { done, total } = progress(item);
                const step = nextStep(
                  item,
                  ws.now,
                  ws.principal,
                  ws.name(item.ownerId),
                  ws.connected,
                );
                return (
                  <li key={item.id} style={{ listStyle: "none" }}>
                    <button
                      className="queue-row"
                      onClick={() => openCase(item.id)}
                      aria-label={`${person?.name ?? item.title}, ${item.employmentType} departure ${item.hrEventId}. ${due.label}. ${done} of ${total} actions accounted for. Next: ${step.title}`}
                    >
                      <Who
                        identity={person}
                        fallback={item.title}
                        detail={`${item.employmentType} · ${item.hrEventId}`}
                      />
                      <span>
                        <Status
                          value={
                            due.kind === "scheduled" ? "scheduled" : item.status
                          }
                        />
                      </span>
                      <span className="queue-progress">
                        <span className="queue-next">{step.title}</span>
                        <span
                          className={`bar ${done === total ? "ok" : ""}`}
                          aria-hidden="true"
                        >
                          <span style={{ width: `${(done / total) * 100}%` }} />
                        </span>
                        <span className="muted">
                          {done} of {total} actions · owner{" "}
                          {ws.name(item.ownerId)}
                        </span>
                      </span>
                      <span className={`sla ${due.kind}`}>
                        <strong>{due.label}</strong>
                        <small>
                          {due.kind === "closed"
                            ? formatDate(item.closedAt)
                            : due.kind === "scheduled"
                              ? `Effective ${formatDate(item.effectiveAt)}`
                              : `Target ${formatDate(item.dueAt)}`}
                        </small>
                      </span>
                      <ChevronRight size={18} aria-hidden="true" />
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        ) : (
          <Empty
            title={
              filter === "overdue"
                ? "Nothing is overdue"
                : filter === "scheduled"
                  ? "No scheduled departures"
                  : filter === "closed"
                    ? "No closed cases yet"
                    : "No departure cases"
            }
            icon={<UserMinus size={24} />}
          >
            {filter === "all" || filter === "open"
              ? "Open a case when HR records a departure. The case keeps the event, owner and required actions."
              : "Try another filter to see the rest of the queue."}
          </Empty>
        )}
      </section>
      <Callout icon={<Info size={18} aria-hidden="true" />} tone="info">
        <strong>Closure means reviewed evidence.</strong> Imported snapshots and
        owner statements stay labeled by source. A closed case is an
        administrative outcome, not proof that every remote session or copy is
        gone.
      </Callout>
    </div>
  );
}
