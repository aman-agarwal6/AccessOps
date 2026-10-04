import { useEffect, useState, type FormEvent } from "react";
import {
  ArrowRight,
  CircleAlert,
  ClipboardCheck,
  FileJson,
  ShieldOff,
  Sparkles,
  Upload,
} from "lucide-react";
import { taskProvenance } from "../../caseflow";
import type { Identity, Principal } from "../../domain";
import {
  platformNames,
  syntheticBindings,
  syntheticReport,
  type NewCase,
  type OffboardingCase,
} from "../../offboarding";
import { Callout, FormError, Modal, Provenance, formatDate } from "../../ui";

export function CreateCaseDialog({
  open,
  onClose,
  identities,
  now,
  connected,
  busy,
  error,
  submit,
}: {
  open: boolean;
  onClose: () => void;
  identities: Identity[];
  now: number;
  connected: boolean;
  busy: boolean;
  error: string;
  submit: (input: NewCase) => void;
}) {
  const people = identities
    .filter((identity) => identity.kind === "human")
    .sort(
      (a, b) => Number(b.status === "active") - Number(a.status === "active"),
    );
  const [identityId, setIdentityId] = useState("");
  const selected = people.find(
    (identity) => identity.id === (identityId || people[0]?.id),
  );
  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    const bindings: NewCase["bindings"] = [];
    for (const provider of ["entra", "github"] as const) {
      const tenantId = String(fields.get(`${provider}-tenant`) ?? "").trim();
      const subjectId = String(fields.get(`${provider}-subject`) ?? "").trim();
      if (tenantId || subjectId)
        bindings.push({ provider, tenantId, subjectId });
    }
    const effective = new Date(String(fields.get("effectiveAt")));
    submit({
      identityId: String(fields.get("identity")),
      employmentType: String(
        fields.get("employmentType"),
      ) as NewCase["employmentType"],
      hrEventId: String(fields.get("hrEventId")).trim(),
      hrSource: String(fields.get("hrSource")).trim(),
      effectiveAt: Number.isNaN(effective.valueOf())
        ? ""
        : effective.toISOString(),
      reason: String(fields.get("reason")).trim(),
      bindings,
    });
  }
  return (
    <Modal
      title="New departure case"
      description="Record the HR event and the exact accounts it covers. Opening a case does not change access yet."
      open={open}
      onClose={onClose}
      wide
    >
      <form className="form" onSubmit={save}>
        <FormError message={error} />
        <div className="form-row">
          <label className="field">
            Departing person
            <select
              name="identity"
              required
              value={identityId || people[0]?.id || ""}
              onChange={(event) => setIdentityId(event.target.value)}
            >
              {people.map((identity) => (
                <option value={identity.id} key={identity.id}>
                  {identity.name} · {identity.department}
                  {identity.status === "active" ? "" : ` · ${identity.status}`}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            Employment type
            <select name="employmentType">
              <option value="employee">Employee</option>
              <option value="contractor">Contractor</option>
            </select>
          </label>
        </div>
        {connected && selected?.directoryBinding && (
          <Callout
            tone="info"
            icon={<ShieldOff size={18} aria-hidden="true" />}
          >
            <strong>Enrolled in the Samba AD lab.</strong> Containment also
            disables that directory account and removes it from{" "}
            {selected.directoryBinding.groupGuids.length} reviewed group
            scope(s). Directory IDs come from the server, never this form.
          </Callout>
        )}
        <div className="form-row">
          <label className="field">
            HR event ID
            <input
              name="hrEventId"
              required
              minLength={8}
              maxLength={64}
              pattern="[A-Za-z0-9._:\-]{8,64}"
              placeholder="HR-2026-1102"
            />
            <span className="field-hint">8–64 letters, digits, . _ : -</span>
          </label>
          <label className="field">
            Departure takes effect
            <input
              name="effectiveAt"
              type="datetime-local"
              required
              defaultValue={new Date(
                now - new Date(now).getTimezoneOffset() * 60000,
              )
                .toISOString()
                .slice(0, 16)}
            />
            <span className="field-hint">Your local time</span>
          </label>
        </div>
        <label className="field">
          HR source
          <input
            name="hrSource"
            required
            minLength={3}
            maxLength={64}
            placeholder="HR service desk"
          />
        </label>
        <label className="field">
          Reason
          <textarea
            name="reason"
            required
            minLength={8}
            maxLength={255}
            rows={3}
            placeholder="Authorized departure event and the handover it requires."
          />
        </label>
        <details className="disclosure">
          <summary>Platform account bindings (optional)</summary>
          <div className="disclosure-body stack">
            <p>
              Use immutable account IDs. Names and email addresses never
              establish which account belongs to whom.
              {!connected && " Synthetic IDs are prefilled."}
            </p>
            {(["entra", "github"] as const).map((provider, index) => (
              <fieldset
                key={provider}
                style={{ border: 0, padding: 0, margin: 0 }}
              >
                <legend
                  style={{
                    fontWeight: 600,
                    color: "var(--text)",
                    marginBottom: 8,
                  }}
                >
                  {platformNames[provider]}
                </legend>
                <div className="form-row">
                  <label className="field">
                    {provider === "entra" ? "Tenant ID" : "Organization ID"}
                    <input
                      name={`${provider}-tenant`}
                      maxLength={120}
                      className="mono"
                      defaultValue={
                        connected ? "" : syntheticBindings[index].tenantId
                      }
                    />
                  </label>
                  <label className="field">
                    Account ID
                    <input
                      name={`${provider}-subject`}
                      maxLength={120}
                      className="mono"
                      defaultValue={
                        connected ? "" : syntheticBindings[index].subjectId
                      }
                    />
                  </label>
                </div>
              </fieldset>
            ))}
          </div>
        </details>
        <div className="form-actions">
          <span className="form-note">You become the accountable owner.</span>
          <button className="btn btn-primary" disabled={busy}>
            Create departure case
            <ArrowRight size={16} aria-hidden="true" />
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function ImportDialog({
  open,
  onClose,
  item,
  now,
  connected,
  busy,
  error,
  setError,
  submit,
}: {
  open: boolean;
  onClose: () => void;
  item: OffboardingCase;
  now: number;
  connected: boolean;
  busy: boolean;
  error: string;
  setError: (message: string) => void;
  submit: (report: unknown) => void;
}) {
  const [text, setText] = useState("");
  useEffect(() => {
    if (open) setText("");
  }, [open]);
  function assess() {
    try {
      if (new TextEncoder().encode(text).length > 100000)
        throw new Error("Reports must be no larger than 100 KB.");
      submit(JSON.parse(text));
    } catch (problem) {
      setError(
        problem instanceof SyntaxError
          ? "This is not valid JSON. Check the report and try again."
          : problem instanceof Error
            ? problem.message
            : "The report could not be read.",
      );
    }
  }
  return (
    <Modal
      title="Import platform report"
      description="Assess a bounded snapshot for this case's bound accounts. Nothing here contacts a cloud tenant."
      open={open}
      onClose={onClose}
      wide
    >
      <div className="stack">
        <Callout tone={connected ? "info" : "warn"}>
          {connected
            ? "The server validates and stores the report. Include only scoped evidence fields, never credentials."
            : "The public demo accepts synthetic fixtures only. Never paste real tenant, employee or credential data here."}
        </Callout>
        {!connected && (
          <div className="row">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() =>
                setText(
                  JSON.stringify(syntheticReport(item, now, "after"), null, 2),
                )
              }
            >
              <FileJson size={16} aria-hidden="true" />
              Load after-departure fixture
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() =>
                setText(
                  JSON.stringify(syntheticReport(item, now, "before"), null, 2),
                )
              }
            >
              Load before-departure fixture
            </button>
          </div>
        )}
        <label className="field">
          Canonical report JSON
          <textarea
            className="code"
            rows={10}
            value={text}
            onChange={(event) => setText(event.target.value)}
            maxLength={100000}
            placeholder='{"schemaVersion": 1, "collectionMethod": "synthetic_fixture", …}'
            spellCheck={false}
          />
        </label>
        <label className="field">
          Or choose a JSON file
          <input
            type="file"
            accept="application/json,.json"
            onChange={async (event) => {
              const file = event.target.files?.[0];
              if (!file) return;
              if (file.size > 100000) {
                setError("Reports must be no larger than 100 KB.");
                return;
              }
              setText(await file.text());
            }}
          />
          <span className="field-hint">100 KB and 100 readings at most</span>
        </label>
        <p className="muted" style={{ fontSize: "var(--fs-sm)" }}>
          Every reading must match a bound tenant and account. Unknown, partial,
          stale or pre-departure readings cannot clear an action, and a new
          import resets owner statements for external actions.
        </p>
        <FormError message={error} />
        <div className="dialog-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy || !text.trim()}
            onClick={assess}
          >
            <Upload size={16} aria-hidden="true" />
            Assess & import report
          </button>
        </div>
      </div>
    </Modal>
  );
}

export function AttestDialog({
  open,
  onClose,
  item,
  taskId,
  principal,
  name,
  connected,
  busy,
  error,
  submit,
}: {
  open: boolean;
  onClose: () => void;
  item: OffboardingCase;
  taskId: string;
  principal?: Principal;
  name: (id?: string) => string;
  connected: boolean;
  busy: boolean;
  error: string;
  submit: (reference: string, summary: string) => void;
}) {
  const task = item.tasks.find((entry) => entry.id === taskId);
  const existing = task?.evidenceKind === "owner_attestation";
  const [reference, setReference] = useState("");
  const [summary, setSummary] = useState("");
  useEffect(() => {
    if (!open) return;
    setReference(existing ? (task?.evidenceReference ?? "") : "");
    setSummary(existing ? (task?.evidenceSummary ?? "") : "");
  }, [open, taskId]);
  return (
    <Modal
      title="Record owner evidence"
      description="A written statement stays an attestation. It is never treated as provider verification."
      open={open}
      onClose={onClose}
    >
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          submit(reference.trim(), summary.trim());
        }}
      >
        <div className="stack" style={{ gap: 6 }}>
          <strong style={{ fontSize: "var(--fs-lg)" }}>{task?.title}</strong>
          <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
            {task ? platformNames[task.platform] : ""} · target{" "}
            {formatDate(task?.dueAt)}
          </span>
        </div>
        {!connected && (
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            style={{ justifySelf: "start" }}
            onClick={() => {
              setReference(
                `CHG-${item.hrEventId.slice(-4)}-${taskId}`.slice(0, 120),
              );
              setSummary(
                "Synthetic owner statement: the scoped action and handover were completed and checked. Sessions, copies and unsupported credentials remain within the stated evidence limits.",
              );
            }}
          >
            <Sparkles size={14} aria-hidden="true" />
            Fill a sample statement
          </button>
        )}
        <label className="field">
          Evidence reference
          <input
            name="reference"
            required
            minLength={8}
            maxLength={120}
            value={reference}
            onChange={(event) => setReference(event.target.value)}
            placeholder="CHG-1048 / handover record"
          />
          <span className="field-hint">
            Ticket, change or record ID · 8–120 characters
          </span>
        </label>
        <label className="field">
          Owner evidence summary
          <textarea
            name="summary"
            required
            minLength={20}
            maxLength={500}
            rows={4}
            value={summary}
            onChange={(event) => setSummary(event.target.value)}
            placeholder="What was done, which scope it covered, and what remains outside it."
          />
          <span className="field-hint">{summary.length}/500 · at least 20</span>
        </label>
        <div className="row">
          <Provenance kind="attested" />
          <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
            Recorded as {name(principal?.id)}
          </span>
        </div>
        <FormError message={error} />
        <div className="dialog-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn-primary" disabled={busy}>
            Save owner attestation
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function CloseDialog({
  open,
  onClose,
  item,
  principal,
  name,
  connected,
  busy,
  error,
  submit,
}: {
  open: boolean;
  onClose: () => void;
  item: OffboardingCase;
  principal?: Principal;
  name: (id?: string) => string;
  connected: boolean;
  busy: boolean;
  error: string;
  submit: () => void;
}) {
  const remaining = item.tasks.filter(
    (task) => task.status === "pending",
  ).length;
  const mix = item.tasks.reduce<Record<string, number>>((counts, task) => {
    const kind = taskProvenance(task, connected);
    counts[kind] = (counts[kind] ?? 0) + 1;
    return counts;
  }, {});
  return (
    <Modal
      title="Review administrative closure"
      description="Accept this exact revision and evidence packet as an independent reviewer."
      open={open}
      onClose={onClose}
    >
      <div className="stack">
        <div className="stack" style={{ gap: 4 }}>
          <strong style={{ fontSize: "var(--fs-lg)" }}>{item.title}</strong>
          <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
            Revision {item.revision} · reviewer {name(principal?.id)}
          </span>
        </div>
        {remaining ? (
          <Callout
            tone="warn"
            icon={<CircleAlert size={18} aria-hidden="true" />}
          >
            <strong>{remaining} required actions are unresolved.</strong> The
            server will reject closure until they are accounted for.
          </Callout>
        ) : (
          <Callout
            tone="ok"
            icon={<ClipboardCheck size={18} aria-hidden="true" />}
          >
            <strong>All {item.tasks.length} actions are accounted for.</strong>{" "}
            Check what kind of evidence backs each one before accepting.
          </Callout>
        )}
        <div>
          <h3 style={{ fontSize: "var(--fs-md)", marginBottom: 8 }}>
            Evidence behind this packet
          </h3>
          <div className="row">
            {Object.entries(mix).map(([kind, count]) => (
              <span key={kind} className="row" style={{ gap: 6 }}>
                <Provenance
                  kind={kind as Parameters<typeof Provenance>[0]["kind"]}
                  label={`${count} × ${kind === "simulated" ? "simulated observation" : kind === "observed" ? "provider observation" : kind === "imported" ? "imported snapshot" : kind === "attested" ? "owner attestation" : "no evidence"}`}
                />
              </span>
            ))}
          </div>
        </div>
        <p className="text-2" style={{ fontSize: "var(--fs-sm)" }}>
          Closure records reviewed evidence. It does not verify that every
          application session, shared credential or copied file is gone.
        </p>
        <details className="disclosure">
          <summary>Exact packet reference</summary>
          <div className="disclosure-body">
            <code className="hash">{item.packetHash}</code>
          </div>
        </details>
        <FormError message={error} />
        <div className="dialog-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn-primary" disabled={busy} onClick={submit}>
            Accept evidence & close case
          </button>
        </div>
      </div>
    </Modal>
  );
}
