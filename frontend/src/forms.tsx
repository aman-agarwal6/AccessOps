import { useState, type FormEvent } from "react";
import {
  ArrowRight,
  Bot,
  Fingerprint,
  ShieldCheck,
  UserRound,
} from "lucide-react";
import {
  isContainment,
  type Enrollment,
  type Identity,
  type NewRequest,
  type Snapshot,
} from "./domain";
import { actionNames } from "./pages/Governance";
import { Callout, FormError } from "./ui";

export function RequestForm({
  data,
  busy,
  connected,
  error,
  onSubmit,
}: {
  data: Snapshot;
  busy: boolean;
  connected: boolean;
  error: string;
  onSubmit: (input: NewRequest) => void;
}) {
  const [identityId, setIdentityId] = useState(data.identities[0]?.id ?? "");
  const [resourceId, setResourceId] = useState(data.resources[0]?.id ?? "");
  const [action, setAction] = useState<NewRequest["action"]>("grant");
  const [permission, setPermission] = useState("read");
  const [newSponsorId, setNewSponsorId] = useState(
    data.identities.find((i) => i.kind === "human" && i.status === "active")
      ?.id ?? "",
  );
  const [reason, setReason] = useState("");
  const [local, setLocal] = useState("");
  const selected = data.identities.find(
    (identity) => identity.id === identityId,
  );
  function submit(event: FormEvent) {
    event.preventDefault();
    if (reason.trim().length < 12) {
      setLocal("Describe the business purpose in at least 12 characters.");
      return;
    }
    onSubmit({
      identityId,
      resourceId,
      action,
      reason: reason.trim(),
      ...(action === "grant" ? { permission } : {}),
      ...(action === "transfer" ? { newSponsorId } : {}),
    });
  }
  return (
    <form onSubmit={submit} className="form">
      <FormError message={local || error} />
      <label className="field">
        Identity
        <select
          value={identityId}
          onChange={(event) => setIdentityId(event.target.value)}
          required
        >
          {data.identities.map((identity) => (
            <option key={identity.id} value={identity.id}>
              {identity.name} · {identity.kind === "agent" ? "agent" : "person"}
            </option>
          ))}
        </select>
      </label>
      <div className="form-row">
        <label className="field">
          Change
          <select
            value={action}
            onChange={(event) =>
              setAction(event.target.value as NewRequest["action"])
            }
          >
            {Object.entries(actionNames)
              .filter(([value]) => value !== "department_transfer")
              .map(([value, label]) => (
                <option value={value} key={value}>
                  {label}
                </option>
              ))}
          </select>
        </label>
        <label className="field">
          Resource
          <select
            value={resourceId}
            onChange={(event) => setResourceId(event.target.value)}
            required
          >
            {data.resources.map((resource) => (
              <option key={resource.id} value={resource.id}>
                {resource.name}
              </option>
            ))}
          </select>
        </label>
      </div>
      {action === "grant" && (
        <div className="form-row">
          <label className="field">
            Permission
            <select
              value={permission}
              onChange={(event) => setPermission(event.target.value)}
            >
              <option value="read">Read</option>
            </select>
          </label>
          <div className="static-field">
            <span>Grant duration</span>
            <strong>
              {selected?.kind === "agent"
                ? "10 minutes · 6 calls"
                : "Until explicitly revoked"}
            </strong>
            <span>
              {connected
                ? "Enforced by the local server policy"
                : "Enforced by the browser model"}
            </span>
          </div>
        </div>
      )}
      {action === "transfer" && (
        <label className="field">
          New accountable sponsor
          <select
            value={newSponsorId}
            onChange={(event) => setNewSponsorId(event.target.value)}
          >
            {data.identities
              .filter((i) => i.kind === "human" && i.status === "active")
              .map((identity) => (
                <option key={identity.id} value={identity.id}>
                  {identity.name}
                </option>
              ))}
          </select>
        </label>
      )}
      <label className="field">
        Business reason
        <textarea
          value={reason}
          onChange={(event) => {
            setReason(event.target.value);
            setLocal("");
          }}
          rows={4}
          minLength={12}
          maxLength={255}
          required
          placeholder="What task needs this change, and why is this scope enough?"
        />
        <span className="field-hint">
          12–255 characters · {reason.length}/255
        </span>
      </label>
      {action === "offboard" && (
        <Callout tone="warn" icon={<Bot size={18} aria-hidden="true" />}>
          A departure also suspends this person's sponsored agents and revokes
          their active grants.
        </Callout>
      )}
      <div className="form-actions">
        <span className="form-note">
          <ShieldCheck size={15} aria-hidden="true" />
          {isContainment({ action })
            ? "Authorized operator containment"
            : "Independent human approval required"}
        </span>
        <button
          className="btn btn-primary"
          type="submit"
          disabled={busy || !identityId || !resourceId}
        >
          Submit request
          <ArrowRight size={16} aria-hidden="true" />
        </button>
      </div>
    </form>
  );
}

export function EnrollmentForm({
  data,
  busy,
  error,
  onSubmit,
}: {
  data: Snapshot;
  busy: boolean;
  error: string;
  onSubmit: (input: Enrollment) => void;
}) {
  const [kind, setKind] = useState<"human" | "agent">("human");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [department, setDepartment] = useState<"Engineering" | "Operations">(
    "Engineering",
  );
  const [project, setProject] = useState("Atlas");
  const [sponsorId, setSponsorId] = useState(
    data.identities.find((i) => i.kind === "human" && i.status === "active")
      ?.id ?? "",
  );
  return (
    <form
      className="form"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({
          name: name.trim(),
          email: email.trim(),
          kind,
          department,
          projectIds: [project],
          ...(kind === "agent" ? { sponsorId } : {}),
        });
      }}
    >
      <FormError message={error} />
      <div className="form-row">
        <label className="field">
          Identity type
          <select
            value={kind}
            onChange={(event) =>
              setKind(event.target.value as "human" | "agent")
            }
          >
            <option value="human">Employee</option>
            <option value="agent">AI agent</option>
          </select>
        </label>
        <label className="field">
          Department
          <select
            value={department}
            onChange={(event) => {
              const value = event.target.value as "Engineering" | "Operations";
              setDepartment(value);
              setProject(value === "Engineering" ? "Atlas" : "Pulse");
            }}
          >
            <option>Engineering</option>
            <option>Operations</option>
          </select>
        </label>
      </div>
      <label className="field">
        Name
        <input
          required
          minLength={3}
          maxLength={100}
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder={
            kind === "agent" ? "Atlas change assistant" : "Taylor Reed"
          }
        />
      </label>
      <label className="field">
        Synthetic email
        <input
          type="email"
          required
          maxLength={200}
          pattern="[^@]+@example\.test"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          placeholder="taylor.reed@example.test"
        />
        <span className="field-hint">
          Use @example.test in this synthetic workspace
        </span>
      </label>
      <div className="form-row">
        <label className="field">
          Project scope
          <select
            value={project}
            onChange={(event) => setProject(event.target.value)}
          >
            <option>Atlas</option>
            <option>Pulse</option>
          </select>
        </label>
        {kind === "agent" && (
          <label className="field">
            Accountable human sponsor
            <select
              value={sponsorId}
              onChange={(event) => setSponsorId(event.target.value)}
            >
              {data.identities
                .filter((i) => i.kind === "human" && i.status === "active")
                .map((identity) => (
                  <option key={identity.id} value={identity.id}>
                    {identity.name}
                  </option>
                ))}
            </select>
          </label>
        )}
      </div>
      <Callout tone="info" icon={<Fingerprint size={18} aria-hidden="true" />}>
        {kind === "agent"
          ? "The agent starts suspended. A secure credential binding must complete before activation; this form cannot mint credentials."
          : "The employee record starts with provider binding pending. Registration assigns no application permissions."}
      </Callout>
      <div className="form-actions">
        <span className="form-note">Record creation is audited.</span>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          Register {kind === "human" ? "employee" : "agent"}
          <ArrowRight size={15} aria-hidden="true" />
        </button>
      </div>
    </form>
  );
}

export function DepartmentForm({
  identity,
  busy,
  error,
  onSubmit,
}: {
  identity?: Identity;
  busy: boolean;
  error: string;
  onSubmit: (department: string, reason: string) => void;
}) {
  const [department, setDepartment] = useState(
    identity?.department === "Engineering" ? "Operations" : "Engineering",
  );
  const [reason, setReason] = useState("");
  return (
    <form
      className="form"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(department, reason.trim());
      }}
    >
      <FormError message={error} />
      <Callout icon={<UserRound size={18} aria-hidden="true" />}>
        {identity?.name} currently belongs to {identity?.department}. The
        request binds the target department and reason for review.
      </Callout>
      <label className="field">
        Target department
        <select
          value={department}
          onChange={(event) => setDepartment(event.target.value)}
        >
          {["Engineering", "Operations"]
            .filter((entry) => entry !== identity?.department)
            .map((entry) => (
              <option key={entry}>{entry}</option>
            ))}
        </select>
      </label>
      <label className="field">
        Business reason
        <textarea
          required
          minLength={12}
          maxLength={255}
          rows={4}
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          placeholder="Explain the move and the access that must be removed."
        />
      </label>
      <div className="form-actions">
        <span className="form-note">
          <ShieldCheck size={15} aria-hidden="true" />
          No new grants are added automatically.
        </span>
        <button
          className="btn btn-primary"
          disabled={busy || !identity}
          type="submit"
        >
          Request transfer
          <ArrowRight size={15} aria-hidden="true" />
        </button>
      </div>
    </form>
  );
}
