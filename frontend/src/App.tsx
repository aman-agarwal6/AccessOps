import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  Bot,
  Check,
  ChevronRight,
  CircleAlert,
  Clock3,
  Code2,
  Command,
  Database,
  FileCheck2,
  FileSearch,
  Fingerprint,
  GitBranch,
  Globe2,
  KeyRound,
  LayoutDashboard,
  ListFilter,
  LoaderCircle,
  LogIn,
  LogOut,
  Menu,
  Network,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldCheck,
  ShieldOff,
  Sparkles,
  SquareArrowOutUpRight,
  Terminal,
  UserRound,
  Users,
  Workflow,
  X,
} from "lucide-react";
import {
  dispatchSimulation,
  initialSimulation,
  isContainment,
  operators,
  type AccessRequest,
  type Command as SimCommand,
  type Enrollment,
  type Identity,
  type NewRequest,
  type Principal,
  type Run,
  type Simulation,
  type Snapshot,
} from "./domain";
import {
  CONNECTED,
  downloadJson,
  lab,
  loadRecordedEvidence,
  type Session,
} from "./api";
import {
  Avatar,
  Badge,
  Drawer,
  Empty,
  External,
  Modal,
  Panel,
  StateIcon,
  formatDate,
  timeAgo,
} from "./components";
import { auditSummary } from "./presentation";

const navigation = [
  { id: "overview", name: "Overview", icon: LayoutDashboard },
  { id: "requests", name: "Requests", icon: GitBranch },
  { id: "identities", name: "Identities", icon: Users },
  { id: "reviews", name: "Access reviews", icon: FileSearch },
  { id: "policies", name: "Policies & resources", icon: ShieldCheck },
  { id: "runs", name: "Runs & evidence", icon: Activity },
] as const;
type Page = (typeof navigation)[number]["id"];
type Selection = { kind: "request" | "identity" | "run"; id: string } | null;
const actionNames: Record<AccessRequest["action"], string> = {
  grant: "Grant access",
  revoke: "Revoke access",
  offboard: "Employee departure",
  transfer: "Transfer sponsorship",
  department_transfer: "Department transfer",
};
const pageDescriptions: Record<Page, string> = {
  overview: "The right access. A clear owner. Evidence at every step.",
  requests: "Review the exact change, then track it through enforcement.",
  identities: "People and agents, with accountable ownership in one place.",
  reviews: "Turn access findings into proposals that humans can review.",
  policies: "Understand the rules and the resources they protect.",
  runs: "Trace the outcome. Separate demonstrations from measured runs.",
};
const emptySnapshot: Snapshot = {
  identities: [],
  resources: [],
  requests: [],
  grants: [],
  reviews: [],
  runs: [],
  audit: [],
  policies: [],
  health: [],
};
const readPage = (): Page => {
  const id = location.hash.replace("#/", "").split("?")[0];
  return navigation.some((n) => n.id === id) ? (id as Page) : "overview";
};

export default function App() {
  const [simulation, setSimulation] = useState<Simulation>(() =>
    initialSimulation(),
  );
  const [connectedData, setConnectedData] = useState<Snapshot>(emptySnapshot);
  const [session, setSession] = useState<Session | null>(null);
  const [page, setPage] = useState<Page>(readPage);
  const [actor, setActor] = useState<Principal>(operators[0]);
  const [selection, setSelection] = useState<Selection>(null);
  const [modal, setModal] = useState<
    "request" | "guide" | "lab" | "reset" | "enroll" | "department" | null
  >(null);
  const [departmentIdentityId, setDepartmentIdentityId] = useState("");
  const [mobileNav, setMobileNav] = useState(false);
  const [toast, setToast] = useState<{
    message: string;
    error?: boolean;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [recorded, setRecorded] = useState<Run[]>([]);
  const [evidenceError, setEvidenceError] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [guideStep, setGuideStep] = useState(-1);
  const [probeIdentity, setProbeIdentity] = useState("atlas-agent");
  const [probeResource, setProbeResource] = useState("atlas");
  const mainRef = useRef<HTMLElement>(null);
  const data = CONNECTED ? connectedData : simulation.snapshot;
  const principal = CONNECTED ? session?.principal : actor;
  const now = CONNECTED ? Date.now() : simulation.now;
  const person = (id?: string) => data.identities.find((i) => i.id === id);
  const resource = (id?: string) => data.resources.find((r) => r.id === id);
  const name = (id?: string) => person(id)?.name ?? id ?? "Unassigned";
  const pending = data.requests.filter((r) => r.status === "pending");
  const sourceUrl = import.meta.env.VITE_SOURCE_URL as string | undefined;

  useEffect(() => {
    const update = () => {
      setPage(readPage());
      setQuery("");
      setFilter("all");
      setMobileNav(false);
    };
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);
  useEffect(() => {
    document.title = `${navigation.find((n) => n.id === page)?.name} · AccessOps`;
  }, [page]);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 7000);
    return () => clearTimeout(timer);
  }, [toast]);
  useEffect(() => {
    const controller = new AbortController();
    loadRecordedEvidence(controller.signal)
      .then(setRecorded)
      .catch((e) => {
        if (e.name !== "AbortError") setEvidenceError(e.message);
      });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    if (CONNECTED) void refresh();
  }, []);

  async function refresh() {
    setBusy(true);
    setLoadError("");
    try {
      const next = await lab.session();
      setSession(next);
      if (next.authenticated) setConnectedData(await lab.snapshot());
      else setConnectedData(emptySnapshot);
    } catch (e) {
      setLoadError(
        e instanceof Error ? e.message : "Could not load the local lab.",
      );
    } finally {
      setBusy(false);
    }
  }
  function go(next: Page) {
    location.hash = `/${next}`;
    setPage(next);
    setQuery("");
    setFilter("all");
    setSelection(null);
    setMobileNav(false);
  }
  function simulate(commands: SimCommand[], as = actor): string | undefined {
    try {
      let state = simulation;
      let result: ReturnType<typeof dispatchSimulation> | undefined;
      for (const command of commands) {
        result = dispatchSimulation(state, command, as);
        state = result.state;
      }
      setSimulation(state);
      setToast({ message: result?.message ?? "Simulation updated." });
      return result?.id;
    } catch (e) {
      setToast({
        message: e instanceof Error ? e.message : "Action failed.",
        error: true,
      });
      return undefined;
    }
  }
  async function perform(command: SimCommand) {
    if (!CONNECTED) {
      const id = simulate([command]);
      if (id) {
        setModal(null);
        setSelection({
          kind: command.type === "enroll" ? "identity" : "request",
          id,
        });
      }
      return;
    }
    setBusy(true);
    try {
      if (command.type === "create") await lab.create(command.input);
      else if (command.type === "enroll") await lab.enroll(command.input);
      else if (command.type === "department")
        await lab.department(
          command.identityId,
          command.department,
          command.reason,
        );
      else if (command.type === "accept") await lab.accept(command.id);
      else if (command.type === "approve") await lab.approve(command.id);
      else if (command.type === "execute") await lab.execute(command.id);
      else if (command.type === "review") await lab.review(command.id);
      else if (command.type === "reconcile") await lab.reconcile();
      else if (command.type === "propose") {
        const finding = data.reviews
          .find((r) => r.id === command.reviewId)
          ?.findings.find((f) => f.id === command.findingId);
        if (!finding) throw new Error("Finding not found.");
        await lab.propose(command.reviewId, {
          identityId: finding.identityId,
          resourceId: finding.resourceId,
          reason: `${finding.title}. ${finding.detail}`.slice(0, 255),
        });
      } else
        throw new Error(
          "This scenario control is available only in browser simulation.",
        );
      setConnectedData(await lab.snapshot());
      setModal(null);
      setToast({
        message:
          "The server accepted the action. The refreshed snapshot shows its current outcome.",
      });
    } catch (e) {
      setToast({
        message: e instanceof Error ? e.message : "Connected action failed.",
        error: true,
      });
    } finally {
      setBusy(false);
    }
  }
  function startGuide() {
    setSimulation(initialSimulation());
    setActor(operators[0]);
    setPage("overview");
    location.hash = "/overview";
    setSelection({ kind: "request", id: "RQ-1042" });
    setGuideStep(0);
  }
  function advanceGuide() {
    if (guideStep === 0)
      simulate([
        { type: "access", identityId: "mara", resourceId: "atlas" },
        { type: "access", identityId: "atlas-agent", resourceId: "atlas" },
      ]);
    if (guideStep === 1)
      setToast({
        message:
          "Scope: Mara plus Atlas digest; three active grants. Containment is an authorized operator action.",
      });
    if (guideStep === 2)
      simulate([{ type: "execute", id: "RQ-1042" }], operators[0]);
    if (guideStep === 3)
      simulate([{ type: "verify", id: "RQ-1042" }], operators[0]);
    if (guideStep === 4)
      simulate(
        [
          { type: "access", identityId: "mara", resourceId: "atlas" },
          { type: "access", identityId: "atlas-agent", resourceId: "atlas" },
        ],
        operators[0],
      );
    if (guideStep === 5) {
      go("runs");
      setGuideStep(-1);
      return;
    }
    setGuideStep(guideStep + 1);
  }
  const selectedRequest =
    selection?.kind === "request"
      ? data.requests.find((r) => r.id === selection.id)
      : undefined;
  const selectedIdentity =
    selection?.kind === "identity" ? person(selection.id) : undefined;
  const selectedRun =
    selection?.kind === "run"
      ? [...recorded, ...data.runs].find((r) => r.id === selection.id)
      : undefined;
  const runManifest = selectedRun?.manifest;
  const runLimitations =
    runManifest &&
    typeof runManifest === "object" &&
    "limitations" in runManifest &&
    Array.isArray(runManifest.limitations)
      ? runManifest.limitations
          .filter(
            (value): value is string =>
              typeof value === "string" &&
              value.trim().length > 0 &&
              value.length <= 4000,
          )
          .slice(0, 30)
      : [];
  const requestRows = data.requests.filter(
    (r) =>
      (filter === "all" || r.status === filter) &&
      `${r.id} ${name(r.identityId)} ${resource(r.resourceId)?.name} ${r.reason}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const identityRows = data.identities.filter(
    (i) =>
      (filter === "all" || i.kind === filter) &&
      `${i.name} ${i.role} ${i.department}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );

  function IdentityCell({ identity }: { identity?: Identity }) {
    return (
      <span className="identity-cell">
        <Avatar identity={identity} small />
        <span>
          <strong>{identity?.name ?? "Unknown identity"}</strong>
          <small>
            {identity?.kind === "agent" ? "Agent · " : ""}
            {identity?.role}
          </small>
        </span>
      </span>
    );
  }
  function RequestTable({
    rows,
    compact = false,
  }: {
    rows: AccessRequest[];
    compact?: boolean;
  }) {
    if (!rows.length)
      return (
        <Empty
          title="No requests in this view"
          action={
            <button
              className="button secondary"
              onClick={() => setModal("request")}
            >
              <Plus size={16} />
              Create a request
            </button>
          }
        >
          Try another filter or start an access change. Every change starts with
          a reviewable request.
        </Empty>
      );
    return (
      <div className="table-wrap">
        <table>
          <caption className="sr-only">Access change requests</caption>
          <thead>
            <tr>
              <th>Identity / request</th>
              <th>Change</th>
              {!compact && <th>Resource</th>}
              <th>Status</th>
              <th>{compact ? "Received" : "Requested by"}</th>
              <th>
                <span className="sr-only">Details</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>
                  <button
                    className="row-link"
                    onClick={() => setSelection({ kind: "request", id: r.id })}
                  >
                    <IdentityCell identity={person(r.identityId)} />
                  </button>
                  <span className="table-id">{r.id}</span>
                </td>
                <td>
                  <span className="change-type">
                    {r.action === "offboard" ? (
                      <LogOut size={15} />
                    ) : r.action === "grant" ? (
                      <KeyRound size={15} />
                    ) : (
                      <GitBranch size={15} />
                    )}
                    {actionNames[r.action]}
                  </span>
                  {r.action === "offboard" && (
                    <small className="subtext">Includes sponsored agents</small>
                  )}
                </td>
                {!compact && (
                  <td>{resource(r.resourceId)?.name ?? r.resourceId}</td>
                )}
                <td>
                  <Badge value={r.status} />
                </td>
                <td className="muted">
                  {compact ? timeAgo(r.createdAt, now) : name(r.requesterId)}
                </td>
                <td>
                  <button
                    className="icon-button"
                    aria-label={`Open request ${r.id}`}
                    onClick={() => setSelection({ kind: "request", id: r.id })}
                  >
                    <ChevronRight size={17} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  function ModeNote() {
    return (
      <span className="origin-note">
        <Globe2 size={13} />
        {CONNECTED
          ? "Connected lab snapshot"
          : "Counts from this browser scenario"}
      </span>
    );
  }
  function SearchBar({
    placeholder,
    children,
  }: {
    placeholder: string;
    children: ReactNode;
  }) {
    return (
      <div className="filterbar">
        <label className="searchbox">
          <Search size={16} aria-hidden="true" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={placeholder}
            aria-label={placeholder}
          />
          {query && (
            <button
              className="icon-button"
              onClick={() => setQuery("")}
              aria-label="Clear search"
            >
              <X size={14} />
            </button>
          )}
        </label>
        <div className="filter-group">{children}</div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <a
        href="#main-content"
        className="skip-link"
        onClick={(e) => {
          e.preventDefault();
          mainRef.current?.focus();
        }}
      >
        Skip to main content
      </a>
      <aside
        className={`sidebar ${mobileNav ? "mobile-open" : ""}`}
        aria-label="Main navigation"
      >
        <a
          href="#/overview"
          className="brand"
          onClick={() => go("overview")}
          aria-label="AccessOps overview"
        >
          <span className="brand-mark">
            <span />
          </span>
          <span>
            Access<span className="brand-light">Ops</span>
          </span>
          <span className="version">v1</span>
        </a>
        <div className="workspace">
          <span className="org-mark">N</span>
          <div>
            <strong>Northstar Systems</strong>
            <span>Identity operations</span>
          </div>
          <span className="workspace-dot" />
        </div>
        <span className="nav-label">WORKSPACE</span>
        <nav>
          {navigation.map((item) => (
            <a
              key={item.id}
              className={page === item.id ? "nav-item active" : "nav-item"}
              href={`#/${item.id}`}
              aria-current={page === item.id ? "page" : undefined}
              onClick={() => go(item.id)}
            >
              <item.icon size={18} />
              <span>{item.name}</span>
              {item.id === "requests" && pending.length > 0 && (
                <span className="nav-count">{pending.length}</span>
              )}
            </a>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-note">
            <span className="small-kicker">BUILT TO BE INSPECTED</span>
            <p>Follow a change from decision to evidence.</p>
            <button onClick={() => setModal("guide")}>
              Engineering guide
              <ArrowUpRight size={15} />
            </button>
          </div>
          <button className="help-link" onClick={() => setModal("lab")}>
            <Terminal size={16} />
            {CONNECTED ? "About this local lab" : "Run the connected lab"}
            <ArrowUpRight size={14} />
          </button>
          <div className="sidebar-footer">
            <span className="tiny-dot" />
            {CONNECTED ? "Local environment" : "Synthetic workspace"}
            <span>AccessOps</span>
          </div>
        </div>
      </aside>
      {mobileNav && (
        <button
          className="nav-backdrop"
          aria-label="Close navigation"
          onClick={() => setMobileNav(false)}
        />
      )}
      <div className="content-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button menu-button"
              aria-label="Toggle navigation"
              aria-expanded={mobileNav}
              onClick={() => setMobileNav(!mobileNav)}
            >
              <Menu size={20} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{navigation.find((n) => n.id === page)?.name}</strong>
          </div>
          <div className="topbar-actions">
            <span className={`mode-label ${CONNECTED ? "connected" : ""}`}>
              <span />
              {CONNECTED ? "Connected lab" : "Browser simulation"}
            </span>
            {CONNECTED ? (
              <button
                className="button compact secondary"
                onClick={() => void refresh()}
                disabled={busy}
              >
                <RefreshCw size={14} />
                Refresh
              </button>
            ) : (
              <button
                className="icon-button reset-button"
                title="Reset browser simulation"
                aria-label="Reset browser simulation"
                onClick={() => setModal("reset")}
              >
                <RotateCcw size={16} />
              </button>
            )}
            <span className="top-divider" />
            <Avatar identity={person(principal?.id)} small />
          </div>
        </header>
        <div
          className="environment-strip"
          role="region"
          aria-label="Environment"
        >
          <span>
            <span className="square-indicator" />
            {CONNECTED
              ? "Actions use your authenticated server session. Provider verification is recorded separately."
              : "Synthetic data · Changes stay in this browser tab · No live identities or external APIs"}
          </span>
          {!CONNECTED && (
            <button onClick={() => setModal("lab")}>
              About the two experiences
              <ArrowUpRight size={12} />
            </button>
          )}
        </div>
        <main id="main-content" ref={mainRef} tabIndex={-1}>
          <div className="page-header">
            <div>
              <div className="eyebrow">
                NORTHSTAR SYSTEMS <span>/</span> ACCESS GOVERNANCE
              </div>
              <h1>
                {page === "overview"
                  ? "Access operations"
                  : navigation.find((n) => n.id === page)?.name}
              </h1>
              <p>{pageDescriptions[page]}</p>
            </div>
            <div className="page-header-actions">
              {!CONNECTED && (
                <label className="actor-select">
                  <span>SIMULATED OPERATOR</span>
                  <select
                    aria-label="Simulated operator"
                    value={actor.id}
                    onChange={(e) =>
                      setActor(operators.find((o) => o.id === e.target.value)!)
                    }
                  >
                    {operators.map((o) => (
                      <option key={o.id} value={o.id}>
                        {o.name}
                        {o.roles.includes("reviewer")
                          ? " · Reviewer"
                          : o.roles.includes("operator")
                            ? " · Operator"
                            : " · Sponsor"}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {page === "identities" && (
                <button
                  className="button primary"
                  onClick={() => setModal("enroll")}
                  disabled={CONNECTED && !session?.authenticated}
                >
                  <Plus size={16} />
                  Register identity
                </button>
              )}
              {(page === "overview" || page === "requests") && (
                <button
                  className="button primary"
                  onClick={() => setModal("request")}
                  disabled={CONNECTED && !session?.authenticated}
                >
                  <Plus size={16} />
                  New request
                </button>
              )}
            </div>
          </div>
          {loadError && (
            <div role="alert" className="error-banner">
              <CircleAlert size={18} />
              <span>{loadError}</span>
              <button onClick={() => void refresh()}>Try again</button>
            </div>
          )}
          {CONNECTED && !session?.authenticated ? (
            <Panel
              title="Connect your operator session"
              subtitle="AccessOps uses the server to complete sign-in and retain OAuth credentials."
            >
              <Empty
                title={
                  busy ? "Checking your session" : "Sign in to the local lab"
                }
                action={
                  <a className="button primary" href="/auth/login">
                    <LogIn size={16} />
                    Sign in with the lab identity provider
                  </a>
                }
              >
                Connected mode never falls back to synthetic results. Your
                authenticated role determines which actions you can take.
              </Empty>
            </Panel>
          ) : (
            <>
              {page === "overview" && (
                <>
                  {!CONNECTED && (
                    <div className="hero">
                      <div className="hero-copy">
                        <span className="hero-kicker">
                          <span className="pulse-dot" />
                          THE 90-SECOND WALKTHROUGH
                        </span>
                        <h2>
                          An employee leaves.
                          <br />
                          Their agent shouldn’t stay.
                        </h2>
                        <p>
                          Review Mara’s departure, suspend her sponsored agent,
                          and see access denied before the next action.
                        </p>
                        <div className="hero-actions">
                          <button
                            className="button primary"
                            onClick={startGuide}
                          >
                            <Play size={15} fill="currentColor" />
                            Start guided scenario
                            <ArrowRight size={16} />
                          </button>
                          <button
                            className="button subtle"
                            onClick={() => setModal("guide")}
                          >
                            Explore the engineering
                            <ArrowUpRight size={15} />
                          </button>
                        </div>
                        <small>
                          Interactive browser simulation · resets the scenario
                        </small>
                      </div>
                      <div
                        className="hero-visual"
                        aria-label="Employee departure affects human and sponsored agent access"
                      >
                        <div className="visual-caption">
                          ONE CHANGE. BOTH IDENTITIES.
                        </div>
                        <div className="relationship">
                          <div className="relationship-node">
                            <Avatar identity={person("mara")} />
                            <strong>Mara Patel</strong>
                            <small>Human sponsor</small>
                          </div>
                          <div className="relationship-line">
                            <span>SPONSORS</span>
                            <span />
                          </div>
                          <div className="relationship-node">
                            <Avatar identity={person("atlas-agent")} />
                            <strong>Atlas digest</strong>
                            <small>Bounded agent</small>
                          </div>
                        </div>
                        <div className="visual-divider" />
                        <div className="visual-outcome">
                          <ShieldCheck size={17} />
                          <span>Authorized containment</span>
                          <span className="visual-outcome-dot" />
                          <span>Verified outcome</span>
                        </div>
                      </div>
                    </div>
                  )}
                  <div className="metrics">
                    <Metric
                      label="Awaiting approval"
                      value={pending.filter((r) => !isContainment(r)).length}
                      detail="Grants and transfers need a reviewer"
                      icon={<GitBranch />}
                      onClick={() => {
                        go("requests");
                        setFilter("pending");
                      }}
                    />
                    <Metric
                      label="Sponsored agents"
                      value={
                        data.identities.filter((i) => i.kind === "agent").length
                      }
                      detail="Every agent has an accountable owner"
                      icon={<Bot />}
                      onClick={() => {
                        go("identities");
                        setFilter("agent");
                      }}
                    />
                    <Metric
                      label="Active grants"
                      value={
                        data.grants.filter(
                          (g) =>
                            g.status === "active" &&
                            (!g.expiresAt || Date.parse(g.expiresAt) > now),
                        ).length
                      }
                      detail="Permissions currently in scope"
                      icon={<KeyRound />}
                      onClick={() => go("identities")}
                    />
                    <Metric
                      label="Verified changes"
                      value={
                        data.requests.filter((r) => r.status === "verified")
                          .length
                      }
                      detail={
                        CONNECTED
                          ? "Observed by the local backend"
                          : "Verified in the browser model only"
                      }
                      icon={<FileCheck2 />}
                      onClick={() => {
                        go("requests");
                        setFilter("verified");
                      }}
                    />
                  </div>
                  <div className="section-meta">
                    <ModeNote />
                    <span>
                      Simulation and recorded evidence are always separate.
                    </span>
                  </div>
                  <div className="overview-grid">
                    <Panel
                      title="Needs your attention"
                      subtitle="Decisions and changes waiting for their next step."
                      action={
                        <button
                          className="text-link"
                          onClick={() => go("requests")}
                        >
                          All requests
                          <ArrowRight size={15} />
                        </button>
                      }
                    >
                      <RequestTable
                        rows={data.requests
                          .filter((r) =>
                            [
                              "pending",
                              "approved",
                              "applied",
                              "failed",
                            ].includes(r.status),
                          )
                          .slice(0, 5)}
                        compact
                      />
                    </Panel>
                    <Panel title="Enforcement, in order" className="flow-panel">
                      <div className="flow-step">
                        <span>01</span>
                        <div>
                          <strong>Choose the right decision path</strong>
                          <p>
                            Grants need review. Authorized containment acts
                            immediately.
                          </p>
                        </div>
                      </div>
                      <div className="flow-step">
                        <span>02</span>
                        <div>
                          <strong>Apply authorization state</strong>
                          <p>
                            Access changes before a protected action can occur.
                          </p>
                        </div>
                      </div>
                      <div className="flow-step">
                        <span>03</span>
                        <div>
                          <strong>Observe the provider</strong>
                          <p>
                            Delivery, enforcement and verification stay
                            distinct.
                          </p>
                        </div>
                      </div>
                      <button
                        className="text-link"
                        onClick={() => go("policies")}
                      >
                        Inspect the rules
                        <ArrowRight size={15} />
                      </button>
                    </Panel>
                  </div>
                  <div className="overview-grid bottom-grid">
                    <Panel
                      title="Recent activity"
                      subtitle={
                        CONNECTED
                          ? "Operations returned by the local backend."
                          : "Only actions performed in this browser scenario."
                      }
                    >
                      {data.audit.length ? (
                        <div className="activity-list">
                          {data.audit.slice(0, 4).map((a) => (
                            <div key={a.id}>
                              <span className="activity-mark">
                                <Activity size={14} />
                              </span>
                              <div>
                                <strong>{a.action}</strong>
                                <p>{auditSummary(a.detail)}</p>
                                <small>
                                  {name(a.actorId)} · {formatDate(a.at)}
                                </small>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="quiet-state">
                          <Clock3 size={22} />
                          <div>
                            <strong>Your next action starts the trail</strong>
                            <p>
                              Open a request or try the guided scenario to see
                              decisions recorded here.
                            </p>
                          </div>
                        </div>
                      )}
                    </Panel>
                    <Panel title="Evidence you can inspect">
                      <div className="evidence-intro">
                        <span className="evidence-icon">
                          <FileCheck2 size={24} />
                        </span>
                        <strong>
                          {recorded.length
                            ? `${recorded.length} recorded local run${recorded.length === 1 ? "" : "s"}`
                            : "Real evidence starts with a real run"}
                        </strong>
                        <p>
                          {recorded.length
                            ? "Dated receipts, checks and limitations from actual local executions."
                            : "No recorded local runs have been published yet. Browser actions never create real-run evidence."}
                        </p>
                        <button
                          className="button secondary"
                          onClick={() => go("runs")}
                        >
                          Open runs & evidence
                          <ArrowRight size={15} />
                        </button>
                      </div>
                    </Panel>
                  </div>
                </>
              )}
              {page === "requests" && (
                <Panel
                  title="Change requests"
                  subtitle={`${data.requests.length} request${data.requests.length === 1 ? "" : "s"} in this ${CONNECTED ? "lab" : "scenario"}`}
                >
                  <SearchBar placeholder="Search identities, requests or reasons">
                    <ListFilter size={16} aria-hidden="true" />
                    <select
                      aria-label="Filter requests by status"
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                    >
                      <option value="all">All statuses</option>
                      {[
                        "pending",
                        "approved",
                        "applied",
                        "verified",
                        "expired",
                        "failed",
                      ].map((s) => (
                        <option value={s} key={s}>
                          {s[0].toUpperCase() + s.slice(1)}
                        </option>
                      ))}
                    </select>
                  </SearchBar>
                  <RequestTable rows={requestRows} />
                  <div className="table-footer">
                    <span>Authorization ≠ application ≠ verification</span>
                    <span>{requestRows.length} shown</span>
                  </div>
                </Panel>
              )}
              {page === "identities" && (
                <>
                  <Panel
                    title="Identity directory"
                    subtitle="Identity status, access and sponsorship are evaluated together."
                  >
                    <SearchBar placeholder="Search names, roles or departments">
                      <div
                        className="segmented"
                        aria-label="Identity type filter"
                      >
                        {["all", "human", "agent"].map((f) => (
                          <button
                            key={f}
                            className={filter === f ? "selected" : ""}
                            aria-pressed={filter === f}
                            onClick={() => setFilter(f)}
                          >
                            {f === "all"
                              ? "All identities"
                              : f === "human"
                                ? "People"
                                : "Agents"}
                          </button>
                        ))}
                      </div>
                    </SearchBar>
                    {identityRows.length ? (
                      <div className="table-wrap">
                        <table>
                          <caption className="sr-only">
                            Identity directory
                          </caption>
                          <thead>
                            <tr>
                              <th>Identity</th>
                              <th>Department</th>
                              <th>Accountable owner</th>
                              <th>Active grants</th>
                              <th>Status</th>
                              <th>
                                <span className="sr-only">Details</span>
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            {identityRows.map((i) => (
                              <tr key={i.id}>
                                <td>
                                  <button
                                    className="row-link"
                                    onClick={() =>
                                      setSelection({
                                        kind: "identity",
                                        id: i.id,
                                      })
                                    }
                                  >
                                    <IdentityCell identity={i} />
                                  </button>
                                </td>
                                <td>{i.department}</td>
                                <td>
                                  {i.kind === "agent" ? (
                                    <button
                                      className="text-link"
                                      onClick={() =>
                                        setSelection({
                                          kind: "identity",
                                          id: i.sponsorId!,
                                        })
                                      }
                                    >
                                      {name(i.sponsorId)}
                                    </button>
                                  ) : (
                                    <span className="muted">
                                      Human identity
                                    </span>
                                  )}
                                </td>
                                <td>
                                  <span className="number-pill">
                                    {
                                      data.grants.filter(
                                        (g) =>
                                          g.identityId === i.id &&
                                          g.status === "active" &&
                                          (!g.expiresAt ||
                                            Date.parse(g.expiresAt) > now),
                                      ).length
                                    }
                                  </span>
                                </td>
                                <td>
                                  <Badge value={i.status} />
                                </td>
                                <td>
                                  <button
                                    className="icon-button"
                                    onClick={() =>
                                      setSelection({
                                        kind: "identity",
                                        id: i.id,
                                      })
                                    }
                                    aria-label={`Inspect ${i.name}`}
                                  >
                                    <ChevronRight size={17} />
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <Empty title="No identities match">
                        Try a different name or identity type.
                      </Empty>
                    )}
                  </Panel>
                  {!CONNECTED && (
                    <Panel
                      title="Try a protected read"
                      subtitle="The model checks identity, sponsorship, grant expiry and policy before simulating a resource effect."
                      className="probe-panel"
                    >
                      <div className="probe-controls">
                        <label>
                          Identity
                          <select
                            value={probeIdentity}
                            onChange={(e) => setProbeIdentity(e.target.value)}
                          >
                            {data.identities.map((i) => (
                              <option key={i.id} value={i.id}>
                                {i.name}
                              </option>
                            ))}
                          </select>
                        </label>
                        <label>
                          Resource
                          <select
                            value={probeResource}
                            onChange={(e) => setProbeResource(e.target.value)}
                          >
                            {data.resources.map((r) => (
                              <option key={r.id} value={r.id}>
                                {r.name}
                              </option>
                            ))}
                          </select>
                        </label>
                        <button
                          className="button primary"
                          onClick={() =>
                            void perform({
                              type: "access",
                              identityId: probeIdentity,
                              resourceId: probeResource,
                            })
                          }
                        >
                          <Play size={15} />
                          Try simulated read
                        </button>
                      </div>
                      {simulation.attempts[0] && (
                        <div
                          className={`access-result ${simulation.attempts[0].allowed ? "allow" : "deny"}`}
                          role="status"
                        >
                          <ShieldCheck size={20} />
                          <div>
                            <strong>
                              {simulation.attempts[0].allowed
                                ? "Allowed"
                                : "Denied before effect"}{" "}
                              · {name(simulation.attempts[0].identityId)}
                            </strong>
                            <p>{simulation.attempts[0].reason}</p>
                          </div>
                          <span>
                            {simulation.attempts[0].effects} simulated effects
                          </span>
                        </div>
                      )}
                    </Panel>
                  )}
                </>
              )}
              {page === "reviews" && (
                <>
                  <div className="principle-banner">
                    <span>
                      <Sparkles size={20} />
                    </span>
                    <div>
                      <strong>
                        A review assistant can propose. It cannot approve.
                      </strong>
                      <p>
                        Bounded deterministic analysis treats record contents as
                        untrusted data. Grant and transfer proposals require
                        independent approval; containment requires an authorized
                        human operator.
                      </p>
                    </div>
                    <Badge value="neutral">Proposal only</Badge>
                  </div>
                  {data.reviews.map((review) => (
                    <Panel
                      key={review.id}
                      title={review.name}
                      subtitle={`${review.id} · Assigned to ${name(review.assignedTo)} · Due ${formatDate(review.dueAt)}`}
                      action={
                        <button
                          className="button primary"
                          disabled={busy}
                          onClick={() =>
                            void perform({ type: "review", id: review.id })
                          }
                        >
                          <Sparkles size={15} />
                          {review.findings.length
                            ? "Refresh review draft"
                            : "Run bounded review"}
                        </button>
                      }
                    >
                      <div className="review-summary">
                        <span>
                          <Database size={15} />
                          {review.resourceIds.length} resources in scope
                        </span>
                        <span>
                          <FileSearch size={15} />
                          {review.findings.length} findings
                        </span>
                        <Badge value={review.status} />
                      </div>
                      {review.findings.length ? (
                        <div className="findings">
                          {review.findings.map((f) => (
                            <article className="finding" key={f.id}>
                              <div className="finding-top">
                                <Badge value={f.severity} />
                                <span>
                                  {name(f.identityId)}
                                  <span className="dot-separator">·</span>
                                  {resource(f.resourceId)?.name}
                                </span>
                              </div>
                              <h3>{f.title}</h3>
                              <p>{f.detail}</p>
                              <details>
                                <summary>Inspect supporting record</summary>
                                <blockquote>
                                  {Array.isArray(f.evidence)
                                    ? f.evidence.join("\n")
                                    : f.evidence}
                                </blockquote>
                                <small>
                                  Record contents are data, never executable
                                  instructions or approval authority.
                                </small>
                              </details>
                              <div className="finding-action">
                                {f.id === "untrusted-note" ? (
                                  <span className="safe-label">
                                    <ShieldCheck size={15} />
                                    Excluded from the approval path
                                  </span>
                                ) : f.proposedRequestId ? (
                                  <button
                                    className="text-link"
                                    onClick={() =>
                                      setSelection({
                                        kind: "request",
                                        id: f.proposedRequestId!,
                                      })
                                    }
                                  >
                                    Inspect unapproved proposal{" "}
                                    {f.proposedRequestId}
                                    <ArrowRight size={15} />
                                  </button>
                                ) : (
                                  <button
                                    className="button secondary compact"
                                    disabled={busy}
                                    onClick={() =>
                                      void perform({
                                        type: "propose",
                                        reviewId: review.id,
                                        findingId: f.id,
                                      })
                                    }
                                  >
                                    <Plus size={14} />
                                    Draft revocation request
                                  </button>
                                )}
                              </div>
                            </article>
                          ))}
                        </div>
                      ) : (
                        <Empty title="Ready for a bounded review">
                          Run the review to compare the scenario’s grants and
                          surface findings. The assistant has no approval or
                          execution capability.
                        </Empty>
                      )}
                    </Panel>
                  ))}
                  <Panel
                    title="Provider drift"
                    subtitle="An external membership is an observation, not an approved grant."
                    className="drift-panel"
                  >
                    <div className="drift-content">
                      <div>
                        <h3>Compare intended and observed access</h3>
                        <p>
                          {CONNECTED
                            ? "Reconciliation records mismatches from the configured provider without silently authorizing them."
                            : "Add an unapproved membership to the provider model, then detect it. AccessOps will still deny a read without an active grant."}
                        </p>
                      </div>
                      <div className="inline-actions">
                        {!CONNECTED && (
                          <button
                            className="button secondary"
                            onClick={() => void perform({ type: "drift" })}
                          >
                            <Plus size={15} />
                            Inject synthetic drift
                          </button>
                        )}
                        <button
                          className="button primary"
                          disabled={busy}
                          onClick={() => void perform({ type: "reconcile" })}
                        >
                          <RefreshCw size={15} />
                          Reconcile access
                        </button>
                      </div>
                    </div>
                  </Panel>
                </>
              )}
              {page === "policies" && (
                <>
                  <div className="policies-grid">
                    {data.policies.map((p, index) => (
                      <article className="policy-card" key={p.id}>
                        <div className="policy-top">
                          <span className="policy-icon">
                            {index === 0 ? (
                              <Users size={21} />
                            ) : index === 1 ? (
                              <Bot size={21} />
                            ) : (
                              <ShieldCheck size={21} />
                            )}
                          </span>
                          <span className="mono">{p.version}</span>
                        </div>
                        <h2>{p.name}</h2>
                        <p>{p.description}</p>
                        <ul>
                          {p.rules.map((rule) => (
                            <li key={rule}>
                              <Check size={14} />
                              <span>{rule}</span>
                            </li>
                          ))}
                        </ul>
                      </article>
                    ))}
                  </div>
                  <Panel
                    title="Resource catalog"
                    subtitle="Permissions have a named resource, a purpose and an accountable owner."
                  >
                    <div className="resource-grid">
                      {data.resources.map((r) => (
                        <article key={r.id}>
                          <div className="resource-heading">
                            <span className="resource-icon">
                              <Database size={18} />
                            </span>
                            <Badge
                              value={
                                r.sensitivity === "Restricted"
                                  ? "medium"
                                  : "neutral"
                              }
                            >
                              {r.sensitivity}
                            </Badge>
                          </div>
                          <h3>{r.name}</h3>
                          <span className="small-kicker">{r.project}</span>
                          <p>{r.description}</p>
                          <div className="resource-owner">
                            <Avatar identity={person(r.ownerId)} small />
                            <span>
                              Owner<strong>{name(r.ownerId)}</strong>
                            </span>
                          </div>
                        </article>
                      ))}
                    </div>
                  </Panel>
                  <Panel
                    title={
                      CONNECTED
                        ? "Connection state"
                        : "Explore failure behavior"
                    }
                    subtitle={
                      CONNECTED
                        ? "Health reported by the connected backend."
                        : "These controls change only the in-memory scenario."
                    }
                  >
                    <div className="health-list">
                      {data.health.map((h) => (
                        <div key={h.name}>
                          <span className="health-icon">
                            <Network size={18} />
                          </span>
                          <div>
                            <strong>{h.name}</strong>
                            <p>{h.detail}</p>
                          </div>
                          <Badge value={h.status} />
                        </div>
                      ))}
                    </div>
                    {!CONNECTED && (
                      <div className="scenario-controls">
                        <button
                          className="button secondary"
                          onClick={() =>
                            void perform({
                              type: "outage",
                              enabled: !data.health.some(
                                (h) => h.status === "unavailable",
                              ),
                            })
                          }
                        >
                          <ShieldOff size={15} />
                          {data.health.some((h) => h.status === "unavailable")
                            ? "Restore policy service"
                            : "Simulate policy outage"}
                        </button>
                        <button
                          className="button secondary"
                          onClick={() => void perform({ type: "advance" })}
                        >
                          <Clock3 size={15} />
                          Advance clock 16 minutes
                        </button>
                        <span>
                          Scenario time:{" "}
                          {formatDate(new Date(now).toISOString())}
                        </span>
                      </div>
                    )}
                  </Panel>
                </>
              )}
              {page === "runs" && (
                <>
                  <div className="evidence-boundary">
                    <FileCheck2 size={21} />
                    <div>
                      <strong>Evidence has an origin.</strong>
                      <p>
                        Recorded runs came from an actual local execution.
                        Browser checks describe this simulation only. Neither is
                        a production certification.
                      </p>
                    </div>
                    <button
                      className="text-link"
                      onClick={() => setModal("guide")}
                    >
                      How to inspect a run
                      <ArrowUpRight size={14} />
                    </button>
                  </div>
                  <Panel
                    title="Recorded local runs"
                    subtitle="Sanitized historical receipts published with this build."
                  >
                    {evidenceError ? (
                      <div className="inline-error" role="alert">
                        <CircleAlert size={19} />
                        <p>{evidenceError} No results are assumed.</p>
                        <button
                          className="button secondary compact"
                          onClick={() => {
                            setEvidenceError("");
                            loadRecordedEvidence()
                              .then(setRecorded)
                              .catch((e) => setEvidenceError(e.message));
                          }}
                        >
                          Retry loading evidence
                        </button>
                      </div>
                    ) : recorded.length ? (
                      <div className="run-list">
                        {recorded.map((run) => (
                          <RunRow
                            run={run}
                            key={run.id}
                            onOpen={() =>
                              setSelection({ kind: "run", id: run.id })
                            }
                          />
                        ))}
                      </div>
                    ) : (
                      <Empty
                        title="No recorded local runs published yet"
                        action={
                          <button
                            className="button secondary"
                            onClick={() => setModal("lab")}
                          >
                            <Terminal size={15} />
                            See the local lab workflow
                          </button>
                        }
                      >
                        The public simulation cannot create real connector
                        evidence. This section will show dated manifests after
                        actual local runs are exported.
                      </Empty>
                    )}
                  </Panel>
                  {CONNECTED && (
                    <Panel
                      title="Connected lab runs"
                      subtitle="Current execution records from the authenticated backend."
                    >
                      {data.runs.length ? (
                        <div className="run-list">
                          {data.runs.map((run) => (
                            <RunRow
                              run={run}
                              key={run.id}
                              onOpen={() =>
                                setSelection({ kind: "run", id: run.id })
                              }
                            />
                          ))}
                        </div>
                      ) : (
                        <Empty title="No connected runs yet">
                          Execute a local scenario, then refresh this snapshot
                          to inspect its checks.
                        </Empty>
                      )}
                    </Panel>
                  )}
                  {!CONNECTED && (
                    <Panel
                      title="Browser scenario checks"
                      subtitle="Results of actions taken in this tab. No external service was exercised."
                      action={
                        (simulation.attempts.length > 0 ||
                          simulation.checks.length > 0) && (
                          <button
                            className="button secondary compact"
                            onClick={() =>
                              downloadJson("accessops-simulation-only.json", {
                                origin: "browser-simulation",
                                synthetic: true,
                                recordedLocalRun: false,
                                at: new Date(now).toISOString(),
                                attempts: simulation.attempts,
                                checks: simulation.checks,
                              })
                            }
                          >
                            <ArrowDownToLine size={14} />
                            Export simulation
                          </button>
                        )
                      }
                    >
                      {simulation.attempts.length ||
                      simulation.checks.length ? (
                        <div className="simulation-evidence">
                          {simulation.checks.map((c, i) => (
                            <div className="check-row" key={`${c.name}-${i}`}>
                              <span className="check-icon">
                                <Check size={16} />
                              </span>
                              <div>
                                <strong>{c.name}</strong>
                                <p>{c.detail}</p>
                              </div>
                              <Badge value="neutral">Simulation</Badge>
                            </div>
                          ))}
                          {simulation.attempts.map((a) => (
                            <div className="check-row" key={a.id}>
                              <span
                                className={`check-icon ${a.allowed ? "" : "denial"}`}
                              >
                                {a.allowed ? (
                                  <KeyRound size={16} />
                                ) : (
                                  <ShieldOff size={16} />
                                )}
                              </span>
                              <div>
                                <strong>
                                  {name(a.identityId)} →{" "}
                                  {resource(a.resourceId)?.name}
                                </strong>
                                <p>{a.reason}</p>
                                <small>
                                  {formatDate(a.at)} · {a.effects} simulated
                                  resource effects
                                </small>
                              </div>
                              <Badge value={a.allowed ? "allowed" : "denied"} />
                            </div>
                          ))}
                        </div>
                      ) : (
                        <Empty
                          title="Run a scenario to inspect its decisions"
                          action={
                            <button
                              className="button secondary"
                              onClick={startGuide}
                            >
                              <Play size={15} />
                              Start guided scenario
                            </button>
                          }
                        >
                          Allowed reads, denied reads and state comparisons will
                          appear here, marked as browser simulation.
                        </Empty>
                      )}
                    </Panel>
                  )}
                  <Panel
                    title="Decision trail"
                    subtitle={
                      CONNECTED
                        ? "Server-reported audit events. Verify integrity using the accompanying manifest."
                        : "Chronological browser actions, without a cryptographic integrity claim."
                    }
                  >
                    {data.audit.length ? (
                      <div
                        className="table-wrap"
                        role="region"
                        aria-label="Decision trail"
                        tabIndex={0}
                      >
                        <table>
                          <caption className="sr-only">Decision trail</caption>
                          <thead>
                            <tr>
                              <th>When</th>
                              <th>Actor</th>
                              <th>Action</th>
                              <th>Target</th>
                              <th>Detail</th>
                            </tr>
                          </thead>
                          <tbody>
                            {data.audit.map((a) => (
                              <tr key={a.id}>
                                <td className="nowrap muted">
                                  {formatDate(a.at)}
                                </td>
                                <td>{name(a.actorId)}</td>
                                <td>{a.action}</td>
                                <td className="mono">{a.targetId}</td>
                                <td className="audit-detail">
                                  {auditSummary(a.detail)}
                                  {typeof a.detail === "object" && (
                                    <details className="audit-record">
                                      <summary>Inspect event record</summary>
                                      <pre
                                        tabIndex={0}
                                        role="region"
                                        aria-label="Serialized event record"
                                      >
                                        {JSON.stringify(
                                          a.detail,
                                          null,
                                          2,
                                        ).slice(0, 16000)}
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
                      <div className="quiet-state">
                        <Activity size={20} />
                        <p>No actions have been recorded in this session.</p>
                      </div>
                    )}
                  </Panel>
                </>
              )}
            </>
          )}
          <footer className="page-footer">
            <span>
              <span className="brand-mini">A</span>AccessOps{" "}
              <span className="dot-separator">·</span> Identity operations, made
              inspectable.
            </span>
            <button onClick={() => setModal("guide")}>
              Architecture & boundaries
              <ArrowUpRight size={12} />
            </button>
          </footer>
        </main>
      </div>
      <Drawer
        open={!!selectedRequest}
        modal={guideStep < 0}
        onClose={() => {
          setSelection(null);
          setGuideStep(-1);
        }}
        title={
          selectedRequest
            ? `${selectedRequest.id} · ${actionNames[selectedRequest.action]}`
            : "Request"
        }
        description={
          CONNECTED
            ? "Current server state. Approval and verification are separate."
            : "Browser simulation · exact change and its decision trail"
        }
        wide
      >
        {selectedRequest && (
          <>
            <div className="detail-identity">
              <Avatar identity={person(selectedRequest.identityId)} />
              <div>
                <h3>{name(selectedRequest.identityId)}</h3>
                <p>{person(selectedRequest.identityId)?.role}</p>
              </div>
              <Badge value={selectedRequest.status} />
            </div>
            <div className="detail-section">
              <h3>Requested change</h3>
              <p className="reason-copy">{selectedRequest.reason}</p>
              <dl className="key-values">
                <div>
                  <dt>Resource</dt>
                  <dd>{resource(selectedRequest.resourceId)?.name}</dd>
                </div>
                <div>
                  <dt>Permission</dt>
                  <dd>
                    {selectedRequest.action === "offboard"
                      ? "All active grants revoked"
                      : (selectedRequest.permission ?? "Existing permission")}
                  </dd>
                </div>
                <div>
                  <dt>Requested by</dt>
                  <dd>{name(selectedRequest.requesterId)}</dd>
                </div>
                <div>
                  <dt>Policy version</dt>
                  <dd className="mono">{selectedRequest.policyVersion}</dd>
                </div>
                {selectedRequest.approverId && (
                  <div>
                    <dt>Approved by</dt>
                    <dd>{name(selectedRequest.approverId)}</dd>
                  </div>
                )}
                {selectedRequest.approvalExpiresAt && (
                  <div>
                    <dt>Approval expires</dt>
                    <dd>{formatDate(selectedRequest.approvalExpiresAt)}</dd>
                  </div>
                )}
                {selectedRequest.newSponsorId && (
                  <div>
                    <dt>New sponsor</dt>
                    <dd>{name(selectedRequest.newSponsorId)}</dd>
                  </div>
                )}
                {selectedRequest.action === "transfer" && (
                  <div>
                    <dt>Successor acceptance</dt>
                    <dd>
                      {selectedRequest.acceptedBy ===
                      selectedRequest.newSponsorId
                        ? `Accepted by ${name(selectedRequest.acceptedBy)}`
                        : "Awaiting the named successor"}
                    </dd>
                  </div>
                )}
                {selectedRequest.targetDepartment && (
                  <div>
                    <dt>Target department</dt>
                    <dd>
                      {selectedRequest.targetDepartment} · old department grants
                      removed
                    </dd>
                  </div>
                )}
              </dl>
            </div>
            {selectedRequest.action === "offboard" && (
              <div className="impact-box">
                <h3>
                  <Network size={17} />
                  Linked identity impact
                </h3>
                <p>
                  Employee departure also suspends sponsored agents and revokes
                  their active grants. Reassignment requires another reviewed
                  change.
                </p>
                {data.identities
                  .filter((i) => i.sponsorId === selectedRequest.identityId)
                  .map((i) => (
                    <button
                      className="linked-identity"
                      key={i.id}
                      onClick={() => {
                        setGuideStep(-1);
                        setSelection({ kind: "identity", id: i.id });
                      }}
                    >
                      <Avatar identity={i} small />
                      <span>
                        {i.name}
                        <small>{i.role}</small>
                      </span>
                      <Badge value={i.status} />
                      <ChevronRight size={15} />
                    </button>
                  ))}
              </div>
            )}
            <div className="state-stages">
              {(isContainment(selectedRequest)
                ? ["authorized", "applied", "verified"]
                : ["approved", "applied", "verified"]
              ).map((stage, i) => {
                const statuses = ["pending", "approved", "applied", "verified"];
                const completed = isContainment(selectedRequest)
                  ? i < 2
                    ? ["applied", "verified"].includes(selectedRequest.status)
                    : selectedRequest.status === "verified"
                  : statuses.indexOf(selectedRequest.status) >= i + 1;
                return (
                  <div key={stage} className={completed ? "done" : ""}>
                    <span>{completed ? <Check size={15} /> : i + 1}</span>
                    <strong>{stage}</strong>
                  </div>
                );
              })}
            </div>
            <div className="detail-section">
              <h3>Decision timeline</h3>
              <ol className="timeline">
                {selectedRequest.events.map((e, i) => (
                  <li key={`${e.label}-${i}`}>
                    <span className="timeline-icon">
                      <StateIcon status={e.status} />
                    </span>
                    <div>
                      <strong>{e.label}</strong>
                      <p>{e.detail}</p>
                      <small>{formatDate(e.at)}</small>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
            <div className="decision-box">
              {toast?.error && (
                <p role="alert" className="form-error">
                  {toast.message}
                </p>
              )}
              <h3>
                {selectedRequest.status === "pending"
                  ? isContainment(selectedRequest)
                    ? "Authorized containment"
                    : "Independent review required"
                  : selectedRequest.status === "approved"
                    ? "Approved, ready to apply"
                    : selectedRequest.status === "applied"
                      ? "Applied, awaiting observation"
                      : selectedRequest.status === "verified"
                        ? "Verification recorded"
                        : "A fresh decision is needed"}
              </h3>
              <p>
                {selectedRequest.status === "pending"
                  ? isContainment(selectedRequest)
                    ? "An authorized operator can remove access immediately. Containment is audited and does not wait for a second approval."
                    : "Approval covers the exact identity, resource, action, reason and policy version for 15 minutes."
                  : selectedRequest.status === "approved"
                    ? "Application rechecks the approval, identity and policy. Access has not changed yet."
                    : selectedRequest.status === "applied"
                      ? "AccessOps authorization state has changed. Provider delivery and revocation evidence are still separate."
                      : selectedRequest.status === "verified"
                        ? CONNECTED
                          ? "Inspect the run manifest for the actual checks and limitations."
                          : "Only the browser provider model was checked. Actual token and session revocation needs local-run evidence."
                        : "Expired or failed requests cannot silently regain approval."}
              </p>
              <div className="inline-actions">
                {selectedRequest.status === "pending" &&
                  isContainment(selectedRequest) && (
                    <button
                      className="button primary"
                      disabled={busy}
                      onClick={() =>
                        void perform({
                          type: "execute",
                          id: selectedRequest.id,
                        })
                      }
                    >
                      <ShieldOff size={16} />
                      Apply containment
                    </button>
                  )}
                {selectedRequest.status === "pending" &&
                  !isContainment(selectedRequest) && (
                    <>
                      {selectedRequest.action === "transfer" &&
                        selectedRequest.acceptedBy !==
                          selectedRequest.newSponsorId && (
                          <button
                            className="button secondary"
                            disabled={busy}
                            onClick={() =>
                              void perform({
                                type: "accept",
                                id: selectedRequest.id,
                              })
                            }
                          >
                            <UserRound size={16} />
                            Accept sponsorship
                          </button>
                        )}
                      <button
                        className="button primary"
                        disabled={busy}
                        onClick={() =>
                          void perform({
                            type: "approve",
                            id: selectedRequest.id,
                          })
                        }
                      >
                        <ShieldCheck size={16} />
                        Approve exact change
                      </button>
                    </>
                  )}
                {selectedRequest.status === "approved" && (
                  <button
                    className="button primary"
                    disabled={busy}
                    onClick={() =>
                      void perform({ type: "execute", id: selectedRequest.id })
                    }
                  >
                    <Play size={15} />
                    Apply approved change
                  </button>
                )}
                {selectedRequest.status === "applied" &&
                  (!CONNECTED ? (
                    <button
                      className="button primary"
                      onClick={() =>
                        void perform({ type: "verify", id: selectedRequest.id })
                      }
                    >
                      <FileCheck2 size={16} />
                      Check simulated provider
                    </button>
                  ) : (
                    <button
                      className="button secondary"
                      onClick={() => void refresh()}
                      disabled={busy}
                    >
                      <RefreshCw size={15} />
                      Refresh provider outcome
                    </button>
                  ))}
                {selectedRequest.status === "verified" && (
                  <button
                    className="button secondary"
                    onClick={() => {
                      setGuideStep(-1);
                      go("runs");
                    }}
                  >
                    Inspect evidence
                    <ArrowRight size={15} />
                  </button>
                )}
              </div>
              {!CONNECTED &&
                selectedRequest.status === "pending" &&
                !isContainment(selectedRequest) &&
                actor.id !== "op-avery" && (
                  <div className="reviewer-hint">
                    <UserRound size={16} />
                    <span>Approval needs an independent reviewer.</span>
                    <button onClick={() => setActor(operators[1])}>
                      Switch to Avery, reviewer
                      <ArrowRight size={14} />
                    </button>
                  </div>
                )}
              {!CONNECTED &&
                selectedRequest.status === "pending" &&
                selectedRequest.action === "transfer" &&
                selectedRequest.newSponsorId === "nina" &&
                actor.id !== "nina" && (
                  <div className="reviewer-hint">
                    <UserRound size={16} />
                    <span>The named successor must accept responsibility.</span>
                    <button onClick={() => setActor(operators[2])}>
                      Switch to Nina, successor
                      <ArrowRight size={14} />
                    </button>
                  </div>
                )}
            </div>
          </>
        )}
      </Drawer>
      <Drawer
        open={!!selectedIdentity}
        onClose={() => setSelection(null)}
        title={selectedIdentity?.name ?? "Identity"}
        description="Current access, sponsorship and lifecycle state"
      >
        {selectedIdentity && (
          <>
            <div className="detail-identity">
              <Avatar identity={selectedIdentity} />
              <div>
                <h3>
                  {selectedIdentity.kind === "agent"
                    ? "Agent identity"
                    : "Human identity"}
                </h3>
                <p>{selectedIdentity.role}</p>
              </div>
              <Badge value={selectedIdentity.status} />
            </div>
            <dl className="key-values">
              <div>
                <dt>Department</dt>
                <dd>{selectedIdentity.department}</dd>
              </div>
              <div>
                <dt>Owner</dt>
                <dd>
                  {selectedIdentity.kind === "agent"
                    ? name(selectedIdentity.sponsorId)
                    : "Human identity"}
                </dd>
              </div>
              <div>
                <dt>Stable subject</dt>
                <dd className="mono break-text">
                  {selectedIdentity.providerSubject ?? selectedIdentity.id}
                </dd>
              </div>
              <div>
                <dt>Updated</dt>
                <dd>{formatDate(selectedIdentity.updatedAt)}</dd>
              </div>
              {selectedIdentity.projectIds && (
                <div>
                  <dt>Projects</dt>
                  <dd>{selectedIdentity.projectIds.join(", ")}</dd>
                </div>
              )}
              {selectedIdentity.providerBinding && (
                <div>
                  <dt>Provider binding</dt>
                  <dd>{selectedIdentity.providerBinding}</dd>
                </div>
              )}
              {selectedIdentity.kind === "agent" &&
                selectedIdentity.credentialBinding && (
                  <div>
                    <dt>Agent credential binding</dt>
                    <dd>
                      {selectedIdentity.credentialBinding.replaceAll("-", " ")}
                    </dd>
                  </div>
                )}
            </dl>
            {selectedIdentity.kind === "human" &&
              selectedIdentity.status === "active" && (
                <button
                  className="button secondary"
                  onClick={() => {
                    setDepartmentIdentityId(selectedIdentity.id);
                    setSelection(null);
                    setModal("department");
                  }}
                >
                  <GitBranch size={15} />
                  Request department transfer
                </button>
              )}
            {selectedIdentity.kind === "agent" &&
              selectedIdentity.status === "suspended" && (
                <div className="small-notice">
                  <ShieldOff size={18} />
                  <p>
                    Recovery requires reviewed local credential binding and a
                    separate approved grant. A sponsor change does not
                    reactivate this agent.
                  </p>
                </div>
              )}
            <div className="detail-section">
              <h3>Access grants</h3>
              {data.grants.filter((g) => g.identityId === selectedIdentity.id)
                .length ? (
                <div className="grant-list">
                  {data.grants
                    .filter((g) => g.identityId === selectedIdentity.id)
                    .map((g) => (
                      <article key={g.id}>
                        <div>
                          <strong>{resource(g.resourceId)?.name}</strong>
                          <Badge value={g.status} />
                        </div>
                        <p>{g.purpose}</p>
                        <dl>
                          <div>
                            <dt>Permission</dt>
                            <dd>{g.permission}</dd>
                          </div>
                          <div>
                            <dt>Expires</dt>
                            <dd>{formatDate(g.expiresAt)}</dd>
                          </div>
                          {g.maxCalls !== undefined && (
                            <div>
                              <dt>Call budget</dt>
                              <dd>
                                {g.callsUsed ?? 0} / {g.maxCalls} used
                              </dd>
                            </div>
                          )}
                          <div>
                            <dt>Approval source</dt>
                            <dd className="mono">
                              {!CONNECTED &&
                              g.sourceRequestId?.startsWith("baseline-")
                                ? `Baseline fixture · ${g.sourceRequestId}`
                                : (g.sourceRequestId ?? "Missing provenance")}
                            </dd>
                          </div>
                        </dl>
                        {!CONNECTED && (
                          <button
                            className="text-link"
                            onClick={() =>
                              void perform({
                                type: "access",
                                identityId: selectedIdentity.id,
                                resourceId: g.resourceId,
                              })
                            }
                          >
                            Try a simulated read
                            <Play size={13} />
                          </button>
                        )}
                      </article>
                    ))}
                </div>
              ) : (
                <div className="quiet-state">
                  <KeyRound size={18} />
                  <p>No grants are assigned to this identity.</p>
                </div>
              )}
            </div>
            {data.identities.some(
              (i) => i.sponsorId === selectedIdentity.id,
            ) && (
              <div className="detail-section">
                <h3>Sponsored agents</h3>
                {data.identities
                  .filter((i) => i.sponsorId === selectedIdentity.id)
                  .map((i) => (
                    <button
                      key={i.id}
                      className="linked-identity"
                      onClick={() =>
                        setSelection({ kind: "identity", id: i.id })
                      }
                    >
                      <Avatar identity={i} small />
                      <span>{i.name}</span>
                      <Badge value={i.status} />
                      <ChevronRight size={15} />
                    </button>
                  ))}
              </div>
            )}
            {!CONNECTED && (
              <div className="small-notice">
                <Globe2 size={16} />
                <p>
                  This identity is synthetic. No account credentials or real
                  personal records are present.
                </p>
              </div>
            )}
          </>
        )}
      </Drawer>
      <Drawer
        open={!!selectedRun}
        onClose={() => setSelection(null)}
        title={selectedRun?.name ?? "Run"}
        description={
          selectedRun
            ? `${selectedRun.origin === "recorded" ? "Recorded local execution" : "Connected execution"} · ${selectedRun.id}`
            : "Evidence"
        }
        wide
      >
        {selectedRun && (
          <>
            <div className="run-summary">
              <Badge value={selectedRun.status} />
              <span>{formatDate(selectedRun.startedAt)}</span>
            </div>
            <p className="reason-copy">{selectedRun.summary}</p>
            {runLimitations.length > 0 && (
              <div className="detail-section">
                <h3>Scope and limitations</h3>
                <ul className="run-limitations">
                  {runLimitations.map((limitation, index) => (
                    <li key={index}>{limitation}</li>
                  ))}
                </ul>
              </div>
            )}
            <div className="detail-section">
              <h3>Executed checks</h3>
              {selectedRun.checks.map((check, i) => (
                <div className="check-row" key={`${check.name}-${i}`}>
                  <span className="check-icon">
                    <StateIcon status={check.status} />
                  </span>
                  <div>
                    <strong>{check.name}</strong>
                    <p>{check.detail}</p>
                  </div>
                  <Badge value={check.status} />
                </div>
              ))}
            </div>
            <button
              className="button secondary"
              onClick={() =>
                downloadJson(
                  `accessops-${selectedRun.id.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`,
                  selectedRun,
                )
              }
            >
              <ArrowDownToLine size={15} />
              Download this run record
            </button>
            <details className="raw-record">
              <summary>Inspect the serialized record</summary>
              <pre>{JSON.stringify(selectedRun, null, 2)}</pre>
            </details>
          </>
        )}
      </Drawer>
      <Modal
        open={modal === "request"}
        onClose={() => setModal(null)}
        title="New access request"
        description="Describe the smallest change needed. Submission does not grant access."
      >
        {toast?.error && (
          <p role="alert" className="form-error">
            {toast.message}
          </p>
        )}
        <RequestForm
          data={data}
          busy={busy}
          onSubmit={(input) => void perform({ type: "create", input })}
        />
      </Modal>
      <Modal
        open={modal === "enroll"}
        onClose={() => setModal(null)}
        title="Register an identity"
        description="Create an inventory record with explicit ownership. Registration issues no access grant or agent credential."
      >
        {toast?.error && (
          <p role="alert" className="form-error">
            {toast.message}
          </p>
        )}
        <EnrollmentForm
          data={data}
          busy={busy}
          onSubmit={(input) => void perform({ type: "enroll", input })}
        />
      </Modal>
      <Modal
        open={modal === "department"}
        onClose={() => setModal(null)}
        title="Request department transfer"
        description="Independent approval is required. Previous department grants are revoked; new access needs a separate request."
      >
        {toast?.error && (
          <p role="alert" className="form-error">
            {toast.message}
          </p>
        )}
        <DepartmentForm
          identity={person(departmentIdentityId)}
          busy={busy}
          onSubmit={(department, reason) =>
            void perform({
              type: "department",
              identityId: departmentIdentityId,
              department,
              reason,
            })
          }
        />
      </Modal>
      <Modal
        open={modal === "reset"}
        onClose={() => setModal(null)}
        title="Reset the browser scenario?"
        description="This removes only the synthetic changes and checks in this tab."
      >
        <p className="modal-copy">
          The initial Northstar workspace will be restored. Recorded local
          evidence is unaffected.
        </p>
        <div className="modal-actions">
          <button className="button secondary" onClick={() => setModal(null)}>
            Keep exploring
          </button>
          <button
            className="button primary"
            onClick={() => {
              setSimulation(initialSimulation());
              setActor(operators[0]);
              setGuideStep(-1);
              setSelection(null);
              setModal(null);
              setToast({ message: "Browser scenario reset." });
            }}
          >
            <RotateCcw size={15} />
            Reset scenario
          </button>
        </div>
      </Modal>
      <Modal
        open={modal === "lab"}
        onClose={() => setModal(null)}
        title="Two experiences, clear boundaries"
        description="Explore without setup. Reproduce real operations in your own local lab."
      >
        <div className="experience-card">
          <Globe2 size={22} />
          <div>
            <h3>Public browser simulation</h3>
            <p>
              Fictional identities and an in-memory provider model. No login,
              paid API, live connection or LLM. Refreshing the tab resets state.
            </p>
          </div>
          <Badge value="neutral">You can explore now</Badge>
        </div>
        <div className="experience-card">
          <Terminal size={22} />
          <div>
            <h3>Authenticated local lab</h3>
            <p>
              The backend owns identity validation, policy decisions and
              connector effects. OAuth tokens stay on the server. Real runs
              produce dated receipts.
            </p>
          </div>
          <Badge value={CONNECTED ? "active" : "neutral"}>
            {CONNECTED ? "This build" : "Self-hosted"}
          </Badge>
        </div>
        <div className="detail-section">
          <h3>Local setup route</h3>
          <ol className="numbered-list">
            <li>
              Read the repository’s setup guide and generate local secrets and
              trusted certificates.
            </li>
            <li>
              Start the isolated lab services, then open the configured local
              HTTPS address.
            </li>
            <li>
              Sign in as an authorized operator, run the scenario and inspect
              its actual checks.
            </li>
            <li>Export sanitized evidence separately for the public viewer.</li>
          </ol>
          {sourceUrl ? (
            <External href={sourceUrl}>
              Open source & setup instructions
            </External>
          ) : (
            <p className="muted">
              Public source publication is pending. The local repository
              contains setup instructions.
            </p>
          )}
        </div>
        {CONNECTED && session?.authenticated && (
          <button
            className="button secondary"
            onClick={() => {
              setBusy(true);
              lab
                .logout()
                .then(() => {
                  setSession(null);
                  setConnectedData(emptySnapshot);
                  setModal(null);
                })
                .catch((e) => setToast({ message: e.message, error: true }))
                .finally(() => setBusy(false));
            }}
            disabled={busy}
          >
            <LogOut size={15} />
            Sign out of the lab
          </button>
        )}
      </Modal>
      <Modal
        open={modal === "guide"}
        onClose={() => setModal(null)}
        title="The ten-minute engineering route"
        description="Start with the trust boundary, then follow a single change to evidence."
      >
        <div className="architecture-strip">
          <span>
            <UserRound size={18} />
            Operator
          </span>
          <ArrowRight size={15} />
          <span>
            <ShieldCheck size={18} />
            Server policy
          </span>
          <ArrowRight size={15} />
          <span>
            <Database size={18} />
            Provider
          </span>
          <ArrowRight size={15} />
          <span>
            <FileCheck2 size={18} />
            Evidence
          </span>
        </div>
        <ol className="engineering-route">
          <li>
            <span>01</span>
            <div>
              <h3>Identity & enforcement</h3>
              <p>
                Human sessions and agent tokens are validated at the server
                boundary. Browser state is never authority.
              </p>
              <button
                className="text-link"
                onClick={() => {
                  setModal(null);
                  go("policies");
                }}
              >
                Inspect policy rules
                <ArrowRight size={14} />
              </button>
            </div>
          </li>
          <li>
            <span>02</span>
            <div>
              <h3>One exact change</h3>
              <p>
                Follow grants through independent approval and expiry; follow
                authorized containment directly to enforcement. Both require
                observed provider results.
              </p>
              <button
                className="text-link"
                onClick={() => {
                  setModal(null);
                  go("requests");
                }}
              >
                Open change requests
                <ArrowRight size={14} />
              </button>
            </div>
          </li>
          <li>
            <span>03</span>
            <div>
              <h3>Failure & recovery</h3>
              <p>
                Inspect denial before effects, unavailable policy, expiry and
                unapproved provider drift. Agent proposals cannot approve
                themselves.
              </p>
              <button
                className="text-link"
                onClick={() => {
                  setModal(null);
                  go("reviews");
                }}
              >
                Inspect bounded reviews
                <ArrowRight size={14} />
              </button>
            </div>
          </li>
          <li>
            <span>04</span>
            <div>
              <h3>What actually ran</h3>
              <p>
                Review dated checks, failures, skipped work and source
                provenance. Simulated results never count as a real connector
                run.
              </p>
              <button
                className="text-link"
                onClick={() => {
                  setModal(null);
                  go("runs");
                }}
              >
                Open runs & evidence
                <ArrowRight size={14} />
              </button>
            </div>
          </li>
        </ol>
        <div className="source-block">
          <Code2 size={19} />
          <div>
            <strong>Source and reproducibility</strong>
            {sourceUrl ? (
              <External href={sourceUrl}>Browse AccessOps source</External>
            ) : (
              <p>
                Public repository publication pending. Source paths:
                frontend/src/domain.ts, backend/, policies/, integrations/ and
                contracts/.
              </p>
            )}
          </div>
        </div>
      </Modal>
      {guideStep >= 0 && (
        <div className="guide-coach" role="region" aria-label="Guided scenario">
          <div className="guide-progress">
            {[0, 1, 2, 3, 4, 5].map((n) => (
              <span className={n <= guideStep ? "filled" : ""} key={n} />
            ))}
          </div>
          <button
            className="icon-button coach-close"
            aria-label="Close guided scenario"
            onClick={() => setGuideStep(-1)}
          >
            <X size={16} />
          </button>
          <small>
            GUIDED SCENARIO <span>{guideStep + 1} / 6</span>
          </small>
          <h3>
            {
              [
                "Start with working access",
                "Inspect the full containment scope",
                "Remove access without delay",
                "Observe the provider model",
                "Retry the same protected reads",
                "Separate the demonstration from proof",
              ][guideStep]
            }
          </h3>
          <p>
            {
              [
                "Mara and Atlas digest can currently read the knowledge base. Establish that baseline first.",
                "Mara sponsors Atlas digest. This departure covers both identities and their three active grants.",
                "Jules is an authorized operator. Offboarding suspends the agent and revokes grants immediately; containment does not wait for independent approval.",
                "Authorization state has changed. Now compare the simulated provider state. An acknowledgment alone is not verification.",
                "Use the same identities and resource as before. Both reads should be denied with zero resource effects.",
                "Inspect the browser checks, then look for separately published real local runs.",
              ][guideStep]
            }
          </p>
          <button className="button primary" onClick={advanceGuide}>
            {
              [
                "Check existing access",
                "Confirm affected scope",
                "Apply containment",
                "Check simulated provider",
                "Retry both reads",
                "Inspect the evidence",
              ][guideStep]
            }
            <ArrowRight size={15} />
          </button>
        </div>
      )}
      {toast && (
        <div
          className={`toast ${toast.error ? "error" : ""}`}
          role={toast.error ? "alert" : "status"}
        >
          <span>
            {toast.error ? <CircleAlert size={19} /> : <Check size={19} />}
          </span>
          <p>{toast.message}</p>
          <button
            className="icon-button"
            aria-label="Dismiss notification"
            onClick={() => setToast(null)}
          >
            <X size={16} />
          </button>
        </div>
      )}
      {busy && (
        <div className="busy-indicator" role="status">
          <LoaderCircle size={15} className="spin" />
          Waiting for the local server…
        </div>
      )}
    </div>
  );
}

function Metric({
  label,
  value,
  detail,
  icon,
  onClick,
}: {
  label: string;
  value: number;
  detail: string;
  icon: ReactNode;
  onClick: () => void;
}) {
  return (
    <button className="metric" onClick={onClick}>
      <span className="metric-top">
        {label}
        <span>{icon}</span>
      </span>
      <strong>
        {value}
        <ArrowUpRight size={18} />
      </strong>
      <small>{detail}</small>
    </button>
  );
}
function RunRow({ run, onOpen }: { run: Run; onOpen: () => void }) {
  return (
    <button className="run-row" onClick={onOpen}>
      <span className="run-icon">
        <FileCheck2 size={20} />
      </span>
      <span>
        <strong>{run.name}</strong>
        <small>
          {run.id} · {formatDate(run.startedAt)} · {run.checks.length} checks
        </small>
      </span>
      <Badge value={run.status} />
      <ChevronRight size={18} />
    </button>
  );
}
function RequestForm({
  data,
  busy,
  onSubmit,
}: {
  data: Snapshot;
  busy: boolean;
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
  const [error, setError] = useState("");
  const selectedIdentity = data.identities.find(
    (identity) => identity.id === identityId,
  );
  function submit(e: FormEvent) {
    e.preventDefault();
    if (reason.trim().length < 12) {
      setError("Describe the business purpose in at least 12 characters.");
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
    <form onSubmit={submit} className="request-form">
      <label>
        Identity
        <select
          value={identityId}
          onChange={(e) => setIdentityId(e.target.value)}
          required
        >
          {data.identities.map((i) => (
            <option key={i.id} value={i.id}>
              {i.name} · {i.kind}
            </option>
          ))}
        </select>
      </label>
      <div className="form-grid">
        <label>
          Change
          <select
            value={action}
            onChange={(e) => setAction(e.target.value as NewRequest["action"])}
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
        <label>
          Resource
          <select
            value={resourceId}
            onChange={(e) => setResourceId(e.target.value)}
            required
          >
            {data.resources.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
        </label>
      </div>
      {action === "grant" && (
        <div className="form-grid">
          <label>
            Permission
            <select
              value={permission}
              onChange={(e) => setPermission(e.target.value)}
            >
              <option value="read">Read</option>
            </select>
          </label>
          <div className="form-static">
            <span>Grant duration</span>
            <strong>
              {selectedIdentity?.kind === "agent"
                ? "10 minutes · 6 calls"
                : "Until explicitly revoked"}
            </strong>
            <small>
              {CONNECTED
                ? "Enforced by the local server policy"
                : "Enforced by the browser model"}
            </small>
          </div>
        </div>
      )}
      {action === "transfer" && (
        <label>
          New accountable sponsor
          <select
            value={newSponsorId}
            onChange={(e) => setNewSponsorId(e.target.value)}
          >
            {data.identities
              .filter((i) => i.kind === "human" && i.status === "active")
              .map((i) => (
                <option key={i.id} value={i.id}>
                  {i.name}
                </option>
              ))}
          </select>
        </label>
      )}
      <label>
        Business reason
        <textarea
          value={reason}
          onChange={(e) => {
            setReason(e.target.value);
            setError("");
          }}
          rows={4}
          minLength={12}
          maxLength={255}
          required
          placeholder="What task needs this change, and why is this scope sufficient?"
        />
        <span className="input-help">
          12–255 characters · {reason.length}/255
        </span>
      </label>
      {action === "offboard" && (
        <div className="small-notice">
          <Bot size={18} />
          <p>
            Offboarding also suspends this person’s sponsored agents and revokes
            their active grants.
          </p>
        </div>
      )}
      {error && (
        <p role="alert" className="form-error">
          {error}
        </p>
      )}
      <div className="form-footer">
        <span>
          <ShieldCheck size={15} />
          {isContainment({ action })
            ? "Authorized operator containment"
            : "Independent human approval required"}
        </span>
        <button
          className="button primary"
          type="submit"
          disabled={busy || !identityId || !resourceId}
        >
          Submit request
          <ArrowRight size={16} />
        </button>
      </div>
    </form>
  );
}

function EnrollmentForm({
  data,
  busy,
  onSubmit,
}: {
  data: Snapshot;
  busy: boolean;
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
      className="request-form"
      onSubmit={(e) => {
        e.preventDefault();
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
      <div className="form-grid">
        <label>
          Identity type
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as "human" | "agent")}
          >
            <option value="human">Employee</option>
            <option value="agent">AI agent</option>
          </select>
        </label>
        <label>
          Department
          <select
            value={department}
            onChange={(e) => {
              const value = e.target.value as "Engineering" | "Operations";
              setDepartment(value);
              setProject(value === "Engineering" ? "Atlas" : "Pulse");
            }}
          >
            <option>Engineering</option>
            <option>Operations</option>
          </select>
        </label>
      </div>
      <label>
        Name
        <input
          required
          minLength={3}
          maxLength={100}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={
            kind === "agent" ? "Atlas change assistant" : "Taylor Reed"
          }
        />
      </label>
      <label>
        Synthetic email
        <input
          type="email"
          required
          maxLength={200}
          pattern="[^@]+@example\.test"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="taylor.reed@example.test"
        />
        <span className="input-help">
          Use @example.test for this synthetic workspace.
        </span>
      </label>
      <label>
        Project scope
        <select value={project} onChange={(e) => setProject(e.target.value)}>
          <option>Atlas</option>
          <option>Pulse</option>
        </select>
      </label>
      {kind === "agent" && (
        <label>
          Accountable human sponsor
          <select
            value={sponsorId}
            onChange={(e) => setSponsorId(e.target.value)}
          >
            {data.identities
              .filter((i) => i.kind === "human" && i.status === "active")
              .map((i) => (
                <option key={i.id} value={i.id}>
                  {i.name}
                </option>
              ))}
          </select>
        </label>
      )}
      <div className="small-notice">
        <Fingerprint size={18} />
        <p>
          {kind === "agent"
            ? "The agent begins suspended. Secure credential binding must complete before activation; this form cannot mint credentials."
            : "The employee record is created with provider binding pending. Registration does not assign application permissions."}
        </p>
      </div>
      <div className="form-footer">
        <span>Record creation is audited.</span>
        <button type="submit" className="button primary" disabled={busy}>
          Register {kind === "human" ? "employee" : "agent"}
          <ArrowRight size={15} />
        </button>
      </div>
    </form>
  );
}

function DepartmentForm({
  identity,
  busy,
  onSubmit,
}: {
  identity?: Identity;
  busy: boolean;
  onSubmit: (department: string, reason: string) => void;
}) {
  const [department, setDepartment] = useState(
    identity?.department === "Engineering" ? "Operations" : "Engineering",
  );
  const [reason, setReason] = useState("");
  return (
    <form
      className="request-form"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(department, reason.trim());
      }}
    >
      <div className="small-notice">
        <UserRound size={18} />
        <p>
          {identity?.name} currently belongs to {identity?.department}. The
          request binds the target department and reason for review.
        </p>
      </div>
      <label style={{ marginTop: 18 }}>
        Target department
        <select
          value={department}
          onChange={(e) => setDepartment(e.target.value)}
        >
          {["Engineering", "Operations"]
            .filter((d) => d !== identity?.department)
            .map((d) => (
              <option key={d}>{d}</option>
            ))}
        </select>
      </label>
      <label>
        Business reason
        <textarea
          required
          minLength={12}
          maxLength={255}
          rows={4}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Explain the department change and the access that must be removed."
        />
      </label>
      <div className="form-footer">
        <span>
          <ShieldCheck size={15} />
          No new grants are added automatically.
        </span>
        <button
          className="button primary"
          disabled={busy || !identity}
          type="submit"
        >
          Request transfer
          <ArrowRight size={15} />
        </button>
      </div>
    </form>
  );
}
