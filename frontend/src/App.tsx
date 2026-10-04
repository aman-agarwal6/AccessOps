import { useCallback, useEffect, useRef, useState } from "react";
import { Check, CircleAlert, LoaderCircle, LogIn, Plus, X } from "lucide-react";
import {
  dispatchSimulation,
  initialSimulation,
  operators,
  type Command,
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
  assessSimulatedCase,
  attestSimulatedTask,
  casePacket,
  closeSimulatedCase,
  containSimulatedCase,
  createSimulatedCase,
  importSimulatedReport,
  initialOffboardingCases,
  reconcileSimulatedCase,
  type OffboardingCase,
} from "./offboarding";
import type { CaseCommand } from "./casecommands";
import { sla } from "./caseflow";
import { applyTheme, saveTheme, storedTheme, type Theme } from "./theme";
import { Sidebar, Topbar } from "./shell";
import { Coach, GuideDialog, LabDialog, ResetDialog } from "./dialogs";
import { IdentityDrawer, RequestDrawer, RunDrawer } from "./details";
import { DepartmentForm, EnrollmentForm, RequestForm } from "./forms";
import { Overview } from "./pages/Overview";
import { CasesPage } from "./pages/cases/CasesPage";
import {
  IdentitiesPage,
  PoliciesPage,
  RequestsPage,
  ReviewsPage,
} from "./pages/Governance";
import { EvidencePage } from "./pages/Evidence";
import { Callout, Empty, External, Modal, Panel } from "./ui";
import {
  pageInfo,
  readPage,
  type ModalKind,
  type Page,
  type Selection,
  type Workspace,
} from "./workspace";

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
const message = (error: unknown, fallback: string) =>
  error instanceof Error ? error.message : fallback;

export default function App() {
  const [simulation, setSimulation] = useState<Simulation>(() =>
    initialSimulation(),
  );
  const [connectedData, setConnectedData] = useState<Snapshot>(emptySnapshot);
  const [caseSimulation, setCaseSimulation] = useState<OffboardingCase[]>([]);
  const [session, setSession] = useState<Session | null>(null);
  const [page, setPage] = useState<Page>(readPage);
  const [navKey, setNavKey] = useState(0);
  const [initialFilter, setInitialFilter] = useState("");
  const [actor, setActor] = useState<Principal>(operators[0]);
  const [selection, setSelection] = useState<Selection>(null);
  const [modal, setModal] = useState<ModalKind>(null);
  const [departmentIdentityId, setDepartmentIdentityId] = useState("");
  const [navOpen, setNavOpen] = useState(false);
  const [toast, setToast] = useState<{ text: string; error?: boolean } | null>(
    null,
  );
  const [surfaceError, setSurfaceError] = useState("");
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [recorded, setRecorded] = useState<Run[]>([]);
  const [recordedState, setRecordedState] = useState<
    "loading" | "ready" | "error"
  >("loading");
  const [recordedError, setRecordedError] = useState("");
  const [guideStep, setGuideStep] = useState(-1);
  const [theme, setTheme] = useState<Theme>(storedTheme);
  const [clock, setClock] = useState(() => Date.now());
  const mainRef = useRef<HTMLElement>(null);
  const shownPage = useRef(page);

  const data = CONNECTED ? connectedData : simulation.snapshot;
  const now = CONNECTED ? clock : Math.max(simulation.now, clock);
  const cases = CONNECTED
    ? (data.offboardingCases ?? [])
    : caseSimulation.map((item) => assessSimulatedCase(item, now));
  const principal = CONNECTED ? session?.principal : actor;
  const authenticated = !CONNECTED || !!session?.authenticated;
  const sourceUrl = import.meta.env.VITE_SOURCE_URL as string | undefined;
  const person = (id?: string) => data.identities.find((i) => i.id === id);
  const resource = (id?: string) => data.resources.find((r) => r.id === id);
  const name = (id?: string) =>
    person(id)?.name ??
    operators.find((entry) => entry.id === id)?.name ??
    id ??
    "Unassigned";

  /* ---------- effects ---------- */
  useEffect(() => {
    if (!CONNECTED)
      void initialOffboardingCases(simulation.now).then(setCaseSimulation);
    if (CONNECTED) void refresh();
    const timer = setInterval(() => setClock(Date.now()), 30000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => applyTheme(theme), [theme]);
  useEffect(() => {
    const update = () => {
      setPage(readPage());
      setNavOpen(false);
    };
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);
  useEffect(() => {
    document.title = `${pageInfo(page).name} · AccessOps`;
    if (shownPage.current === page) return;
    shownPage.current = page;
    // Move keyboard and screen-reader context to the new page, from the top.
    window.scrollTo({ top: 0 });
    mainRef.current?.focus({ preventScroll: true });
  }, [page]);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), toast.error ? 10000 : 6000);
    return () => clearTimeout(timer);
  }, [toast]);
  useEffect(() => setSurfaceError(""), [selection, modal]);
  useEffect(() => {
    if (!navOpen) return;
    // Mobile drawer: move focus in, close on Escape and return focus to the menu.
    document.querySelector<HTMLElement>(".sidebar .nav-link")?.focus();
    const close = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setNavOpen(false);
      document.querySelector<HTMLElement>(".menu-btn")?.focus();
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [navOpen]);
  const loadRecorded = useCallback(() => {
    const controller = new AbortController();
    setRecordedState("loading");
    setRecordedError("");
    loadRecordedEvidence(controller.signal)
      .then((runs) => {
        setRecorded(runs);
        setRecordedState("ready");
      })
      .catch((error) => {
        if (error.name === "AbortError") return;
        setRecordedError(
          message(error, "Recorded evidence could not be loaded."),
        );
        setRecordedState("error");
      });
    return controller;
  }, []);
  useEffect(() => {
    const controller = loadRecorded();
    return () => controller.abort();
  }, [loadRecorded]);

  /* ---------- actions ---------- */
  async function refresh() {
    setBusy(true);
    setLoadError("");
    try {
      const next = await lab.session();
      setSession(next);
      setConnectedData(
        next.authenticated ? await lab.snapshot() : emptySnapshot,
      );
    } catch (error) {
      setLoadError(message(error, "Could not load the local lab."));
    } finally {
      setBusy(false);
    }
  }
  function report(error: unknown, fallback: string) {
    const text = message(error, fallback);
    if (selection || modal) setSurfaceError(text);
    else setToast({ text, error: true });
  }
  function go(next: Page, filter = "") {
    location.hash = `/${next}`;
    setPage(next);
    setInitialFilter(filter);
    setNavKey((value) => value + 1);
    setSelection(null);
    setNavOpen(false);
  }
  function simulate(commands: Command[], as = actor): string | undefined {
    try {
      let state = simulation;
      let result: ReturnType<typeof dispatchSimulation> | undefined;
      for (const command of commands) {
        result = dispatchSimulation(state, command, as);
        state = result.state;
      }
      setSimulation(state);
      setSurfaceError("");
      setToast({ text: result?.message ?? "Simulation updated." });
      return result?.id;
    } catch (error) {
      report(error, "Action failed.");
      return undefined;
    }
  }
  async function perform(command: Command) {
    if (!CONNECTED) {
      const id = simulate([command]);
      if (
        id &&
        ["create", "enroll", "department", "propose"].includes(command.type)
      ) {
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
          .find((review) => review.id === command.reviewId)
          ?.findings.find((entry) => entry.id === command.findingId);
        if (!finding) throw new Error("Finding not found.");
        await lab.propose(command.reviewId, {
          identityId: finding.identityId,
          resourceId: finding.resourceId,
          reason: `${finding.title}. ${finding.detail}`.slice(0, 255),
        });
      } else
        throw new Error(
          "This scenario control exists only in the browser simulation.",
        );
      setConnectedData(await lab.snapshot());
      setModal(null);
      setToast({
        text: "The server accepted the action. The refreshed data shows its current outcome.",
      });
    } catch (error) {
      report(error, "The lab action failed.");
    } finally {
      setBusy(false);
    }
  }
  async function performCase(
    command: CaseCommand,
  ): Promise<string | undefined> {
    if (!principal || busy) return undefined;
    setBusy(true);
    try {
      if (CONNECTED) {
        let result: unknown;
        if (command.type === "create")
          result = await lab.createCase(command.input);
        else if (command.type === "import")
          result = await lab.importCase(command.id, command.report);
        else if (command.type === "contain")
          result = await lab.containCase(command.id);
        else if (command.type === "reconcile") result = await lab.reconcile();
        else if (command.type === "observeDirectory")
          result = await lab.observeDirectory(command.id);
        else if (command.type === "attest")
          result = await lab.attestCase(
            command.id,
            command.taskId,
            command.reference,
            command.summary,
          );
        else
          result = await lab.closeCase({
            id: command.id,
            revision: command.expectedRevision,
            packetHash: command.packetHash,
          });
        setConnectedData(await lab.snapshot());
        return command.type === "create"
          ? (result as { result: OffboardingCase }).result.id
          : command.id;
      }
      let item: OffboardingCase;
      if (command.type === "create") {
        const identity = data.identities.find(
          (entry) =>
            entry.id === command.input.identityId && entry.kind === "human",
        );
        if (!identity) throw new Error("Choose an existing person.");
        if (cases.some((entry) => entry.hrEventId === command.input.hrEventId))
          throw new Error("This HR event already has a case.");
        item = await createSimulatedCase(
          command.input,
          principal,
          now,
          identity.name,
        );
      } else {
        const current = cases.find((entry) => entry.id === command.id);
        if (!current) throw new Error("This departure case was not found.");
        if (command.type === "import")
          item = await importSimulatedReport(
            current,
            command.report,
            principal,
            now,
          );
        else if (command.type === "contain") {
          const result = await containSimulatedCase(
            current,
            simulation,
            principal,
            now,
          );
          item = result.item;
          setSimulation(result.simulation);
        } else if (command.type === "attest")
          item = await attestSimulatedTask(
            current,
            command.taskId,
            command.reference,
            command.summary,
            principal,
            now,
          );
        else if (command.type === "reconcile") {
          const result = await reconcileSimulatedCase(
            current,
            simulation,
            principal,
            now,
          );
          item = result.item;
          setSimulation(result.simulation);
        } else if (command.type === "observeDirectory")
          throw new Error(
            "Directory refresh needs an enrolled case in the connected lab.",
          );
        else
          item = await closeSimulatedCase(
            current,
            principal,
            now,
            command.expectedRevision,
            command.packetHash,
          );
      }
      setCaseSimulation((previous) => [
        item,
        ...previous.filter((entry) => entry.id !== item.id),
      ]);
      return item.id;
    } finally {
      setBusy(false);
    }
  }
  async function exportPacket(id: string) {
    setBusy(true);
    try {
      const item = cases.find((entry) => entry.id === id);
      if (!item) throw new Error("This departure case was not found.");
      downloadJson(
        `${item.hrEventId}-${item.status === "closed" ? "closure" : "draft"}-packet.json`,
        CONNECTED ? await lab.casePacket(id) : casePacket(item),
      );
    } catch (error) {
      report(error, "The packet could not be exported.");
    } finally {
      setBusy(false);
    }
  }
  function resetSimulation() {
    const next = initialSimulation();
    setSimulation(next);
    void initialOffboardingCases(next.now).then(setCaseSimulation);
    setActor(operators[0]);
    setGuideStep(-1);
    setSelection(null);
    setModal(null);
    setToast({ text: "Simulation reset." });
  }
  function startGuide() {
    const next = initialSimulation();
    setSimulation(next);
    void initialOffboardingCases(next.now).then(setCaseSimulation);
    setActor(operators[0]);
    go("overview");
    setSelection({ kind: "request", id: "RQ-1042" });
    setGuideStep(0);
  }
  function advanceGuide() {
    const reads: Command[] = [
      { type: "access", identityId: "mara", resourceId: "atlas" },
      { type: "access", identityId: "atlas-agent", resourceId: "atlas" },
    ];
    if (guideStep === 0) simulate(reads);
    if (guideStep === 1)
      setToast({
        text: "Scope: Mara plus the Atlas digest agent, three active grants. Containment is an authorized operator action.",
      });
    if (guideStep === 2)
      simulate([{ type: "execute", id: "RQ-1042" }], operators[0]);
    if (guideStep === 3)
      simulate([{ type: "verify", id: "RQ-1042" }], operators[0]);
    if (guideStep === 4) simulate(reads, operators[0]);
    if (guideStep === 5) {
      go("runs");
      setGuideStep(-1);
      return;
    }
    setGuideStep(guideStep + 1);
  }
  function signOut() {
    setBusy(true);
    lab
      .logout()
      .then(() => {
        setSession(null);
        setConnectedData(emptySnapshot);
        setModal(null);
      })
      .catch((error) => report(error, "Sign-out failed."))
      .finally(() => setBusy(false));
  }

  const ws: Workspace = {
    connected: CONNECTED,
    authenticated,
    data,
    cases,
    simulation,
    recorded,
    recordedState,
    recordedError,
    principal,
    now,
    busy,
    sourceUrl,
    person,
    resource,
    name,
    go,
    select: setSelection,
    openModal: setModal,
    perform,
    performCase,
    exportPacket,
    exportSimulation: () =>
      downloadJson("accessops-simulation-only.json", {
        origin: "browser-simulation",
        synthetic: true,
        recordedLocalRun: false,
        at: new Date(now).toISOString(),
        attempts: simulation.attempts,
        checks: simulation.checks,
      }),
    retryRecorded: () => void loadRecorded(),
    startGuide,
    actAs: CONNECTED
      ? undefined
      : (id) => {
          const next = operators.find((entry) => entry.id === id);
          if (next) {
            setActor(next);
            setToast({ text: `Now acting as ${next.name}.` });
          }
        },
    initialFilter,
  };

  const selectedRequest =
    selection?.kind === "request"
      ? data.requests.find((request) => request.id === selection.id)
      : undefined;
  const selectedIdentity =
    selection?.kind === "identity" ? person(selection.id) : undefined;
  const selectedRun =
    selection?.kind === "run"
      ? [...recorded, ...data.runs].find((run) => run.id === selection.id)
      : undefined;
  const openCases = cases.filter((item) => item.status !== "closed");
  const info = pageInfo(page);

  return (
    <div className="shell">
      <a
        href="#main-content"
        className="skip-link"
        onClick={(event) => {
          event.preventDefault();
          mainRef.current?.focus();
        }}
      >
        Skip to main content
      </a>
      <Sidebar
        page={page}
        open={navOpen}
        connected={CONNECTED}
        counts={{
          cases: openCases.length,
          overdue: openCases.filter((item) => sla(item, now).kind === "overdue")
            .length,
          requests: data.requests.filter(
            (request) => request.status === "pending",
          ).length,
        }}
        sourceUrl={sourceUrl}
        go={go}
        openModal={setModal}
      />
      {navOpen && (
        <button
          className="nav-backdrop"
          aria-label="Close navigation"
          onClick={() => setNavOpen(false)}
        />
      )}
      <div className="main-col">
        <Topbar
          page={page}
          connected={CONNECTED}
          actor={actor}
          principal={session?.principal}
          busy={busy}
          theme={theme}
          navOpen={navOpen}
          onMenu={() => setNavOpen(!navOpen)}
          onActor={(id) =>
            setActor(operators.find((entry) => entry.id === id)!)
          }
          onTheme={() => {
            const next = theme === "dark" ? "light" : "dark";
            saveTheme(next);
            setTheme(next);
          }}
          onReset={() => setModal("reset")}
          onRefresh={() => void refresh()}
          onSignOut={session?.authenticated ? signOut : undefined}
        />
        <main id="main-content" ref={mainRef} tabIndex={-1} className="page">
          {loadError && (
            <div style={{ marginBottom: 24 }}>
              <Callout
                tone="danger"
                role="alert"
                action={
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => void refresh()}
                  >
                    Try again
                  </button>
                }
              >
                {loadError}
              </Callout>
            </div>
          )}
          {CONNECTED && !session?.authenticated ? (
            <Panel
              title="Sign in to the local lab"
              description="The server completes sign-in and keeps OAuth tokens. Nothing is stored in the browser."
            >
              <Empty
                title={
                  busy
                    ? "Checking your session…"
                    : "Your operator session has ended"
                }
                icon={<LogIn size={24} />}
                action={
                  <a className="btn btn-primary" href="/auth/login">
                    <LogIn size={16} aria-hidden="true" />
                    Sign in with the lab identity provider
                  </a>
                }
              >
                Connected mode never falls back to synthetic data. Your
                authenticated role decides which actions you can take.
              </Empty>
            </Panel>
          ) : (
            <div key={`${page}-${navKey}`}>
              {page !== "cases" && (
                <div className="page-head">
                  <div>
                    <h1>{info.name}</h1>
                    <p>{info.description}</p>
                  </div>
                  <div className="page-actions">
                    {page === "identities" && (
                      <button
                        className="btn btn-primary"
                        onClick={() => setModal("enroll")}
                        disabled={!authenticated}
                      >
                        <Plus size={16} aria-hidden="true" />
                        Register identity
                      </button>
                    )}
                    {(page === "overview" || page === "requests") && (
                      <button
                        className={`btn ${page === "requests" ? "btn-primary" : "btn-secondary"}`}
                        onClick={() => setModal("request")}
                        disabled={!authenticated}
                      >
                        <Plus size={16} aria-hidden="true" />
                        New request
                      </button>
                    )}
                  </div>
                </div>
              )}
              {page === "overview" && <Overview ws={ws} />}
              {page === "cases" && <CasesPage ws={ws} />}
              {page === "requests" && <RequestsPage ws={ws} />}
              {page === "identities" && <IdentitiesPage ws={ws} />}
              {page === "reviews" && <ReviewsPage ws={ws} />}
              {page === "policies" && <PoliciesPage ws={ws} />}
              {page === "runs" && <EvidencePage ws={ws} />}
            </div>
          )}
          <footer className="page-foot">
            <span>
              AccessOps · synthetic identities only · built to be inspected
            </span>
            {sourceUrl ? (
              <External href={sourceUrl}>Source and setup</External>
            ) : (
              <button className="link-btn" onClick={() => setModal("guide")}>
                How it works
              </button>
            )}
          </footer>
        </main>
      </div>

      <RequestDrawer
        ws={ws}
        request={selectedRequest}
        error={surfaceError}
        modal={guideStep < 0}
        onClose={() => {
          setSelection(null);
          setGuideStep(-1);
        }}
        refresh={() => void refresh()}
      />
      <IdentityDrawer
        ws={ws}
        identity={selectedIdentity}
        onClose={() => setSelection(null)}
        onTransfer={(id) => {
          setDepartmentIdentityId(id);
          setSelection(null);
          setModal("department");
        }}
      />
      <RunDrawer run={selectedRun} onClose={() => setSelection(null)} />
      <Modal
        open={modal === "request"}
        onClose={() => setModal(null)}
        title="New access request"
        description="Ask for the smallest change that does the job. Submitting does not grant access."
      >
        <RequestForm
          data={data}
          busy={busy}
          connected={CONNECTED}
          error={surfaceError}
          onSubmit={(input) => void perform({ type: "create", input })}
        />
      </Modal>
      <Modal
        open={modal === "enroll"}
        onClose={() => setModal(null)}
        title="Register an identity"
        description="Create an inventory record with explicit ownership. Registration issues no grant or agent credential."
      >
        <EnrollmentForm
          data={data}
          busy={busy}
          error={surfaceError}
          onSubmit={(input) => void perform({ type: "enroll", input })}
        />
      </Modal>
      <Modal
        open={modal === "department"}
        onClose={() => setModal(null)}
        title="Request department transfer"
        description="Needs independent approval. Old department grants are revoked; new access needs its own request."
      >
        <DepartmentForm
          identity={person(departmentIdentityId)}
          busy={busy}
          error={surfaceError}
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
      <ResetDialog
        open={modal === "reset"}
        onClose={() => setModal(null)}
        onReset={resetSimulation}
      />
      <LabDialog
        open={modal === "lab"}
        onClose={() => setModal(null)}
        connected={CONNECTED}
        sourceUrl={sourceUrl}
        busy={busy}
        onSignOut={session?.authenticated ? signOut : undefined}
      />
      <GuideDialog
        open={modal === "guide"}
        onClose={() => setModal(null)}
        go={go}
        sourceUrl={sourceUrl}
      />
      {guideStep >= 0 && (
        <Coach
          step={guideStep}
          onNext={advanceGuide}
          onClose={() => setGuideStep(-1)}
        />
      )}
      <div className="toast-region" aria-live="polite">
        {toast && (
          <div
            className={`toast ${toast.error ? "error" : ""}`}
            role={toast.error ? "alert" : "status"}
          >
            {toast.error ? (
              <CircleAlert size={18} aria-hidden="true" />
            ) : (
              <Check size={18} aria-hidden="true" />
            )}
            <p>{toast.text}</p>
            <button
              className="icon-btn"
              aria-label="Dismiss notification"
              onClick={() => setToast(null)}
            >
              <X size={16} />
            </button>
          </div>
        )}
      </div>
      {busy && CONNECTED && (
        <div className="busy" role="status">
          <LoaderCircle size={15} className="spin" aria-hidden="true" />
          Waiting for the local server…
        </div>
      )}
    </div>
  );
}
