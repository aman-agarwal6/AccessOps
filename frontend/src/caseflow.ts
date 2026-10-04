import type { Principal } from "./domain";
import type { OffboardingCase, OffboardingTask } from "./offboarding";
import type { ProvenanceKind } from "./ui";

/** Tasks the system observes itself; owners can never attest these. */
export const NATIVE_TASKS = [
  "local-containment",
  "keycloak-directory",
  "ad-directory",
] as const;
export const isNative = (id: string) =>
  (NATIVE_TASKS as readonly string[]).includes(id);

export const PHASES = [
  {
    id: "contain",
    title: "Contain access",
    tasks: ["local-containment", "keycloak-directory", "ad-directory"],
  },
  {
    id: "cloud",
    title: "Cloud accounts",
    tasks: ["entra-directory", "github-org", "github-repositories"],
  },
  {
    id: "handover",
    title: "Sessions, credentials and data",
    tasks: ["entra-sessions", "credentials", "m365-handover", "legacy-scope"],
  },
] as const;

export function phaseTasks(item: OffboardingCase) {
  const known = new Set<string>(PHASES.flatMap((phase) => phase.tasks));
  return PHASES.map((phase, index) => ({
    ...phase,
    tasks: item.tasks.filter((task) =>
      index === PHASES.length - 1
        ? (phase.tasks as readonly string[]).includes(task.id) ||
          !known.has(task.id)
        : (phase.tasks as readonly string[]).includes(task.id),
    ),
  })).filter((phase) => phase.tasks.length > 0);
}

export function taskProvenance(
  task: OffboardingTask,
  connected: boolean,
): ProvenanceKind {
  switch (task.evidenceKind) {
    case "provider_observation":
      return connected ? "observed" : "simulated";
    case "imported_snapshot":
      return "imported";
    case "owner_attestation":
      return "attested";
    default:
      return "pending";
  }
}

export function progress(item: OffboardingCase) {
  const done = item.tasks.filter((task) => task.status !== "pending").length;
  return {
    done,
    total: item.tasks.length,
    remaining: item.tasks.length - done,
  };
}

export type Sla = {
  kind: "closed" | "scheduled" | "overdue" | "soon" | "ok";
  label: string;
  detail: string;
};
export function sla(item: OffboardingCase, now: number): Sla {
  const due = Date.parse(item.dueAt);
  const effective = Date.parse(item.effectiveAt);
  if (item.status === "closed")
    return { kind: "closed", label: "Closed", detail: "" };
  if (effective > now)
    return {
      kind: "scheduled",
      label: `Starts in ${span(effective - now)}`,
      detail: "Scheduled departure",
    };
  if (due < now)
    return {
      kind: "overdue",
      label: `Overdue ${span(now - due)}`,
      detail: "Past the four-hour target",
    };
  return {
    kind: due - now < 3600000 ? "soon" : "ok",
    label: `Due in ${span(due - now)}`,
    detail: "Four-hour closure target",
  };
}
function span(ms: number) {
  const minutes = Math.max(1, Math.round(ms / 60000));
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ${String(minutes % 60).padStart(2, "0")}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}

export type StepAction =
  | "contain"
  | "reconcile"
  | "observeDirectory"
  | "import"
  | "attest"
  | "close"
  | "export";
export type NextStep = {
  stage:
    | "closed"
    | "scheduled"
    | "contain"
    | "observe"
    | "import"
    | "attest"
    | "refresh"
    | "review";
  tone: "action" | "waiting" | "done";
  title: string;
  detail: string;
  action?: { kind: StepAction; label: string; taskId?: string };
  /** Why the current principal cannot take the action, if they cannot. */
  blockedBy?: string;
  /** Who can take the action, for role switching in the public simulation. */
  needs?: "owner" | "operator" | "reviewer";
};

const pendingTask = (item: OffboardingCase, id: string) =>
  item.tasks.find((task) => task.id === id)?.status === "pending";

export function nextStep(
  item: OffboardingCase,
  now: number,
  principal: Principal | undefined,
  ownerName: string,
  connected: boolean,
): NextStep {
  const roles = principal?.roles ?? [];
  const operator = roles.includes("operator");
  const reviewer = roles.includes("reviewer") || roles.includes("approver");
  if (item.status === "closed")
    return {
      stage: "closed",
      tone: "done",
      title: "Closed on reviewed evidence",
      detail:
        "The packet is frozen. Closure records what was reviewed; it does not prove every remote session or copy is gone.",
      action: { kind: "export", label: "Export closure packet" },
    };
  if (Date.parse(item.effectiveAt) > now)
    return {
      stage: "scheduled",
      tone: "waiting",
      title: "Waiting for the departure date",
      detail:
        "Containment and owner evidence unlock when the departure takes effect. The case stays open until then.",
    };
  if (!item.containmentRequestId)
    return {
      stage: "contain",
      tone: "action",
      title: "Contain local access",
      detail:
        "Revoke this person's grants and suspend the agents they sponsor. Directory removal is queued and verified separately.",
      action: { kind: "contain", label: "Apply local containment" },
      needs: "operator",
      blockedBy: operator ? undefined : "Requires the operator role.",
    };
  if (pendingTask(item, "local-containment"))
    return {
      stage: "observe",
      tone: "waiting",
      title: "Containment is not confirmed yet",
      detail:
        "The linked containment request has not reached an observed state. Refresh after the worker completes.",
    };
  if (pendingTask(item, "keycloak-directory"))
    return {
      stage: "observe",
      tone: "action",
      title: "Read the directory again",
      detail:
        "The workforce directory reading is missing, unknown or older than two hours. Reconciliation reads it again; nothing is assumed.",
      action: { kind: "reconcile", label: "Run reconciliation" },
      needs: "operator",
      blockedBy: operator ? undefined : "Requires the operator role.",
    };
  if (pendingTask(item, "ad-directory"))
    return connected
      ? {
          stage: "observe",
          tone: "action",
          title: "Refresh the directory observation",
          detail:
            "The enrolled directory account needs a fresh read-only observation after containment.",
          action: { kind: "observeDirectory", label: "Refresh directory" },
          needs: "operator",
          blockedBy: operator ? undefined : "Requires the operator role.",
        }
      : {
          stage: "observe",
          tone: "waiting",
          title: "Directory evidence needs the connected lab",
          detail:
            "Only the authenticated lab can observe the enrolled directory account.",
        };
  if (pendingTask(item, "entra-directory") && item.bindings.length)
    return {
      stage: "import",
      tone: "action",
      title: "Import an after-departure platform report",
      detail:
        "Bring in a bounded snapshot for the bound Entra and GitHub accounts. Reports are assessed as untrusted evidence; unknown never counts as removed.",
      action: { kind: "import", label: "Import platform report" },
      needs: "operator",
      blockedBy: operator ? undefined : "Requires the operator role.",
    };
  const attestable = item.tasks.filter(
    (task) => task.status === "pending" && !isNative(task.id),
  );
  if (attestable.length)
    return {
      stage: "attest",
      tone: "action",
      title: `Record owner evidence · ${attestable.length} remaining`,
      detail:
        "For each external action, state what was checked, the scope covered and any residual risk. Statements stay labeled as attestations.",
      action: {
        kind: "attest",
        label: "Record next statement",
        taskId: attestable[0].id,
      },
      needs: "owner",
      blockedBy:
        principal?.id === item.ownerId && operator
          ? undefined
          : `Only the case owner, ${ownerName}, can record owner evidence.`,
    };
  if (item.blockers.length)
    return {
      stage: "refresh",
      tone: "action",
      title: "Some evidence is stale",
      detail: item.blockers[0],
      action: item.blockers.some((line) => line.includes("directory account"))
        ? { kind: "reconcile", label: "Run reconciliation" }
        : { kind: "import", label: "Import a fresh report" },
      needs: "operator",
      blockedBy: operator ? undefined : "Requires the operator role.",
    };
  const independent =
    reviewer &&
    principal?.id !== item.ownerId &&
    !item.tasks.some((task) => task.submittedById === principal?.id);
  return {
    stage: "review",
    tone: "action",
    title: "Ready for independent review",
    detail:
      "Every required action is accounted for. A reviewer who did not own the case or submit evidence accepts the exact packet.",
    action: { kind: "close", label: "Review & close case" },
    needs: "reviewer",
    blockedBy: independent
      ? undefined
      : "Closure needs an independent reviewer, not the owner or an evidence submitter.",
  };
}

export type QueueFilter = "open" | "overdue" | "scheduled" | "closed" | "all";
export function inQueue(
  item: OffboardingCase,
  filter: QueueFilter,
  now: number,
) {
  const state = sla(item, now).kind;
  if (filter === "all") return true;
  if (filter === "closed") return state === "closed";
  if (filter === "scheduled") return state === "scheduled";
  if (filter === "overdue") return state === "overdue";
  return state !== "closed";
}
/** Overdue first, then soonest due; scheduled after active; closed last. */
export function byUrgency(now: number) {
  const rank = { overdue: 0, soon: 1, ok: 2, scheduled: 3, closed: 4 } as const;
  return (a: OffboardingCase, b: OffboardingCase) => {
    const ra = rank[sla(a, now).kind];
    const rb = rank[sla(b, now).kind];
    if (ra !== rb) return ra - rb;
    if (ra === 4)
      return (
        Date.parse(b.closedAt ?? b.updatedAt) -
        Date.parse(a.closedAt ?? a.updatedAt)
      );
    return Date.parse(a.dueAt) - Date.parse(b.dueAt);
  };
}
