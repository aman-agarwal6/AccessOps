import {
  dispatchSimulation,
  DomainError,
  initialSimulation,
  type Principal,
  type Simulation,
} from "./domain";

export type Platform =
  "accessops" | "keycloak" | "entra" | "github" | "m365" | "legacy";
export type Binding = {
  provider: "entra" | "github";
  tenantId: string;
  subjectId: string;
};
export type DirectoryBinding = {
  domainGuid: string;
  userGuid: string;
  groupGuids: string[];
};
export type OffboardingTask = {
  id: string;
  platform: Platform;
  boundary:
    | "local"
    | "directory"
    | "sessions"
    | "credentials"
    | "data"
    | "license"
    | "legacy";
  title: string;
  ownerId: string;
  dueAt: string;
  status: "pending" | "observed" | "attested";
  required: true;
  evidenceKind:
    "none" | "provider_observation" | "imported_snapshot" | "owner_attestation";
  evidenceSummary?: string;
  evidenceReference?: string;
  observedAt?: string;
  completedAt?: string;
  submittedById?: string;
};
export type PlatformImport = {
  id: string;
  platform: "entra" | "github" | "mixed";
  capturedAt: string;
  importedAt: string;
  recordCount: number;
  sha256: string;
  collectionMethod: string;
  limitations: string[];
};
export type OffboardingCase = {
  id: string;
  identityId: string;
  title: string;
  employmentType: "employee" | "contractor";
  hrEventId: string;
  hrSource: string;
  reason?: string;
  effectiveAt: string;
  ownerId: string;
  dueAt: string;
  status: "open" | "in_progress" | "blocked" | "closed";
  createdAt: string;
  updatedAt: string;
  revision: number;
  policyVersion?: string;
  containmentRequestId?: string;
  /** Set when a signed HR feed opened the case and contains it automatically. */
  intakeSourceId?: string;
  bindings: Binding[];
  adBinding?: DirectoryBinding;
  tasks: OffboardingTask[];
  imports: PlatformImport[];
  blockers: string[];
  packetHash: string;
  closedAt?: string;
  closedById?: string;
  closureBasis?: "reviewed_evidence";
  evidenceLimitations: string[];
  /** Browser-only assessment input; never sent as a connected mutation. */
  simulatedReadings?: (Observation & { importHash?: string })[];
};
export type NewCase = {
  identityId: string;
  employmentType: "employee" | "contractor";
  hrEventId: string;
  hrSource: string;
  effectiveAt: string;
  reason: string;
  bindings: Binding[];
};
export type Observation = Binding & {
  observedAt: string;
  capability:
    | "account_enabled"
    | "organization_membership"
    | "outside_collaborator"
    | "repository_collaborator"
    | "session_revocation"
    | "credential_revocation";
  status: "observed" | "unknown";
  value: boolean | null;
  scope: string;
  reasonCode: string;
};
export type PlatformReport = {
  schemaVersion: 1;
  collectionMethod: "synthetic_fixture" | "read_only_api" | "manual_export";
  collectedAt: string;
  observations: Observation[];
  limitations: string[];
};
export const platformNames: Record<Platform, string> = {
  accessops: "AccessOps",
  keycloak: "Keycloak workforce",
  entra: "Microsoft Entra ID",
  github: "GitHub organization",
  m365: "Microsoft 365",
  legacy: "AD & legacy applications",
};
const definitions: [string, Platform, OffboardingTask["boundary"], string][] = [
  [
    "local-containment",
    "accessops",
    "local",
    "Revoke local grants and suspend sponsored agents",
  ],
  [
    "keycloak-directory",
    "keycloak",
    "directory",
    "Disable the workforce directory account",
  ],
  ["entra-directory", "entra", "directory", "Block Microsoft Entra sign-in"],
  [
    "entra-sessions",
    "entra",
    "sessions",
    "Review Entra and application session termination",
  ],
  [
    "github-org",
    "github",
    "directory",
    "Remove GitHub organization membership",
  ],
  [
    "github-repositories",
    "github",
    "directory",
    "Check repository and outside collaborator access",
  ],
  [
    "credentials",
    "github",
    "credentials",
    "Rotate shared automation credentials and hand over ownership",
  ],
  [
    "m365-handover",
    "m365",
    "data",
    "Review mailbox, OneDrive retention and license handover",
  ],
  [
    "legacy-scope",
    "legacy",
    "legacy",
    "Confirm AD and legacy application scope",
  ],
];
export const syntheticBindings: Binding[] = [
  {
    provider: "entra",
    tenantId: "11111111-1111-4111-8111-111111111111",
    subjectId: "22222222-2222-4222-8222-222222222222",
  },
  { provider: "github", tenantId: "424242", subjectId: "1001" },
];
const iso = (time: number) => new Date(time).toISOString();
const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const text = (value: unknown, min: number, max: number): value is string =>
  typeof value === "string" &&
  value.trim().length >= min &&
  value.length <= max &&
  !/[\u0000-\u001f]/.test(value);
const date = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length <= 40 &&
  /^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value) &&
  Number.isFinite(Date.parse(value));
const keys = (value: Record<string, unknown>, allowed: string[]) =>
  Object.keys(value).every((key) => allowed.includes(key));
const validBinding = (binding: Binding) =>
  binding.provider === "entra"
    ? /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(binding.tenantId) &&
      /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(binding.subjectId)
    : binding.provider === "github" &&
      /^[1-9][0-9]{0,19}$/.test(binding.tenantId) &&
      /^[1-9][0-9]{0,19}$/.test(binding.subjectId);

export function parsePlatformReport(
  value: unknown,
  bindings: Binding[],
  now: number,
  publicDemo: boolean,
): PlatformReport {
  if (
    !object(value) ||
    !keys(value, [
      "schemaVersion",
      "collectionMethod",
      "collectedAt",
      "observations",
      "limitations",
    ]) ||
    value.schemaVersion !== 1 ||
    !["synthetic_fixture", "read_only_api", "manual_export"].includes(
      String(value.collectionMethod),
    ) ||
    !date(value.collectedAt) ||
    Date.parse(value.collectedAt) > now + 5000 ||
    !Array.isArray(value.observations) ||
    value.observations.length < 1 ||
    value.observations.length > 100 ||
    !Array.isArray(value.limitations) ||
    value.limitations.length > 20 ||
    !value.limitations.every((line) => text(line, 1, 240))
  )
    throw new DomainError(
      "Report format or timestamps are invalid. Use the documented canonical JSON report.",
    );
  if (publicDemo && value.collectionMethod !== "synthetic_fixture")
    throw new DomainError(
      "The public demo accepts synthetic fixtures only. Keep tenant and personal data in your authenticated environment.",
    );
  const seen = new Set<string>();
  for (const observation of value.observations) {
    if (
      !object(observation) ||
      !keys(observation, [
        "provider",
        "tenantId",
        "subjectId",
        "observedAt",
        "capability",
        "status",
        "value",
        "scope",
        "reasonCode",
      ]) ||
      !["entra", "github"].includes(String(observation.provider)) ||
      !text(observation.tenantId, 1, 120) ||
      !text(observation.subjectId, 1, 120) ||
      !date(observation.observedAt) ||
      Date.parse(observation.observedAt) > Date.parse(value.collectedAt) ||
      ![
        "account_enabled",
        "organization_membership",
        "outside_collaborator",
        "repository_collaborator",
        "session_revocation",
        "credential_revocation",
      ].includes(String(observation.capability)) ||
      !["observed", "unknown"].includes(String(observation.status)) ||
      (observation.status === "observed"
        ? typeof observation.value !== "boolean"
        : observation.value !== null) ||
      !text(observation.scope, 1, 120) ||
      !text(observation.reasonCode, 1, 80) ||
      !/^[A-Za-z0-9_.:-]+$/.test(observation.reasonCode) ||
      !validBinding(observation as Observation) ||
      (observation.provider === "github" &&
        observation.capability === "account_enabled") ||
      (observation.provider === "entra" &&
        [
          "organization_membership",
          "outside_collaborator",
          "repository_collaborator",
        ].includes(String(observation.capability)))
    )
      throw new DomainError(
        "An observation is malformed, unknown, or contains unsupported fields.",
      );
    if (
      !bindings.some(
        (binding) =>
          binding.provider === observation.provider &&
          binding.tenantId === observation.tenantId &&
          binding.subjectId === observation.subjectId,
      )
    )
      throw new DomainError(
        "The report does not match this case’s explicitly bound tenant and account.",
      );
    const key = JSON.stringify([
      observation.provider,
      observation.tenantId,
      observation.subjectId,
      observation.capability,
      observation.scope,
    ]);
    if (seen.has(key))
      throw new DomainError("Duplicate observations are not allowed.");
    seen.add(key);
  }
  return value as PlatformReport;
}

export async function digest(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const result = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(result), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
export function caseBlockers(item: OffboardingCase, now: number): string[] {
  const residual = (item.simulatedReadings ?? [])
    .filter(
      (reading) =>
        reading.status === "observed" &&
        reading.value === true &&
        [
          "account_enabled",
          "organization_membership",
          "outside_collaborator",
          "repository_collaborator",
        ].includes(reading.capability),
    )
    .flatMap((reading) => {
      const id =
        reading.capability === "account_enabled"
          ? "entra-directory"
          : reading.capability === "organization_membership"
            ? "github-org"
            : "github-repositories";
      const task = item.tasks.find((entry) => entry.id === id);
      return task?.evidenceKind === "owner_attestation" &&
        task.completedAt &&
        Date.parse(task.completedAt) > Date.parse(reading.observedAt)
        ? []
        : [
            `Residual ${reading.provider} access is reported in ${reading.scope}.`,
          ];
    });
  return [
    ...(Date.parse(item.effectiveAt) > now
      ? ["The departure is scheduled for the future."]
      : []),
    ...item.tasks
      .filter(
        (task) =>
          task.status === "pending" ||
          (task.evidenceKind === "imported_snapshot" &&
            (!task.observedAt ||
              Date.parse(task.observedAt) < Date.parse(item.effectiveAt) ||
              now - Date.parse(task.observedAt) > 7200000 ||
              Date.parse(task.observedAt) > now)) ||
          (task.id === "keycloak-directory" &&
            task.status === "observed" &&
            (!task.observedAt || now - Date.parse(task.observedAt) > 7200000)),
      )
      .map((task) =>
        task.status === "pending"
          ? task.title
          : `${task.title}: evidence is stale or outside the departure window.`,
      ),
    ...new Set(residual),
  ];
}
export function casePacket(item: OffboardingCase) {
  const { simulatedReadings, ...details } = item;
  return {
    schemaVersion: 1,
    mode: "browser_simulation",
    outcome: item.status === "closed" ? "administrative_closure" : "draft",
    case: details,
    importedObservations: simulatedReadings ?? [],
    limitations: item.evidenceLimitations,
  };
}
export function assessSimulatedCase(
  original: OffboardingCase,
  now: number,
): OffboardingCase {
  if (original.status === "closed") return original;
  const item = structuredClone(original);
  for (const task of item.tasks) {
    if (
      task.status === "observed" &&
      (task.id === "keycloak-directory" ||
        task.evidenceKind === "imported_snapshot") &&
      (!task.observedAt ||
        now - Date.parse(task.observedAt) > 7200000 ||
        Date.parse(task.observedAt) < Date.parse(item.effectiveAt))
    )
      task.status = "pending";
  }
  item.blockers = caseBlockers(item, now);
  if (item.containmentRequestId)
    item.status = item.blockers.length ? "blocked" : "in_progress";
  return item;
}
async function updated(
  item: OffboardingCase,
  now: number,
): Promise<OffboardingCase> {
  item.updatedAt = iso(now);
  item.revision += 1;
  item.blockers = caseBlockers(item, now);
  item.status = item.containmentRequestId
    ? item.blockers.length
      ? "blocked"
      : "in_progress"
    : item.imports.length
      ? "in_progress"
      : "open";
  item.packetHash = await digest({ ...item, packetHash: "" });
  return item;
}
export async function createSimulatedCase(
  input: NewCase,
  actor: Principal,
  now: number,
  name: string,
  id: string = crypto.randomUUID(),
): Promise<OffboardingCase> {
  if (!actor.roles.includes("operator"))
    throw new DomainError("An operator must open the case.");
  if (
    !/^[A-Za-z0-9._:-]{8,64}$/.test(input.hrEventId) ||
    !text(input.hrSource, 3, 64) ||
    !text(input.reason, 8, 255) ||
    !date(input.effectiveAt) ||
    !["employee", "contractor"].includes(input.employmentType) ||
    Math.abs(Date.parse(input.effectiveAt) - now) > 366 * 86400000
  )
    throw new DomainError("Complete the departure event, date and reason.");
  if (
    input.bindings.length > 2 ||
    new Set(input.bindings.map((b) => b.provider)).size !==
      input.bindings.length ||
    input.bindings.some((b) => !validBinding(b))
  )
    throw new DomainError(
      "Use one explicit tenant/account binding per platform.",
    );
  const dueAt = iso(Date.parse(input.effectiveAt) + 4 * 3600000);
  return updated(
    {
      id,
      identityId: input.identityId,
      title: `${name} · ${input.employmentType} departure`,
      employmentType: input.employmentType,
      hrEventId: input.hrEventId,
      hrSource: input.hrSource,
      reason: input.reason,
      effectiveAt: input.effectiveAt,
      ownerId: actor.id,
      dueAt,
      status: "open",
      createdAt: iso(now),
      updatedAt: iso(now),
      revision: 0,
      bindings: structuredClone(input.bindings),
      tasks: definitions.map(([id, platform, boundary, title]) => ({
        id,
        platform,
        boundary,
        title,
        ownerId: actor.id,
        dueAt,
        status: "pending",
        required: true,
        evidenceKind: "none",
      })),
      imports: [],
      blockers: [],
      packetHash: "",
      evidenceLimitations: [
        "Browser simulation with synthetic identities; no external platforms were contacted.",
        "Imported reports are untrusted point-in-time evidence, not live provider verification.",
        "Owner attestations remain manual statements. Administrative closure does not prove universal access termination.",
        "Directory disablement does not recall running work, application sessions, copied data or shared credentials.",
      ],
    },
    now,
  );
}
const seedOperator = {
  id: "op-jules",
  name: "Jules Morgan",
  roles: ["operator"],
};
const seedReviewer = {
  id: "op-avery",
  name: "Avery Chen",
  roles: ["reviewer", "operator"],
};
const hour = 3600000;
/**
 * A small, realistic public queue built through the same simulation functions a
 * visitor uses: the guided case (due soon), an overdue case, a scheduled
 * departure and one closed historical case. Every record is synthetic.
 */
export async function initialOffboardingCases(
  now: number,
): Promise<OffboardingCase[]> {
  const opened = async (
    identityId: string,
    name: string,
    id: string,
    hrEventId: string,
    employmentType: NewCase["employmentType"],
    effectiveAt: number,
    reason: string,
  ) =>
    createSimulatedCase(
      {
        identityId,
        employmentType,
        hrEventId,
        hrSource: "HR service desk · synthetic event",
        effectiveAt: iso(effectiveAt),
        reason,
        bindings: syntheticBindings,
      },
      seedOperator,
      Math.min(now, effectiveAt + 5 * 60000),
      name,
      id,
    );
  const mara = await opened(
    "mara",
    "Mara Patel",
    "case-hr-1084",
    "HR-2026-1084",
    "employee",
    now - 75 * 60000,
    "Confirmed employee departure requires cross-system access containment and ownership handover.",
  );
  const leo = await opened(
    "leo",
    "Leo Brooks",
    "case-hr-1079",
    "HR-2026-1079",
    "contractor",
    now - 6 * hour,
    "Contract ended early. Support queue access and shared tooling need an owner handover.",
  );
  const sam = await opened(
    "sam",
    "Sam Rivera",
    "case-hr-1091",
    "HR-2026-1091",
    "employee",
    now + 2 * 24 * hour,
    "Planned departure after the operations handover. Containment waits for the effective time.",
  );
  return [
    await importSimulatedReport(
      mara,
      syntheticReport(mara, now, "before"),
      seedOperator,
      now,
    ),
    await importSimulatedReport(
      leo,
      syntheticReport(leo, now, "before"),
      seedOperator,
      now,
    ),
    sam,
    await closedHistoricalCase(now - 6 * 24 * hour),
  ];
}
/** Completes a past case end to end in a throwaway simulation of that day. */
async function closedHistoricalCase(start: number): Promise<OffboardingCase> {
  const day = initialSimulation(start);
  const person = day.snapshot.identities.find((entry) => entry.id === "priya");
  if (person) person.status = "active";
  let item = await createSimulatedCase(
    {
      identityId: "priya",
      employmentType: "contractor",
      hrEventId: "HR-2026-1062",
      hrSource: "HR service desk · synthetic event",
      effectiveAt: iso(start),
      reason:
        "Contract completed. QA environment access and test accounts handed back to the Atlas team.",
      bindings: syntheticBindings,
    },
    seedOperator,
    start + 60000,
    "Priya Nair",
    "case-hr-1062",
  );
  item = await importSimulatedReport(
    item,
    syntheticReport(item, start, "before"),
    seedOperator,
    start + 2 * 60000,
  );
  item = (
    await containSimulatedCase(item, day, seedOperator, start + 10 * 60000)
  ).item;
  item = await importSimulatedReport(
    item,
    syntheticReport(item, start + 40 * 60000, "after"),
    seedOperator,
    start + 40 * 60000,
  );
  let at = start + 50 * 60000;
  for (const task of item.tasks.filter((entry) => entry.status === "pending")) {
    item = await attestSimulatedTask(
      item,
      task.id,
      `CHG-1062-${task.id}`.slice(0, 120),
      "Synthetic owner statement: the scoped handover was completed and checked. Sessions, copies and unsupported credentials stay within the stated evidence limits.",
      seedOperator,
      at,
    );
    at += 60000;
  }
  return closeSimulatedCase(
    item,
    seedReviewer,
    at + 5 * 60000,
    item.revision,
    item.packetHash,
  );
}
export function syntheticReport(
  item: OffboardingCase,
  now: number,
  phase: "before" | "after",
): PlatformReport {
  const observedAt = iso(
    phase === "before" ? Date.parse(item.effectiveAt) - 60000 : now,
  );
  return {
    schemaVersion: 1,
    collectionMethod: "synthetic_fixture",
    collectedAt: observedAt,
    observations: item.bindings.flatMap((binding) =>
      (binding.provider === "entra"
        ? ["account_enabled", "session_revocation", "credential_revocation"]
        : [
            "organization_membership",
            "outside_collaborator",
            "repository_collaborator",
            "session_revocation",
            "credential_revocation",
          ]
      ).map((capability) => ({
        ...binding,
        capability: capability as Observation["capability"],
        status:
          capability.endsWith("revocation") ||
          (binding.provider === "github" &&
            (phase === "after" || capability === "outside_collaborator"))
            ? ("unknown" as const)
            : ("observed" as const),
        value:
          capability.endsWith("revocation") ||
          (binding.provider === "github" &&
            (phase === "after" || capability === "outside_collaborator"))
            ? null
            : phase === "before",
        observedAt,
        scope:
          binding.provider === "entra"
            ? "Synthetic workforce tenant"
            : "Synthetic Northstar organization and repository scope",
        reasonCode:
          capability.endsWith("revocation") ||
          (binding.provider === "github" &&
            (phase === "after" || capability === "outside_collaborator"))
            ? "export_coverage_unverified"
            : "synthetic_export",
      })),
    ),
    limitations: [
      "Synthetic fixture. Microsoft and GitHub were not contacted.",
      "Application sessions, shared credentials, local clones, data retention and billing are outside this snapshot.",
    ],
  };
}
function mutable(item: OffboardingCase, actor: Principal) {
  if (item.status === "closed")
    throw new DomainError(
      "Closed cases preserve their packet. Open a new case for further work.",
    );
  if (!actor.roles.includes("operator"))
    throw new DomainError("This action requires an operator.");
}
export async function importSimulatedReport(
  original: OffboardingCase,
  value: unknown,
  actor: Principal,
  now: number,
): Promise<OffboardingCase> {
  mutable(original, actor);
  const report = structuredClone(
    parsePlatformReport(value, original.bindings, now, true),
  );
  const item = structuredClone(original);
  const sha256 = await digest(report);
  if (item.imports.some((entry) => entry.sha256 === sha256))
    throw new DomainError("This report is already imported.");
  const readings = new Map(
    (item.simulatedReadings ?? []).map((entry) => [
      JSON.stringify([
        entry.provider,
        entry.tenantId,
        entry.subjectId,
        entry.capability,
        entry.scope,
      ]),
      entry,
    ]),
  );
  for (const entry of report.observations) {
    const key = JSON.stringify([
      entry.provider,
      entry.tenantId,
      entry.subjectId,
      entry.capability,
      entry.scope,
    ]);
    const previous = readings.get(key);
    if (
      !previous ||
      Date.parse(previous.observedAt) <= Date.parse(entry.observedAt)
    )
      readings.set(key, { ...entry, importHash: sha256 });
  }
  item.simulatedReadings = [...readings.values()];
  for (const task of item.tasks) {
    if (!["local-containment", "keycloak-directory"].includes(task.id)) {
      task.status = "pending";
      task.evidenceKind = "none";
      delete task.evidenceSummary;
      delete task.evidenceReference;
      delete task.observedAt;
      delete task.completedAt;
      delete task.submittedById;
    }
  }
  const fresh = item.simulatedReadings.filter(
    (observation) =>
      observation.status === "observed" &&
      Date.parse(observation.observedAt) >= Date.parse(item.effectiveAt) &&
      Date.parse(observation.observedAt) <= now &&
      now - Date.parse(observation.observedAt) <= 7200000,
  );
  const absent = (
    provider: Binding["provider"],
    capability: Observation["capability"],
  ) => {
    const observations = item.simulatedReadings!.filter(
      (entry) => entry.provider === provider && entry.capability === capability,
    );
    return (
      observations.length > 0 &&
      observations.every(
        (entry) => fresh.includes(entry) && entry.value === false,
      )
    );
  };
  for (const [id, satisfied] of [
    ["entra-directory", absent("entra", "account_enabled")],
  ] as const) {
    if (satisfied)
      Object.assign(
        item.tasks.find((task) => task.id === id)!,
        {
          status: "observed",
          evidenceKind: "imported_snapshot",
          evidenceSummary:
            "The imported synthetic snapshot reports the required state in its supplied scope. Independent evidence review is still required.",
          evidenceReference: [
            ...new Set(
              item.simulatedReadings
                .filter(
                  (entry) =>
                    entry.provider === "entra" &&
                    entry.capability === "account_enabled",
                )
                .map((entry) => entry.importHash)
                .filter(Boolean),
            ),
          ].join(" · "),
          observedAt: iso(
            Math.min(
              ...item.simulatedReadings
                .filter(
                  (entry) =>
                    entry.provider === "entra" &&
                    entry.capability === "account_enabled",
                )
                .map((entry) => Date.parse(entry.observedAt)),
            ),
          ),
        },
      );
  }
  const platforms = new Set(report.observations.map((entry) => entry.provider));
  item.imports.unshift({
    id: crypto.randomUUID(),
    platform: platforms.size === 2 ? "mixed" : report.observations[0].provider,
    capturedAt: report.collectedAt,
    importedAt: iso(now),
    recordCount: report.observations.length,
    sha256,
    collectionMethod: report.collectionMethod,
    limitations: report.limitations,
  });
  return updated(item, now);
}
export async function containSimulatedCase(
  original: OffboardingCase,
  simulation: Simulation,
  actor: Principal,
  now: number,
): Promise<{ item: OffboardingCase; simulation: Simulation }> {
  mutable(original, actor);
  if (Date.parse(original.effectiveAt) > now)
    throw new DomainError(
      "Future departures cannot be contained through this case.",
    );
  if (original.containmentRequestId)
    throw new DomainError("Containment is already linked to this case.");
  const item = structuredClone(original);
  const created = dispatchSimulation(
    simulation,
    {
      type: "create",
      input: {
        identityId: item.identityId,
        resourceId: simulation.snapshot.resources[0].id,
        action: "offboard",
        reason: `HR departure ${item.hrEventId}: contain employee and sponsored-agent access.`,
      },
    },
    actor,
  );
  const applied = dispatchSimulation(
    created.state,
    { type: "execute", id: created.id! },
    actor,
  );
  item.containmentRequestId = created.id;
  Object.assign(
    item.tasks.find((task) => task.id === "local-containment")!,
    {
      status: "observed",
      evidenceKind: "provider_observation",
      evidenceSummary:
        "Simulation applied local containment: employee grants revoked and sponsored agents suspended. Existing remote work cannot be recalled.",
      evidenceReference: created.id,
      observedAt: iso(now),
    },
  );
  // A modeled provider observation follows the modeled effect. It is not a cloud verification control.
  const observed = dispatchSimulation(
    applied.state,
    { type: "verify", id: created.id! },
    actor,
  );
  Object.assign(
    item.tasks.find((task) => task.id === "keycloak-directory")!,
    {
      status: "observed",
      evidenceKind: "provider_observation",
      evidenceSummary:
        "Simulated workforce directory observation reports the human account disabled. This does not verify application sessions or service-account credentials.",
      evidenceReference: created.id,
      observedAt: iso(now),
    },
  );
  return { item: await updated(item, now), simulation: observed.state };
}
export async function reconcileSimulatedCase(
  original: OffboardingCase,
  simulation: Simulation,
  actor: Principal,
  now: number,
): Promise<{ item: OffboardingCase; simulation: Simulation }> {
  mutable(original, actor);
  const result = dispatchSimulation(simulation, { type: "reconcile" }, actor);
  const item = structuredClone(original);
  const task = item.tasks.find((entry) => entry.id === "keycloak-directory")!;
  const available = result.state.snapshot.health.some(
    (entry) =>
      entry.name === "Directory connector" && entry.status === "healthy",
  );
  if (
    item.containmentRequestId &&
    available &&
    result.state.snapshot.identities.some(
      (entry) => entry.id === item.identityId && entry.status === "offboarded",
    )
  )
    Object.assign(task, {
      status: "observed",
      evidenceKind: "provider_observation",
      observedAt: iso(now),
      evidenceSummary:
        "Simulated local reconciliation observes the workforce human account disabled. Sessions, agent credentials and cloud accounts are separate boundaries.",
    });
  else
    Object.assign(task, {
      status: "pending",
      evidenceKind: "none",
      evidenceSummary:
        "The modeled directory account state is unknown or unavailable. Closure remains blocked.",
    });
  return { item: await updated(item, now), simulation: result.state };
}
export async function attestSimulatedTask(
  original: OffboardingCase,
  id: string,
  reference: string,
  summary: string,
  actor: Principal,
  now: number,
): Promise<OffboardingCase> {
  mutable(original, actor);
  if (actor.id !== original.ownerId)
    throw new DomainError(
      "Only the accountable case owner can record external work.",
    );
  if (Date.parse(original.effectiveAt) > now)
    throw new DomainError(
      "Wait until the departure is effective to attest completed work.",
    );
  const item = structuredClone(original);
  const task = item.tasks.find((entry) => entry.id === id);
  if (
    !task ||
    ["local-containment", "keycloak-directory", "ad-directory"].includes(id)
  )
    throw new DomainError(
      "Local and provider observation tasks cannot be manually attested.",
    );
  if (!text(reference, 8, 120) || !text(summary, 20, 500))
    throw new DomainError(
      "Give an evidence reference of 8–120 characters and a summary of 20–500 characters.",
    );
  Object.assign(task, {
    status: "attested",
    evidenceKind: "owner_attestation",
    evidenceReference: reference,
    evidenceSummary: summary,
    completedAt: iso(now),
    submittedById: actor.id,
  });
  return updated(item, now);
}
export async function closeSimulatedCase(
  original: OffboardingCase,
  actor: Principal,
  now: number,
  expectedRevision: number,
  packetHash: string,
): Promise<OffboardingCase> {
  if (original.status === "closed")
    throw new DomainError("This case is already closed.");
  if (!actor.roles.includes("reviewer") && !actor.roles.includes("approver"))
    throw new DomainError("Closure requires an independent reviewer.");
  if (
    actor.id === original.ownerId ||
    original.tasks.some((task) => task.submittedById === actor.id)
  )
    throw new DomainError(
      "The case owner or an attestation submitter cannot close their own evidence.",
    );
  if (
    expectedRevision !== original.revision ||
    packetHash !== original.packetHash
  )
    throw new DomainError(
      "The case changed. Refresh before reviewing closure.",
    );
  if (caseBlockers(original, now).length)
    throw new DomainError("Unresolved required actions block closure.");
  return {
    ...structuredClone(original),
    status: "closed",
    closedAt: iso(now),
    closedById: actor.id,
    closureBasis: "reviewed_evidence",
    updatedAt: iso(now),
    revision: original.revision + 1,
  };
}
