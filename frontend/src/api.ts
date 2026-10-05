import type {
  Enrollment,
  NewRequest,
  Principal,
  Run,
  Snapshot,
} from "./domain";
import type { NewCase, OffboardingCase } from "./offboarding";

export const CONNECTED = import.meta.env.VITE_ACCESSOPS_MODE === "connected";
export type Session = {
  authenticated: boolean;
  principal?: Principal;
  mode: "connected";
};
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const boundedText = (v: unknown, limit: number): v is string =>
  typeof v === "string" && v.trim().length > 0 && v.length <= limit;
const dateText = (v: unknown): v is string =>
  typeof v === "string" &&
  v.length <= 40 &&
  /^\d{4}-\d{2}-\d{2}T/.test(v) &&
  Number.isFinite(Date.parse(v));
const guid = (value: unknown) =>
  typeof value === "string" &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);
const directoryBinding = (value: unknown) =>
  value === undefined ||
  (object(value) &&
    guid(value.domainGuid) &&
    guid(value.userGuid) &&
    Array.isArray(value.groupGuids) &&
    value.groupGuids.length <= 10 &&
    value.groupGuids.every(guid) &&
    new Set(value.groupGuids).size === value.groupGuids.length);

export function parseSnapshot(value: unknown): Snapshot {
  if (!object(value))
    throw new Error("The server returned an invalid snapshot.");
  for (const key of [
    "identities",
    "resources",
    "requests",
    "grants",
    "reviews",
    "runs",
    "audit",
    "policies",
    "health",
  ]) {
    if (
      !Array.isArray(value[key]) ||
      value[key].length > 10000 ||
      !value[key].every(object)
    )
      throw new Error(`The server returned invalid ${key} data.`);
  }
  if (
    !(value.identities as Record<string, unknown>[]).every((identity) =>
      directoryBinding(identity.directoryBinding),
    )
  )
    throw new Error(
      "The server returned invalid trusted directory enrollment.",
    );
  if (
    value.offboardingCases !== undefined &&
    (!Array.isArray(value.offboardingCases) ||
      value.offboardingCases.length > 1000 ||
      !value.offboardingCases.every(
        (item) =>
          object(item) &&
          boundedText(item.id, 128) &&
          boundedText(item.title, 240) &&
          boundedText(item.identityId, 128) &&
          directoryBinding(item.adBinding) &&
          Number.isSafeInteger(item.revision) &&
          Number(item.revision) >= 1 &&
          ["open", "in_progress", "blocked", "closed"].includes(
            String(item.status),
          ) &&
          Array.isArray(item.tasks) &&
          item.tasks.length <= 100 &&
          item.tasks.every(
            (task) =>
              object(task) &&
              boundedText(task.id, 128) &&
              boundedText(task.title, 240) &&
              ["pending", "observed", "attested"].includes(
                String(task.status),
              ) &&
              [
                "none",
                "provider_observation",
                "imported_snapshot",
                "owner_attestation",
              ].includes(String(task.evidenceKind)),
          ) &&
          Array.isArray(item.imports) &&
          item.imports.every(object) &&
          Array.isArray(item.bindings) &&
          Array.isArray(item.blockers) &&
          item.blockers.every((line) => boundedText(line, 500)) &&
          Array.isArray(item.evidenceLimitations) &&
          item.evidenceLimitations.every((line) => boundedText(line, 1000)),
      ))
  )
    throw new Error("The server returned invalid offboarding cases.");
  if (value.offboardingCases === undefined) value.offboardingCases = [];
  if (
    value.services !== undefined &&
    (!Array.isArray(value.services) ||
      value.services.length > 100 ||
      !value.services.every(
        (item) => object(item) && guid(item.id) && boundedText(item.name, 120),
      ))
  )
    throw new Error("The server returned invalid service data.");
  if (value.services === undefined) value.services = [];
  return value as Snapshot;
}
function csrf(): string {
  const cookie = document.cookie
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith("csrftoken="));
  if (!cookie)
    throw new ApiError(
      "The session security token is missing. Sign in again before changing access.",
      403,
    );
  return decodeURIComponent(cookie.slice("csrftoken=".length));
}
async function request(path: string, body?: unknown): Promise<unknown> {
  if (!CONNECTED)
    throw new ApiError(
      "Connected actions are unavailable in the browser simulation.",
      403,
    );
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    credentials: "same-origin",
    redirect: "error",
    cache: "no-store",
    headers:
      body === undefined
        ? { Accept: "application/json" }
        : {
            Accept: "application/json",
            "Content-Type": "application/json",
            "X-CSRFToken": csrf(),
            "Idempotency-Key": crypto.randomUUID(),
          },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(15000),
  });
  const data: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const error =
      object(data) &&
      object(data.error) &&
      typeof data.error.message === "string"
        ? data.error.message
        : "The request could not be completed. Refresh the session and retry.";
    throw new ApiError(error.slice(0, 400), response.status);
  }
  return data;
}
export const lab = {
  async observeDirectory(id: string) {
    return request(
      `/api/v1/offboarding-cases/${encodeURIComponent(id)}/observe-directory`,
      {},
    );
  },
  async createCase(input: NewCase) {
    return request("/api/v1/offboarding-cases", input);
  },
  async importCase(id: string, report: unknown) {
    return request(
      `/api/v1/offboarding-cases/${encodeURIComponent(id)}/import`,
      { report },
    );
  },
  async containCase(id: string) {
    return request(
      `/api/v1/offboarding-cases/${encodeURIComponent(id)}/contain`,
      {},
    );
  },
  async attestCase(
    id: string,
    taskId: string,
    reference: string,
    summary: string,
  ) {
    return request(
      `/api/v1/offboarding-cases/${encodeURIComponent(id)}/tasks/${encodeURIComponent(taskId)}/attest`,
      { reference, summary },
    );
  },
  async closeCase(
    item: Pick<OffboardingCase, "id" | "revision" | "packetHash">,
  ) {
    return request(
      `/api/v1/offboarding-cases/${encodeURIComponent(item.id)}/close`,
      { expectedRevision: item.revision, packetHash: item.packetHash },
    );
  },
  async casePacket(id: string) {
    return request(
      `/api/v1/offboarding-cases/${encodeURIComponent(id)}/packet`,
    );
  },
  async session(): Promise<Session> {
    const data = await request("/api/v1/session");
    if (!object(data) || typeof data.authenticated !== "boolean")
      throw new Error("Invalid session response.");
    return data as Session;
  },
  async snapshot(): Promise<Snapshot> {
    return parseSnapshot(await request("/api/v1/snapshot"));
  },
  async create(input: NewRequest) {
    return request("/api/v1/requests", input);
  },
  async enroll(input: Enrollment) {
    return request("/api/v1/identities", input);
  },
  async department(id: string, department: string, reason: string) {
    return request(
      `/api/v1/identities/${encodeURIComponent(id)}/transfer-department`,
      { department, reason },
    );
  },
  async accept(id: string) {
    return request(`/api/v1/requests/${encodeURIComponent(id)}/accept`, {});
  },
  async approve(id: string) {
    return request(`/api/v1/requests/${encodeURIComponent(id)}/approve`, {});
  },
  async execute(id: string) {
    return request(`/api/v1/requests/${encodeURIComponent(id)}/execute`, {});
  },
  async review(id: string) {
    return request(`/api/v1/reviews/${encodeURIComponent(id)}/run`, {
      mode: "deterministic",
    });
  },
  async propose(
    id: string,
    input: { identityId: string; resourceId: string; reason: string },
  ) {
    return request(`/api/v1/reviews/${encodeURIComponent(id)}/propose`, input);
  },
  async reconcile() {
    return request("/api/v1/reconcile", {});
  },
  async logout() {
    return request("/auth/logout", {});
  },
};

export async function loadRecordedEvidence(
  signal?: AbortSignal,
): Promise<Run[]> {
  const response = await fetch(
    `${import.meta.env.BASE_URL}evidence/index.json`,
    {
      signal: signal
        ? AbortSignal.any([signal, AbortSignal.timeout(15000)])
        : AbortSignal.timeout(15000),
      cache: "no-cache",
      credentials: "omit",
      redirect: "error",
    },
  );
  if (!response.ok)
    throw new Error("Recorded evidence index could not be loaded.");
  const content = await response.text();
  if (content.length > 4000000)
    throw new Error("Recorded evidence index exceeds the size limit.");
  const data: unknown = JSON.parse(content);
  return parseRecordedEvidence(data);
}

export function parseRecordedEvidence(data: unknown): Run[] {
  if (!object(data) || !Array.isArray(data.runs) || data.runs.length > 1000)
    throw new Error("Recorded evidence index is invalid.");
  if (
    !data.runs.every(
      (r) =>
        object(r) &&
        boundedText(r.id, 128) &&
        boundedText(r.name, 200) &&
        boundedText(r.scenario, 200) &&
        boundedText(r.summary, 4000) &&
        r.origin === "recorded" &&
        ["passed", "failed", "pending"].includes(String(r.status)) &&
        dateText(r.startedAt) &&
        (r.finishedAt === undefined ||
          (dateText(r.finishedAt) &&
            Date.parse(r.finishedAt) >= Date.parse(r.startedAt))) &&
        Array.isArray(r.checks) &&
        r.checks.length <= 1000 &&
        r.checks.every(
          (c) =>
            object(c) &&
            boundedText(c.name, 200) &&
            ["passed", "failed", "skipped"].includes(String(c.status)) &&
            boundedText(c.detail, 4000),
        ),
    )
  )
    throw new Error("Recorded evidence did not match the published contract.");
  if (new Set(data.runs.map((run) => run.id)).size !== data.runs.length)
    throw new Error("Recorded evidence contains duplicate run identifiers.");
  return data.runs as Run[];
}

export function downloadJson(name: string, value: unknown) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
