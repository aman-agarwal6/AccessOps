import type { Audit } from "./domain";

const labels: Record<string, string> = {
  kind: "Operation",
  action: "Change",
  status: "State",
  attempt: "Attempt",
  providerEffect: "Provider outcome",
  localEffect: "Authorization outcome",
  credentialBinding: "Credential binding",
  resourceGrants: "New grants",
  department: "Department",
  findingCount: "Findings",
  callsUsed: "Calls",
  draftsCreated: "Drafts",
  active: "Account active",
  member: "Membership present",
  verified: "Verified",
};

export function auditSummary(detail: Audit["detail"]): string {
  if (typeof detail === "string") return detail.slice(0, 400);
  const parts = Object.entries(labels).flatMap(([key, label]) => {
    const value = detail[key];
    const text =
      typeof value === "string" && value.length <= 96
        ? value.replaceAll("_", " ").replaceAll("-", " ")
        : typeof value === "number" && Number.isFinite(value)
          ? String(value)
          : typeof value === "boolean"
            ? value
              ? "yes"
              : "no"
            : "";
    return text ? [`${label}: ${text}`] : [];
  });
  return parts.length
    ? parts.join(" · ").slice(0, 400)
    : "Recorded by the local server. Inspect the event record for details.";
}
