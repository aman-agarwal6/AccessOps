import { describe, expect, it } from "vitest";
import { auditSummary } from "./presentation";

describe("readable audit summaries", () => {
  it("summarizes structured events without including internal identifiers", () => {
    expect(
      auditSummary({ kind: "reconcile", jobId: "fixture-job-id", attempt: 2 }),
    ).toBe("Operation: reconcile · Attempt: 2");
  });
  it("shows explicit provider uncertainty and credential binding state", () => {
    expect(
      auditSummary({
        providerEffect: "unknown",
        credentialBinding: "recovery-required",
      }),
    ).toBe("Provider outcome: unknown · Credential binding: recovery required");
  });
  it("bounds text and ignores malformed or unknown fields", () => {
    expect(auditSummary("x".repeat(600))).toHaveLength(400);
    expect(
      auditSummary({
        status: { nested: "unexpected" },
        arbitrary: "fixture-value",
      }),
    ).toBe(
      "Recorded by the local server. Inspect the event record for details.",
    );
  });
});
