import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { parseRecordedEvidence } from "./api";
import type { Run } from "./domain";

const recordedRun = (): Run => ({
  id: "local-run-1",
  name: "Recorded employee and agent containment",
  scenario: "containment",
  status: "passed",
  origin: "recorded",
  startedAt: "2026-10-03T12:00:00Z",
  finishedAt: "2026-10-03T12:00:02Z",
  summary: "Synthetic identities were denied after authorized containment.",
  checks: [
    {
      name: "Protected read after containment",
      status: "passed",
      detail: "The local resource adapter observed zero effects.",
    },
  ],
  manifest: { limitations: ["Local reference execution only."] },
});

describe("recorded evidence contract", () => {
  it("validates every currently published record against the read-only contract", () => {
    const index: unknown = JSON.parse(
      readFileSync("public/evidence/index.json", "utf8"),
    );
    const runs = parseRecordedEvidence(index);
    expect(runs.every((run) => run.origin === "recorded")).toBe(true);
  });
  it("accepts empty indexes and complete recorded runs with limitations", () => {
    expect(parseRecordedEvidence({ runs: [] })).toEqual([]);
    const run = recordedRun();
    expect(parseRecordedEvidence({ runs: [run] })).toEqual([run]);
  });

  it("rejects browser and connected results from the recorded collection", () => {
    for (const origin of ["simulation", "connected"]) {
      expect(() =>
        parseRecordedEvidence({ runs: [{ ...recordedRun(), origin }] }),
      ).toThrow("published contract");
    }
  });

  it("rejects incomplete or malformed run records", () => {
    for (const changes of [
      { summary: undefined },
      { scenario: undefined },
      { startedAt: "not a date" },
      { finishedAt: "2026-10-02T12:00:00Z" },
      { status: "verified" },
      { checks: [{ name: "Read", status: "passed", detail: null }] },
    ]) {
      expect(() =>
        parseRecordedEvidence({ runs: [{ ...recordedRun(), ...changes }] }),
      ).toThrow("published contract");
    }
  });

  it("rejects duplicate identifiers and excessive record sizes", () => {
    expect(() =>
      parseRecordedEvidence({ runs: [recordedRun(), recordedRun()] }),
    ).toThrow("duplicate");
    expect(() =>
      parseRecordedEvidence({ runs: Array(1001).fill(recordedRun()) }),
    ).toThrow("invalid");
    expect(() =>
      parseRecordedEvidence({
        runs: [{ ...recordedRun(), summary: "x".repeat(4001) }],
      }),
    ).toThrow("published contract");
  });
});
