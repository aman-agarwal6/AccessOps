import { describe, expect, it } from "vitest";
import { accessDecision, initialSimulation, operators } from "./domain";
import { parseSnapshot } from "./api";
import {
  attestSimulatedTask,
  caseBlockers,
  casePacket,
  closeSimulatedCase,
  containSimulatedCase,
  createSimulatedCase,
  importSimulatedReport,
  initialOffboardingCases,
  parsePlatformReport,
  reconcileSimulatedCase,
  assessSimulatedCase,
  syntheticBindings,
  syntheticReport,
  type OffboardingCase,
} from "./offboarding";

const now = Date.parse("2026-10-03T12:00:00Z");
/** A fixed fixture (departure five hours ago) independent of the public seed. */
async function start() {
  const item = await createSimulatedCase(
    {
      identityId: "mara",
      employmentType: "employee",
      hrEventId: "HR-2026-1084",
      hrSource: "HR service desk · synthetic event",
      effectiveAt: new Date(now - 5 * 3600000).toISOString(),
      reason:
        "Confirmed employee departure requires cross-system access containment and ownership handover.",
      bindings: syntheticBindings,
    },
    operators[0],
    now,
    "Mara Patel",
    "case-hr-1084",
  );
  return importSimulatedReport(
    item,
    syntheticReport(item, now, "before"),
    operators[0],
    now,
  );
}
const statement =
  "Synthetic owner confirms the scoped action, handover and remaining limitations.";
async function prepared() {
  let item = await start();
  item = (
    await containSimulatedCase(item, initialSimulation(now), operators[0], now)
  ).item;
  item = await importSimulatedReport(
    item,
    syntheticReport(item, now, "after"),
    operators[0],
    now,
  );
  return item;
}
async function completed(): Promise<OffboardingCase> {
  let item = await prepared();
  for (const task of item.tasks.filter((entry) => entry.status === "pending"))
    item = await attestSimulatedTask(
      item,
      task.id,
      "CHG-1048-EVIDENCE",
      statement,
      operators[0],
      now + 1000,
    );
  return item;
}
describe("public demo queue", () => {
  it("seeds due, overdue, scheduled and closed cases through real case rules", async () => {
    const [mara, leo, sam, priya] = await initialOffboardingCases(now);
    expect(mara.id).toBe("case-hr-1084");
    expect(Date.parse(mara.dueAt)).toBeGreaterThan(now);
    expect(mara.containmentRequestId).toBeUndefined();
    expect(Date.parse(leo.dueAt)).toBeLessThan(now);
    expect(leo.employmentType).toBe("contractor");
    expect(Date.parse(sam.effectiveAt)).toBeGreaterThan(now);
    expect(caseBlockers(sam, now)[0]).toContain("future");
    expect(priya).toMatchObject({
      status: "closed",
      closureBasis: "reviewed_evidence",
      closedById: "op-avery",
      ownerId: "op-jules",
    });
    expect(
      priya.tasks.filter((task) => task.evidenceKind === "owner_attestation"),
    ).toHaveLength(6);
    expect(casePacket(priya).limitations.join(" ")).toContain(
      "no external platforms were contacted",
    );
  });
});
describe("cross-system offboarding case controls", () => {
  it("keeps pre-departure evidence and residual access unresolved", async () => {
    const item = await start();
    expect(item.tasks).toHaveLength(9);
    expect(item.tasks.every((task) => task.status === "pending")).toBe(true);
    expect(item.imports[0].collectionMethod).toBe("synthetic_fixture");
    expect(item.blockers.some((line) => line.includes("Residual"))).toBe(true);
    expect(Date.parse(item.dueAt)).toBe(now - 3600000);
    expect(casePacket(item).mode).toBe("browser_simulation");
  });
  it("links containment to employee and sponsored agent enforcement", async () => {
    const original = initialSimulation(now);
    const result = await containSimulatedCase(
      await start(),
      original,
      operators[0],
      now,
    );
    expect(accessDecision(original, "mara", "atlas").allowed).toBe(true);
    expect(accessDecision(result.simulation, "mara", "atlas").allowed).toBe(
      false,
    );
    expect(
      accessDecision(result.simulation, "atlas-agent", "atlas").allowed,
    ).toBe(false);
    expect(
      result.item.tasks.filter(
        (task) => task.evidenceKind === "provider_observation",
      ),
    ).toHaveLength(2);
    expect(result.simulation.snapshot.runs).toEqual([]);
    expect(
      result.item.tasks.find((task) => task.id === "entra-sessions")?.status,
    ).toBe("pending");
  });
  it("assesses only narrow fresh snapshot state and preserves owner boundaries", async () => {
    const item = await prepared();
    expect(
      item.tasks.find((task) => task.id === "entra-directory"),
    ).toMatchObject({ status: "observed", evidenceKind: "imported_snapshot" });
    expect(item.tasks.find((task) => task.id === "github-org")?.status).toBe(
      "pending",
    );
    expect(
      item.tasks.find((task) => task.id === "github-repositories")?.status,
    ).toBe("pending");
    expect(
      item.tasks
        .filter((task) => task.status === "pending")
        .map((task) => task.id),
    ).toEqual([
      "entra-sessions",
      "github-org",
      "github-repositories",
      "credentials",
      "m365-handover",
      "legacy-scope",
    ]);
  });
  it("rejects malformed, future, cross-binding and non-synthetic public reports", async () => {
    const item = await start();
    const valid = syntheticReport(item, now, "after");
    const examples = [
      { ...valid, schemaVersion: 2 },
      { ...valid, collectionMethod: "read_only_api" },
      { ...valid, collectedAt: new Date(now + 600000).toISOString() },
      { ...valid, token: "unsupported-field" },
      {
        ...valid,
        observations: [
          {
            ...valid.observations[0],
            subjectId: "33333333-3333-4333-8333-333333333333",
          },
        ],
      },
      {
        ...valid,
        observations: [
          { ...valid.observations[0], status: "unknown", value: false },
        ],
      },
      {
        ...valid,
        observations: [valid.observations[0], valid.observations[0]],
      },
      { ...valid, observations: Array(101).fill(valid.observations[0]) },
    ];
    for (const report of examples)
      expect(() =>
        parsePlatformReport(report, item.bindings, now, true),
      ).toThrow();
    expect(
      parsePlatformReport(
        { ...valid, collectionMethod: "manual_export" },
        item.bindings,
        now,
        false,
      ).collectionMethod,
    ).toBe("manual_export");
  });
  it("keeps stale, partial and unknown imported observations from clearing tasks", async () => {
    const item = await start();
    for (const phase of ["stale", "partial", "unknown"] as const) {
      const report = syntheticReport(item, now, "after");
      if (phase === "stale") {
        report.collectedAt = new Date(now - 3 * 3600000).toISOString();
        report.observations.forEach((entry) => {
          entry.observedAt = report.collectedAt;
        });
      } else if (phase === "partial")
        report.observations = report.observations.filter(
          (entry) => entry.capability !== "account_enabled",
        );
      else
        report.observations.forEach((entry) => {
          entry.status = "unknown";
          entry.value = null;
        });
      const result = await importSimulatedReport(
        item,
        report,
        operators[0],
        now,
      );
      expect(
        result.tasks.find((task) => task.id === "github-repositories")?.status,
      ).toBe("pending");
      expect(
        result.tasks.find((task) => task.id === "entra-directory")?.status,
      ).toBe("pending");
    }
  });
  it("invalidates external attestations on import and preserves local observations", async () => {
    const item = await completed();
    const report = syntheticReport(item, now + 2000, "after");
    const changed = await importSimulatedReport(
      item,
      report,
      operators[0],
      now + 2000,
    );
    expect(
      changed.tasks.find((task) => task.id === "entra-sessions")?.status,
    ).toBe("pending");
    expect(
      changed.tasks.find((task) => task.id === "local-containment")?.status,
    ).toBe("observed");
    expect(changed.packetHash).not.toBe(item.packetHash);
    expect(changed.revision).toBe(item.revision + 1);
    expect(
      item.tasks.find((task) => task.id === "entra-sessions")?.status,
    ).toBe("attested");
  });
  it("requires accountable owner evidence and rejects future departure effects", async () => {
    const item = await start();
    await expect(
      attestSimulatedTask(
        item,
        "entra-sessions",
        "CHG-1048",
        statement,
        operators[1],
        now,
      ),
    ).rejects.toThrow("accountable case owner");
    await expect(
      attestSimulatedTask(
        item,
        "local-containment",
        "CHG-1048",
        statement,
        operators[0],
        now,
      ),
    ).rejects.toThrow("cannot be manually attested");
    const future = await createSimulatedCase(
      {
        identityId: "mara",
        employmentType: "contractor",
        hrEventId: "HR-FUTURE-1048",
        hrSource: "Synthetic HR event",
        effectiveAt: new Date(now + 3600000).toISOString(),
        reason: "Planned contract departure and scoped access handover.",
        bindings: syntheticBindings,
      },
      operators[0],
      now,
      "Mara Patel",
    );
    await expect(
      containSimulatedCase(future, initialSimulation(now), operators[0], now),
    ).rejects.toThrow("Future departures");
    await expect(
      attestSimulatedTask(
        future,
        "credentials",
        "CHG-1048",
        statement,
        operators[0],
        now,
      ),
    ).rejects.toThrow("effective");
    expect(caseBlockers(future, now)[0]).toContain("future");
  });
  it("blocks incomplete, stale and self-reviewed closure and freezes accepted evidence", async () => {
    const incomplete = await prepared();
    await expect(
      closeSimulatedCase(
        incomplete,
        operators[1],
        now,
        incomplete.revision,
        incomplete.packetHash,
      ),
    ).rejects.toThrow("Unresolved");
    const item = await completed();
    await expect(
      closeSimulatedCase(
        item,
        { ...operators[0], roles: ["operator", "reviewer"] },
        now,
        item.revision,
        item.packetHash,
      ),
    ).rejects.toThrow("own evidence");
    await expect(
      closeSimulatedCase(
        item,
        operators[1],
        now,
        item.revision - 1,
        item.packetHash,
      ),
    ).rejects.toThrow("changed");
    await expect(
      closeSimulatedCase(
        item,
        operators[1],
        now + 3 * 3600000,
        item.revision,
        item.packetHash,
      ),
    ).rejects.toThrow("Unresolved");
    const closed = await closeSimulatedCase(
      item,
      operators[1],
      now + 2000,
      item.revision,
      item.packetHash,
    );
    expect(closed).toMatchObject({
      status: "closed",
      closureBasis: "reviewed_evidence",
      closedById: "op-avery",
    });
    expect(
      closed.tasks.find((task) => task.id === "credentials")?.evidenceKind,
    ).toBe("owner_attestation");
    const packet = JSON.stringify(casePacket(closed));
    await expect(
      importSimulatedReport(
        closed,
        syntheticReport(closed, now + 3000, "after"),
        operators[0],
        now + 3000,
      ),
    ).rejects.toThrow("Closed cases");
    expect(JSON.stringify(casePacket(closed))).toBe(packet);
    expect(item.status).not.toBe("closed");
  });
  it("preserves optional legacy snapshots and rejects malformed case DTOs", async () => {
    const snapshot = initialSimulation(now).snapshot;
    expect(parseSnapshot(snapshot).offboardingCases).toEqual([]);
    expect(
      parseSnapshot({ ...snapshot, offboardingCases: [await start()] })
        .offboardingCases,
    ).toHaveLength(1);
    expect(() =>
      parseSnapshot({ ...snapshot, offboardingCases: [{ id: "broken" }] }),
    ).toThrow("invalid offboarding");
  });
  it("does not hide conflicting scopes or newer unknown directory observations", async () => {
    const item = await prepared();
    const report = syntheticReport(item, now + 1000, "after");
    report.observations.push({
      ...report.observations[0],
      scope: "Another explicitly reported scope",
      value: true,
    });
    const conflicting = await importSimulatedReport(
      item,
      report,
      operators[0],
      now + 1000,
    );
    expect(
      conflicting.tasks.find((task) => task.id === "entra-directory")?.status,
    ).toBe("pending");
    expect(
      conflicting.blockers.some((line) => line.includes("Residual entra")),
    ).toBe(true);
    const unknown = syntheticReport(item, now + 1000, "after");
    unknown.observations[0].status = "unknown";
    unknown.observations[0].value = null;
    expect(
      (
        await importSimulatedReport(item, unknown, operators[0], now + 1000)
      ).tasks.find((task) => task.id === "entra-directory")?.status,
    ).toBe("pending");
    const delayed = syntheticReport(item, now, "after");
    delayed.observations[0].observedAt = new Date(
      now - 90 * 60000,
    ).toISOString();
    const assessed = await importSimulatedReport(
      await start(),
      delayed,
      operators[0],
      now,
    );
    expect(
      assessed.tasks.find((task) => task.id === "entra-directory")?.observedAt,
    ).toBe(delayed.observations[0].observedAt);
    expect(
      caseBlockers(assessed, now + 31 * 60000).some((line) =>
        line.includes("stale"),
      ),
    ).toBe(true);
  });
  it("expires and refreshes only the modeled local directory proof", async () => {
    const contained = await containSimulatedCase(
      await start(),
      initialSimulation(now),
      operators[0],
      now,
    );
    const later = now + 3 * 3600000;
    expect(
      assessSimulatedCase(contained.item, later).tasks.find(
        (task) => task.id === "keycloak-directory",
      )?.status,
    ).toBe("pending");
    const fresh = await reconcileSimulatedCase(
      contained.item,
      contained.simulation,
      operators[0],
      later,
    );
    expect(
      fresh.item.tasks.find((task) => task.id === "keycloak-directory"),
    ).toMatchObject({
      status: "observed",
      evidenceKind: "provider_observation",
      observedAt: new Date(later).toISOString(),
    });
    expect(
      fresh.item.tasks.find((task) => task.id === "entra-directory")?.status,
    ).toBe("pending");
    contained.simulation.snapshot.health.find(
      (entry) => entry.name === "Directory connector",
    )!.status = "unavailable";
    expect(
      (
        await reconcileSimulatedCase(
          contained.item,
          contained.simulation,
          operators[0],
          later,
        )
      ).item.tasks.find((task) => task.id === "keycloak-directory")?.status,
    ).toBe("pending");
  });
});
