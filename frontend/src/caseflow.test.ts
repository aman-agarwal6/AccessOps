import { describe, expect, it } from "vitest";
import {
  byUrgency,
  inQueue,
  nextStep,
  phaseTasks,
  isNative,
  sla,
  taskProvenance,
} from "./caseflow";
import { initialSimulation, operators } from "./domain";
import {
  attestSimulatedTask,
  containSimulatedCase,
  importSimulatedReport,
  initialOffboardingCases,
  syntheticReport,
} from "./offboarding";

const now = Date.parse("2026-10-03T12:00:00Z");
const [jules, avery, nina] = operators;

describe("case next step", () => {
  it("walks contain → import → attest → independent review", async () => {
    let [item] = await initialOffboardingCases(now);
    expect(nextStep(item, now, jules, "Jules", false)).toMatchObject({
      stage: "contain",
      blockedBy: undefined,
    });
    item = (
      await containSimulatedCase(item, initialSimulation(now), jules, now)
    ).item;
    expect(nextStep(item, now, jules, "Jules", false).stage).toBe("import");
    item = await importSimulatedReport(
      item,
      syntheticReport(item, now, "after"),
      jules,
      now,
    );
    const attest = nextStep(item, now, jules, "Jules", false);
    expect(attest).toMatchObject({ stage: "attest", needs: "owner" });
    expect(attest.title).toContain("6 remaining");
    expect(nextStep(item, now, avery, "Jules", false).blockedBy).toContain(
      "Only the case owner",
    );
    for (const task of item.tasks.filter((entry) => entry.status === "pending"))
      item = await attestSimulatedTask(
        item,
        task.id,
        "CHG-TEST-0001",
        "Synthetic owner statement for the scoped handover test.",
        jules,
        now + 1000,
      );
    const owner = nextStep(item, now + 2000, jules, "Jules", false);
    expect(owner.stage).toBe("review");
    expect(owner.blockedBy).toContain("independent reviewer");
    expect(
      nextStep(item, now + 2000, avery, "Jules", false).blockedBy,
    ).toBeUndefined();
    expect(
      nextStep(item, now + 2000, nina, "Jules", false).blockedBy,
    ).toBeDefined();
  });
  it("explains missing roles and never offers early action on scheduled departures", async () => {
    const [mara, , sam, priya] = await initialOffboardingCases(now);
    expect(nextStep(mara, now, nina, "Jules", false).blockedBy).toBe(
      "Requires the operator role.",
    );
    const scheduled = nextStep(sam, now, jules, "Jules", false);
    expect(scheduled.stage).toBe("scheduled");
    expect(scheduled.action).toBeUndefined();
    expect(nextStep(priya, now, jules, "Jules", false).stage).toBe("closed");
  });
});

describe("queue and evidence presentation", () => {
  it("orders by urgency and filters by target state", async () => {
    const cases = await initialOffboardingCases(now);
    const order = [...cases].sort(byUrgency(now)).map((item) => item.hrEventId);
    expect(order).toEqual([
      "HR-2026-1079",
      "HR-2026-1084",
      "HR-2026-1091",
      "HR-2026-1062",
    ]);
    expect(cases.filter((item) => inQueue(item, "overdue", now))).toHaveLength(
      1,
    );
    expect(cases.filter((item) => inQueue(item, "open", now))).toHaveLength(3);
    expect(sla(cases[0], now).label).toMatch(/^Due in 2h 45m$/);
    expect(sla(cases[2], now).kind).toBe("scheduled");
  });
  it("labels native browser readings as simulated, never as provider observations", async () => {
    const [item] = await initialOffboardingCases(now);
    const contained = (
      await containSimulatedCase(item, initialSimulation(now), jules, now)
    ).item;
    const local = contained.tasks.find(
      (task) => task.id === "local-containment",
    )!;
    expect(taskProvenance(local, false)).toBe("simulated");
    expect(taskProvenance(local, true)).toBe("observed");
    expect(phaseTasks(contained).flatMap((phase) => phase.tasks)).toHaveLength(
      9,
    );
  });
  it("groups a sign-in after departure with containment and lets the owner record it", async () => {
    const [item] = await initialOffboardingCases(now);
    const flagged = {
      ...item,
      tasks: [
        ...item.tasks,
        {
          ...item.tasks[0],
          id: "post-departure-access",
          title: "Investigate sign-in after departure",
          status: "pending" as const,
          evidenceKind: "none" as const,
        },
      ],
    };
    const contain = phaseTasks(flagged).find(
      (phase) => phase.id === "contain",
    )!;
    expect(contain.tasks.map((task) => task.id)).toContain(
      "post-departure-access",
    );
    expect(isNative("post-departure-access")).toBe(false);
  });
});
