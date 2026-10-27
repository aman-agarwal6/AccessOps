import { describe, expect, it, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { parseSnapshot } from "./api";
import { isNative, nextStep, watchLine } from "./caseflow";
import { initialSimulation, operators, type Principal } from "./domain";
import { CaseDetail } from "./pages/cases/CaseDetail";
import { formatDate } from "./ui";
import type { Workspace } from "./workspace";
import {
  attestSimulatedTask,
  containSimulatedCase,
  importSimulatedReport,
  initialOffboardingCases,
  syntheticReport,
  type CaseWatch,
  type EntraBinding,
  type OffboardingCase,
} from "./offboarding";

const now = Date.parse("2026-10-03T12:00:00Z");
const [jules, avery] = operators;
const enrollment: EntraBinding = {
  tenantId: "11111111-1111-4111-8111-111111111111",
  userId: "33333333-3333-4333-8333-333333333333",
  groupIds: ["66666666-6666-4666-8666-666666666666"],
};
const watch = (patch: Partial<CaseWatch> = {}): CaseWatch => ({
  status: "watching",
  windowEndsAt: "2026-10-04T08:00:00Z",
  lastReadAt: new Date(now - 12000).toISOString(),
  lastAttemptAt: new Date(now - 12000).toISOString(),
  refused: 0,
  successes: 0,
  afterClosure: 0,
  ...patch,
});

/** The guided case, contained, before any after-departure report. */
async function contained(): Promise<OffboardingCase> {
  const [item] = await initialOffboardingCases(now);
  return (await containSimulatedCase(item, initialSimulation(now), jules, now))
    .item;
}
/** Every action accounted for; only the independent review is left. */
async function ready(): Promise<OffboardingCase> {
  const start = await contained();
  let item = await importSimulatedReport(
    start,
    syntheticReport(start, now, "after"),
    jules,
    now,
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
  return item;
}
function render(
  item: OffboardingCase,
  connected = true,
  principal: Principal = jules,
) {
  const snapshot = initialSimulation(now).snapshot;
  const ws = {
    connected,
    authenticated: true,
    data: snapshot,
    cases: [item],
    principal,
    now,
    busy: false,
    person: (id?: string) => snapshot.identities.find((i) => i.id === id),
    resource: () => undefined,
    name: () => "Synthetic operator",
    exportPacket: vi.fn(),
  } as unknown as Workspace;
  return renderToStaticMarkup(
    createElement(CaseDetail, { ws, item, notice: "", onAction: vi.fn() }),
  )
    .replace(/<!-- -->/g, "")
    .replace(/&#x27;/g, "'");
}
const row = (html: string, title: string) =>
  html.split(`<h4>${title}</h4>`)[1].split("</li>")[0];
const nextStepCard = (html: string) =>
  html.split('aria-labelledby="next-step-title"')[1].split("</section>")[0];

describe("server-enrolled Entra account", () => {
  it("is observed by the worker and never offered for owner evidence", async () => {
    // No import bindings: before the fix, the next step attested this task.
    const item = {
      ...(await contained()),
      bindings: [],
      entraBinding: enrollment,
    };
    expect(isNative(item, "entra-directory")).toBe(true);
    expect(isNative(item, "entra-sessions")).toBe(false);
    expect(isNative({}, "entra-directory")).toBe(false);
    expect(nextStep(item, now, jules, "Jules", true)).toMatchObject({
      stage: "observe",
      action: { kind: "observeDirectory" },
    });
    const offline = nextStep(item, now, jules, "Jules", false);
    expect(offline).toMatchObject({ stage: "observe", tone: "waiting" });
    expect(offline.action).toBeUndefined();
    await expect(
      attestSimulatedTask(
        item,
        "entra-directory",
        "CHG-ENTRA-1048",
        "Synthetic owner statement cannot replace the enrolled Entra observation.",
        jules,
        now,
      ),
    ).rejects.toThrow("cannot be manually attested");

    const observed = structuredClone(item);
    Object.assign(
      observed.tasks.find((task) => task.id === "entra-directory")!,
      { status: "observed", evidenceKind: "provider_observation" },
    );
    const step = nextStep(observed, now, jules, "Jules", true);
    expect(step).toMatchObject({ stage: "attest", needs: "owner" });
    expect(step.title).toContain("6 remaining");
    expect(step.action?.taskId).not.toBe("entra-directory");
  });

  it("lists the enrolled IDs and offers a directory refresh instead of a statement", async () => {
    const item = { ...(await contained()), entraBinding: enrollment };
    const html = render(item);
    const entra = row(html, "Block Microsoft Entra sign-in");
    expect(entra).toContain("Refresh directory");
    expect(entra).not.toContain("Record owner evidence");
    expect(
      row(html, "Review Entra and application session termination"),
    ).toContain("Record owner evidence");
    expect(html).toContain("Bound account IDs · 3");
    expect(html).toContain("Microsoft Entra ID (server-enrolled)");
    expect(html).toContain(`Account ${enrollment.userId}`);
    expect(html).toContain("Trusted enrollment");
    expect(html).not.toContain('name="userId"');

    // The browser simulation has no enrollment; the owner still attests there.
    const simulated = render(await contained(), false);
    expect(row(simulated, "Block Microsoft Entra sign-in")).toContain(
      "Record owner evidence",
    );
    expect(simulated).toContain("Bound account IDs · 2");
    expect(simulated).not.toContain("server-enrolled");
  });

  it("accepts the trusted DTO fields and rejects malformed ones", async () => {
    const item = { ...(await ready()), entraBinding: enrollment };
    const snapshot = initialSimulation(now).snapshot;
    const pending = watch({
      status: "pending",
      lastReadAt: null,
      lastAttemptAt: null,
      refused: null,
    });
    const [parsed] =
      parseSnapshot({
        ...snapshot,
        offboardingCases: [{ ...item, watch: pending }],
      }).offboardingCases ?? [];
    expect(parsed.entraBinding).toEqual(enrollment);
    expect(parsed.watch).toEqual(pending);
    // Python's isoformat, as the backend sends it.
    const sent = watch({
      windowEndsAt: "2026-10-28T21:13:23.009770+00:00",
      lastReadAt: "2026-10-27T21:14:02.118204+00:00",
      lastAttemptAt: "2026-10-27T21:14:02.118204+00:00",
    });
    expect(
      parseSnapshot({
        ...snapshot,
        offboardingCases: [{ ...item, watch: sent }],
      }).offboardingCases?.[0].watch,
    ).toEqual(sent);
    const [group] = enrollment.groupIds;
    for (const bad of [
      { entraBinding: { ...enrollment, userId: "display-name" } },
      { entraBinding: { ...enrollment, tenantId: "contoso" } },
      { entraBinding: { ...enrollment, groupIds: "all" } },
      { entraBinding: { ...enrollment, groupIds: [group, group] } },
      { watch: { ...watch(), status: "asleep" } },
      { watch: { ...watch(), afterClosure: -1 } },
      { watch: { ...watch(), successes: 1.5 } },
      { watch: { ...watch(), refused: -1 } },
      { watch: { ...watch(), lastReadAt: "yesterday" } },
      { watch: { ...watch(), lastAttemptAt: "soon" } },
      { watch: { ...watch(), windowEndsAt: null } },
    ])
      expect(() =>
        parseSnapshot({
          ...snapshot,
          offboardingCases: [{ ...item, ...bad }],
        }),
      ).toThrow("invalid offboarding");
  });
});

describe("sign-in watch after departure", () => {
  it("waits, with nothing to click, while the watch blocks closure", async () => {
    const item = await ready();
    expect(nextStep(item, now, avery, "Jules", true).stage).toBe("review");
    for (const [status, title] of [
      ["not_configured", "Sign-ins after departure can't be checked"],
      ["pending", "Waiting for the first sign-in check"],
      ["unavailable", "Waiting for a successful sign-in check"],
      ["stale", "Waiting for a current sign-in check"],
      ["finishing", "Waiting for the final sign-in check"],
    ] as const) {
      const waiting = {
        ...item,
        watch: watch({ status }),
        blockers: ["A watch blocker from the server."],
      };
      for (const principal of [avery, jules]) {
        const step = nextStep(waiting, now, principal, "Jules", true);
        expect(step).toMatchObject({ stage: "watch", tone: "waiting", title });
        expect(step.action).toBeUndefined();
        expect(step.blockedBy).toBeUndefined();
      }
      const card = nextStepCard(render(waiting, true, avery));
      expect(card).toContain(title);
      expect(card).not.toContain("<button");
    }
    for (const status of ["watching", "complete", "missed"] as const)
      expect(
        nextStep(
          { ...item, watch: watch({ status }) },
          now,
          avery,
          "Jules",
          true,
        ),
      ).toMatchObject({ stage: "review", action: { kind: "close" } });
  });

  it("shows the watch in one line, and nothing in the simulation", async () => {
    const item = await ready();
    expect(render(item)).not.toContain("Sign-in watch");
    const end = formatDate(watch().windowEndsAt);
    expect(render({ ...item, watch: watch() })).toContain(
      `<strong>Sign-in watch:</strong> last checked 12s ago · runs until ${end}`,
    );
    expect(
      watchLine(watch({ status: "unavailable", lastReadAt: null }), now),
    ).toEqual({
      tone: "danger",
      text: `latest check failed · no successful check yet · runs until ${end}`,
    });
    expect(
      watchLine(
        watch({ status: "finishing" }),
        Date.parse("2026-10-04T09:00:00Z"),
      ),
    ).toEqual({
      tone: "neutral",
      text: `waiting for the final check · day ended ${end}`,
    });
    expect(watchLine(watch({ status: "missed" }), now)).toEqual({
      tone: "warn",
      text: `did not cover the full day after departure · runs until ${end}`,
    });
    // The packet says only that an attempt was refused; the line has the count.
    expect(watchLine(watch({ refused: 1 }), now)?.text).toBe(
      `last checked 12s ago · 1 refused attempt · runs until ${end}`,
    );
    expect(
      watchLine(watch({ status: "complete", refused: 3 }), now)?.text,
    ).toBe(`complete · covered the day until ${end} · 3 refused attempts`);
    expect(watchLine(undefined, now)).toBeUndefined();
  });

  it("alerts when a sign-in is read after closure", async () => {
    const closed = (await initialOffboardingCases(now))[3];
    expect(closed.status).toBe("closed");
    const two = render({
      ...closed,
      watch: watch({ status: "complete", successes: 2, afterClosure: 2 }),
    });
    expect(two).toContain('role="alert"');
    expect(two).toContain("2 sign-ins were first read after closure.");
    // Signals depend on the server's configuration, which the console can't see.
    expect(two).toContain(
      "Each sign-in is audited and, where leaver signals are configured, sent to the SOC.",
    );
    expect(
      render({
        ...closed,
        watch: watch({ status: "watching", successes: 1, afterClosure: 1 }),
      }),
    ).toContain("1 sign-in was first read after closure.");
    expect(render({ ...closed, watch: watch() })).not.toContain(
      "after closure",
    );
    expect(render(closed)).not.toContain("after closure");
  });

  it("names a closed case's watch findings in the queue", async () => {
    const closed = (await initialOffboardingCases(now))[3];
    const title = (patch?: Partial<CaseWatch>) =>
      nextStep(
        { ...closed, watch: patch && watch(patch) },
        now,
        jules,
        "Jules",
        true,
      ).title;
    expect(title()).toBe("Closed on reviewed evidence");
    expect(title({})).toBe("Closed on reviewed evidence");
    expect(title({ status: "complete", successes: 1, afterClosure: 1 })).toBe(
      "Closed · 1 sign-in read after closure",
    );
    expect(title({ status: "unavailable", afterClosure: 2 })).toBe(
      "Closed · 2 sign-ins read after closure",
    );
    for (const status of ["unavailable", "stale"] as const)
      expect(title({ status })).toBe("Closed · sign-in watch interrupted");
    for (const status of ["finishing", "missed", "not_configured"] as const)
      expect(title({ status })).toBe("Closed on reviewed evidence");
  });
});
