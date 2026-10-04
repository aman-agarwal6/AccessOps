import { afterEach, describe, expect, it, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { initialSimulation, operators } from "./domain";
import { parseSnapshot } from "./api";
import { CaseDetail } from "./pages/cases/CaseDetail";
import type { Workspace } from "./workspace";
import {
  attestSimulatedTask,
  initialOffboardingCases,
  type DirectoryBinding,
  type OffboardingCase,
} from "./offboarding";

const now = Date.parse("2026-10-03T12:00:00Z");
const enrollment: DirectoryBinding = {
  domainGuid: "44444444-4444-4444-8444-444444444444",
  userGuid: "55555555-5555-4555-8555-555555555555",
  groupGuids: ["66666666-6666-4666-8666-666666666666"],
};
async function fixture(): Promise<OffboardingCase> {
  const item = (await initialOffboardingCases(now))[0];
  item.adBinding = enrollment;
  item.tasks.push({
    id: "ad-directory",
    platform: "legacy",
    boundary: "directory",
    title: "Observe scoped Samba AD directory containment",
    ownerId: item.ownerId,
    dueAt: item.dueAt,
    status: "pending",
    required: true,
    evidenceKind: "none",
  });
  return item;
}
afterEach(() => vi.unstubAllGlobals());
describe("optional trusted AD enrollment presentation", () => {
  it("accepts trusted enrollment DTOs and rejects malformed or excessive GUID scope", async () => {
    const item = await fixture();
    const snapshot = initialSimulation(now).snapshot;
    snapshot.identities[0].directoryBinding = enrollment;
    expect(
      parseSnapshot({ ...snapshot, offboardingCases: [item] })
        .offboardingCases?.[0].adBinding,
    ).toEqual(enrollment);
    for (const adBinding of [
      { ...enrollment, userGuid: "display-name" },
      { ...enrollment, groupGuids: Array(11).fill(enrollment.groupGuids[0]) },
    ]) {
      expect(() =>
        parseSnapshot({
          ...snapshot,
          offboardingCases: [{ ...item, adBinding }],
        }),
      ).toThrow("invalid offboarding");
    }
    snapshot.identities[0].directoryBinding = {
      ...enrollment,
      domainGuid: "unbound-domain",
    };
    expect(() => parseSnapshot(snapshot)).toThrow("invalid trusted directory");
  });
  it("never permits manual attestation for the directory observation task", async () => {
    const item = await fixture();
    await expect(
      attestSimulatedTask(
        item,
        "ad-directory",
        "CHG-AD-1048",
        "Synthetic owner statement cannot replace the scoped directory observation.",
        operators[0],
        now,
      ),
    ).rejects.toThrow("cannot be manually attested");
    expect(item.tasks.find((task) => task.id === "ad-directory")?.status).toBe(
      "pending",
    );
    expect((await initialOffboardingCases(now))[0].tasks).toHaveLength(9);
  });
  it("shows scoped directory refresh without manual completion or editable GUIDs", async () => {
    const item = await fixture();
    const snapshot = initialSimulation(now).snapshot;
    const ws = {
      connected: true,
      authenticated: true,
      data: snapshot,
      cases: [item],
      principal: operators[0],
      now,
      busy: false,
      person: (id?: string) => snapshot.identities.find((i) => i.id === id),
      resource: () => undefined,
      name: () => "Synthetic operator",
      exportPacket: vi.fn(),
    } as unknown as Workspace;
    const render = () =>
      renderToStaticMarkup(
        createElement(CaseDetail, { ws, item, notice: "", onAction: vi.fn() }),
      );
    const html = render();
    const row = html
      .split("<h4>Observe scoped Samba AD directory containment</h4>")[1]
      .split("</li>")[0];
    expect(row).toContain("Samba AD lab");
    expect(row).toContain("Refresh directory");
    expect(row).toContain('disabled=""');
    expect(row).not.toContain("Record owner evidence");
    expect(html).toContain("read only");
    expect(html).not.toContain('name="domainGuid"');
    expect(html).not.toContain('name="userGuid"');
    item.containmentRequestId = "synthetic-containment-request";
    item.tasks.find((task) => task.id === "local-containment")!.status =
      "observed";
    const enabled = render()
      .split("<h4>Observe scoped Samba AD directory containment</h4>")[1]
      .split("</li>")[0];
    expect(enabled).not.toContain('disabled=""');
  });
});
