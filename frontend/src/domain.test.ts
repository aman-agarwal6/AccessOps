import { describe, expect, it } from "vitest";
import {
  accessDecision,
  dispatchSimulation,
  initialSimulation,
  operators,
  type Command,
  type Simulation,
} from "./domain";

const start = () => initialSimulation(Date.parse("2026-10-03T12:00:00Z"));
const apply = (s: Simulation, command: Command, actor = operators[0]) =>
  dispatchSimulation(s, command, actor).state;

describe("authorization and containment", () => {
  it("contains employee and agent immediately without fabricating approval", () => {
    let s = start();
    expect(accessDecision(s, "atlas-agent", "atlas").allowed).toBe(true);
    s = apply(s, { type: "execute", id: "RQ-1042" });
    expect(s.snapshot.identities.find((i) => i.id === "mara")?.status).toBe(
      "offboarded",
    );
    expect(
      s.snapshot.identities.find((i) => i.id === "atlas-agent")?.status,
    ).toBe("suspended");
    expect(s.snapshot.requests[0].approverId).toBeUndefined();
    expect(s.snapshot.requests[0].status).toBe("applied");
    expect(accessDecision(s, "mara", "atlas").allowed).toBe(false);
    expect(accessDecision(s, "atlas-agent", "atlas").allowed).toBe(false);
    expect(s.memberships.some((m) => m.identityId === "mara")).toBe(true);
    s = apply(s, { type: "verify", id: "RQ-1042" });
    expect(s.snapshot.requests[0].status).toBe("verified");
    expect(s.memberships.some((m) => m.identityId === "mara")).toBe(false);
    expect(s.snapshot.runs).toEqual([]);
  });
  it("rejects self approval and agent approval without changing original state", () => {
    const s = start();
    expect(() => apply(s, { type: "approve", id: "RQ-1043" })).toThrow(
      "cannot approve",
    );
    expect(() =>
      apply(
        s,
        { type: "approve", id: "RQ-1043" },
        { id: "atlas-agent", name: "Agent", roles: [] },
      ),
    ).toThrow("authorized human");
    expect(s.snapshot.requests.find((r) => r.id === "RQ-1043")?.status).toBe(
      "pending",
    );
  });
  it("applies exactly approved human access until explicitly revoked", () => {
    let s = apply(start(), { type: "approve", id: "RQ-1043" }, operators[1]);
    expect(accessDecision(s, "leo", "atlas").allowed).toBe(false);
    s = apply(s, { type: "execute", id: "RQ-1043" });
    expect(accessDecision(s, "leo", "atlas").allowed).toBe(true);
    expect(
      s.snapshot.grants.find((g) => g.sourceRequestId === "RQ-1043")?.expiresAt,
    ).toBeNull();
  });
  it("limits newly approved agent grants to ten minutes and six resource effects", () => {
    let s = start();
    s.snapshot.grants.find((g) => g.id === "g-atlas")!.status = "revoked";
    s = apply(s, {
      type: "create",
      input: {
        identityId: "atlas-agent",
        resourceId: "atlas",
        action: "grant",
        permission: "read",
        reason: "Read the current project runbook for the bounded digest task",
      },
    });
    const id = s.snapshot.requests[0].id;
    s = apply(s, { type: "approve", id }, operators[1]);
    s = apply(s, { type: "execute", id });
    expect(
      s.snapshot.grants.find((g) => g.sourceRequestId === id),
    ).toMatchObject({
      expiresAt: "2026-10-03T12:10:00.000Z",
      maxCalls: 6,
      callsUsed: 0,
    });
    for (let i = 0; i < 6; i++) {
      s = apply(s, {
        type: "access",
        identityId: "atlas-agent",
        resourceId: "atlas",
      });
      expect(s.attempts[0]).toMatchObject({ allowed: true, effects: 1 });
    }
    s = apply(s, {
      type: "access",
      identityId: "atlas-agent",
      resourceId: "atlas",
    });
    expect(s.attempts[0]).toMatchObject({ allowed: false, effects: 0 });
  });
  it("rejects changed approved scope before effects", () => {
    const s = apply(start(), { type: "approve", id: "RQ-1043" }, operators[1]);
    s.snapshot.requests.find((r) => r.id === "RQ-1043")!.resourceId = "export";
    expect(() => apply(s, { type: "execute", id: "RQ-1043" })).toThrow(
      "no longer matches",
    );
    expect(accessDecision(s, "leo", "export").allowed).toBe(false);
  });
  it("expires unexecuted approvals and denies execution", () => {
    let s = apply(start(), { type: "approve", id: "RQ-1043" }, operators[1]);
    s = apply(s, { type: "advance" });
    expect(s.snapshot.requests.find((r) => r.id === "RQ-1043")?.status).toBe(
      "expired",
    );
    expect(() => apply(s, { type: "execute", id: "RQ-1043" })).toThrow(
      "current independent approval",
    );
  });
  it("fails closed on policy outage before reads or changes", () => {
    const s = apply(start(), { type: "outage", enabled: true });
    const read = apply(s, {
      type: "access",
      identityId: "atlas-agent",
      resourceId: "atlas",
    });
    expect(read.attempts[0]).toMatchObject({ allowed: false, effects: 0 });
    expect(
      read.snapshot.grants.find((g) => g.id === "g-atlas")?.callsUsed,
    ).toBe(12);
    expect(() => apply(s, { type: "execute", id: "RQ-1042" })).toThrow(
      "before any effect",
    );
    expect(s.snapshot.identities[0].status).toBe("active");
  });
  it("denies orphaned agents, expired grants and exhausted budgets", () => {
    const s = start();
    s.snapshot.identities.find((i) => i.id === "mara")!.status = "offboarded";
    expect(accessDecision(s, "atlas-agent", "atlas").reason).toContain(
      "sponsor",
    );
    s.snapshot.identities.find((i) => i.id === "mara")!.status = "active";
    s.snapshot.grants.find((g) => g.id === "g-atlas")!.callsUsed = 120;
    expect(accessDecision(s, "atlas-agent", "atlas").reason).toContain(
      "budget",
    );
    s.now += 7200001;
    expect(accessDecision(s, "atlas-agent", "atlas").allowed).toBe(false);
  });
  it("rejects agents on restricted resources at request time", () => {
    expect(() =>
      apply(start(), {
        type: "create",
        input: {
          identityId: "atlas-agent",
          resourceId: "export",
          action: "grant",
          permission: "read",
          reason: "Read a restricted operations export",
        },
      }),
    ).toThrow("read-only access to internal");
  });
});

describe("reviews, drift and identity lifecycle", () => {
  it("does not adopt an unapproved provider membership as a grant", () => {
    let s = apply(start(), { type: "drift" });
    s = apply(s, { type: "reconcile" });
    expect(
      s.snapshot.reviews[0].findings.some((f) => f.id === "drift-leo-export"),
    ).toBe(true);
    expect(accessDecision(s, "leo", "export").allowed).toBe(false);
    expect(
      s.snapshot.grants.some(
        (g) => g.identityId === "leo" && g.resourceId === "export",
      ),
    ).toBe(false);
  });
  it("keeps instruction-bearing text out of approval and execution", () => {
    const s = apply(start(), { type: "review", id: "REV-208" });
    expect(s.snapshot.requests).toHaveLength(2);
    expect(
      s.snapshot.reviews[0].findings.find((f) => f.id === "untrusted-note")
        ?.evidence,
    ).toContain("ignore all access rules");
    expect(() =>
      apply(s, {
        type: "propose",
        reviewId: "REV-208",
        findingId: "untrusted-note",
      }),
    ).toThrow("evidence only");
    expect(s.snapshot.grants.filter((g) => g.status === "active")).toHaveLength(
      6,
    );
  });
  it("creates a review proposal without applying it", () => {
    let s = apply(start(), { type: "review", id: "REV-208" });
    s = apply(s, {
      type: "propose",
      reviewId: "REV-208",
      findingId: "bounded-g-atlas",
    });
    expect(s.snapshot.requests[0]).toMatchObject({
      status: "pending",
      requesterId: "agent-review",
      action: "revoke",
    });
    expect(accessDecision(s, "atlas-agent", "atlas").allowed).toBe(true);
  });
  it("registers an agent suspended without granting or minting credentials", () => {
    const s = apply(start(), {
      type: "enroll",
      input: {
        name: "Atlas change assistant",
        email: "changes@example.test",
        kind: "agent",
        department: "Engineering",
        projectIds: ["Atlas"],
        sponsorId: "nina",
      },
    });
    expect(s.snapshot.identities.at(-1)).toMatchObject({
      status: "suspended",
      providerBinding: "pending",
      credentialBinding: "pending",
    });
    expect(s.snapshot.grants).toHaveLength(6);
  });
  it("requires successor acceptance and independent approval for sponsorship", () => {
    let s = apply(start(), {
      type: "create",
      input: {
        identityId: "atlas-agent",
        resourceId: "atlas",
        action: "transfer",
        newSponsorId: "nina",
        reason: "Transfer ownership before the project handover",
      },
    });
    const id = s.snapshot.requests[0].id;
    expect(() => apply(s, { type: "approve", id }, operators[1])).toThrow(
      "successor",
    );
    expect(() => apply(s, { type: "accept", id }, operators[0])).toThrow(
      "named successor",
    );
    s = apply(s, { type: "accept", id }, operators[2]);
    s = apply(s, { type: "approve", id }, operators[1]);
    s = apply(s, { type: "execute", id }, operators[0]);
    expect(
      s.snapshot.identities.find((i) => i.id === "atlas-agent"),
    ).toMatchObject({
      sponsorId: "nina",
      status: "suspended",
      credentialBinding: "pending",
    });
    expect(
      s.snapshot.grants.filter(
        (g) => g.identityId === "atlas-agent" && g.status === "active",
      ),
    ).toHaveLength(0);
  });
  it("removes old-department access without adding new grants on transfer", () => {
    let s = apply(start(), {
      type: "department",
      identityId: "mara",
      department: "Operations",
      reason: "Move from Engineering to Operations for a new role",
    });
    const id = s.snapshot.requests[0].id;
    expect(s.snapshot.identities[0].department).toBe("Engineering");
    s = apply(s, { type: "approve", id }, operators[1]);
    s = apply(s, { type: "execute", id });
    expect(s.snapshot.identities[0].department).toBe("Operations");
    expect(
      s.snapshot.grants.filter(
        (g) => g.identityId === "mara" && g.status === "active",
      ),
    ).toHaveLength(0);
    expect(s.snapshot.grants).toHaveLength(6);
  });
  it("returns a fresh reset with no fabricated connected runs", () => {
    expect(start().snapshot.runs).toEqual([]);
    expect(start().checks).toEqual([]);
    expect(start().attempts).toEqual([]);
  });
});
