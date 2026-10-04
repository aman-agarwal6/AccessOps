import type { NewCase } from "./offboarding";

export type CaseCommand =
  | { type: "create"; input: NewCase }
  | { type: "import"; id: string; report: unknown }
  | { type: "contain"; id: string }
  | { type: "reconcile"; id: string }
  | { type: "observeDirectory"; id: string }
  | {
      type: "attest";
      id: string;
      taskId: string;
      reference: string;
      summary: string;
    }
  | { type: "close"; id: string; expectedRevision: number; packetHash: string };
