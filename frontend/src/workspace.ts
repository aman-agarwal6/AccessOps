import {
  Activity,
  FileCheck2,
  FileSearch,
  GitPullRequestArrow,
  LayoutDashboard,
  ShieldCheck,
  Users,
} from "lucide-react";
import type {
  Command,
  Identity,
  Principal,
  Resource,
  Run,
  Simulation,
  Snapshot,
} from "./domain";
import type { OffboardingCase } from "./offboarding";
import type { CaseCommand } from "./casecommands";

export const navigation = [
  {
    id: "overview",
    name: "Overview",
    group: "Offboarding",
    icon: LayoutDashboard,
    description:
      "What needs attention across departures, access changes and evidence.",
  },
  {
    id: "cases",
    name: "Offboarding cases",
    group: "Offboarding",
    icon: FileCheck2,
    description:
      "Each departure gets an owner, a four-hour target, required actions and an independent closure.",
  },
  {
    id: "requests",
    name: "Requests",
    group: "Access governance",
    icon: GitPullRequestArrow,
    description:
      "Review the exact change, then follow it through approval, enforcement and verification.",
  },
  {
    id: "identities",
    name: "Identities",
    group: "Access governance",
    icon: Users,
    description:
      "People and agents with their access, sponsors and lifecycle state.",
  },
  {
    id: "reviews",
    name: "Access reviews",
    group: "Access governance",
    icon: FileSearch,
    description:
      "A bounded assistant drafts findings. People decide; nothing it writes can approve access.",
  },
  {
    id: "policies",
    name: "Policies & resources",
    group: "Access governance",
    icon: ShieldCheck,
    description:
      "The rules every action is checked against, and the resources they protect.",
  },
  {
    id: "runs",
    name: "Runs & evidence",
    group: "Evidence",
    icon: Activity,
    description:
      "What actually ran, where it ran and how much each kind of evidence can prove.",
  },
] as const;
export type Page = (typeof navigation)[number]["id"];
export const pageInfo = (page: Page) =>
  navigation.find((entry) => entry.id === page)!;
export const readPage = (): Page => {
  const id = location.hash.replace("#/", "").split("?")[0];
  return navigation.some((entry) => entry.id === id)
    ? (id as Page)
    : "overview";
};

export type Selection = {
  kind: "request" | "identity" | "run";
  id: string;
} | null;
export type ModalKind =
  "request" | "guide" | "lab" | "reset" | "enroll" | "department" | null;

/** Everything a page needs, passed explicitly instead of through closures. */
export type Workspace = {
  connected: boolean;
  authenticated: boolean;
  data: Snapshot;
  cases: OffboardingCase[];
  simulation: Simulation;
  recorded: Run[];
  recordedState: "loading" | "ready" | "error";
  recordedError: string;
  principal?: Principal;
  now: number;
  busy: boolean;
  sourceUrl?: string;
  person: (id?: string) => Identity | undefined;
  resource: (id?: string) => Resource | undefined;
  name: (id?: string) => string;
  go: (page: Page, filter?: string) => void;
  select: (selection: Selection) => void;
  openModal: (modal: ModalKind) => void;
  perform: (command: Command) => Promise<void>;
  performCase: (command: CaseCommand) => Promise<string | undefined>;
  exportPacket: (id: string) => Promise<void>;
  exportSimulation: () => void;
  retryRecorded: () => void;
  startGuide: () => void;
  /** Simulation only: switch the acting operator to satisfy a role boundary. */
  actAs?: (id: string) => void;
  initialFilter: string;
};
