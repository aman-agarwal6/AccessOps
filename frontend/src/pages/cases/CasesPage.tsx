import { useEffect, useState } from "react";
import type { QueueFilter, StepAction } from "../../caseflow";
import type { CaseCommand } from "../../casecommands";
import { Empty, FormError } from "../../ui";
import type { Workspace } from "../../workspace";
import { CaseDetail } from "./CaseDetail";
import {
  AttestDialog,
  CloseDialog,
  CreateCaseDialog,
  ImportDialog,
} from "./CaseDialogs";
import { CaseQueue } from "./CaseQueue";
import { openCase, selectedCaseId } from "./route";

type Dialog = "create" | "import" | "attest" | "close" | null;
const filters: QueueFilter[] = [
  "open",
  "overdue",
  "scheduled",
  "closed",
  "all",
];

export function CasesPage({ ws }: { ws: Workspace }) {
  const [caseId, setCaseId] = useState(selectedCaseId);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [taskId, setTaskId] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [filter, setFilter] = useState<QueueFilter>(
    filters.includes(ws.initialFilter as QueueFilter)
      ? (ws.initialFilter as QueueFilter)
      : "open",
  );
  useEffect(() => {
    const update = () => {
      setCaseId(selectedCaseId());
      setDialog(null);
      setNotice("");
    };
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);
  useEffect(() => {
    if (caseId) window.scrollTo({ top: 0 });
  }, [caseId]);
  const item = ws.cases.find((entry) => entry.id === caseId);

  function begin(next: Dialog) {
    setError("");
    setNotice("");
    setDialog(next);
  }
  async function run(command: CaseCommand, success: string) {
    setError("");
    try {
      const id = await ws.performCase(command);
      if (!id) return;
      setDialog(null);
      if (command.type === "create") openCase(id);
      else setNotice(success);
    } catch (problem) {
      setError(
        problem instanceof Error ? problem.message : "The case action failed.",
      );
    }
  }
  function onAction(kind: StepAction, task?: string) {
    if (!item) return;
    if (kind === "export") void ws.exportPacket(item.id);
    else if (kind === "import") begin("import");
    else if (kind === "close") begin("close");
    else if (kind === "attest") {
      setTaskId(task ?? "");
      begin("attest");
    } else if (kind === "contain")
      void run(
        { type: "contain", id: item.id },
        "Local access contained. Grants are revoked and sponsored agents suspended; directory evidence is shown below.",
      );
    else if (kind === "reconcile")
      void run(
        { type: "reconcile", id: item.id },
        "Directory read again. The latest observation now decides the workforce task.",
      );
    else
      void run(
        { type: "observeDirectory", id: item.id },
        "Read-only directory observation queued. Refresh to see the result.",
      );
  }

  if (caseId && !item)
    return (
      <Empty
        title="This case is not available"
        action={
          <button className="btn btn-secondary" onClick={() => openCase()}>
            Back to the queue
          </button>
        }
      >
        It may be outside your project scope, or the browser simulation was
        reset. Cases are only listed when you are allowed to see them.
      </Empty>
    );

  return (
    <>
      {!dialog && error && (
        <div style={{ marginBottom: 16 }}>
          <FormError message={error} />
        </div>
      )}
      {item ? (
        <CaseDetail ws={ws} item={item} notice={notice} onAction={onAction} />
      ) : (
        <>
          <div className="page-head">
            <div>
              <h1>Offboarding cases</h1>
              <p>
                Each departure gets an owner, a four-hour target, required
                actions across every system and an independent closure.
              </p>
            </div>
          </div>
          <CaseQueue
            ws={ws}
            filter={filter}
            setFilter={setFilter}
            onCreate={() => begin("create")}
          />
        </>
      )}
      <CreateCaseDialog
        open={dialog === "create"}
        onClose={() => setDialog(null)}
        identities={ws.data.identities}
        now={ws.now}
        connected={ws.connected}
        busy={ws.busy}
        error={error}
        submit={(input) =>
          void run({ type: "create", input }, "Departure case opened.")
        }
      />
      {item && (
        <>
          <ImportDialog
            open={dialog === "import"}
            onClose={() => setDialog(null)}
            item={item}
            now={ws.now}
            connected={ws.connected}
            busy={ws.busy}
            error={error}
            setError={setError}
            submit={(report) =>
              void run(
                { type: "import", id: item.id, report },
                "Report assessed. Matched readings are labeled as imported snapshots; unknown readings stay unresolved.",
              )
            }
          />
          <AttestDialog
            open={dialog === "attest"}
            onClose={() => setDialog(null)}
            item={item}
            taskId={taskId}
            principal={ws.principal}
            name={ws.name}
            connected={ws.connected}
            busy={ws.busy}
            error={error}
            submit={(reference, summary) =>
              void run(
                { type: "attest", id: item.id, taskId, reference, summary },
                "Owner statement saved and labeled as an attestation.",
              )
            }
          />
          <CloseDialog
            open={dialog === "close"}
            onClose={() => setDialog(null)}
            item={item}
            principal={ws.principal}
            name={ws.name}
            connected={ws.connected}
            busy={ws.busy}
            error={error}
            submit={() =>
              void run(
                {
                  type: "close",
                  id: item.id,
                  expectedRevision: item.revision,
                  packetHash: item.packetHash,
                },
                "Case closed on reviewed evidence. The packet is now frozen.",
              )
            }
          />
        </>
      )}
    </>
  );
}
