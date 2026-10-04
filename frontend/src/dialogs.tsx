import {
  ArrowRight,
  FlaskConical,
  LogOut,
  RotateCcw,
  ServerCog,
  X,
} from "lucide-react";
import { External, Modal } from "./ui";
import type { Page } from "./workspace";

export function LabDialog({
  open,
  onClose,
  connected,
  sourceUrl,
  busy,
  onSignOut,
}: {
  open: boolean;
  onClose: () => void;
  connected: boolean;
  sourceUrl?: string;
  busy: boolean;
  onSignOut?: () => void;
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={connected ? "About this lab" : "Run AccessOps locally"}
      description="Explore without setup here. Reproduce real operations in your own isolated lab."
    >
      <div className="mode-compare">
        <article>
          <FlaskConical size={22} aria-hidden="true" />
          <div>
            <h3>Browser simulation{connected ? "" : " · you are here"}</h3>
            <p>
              Fictional identities and an in-memory provider model. No sign-in,
              paid API, live connection or language model. Refreshing resets it.
            </p>
          </div>
        </article>
        <article>
          <ServerCog size={22} aria-hidden="true" />
          <div>
            <h3>Authenticated local lab{connected ? " · you are here" : ""}</h3>
            <p>
              Django, PostgreSQL, Keycloak, OPA and an optional Samba directory
              on loopback. The server validates identity, policy and every
              connector effect; tokens never reach the browser.
            </p>
          </div>
        </article>
      </div>
      <div className="detail-section">
        <h3>Local setup</h3>
        <ol className="steps">
          <li>
            Read the setup guide; it generates local secrets and certificates.
          </li>
          <li>
            Start the isolated services, then open the local HTTPS address.
          </li>
          <li>Sign in as a lab operator and work a departure case.</li>
          <li>
            Run the acceptance scripts; their sanitized reports feed this
            viewer.
          </li>
        </ol>
      </div>
      <div className="row">
        {sourceUrl && (
          <External href={`${sourceUrl}#readme`}>
            Setup guide on GitHub
          </External>
        )}
        {connected && onSignOut && (
          <button
            className="btn btn-secondary"
            onClick={onSignOut}
            disabled={busy}
          >
            <LogOut size={15} aria-hidden="true" />
            Sign out of the lab
          </button>
        )}
      </div>
    </Modal>
  );
}

export function GuideDialog({
  open,
  onClose,
  go,
  sourceUrl,
}: {
  open: boolean;
  onClose: () => void;
  go: (page: Page) => void;
  sourceUrl?: string;
}) {
  const steps: { page: Page; title: string; text: string; link: string }[] = [
    {
      page: "cases",
      title: "Work a departure",
      text: "An HR event opens a case with an owner and a four-hour target. Contain access, import platform evidence, record owner statements, then have someone else close it.",
      link: "Open offboarding cases",
    },
    {
      page: "requests",
      title: "Follow one exact change",
      text: "Grants need an independent approver bound to the exact change, policy version and a 15-minute window. Containment acts immediately.",
      link: "Open requests",
    },
    {
      page: "reviews",
      title: "Watch the boundaries hold",
      text: "Denials happen before any effect, a policy outage fails closed, and provider drift is flagged, never adopted. The assistant can only propose.",
      link: "Open access reviews",
    },
    {
      page: "runs",
      title: "Check what actually ran",
      text: "Recorded lab runs, failed attempts included, sit apart from browser checks and from signed release evidence.",
      link: "Open runs & evidence",
    },
  ];
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="How AccessOps works"
      description="Four stops, about ten minutes, from a departure to the evidence behind it."
    >
      <ol className="route">
        {steps.map((step, index) => (
          <li key={step.page}>
            <span aria-hidden="true">{index + 1}</span>
            <div>
              <h3>{step.title}</h3>
              <p>{step.text}</p>
              <button
                className="link-btn"
                onClick={() => {
                  onClose();
                  go(step.page);
                }}
              >
                {step.link}
                <ArrowRight size={14} aria-hidden="true" />
              </button>
            </div>
          </li>
        ))}
      </ol>
      {sourceUrl && <External href={sourceUrl}>Browse the source</External>}
    </Modal>
  );
}

export function ResetDialog({
  open,
  onClose,
  onReset,
}: {
  open: boolean;
  onClose: () => void;
  onReset: () => void;
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Reset the simulation?"
      description="This clears only the synthetic changes and checks in this tab."
    >
      <p className="text-2">
        The starting Northstar workspace and departure queue come back. Recorded
        lab evidence is not affected.
      </p>
      <div className="dialog-actions">
        <button className="btn btn-ghost" onClick={onClose}>
          Keep exploring
        </button>
        <button className="btn btn-primary" onClick={onReset}>
          <RotateCcw size={15} aria-hidden="true" />
          Reset simulation
        </button>
      </div>
    </Modal>
  );
}

const coachSteps = [
  {
    title: "Start with working access",
    text: "Mara and the Atlas digest agent can read the knowledge base today. Confirm that baseline first.",
    button: "Check existing access",
  },
  {
    title: "See the full blast radius",
    text: "Mara sponsors Atlas digest, so her departure covers both identities and three active grants.",
    button: "Confirm affected scope",
  },
  {
    title: "Remove access without waiting",
    text: "Jules is an authorized operator. Containment suspends the agent and revokes grants now; it does not wait for a second approval.",
    button: "Apply containment",
  },
  {
    title: "Observe the provider",
    text: "Authorization changed. Now compare the simulated provider state; an acknowledgment alone is not verification.",
    button: "Check simulated provider",
  },
  {
    title: "Retry the same reads",
    text: "Same people, same resource. Both reads should be denied with zero resource effects.",
    button: "Retry both reads",
  },
  {
    title: "Keep demo and proof apart",
    text: "Inspect the browser checks, then compare them with the separately recorded lab runs.",
    button: "Inspect the evidence",
  },
];
export function Coach({
  step,
  onNext,
  onClose,
}: {
  step: number;
  onNext: () => void;
  onClose: () => void;
}) {
  const current = coachSteps[step];
  return (
    <section className="coach" role="region" aria-label="Guided scenario">
      <div className="coach-top">
        <span className="eyebrow">
          Containment walkthrough · {step + 1} of {coachSteps.length}
        </span>
        <button
          className="icon-btn"
          aria-label="Close walkthrough"
          onClick={onClose}
        >
          <X size={16} />
        </button>
      </div>
      <div className="coach-steps" aria-hidden="true">
        {coachSteps.map((_, index) => (
          <span key={index} className={index <= step ? "on" : ""} />
        ))}
      </div>
      <h3>{current.title}</h3>
      <p>{current.text}</p>
      <button className="btn btn-primary" onClick={onNext}>
        {current.button}
        <ArrowRight size={15} aria-hidden="true" />
      </button>
    </section>
  );
}
