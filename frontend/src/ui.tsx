import { useRef, type ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowUpRight,
  BadgeCheck,
  Bot,
  Check,
  Circle,
  CircleAlert,
  CircleDashed,
  Clock3,
  FileInput,
  FlaskConical,
  Inbox,
  PenLine,
  Radar,
  Search,
  UserRound,
  X,
} from "lucide-react";
import type { Identity } from "./domain";

/* ---------- Status ---------- */
const tones: Record<string, "ok" | "warn" | "danger" | "info" | "accent"> = {
  active: "ok",
  verified: "ok",
  passed: "ok",
  healthy: "ok",
  allowed: "ok",
  complete: "ok",
  closed: "ok",
  observed: "ok",
  failed: "danger",
  offboarded: "danger",
  denied: "danger",
  high: "danger",
  unavailable: "danger",
  blocked: "warn",
  pending: "warn",
  approved: "info",
  applied: "info",
  in_progress: "info",
  in_review: "info",
  suspended: "warn",
  expired: "warn",
  medium: "warn",
  open: "accent",
  scheduled: "accent",
};
const statusLabels: Record<string, string> = {
  in_progress: "In progress",
  in_review: "In review",
  blocked: "Needs evidence",
};
const sentence = (value: string) =>
  value.charAt(0).toUpperCase() + value.slice(1).replaceAll("_", " ");
export function Status({
  value,
  children,
}: {
  value: string;
  children?: ReactNode;
}) {
  return (
    <span className={`pill ${tones[value] ?? ""}`}>
      {children ?? statusLabels[value] ?? sentence(value)}
    </span>
  );
}

/* ---------- Evidence provenance ---------- */
export type ProvenanceKind =
  "signed" | "observed" | "imported" | "attested" | "simulated" | "pending";
export const provenance: Record<
  ProvenanceKind,
  { label: string; icon: typeof Radar; meaning: string }
> = {
  signed: {
    label: "Signed CI evidence",
    icon: BadgeCheck,
    meaning:
      "Release bytes bound to the public workflow and source commit by a Sigstore attestation.",
  },
  observed: {
    label: "Provider observation",
    icon: Radar,
    meaning:
      "Read back from the connected lab's real Keycloak or directory after the change.",
  },
  imported: {
    label: "Imported snapshot",
    icon: FileInput,
    meaning:
      "A bounded report someone supplied. Point-in-time and untrusted, not live verification.",
  },
  attested: {
    label: "Owner attestation",
    icon: PenLine,
    meaning:
      "A written statement by the case owner. Reviewed at closure, never treated as proof.",
  },
  simulated: {
    label: "Simulated",
    icon: FlaskConical,
    meaning:
      "Produced by this browser model. Nothing outside the tab was contacted.",
  },
  pending: {
    label: "No evidence yet",
    icon: CircleDashed,
    meaning: "The action is unresolved and blocks closure.",
  },
};
export function Provenance({
  kind,
  label,
}: {
  kind: ProvenanceKind;
  label?: string;
}) {
  const { icon: Icon, label: fallback } = provenance[kind];
  return (
    <span className={`prov prov-${kind}`}>
      <Icon size={14} aria-hidden="true" />
      {label ?? fallback}
    </span>
  );
}

/* ---------- Identity ---------- */
export function initials(name?: string) {
  return (name ?? "")
    .split(" ")
    .map((part) => part[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase();
}
export function Avatar({
  identity,
  name,
  size,
}: {
  identity?: Identity;
  name?: string;
  size?: "sm" | "lg";
}) {
  const agent = identity?.kind === "agent";
  const text = initials(identity?.name ?? name);
  return (
    <span
      className={`avatar ${agent ? "agent" : ""} ${size ?? ""}`}
      aria-hidden="true"
    >
      {agent ? (
        <Bot size={size === "sm" ? 16 : 20} />
      ) : (
        text || <UserRound size={18} />
      )}
    </span>
  );
}
export function Who({
  identity,
  fallback,
  detail,
}: {
  identity?: Identity;
  fallback?: string;
  detail?: ReactNode;
}) {
  return (
    <span className="who">
      <Avatar identity={identity} name={fallback} size="sm" />
      <span>
        <strong>{identity?.name ?? fallback ?? "Unknown identity"}</strong>
        <small>
          {detail ??
            `${identity?.kind === "agent" ? "Agent · " : ""}${identity?.role ?? ""}`}
        </small>
      </span>
    </span>
  );
}

/* ---------- Containers ---------- */
export function Panel({
  title,
  description,
  action,
  children,
  flush = false,
  className = "",
  id,
}: {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  className?: string;
  id?: string;
}) {
  return (
    <section className={`panel ${className}`} aria-labelledby={id}>
      <header className="panel-head">
        <div>
          <h2 id={id}>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        {action}
      </header>
      <div className={`panel-body ${flush ? "flush" : ""}`}>{children}</div>
    </section>
  );
}
export function Empty({
  title,
  children,
  action,
  icon,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className="empty">
      <span className="empty-icon" aria-hidden="true">
        {icon ?? <Inbox size={24} />}
      </span>
      <h3>{title}</h3>
      <p>{children}</p>
      {action}
    </div>
  );
}
export function Callout({
  tone = "neutral",
  icon,
  children,
  action,
  role,
}: {
  tone?: "neutral" | "info" | "warn" | "danger" | "ok";
  icon?: ReactNode;
  children: ReactNode;
  action?: ReactNode;
  role?: "alert" | "status";
}) {
  return (
    <div className={`callout ${tone}`} role={role}>
      {icon ?? <CircleAlert size={18} aria-hidden="true" />}
      <div>{children}</div>
      {action && <div className="callout-action">{action}</div>}
    </div>
  );
}
export function FormError({ message }: { message?: string }) {
  if (!message) return null;
  return (
    <p className="form-error" role="alert">
      <CircleAlert size={16} aria-hidden="true" />
      <span>{message}</span>
    </p>
  );
}

/* ---------- Dialogs ---------- */
function useReturnFocus() {
  const opener = useRef<HTMLElement | null>(null);
  return {
    onOpenAutoFocus: () => {
      opener.current = document.activeElement as HTMLElement;
    },
    onCloseAutoFocus: (event: Event) => {
      if (opener.current?.isConnected) {
        event.preventDefault();
        opener.current.focus();
      }
    },
  };
}
export function Modal({
  title,
  description,
  open,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  description: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const focus = useReturnFocus();
  return (
    <Dialog.Root open={open} onOpenChange={(next) => !next && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className={`dialog ${wide ? "wide" : ""}`} {...focus}>
          <div className="dialog-head">
            <div>
              <Dialog.Title>{title}</Dialog.Title>
              <Dialog.Description>{description}</Dialog.Description>
            </div>
            <Dialog.Close className="icon-btn" aria-label="Close dialog">
              <X size={20} />
            </Dialog.Close>
          </div>
          <div className="dialog-body">{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
export function Drawer({
  title,
  description,
  open,
  onClose,
  children,
  wide = false,
  modal = true,
}: {
  title: string;
  description: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
  modal?: boolean;
}) {
  const focus = useReturnFocus();
  return (
    <Dialog.Root
      open={open}
      modal={modal}
      onOpenChange={(next) => !next && onClose()}
    >
      <Dialog.Portal>
        {modal && <Dialog.Overlay className="overlay" />}
        <Dialog.Content
          className={`drawer ${wide ? "wide" : ""}`}
          {...focus}
          onInteractOutside={(event) => {
            if (!modal) event.preventDefault();
          }}
        >
          <div className="dialog-head">
            <div>
              <Dialog.Title>{title}</Dialog.Title>
              <Dialog.Description>{description}</Dialog.Description>
            </div>
            <Dialog.Close className="icon-btn" aria-label="Close details">
              <X size={20} />
            </Dialog.Close>
          </div>
          <div className="dialog-body">{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/* ---------- Inputs ---------- */
export function SearchField({
  value,
  onChange,
  label,
}: {
  value: string;
  onChange: (value: string) => void;
  label: string;
}) {
  return (
    <label className="search">
      <Search size={16} aria-hidden="true" />
      <input
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={label}
        aria-label={label}
      />
      {value && (
        <button
          type="button"
          className="icon-btn"
          onClick={() => onChange("")}
          aria-label="Clear search"
        >
          <X size={14} />
        </button>
      )}
    </label>
  );
}
export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: { value: T; label: string; count?: number }[];
  onChange: (value: T) => void;
}) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
          {option.count !== undefined && (
            <span className="count">{option.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

/* ---------- Misc ---------- */
export function StateIcon({ status }: { status: string }) {
  return ["passed", "complete", "verified", "allowed"].includes(status) ? (
    <Check size={16} aria-hidden="true" />
  ) : ["failed", "blocked", "denied"].includes(status) ? (
    <CircleAlert size={16} aria-hidden="true" />
  ) : ["pending", "approved"].includes(status) ? (
    <Clock3 size={16} aria-hidden="true" />
  ) : (
    <Circle size={16} aria-hidden="true" />
  );
}
export function External({
  href,
  children,
}: {
  href: string;
  children: ReactNode;
}) {
  return (
    <a className="link-btn" href={href} target="_blank" rel="noreferrer">
      {children}
      <ArrowUpRight size={14} aria-hidden="true" />
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  );
}
export function Ring({
  value,
  total,
  label,
}: {
  value: number;
  total: number;
  label: string;
}) {
  const percent = total ? Math.round((value / total) * 100) : 0;
  return (
    <span
      className={`ring ${percent === 100 ? "ok" : ""}`}
      style={{ ["--value" as string]: percent }}
      role="img"
      aria-label={label}
    >
      <span>
        {value}/{total}
      </span>
    </span>
  );
}

/* ---------- Time ---------- */
export function formatDate(value?: string | null) {
  if (!value) return "No expiry";
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? "Unknown date"
    : new Intl.DateTimeFormat("en", {
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
        timeZone: "UTC",
      }).format(date) + " UTC";
}
export function timeAgo(value: string, now: number) {
  const minutes = Math.max(0, Math.floor((now - Date.parse(value)) / 60000));
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 48 * 60) return `${Math.floor(minutes / 60)}h ago`;
  return `${Math.floor(minutes / 1440)}d ago`;
}
export function duration(ms: number) {
  const minutes = Math.max(0, Math.round(Math.abs(ms) / 60000));
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ${String(minutes % 60).padStart(2, "0")}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}
