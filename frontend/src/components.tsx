import { useRef, type ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowUpRight,
  Bot,
  Check,
  Circle,
  CircleAlert,
  Clock3,
  FileCheck2,
  UserRound,
  X,
} from "lucide-react";
import type { Identity } from "./domain";

export function Badge({
  value,
  children,
}: {
  value: string;
  children?: ReactNode;
}) {
  const tone = [
    "active",
    "verified",
    "passed",
    "healthy",
    "allowed",
    "complete",
  ].includes(value)
    ? "green"
    : [
          "failed",
          "offboarded",
          "denied",
          "high",
          "unavailable",
          "blocked",
        ].includes(value)
      ? "red"
      : [
            "pending",
            "approved",
            "applied",
            "suspended",
            "expired",
            "medium",
            "in_review",
          ].includes(value)
        ? "amber"
        : "neutral";
  return (
    <span className={`badge ${tone}`}>
      <span className="badge-dot" />
      {children ?? value.replaceAll("_", " ")}
    </span>
  );
}
export function Avatar({
  identity,
  small = false,
}: {
  identity?: Identity;
  small?: boolean;
}) {
  return (
    <span
      className={`avatar ${identity?.kind === "agent" ? "agent" : ""} ${small ? "small" : ""}`}
      aria-hidden="true"
    >
      {identity?.kind === "agent" ? (
        <Bot size={small ? 16 : 20} />
      ) : (
        (identity?.name
          .split(" ")
          .map((n) => n[0])
          .slice(0, 2)
          .join("") ?? <UserRound size={18} />)
      )}
    </span>
  );
}
export function Empty({
  title,
  children,
  action,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <FileCheck2 size={25} />
      </span>
      <h3>{title}</h3>
      <p>{children}</p>
      {action}
    </div>
  );
}
export function Panel({
  title,
  subtitle,
  action,
  children,
  className = "",
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
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
  const opener = useRef<HTMLElement | null>(null);
  return (
    <Dialog.Root
      open={open}
      modal={modal}
      onOpenChange={(o) => !o && onClose()}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content
          className={`drawer ${wide ? "wide" : ""}`}
          onOpenAutoFocus={() => {
            opener.current = document.activeElement as HTMLElement;
          }}
          onCloseAutoFocus={(e) => {
            if (opener.current?.isConnected) {
              e.preventDefault();
              opener.current.focus();
            }
          }}
          onInteractOutside={(e) => {
            if (!modal) e.preventDefault();
          }}
        >
          <div className="drawer-heading">
            <div>
              <Dialog.Title>{title}</Dialog.Title>
              <Dialog.Description>{description}</Dialog.Description>
            </div>
            <Dialog.Close className="icon-button" aria-label="Close details">
              <X size={20} />
            </Dialog.Close>
          </div>
          <div className="drawer-body">{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
export function Modal({
  title,
  description,
  open,
  onClose,
  children,
}: {
  title: string;
  description: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  const opener = useRef<HTMLElement | null>(null);
  return (
    <Dialog.Root open={open} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content
          className="modal"
          onOpenAutoFocus={() => {
            opener.current = document.activeElement as HTMLElement;
          }}
          onCloseAutoFocus={(e) => {
            if (opener.current?.isConnected) {
              e.preventDefault();
              opener.current.focus();
            }
          }}
        >
          <div className="drawer-heading">
            <div>
              <Dialog.Title>{title}</Dialog.Title>
              <Dialog.Description>{description}</Dialog.Description>
            </div>
            <Dialog.Close className="icon-button" aria-label="Close dialog">
              <X size={20} />
            </Dialog.Close>
          </div>
          <div className="drawer-body">{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
export function StateIcon({ status }: { status: string }) {
  return ["passed", "complete", "verified"].includes(status) ? (
    <Check size={16} />
  ) : ["failed", "blocked", "denied"].includes(status) ? (
    <CircleAlert size={16} />
  ) : ["pending", "approved"].includes(status) ? (
    <Clock3 size={16} />
  ) : (
    <Circle size={16} />
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
    <a className="text-link" href={href} target="_blank" rel="noreferrer">
      {children}
      <ArrowUpRight size={14} aria-hidden="true" />
    </a>
  );
}
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
  return minutes < 1
    ? "Just now"
    : minutes < 60
      ? `${minutes}m ago`
      : `${Math.floor(minutes / 60)}h ago`;
}
