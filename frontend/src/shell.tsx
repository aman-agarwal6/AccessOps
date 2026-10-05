import {
  BookOpen,
  ChevronRight,
  Code2,
  FlaskConical,
  LogOut,
  Menu,
  Moon,
  RefreshCw,
  RotateCcw,
  ServerCog,
  Sun,
  Terminal,
} from "lucide-react";
import type { Principal } from "./domain";
import { operators } from "./domain";
import { Avatar } from "./ui";
import { navigation, pageInfo, type ModalKind, type Page } from "./workspace";

const groups = ["Offboarding", "Access governance", "Evidence"] as const;

export function Sidebar({
  page,
  open,
  connected,
  counts,
  sourceUrl,
  go,
  openModal,
}: {
  page: Page;
  open: boolean;
  connected: boolean;
  counts: { cases: number; overdue: number; requests: number };
  sourceUrl?: string;
  go: (page: Page) => void;
  openModal: (modal: ModalKind) => void;
}) {
  return (
    <aside
      className={`sidebar ${open ? "open" : ""}`}
      aria-label="Main navigation"
    >
      <a
        href="#/overview"
        className="brand"
        onClick={(event) => {
          event.preventDefault();
          go("overview");
        }}
      >
        <span className="brand-mark" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <path
              d="M12 3 4.5 6v5.5c0 4.6 3.1 8.4 7.5 9.5 4.4-1.1 7.5-4.9 7.5-9.5V6L12 3Z"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinejoin="round"
            />
            <path
              d="m8.8 12.2 2.3 2.3 4.4-4.6"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
        AccessOps
        <small>v0.4</small>
      </a>
      <div className={`mode-card ${connected ? "connected" : ""}`}>
        <strong>
          {connected ? (
            <ServerCog size={16} aria-hidden="true" />
          ) : (
            <FlaskConical size={16} aria-hidden="true" />
          )}
          {connected ? "Connected lab" : "Browser simulation"}
        </strong>
        <span>
          {connected
            ? "Authenticated local services. Actions change real lab state."
            : "Synthetic data in this tab only. No sign-in, live identities or external calls."}
        </span>
      </div>
      <nav aria-label="Sections">
        {groups.map((group) => (
          <div className="nav-group" key={group}>
            <div className="nav-group-label" id={`nav-${group}`}>
              {group}
            </div>
            <ul
              aria-labelledby={`nav-${group}`}
              style={{ display: "grid", gap: 2 }}
            >
              {navigation
                .filter((item) => item.group === group)
                .map((item) => {
                  const count =
                    item.id === "cases"
                      ? counts.cases
                      : item.id === "requests"
                        ? counts.requests
                        : 0;
                  return (
                    <li key={item.id} style={{ listStyle: "none" }}>
                      <a
                        className="nav-link"
                        href={`#/${item.id}`}
                        aria-current={page === item.id ? "page" : undefined}
                        onClick={(event) => {
                          event.preventDefault();
                          go(item.id);
                        }}
                      >
                        <item.icon size={18} aria-hidden="true" />
                        <span>{item.name}</span>
                        {count > 0 && (
                          <span
                            className={`nav-count ${item.id === "cases" && counts.overdue ? "alert" : ""}`}
                            aria-label={
                              item.id === "cases"
                                ? `${count} open, ${counts.overdue} overdue`
                                : `${count} pending`
                            }
                          >
                            {count}
                          </span>
                        )}
                      </a>
                    </li>
                  );
                })}
            </ul>
          </div>
        ))}
      </nav>
      <div className="sidebar-foot">
        <button className="nav-link" onClick={() => openModal("guide")}>
          <BookOpen size={17} aria-hidden="true" />
          How it works
        </button>
        <button className="nav-link" onClick={() => openModal("lab")}>
          <Terminal size={17} aria-hidden="true" />
          {connected ? "About this lab" : "Run it locally"}
        </button>
        {sourceUrl && (
          <a
            className="nav-link"
            href={sourceUrl}
            target="_blank"
            rel="noreferrer"
          >
            <Code2 size={17} aria-hidden="true" />
            Source code
            <span className="sr-only">(opens in a new tab)</span>
          </a>
        )}
      </div>
    </aside>
  );
}

export function Topbar({
  page,
  connected,
  actor,
  principal,
  busy,
  theme,
  navOpen,
  onMenu,
  onActor,
  onTheme,
  onReset,
  onRefresh,
  onSignOut,
}: {
  page: Page;
  connected: boolean;
  actor: Principal;
  principal?: Principal;
  busy: boolean;
  theme: "dark" | "light";
  navOpen: boolean;
  onMenu: () => void;
  onActor: (id: string) => void;
  onTheme: () => void;
  onReset: () => void;
  onRefresh: () => void;
  onSignOut?: () => void;
}) {
  return (
    <header className="topbar">
      <button
        className="icon-btn menu-btn"
        aria-label="Open navigation"
        aria-expanded={navOpen}
        onClick={onMenu}
      >
        <Menu size={20} />
      </button>
      <div className="crumbs">
        <span className="crumb-root">Northstar Systems</span>
        <ChevronRight size={14} aria-hidden="true" className="crumb-root" />
        <strong>{pageInfo(page).name}</strong>
      </div>
      <div className="topbar-actions">
        {!connected ? (
          <label className="acting">
            <span>Acting as</span>
            <select
              aria-label="Acting as (simulated operator)"
              value={actor.id}
              onChange={(event) => onActor(event.target.value)}
            >
              {operators.map((entry) => (
                <option key={entry.id} value={entry.id}>
                  {entry.name} ·{" "}
                  {entry.roles.includes("reviewer")
                    ? "Reviewer"
                    : entry.roles.includes("operator")
                      ? "Operator"
                      : "Sponsor"}
                </option>
              ))}
            </select>
          </label>
        ) : (
          principal && (
            <span className="principal">
              <Avatar name={principal.name} size="sm" />
              <span>
                {principal.name}
                <small>{principal.roles.join(", ")}</small>
              </span>
            </span>
          )
        )}
        <button
          className="icon-btn"
          onClick={onTheme}
          aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
          title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
        >
          {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        {connected ? (
          <>
            <button
              className="icon-btn"
              onClick={onRefresh}
              disabled={busy}
              aria-label="Refresh lab data"
              title="Refresh lab data"
            >
              <RefreshCw size={18} className={busy ? "spin" : ""} />
            </button>
            {onSignOut && (
              <button
                className="icon-btn"
                onClick={onSignOut}
                disabled={busy}
                aria-label="Sign out of the lab"
                title="Sign out"
              >
                <LogOut size={18} />
              </button>
            )}
          </>
        ) : (
          <button
            className="icon-btn"
            onClick={onReset}
            aria-label="Reset the browser simulation"
            title="Reset the simulation"
          >
            <RotateCcw size={18} />
          </button>
        )}
      </div>
    </header>
  );
}
