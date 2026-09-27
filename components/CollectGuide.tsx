"use client";

import Link from "next/link";
import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

import { CopyPathButton } from "@/components/CopyPathButton";
import type { Dict } from "@/src/dict/types";

/*
 * Collection commands — identical in every locale; only the prose around
 * them is translated. Everything here must produce plain .evtx files, since
 * that's all the drop zone accepts (EvtxUploader filters on /\.evtx$/i and
 * doesn't open folders or archives).
 */

// Admin PowerShell: export the high-value channels to C:\triage with the
// built-in wevtutil (the EventLog service's own export, so the file lock is
// not a problem). "/" in a channel name becomes "%4" in the file name, which
// is how Windows itself names the files in winevt\Logs.
const QUICK_PS = String.raw`New-Item -ItemType Directory -Force C:\triage | Out-Null; foreach ($c in 'Security','System','Application','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational') { wevtutil epl $c "C:\triage\$($c -replace '/','%4').evtx" /ow:true }`;

// Admin cmd.exe: one channel, same result.
const QUICK_CMD = String.raw`mkdir C:\triage 2>nul & wevtutil epl Security C:\triage\Security.evtx /ow:true`;

// KAPE EventLogs target (same command as the collection blog post).
const KAPE_CMD = String.raw`kape.exe --tsource C: --target EventLogs --tdest C:\triage`;

// Velociraptor offline collection with the KapeFiles EventLogs target.
const VELO_CMD = String.raw`mkdir C:\triage 2>nul & velociraptor.exe artifacts collect Windows.KapeFiles.Targets --args EventLogs=Y --output C:\triage\evtx.zip`;

// Image already mounted read-only at /mnt/win (Linux/macOS shell).
const MOUNT_CMD = `mkdir -p ~/triage && cp /mnt/win/Windows/System32/winevt/Logs/*.evtx ~/triage/`;

const LOGS_DIR = "C:\\Windows\\System32\\winevt\\Logs\\";

const REDIRECT_CMD = `wevtutil gl Security`;

type TabId = "quick" | "triage" | "image" | "location";
const TABS: TabId[] = ["quick", "triage", "image", "location"];

/** Render `backtick` spans as inline code; everything else as text. */
function withCode(text: string): ReactNode[] {
  return text.split("`").map((part, i) =>
    i % 2 === 1 ? (
      <code
        key={i}
        className="break-words rounded bg-ink-100 px-1 py-px font-mono text-[0.85em] text-ink-800 dark:bg-ink-800 dark:text-ink-200"
      >
        {part}
      </code>
    ) : (
      part
    ),
  );
}

function CommandBlock({
  label,
  shell,
  command,
  note,
  t,
}: {
  label: string;
  shell: string;
  command: string;
  note?: string;
  t: Dict["collect"];
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <p className="text-sm font-medium text-ink-900 dark:text-ink-100">{label}</p>
      <div className="min-w-0 overflow-hidden rounded-lg border border-ink-200 bg-ink-50/80 dark:border-ink-800 dark:bg-ink-950/70">
        <div className="flex items-center justify-between gap-2 border-b border-ink-200 py-1 pr-1 pl-3 dark:border-ink-800">
          <span className="font-mono text-[11px] tracking-wide text-ink-500 uppercase">
            {shell}
          </span>
          <CopyPathButton
            value={command}
            label={`${t.copyCommand}: ${label}`}
            copiedLabel={t.copied}
            text={t.copy}
          />
        </div>
        <pre className="overflow-x-auto px-3 py-2.5 font-mono text-xs leading-relaxed text-ink-900 dark:text-ink-100">
          <code>{command}</code>
        </pre>
      </div>
      {note && (
        <p className="text-xs leading-relaxed text-ink-600 dark:text-ink-400">
          {withCode(note)}
        </p>
      )}
    </div>
  );
}

function Prereq({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-start gap-2 rounded-lg border border-glow-400/40 bg-glow-400/10 px-3 py-2 text-xs leading-relaxed text-ink-700 dark:text-ink-300">
      <span aria-hidden="true" className="font-mono text-glow-700 dark:text-glow-300">
        !
      </span>
      <span>{children}</span>
    </p>
  );
}

/**
 * "How to get your .evtx files": a step strip, method tabs ordered easiest
 * first, and the pitfalls that actually bite. Rendered under the drop zone
 * (anchor #collect) and, `compact`, inside the workspace's help dialog.
 */
export function CollectGuide({
  dict,
  locale,
  compact = false,
}: {
  dict: Dict;
  locale: string;
  /** Dialog variant: no anchor id, no heading/step strip, no in-page links. */
  compact?: boolean;
}) {
  const t = dict.collect;
  const baseId = useId();
  const [active, setActive] = useState<TabId>("quick");
  const tabRefs = useRef<Record<TabId, HTMLButtonElement | null>>({
    quick: null,
    triage: null,
    image: null,
    location: null,
  });

  const labels: Record<TabId, string> = {
    quick: t.tabQuick,
    triage: t.tabTriage,
    image: t.tabImage,
    location: t.tabLocation,
  };

  // WAI-ARIA tabs: arrows move and activate, Home/End jump to the ends.
  const onTabKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    const i = TABS.indexOf(active);
    let next: number | null = null;
    if (e.key === "ArrowRight") next = (i + 1) % TABS.length;
    else if (e.key === "ArrowLeft") next = (i - 1 + TABS.length) % TABS.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = TABS.length - 1;
    if (next == null) return;
    e.preventDefault();
    const id = TABS[next];
    setActive(id);
    tabRefs.current[id]?.focus();
  };

  const tabId = (id: TabId) => `${baseId}-tab-${id}`;
  const panelId = (id: TabId) => `${baseId}-panel-${id}`;

  const panels: Record<TabId, ReactNode> = {
    quick: (
      <>
        <Prereq>{withCode(t.quickPrereq)}</Prereq>
        <CommandBlock
          label={t.quickPsLabel}
          shell="PowerShell (Admin)"
          command={QUICK_PS}
          note={t.quickPsNote}
          t={t}
        />
        <CommandBlock
          label={t.quickCmdLabel}
          shell="cmd (Admin)"
          command={QUICK_CMD}
          t={t}
        />
        <div className="flex flex-col gap-1">
          <p className="text-sm font-medium text-ink-900 dark:text-ink-100">
            {t.quickGuiLabel}
          </p>
          <p className="text-xs leading-relaxed text-ink-600 dark:text-ink-400">
            {withCode(t.quickGui)}
          </p>
        </div>
      </>
    ),
    triage: (
      <>
        <Prereq>{withCode(t.triagePrereq)}</Prereq>
        <CommandBlock
          label={t.kapeLabel}
          shell="cmd (Admin)"
          command={KAPE_CMD}
          note={t.kapeNote}
          t={t}
        />
        <CommandBlock
          label={t.veloLabel}
          shell="cmd (Admin)"
          command={VELO_CMD}
          note={t.veloNote}
          t={t}
        />
      </>
    ),
    image: (
      <>
        <p className="text-xs leading-relaxed text-ink-600 dark:text-ink-400">
          {withCode(t.imageIntro)}
        </p>
        <div className="flex flex-col gap-1">
          <p className="text-sm font-medium text-ink-900 dark:text-ink-100">
            {t.ftkLabel}
          </p>
          <p className="text-xs leading-relaxed text-ink-600 dark:text-ink-400">
            {withCode(t.ftkSteps)}
          </p>
        </div>
        <CommandBlock
          label={t.mountLabel}
          shell="bash / zsh"
          command={MOUNT_CMD}
          note={t.mountNote}
          t={t}
        />
      </>
    ),
    location: (
      <>
        <p className="text-xs leading-relaxed text-ink-600 dark:text-ink-400">
          {withCode(t.locationIntro)}
        </p>
        <div className="flex min-w-0 items-start gap-2 rounded-lg border border-ink-200 bg-ink-50/80 px-3 py-2 dark:border-ink-800 dark:bg-ink-950/70">
          <code className="min-w-0 flex-1 font-mono text-xs break-all text-ink-900 dark:text-ink-100">
            {LOGS_DIR}
          </code>
          <CopyPathButton
            value={LOGS_DIR}
            label={dict.fileLocation.copy}
            copiedLabel={t.copied}
          />
        </div>
        <ul className="flex list-disc flex-col gap-1.5 pl-4 text-xs leading-relaxed text-ink-600 marker:text-uv-500 dark:text-ink-400">
          <li>{withCode(t.locationFiles)}</li>
          <li>{withCode(t.locationArchive)}</li>
        </ul>
        <CommandBlock
          label={t.locationRedirect}
          shell="cmd / PowerShell"
          command={REDIRECT_CMD}
          t={t}
        />
        {!compact && (
          <a
            href="#evtx-location-heading"
            className="self-start text-xs font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700"
          >
            {t.allPaths} ↓
          </a>
        )}
      </>
    ),
  };

  return (
    <section
      id={compact ? undefined : "collect"}
      aria-labelledby={compact ? undefined : `${baseId}-heading`}
      className={
        compact
          ? "flex min-w-0 flex-col gap-4"
          : "surface flex min-w-0 scroll-mt-24 flex-col gap-4 p-4 sm:p-6"
      }
    >
      {/* In the dialog the DialogTitle already names the guide. */}
      {!compact && (
        <div className="flex flex-col gap-1">
          <h2
            id={`${baseId}-heading`}
            className="text-lg text-ink-950 sm:text-xl dark:text-ink-50"
          >
            {t.heading}
          </h2>
          <p className="text-sm text-ink-600 dark:text-ink-400">{t.intro}</p>
        </div>
      )}

      {!compact && (
        <ol className="grid gap-2 sm:grid-cols-3">
          {t.steps.map((step, i) => (
            <li
              key={i}
              className="flex items-center gap-2.5 rounded-lg border border-ink-200/80 bg-ink-50/60 px-3 py-2 text-sm text-ink-800 dark:border-ink-800 dark:bg-ink-950/60 dark:text-ink-200"
            >
              <span
                aria-hidden="true"
                className="flex size-6 shrink-0 items-center justify-center rounded-full bg-uv-600 font-mono text-xs font-semibold text-white dark:bg-uv-500"
              >
                {i + 1}
              </span>
              <span className="min-w-0">{step}</span>
            </li>
          ))}
        </ol>
      )}

      <div className="flex min-w-0 flex-col gap-4">
        <div
          role="tablist"
          aria-label={t.tabsLabel}
          className="flex max-w-full gap-1 overflow-x-auto rounded-lg border border-ink-200 p-0.5 text-xs sm:w-fit sm:text-sm dark:border-ink-800"
        >
          {TABS.map((id) => {
            const selected = active === id;
            return (
              <button
                key={id}
                ref={(el) => {
                  tabRefs.current[id] = el;
                }}
                id={tabId(id)}
                type="button"
                role="tab"
                aria-selected={selected}
                aria-controls={panelId(id)}
                tabIndex={selected ? 0 : -1}
                onClick={() => setActive(id)}
                onKeyDown={onTabKey}
                className={`inline-flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 whitespace-nowrap transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-uv-500 motion-reduce:transition-none ${
                  selected
                    ? "bg-ink-900 text-ink-50 dark:bg-ink-100 dark:text-ink-900"
                    : "text-ink-600 hover:bg-ink-100 dark:text-ink-300 dark:hover:bg-ink-900"
                }`}
              >
                {labels[id]}
                {id === "quick" && (
                  <span
                    className={`rounded px-1 text-[10px] font-semibold uppercase ${
                      selected
                        ? "bg-glow-400/30 text-glow-200 dark:text-glow-800"
                        : "bg-glow-400/20 text-glow-800 dark:text-glow-300"
                    }`}
                  >
                    {t.recommended}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* All panels are server-rendered (hidden ones too) so the commands
            are in the HTML for search engines and no-JS readers. */}
        {TABS.map((id) => (
          <div
            key={id}
            id={panelId(id)}
            role="tabpanel"
            aria-labelledby={tabId(id)}
            tabIndex={0}
            hidden={active !== id}
            className="flex min-w-0 flex-col gap-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-uv-500 focus-visible:ring-offset-2 rounded-md"
          >
            {panels[id]}
          </div>
        ))}
      </div>

      <div className="flex flex-col gap-1.5 border-t border-ink-200 pt-3 dark:border-ink-800">
        <h3 className="font-mono text-xs font-semibold tracking-wide text-ink-700 uppercase dark:text-ink-300">
          {t.gotchasHeading}
        </h3>
        <ul className="flex list-disc flex-col gap-1 pl-4 text-xs leading-relaxed text-ink-600 marker:text-uv-500 dark:text-ink-400">
          {t.gotchas.map((g, i) => (
            <li key={i}>{withCode(g)}</li>
          ))}
        </ul>
        {!compact && (
          <Link
            href={`/${locale}/blog/collecting-evtx-from-live-system`}
            className="self-start text-xs text-ink-600 underline-offset-2 hover:text-ink-900 hover:underline dark:text-ink-400 dark:hover:text-ink-100"
          >
            {dict.fileLocation.readMore} →
          </Link>
        )}
      </div>
    </section>
  );
}
