import Link from "next/link";
import type { ReactNode } from "react";

import { CopyPathButton } from "@/components/CopyPathButton";
import type { Dict } from "@/src/dict/types";

const LOGS = String.raw`C:\Windows\System32\winevt\Logs`;

type PathRow = {
  /** Channel / file label. Either a literal (channel names are not
   *  translated) or a key into `dict.fileLocation`. */
  label: string | { key: "allChannels" | "archived" | "legacy" };
  path: string;
  /** Optional OS qualifier shown next to the label. */
  os?: "vistaPlus" | "xp";
};

// Paths are identical on every Windows version since Vista / Server 2008;
// `%4` is how the EventLog service encodes "/" in channel file names.
const PATHS: PathRow[] = [
  { label: { key: "allChannels" }, path: `${LOGS}\\`, os: "vistaPlus" },
  { label: "Security", path: `${LOGS}\\Security.evtx` },
  { label: "System", path: `${LOGS}\\System.evtx` },
  { label: "Application", path: `${LOGS}\\Application.evtx` },
  {
    label: "Sysmon",
    path: `${LOGS}\\Microsoft-Windows-Sysmon%4Operational.evtx`,
  },
  {
    label: "PowerShell (4103/4104)",
    path: `${LOGS}\\Microsoft-Windows-PowerShell%4Operational.evtx`,
  },
  {
    label: "Windows PowerShell (400/600/800)",
    path: `${LOGS}\\Windows PowerShell.evtx`,
  },
  {
    label: "RDP — LocalSessionManager",
    path: `${LOGS}\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`,
  },
  {
    label: "RDP — RemoteConnectionManager",
    path: `${LOGS}\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`,
  },
  {
    label: "Task Scheduler",
    path: `${LOGS}\\Microsoft-Windows-TaskScheduler%4Operational.evtx`,
  },
  {
    label: "Defender",
    path: `${LOGS}\\Microsoft-Windows-Windows Defender%4Operational.evtx`,
  },
  { label: { key: "archived" }, path: `${LOGS}\\Archive-Security-*.evtx` },
  {
    label: { key: "legacy" },
    path: String.raw`C:\Windows\System32\config\SecEvent.Evt`,
    os: "xp",
  },
];

/** Render `backtick` spans as inline code; everything else as text. */
function withCode(text: string): ReactNode[] {
  return text.split("`").map((part, i) =>
    i % 2 === 1 ? (
      <code
        key={i}
        className="break-all rounded bg-ink-100 px-1 py-px font-mono text-[11px] text-ink-800 dark:bg-ink-800 dark:text-ink-200"
      >
        {part}
      </code>
    ) : (
      part
    ),
  );
}

export function EvtxLocations({
  dict,
  locale,
}: {
  dict: Dict;
  locale: string;
}) {
  const t = dict.fileLocation;

  return (
    <section aria-labelledby="evtx-location-heading" className="flex flex-col gap-10">
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)] lg:items-end lg:gap-16">
        <div className="flex flex-col gap-4">
          <span className="eyebrow normal-case tracking-normal">{LOGS}</span>
          <h2
            id="evtx-location-heading"
            className="text-[2rem] leading-[1.05] tracking-[-0.035em] text-balance text-ink-950 sm:text-5xl dark:text-white"
          >
            {t.heading}
          </h2>
        </div>
        <p className="max-w-md text-base leading-relaxed text-ink-600 lg:pb-1.5 dark:text-ink-400">
          {t.intro}
        </p>
      </div>

      <div className="overflow-hidden rounded-2xl border border-ink-200 dark:border-white/[0.08]">
        <div className="hidden grid-cols-[minmax(0,15rem)_minmax(0,1fr)_auto] gap-6 border-b border-ink-200 bg-ink-50 px-5 py-2.5 font-mono text-[11px] tracking-[0.12em] text-ink-500 uppercase md:grid dark:border-white/[0.08] dark:bg-white/[0.02]">
          <span>Channel</span>
          <span>Path</span>
          <span className="sr-only">{t.copy}</span>
        </div>
        <ul>
          {PATHS.map((row) => {
            const label =
              typeof row.label === "string" ? row.label : t[row.label.key];
            const os =
              row.os === "vistaPlus"
                ? t.vistaPlus
                : row.os === "xp"
                  ? "Windows XP / Server 2003"
                  : null;
            return (
              <li
                key={row.path}
                className="group grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1 border-b border-ink-200 px-5 py-3 transition-colors last:border-b-0 hover:bg-ink-50/70 md:grid-cols-[minmax(0,15rem)_minmax(0,1fr)_auto] md:gap-6 dark:border-white/[0.06] dark:hover:bg-white/[0.02]"
              >
                <span className="flex flex-wrap items-center gap-2 text-sm font-medium text-ink-900 dark:text-ink-100">
                  {label}
                  {os && (
                    <span className="rounded-full border border-ink-200 px-1.5 font-mono text-[10px] font-normal text-ink-500 dark:border-white/10">
                      {os}
                    </span>
                  )}
                </span>
                <code className="col-start-1 row-start-2 font-mono text-xs break-all text-ink-600 md:col-start-auto md:row-start-auto dark:text-ink-400">
                  {row.path}
                </code>
                <span className="row-span-2 md:row-span-1">
                  <CopyPathButton
                    value={row.path}
                    label={t.copy}
                    copiedLabel={t.copied}
                  />
                </span>
              </li>
            );
          })}
        </ul>
      </div>

      <div className="flex flex-col gap-5">
        <h3 className="text-lg font-semibold tracking-[-0.015em] text-ink-950 dark:text-white">
          {t.howToHeading}
        </h3>
        <ol className="grid gap-px overflow-hidden rounded-2xl border border-ink-200 bg-ink-200 sm:grid-cols-2 lg:grid-cols-3 dark:border-white/[0.08] dark:bg-white/[0.08]">
          {t.howTo.map((item, i) => (
            <li
              key={i}
              className="flex flex-col gap-3 bg-background p-5 text-sm leading-relaxed text-ink-600 dark:text-ink-400"
            >
              <span className="font-mono text-xs text-uv-600 dark:text-uv-400">
                {String(i + 1).padStart(2, "0")}
              </span>
              <span>{withCode(item)}</span>
            </li>
          ))}
        </ol>
        <Link
          href={`/${locale}/blog/collecting-evtx-from-live-system`}
          className="self-start text-sm font-medium text-ink-950 underline decoration-uv-500 decoration-2 underline-offset-4 hover:text-uv-700 dark:text-white dark:hover:text-uv-300"
        >
          {t.readMore} →
        </Link>
      </div>
    </section>
  );
}
