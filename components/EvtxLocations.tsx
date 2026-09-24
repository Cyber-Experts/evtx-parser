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
        className="break-all rounded bg-zinc-100 px-1 py-px font-mono text-[11px] text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200"
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
    <section
      aria-labelledby="evtx-location-heading"
      className="flex flex-col gap-3 rounded-lg border border-zinc-200 bg-zinc-50/60 p-4 dark:border-zinc-800 dark:bg-zinc-900/40"
    >
      <div className="flex flex-col gap-1">
        <h2
          id="evtx-location-heading"
          className="font-mono text-base font-semibold text-zinc-900 dark:text-zinc-100"
        >
          {t.heading}
        </h2>
        <p className="text-xs text-zinc-600 dark:text-zinc-400">{t.intro}</p>
      </div>

      <ul className="grid gap-1.5 lg:grid-cols-2">
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
              className="flex min-w-0 items-start gap-2 rounded border border-zinc-200 bg-white px-2.5 py-1.5 dark:border-zinc-800 dark:bg-zinc-950"
            >
              <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                <span className="text-[11px] text-zinc-500">
                  {label}
                  {os && (
                    <span className="ml-1.5 rounded border border-zinc-200 px-1 font-mono text-[10px] text-zinc-500 dark:border-zinc-700">
                      {os}
                    </span>
                  )}
                </span>
                <code className="break-all font-mono text-xs text-zinc-900 dark:text-zinc-100">
                  {row.path}
                </code>
              </div>
              <CopyPathButton
                value={row.path}
                label={t.copy}
                copiedLabel={t.copied}
              />
            </li>
          );
        })}
      </ul>

      <div className="flex flex-col gap-1.5 border-t border-zinc-200 pt-3 dark:border-zinc-800">
        <h3 className="font-mono text-xs font-semibold uppercase tracking-wide text-zinc-700 dark:text-zinc-300">
          {t.howToHeading}
        </h3>
        <ul className="flex list-disc flex-col gap-1 pl-4 text-xs leading-relaxed text-zinc-600 marker:text-amber-500 dark:text-zinc-400">
          {t.howTo.map((item, i) => (
            <li key={i}>{withCode(item)}</li>
          ))}
        </ul>
        <Link
          href={`/${locale}/blog/collecting-evtx-from-live-system`}
          className="self-start text-xs text-zinc-600 underline-offset-2 hover:text-zinc-900 hover:underline dark:text-zinc-400 dark:hover:text-zinc-100"
        >
          {t.readMore} →
        </Link>
      </div>
    </section>
  );
}
