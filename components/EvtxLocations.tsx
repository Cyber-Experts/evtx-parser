import Link from "next/link";
import type { ReactNode } from "react";
import { FileText, FolderOpen } from "lucide-react";

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
    <section
      aria-labelledby="evtx-location-heading"
      className="grid gap-10 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.8fr)] lg:gap-16"
    >
      <div className="flex flex-col gap-4 lg:sticky lg:top-24 lg:self-start">
        <span className="eyebrow normal-case">C:\Windows\…\Logs</span>
        <h2
          id="evtx-location-heading"
          className="text-3xl leading-[1.05] tracking-[-0.04em] text-balance text-ink-950 sm:text-4xl dark:text-ink-50"
        >
          {t.heading}
        </h2>
        <p className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">{t.intro}</p>
        <div className="mt-2 flex flex-col gap-2 border-t border-ink-200/70 pt-5 dark:border-white/[0.07]">
          <h3 className="font-mono text-[11px] font-medium tracking-[0.12em] text-ink-500 uppercase">
            {t.howToHeading}
          </h3>
          <ul className="flex flex-col gap-2 text-xs leading-relaxed text-ink-600 dark:text-ink-400">
            {t.howTo.map((item, i) => (
              <li key={i} className="flex gap-2">
                <span aria-hidden="true" className="mt-1.5 size-1 shrink-0 rounded-full bg-uv-500" />
                <span className="min-w-0 [overflow-wrap:anywhere]">{withCode(item)}</span>
              </li>
            ))}
          </ul>
          <Link
            href={`/${locale}/blog/collecting-evtx-from-live-system`}
            className="mt-1 self-start text-sm font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700"
          >
            {t.readMore} →
          </Link>
        </div>
      </div>

      {/* File-explorer panel */}
      <div className="surface overflow-hidden">
        <div className="flex items-center gap-3 border-b border-ink-200/80 bg-ink-50/70 px-4 py-2.5 dark:border-white/[0.07] dark:bg-white/[0.02]">
          <span aria-hidden="true" className="flex gap-1.5">
            <span className="size-2.5 rounded-full bg-ink-200 dark:bg-white/15" />
            <span className="size-2.5 rounded-full bg-ink-200 dark:bg-white/15" />
            <span className="size-2.5 rounded-full bg-ink-200 dark:bg-white/15" />
          </span>
          <FolderOpen aria-hidden="true" className="size-4 text-uv-600 dark:text-uv-300" />
          <code className="min-w-0 truncate font-mono text-xs text-ink-700 dark:text-ink-300">
            {LOGS}
          </code>
        </div>
        <ul className="divide-y divide-ink-100 dark:divide-white/[0.05]">
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
                className="group flex min-w-0 items-center gap-3 px-4 py-2.5 transition-colors hover:bg-uv-50/50 dark:hover:bg-uv-400/[0.04]"
              >
                <FileText
                  aria-hidden="true"
                  className="size-4 shrink-0 text-ink-400 group-hover:text-uv-600 dark:group-hover:text-uv-300"
                />
                <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <span className="flex flex-wrap items-center gap-1.5 text-xs font-medium text-ink-800 dark:text-ink-200">
                    {label}
                    {os && (
                      <span className="rounded border border-ink-200 px-1 font-mono text-[10px] font-normal text-ink-500 dark:border-white/10">
                        {os}
                      </span>
                    )}
                  </span>
                  <code className="font-mono text-[11px] break-all text-ink-500">
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
      </div>
    </section>
  );
}
