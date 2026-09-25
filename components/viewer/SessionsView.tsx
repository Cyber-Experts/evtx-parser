"use client";

import { useMemo, useState } from "react";

import type { Dict } from "@/src/dict/types";
import { eventName } from "@/lib/event-info";
import {
  formatDuration,
  sessionDurationMs,
  type LogonSession,
} from "@/lib/sessions";
import { formatTimestamp, type TimeMode } from "@/lib/time";

type SortKey = "start" | "duration" | "events";

const SECURITY = "Microsoft-Windows-Security-Auditing";
// Activity chips skip the session's own bookkeeping events.
const BOOKKEEPING = new Set([4624, 4634, 4647, 4672]);

export function SessionsView({
  sessions,
  dict,
  timeMode,
  onOpen,
}: {
  sessions: LogonSession[];
  dict: Dict;
  timeMode: TimeMode;
  onOpen: (s: LogonSession) => void;
}) {
  const v = dict.viewer;
  const [showSystem, setShowSystem] = useState(false);
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({
    key: "start",
    desc: false,
  });

  const visible = useMemo(() => {
    const list = sessions.filter((s) => showSystem || !s.system);
    const val = (s: LogonSession): number | string =>
      sort.key === "events"
        ? s.events
        : sort.key === "duration"
          ? (sessionDurationMs(s) ?? -1)
          : (s.start ?? s.firstSeen);
    return [...list].sort((a, b) => {
      const x = val(a);
      const y = val(b);
      const c = x < y ? -1 : x > y ? 1 : 0;
      return sort.desc ? -c : c;
    });
  }, [sessions, showSystem, sort]);

  const systemCount = sessions.filter((s) => s.system).length;

  const header = (key: SortKey, label: string) => (
    <th className="px-3 py-2">
      <button
        type="button"
        onClick={() =>
          setSort((p) => ({ key, desc: p.key === key ? !p.desc : key !== "start" }))
        }
        className={`flex items-center gap-1 hover:text-zinc-900 dark:hover:text-zinc-100 ${
          sort.key === key ? "text-amber-700 dark:text-amber-300" : ""
        }`}
      >
        {label}
        <span className="text-[10px]">
          {sort.key === key ? (sort.desc ? "↓" : "↑") : ""}
        </span>
      </button>
    </th>
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-zinc-500">
        <span>{v.sessionsHint}</span>
        <label className="flex items-center gap-1.5">
          <input
            type="checkbox"
            checked={showSystem}
            onChange={(e) => setShowSystem(e.target.checked)}
            className="accent-amber-500"
          />
          {v.showSystemSessions} ({systemCount})
        </label>
      </div>

      {visible.length === 0 ? (
        <p className="rounded-md border border-zinc-200 p-4 text-sm text-zinc-500 dark:border-zinc-800">
          {v.noSessions}
        </p>
      ) : (
        <div className="-mx-4 min-h-0 flex-1 overflow-auto border-y border-zinc-200 sm:mx-0 sm:rounded-md sm:border dark:border-zinc-800">
          <table className="w-full text-left font-mono text-xs">
            <thead className="sticky top-0 z-10 bg-zinc-50 text-zinc-500 dark:bg-zinc-900 dark:text-zinc-400">
              <tr>
                {header("start", v.sessionStart)}
                <th className="px-3 py-2">{v.sessionEnd}</th>
                {header("duration", v.sessionDuration)}
                <th className="px-3 py-2">{v.sessionUser}</th>
                <th className="px-3 py-2">{v.sessionType}</th>
                <th className="px-3 py-2">{v.sessionAdmin}</th>
                {header("events", v.sessionEvents)}
                <th className="px-3 py-2">{v.sessionActivity}</th>
                <th className="px-3 py-2">{v.sessionSource}</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((s) => {
                const dur = sessionDurationMs(s);
                const activity = s.eventIds
                  .filter(([id]) => !BOOKKEEPING.has(id))
                  .slice(0, 4);
                return (
                  <tr
                    key={s.key}
                    onClick={() => onOpen(s)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") onOpen(s);
                    }}
                    tabIndex={0}
                    title={`${s.computer} · ${s.logonIds.join(" + ")}`}
                    className={`cursor-pointer border-t border-zinc-100 hover:bg-amber-50 focus:bg-amber-50 focus:outline-none dark:border-zinc-800 dark:hover:bg-amber-400/10 dark:focus:bg-amber-400/10 ${
                      s.system ? "text-zinc-400" : ""
                    }`}
                  >
                    <td className="whitespace-nowrap px-3 py-1.5">
                      {s.start ? (
                        formatTimestamp(s.start, timeMode).slice(0, 19)
                      ) : (
                        <span className="text-zinc-400">
                          ≤ {formatTimestamp(s.firstSeen, timeMode).slice(0, 19)}{" "}
                          <span className="text-[10px]">({v.sessionUnknownStart})</span>
                        </span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5">
                      {s.end ? (
                        <>
                          {formatTimestamp(s.end, timeMode).slice(0, 19)}
                          <span className="ml-1 text-zinc-400">{s.endEventId}</span>
                        </>
                      ) : (
                        <span className="text-amber-600 dark:text-amber-400">
                          {v.sessionOpen}
                        </span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5 text-zinc-600 dark:text-zinc-400">
                      {dur != null ? formatDuration(dur) : "—"}
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5 font-semibold text-zinc-900 dark:text-zinc-100">
                      {s.user || <span className="text-zinc-400">—</span>}
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5">
                      {s.logonType != null ? (
                        <>
                          {s.logonType}
                          {s.logonTypeLabel && (
                            <span className="ml-1 text-zinc-400">
                              · {s.logonTypeLabel}
                            </span>
                          )}
                        </>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="px-3 py-1.5">
                      {s.admin ? (
                        <span className="rounded bg-red-500/15 px-1.5 py-0.5 text-red-700 dark:text-red-300">
                          admin
                        </span>
                      ) : (
                        ""
                      )}
                    </td>
                    <td className="px-3 py-1.5 tabular-nums">{s.events}</td>
                    <td className="px-3 py-1.5">
                      <span className="flex gap-1 whitespace-nowrap">
                        {activity.map(([id, n]) => (
                          <span
                            key={id}
                            title={eventName(id, SECURITY) ?? String(id)}
                            className="rounded border border-zinc-200 px-1 dark:border-zinc-700"
                          >
                            {id}
                            <span className="text-zinc-400">×{n}</span>
                          </span>
                        ))}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5">
                      {[s.sourceIp, s.workstation].filter(Boolean).join(" · ") || "—"}
                      {s.authPackage && (
                        <span className="ml-1 text-zinc-400">({s.authPackage})</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
