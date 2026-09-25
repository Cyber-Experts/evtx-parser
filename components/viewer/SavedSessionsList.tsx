"use client";

import { useEffect, useState } from "react";

import type { Dict } from "@/src/dict/types";
import {
  deleteSession,
  listSavedSessions,
  type SavedSessionMeta,
} from "@/lib/saved-sessions";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

/** Start-screen list of sessions saved in this browser, with resume/delete. */
export function SavedSessionsList({
  dict,
  locale,
  onResume,
  busy,
}: {
  dict: Dict;
  locale: string;
  onResume: (id: string) => void;
  busy: boolean;
}) {
  const v = dict.viewer;
  const [sessions, setSessions] = useState<SavedSessionMeta[]>([]);

  useEffect(() => {
    let alive = true;
    listSavedSessions()
      .then((s) => {
        if (alive) setSessions(s);
      })
      .catch(() => {
        // IndexedDB unavailable (private mode, blocked storage): no list.
      });
    return () => {
      alive = false;
    };
  }, []);

  if (sessions.length === 0) return null;
  const dateFmt = new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" });
  const num = new Intl.NumberFormat(locale);

  return (
    <section
      aria-label={v.savedSessionsTitle}
      className="flex flex-col gap-2 rounded-lg border border-zinc-200 p-3 text-sm dark:border-zinc-800"
    >
      <div className="flex flex-col gap-0.5">
        <h2 className="font-semibold text-zinc-900 dark:text-zinc-100">💾 {v.savedSessionsTitle}</h2>
        <p className="text-xs text-zinc-500">{v.savedSessionsHint}</p>
      </div>
      <ul className="flex flex-col divide-y divide-zinc-100 dark:divide-zinc-800">
        {sessions.map((s) => (
          <li key={s.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
            <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-900 dark:text-zinc-100" title={s.files.map((f) => f.name).join("\n")}>
              {s.name}
            </span>
            <span className="font-mono text-xs text-zinc-500">
              {num.format(s.files.length)} {v.filesLabel} · {formatBytes(s.totalSize)} ·{" "}
              {num.format(s.events)} {dict.home.eventsLabel} · {dateFmt.format(s.savedAt)}
            </span>
            <span className="flex gap-1.5">
              <button
                type="button"
                disabled={busy}
                onClick={() => onResume(s.id)}
                className="rounded-md border border-zinc-900 bg-zinc-900 px-2.5 py-1 text-xs font-medium text-zinc-50 hover:bg-zinc-700 disabled:opacity-50 dark:border-zinc-100 dark:bg-zinc-100 dark:text-zinc-900"
              >
                {v.resumeSession}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={async () => {
                  if (!window.confirm(`${v.deleteSession}: ${s.name}?`)) return;
                  await deleteSession(s.id);
                  setSessions((prev) => prev.filter((x) => x.id !== s.id));
                }}
                className="rounded-md border border-zinc-300 px-2.5 py-1 text-xs text-zinc-700 hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
              >
                {v.deleteSession}
              </button>
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
