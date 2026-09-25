"use client";

import { useEffect, useState } from "react";

import type { Dict } from "@/src/dict/types";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { SessionNameDialog } from "@/components/viewer/SessionNameDialog";
import {
  deleteSession,
  listSavedSessions,
  renameSession,
  type SavedSessionMeta,
} from "@/lib/saved-sessions";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

/** Start-screen list of sessions saved in this browser: resume, rename, delete. */
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
  const [toDelete, setToDelete] = useState<SavedSessionMeta | null>(null);
  const [toRename, setToRename] = useState<SavedSessionMeta | null>(null);

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
  const details = (s: SavedSessionMeta) =>
    `${num.format(s.files.length)} ${s.files.length === 1 ? v.fileLabel : v.filesLabel} · ${formatBytes(s.totalSize)} · ${num.format(s.events)} ${dict.home.eventsLabel}`;
  const btn =
    "rounded-md border border-ink-300 px-2.5 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50 dark:border-ink-700 dark:text-ink-300 dark:hover:bg-ink-900";

  return (
    <section
      aria-label={v.savedSessionsTitle}
      className="surface flex flex-col gap-2 p-5 text-sm"
    >
      <div className="flex flex-col gap-0.5">
        <h2 className="font-semibold text-ink-900 dark:text-ink-100">💾 {v.savedSessionsTitle}</h2>
        <p className="text-xs text-ink-500">{v.savedSessionsHint}</p>
      </div>
      <ul className="flex flex-col divide-y divide-ink-100 dark:divide-ink-800">
        {sessions.map((s) => (
          <li key={s.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
            <span
              className="min-w-0 flex-1 truncate font-medium text-ink-900 dark:text-ink-100"
              title={s.files.map((f) => f.name).join("\n")}
            >
              {s.name}
            </span>
            <span className="font-mono text-xs text-ink-500">
              {details(s)} · {dateFmt.format(s.savedAt)}
            </span>
            <span className="flex gap-1.5">
              <button
                type="button"
                disabled={busy}
                onClick={() => onResume(s.id)}
                className="rounded-md border border-ink-900 bg-ink-900 px-2.5 py-1 text-xs font-medium text-ink-50 hover:bg-ink-700 disabled:opacity-50 dark:border-ink-100 dark:bg-ink-100 dark:text-ink-900"
              >
                {v.resumeSession}
              </button>
              <button type="button" disabled={busy} onClick={() => setToRename(s)} className={btn}>
                {v.renameSession}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => setToDelete(s)}
                className={`${btn} hover:border-red-400 hover:text-red-700 dark:hover:text-red-400`}
              >
                {v.deleteSession}
              </button>
            </span>
          </li>
        ))}
      </ul>

      <SessionNameDialog
        open={toRename != null}
        onOpenChange={(open) => !open && setToRename(null)}
        dict={dict}
        title={v.renameSessionTitle}
        initialName={toRename?.name ?? ""}
        confirmLabel={v.renameSession}
        onConfirm={async (name) => {
          const target = toRename;
          if (!target) return;
          await renameSession(target.id, name);
          setSessions((prev) => prev.map((x) => (x.id === target.id ? { ...x, name } : x)));
        }}
      />

      <AlertDialog open={toDelete != null} onOpenChange={(open) => !open && setToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{v.deleteSessionTitle}</AlertDialogTitle>
            <AlertDialogDescription>
              <span className="block font-medium text-foreground">{toDelete?.name}</span>
              <span className="block font-mono text-xs">{toDelete && details(toDelete)}</span>
              <span className="mt-2 block">{v.confirmDeleteSession}</span>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{v.cancel}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={async () => {
                const target = toDelete;
                if (!target) return;
                await deleteSession(target.id);
                setSessions((prev) => prev.filter((x) => x.id !== target.id));
                setToDelete(null);
              }}
            >
              {v.deleteSession}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
