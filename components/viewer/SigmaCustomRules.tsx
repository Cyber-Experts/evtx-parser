"use client";

import { useRef, useState } from "react";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { SigmaLevel, SigmaSkipped } from "@/lib/sigma/types";
import type { Dict } from "@/src/dict/types";

import { SIGMA_LEVEL_DOT } from "./SigmaView";

/** One pasted text or dropped file, with its validation outcome. */
export type CustomRuleEntry = {
  key: string;
  name: string;
  text: string;
  rules: { id: string; title: string; level: SigmaLevel }[];
  errors: SigmaSkipped[];
};

export function SigmaCustomRules({
  open,
  onOpenChange,
  dict,
  entries,
  onAddTexts,
  onRemove,
  onClear,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  dict: Dict;
  entries: CustomRuleEntry[];
  /** Validate + add; resolves once the entries are stored. */
  onAddTexts: (items: { name: string; text: string }[]) => Promise<void>;
  onRemove: (key: string) => void;
  onClear: () => void;
}) {
  const s = dict.sigma;
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [over, setOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const addFiles = async (files: File[]) => {
    const yml = files.filter((f) => /\.ya?ml$/i.test(f.name));
    if (!yml.length) return;
    setBusy(true);
    try {
      await onAddTexts(await Promise.all(yml.map(async (f) => ({ name: f.name, text: await f.text() }))));
    } finally {
      setBusy(false);
    }
  };

  const addDraft = async () => {
    if (!draft.trim()) return;
    setBusy(true);
    try {
      await onAddTexts([{ name: "pasted", text: draft }]);
      setDraft("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{s.customTitle}</DialogTitle>
          <DialogDescription>{s.customHint}</DialogDescription>
        </DialogHeader>

        <div
          data-sigma-drop
          onDragEnter={(e) => {
            e.preventDefault();
            e.stopPropagation();
            setOver(true);
          }}
          onDragOver={(e) => {
            e.preventDefault();
            e.stopPropagation();
          }}
          onDragLeave={(e) => {
            e.stopPropagation();
            if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setOver(false);
          }}
          onDrop={(e) => {
            e.preventDefault();
            e.stopPropagation();
            setOver(false);
            void addFiles(Array.from(e.dataTransfer.files));
          }}
          className={`flex flex-col gap-2 rounded-lg border-2 border-dashed p-2 transition-colors ${
            over ? "border-uv-500 bg-uv-500/5" : "border-transparent"
          }`}
        >
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={s.customPlaceholder}
            spellCheck={false}
            rows={9}
            aria-label={s.customTitle}
            className="w-full rounded-md border border-ink-300 bg-transparent p-2 font-mono text-xs dark:border-ink-700"
          />
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <button
              type="button"
              onClick={addDraft}
              disabled={busy || !draft.trim()}
              className="rounded-md bg-uv-600 px-3 py-1.5 font-medium text-white hover:bg-uv-500 disabled:opacity-40 dark:bg-uv-500 dark:hover:bg-uv-400"
            >
              {s.customAdd}
            </button>
            <button
              type="button"
              onClick={() => fileRef.current?.click()}
              disabled={busy}
              className="rounded-md border border-ink-300 px-3 py-1.5 text-ink-700 hover:bg-ink-100 dark:border-ink-700 dark:text-ink-300 dark:hover:bg-ink-900"
            >
              {s.customPick}
            </button>
            <span className="text-ink-400">{s.customDrop}</span>
            <input
              ref={fileRef}
              type="file"
              accept=".yml,.yaml"
              multiple
              className="hidden"
              onChange={(e) => {
                const picked = Array.from(e.target.files ?? []);
                e.target.value = "";
                void addFiles(picked);
              }}
            />
          </div>
        </div>

        <div className="flex flex-col gap-2 text-xs">
          <div className="flex items-center gap-2">
            <h3 className="font-semibold text-ink-700 dark:text-ink-200">{s.customLoaded}</h3>
            {entries.length > 0 && (
              <button
                type="button"
                onClick={onClear}
                className="ml-auto rounded border border-ink-200 px-2 py-0.5 text-ink-600 hover:bg-ink-100 dark:border-ink-700 dark:text-ink-300 dark:hover:bg-ink-900"
              >
                {s.customClear}
              </button>
            )}
          </div>
          {entries.length === 0 ? (
            <p className="text-ink-500">{s.customEmpty}</p>
          ) : (
            <ul className="flex flex-col gap-1.5">
              {entries.map((e) => (
                <li key={e.key} className="rounded-md border border-ink-200 p-2 dark:border-ink-800">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-mono text-ink-500">{e.name}</span>
                    <button
                      type="button"
                      onClick={() => onRemove(e.key)}
                      className="ml-auto shrink-0 rounded px-1.5 text-ink-500 hover:bg-ink-100 hover:text-ink-900 dark:hover:bg-ink-800 dark:hover:text-ink-100"
                    >
                      {s.customRemove}
                    </button>
                  </div>
                  <ul className="mt-1 flex flex-col gap-0.5">
                    {e.rules.map((r) => (
                      <li key={r.id} className="flex items-center gap-2">
                        <span className={`h-2 w-2 shrink-0 rounded-full ${SIGMA_LEVEL_DOT[r.level]}`} aria-hidden="true" />
                        <span className="text-ink-800 dark:text-ink-200">{r.title}</span>
                        <span className="text-ink-400">{s.levels[r.level]}</span>
                      </li>
                    ))}
                    {e.errors.map((err, i) => (
                      <li key={`e${i}`} className="text-red-700 dark:text-red-400">
                        {s.customInvalid}: <span className="font-medium">{err.title}</span> — {err.reason}
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
