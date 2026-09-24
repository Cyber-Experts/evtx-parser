"use client";

import { useMemo, useState } from "react";

import type { Dict } from "@/src/dict/types";
import type { Locale } from "@/src/dict/locales";
import { HUNTS, type HuntCategory } from "@/lib/hunts";
import { pickLocale } from "@/lib/landing/locale-content";
import {
  compileSearch,
  parseSearch,
  type SearchRow,
} from "@/lib/search-query";

type Row = SearchRow & { _g: number };

const CATEGORY_ORDER: HuntCategory[] = [
  "credential",
  "lateral",
  "persistence",
  "execution",
  "evasion",
];

// Hunts compile once per page load; the queries are static.
const COMPILED = HUNTS.map((h) => ({
  hunt: h,
  test: compileSearch(parseSearch(h.query)),
}));

export function HuntsMenu<R extends Row>({
  rows,
  allPairs,
  haystackOf,
  locale,
  dict,
  activeQuery,
  onRun,
}: {
  rows: R[];
  allPairs: [string, string][][];
  haystackOf: (r: R) => string;
  locale: Locale;
  dict: Dict;
  activeQuery: string;
  onRun: (query: string) => void;
}) {
  const v = dict.viewer;
  const [open, setOpen] = useState(false);

  // Only count while the menu is open: ~20 queries over every row.
  const counts = useMemo(() => {
    if (!open) return null;
    const out = new Map<string, number>();
    for (const { hunt, test } of COMPILED) {
      if (!test) continue;
      let n = 0;
      for (const r of rows) {
        if (test(r, allPairs[r._g] ?? [], () => haystackOf(r))) n++;
      }
      out.set(hunt.id, n);
    }
    return out;
  }, [open, rows, allPairs, haystackOf]);

  const categoryLabel: Record<HuntCategory, string> = {
    credential: v.catCredential,
    lateral: v.catLateral,
    persistence: v.catPersistence,
    execution: v.catExecution,
    evasion: v.catEvasion,
  };

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className={`rounded-md border px-2 py-1 text-xs transition-colors ${
          open
            ? "border-amber-500 bg-amber-500/15 text-amber-700 dark:text-amber-300"
            : "border-zinc-300 text-zinc-700 hover:bg-zinc-100 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
        }`}
      >
        🎯 {v.hunts}
      </button>
      {open && counts && (
        <div className="absolute left-0 top-full z-30 mt-1 max-h-[70vh] w-[min(28rem,calc(100vw-2rem))] overflow-y-auto rounded-md border border-zinc-200 bg-white p-2 text-xs shadow-lg dark:border-zinc-800 dark:bg-zinc-900">
          <p className="px-1 pb-2 text-zinc-500">{v.huntsHint}</p>
          {CATEGORY_ORDER.map((cat) => {
            const items = HUNTS.filter((h) => h.category === cat);
            if (items.length === 0) return null;
            return (
              <div key={cat} className="pb-2">
                <div className="px-1 pb-1 text-[10px] uppercase tracking-wide text-zinc-400">
                  {categoryLabel[cat]}
                </div>
                {items.map((h) => {
                  const n = counts.get(h.id) ?? 0;
                  const active = activeQuery === h.query;
                  return (
                    <button
                      key={h.id}
                      type="button"
                      onClick={() => {
                        onRun(h.query);
                        setOpen(false);
                      }}
                      title={`${h.mitre ? `MITRE ATT&CK ${h.mitre}\n` : ""}${h.query}`}
                      className={`flex w-full items-center justify-between gap-3 rounded px-1.5 py-1 text-left ${
                        active
                          ? "bg-amber-500/15 text-amber-800 dark:text-amber-200"
                          : n > 0
                            ? "text-zinc-800 hover:bg-zinc-100 dark:text-zinc-200 dark:hover:bg-zinc-800"
                            : "text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800"
                      }`}
                    >
                      <span className="min-w-0 truncate">
                        {pickLocale(h.name, locale)}
                      </span>
                      <span
                        className={`shrink-0 rounded px-1.5 font-mono tabular-nums ${
                          n > 0
                            ? "bg-amber-500/20 text-amber-800 dark:text-amber-200"
                            : "text-zinc-400"
                        }`}
                      >
                        {n}
                      </span>
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
