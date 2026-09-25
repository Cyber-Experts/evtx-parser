"use client";

import { useEffect, useState } from "react";

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

// Roughly the ATT&CK kill-chain order.
const CATEGORY_ORDER: HuntCategory[] = [
  "initial",
  "execution",
  "persistence",
  "credential",
  "discovery",
  "lateral",
  "evasion",
  "impact",
];

// Rows processed per slice before yielding back to the browser.
const SLICE = 4000;

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
  const [needle, setNeedle] = useState("");
  const [hitsOnly, setHitsOnly] = useState(false);

  // Counting runs every hunt over every row, so it happens only while the
  // menu is open and in small slices, keeping the page responsive on
  // million-event logs. Results are tied to the rows they were computed for.
  const [result, setResult] = useState<{
    rows: R[];
    counts: Map<string, number>;
  } | null>(null);
  const [progress, setProgress] = useState(0);
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    const counts = new Map<string, number>(COMPILED.map(({ hunt }) => [hunt.id, 0]));
    let i = 0;
    const step = () => {
      if (cancelled) return;
      const end = Math.min(rows.length, i + SLICE);
      for (; i < end; i++) {
        const r = rows[i];
        const pairs = allPairs[r._g] ?? [];
        const hay = () => haystackOf(r);
        for (const { hunt, test } of COMPILED) {
          if (test && test(r, pairs, hay)) {
            counts.set(hunt.id, (counts.get(hunt.id) ?? 0) + 1);
          }
        }
      }
      if (i < rows.length) {
        setProgress(i / rows.length);
        setTimeout(step, 0);
      } else {
        setResult({ rows, counts });
      }
    };
    const id = setTimeout(step, 0);
    return () => {
      cancelled = true;
      clearTimeout(id);
    };
  }, [open, rows, allPairs, haystackOf]);
  const counts = result && result.rows === rows ? result.counts : null;

  const categoryLabel: Record<HuntCategory, string> = {
    initial: v.catInitial,
    discovery: v.catDiscovery,
    impact: v.catImpact,
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
      {open && (
        <div className="absolute left-0 top-full z-30 mt-1 max-h-[70vh] w-[min(28rem,calc(100vw-2rem))] overflow-y-auto rounded-md border border-zinc-200 bg-white p-2 text-xs shadow-lg dark:border-zinc-800 dark:bg-zinc-900">
          <p className="px-1 pb-2 text-zinc-500">
            {v.huntsHint}
            {!counts && (
              <span className="ml-1 font-mono text-amber-600 dark:text-amber-400">
                {Math.round(progress * 100)}%
              </span>
            )}
          </p>
          <div className="flex items-center gap-2 px-1 pb-2">
            <input
              type="search"
              value={needle}
              onChange={(e) => setNeedle(e.target.value)}
              placeholder={v.huntsFilter}
              autoFocus
              className="min-w-0 flex-1 rounded border border-zinc-200 bg-transparent px-2 py-1 outline-none focus:border-amber-500 dark:border-zinc-700"
            />
            <label className="flex shrink-0 items-center gap-1 text-zinc-500">
              <input
                type="checkbox"
                checked={hitsOnly}
                onChange={(e) => setHitsOnly(e.target.checked)}
                className="accent-amber-500"
              />
              {v.hitsOnly}
            </label>
          </div>
          {CATEGORY_ORDER.map((cat) => {
            const q = needle.trim().toLowerCase();
            const items = HUNTS.filter(
              (h) =>
                h.category === cat &&
                (!hitsOnly || !counts || (counts.get(h.id) ?? 0) > 0) &&
                (!q ||
                  pickLocale(h.name, locale).toLowerCase().includes(q) ||
                  h.name.en.toLowerCase().includes(q) ||
                  (h.mitre ?? "").toLowerCase().includes(q)),
            );
            if (items.length === 0) return null;
            return (
              <div key={cat} className="pb-2">
                <div className="px-1 pb-1 text-[10px] uppercase tracking-wide text-zinc-400">
                  {categoryLabel[cat]}
                </div>
                {items.map((h) => {
                  const n = counts?.get(h.id) ?? 0;
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
                        {counts ? n : "…"}
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
