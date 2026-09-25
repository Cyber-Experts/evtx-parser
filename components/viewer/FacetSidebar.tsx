"use client";

import { useDeferredValue, useMemo, useState } from "react";

import type { Dict } from "@/src/dict/types";
import { eventName } from "@/lib/event-info";
import {
  PREFERRED_FIELDS,
  hasClause,
  type SearchRow,
} from "@/lib/search-query";

type FacetRow = SearchRow & { _g: number };

const META = ["EventID", "Level", "Provider", "Channel", "Computer", "File"] as const;
type MetaField = (typeof META)[number];

const PAGE = 8;
const EXPANDED = 50;

type Facet = {
  field: string;
  values: [string, number][];
  distinct: number;
};

function metaValue(field: MetaField, r: FacetRow): string {
  switch (field) {
    case "EventID":
      return r.event_id == null ? "" : String(r.event_id);
    case "Level":
      return r.level == null ? "" : String(r.level);
    case "Provider":
      return r.provider ?? "";
    case "Channel":
      return r.channel ?? "";
    case "Computer":
      return r.computer ?? "";
    case "File":
      return r._file;
  }
}

export function FacetSidebar({
  rows,
  allPairs,
  query,
  dict,
  multiFile,
  levelLabel,
  onInclude,
  onExclude,
  onRemove,
}: {
  rows: FacetRow[];
  allPairs: [string, string][][];
  query: string;
  dict: Dict;
  multiFile: boolean;
  levelLabel: (level: number) => string;
  onInclude: (field: string, value: string) => void;
  onExclude: (field: string, value: string) => void;
  onRemove: (field: string, value: string) => void;
}) {
  const v = dict.viewer;
  // Counting runs over every filtered row; defer it so typing stays snappy
  // on large logs.
  const deferredRows = useDeferredValue(rows);
  const [extraFields, setExtraFields] = useState<string[]>([]);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [rare, setRare] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [valueFilter, setValueFilter] = useState<Record<string, string>>({});

  const { facets, otherKeys, idNames } = useMemo(() => {
    const tracked = new Map<string, string>(); // lower → display
    for (const f of [...PREFERRED_FIELDS, ...extraFields]) {
      tracked.set(f.toLowerCase(), f);
    }
    const meta = new Map<MetaField, Map<string, number>>(
      META.map((m) => [m, new Map()]),
    );
    const data = new Map<string, Map<string, number>>();
    const coverage = new Map<string, number>();
    const displayKey = new Map<string, string>();
    const idNames = new Map<string, string>();

    for (const r of deferredRows) {
      for (const m of META) {
        const val = metaValue(m, r);
        if (!val) continue;
        const c = meta.get(m)!;
        c.set(val, (c.get(val) ?? 0) + 1);
      }
      if (r.event_id != null) {
        const id = String(r.event_id);
        if (!idNames.has(id)) {
          const n = eventName(r.event_id, r.provider);
          if (n) idNames.set(id, n);
        }
      }
      for (const [k, val] of allPairs[r._g] ?? []) {
        const lk = k.toLowerCase();
        coverage.set(lk, (coverage.get(lk) ?? 0) + 1);
        if (!displayKey.has(lk)) displayKey.set(lk, k);
        if (!tracked.has(lk) || !val) continue;
        let c = data.get(lk);
        if (!c) data.set(lk, (c = new Map()));
        c.set(val, (c.get(val) ?? 0) + 1);
      }
    }

    const toFacet = (field: string, counts: Map<string, number>): Facet => ({
      field,
      values: [...counts.entries()].sort((a, b) => b[1] - a[1]),
      distinct: counts.size,
    });

    const out: Facet[] = [];
    out.push(toFacet("EventID", meta.get("EventID")!));
    for (const [lk, disp] of tracked) {
      const c = data.get(lk);
      if (c && c.size > 0) out.push(toFacet(displayKey.get(lk) ?? disp, c));
    }
    for (const m of META) {
      if (m === "EventID") continue;
      if (m === "File" && !multiFile) continue;
      const c = meta.get(m)!;
      // A single-valued facet is noise unless the user is filtering on it.
      if (c.size > 1 || [...c.keys()].some((x) => hasClause(query, m, x))) {
        out.push(toFacet(m, c));
      }
    }

    const otherKeys = [...coverage.entries()]
      .filter(([lk]) => !tracked.has(lk))
      .sort((a, b) => b[1] - a[1])
      .map(([lk]) => displayKey.get(lk) ?? lk);

    return { facets: out, otherKeys, idNames };
  }, [deferredRows, allPairs, extraFields, multiFile, query]);

  const toggleIn = (
    setter: React.Dispatch<React.SetStateAction<Set<string>>>,
    key: string,
  ) =>
    setter((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const labelFor = (field: string, value: string): string => {
    if (field === "EventID") {
      const n = idNames.get(value);
      return n ? `${value} · ${n}` : value;
    }
    if (field === "Level") return levelLabel(Number(value));
    return value;
  };

  return (
    <div className="flex flex-col gap-2 text-xs">
      {facets.map((f) => {
        const isCollapsed = collapsed.has(f.field);
        const isRare = rare.has(f.field);
        const needle = (valueFilter[f.field] ?? "").toLowerCase();
        let values = isRare ? [...f.values].reverse() : f.values;
        if (needle) {
          values = values.filter(([x]) =>
            labelFor(f.field, x).toLowerCase().includes(needle),
          );
        }
        const limit = expanded.has(f.field) ? EXPANDED : PAGE;
        return (
          <section
            key={f.field}
            className="rounded-md border border-ink-200 dark:border-ink-800"
          >
            <header className="flex items-center justify-between gap-2 px-2 py-1.5">
              <button
                type="button"
                onClick={() => toggleIn(setCollapsed, f.field)}
                aria-expanded={!isCollapsed}
                className="flex min-w-0 items-center gap-1 font-mono font-semibold text-ink-800 dark:text-ink-200"
              >
                <span aria-hidden="true" className="text-ink-400">
                  {isCollapsed ? "▸" : "▾"}
                </span>
                <span className="truncate">{f.field}</span>
                <span className="font-normal text-ink-400">{f.distinct}</span>
              </button>
              {!isCollapsed && f.distinct > 1 && (
                <button
                  type="button"
                  onClick={() => toggleIn(setRare, f.field)}
                  aria-pressed={isRare}
                  className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] ${
                    isRare
                      ? "border-uv-500 bg-uv-500/15 text-uv-700 dark:text-uv-300"
                      : "border-ink-200 text-ink-500 dark:border-ink-800"
                  }`}
                >
                  {isRare ? v.rare : v.top}
                </button>
              )}
            </header>
            {!isCollapsed && (
              <div className="flex flex-col gap-0.5 px-1 pb-1.5">
                {f.distinct > PAGE && (
                  <input
                    type="search"
                    value={valueFilter[f.field] ?? ""}
                    onChange={(e) =>
                      setValueFilter((p) => ({ ...p, [f.field]: e.target.value }))
                    }
                    placeholder={v.filterValues}
                    className="mx-1 mb-1 rounded border border-ink-200 bg-transparent px-2 py-0.5 font-mono text-[11px] outline-none focus:border-uv-500 dark:border-ink-800"
                  />
                )}
                {values.length === 0 && (
                  <span className="px-1 text-ink-400">{v.noValues}</span>
                )}
                {values.slice(0, limit).map(([x, n]) => {
                  const on = hasClause(query, f.field, x);
                  const label = labelFor(f.field, x);
                  return (
                    <div
                      key={x}
                      className={`group flex items-center gap-1 rounded px-1 ${
                        on ? "bg-uv-500/15" : "hover:bg-ink-100 dark:hover:bg-ink-900"
                      }`}
                    >
                      <button
                        type="button"
                        onClick={() =>
                          on ? onRemove(f.field, x) : onInclude(f.field, x)
                        }
                        title={`${label}\n${on ? v.remove : v.include}`}
                        className={`min-w-0 flex-1 truncate py-0.5 text-left font-mono ${
                          on
                            ? "text-uv-800 dark:text-uv-200"
                            : "text-ink-700 dark:text-ink-300"
                        }`}
                      >
                        {label}
                      </button>
                      <span className="shrink-0 font-mono tabular-nums text-ink-400">
                        {n}
                      </span>
                      <button
                        type="button"
                        onClick={() => onExclude(f.field, x)}
                        title={v.exclude}
                        aria-label={`${v.exclude}: ${label}`}
                        className="shrink-0 rounded px-1 text-ink-400 opacity-0 hover:bg-ink-200 hover:text-ink-900 focus:opacity-100 group-hover:opacity-100 dark:hover:bg-ink-800 dark:hover:text-ink-100"
                      >
                        −
                      </button>
                    </div>
                  );
                })}
                {values.length > PAGE && (
                  <button
                    type="button"
                    onClick={() => toggleIn(setExpanded, f.field)}
                    className="self-start px-1 text-[11px] text-ink-500 hover:text-ink-900 hover:underline dark:hover:text-ink-100"
                  >
                    {expanded.has(f.field) ? v.showLess : v.showMore}
                  </button>
                )}
              </div>
            )}
          </section>
        );
      })}
      {otherKeys.length > 0 && (
        <select
          value=""
          onChange={(e) => {
            const k = e.target.value;
            if (k) setExtraFields((p) => (p.includes(k) ? p : [...p, k]));
          }}
          aria-label={v.addField}
          className="rounded-md border border-ink-200 bg-transparent px-2 py-1 font-mono text-[11px] text-ink-600 dark:border-ink-800 dark:bg-ink-950 dark:text-ink-300"
        >
          <option value="">{v.addField}</option>
          {otherKeys.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
      )}
    </div>
  );
}
