"use client";

import Link from "next/link";
import { useMemo, useState, useSyncExternalStore } from "react";

import type { EventsDict } from "@/src/dict/events";
import { fill } from "@/src/dict/events";

export type IndexItem = {
  key: string;
  id: number;
  channel: string;
  channelLabel: string;
  title: string;
  summary: string;
  category: string;
  tactics: string[];
  href: string;
  /** Linked page is the English original (no translation in this locale). */
  fallback: boolean;
};

type Option = { value: string; label: string };

const PARAMS = ["q", "channel", "category", "tactic"] as const;
type Filters = Record<(typeof PARAMS)[number], string>;
const EMPTY: Filters = { q: "", channel: "", category: "", tactic: "" };

const noopSubscribe = () => () => {};

function fromSearch(search: string): Filters {
  const p = new URLSearchParams(search);
  const out = { ...EMPTY };
  for (const k of PARAMS) out[k] = p.get(k) ?? "";
  return out;
}

function norm(s: string) {
  return s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
}

export function EventIndex({
  items,
  channels,
  categories,
  tactics,
  dict,
}: {
  items: IndexItem[];
  channels: Option[];
  categories: Option[];
  tactics: Option[];
  dict: EventsDict;
}) {
  // Filters are shareable (?channel=sysmon&q=dns). The query string is read
  // as an external store (empty on the server), so the statically rendered
  // list never depends on it; once the user edits a filter, state wins.
  const search = useSyncExternalStore(
    noopSubscribe,
    () => window.location.search,
    () => "",
  );
  const [edited, setEdited] = useState<Filters | null>(null);
  const fromUrl = useMemo(() => fromSearch(search), [search]);
  const f = edited ?? fromUrl;

  const update = (patch: Partial<Filters>) => {
    const next = { ...f, ...patch };
    setEdited(next);
    const p = new URLSearchParams();
    for (const k of PARAMS) if (next[k]) p.set(k, next[k]);
    const qs = p.toString();
    window.history.replaceState(null, "", `${window.location.pathname}${qs ? `?${qs}` : ""}`);
  };

  const shown = useMemo(() => {
    const q = norm(f.q.trim());
    const terms = q ? q.split(/\s+/) : [];
    return items.filter((it) => {
      if (f.channel && it.channel !== f.channel) return false;
      if (f.category && it.category !== f.category) return false;
      if (f.tactic && !it.tactics.includes(f.tactic)) return false;
      if (!terms.length) return true;
      const hay = norm(`${it.id} ${it.title} ${it.summary} ${it.channelLabel}`);
      return terms.every((t) => (/^\d+$/.test(t) ? String(it.id).startsWith(t) || hay.includes(t) : hay.includes(t)));
    });
  }, [items, f]);

  const select =
    "h-9 rounded-md border border-ink-200 bg-card px-2 text-sm text-ink-800 outline-none focus:border-uv-500 dark:border-ink-800 dark:text-ink-200";
  const active = PARAMS.some((k) => f[k]);

  return (
    <div className="flex flex-col gap-4">
      <div className="surface flex flex-col gap-3 p-4" role="search">
        <label className="flex flex-col gap-1">
          <span className="eyebrow">{dict.searchLabel}</span>
          <input
            type="search"
            value={f.q}
            onChange={(e) => update({ q: e.target.value })}
            placeholder={dict.searchPlaceholder}
            className="h-10 rounded-md border border-ink-200 bg-card px-3 text-sm text-ink-900 outline-none focus:border-uv-500 dark:border-ink-800 dark:text-ink-100"
          />
        </label>
        <div className="grid gap-3 sm:grid-cols-3">
          <label className="flex flex-col gap-1">
            <span className="eyebrow">{dict.channelFilter}</span>
            <select className={select} value={f.channel} onChange={(e) => update({ channel: e.target.value })}>
              <option value="">{dict.all}</option>
              {channels.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="eyebrow">{dict.categoryFilter}</span>
            <select className={select} value={f.category} onChange={(e) => update({ category: e.target.value })}>
              <option value="">{dict.all}</option>
              {categories.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="eyebrow">{dict.tacticFilter}</span>
            <select className={select} value={f.tactic} onChange={(e) => update({ tactic: e.target.value })}>
              <option value="">{dict.all}</option>
              {tactics.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="flex items-center justify-between gap-3 text-sm text-ink-600 dark:text-ink-400">
          <span aria-live="polite">{fill(dict.resultCount, { count: shown.length })}</span>
          {active && (
            <button
              type="button"
              onClick={() => update(EMPTY)}
              className="rounded-md px-2 py-1 text-uv-700 hover:bg-uv-500/10 dark:text-uv-300"
            >
              {dict.reset}
            </button>
          )}
        </div>
      </div>

      {shown.length === 0 ? (
        <p className="surface p-5 text-sm text-ink-600 dark:text-ink-400">{dict.noResults}</p>
      ) : (
        <ul className="grid gap-2">
          {shown.map((it) => (
            <li key={it.key}>
              <Link
                href={it.href}
                hrefLang={it.fallback ? "en" : undefined}
                className="surface surface-interactive group flex items-start gap-3 px-4 py-3"
              >
                <span className="mt-0.5 min-w-[3.75rem] rounded-md bg-uv-50 px-1.5 py-0.5 text-center font-mono text-sm text-uv-700 dark:bg-uv-400/10 dark:text-uv-300">
                  {it.id}
                </span>
                <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className="font-medium text-ink-900 dark:text-ink-100" lang={it.fallback ? "en" : undefined}>
                      {it.title}
                    </span>
                    <span className="font-mono text-[0.6875rem] tracking-wide text-ink-500 uppercase dark:text-ink-400">
                      {it.channelLabel}
                    </span>
                    {it.fallback && (
                      <span
                        title={dict.englishTitle}
                        className="rounded-full border border-ink-200 px-1.5 text-[0.6875rem] text-ink-500 dark:border-ink-700 dark:text-ink-400"
                      >
                        {dict.englishBadge}
                      </span>
                    )}
                  </span>
                  <span
                    className="line-clamp-2 text-sm leading-relaxed text-ink-600 dark:text-ink-400"
                    lang={it.fallback ? "en" : undefined}
                  >
                    {it.summary}
                  </span>
                </span>
                <span aria-hidden="true" className="mt-1 text-uv-500 transition-transform group-hover:translate-x-0.5">
                  →
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
