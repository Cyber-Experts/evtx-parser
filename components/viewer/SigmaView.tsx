"use client";

import { useMemo, useState } from "react";

import { keyFields, type SigmaExportRow } from "@/lib/sigma/export";
import sigmaMeta from "@/lib/sigma/sigmahq-meta.json";
import {
  SIGMA_LEVELS,
  attackTags,
  attackUrl,
  sigmaRuleUrl,
  tacticLabel,
  type SigmaLevel,
  type SigmaMatch,
  type SigmaRunStats,
} from "@/lib/sigma/types";
import { formatTimestamp, type TimeMode } from "@/lib/time";
import type { Dict } from "@/src/dict/types";

export type SigmaStatus =
  | { phase: "idle" }
  | { phase: "loading" }
  | { phase: "running"; done: number; total: number }
  | { phase: "done" }
  | { phase: "error"; message: string };

// Level badge / dot colours, most to least severe.
export const SIGMA_LEVEL_DOT: Record<SigmaLevel, string> = {
  critical: "bg-red-600 dark:bg-red-500",
  high: "bg-orange-500 dark:bg-orange-400",
  medium: "bg-amber-400 dark:bg-amber-300",
  low: "bg-sky-500 dark:bg-sky-400",
  informational: "bg-ink-400",
};
const LEVEL_TEXT: Record<SigmaLevel, string> = {
  critical: "text-red-700 dark:text-red-400",
  high: "text-orange-700 dark:text-orange-300",
  medium: "text-amber-700 dark:text-amber-300",
  low: "text-sky-700 dark:text-sky-300",
  informational: "text-ink-500",
};

const MAX_EVENTS = 200;

const fill = (s: string, vars: Record<string, string | number>) =>
  s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));

export function SigmaView({
  dict,
  numberFmt,
  timeMode,
  status,
  matches,
  totals,
  rangeActive,
  stats,
  selectedId,
  onSelect,
  rowAt,
  pairsAt,
  onOpenEvent,
  onAround,
  onShowInTable,
  onExport,
  customCount,
  onOpenCustom,
}: {
  dict: Dict;
  numberFmt: Intl.NumberFormat;
  timeMode: TimeMode;
  status: SigmaStatus;
  /** Matches scoped to the current time range. */
  matches: SigmaMatch[];
  /** Unscoped event count per rule id (shown as "n / total" in a range). */
  totals: Map<string, number>;
  rangeActive: boolean;
  stats: SigmaRunStats | null;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  rowAt: (g: number) => SigmaExportRow;
  pairsAt: (g: number) => [string, string][];
  onOpenEvent: (g: number, ruleId: string) => void;
  onAround: (g: number) => void;
  onShowInTable: (ruleId: string) => void;
  onExport: (kind: "csv" | "json") => void;
  customCount: number;
  onOpenCustom: () => void;
}) {
  const s = dict.sigma;
  const [query, setQuery] = useState("");
  const [levels, setLevels] = useState<Set<SigmaLevel>>(new Set());
  const [tactic, setTactic] = useState("");

  const release = stats?.release || sigmaMeta.release;

  const byLevel = useMemo(() => {
    const m = new Map<SigmaLevel, number>();
    for (const x of matches) m.set(x.rule.level, (m.get(x.rule.level) ?? 0) + 1);
    return m;
  }, [matches]);

  const tactics = useMemo(() => {
    const set = new Set<string>();
    for (const x of matches) for (const t of attackTags(x.rule.tags).tactics) set.add(t);
    return [...set].sort();
  }, [matches]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return matches.filter((m) => {
      if (levels.size && !levels.has(m.rule.level)) return false;
      if (tactic && !attackTags(m.rule.tags).tactics.includes(tactic)) return false;
      if (!q) return true;
      const hay = [
        m.rule.title,
        m.rule.id,
        m.rule.description ?? "",
        m.rule.author ?? "",
        ...(m.rule.tags ?? []),
      ]
        .join("\n")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [matches, levels, tactic, query]);

  const selected = useMemo(
    () => visible.find((m) => m.rule.id === selectedId) ?? null,
    [visible, selectedId],
  );

  const totalEvents = useMemo(() => {
    const set = new Set<number>();
    for (const m of matches) for (const g of m.gids) set.add(g);
    return set.size;
  }, [matches]);

  const busy = status.phase === "loading" || status.phase === "running";
  const pct =
    status.phase === "running" && status.total > 0
      ? Math.floor((status.done / status.total) * 100)
      : 0;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-ink-600 dark:text-ink-400">
          {fill(s.intro, {
            n: numberFmt.format(stats?.bundled ?? sigmaMeta.counts.bundled),
            release,
          })}
        </span>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onOpenCustom}
            className="rounded-md border border-ink-300 px-2 py-1 text-ink-700 hover:bg-ink-100 dark:border-ink-700 dark:text-ink-300 dark:hover:bg-ink-900"
          >
            {fill(s.customRules, { n: numberFmt.format(customCount) })}
          </button>
          <button
            type="button"
            onClick={() => onExport("csv")}
            disabled={matches.length === 0 || busy}
            className="rounded-md border border-ink-300 px-2 py-1 text-ink-700 hover:bg-ink-100 disabled:opacity-40 dark:border-ink-700 dark:text-ink-300 dark:hover:bg-ink-900"
          >
            {s.exportCsv}
          </button>
          <button
            type="button"
            onClick={() => onExport("json")}
            disabled={matches.length === 0 || busy}
            className="rounded-md border border-ink-300 px-2 py-1 text-ink-700 hover:bg-ink-100 disabled:opacity-40 dark:border-ink-700 dark:text-ink-300 dark:hover:bg-ink-900"
          >
            {s.exportJson}
          </button>
        </div>
      </div>

      {busy && (
        <div className="flex flex-col gap-1 rounded-md border border-uv-500/30 bg-uv-50/40 px-3 py-2 dark:border-uv-400/20 dark:bg-uv-400/[0.06]">
          <span className="font-mono text-ink-700 dark:text-ink-300" role="status">
            {status.phase === "loading" ? s.loadingRules : fill(s.running, { pct })}
          </span>
          <div className="relative h-1 w-full overflow-hidden rounded-full bg-uv-500/15">
            <div
              className="absolute inset-y-0 left-0 rounded-full bg-uv-500 transition-[width] dark:bg-uv-400"
              style={{ width: `${status.phase === "running" ? pct : 5}%` }}
            />
          </div>
        </div>
      )}
      {status.phase === "error" && (
        <p className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-200">
          {fill(s.failed, { error: status.message })}
        </p>
      )}

      {status.phase === "done" && (
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={s.search}
            aria-label={s.search}
            className="w-full min-w-0 rounded-md border border-ink-300 bg-transparent px-2 py-1 sm:w-64 dark:border-ink-700"
          />
          <div className="flex flex-wrap gap-1.5" role="group" aria-label={s.allLevels}>
            {SIGMA_LEVELS.map((l) => {
              const n = byLevel.get(l) ?? 0;
              const active = levels.has(l);
              return (
                <button
                  key={l}
                  type="button"
                  disabled={n === 0 && !active}
                  aria-pressed={active}
                  onClick={() =>
                    setLevels((prev) => {
                      const next = new Set(prev);
                      if (next.has(l)) next.delete(l);
                      else next.add(l);
                      return next;
                    })
                  }
                  className={`flex items-center gap-1.5 rounded border px-1.5 py-0.5 transition-colors disabled:opacity-40 ${
                    active
                      ? "border-uv-500 bg-uv-500/15 text-uv-700 dark:border-uv-400/60 dark:bg-uv-400/10 dark:text-uv-300"
                      : "border-ink-200 text-ink-600 hover:border-uv-400 dark:border-ink-800 dark:text-ink-300 dark:hover:border-uv-400/60"
                  }`}
                >
                  <span className={`h-2 w-2 rounded-full ${SIGMA_LEVEL_DOT[l]}`} aria-hidden="true" />
                  {s.levels[l]}
                  <span className="font-mono tabular-nums text-ink-400">{numberFmt.format(n)}</span>
                </button>
              );
            })}
          </div>
          {tactics.length > 0 && (
            <select
              value={tactic}
              onChange={(e) => setTactic(e.target.value)}
              aria-label={s.allTactics}
              className="rounded-md border border-ink-300 bg-transparent px-1.5 py-1 dark:border-ink-700 dark:bg-ink-950"
            >
              <option value="">{s.allTactics}</option>
              {tactics.map((t) => (
                <option key={t} value={t}>
                  {tacticLabel(t)}
                </option>
              ))}
            </select>
          )}
          <span className="text-ink-500 sm:ml-auto">
            {fill(s.summary, {
              rules: numberFmt.format(matches.length),
              events: numberFmt.format(totalEvents),
            })}
          </span>
        </div>
      )}

      {status.phase === "done" && (
        <div className="flex min-h-0 flex-1 flex-col gap-3 lg:flex-row">
          <div className="-mx-4 max-h-80 min-h-0 overflow-y-auto border-y border-ink-200 sm:mx-0 sm:rounded-md sm:border lg:max-h-none lg:w-[42%] lg:shrink-0 dark:border-ink-800">
            {visible.length === 0 ? (
              <p className="p-4 text-sm text-ink-500">
                {matches.length === 0 ? s.noMatches : s.noMatchesFiltered}
              </p>
            ) : (
              <ul>
                {SIGMA_LEVELS.map((l) => {
                  const group = visible.filter((m) => m.rule.level === l);
                  if (group.length === 0) return null;
                  return (
                    <li key={l}>
                      <h3 className="sticky top-0 z-10 flex items-center gap-2 border-b border-ink-100 bg-ink-50 px-3 py-1.5 font-semibold text-ink-600 dark:border-ink-800 dark:bg-ink-900 dark:text-ink-300">
                        <span className={`h-2 w-2 rounded-full ${SIGMA_LEVEL_DOT[l]}`} aria-hidden="true" />
                        {s.levels[l]}
                        <span className="font-mono font-normal text-ink-400">{numberFmt.format(group.length)}</span>
                      </h3>
                      <ul>
                        {group.map((m) => {
                          const active = selected?.rule.id === m.rule.id;
                          const total = totals.get(m.rule.id) ?? m.gids.length;
                          return (
                            <li key={m.rule.id}>
                              <button
                                type="button"
                                onClick={() => onSelect(active ? null : m.rule.id)}
                                aria-pressed={active}
                                className={`flex w-full items-center gap-2 border-b border-ink-100 px-3 py-1.5 text-left transition-colors dark:border-ink-800/70 ${
                                  active
                                    ? "bg-uv-500/10"
                                    : "hover:bg-ink-50 dark:hover:bg-ink-900"
                                }`}
                              >
                                <span className="min-w-0 flex-1 truncate text-ink-800 dark:text-ink-200" title={m.rule.title}>
                                  {m.rule.title}
                                </span>
                                {m.rule.source === "custom" && (
                                  <span className="shrink-0 rounded border border-uv-400/50 px-1 text-[10px] text-uv-700 dark:text-uv-300">
                                    {s.customBadge}
                                  </span>
                                )}
                                <span
                                  className="shrink-0 rounded bg-ink-100 px-1.5 font-mono text-[10px] tabular-nums text-ink-600 dark:bg-ink-800 dark:text-ink-300"
                                  title={
                                    rangeActive
                                      ? dict.viewer.rangeCount
                                          .replace("{n}", numberFmt.format(m.gids.length))
                                          .replace("{total}", numberFmt.format(total))
                                      : undefined
                                  }
                                >
                                  {numberFmt.format(m.gids.length)}
                                </span>
                              </button>
                            </li>
                          );
                        })}
                      </ul>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          <div className="min-h-0 min-w-0 flex-1 overflow-y-auto">
            {selected ? (
              <RuleDetail
                match={selected}
                dict={dict}
                release={release}
                numberFmt={numberFmt}
                timeMode={timeMode}
                rowAt={rowAt}
                pairsAt={pairsAt}
                onOpenEvent={onOpenEvent}
                onAround={onAround}
                onShowInTable={onShowInTable}
              />
            ) : (
              matches.length > 0 && (
                <p className="rounded-md border border-dashed border-ink-200 p-4 text-sm text-ink-500 dark:border-ink-800">
                  {s.selectRule}
                </p>
              )
            )}
          </div>
        </div>
      )}

      <p className="text-[11px] text-ink-400">
        {fill(s.coverage, {
          bundled: numberFmt.format(sigmaMeta.counts.bundled),
          release: sigmaMeta.release,
          unsupported: numberFmt.format(sigmaMeta.counts.unsupported),
          deprecated: numberFmt.format(sigmaMeta.counts.deprecated),
        })}{" "}
        {stats &&
          fill(s.stats, {
            rules: numberFmt.format(stats.evaluated),
            events: numberFmt.format(stats.events),
            ms: numberFmt.format(stats.ms),
          })}{" "}
        <a
          href="https://github.com/SigmaHQ/Detection-Rule-License"
          target="_blank"
          rel="noopener noreferrer"
          className="underline decoration-dotted hover:text-ink-700 dark:hover:text-ink-200"
        >
          {s.licenseNote}
        </a>
      </p>
    </div>
  );
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-[11px] font-semibold uppercase tracking-wide text-ink-400">{label}</dt>
      <dd className="text-ink-700 dark:text-ink-300">{children}</dd>
    </div>
  );
}

function RuleDetail({
  match,
  dict,
  release,
  numberFmt,
  timeMode,
  rowAt,
  pairsAt,
  onOpenEvent,
  onAround,
  onShowInTable,
}: {
  match: SigmaMatch;
  dict: Dict;
  release: string;
  numberFmt: Intl.NumberFormat;
  timeMode: TimeMode;
  rowAt: (g: number) => SigmaExportRow;
  pairsAt: (g: number) => [string, string][];
  onOpenEvent: (g: number, ruleId: string) => void;
  onAround: (g: number) => void;
  onShowInTable: (ruleId: string) => void;
}) {
  const s = dict.sigma;
  const r = match.rule;
  const { techniques, tactics } = attackTags(r.tags);
  const url = sigmaRuleUrl(r, release);
  const otherTags = (r.tags ?? []).filter((t) => !t.toLowerCase().startsWith("attack."));

  const events = useMemo(() => {
    const list = match.gids.map((g) => ({ g, row: rowAt(g) }));
    list.sort((a, b) => a.row.timestamp.localeCompare(b.row.timestamp) || a.g - b.g);
    return list.slice(0, MAX_EVENTS);
  }, [match, rowAt]);

  const logsource = [r.logsource.product, r.logsource.category, r.logsource.service]
    .filter(Boolean)
    .join(" / ");

  return (
    <article className="flex flex-col gap-3 rounded-md border border-ink-200 p-3 dark:border-ink-800">
      <header className="flex flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`h-2.5 w-2.5 rounded-full ${SIGMA_LEVEL_DOT[r.level]}`} aria-hidden="true" />
          <span className={`font-semibold uppercase tracking-wide ${LEVEL_TEXT[r.level]}`}>
            {s.levels[r.level]}
          </span>
          {r.status && <span className="text-ink-400">· {r.status}</span>}
          {r.source === "custom" && (
            <span className="rounded border border-uv-400/50 px-1 text-[10px] text-uv-700 dark:text-uv-300">
              {s.customBadge}
            </span>
          )}
        </div>
        <h3 className="text-sm font-semibold text-ink-900 dark:text-ink-50">{r.title}</h3>
        {/* DRL 1.1: matches must identify the rule's author(s). */}
        <p className="text-ink-500">
          {s.ruleBy.replace("{author}", r.author?.trim() || "—")}
          {r.source === "sigmahq" && (
            <>
              {" · SigmaHQ · "}
              <a
                href="https://github.com/SigmaHQ/Detection-Rule-License"
                target="_blank"
                rel="noopener noreferrer"
                className="underline decoration-dotted"
              >
                DRL 1.1
              </a>
            </>
          )}
          {url && (
            <>
              {" · "}
              <a href={url} target="_blank" rel="noopener noreferrer" className="text-uv-700 underline decoration-dotted dark:text-uv-300">
                {s.viewRule}
              </a>
            </>
          )}
        </p>
      </header>

      <dl className="grid gap-3 sm:grid-cols-2">
        {r.description && (
          <div className="sm:col-span-2">
            <Section label={s.description}>
              <span className="whitespace-pre-line">{r.description}</span>
            </Section>
          </div>
        )}
        {(techniques.length > 0 || tactics.length > 0) && (
          <Section label={s.attack}>
            <span className="flex flex-wrap gap-1">
              {tactics.map((t) => (
                <span key={t} className="rounded bg-ink-100 px-1.5 py-0.5 dark:bg-ink-800">
                  {tacticLabel(t)}
                </span>
              ))}
              {techniques.map((t) => (
                <a
                  key={t}
                  href={attackUrl(t)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="rounded border border-uv-400/40 px-1.5 py-0.5 font-mono text-uv-700 hover:bg-uv-500/10 dark:text-uv-300"
                >
                  {t}
                </a>
              ))}
            </span>
          </Section>
        )}
        {r.falsepositives && r.falsepositives.length > 0 && (
          <Section label={s.falsePositives}>
            <ul className="list-disc pl-4">
              {r.falsepositives.map((f, i) => (
                <li key={i}>{f}</li>
              ))}
            </ul>
          </Section>
        )}
        {otherTags.length > 0 && (
          <Section label={s.tags}>
            <span className="font-mono">{otherTags.join(", ")}</span>
          </Section>
        )}
        <Section label={s.logsource}>
          <span className="font-mono">{logsource || "—"}</span>
        </Section>
        <Section label={s.ruleId}>
          <span className="break-all font-mono">{r.id}</span>
        </Section>
        {(r.date || r.modified) && (
          <Section label={s.date}>
            <span className="font-mono">
              {r.date}
              {r.modified && r.modified !== r.date ? ` → ${r.modified}` : ""}
            </span>
          </Section>
        )}
        {r.source === "sigmahq" && (
          <Section label={s.license}>
            <a
              href="https://github.com/SigmaHQ/Detection-Rule-License"
              target="_blank"
              rel="noopener noreferrer"
              className="underline decoration-dotted"
            >
              Detection Rule License (DRL) 1.1
            </a>
          </Section>
        )}
        {r.references && r.references.length > 0 && (
          <div className="sm:col-span-2">
            <Section label={s.references}>
              <ul className="flex flex-col gap-0.5">
                {r.references.map((ref) => (
                  <li key={ref} className="truncate">
                    {/^https?:\/\//.test(ref) ? (
                      <a href={ref} target="_blank" rel="noopener noreferrer" className="text-uv-700 underline decoration-dotted dark:text-uv-300">
                        {ref}
                      </a>
                    ) : (
                      ref
                    )}
                  </li>
                ))}
              </ul>
            </Section>
          </div>
        )}
      </dl>

      <div className="flex flex-wrap items-center gap-2">
        <h4 className="font-semibold text-ink-700 dark:text-ink-200">
          {s.matchedEvents}{" "}
          <span className="font-mono font-normal text-ink-400">{numberFmt.format(match.gids.length)}</span>
        </h4>
        <button
          type="button"
          onClick={() => onShowInTable(r.id)}
          className="ml-auto rounded-md border border-uv-500/40 bg-uv-500/10 px-2 py-1 font-medium text-uv-700 hover:bg-uv-500/20 dark:text-uv-300"
        >
          {s.showInTable}
        </button>
      </div>
      <div className="-mx-3 overflow-x-auto sm:mx-0">
        <table className="w-full text-left font-mono text-[11px]">
          <thead className="text-ink-400">
            <tr>
              <th className="px-2 py-1 font-normal">{dict.table.time}</th>
              <th className="px-2 py-1 font-normal">{dict.table.computer}</th>
              <th className="px-2 py-1 font-normal">{dict.table.eventId}</th>
              <th className="px-2 py-1 font-normal">{s.keyFields}</th>
              <th className="px-2 py-1" />
            </tr>
          </thead>
          <tbody>
            {events.map(({ g, row }) => {
              const kf = keyFields(match, row, pairsAt(g));
              return (
                <tr key={g} className="border-t border-ink-100 align-top dark:border-ink-800">
                  <td className="whitespace-nowrap px-2 py-1">
                    <button
                      type="button"
                      onClick={() => onOpenEvent(g, r.id)}
                      title={s.openEvent}
                      className="text-uv-700 underline decoration-dotted hover:text-uv-900 dark:text-uv-300"
                    >
                      {formatTimestamp(row.timestamp, timeMode).slice(0, 19)}
                    </button>
                  </td>
                  <td className="whitespace-nowrap px-2 py-1">{row.computer}</td>
                  <td className="px-2 py-1">{row.event_id}</td>
                  <td className="max-w-[40ch] px-2 py-1">
                    <span className="line-clamp-2 break-all text-ink-600 dark:text-ink-400" title={kf.map(([k, v]) => `${k}=${v}`).join("\n")}>
                      {kf.slice(0, 3).map(([k, v]) => (
                        <span key={k} className="mr-2">
                          <span className="text-ink-400">{k}=</span>
                          {v}
                        </span>
                      ))}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-2 py-1 text-right">
                    <button
                      type="button"
                      onClick={() => onAround(g)}
                      className="rounded border border-ink-200 px-1.5 py-0.5 text-ink-600 hover:border-uv-400 dark:border-ink-700 dark:text-ink-300"
                    >
                      {s.around}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {match.gids.length > MAX_EVENTS && (
        <p className="text-ink-500">
          {fill(s.moreEvents, {
            shown: numberFmt.format(MAX_EVENTS),
            total: numberFmt.format(match.gids.length),
          })}
        </p>
      )}
    </article>
  );
}
