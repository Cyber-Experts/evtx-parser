"use client";

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  EvtxClient,
  type EventIdCount,
  type EventRow,
} from "@/lib/evtx-client";
import { eventName, summaryFieldsFor } from "@/lib/event-info";
import { Timeline } from "@/components/Timeline";
import type { Dict } from "@/src/dict/types";

// Virtualization: render only the rows the user can actually see plus a
// small overscan, so scrolling a 100k-event Security.evtx stays smooth.
const ROW_HEIGHT = 32; // px — measured for the existing px-3 py-1.5 cells
const OVERSCAN = 8;
const SCROLL_HEIGHT_PX = 640; // events-table viewport height
// When a row is expanded we can't easily virtualize around its variable
// height, so we widen the window around the open row instead.
const OPEN_ROW_WINDOW = 200;

const PROVIDER_CHIP_LIMIT = 8;
const CHANNEL_CHIP_LIMIT = 6;

const LEVELS: Array<{ value: number; key: keyof Dict["levels"] }> = [
  { value: 1, key: "critical" },
  { value: 2, key: "error" },
  { value: 3, key: "warning" },
  { value: 4, key: "info" },
  { value: 5, key: "verbose" },
];

type IndexedRow = EventRow & { _idx: number };

type Status =
  | { kind: "idle" }
  | { kind: "loading"; label: string }
  | {
      kind: "ready";
      fileName: string;
      fileSize: number;
      rows: IndexedRow[];
      topEventIds: EventIdCount[];
      pairs: [string, string][][];
    }
  | { kind: "error"; message: string };

// Hard cap on how many dynamic EventData columns we render when the filter
// narrows to a single Event ID. Most useful events have <8 fields; anything
// past that scrolls off-screen and stops being a "table" in a useful sense.
const MAX_DYNAMIC_COLUMNS = 12;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let n = bytes / 1024;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(1)} ${units[i]}`;
}

function levelClass(level: number | null): string {
  switch (level) {
    case 1:
      return "text-red-700 dark:text-red-400 font-medium";
    case 2:
      return "text-red-600 dark:text-red-300";
    case 3:
      return "text-amber-600 dark:text-amber-300";
    case 4:
      return "text-zinc-700 dark:text-zinc-300";
    case 5:
      return "text-zinc-500";
    default:
      return "text-zinc-400";
  }
}

function levelLabel(level: number | null, dict: Dict): string {
  switch (level) {
    case 1:
      return dict.levels.critical;
    case 2:
      return dict.levels.error;
    case 3:
      return dict.levels.warning;
    case 4:
      return dict.levels.info;
    case 5:
      return dict.levels.verbose;
    default:
      return dict.levels.unknown;
  }
}

function rowMatchesText(row: EventRow, needle: string): boolean {
  if (!needle) return true;
  const n = needle.toLowerCase();
  if (row.event_id != null && String(row.event_id).includes(n)) return true;
  if (row.provider?.toLowerCase().includes(n)) return true;
  if (row.channel?.toLowerCase().includes(n)) return true;
  if (row.computer?.toLowerCase().includes(n)) return true;
  const name = eventName(row.event_id, row.provider);
  if (name?.toLowerCase().includes(n)) return true;
  return false;
}

// Cap the number of EventData-derived columns so a heterogeneous file
// (e.g. a full Security.evtx with hundreds of distinct keys) can't produce
// a pathologically wide CSV. Analysts who want clean columns filter to a
// single Event ID first; this is just a guardrail.
const MAX_DATA_COLUMNS = 256;

function pairsToRecord(pairs: [string, string][]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of pairs) out[k] = v;
  return out;
}

function csvEscape(value: string | number | null | undefined): string {
  if (value == null) return "";
  const s = String(value);
  if (s.includes(",") || s.includes('"') || s.includes("\n") || s.includes("\r")) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function buildCsv(
  rows: EventRow[],
  parsed: Record<string, string>[],
  dict: Dict,
  includeXml: boolean,
  xmls: string[],
): string {
  const keySet = new Set<string>();
  for (const p of parsed) for (const k of Object.keys(p)) keySet.add(k);
  const dataKeys = Array.from(keySet).sort().slice(0, MAX_DATA_COLUMNS);

  const header = [
    dict.table.record,
    dict.table.time,
    dict.table.level,
    dict.table.eventId,
    dict.table.provider,
    dict.table.channel,
    dict.table.computer,
    ...dataKeys,
    ...(includeXml ? ["RawXml"] : []),
  ];
  const lines = rows.map((r, i) => {
    const p = parsed[i] ?? {};
    return [
      Number(r.record_id),
      r.timestamp,
      levelLabel(r.level, dict),
      r.event_id ?? "",
      r.provider ?? "",
      r.channel ?? "",
      r.computer ?? "",
      ...dataKeys.map((k) => p[k] ?? ""),
      ...(includeXml ? [xmls[i] ?? ""] : []),
    ]
      .map(csvEscape)
      .join(",");
  });
  return "﻿" + [header.map(csvEscape).join(","), ...lines].join("\n");
}

function buildJson(
  rows: EventRow[],
  parsed: Record<string, string>[],
  xmls: string[],
): string {
  return JSON.stringify(
    rows.map((r, i) => ({
      record_id: Number(r.record_id),
      timestamp: r.timestamp,
      level: r.level,
      event_id: r.event_id,
      provider: r.provider,
      channel: r.channel,
      computer: r.computer,
      event_data: parsed[i] ?? {},
      xml: xmls[i] ?? "",
    })),
    null,
    2,
  );
}

function download(filename: string, mime: string, body: string) {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function exportBaseName(fileName: string): string {
  return fileName.replace(/\.evtx$/i, "") || "events";
}

type SortField =
  | "record_id"
  | "timestamp"
  | "level"
  | "event_id"
  | "name"
  | "provider"
  | "channel"
  | "computer";
type SortDir = "asc" | "desc";

function sortKey(r: EventRow, field: SortField): number | string {
  switch (field) {
    case "record_id":
      return Number(r.record_id);
    case "timestamp":
      return Date.parse(r.timestamp) || 0;
    case "level":
      return r.level ?? 99;
    case "event_id":
      return r.event_id ?? -1;
    case "name":
      return (eventName(r.event_id, r.provider) ?? "").toLowerCase();
    case "provider":
      return (r.provider ?? "").toLowerCase();
    case "channel":
      return (r.channel ?? "").toLowerCase();
    case "computer":
      return (r.computer ?? "").toLowerCase();
  }
}

function compareRows(
  a: IndexedRow,
  b: IndexedRow,
  field: SortField,
  dir: SortDir,
): number {
  const ka = sortKey(a, field);
  const kb = sortKey(b, field);
  let cmp: number;
  if (typeof ka === "number" && typeof kb === "number") cmp = ka - kb;
  else cmp = String(ka).localeCompare(String(kb));
  if (cmp === 0) cmp = Number(a.record_id) - Number(b.record_id);
  return dir === "asc" ? cmp : -cmp;
}

export function EvtxUploader({
  dict,
  locale,
}: {
  dict: Dict;
  locale: string;
}) {
  const t = dict;
  const clientRef = useRef<EvtxClient | null>(null);
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [dragOver, setDragOver] = useState(false);
  const [filter, setFilter] = useState("");
  const [activeLevels, setActiveLevels] = useState<Set<number>>(new Set());
  const [openRow, setOpenRow] = useState<{
    idx: number;
    pairs: [string, string][];
    xml: string | null;
    showXml: boolean;
  } | null>(null);
  const [timeRange, setTimeRange] = useState<[number, number] | null>(null);
  const [includeXml, setIncludeXml] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [sortField, setSortField] = useState<SortField>("record_id");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [scrollTop, setScrollTop] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    return () => {
      clientRef.current?.terminate();
      clientRef.current = null;
    };
  }, []);

  const handleFile = useCallback(
    async (file: File) => {
      setStatus({
        kind: "loading",
        label: t.home.statusReading.replace("{name}", file.name),
      });
      setFilter("");
      setActiveLevels(new Set());
      setOpenRow(null);
      setTimeRange(null);
      setSortField("record_id");
      setSortDir("asc");
      setScrollTop(0);
      if (scrollRef.current) scrollRef.current.scrollTop = 0;
      try {
        const buffer = await file.arrayBuffer();
        if (!clientRef.current) clientRef.current = new EvtxClient();
        setStatus({ kind: "loading", label: t.home.statusParsing });
        const { rows, topEventIds } = await clientRef.current.load(buffer);
        const indexed: IndexedRow[] = rows.map((r, i) => ({ ...r, _idx: i }));
        let pairs: [string, string][][] = [];
        if (rows.length > 0) {
          try {
            const indices = Array.from({ length: rows.length }, (_, i) => i);
            const res = await clientRef.current.eventDataBatch(indices);
            pairs = res.pairs;
          } catch {
            pairs = rows.map(() => []);
          }
        }
        setStatus({
          kind: "ready",
          fileName: file.name,
          fileSize: file.size,
          rows: indexed,
          topEventIds,
          pairs,
        });
      } catch (err) {
        setStatus({
          kind: "error",
          message: err instanceof Error ? err.message : String(err),
        });
      }
    },
    [t.home.statusReading, t.home.statusParsing],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const allPairs = useMemo<[string, string][][]>(
    () => (status.kind === "ready" ? status.pairs : []),
    [status],
  );

  const toggleDetailsFor = useCallback(
    (idx: number) => {
      if (openRow?.idx === idx) {
        setOpenRow(null);
        return;
      }
      const pairs = allPairs[idx] ?? [];
      setOpenRow({ idx, pairs, xml: null, showXml: false });
    },
    [openRow, allPairs],
  );

  const toggleRawXml = useCallback(async () => {
    const current = openRow;
    if (!current) return;
    if (current.xml != null) {
      setOpenRow({ ...current, showXml: !current.showXml });
      return;
    }
    const client = clientRef.current;
    if (!client) return;
    try {
      const { xml } = await client.xml(current.idx);
      setOpenRow({ ...current, xml, showXml: true });
    } catch (err) {
      setOpenRow({
        ...current,
        xml: err instanceof Error ? err.message : String(err),
        showXml: true,
      });
    }
  }, [openRow]);

  const toggleLevel = useCallback((value: number) => {
    setActiveLevels((prev) => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    });
    setOpenRow(null);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, []);

  const toggleSort = useCallback((field: SortField) => {
    setSortField((prev) => {
      if (prev === field) {
        setSortDir((d) => (d === "asc" ? "desc" : "asc"));
        return prev;
      }
      setSortDir("asc");
      return field;
    });
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, []);

  const numberFmt = useMemo(() => new Intl.NumberFormat(locale), [locale]);
  const dateFmt = useMemo(
    () =>
      new Intl.DateTimeFormat(locale, {
        dateStyle: "short",
        timeStyle: "medium",
        timeZone: "UTC",
      }),
    [locale],
  );

  const allRows = useMemo<IndexedRow[]>(
    () => (status.kind === "ready" ? status.rows : []),
    [status],
  );

  const topProviders = useMemo<Array<[string, number]>>(() => {
    if (allRows.length === 0) return [];
    const counts = new Map<string, number>();
    for (const r of allRows) {
      if (!r.provider) continue;
      counts.set(r.provider, (counts.get(r.provider) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, PROVIDER_CHIP_LIMIT);
  }, [allRows]);

  const topChannels = useMemo<Array<[string, number]>>(() => {
    if (allRows.length === 0) return [];
    const counts = new Map<string, number>();
    for (const r of allRows) {
      if (!r.channel) continue;
      counts.set(r.channel, (counts.get(r.channel) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, CHANNEL_CHIP_LIMIT);
  }, [allRows]);

  const filteredRows = useMemo(() => {
    if (!filter && activeLevels.size === 0 && !timeRange) return allRows;
    return allRows.filter((r) => {
      if (activeLevels.size > 0 && (r.level == null || !activeLevels.has(r.level)))
        return false;
      if (filter && !rowMatchesText(r, filter)) return false;
      if (timeRange) {
        const t = Date.parse(r.timestamp);
        if (t < timeRange[0] || t >= timeRange[1]) return false;
      }
      return true;
    });
  }, [allRows, filter, activeLevels, timeRange]);

  const setFilterAndResetScroll = useCallback((next: string) => {
    setFilter(next);
    setOpenRow(null);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, []);

  const handleSelectTimeRange = useCallback((range: [number, number]) => {
    setTimeRange(range);
    setOpenRow(null);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, []);

  const clearTimeRange = useCallback(() => {
    setTimeRange(null);
    setOpenRow(null);
  }, []);

  // Apply current sort on top of filtering, then derive the virtual window.
  // Sorting allocates a new array; for very large filters this is the most
  // expensive step but it's still tens of ms for ~100k rows on modern CPUs.
  const sortedRows = useMemo(() => {
    const copy = filteredRows.slice();
    copy.sort((a, b) => compareRows(a, b, sortField, sortDir));
    return copy;
  }, [filteredRows, sortField, sortDir]);

  const visibleWindow = useMemo(() => {
    const total = sortedRows.length;
    if (total === 0) return { start: 0, end: 0 };
    if (openRow) {
      // Variable height from the expand panel breaks scroll-driven math, so
      // when a row is open we pin the rendered window to a chunk centered on
      // the open row. Users still see the open row plus nearby context.
      const openIdx = sortedRows.findIndex((r) => r._idx === openRow.idx);
      if (openIdx === -1) {
        return { start: 0, end: Math.min(total, OPEN_ROW_WINDOW) };
      }
      const half = Math.floor(OPEN_ROW_WINDOW / 2);
      const start = Math.max(0, openIdx - half);
      const end = Math.min(total, start + OPEN_ROW_WINDOW);
      return { start, end };
    }
    const visibleCount = Math.ceil(SCROLL_HEIGHT_PX / ROW_HEIGHT);
    const start = Math.max(
      0,
      Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN,
    );
    const end = Math.min(total, start + visibleCount + OVERSCAN * 2);
    return { start, end };
  }, [sortedRows, scrollTop, openRow]);

  const visibleRows = useMemo(
    () => sortedRows.slice(visibleWindow.start, visibleWindow.end),
    [sortedRows, visibleWindow],
  );

  const runExport = useCallback(
    async (kind: "csv" | "json") => {
      if (status.kind !== "ready") return;
      const client = clientRef.current;
      if (!client) return;
      setExporting(true);
      try {
        const idxs = filteredRows.map((r) => r._idx);
        const parsed = idxs.map((i) => pairsToRecord(allPairs[i] ?? []));
        let xmls: string[] = [];
        if (includeXml || kind === "json") {
          try {
            const res = await client.xmlBatch(idxs);
            xmls = res.xmls;
          } catch {
            xmls = idxs.map(() => "");
          }
        }
        const base = exportBaseName(status.fileName);
        if (kind === "csv") {
          download(
            `${base}.csv`,
            "text/csv;charset=utf-8",
            buildCsv(filteredRows, parsed, t, includeXml, xmls),
          );
        } else {
          download(
            `${base}.json`,
            "application/json",
            buildJson(filteredRows, parsed, xmls),
          );
        }
      } finally {
        setExporting(false);
      }
    },
    [status, filteredRows, t, includeXml, allPairs],
  );

  // If every visible (filtered) row shares the same event_id we surface the
  // EventData keys for that ID as real table columns. The key order is taken
  // from the first row that has any, so users see fields in the order Windows
  // emits them rather than alphabetically.
  const dynamicKeys = useMemo<string[] | null>(() => {
    if (filteredRows.length === 0) return null;
    const firstId = filteredRows[0].event_id;
    if (firstId == null) return null;
    for (let i = 1; i < filteredRows.length; i++) {
      if (filteredRows[i].event_id !== firstId) return null;
    }
    const seen = new Set<string>();
    const ordered: string[] = [];
    for (const r of filteredRows) {
      const pairs = allPairs[r._idx];
      if (!pairs) continue;
      for (const [k] of pairs) {
        if (!seen.has(k)) {
          seen.add(k);
          ordered.push(k);
          if (ordered.length >= MAX_DYNAMIC_COLUMNS) return ordered;
        }
      }
    }
    return ordered.length > 0 ? ordered : null;
  }, [filteredRows, allPairs]);

  const extraColCount = dynamicKeys ? dynamicKeys.length : 1;
  // Base columns: record, time, level, eventId, name, provider, channel, computer = 8
  // + extra (summary or dynamic) + 1 details button
  const tableColCount = 8 + extraColCount + 1;

  return (
    <section aria-label={t.home.dropArea} className="flex flex-col gap-4">
      <label
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        className={`flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-4 py-8 text-center text-sm transition-colors sm:px-6 sm:py-12 ${
          dragOver
            ? "border-zinc-900 bg-zinc-100 dark:border-zinc-100 dark:bg-zinc-900"
            : "border-zinc-300 hover:border-zinc-400 dark:border-zinc-700 dark:hover:border-zinc-500"
        }`}
      >
        <span className="font-medium">{t.home.dropArea}</span>
        <span className="text-zinc-500">{t.home.privacyNote}</span>
        <input
          type="file"
          accept=".evtx"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) handleFile(f);
          }}
        />
      </label>

      {status.kind === "loading" && (
        <div className="text-sm text-zinc-600 dark:text-zinc-400">
          {status.label}
        </div>
      )}

      {status.kind === "error" && (
        <div className="rounded-md border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-200">
          {status.message}
        </div>
      )}

      {status.kind === "ready" && (
        <>
          <div className="flex flex-wrap items-baseline justify-between gap-3 text-sm">
            <div className="text-zinc-600 dark:text-zinc-400">
              <span className="font-mono text-zinc-900 dark:text-zinc-100">
                {status.fileName}
              </span>{" "}
              · {formatBytes(status.fileSize)} ·{" "}
              <span className="font-mono">
                {numberFmt.format(filteredRows.length)}
              </span>{" "}
              / <span className="font-mono">{numberFmt.format(allRows.length)}</span>{" "}
              {t.home.eventsLabel}
            </div>
          </div>

          <Timeline
            rows={allRows}
            selectedRange={timeRange}
            onSelectBucket={handleSelectTimeRange}
            locale={locale}
          />

          {timeRange && (
            <div className="flex items-center gap-2 text-xs">
              <span className="rounded-md border border-zinc-300 bg-zinc-50 px-2 py-1 font-mono text-zinc-700 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
                {dateFmt.format(new Date(timeRange[0]))} → {dateFmt.format(new Date(timeRange[1]))}
              </span>
              <button
                type="button"
                onClick={clearTimeRange}
                className="rounded-md border border-zinc-200 px-2 py-1 text-zinc-600 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-900"
              >
                {t.home.clearTime}
              </button>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <input
              type="search"
              placeholder={t.home.filterPlaceholder}
              value={filter}
              onChange={(e) => setFilterAndResetScroll(e.target.value)}
              className="w-full min-w-0 flex-1 basis-full rounded-md border border-zinc-300 bg-transparent px-3 py-1.5 font-mono text-xs outline-none focus:border-zinc-500 sm:basis-64 dark:border-zinc-700 dark:focus:border-zinc-400"
            />
            {filter && (
              <button
                type="button"
                onClick={() => setFilterAndResetScroll("")}
                className="rounded-md border border-zinc-200 px-2 py-1 text-xs text-zinc-600 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-900"
              >
                {t.home.clearFilter}
              </button>
            )}
            <div className="flex flex-wrap gap-1.5">
              {LEVELS.map(({ value, key }) => {
                const active = activeLevels.has(value);
                return (
                  <button
                    key={value}
                    type="button"
                    onClick={() => toggleLevel(value)}
                    aria-pressed={active}
                    className={`rounded border px-1.5 py-0.5 font-mono text-xs transition-colors ${
                      active
                        ? "border-zinc-900 bg-zinc-900 text-zinc-50 dark:border-zinc-100 dark:bg-zinc-100 dark:text-zinc-900"
                        : "border-zinc-200 text-zinc-500 hover:border-zinc-400 dark:border-zinc-800 dark:hover:border-zinc-600"
                    }`}
                  >
                    {t.levels[key]}
                  </button>
                );
              })}
            </div>
            <div className="flex flex-wrap items-center gap-2 sm:ml-auto">
              <label className="flex items-center gap-1.5 text-zinc-500 dark:text-zinc-400">
                <input
                  type="checkbox"
                  checked={includeXml}
                  onChange={(e) => setIncludeXml(e.target.checked)}
                  className="accent-zinc-900 dark:accent-zinc-100"
                />
                {t.home.includeXml}
              </label>
              <button
                type="button"
                onClick={() => runExport("csv")}
                disabled={filteredRows.length === 0 || exporting}
                className="rounded-md border border-zinc-300 px-2 py-1 text-xs text-zinc-700 hover:bg-zinc-100 disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
              >
                {exporting ? t.home.exporting : t.home.exportCsv}
              </button>
              <button
                type="button"
                onClick={() => runExport("json")}
                disabled={filteredRows.length === 0 || exporting}
                className="rounded-md border border-zinc-300 px-2 py-1 text-xs text-zinc-700 hover:bg-zinc-100 disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
              >
                {exporting ? t.home.exporting : t.home.exportJson}
              </button>
            </div>
          </div>

          {status.topEventIds.length > 0 && (
            <div className="flex flex-wrap gap-1.5 font-mono text-xs text-zinc-500">
              <span className="text-zinc-400">{t.home.topIds}:</span>
              {status.topEventIds.slice(0, 12).map(([id, count]) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setFilterAndResetScroll(String(id))}
                  className="rounded border border-zinc-200 px-1.5 py-0.5 hover:border-zinc-400 dark:border-zinc-800 dark:hover:border-zinc-600"
                  title={`${count} events`}
                >
                  {id}
                  <span className="ml-1 text-zinc-400">×{count}</span>
                </button>
              ))}
            </div>
          )}

          {topProviders.length > 0 && (
            <div className="flex flex-wrap gap-1.5 font-mono text-xs text-zinc-500">
              <span className="text-zinc-400">{t.table.provider}:</span>
              {topProviders.map(([name, count]) => (
                <button
                  key={name}
                  type="button"
                  onClick={() => setFilterAndResetScroll(name)}
                  className="max-w-[20ch] truncate rounded border border-zinc-200 px-1.5 py-0.5 hover:border-zinc-400 dark:border-zinc-800 dark:hover:border-zinc-600"
                  title={`${name} · ${count} events`}
                >
                  {name}
                  <span className="ml-1 text-zinc-400">×{count}</span>
                </button>
              ))}
            </div>
          )}

          {topChannels.length > 0 && (
            <div className="flex flex-wrap gap-1.5 font-mono text-xs text-zinc-500">
              <span className="text-zinc-400">{t.table.channel}:</span>
              {topChannels.map(([name, count]) => (
                <button
                  key={name}
                  type="button"
                  onClick={() => setFilterAndResetScroll(name)}
                  className="max-w-[24ch] truncate rounded border border-zinc-200 px-1.5 py-0.5 hover:border-zinc-400 dark:border-zinc-800 dark:hover:border-zinc-600"
                  title={`${name} · ${count} events`}
                >
                  {name}
                  <span className="ml-1 text-zinc-400">×{count}</span>
                </button>
              ))}
            </div>
          )}

          <div
            ref={scrollRef}
            onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
            style={{ maxHeight: SCROLL_HEIGHT_PX }}
            className="-mx-4 overflow-auto border-y border-zinc-200 sm:mx-0 sm:rounded-md sm:border dark:border-zinc-800"
          >
            <table className="w-full text-left font-mono text-xs">
              <thead className="sticky top-0 z-10 bg-zinc-50 text-zinc-500 shadow-[0_1px_0_var(--tw-shadow-color)] shadow-zinc-200 dark:bg-zinc-900 dark:text-zinc-400 dark:shadow-zinc-800">
                <tr>
                  <SortHeader field="record_id" label={t.table.record} sortField={sortField} sortDir={sortDir} onSort={toggleSort} />
                  <SortHeader field="timestamp" label={t.table.time} sortField={sortField} sortDir={sortDir} onSort={toggleSort} />
                  <SortHeader field="level" label={t.table.level} sortField={sortField} sortDir={sortDir} onSort={toggleSort} />
                  <SortHeader field="event_id" label={t.table.eventId} sortField={sortField} sortDir={sortDir} onSort={toggleSort} />
                  <SortHeader field="name" label={t.table.name} sortField={sortField} sortDir={sortDir} onSort={toggleSort} />
                  <SortHeader field="provider" label={t.table.provider} sortField={sortField} sortDir={sortDir} onSort={toggleSort} />
                  <SortHeader field="channel" label={t.table.channel} sortField={sortField} sortDir={sortDir} onSort={toggleSort} />
                  <SortHeader field="computer" label={t.table.computer} sortField={sortField} sortDir={sortDir} onSort={toggleSort} />
                  {dynamicKeys ? (
                    dynamicKeys.map((k) => (
                      <th key={k} className="px-3 py-2">
                        {k}
                      </th>
                    ))
                  ) : (
                    <th className="px-3 py-2">{t.table.summary}</th>
                  )}
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody>
                {sortedRows.length === 0 && (
                  <tr>
                    <td
                      colSpan={tableColCount}
                      className="px-3 py-6 text-center text-zinc-400"
                    >
                      {t.home.noMatches}
                    </td>
                  </tr>
                )}
                {visibleWindow.start > 0 && (
                  <tr aria-hidden="true">
                    <td
                      colSpan={tableColCount}
                      style={{ height: visibleWindow.start * ROW_HEIGHT, padding: 0 }}
                    />
                  </tr>
                )}
                {visibleRows.map((r) => {
                  const isOpen = openRow?.idx === r._idx;
                  const resolvedName = eventName(r.event_id, r.provider);
                  const pairs = allPairs[r._idx] ?? [];
                  return (
                    <Fragment key={r._idx}>
                      <tr
                        className={`border-t border-zinc-100 dark:border-zinc-800 ${
                          isOpen ? "bg-zinc-50 dark:bg-zinc-950" : ""
                        }`}
                      >
                        <td className="px-3 py-1.5 text-zinc-500">
                          {Number(r.record_id)}
                        </td>
                        <td className="px-3 py-1.5 text-zinc-600 dark:text-zinc-400">
                          {dateFmt.format(new Date(r.timestamp))}
                        </td>
                        <td className={`px-3 py-1.5 ${levelClass(r.level)}`}>
                          {levelLabel(r.level, t)}
                        </td>
                        <td className="px-3 py-1.5">{r.event_id ?? ""}</td>
                        <td className="px-3 py-1.5 text-zinc-700 dark:text-zinc-300">
                          {resolvedName ?? (
                            <span className="text-zinc-400">—</span>
                          )}
                        </td>
                        <FilterableCell
                          value={r.provider}
                          onFilter={setFilterAndResetScroll}
                        />
                        <FilterableCell
                          value={r.channel}
                          onFilter={setFilterAndResetScroll}
                        />
                        <FilterableCell
                          value={r.computer}
                          onFilter={setFilterAndResetScroll}
                        />
                        {dynamicKeys ? (
                          <DynamicCells
                            keys={dynamicKeys}
                            pairs={pairs}
                            onFilter={setFilterAndResetScroll}
                          />
                        ) : (
                          <td className="px-3 py-1.5 text-zinc-700 dark:text-zinc-300">
                            <SummaryCell
                              row={r}
                              pairs={pairs}
                              onFilter={setFilterAndResetScroll}
                            />
                          </td>
                        )}
                        <td className="px-3 py-1.5">
                          <button
                            type="button"
                            onClick={() => toggleDetailsFor(r._idx)}
                            aria-expanded={isOpen}
                            className={`rounded border px-1.5 py-0.5 ${
                              isOpen
                                ? "border-zinc-900 bg-zinc-900 text-zinc-50 dark:border-zinc-100 dark:bg-zinc-100 dark:text-zinc-900"
                                : "border-zinc-200 text-zinc-500 hover:border-zinc-400 dark:border-zinc-800 dark:hover:border-zinc-600"
                            }`}
                          >
                            {isOpen ? t.table.closeDetails : t.table.viewDetails}
                          </button>
                        </td>
                      </tr>
                      {isOpen && openRow && (
                        <tr className="border-t border-zinc-100 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-950">
                          <td colSpan={tableColCount} className="p-3">
                            <div className="flex flex-col gap-3">
                              <DetailsPanel
                                pairs={openRow.pairs}
                                dict={t}
                                onFilter={setFilterAndResetScroll}
                              />
                              <div>
                                <button
                                  type="button"
                                  onClick={toggleRawXml}
                                  className="rounded-md border border-zinc-200 px-2 py-1 text-xs text-zinc-600 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-900"
                                >
                                  {openRow.showXml
                                    ? t.table.hideRawXml
                                    : t.table.showRawXml}
                                </button>
                              </div>
                              {openRow.showXml && openRow.xml != null && (
                                <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded border border-zinc-200 bg-white p-3 font-mono text-[11px] leading-relaxed text-zinc-700 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-300">
                                  {openRow.xml}
                                </pre>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
                {visibleWindow.end < sortedRows.length && (
                  <tr aria-hidden="true">
                    <td
                      colSpan={tableColCount}
                      style={{
                        height:
                          (sortedRows.length - visibleWindow.end) * ROW_HEIGHT,
                        padding: 0,
                      }}
                    />
                  </tr>
                )}
              </tbody>
            </table>
          </div>

        </>
      )}
    </section>
  );
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function SortHeader({
  field,
  label,
  sortField,
  sortDir,
  onSort,
}: {
  field: SortField;
  label: string;
  sortField: SortField;
  sortDir: SortDir;
  onSort: (field: SortField) => void;
}) {
  const active = sortField === field;
  const indicator = active ? (sortDir === "asc" ? "↑" : "↓") : "";
  return (
    <th className="px-3 py-2">
      <button
        type="button"
        onClick={() => onSort(field)}
        className={`flex items-center gap-1 text-left hover:text-zinc-900 dark:hover:text-zinc-100 ${
          active ? "text-zinc-900 dark:text-zinc-100" : ""
        }`}
      >
        <span>{label}</span>
        <span className="text-[10px]">{indicator}</span>
      </button>
    </th>
  );
}

function FilterableCell({
  value,
  onFilter,
}: {
  value: string | null | undefined;
  onFilter: (v: string) => void;
}) {
  if (!value) {
    return <td className="px-3 py-1.5 text-zinc-400">—</td>;
  }
  return (
    <td className="px-3 py-1.5 text-zinc-600 dark:text-zinc-400">
      <button
        type="button"
        onClick={() => onFilter(value)}
        title={value}
        className="max-w-[24ch] truncate text-left hover:text-zinc-900 hover:underline dark:hover:text-zinc-100"
      >
        {value}
      </button>
    </td>
  );
}

function SummaryCell({
  row,
  pairs,
  onFilter,
}: {
  row: EventRow;
  pairs: [string, string][];
  onFilter: (v: string) => void;
}) {
  const fields = summaryFieldsFor(row.event_id, row.provider);
  if (pairs.length === 0) {
    return <span className="text-zinc-400">—</span>;
  }
  const map = new Map(pairs);
  let picks: Array<[string, string]> = fields
    .map((k): [string, string] | null => {
      const v = map.get(k);
      return v != null && v !== "" ? [k, v] : null;
    })
    .filter((x): x is [string, string] => x !== null);
  if (picks.length === 0) {
    picks = pairs.filter(([, v]) => v !== "").slice(0, 2);
  }
  if (picks.length === 0) {
    return <span className="text-zinc-400">—</span>;
  }
  return (
    <span className="flex flex-wrap gap-x-3 gap-y-0.5">
      {picks.map(([k, v]) => (
        <span key={k} className="whitespace-nowrap">
          <span className="text-zinc-400">{k}=</span>
          <button
            type="button"
            onClick={() => onFilter(v)}
            title={`Filter: ${v}`}
            className="hover:text-zinc-900 hover:underline dark:hover:text-zinc-100"
          >
            {truncate(v, 60)}
          </button>
        </span>
      ))}
    </span>
  );
}

function DynamicCells({
  keys,
  pairs,
  onFilter,
}: {
  keys: string[];
  pairs: [string, string][];
  onFilter: (v: string) => void;
}) {
  const map = new Map(pairs);
  return (
    <>
      {keys.map((k) => {
        const v = map.get(k);
        return (
          <td
            key={k}
            className="px-3 py-1.5 text-zinc-700 dark:text-zinc-300"
            title={v ?? ""}
          >
            {v != null && v !== "" ? (
              <button
                type="button"
                onClick={() => onFilter(v)}
                title={`Filter: ${v}`}
                className="max-w-[28ch] truncate text-left hover:text-zinc-900 hover:underline dark:hover:text-zinc-100"
              >
                {truncate(v, 80)}
              </button>
            ) : (
              <span className="text-zinc-400">—</span>
            )}
          </td>
        );
      })}
    </>
  );
}

function DetailsPanel({
  pairs,
  dict,
  onFilter,
}: {
  pairs: [string, string][];
  dict: Dict;
  onFilter: (v: string) => void;
}) {
  if (pairs.length === 0) {
    return (
      <div className="text-xs italic text-zinc-500">
        {dict.table.noEventData}
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-1">
      <div className="text-[10px] uppercase tracking-wide text-zinc-400">
        {dict.table.eventData}
      </div>
      <div className="overflow-x-auto rounded border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-950">
        <table className="w-full border-collapse text-left font-mono text-[11px]">
          <tbody>
            {pairs.map(([k, v], i) => (
              <tr
                key={`${k}-${i}`}
                className="border-b border-zinc-100 last:border-b-0 dark:border-zinc-900"
              >
                <td className="w-1 whitespace-nowrap px-2 py-1 align-top text-zinc-500">
                  {k}
                </td>
                <td className="break-all px-2 py-1 align-top text-zinc-800 dark:text-zinc-200">
                  {v ? (
                    <button
                      type="button"
                      onClick={() => onFilter(v)}
                      title={`Filter: ${v}`}
                      className="text-left hover:underline"
                    >
                      {v}
                    </button>
                  ) : (
                    <span className="text-zinc-400">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
