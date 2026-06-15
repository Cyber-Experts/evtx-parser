"use client";

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { track } from "@vercel/analytics";

import {
  EvtxClient,
  type EventIdCount,
  type EventRow,
} from "@/lib/evtx-client";
import { eventName, summaryFieldsFor } from "@/lib/event-info";
import { Timeline } from "@/components/Timeline";
import { FilterBuilder, type FilterFacets } from "@/components/FilterBuilder";
import {
  type Group,
  emptyRoot,
  evaluateNode,
  hasConditions,
} from "@/lib/filter-query";
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

// One parsed EVTX file kept in the session. `id` addresses the file's handle
// in the worker (lazy XML); `rows`/`pairs` are the file-local parse results.
type LoadedFile = {
  id: number;
  name: string;
  size: number;
  rows: EventRow[];
  pairs: [string, string][][];
  topEventIds: EventIdCount[];
};

// A row in the merged, cross-file view. `_g` is the global index into the
// merged `allRows`/`allPairs` arrays (React key + EventData lookup); `_fileId`
// + `_idx` address the source file's worker handle for lazy XML; `_file` is the
// source file name (Source column / export).
type IndexedRow = EventRow & {
  _g: number;
  _fileId: number;
  _idx: number;
  _file: string;
};

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

// Coarse file-size bucket for analytics. We never send the byte count, file
// name, or any record content — only which order-of-magnitude bracket the
// upload fell into, so we can understand typical workload sizes.
function sizeBucket(bytes: number): string {
  if (bytes < 1024 * 1024) return "<1MB";
  if (bytes < 10 * 1024 * 1024) return "1-10MB";
  if (bytes < 100 * 1024 * 1024) return "10-100MB";
  return ">100MB";
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

function rowMatchesText(row: IndexedRow, needle: string): boolean {
  if (!needle) return true;
  const n = needle.toLowerCase();
  if (row.event_id != null && String(row.event_id).includes(n)) return true;
  if (row.provider?.toLowerCase().includes(n)) return true;
  if (row.channel?.toLowerCase().includes(n)) return true;
  if (row.computer?.toLowerCase().includes(n)) return true;
  if (row._file.toLowerCase().includes(n)) return true;
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
  rows: IndexedRow[],
  parsed: Record<string, string>[],
  dict: Dict,
  includeXml: boolean,
  xmls: string[],
  includeSource: boolean,
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
    ...(includeSource ? [dict.table.source] : []),
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
      ...(includeSource ? [r._file] : []),
      ...dataKeys.map((k) => p[k] ?? ""),
      ...(includeXml ? [xmls[i] ?? ""] : []),
    ]
      .map(csvEscape)
      .join(",");
  });
  return "﻿" + [header.map(csvEscape).join(","), ...lines].join("\n");
}

function buildJson(
  rows: IndexedRow[],
  parsed: Record<string, string>[],
  xmls: string[],
  includeSource: boolean,
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
      ...(includeSource ? { source_file: r._file } : {}),
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
  | "computer"
  | "source";
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
    case "source":
      // Source is compared directly in compareRows (needs the row's file name),
      // never via sortKey; this case only satisfies exhaustiveness.
      return "";
  }
}

function compareRows(
  a: IndexedRow,
  b: IndexedRow,
  field: SortField,
  dir: SortDir,
): number {
  let cmp: number;
  if (field === "source") {
    cmp = a._file.localeCompare(b._file);
  } else {
    const ka = sortKey(a, field);
    const kb = sortKey(b, field);
    if (typeof ka === "number" && typeof kb === "number") cmp = ka - kb;
    else cmp = String(ka).localeCompare(String(kb));
  }
  // Stable tiebreak by global order (file order, then record order within file)
  // so rows from the same file stay grouped and the sort never jitters.
  if (cmp === 0) cmp = a._g - b._g;
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
  // Files accumulate across uploads (multi-file import): each pick/drop appends
  // to the session. `loading` holds the current progress label while parsing.
  const [files, setFiles] = useState<LoadedFile[]>([]);
  const fileIdRef = useRef(1);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [filter, setFilter] = useState("");
  const [activeLevels, setActiveLevels] = useState<Set<number>>(new Set());
  const [activeEventIds, setActiveEventIds] = useState<Set<number>>(new Set());
  const [activeProviders, setActiveProviders] = useState<Set<string>>(new Set());
  const [activeChannels, setActiveChannels] = useState<Set<string>>(new Set());
  // Structured query builder (EventData + nested AND/OR), ANDed on top of the
  // quick chips/text/timeline above.
  const [query, setQuery] = useState<Group>(() => emptyRoot());
  const [showBuilder, setShowBuilder] = useState(false);
  const [openRow, setOpenRow] = useState<{
    g: number;
    fileId: number;
    localIdx: number;
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

  // Parse one or more files and append them to the session. Files are parsed
  // sequentially (the worker holds one WASM instance) and each becomes its own
  // handle so later XML lookups stay lazy and per-file.
  const handleFiles = useCallback(
    async (incoming: File[]) => {
      const evtxFiles = incoming.filter((f) => /\.evtx$/i.test(f.name));
      if (evtxFiles.length === 0) return;
      setError(null);
      // A new upload changes the dataset, so drop transient view state but keep
      // the user's text/level filters — they still make sense across files.
      setOpenRow(null);
      setTimeRange(null);
      setScrollTop(0);
      if (scrollRef.current) scrollRef.current.scrollTop = 0;
      try {
        if (!clientRef.current) clientRef.current = new EvtxClient();
        const client = clientRef.current;
        for (const file of evtxFiles) {
          setLoading(t.home.statusReading.replace("{name}", file.name));
          const buffer = await file.arrayBuffer();
          setLoading(t.home.statusParsing);
          const id = fileIdRef.current++;
          const { rows, topEventIds } = await client.load(id, buffer);
          let pairs: [string, string][][] = [];
          if (rows.length > 0) {
            try {
              const indices = Array.from({ length: rows.length }, (_, i) => i);
              const res = await client.eventDataBatch(id, indices);
              pairs = res.pairs;
            } catch {
              pairs = rows.map(() => []);
            }
          }
          setFiles((prev) => [
            ...prev,
            { id, name: file.name, size: file.size, rows, pairs, topEventIds },
          ]);
          // High-intent event: the visitor actually parsed a log. Only coarse,
          // non-identifying signal — size bucket + record count, once per file.
          // No file name, no bytes, no record content ever leaves the browser.
          track("parse_file", {
            size_bucket: sizeBucket(file.size),
            records: rows.length,
          });
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setLoading(null);
      }
    },
    [t.home.statusReading, t.home.statusParsing],
  );

  const removeFile = useCallback((id: number) => {
    setFiles((prev) => prev.filter((f) => f.id !== id));
    clientRef.current?.free(id);
    setOpenRow(null);
    setTimeRange(null);
  }, []);

  const clearAll = useCallback(() => {
    setFiles((prev) => {
      for (const f of prev) clientRef.current?.free(f.id);
      return [];
    });
    setOpenRow(null);
    setTimeRange(null);
    setFilter("");
    setActiveLevels(new Set());
    setActiveEventIds(new Set());
    setActiveProviders(new Set());
    setActiveChannels(new Set());
    setQuery(emptyRoot());
    setError(null);
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const dropped = Array.from(e.dataTransfer.files ?? []);
      if (dropped.length) handleFiles(dropped);
    },
    [handleFiles],
  );

  // Merge every loaded file's EventData into one array aligned with `allRows`
  // by global index (`_g`), so lazy lookups index straight into it.
  const allPairs = useMemo<[string, string][][]>(() => {
    const out: [string, string][][] = [];
    for (const f of files) for (const p of f.pairs) out.push(p);
    return out;
  }, [files]);

  const toggleDetailsFor = useCallback(
    (row: IndexedRow) => {
      if (openRow?.g === row._g) {
        setOpenRow(null);
        return;
      }
      const pairs = allPairs[row._g] ?? [];
      setOpenRow({
        g: row._g,
        fileId: row._fileId,
        localIdx: row._idx,
        pairs,
        xml: null,
        showXml: false,
      });
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
      const { xml } = await client.xml(current.fileId, current.localIdx);
      setOpenRow({ ...current, xml, showXml: true });
    } catch (err) {
      setOpenRow({
        ...current,
        xml: err instanceof Error ? err.message : String(err),
        showXml: true,
      });
    }
  }, [openRow]);

  // Faceted multi-select: each chip toggles its value in a Set. Rows match if
  // they satisfy ANY value within a category (OR) and EVERY active category
  // (AND), matching the long-standing behaviour of the level buttons.
  const toggleFacet = useCallback(
    <T,>(setter: React.Dispatch<React.SetStateAction<Set<T>>>, value: T) => {
      setter((prev) => {
        const next = new Set(prev);
        if (next.has(value)) next.delete(value);
        else next.add(value);
        return next;
      });
      setOpenRow(null);
      if (scrollRef.current) scrollRef.current.scrollTop = 0;
    },
    [],
  );

  const toggleLevel = useCallback(
    (value: number) => toggleFacet(setActiveLevels, value),
    [toggleFacet],
  );

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

  // Merge every loaded file's rows into one cross-file view. `_g` is the global
  // position (and React key); `_fileId`/`_idx` keep the link back to the source
  // file's worker handle for lazy XML.
  const allRows = useMemo<IndexedRow[]>(() => {
    const out: IndexedRow[] = [];
    let g = 0;
    for (const f of files) {
      for (let i = 0; i < f.rows.length; i++) {
        out.push({ ...f.rows[i], _g: g++, _fileId: f.id, _idx: i, _file: f.name });
      }
    }
    return out;
  }, [files]);

  const ready = files.length > 0;
  const multiFile = files.length > 1;
  const totalSize = useMemo(
    () => files.reduce((s, f) => s + f.size, 0),
    [files],
  );

  // Top Event IDs across all files. Each file's list is pre-capped at 50, so the
  // long tail is approximate, but the high-count IDs that matter are exact.
  const topEventIds = useMemo<EventIdCount[]>(() => {
    if (files.length <= 1) return files[0]?.topEventIds ?? [];
    const m = new Map<number, number>();
    for (const f of files) {
      for (const [id, c] of f.topEventIds) m.set(id, (m.get(id) ?? 0) + c);
    }
    return [...m.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 50) as EventIdCount[];
  }, [files]);

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

  // Distinct values for the query builder's autocomplete. Capped so a wildly
  // heterogeneous file can't blow up the suggestion lists.
  const facets = useMemo<FilterFacets>(() => {
    const providers = new Set<string>();
    const channels = new Set<string>();
    const computers = new Set<string>();
    const fileNames = new Set<string>();
    const eventNames = new Set<string>();
    for (const r of allRows) {
      if (r.provider) providers.add(r.provider);
      if (r.channel) channels.add(r.channel);
      if (r.computer) computers.add(r.computer);
      fileNames.add(r._file);
      const name = eventName(r.event_id, r.provider);
      if (name) eventNames.add(name);
    }
    const keys = new Set<string>();
    for (const pairs of allPairs) {
      for (const [k] of pairs) {
        keys.add(k);
        if (keys.size >= 200) break;
      }
      if (keys.size >= 200) break;
    }
    return {
      providers: [...providers].sort(),
      channels: [...channels].sort(),
      computers: [...computers].sort(),
      files: [...fileNames].sort(),
      eventNames: [...eventNames].sort(),
      eventDataKeys: [...keys].sort(),
      valuesForKey: (key: string) => {
        const k = key.toLowerCase();
        const vals = new Set<string>();
        for (const pairs of allPairs) {
          for (const [pk, pv] of pairs) {
            if (pk.toLowerCase() === k && pv) vals.add(pv);
          }
          if (vals.size >= 100) break;
        }
        return [...vals].sort();
      },
    };
  }, [allRows, allPairs]);

  const queryActive = hasConditions(query);

  const filteredRows = useMemo(() => {
    if (
      !filter &&
      activeLevels.size === 0 &&
      activeEventIds.size === 0 &&
      activeProviders.size === 0 &&
      activeChannels.size === 0 &&
      !timeRange &&
      !queryActive
    )
      return allRows;
    return allRows.filter((r) => {
      if (activeLevels.size > 0 && (r.level == null || !activeLevels.has(r.level)))
        return false;
      if (
        activeEventIds.size > 0 &&
        (r.event_id == null || !activeEventIds.has(r.event_id))
      )
        return false;
      if (activeProviders.size > 0 && (!r.provider || !activeProviders.has(r.provider)))
        return false;
      if (activeChannels.size > 0 && (!r.channel || !activeChannels.has(r.channel)))
        return false;
      if (filter && !rowMatchesText(r, filter)) return false;
      if (timeRange) {
        const t = Date.parse(r.timestamp);
        if (t < timeRange[0] || t >= timeRange[1]) return false;
      }
      if (queryActive && !evaluateNode(query, r, allPairs[r._g] ?? [])) return false;
      return true;
    });
  }, [
    allRows,
    allPairs,
    filter,
    activeLevels,
    activeEventIds,
    activeProviders,
    activeChannels,
    timeRange,
    query,
    queryActive,
  ]);

  const setFilterAndResetScroll = useCallback((next: string) => {
    setFilter(next);
    setOpenRow(null);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, []);

  const handleQueryChange = useCallback((next: Group) => {
    setQuery(next);
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
      const openIdx = sortedRows.findIndex((r) => r._g === openRow.g);
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
      if (!ready) return;
      const client = clientRef.current;
      if (!client) return;
      setExporting(true);
      try {
        const parsed = filteredRows.map((r) =>
          pairsToRecord(allPairs[r._g] ?? []),
        );
        let xmls: string[] = [];
        if (includeXml || kind === "json") {
          // XML lives in per-file handles, so fetch one batch per source file
          // then reassemble in the filtered-row order the export expects.
          const byFile = new Map<number, number[]>();
          for (const r of filteredRows) {
            const arr = byFile.get(r._fileId) ?? [];
            arr.push(r._idx);
            byFile.set(r._fileId, arr);
          }
          const lookup = new Map<number, Map<number, string>>();
          for (const [fileId, localIdxs] of byFile) {
            const m = new Map<number, string>();
            try {
              const res = await client.xmlBatch(fileId, localIdxs);
              localIdxs.forEach((li, k) => m.set(li, res.xmls[k] ?? ""));
            } catch {
              // leave this file's rows with empty XML
            }
            lookup.set(fileId, m);
          }
          xmls = filteredRows.map(
            (r) => lookup.get(r._fileId)?.get(r._idx) ?? "",
          );
        }
        // High-intent event: the visitor exported their triage results.
        // Only format, row count, file count, and the include-XML toggle —
        // never the file name or any exported record content.
        track("export_events", {
          format: kind,
          rows: filteredRows.length,
          files: files.length,
          include_xml: kind === "json" ? true : includeXml,
        });
        const base =
          files.length === 1 ? exportBaseName(files[0].name) : "evtx-events";
        if (kind === "csv") {
          download(
            `${base}.csv`,
            "text/csv;charset=utf-8",
            buildCsv(filteredRows, parsed, t, includeXml, xmls, multiFile),
          );
        } else {
          download(
            `${base}.json`,
            "application/json",
            buildJson(filteredRows, parsed, xmls, multiFile),
          );
        }
      } finally {
        setExporting(false);
      }
    },
    [ready, files, multiFile, filteredRows, t, includeXml, allPairs],
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
      const pairs = allPairs[r._g];
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
  // (+ source when multiple files) + extra (summary or dynamic) + 1 details button
  const baseColCount = multiFile ? 9 : 8;
  const tableColCount = baseColCount + extraColCount + 1;

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
          multiple
          className="hidden"
          onChange={(e) => {
            const picked = Array.from(e.target.files ?? []);
            // Reset so re-selecting the same file still fires onChange.
            e.target.value = "";
            if (picked.length) handleFiles(picked);
          }}
        />
      </label>

      {loading && (
        <div className="text-sm text-zinc-600 dark:text-zinc-400">
          {loading}
        </div>
      )}

      {error && (
        <div className="rounded-md border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-200">
          {error}
        </div>
      )}

      {ready && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
            <div className="flex flex-wrap items-center gap-1.5">
              {files.map((f) => (
                <span
                  key={f.id}
                  className="flex items-center gap-1.5 rounded-md border border-zinc-300 bg-zinc-50 py-1 pl-2 pr-1 text-xs dark:border-zinc-700 dark:bg-zinc-900"
                >
                  <span
                    className="max-w-[24ch] truncate font-mono text-zinc-900 dark:text-zinc-100"
                    title={f.name}
                  >
                    {f.name}
                  </span>
                  <span className="font-mono text-zinc-400">
                    {numberFmt.format(f.rows.length)}
                  </span>
                  <button
                    type="button"
                    onClick={() => removeFile(f.id)}
                    aria-label={t.home.removeFile}
                    title={t.home.removeFile}
                    className="rounded px-1 leading-none text-zinc-400 hover:bg-zinc-200 hover:text-zinc-900 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
                  >
                    ×
                  </button>
                </span>
              ))}
              {multiFile && (
                <button
                  type="button"
                  onClick={clearAll}
                  className="rounded-md border border-zinc-200 px-2 py-1 text-xs text-zinc-600 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-900"
                >
                  {t.home.clearAll}
                </button>
              )}
            </div>
            <div className="text-zinc-600 dark:text-zinc-400">
              {formatBytes(totalSize)} ·{" "}
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

          {topEventIds.length > 0 && (
            <div className="flex flex-wrap gap-1.5 font-mono text-xs text-zinc-500">
              <span className="text-zinc-400">{t.home.topIds}:</span>
              {topEventIds.slice(0, 12).map(([id, count]) => {
                const active = activeEventIds.has(id);
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => toggleFacet(setActiveEventIds, id)}
                    aria-pressed={active}
                    className={`rounded border px-1.5 py-0.5 transition-colors ${
                      active
                        ? "border-zinc-900 bg-zinc-900 text-zinc-50 dark:border-zinc-100 dark:bg-zinc-100 dark:text-zinc-900"
                        : "border-zinc-200 hover:border-zinc-400 dark:border-zinc-800 dark:hover:border-zinc-600"
                    }`}
                    title={`${count} events`}
                  >
                    {id}
                    <span className={`ml-1 ${active ? "text-zinc-300 dark:text-zinc-600" : "text-zinc-400"}`}>
                      ×{count}
                    </span>
                  </button>
                );
              })}
            </div>
          )}

          {topProviders.length > 0 && (
            <div className="flex flex-wrap gap-1.5 font-mono text-xs text-zinc-500">
              <span className="text-zinc-400">{t.table.provider}:</span>
              {topProviders.map(([name, count]) => {
                const active = activeProviders.has(name);
                return (
                  <button
                    key={name}
                    type="button"
                    onClick={() => toggleFacet(setActiveProviders, name)}
                    aria-pressed={active}
                    className={`max-w-[20ch] truncate rounded border px-1.5 py-0.5 transition-colors ${
                      active
                        ? "border-zinc-900 bg-zinc-900 text-zinc-50 dark:border-zinc-100 dark:bg-zinc-100 dark:text-zinc-900"
                        : "border-zinc-200 hover:border-zinc-400 dark:border-zinc-800 dark:hover:border-zinc-600"
                    }`}
                    title={`${name} · ${count} events`}
                  >
                    {name}
                    <span className={`ml-1 ${active ? "text-zinc-300 dark:text-zinc-600" : "text-zinc-400"}`}>
                      ×{count}
                    </span>
                  </button>
                );
              })}
            </div>
          )}

          {topChannels.length > 0 && (
            <div className="flex flex-wrap gap-1.5 font-mono text-xs text-zinc-500">
              <span className="text-zinc-400">{t.table.channel}:</span>
              {topChannels.map(([name, count]) => {
                const active = activeChannels.has(name);
                return (
                  <button
                    key={name}
                    type="button"
                    onClick={() => toggleFacet(setActiveChannels, name)}
                    aria-pressed={active}
                    className={`max-w-[24ch] truncate rounded border px-1.5 py-0.5 transition-colors ${
                      active
                        ? "border-zinc-900 bg-zinc-900 text-zinc-50 dark:border-zinc-100 dark:bg-zinc-100 dark:text-zinc-900"
                        : "border-zinc-200 hover:border-zinc-400 dark:border-zinc-800 dark:hover:border-zinc-600"
                    }`}
                    title={`${name} · ${count} events`}
                  >
                    {name}
                    <span className={`ml-1 ${active ? "text-zinc-300 dark:text-zinc-600" : "text-zinc-400"}`}>
                      ×{count}
                    </span>
                  </button>
                );
              })}
            </div>
          )}

          <div className="flex flex-col gap-2">
            <button
              type="button"
              onClick={() => setShowBuilder((v) => !v)}
              aria-expanded={showBuilder}
              className="flex w-fit items-center gap-1.5 text-xs font-medium text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100"
            >
              <span className="text-zinc-400">{showBuilder ? "▾" : "▸"}</span>
              {t.filter.advanced}
              {queryActive && (
                <span className="rounded-full bg-zinc-900 px-1.5 text-[10px] text-zinc-50 dark:bg-zinc-100 dark:text-zinc-900">
                  ●
                </span>
              )}
            </button>
            {showBuilder && (
              <div className="rounded-md border border-zinc-200 p-3 dark:border-zinc-800">
                <FilterBuilder
                  query={query}
                  onChange={handleQueryChange}
                  facets={facets}
                  dict={t}
                />
              </div>
            )}
          </div>

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
                  {multiFile && (
                    <SortHeader field="source" label={t.table.source} sortField={sortField} sortDir={sortDir} onSort={toggleSort} />
                  )}
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
                  const isOpen = openRow?.g === r._g;
                  const resolvedName = eventName(r.event_id, r.provider);
                  const pairs = allPairs[r._g] ?? [];
                  return (
                    <Fragment key={r._g}>
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
                        {multiFile && (
                          <FilterableCell
                            value={r._file}
                            onFilter={setFilterAndResetScroll}
                          />
                        )}
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
                            onClick={() => toggleDetailsFor(r)}
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
