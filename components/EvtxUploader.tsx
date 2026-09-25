"use client";

import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { track } from "@vercel/analytics";

import {
  EvtxClient,
  type EventIdCount,
  type EventRow,
} from "@/lib/evtx-client";
import { eventName, summaryFieldsFor } from "@/lib/event-info";
import { runDetections, type Finding, type Severity } from "@/lib/detections";
import { Timeline } from "@/components/Timeline";
import { FilterBuilder, type FilterFacets } from "@/components/FilterBuilder";
import {
  type Group,
  emptyRoot,
  evaluateNode,
  hasConditions,
} from "@/lib/filter-query";
import {
  META_FIELD_NAMES,
  MULTI_FIELDS,
  PREFERRED_FIELDS,
  compileSearch,
  haystackFor,
  highlightTerms,
  parseSearch,
  withClause,
  withoutClause,
} from "@/lib/search-query";
import { SearchBox } from "@/components/viewer/SearchBox";
import { HuntsMenu } from "@/components/viewer/HuntsMenu";
import type { Locale } from "@/src/dict/locales";
import { FacetSidebar } from "@/components/viewer/FacetSidebar";
import {
  HighlightContext,
  Hl,
  buildHighlightRegExp,
} from "@/components/viewer/Highlight";
import { decodeValue, describeEvent } from "@/lib/event-decode";
import {
  formatEpoch,
  formatTimestamp,
  zoneLabel,
  type TimeMode,
} from "@/lib/time";
import { CopyPathButton } from "@/components/CopyPathButton";
import { copyText } from "@/lib/clipboard";
import type { Dict } from "@/src/dict/types";

// Virtualization: render only the rows the user can actually see plus a
// small overscan, so scrolling a 100k-event Security.evtx stays smooth.
const ROW_HEIGHT = 32; // px — measured for the existing px-3 py-1.5 cells
const OVERSCAN = 8;
const SCROLL_HEIGHT_PX = 640; // events-table viewport height
// When a row is expanded we can't easily virtualize around its variable
// height, so we widen the window around the open row instead.
const OPEN_ROW_WINDOW = 200;


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

// Lazily built, per-dataset caches for search. Kept outside the component so
// the memoized closures own their mutable cache.
function makeHaystackIndex(allPairs: [string, string][][]) {
  const cache: string[] = [];
  return (r: IndexedRow): string =>
    (cache[r._g] ??= haystackFor(r, allPairs[r._g] ?? []));
}

const META_VALUE: Record<string, (r: IndexedRow) => string | null> = {
  eventid: (r) => (r.event_id == null ? null : String(r.event_id)),
  level: (r) => (r.level == null ? null : String(r.level)),
  provider: (r) => r.provider,
  channel: (r) => r.channel,
  computer: (r) => r.computer,
  file: (r) => r._file,
};

/** Distinct values of a field (lower-cased name), most frequent first. */
function makeValueIndex(rows: IndexedRow[], allPairs: [string, string][][]) {
  const cache = new Map<string, [string, number][]>();
  return (field: string): [string, number][] => {
    const hit = cache.get(field);
    if (hit) return hit;
    const counts = new Map<string, number>();
    const bump = (v: string | null | undefined) => {
      if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
    };
    const meta = META_VALUE[field];
    if (meta) {
      for (const r of rows) bump(meta(r));
    } else {
      const keys = MULTI_FIELDS[field] ?? [field];
      for (const pairs of allPairs)
        for (const [k, v] of pairs) if (keys.includes(k.toLowerCase())) bump(v);
    }
    const out = [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 200);
    cache.set(field, out);
    return out;
  };
}

// Cap the number of EventData-derived columns so a heterogeneous file
// (e.g. a full Security.evtx with hundreds of distinct keys) can't produce
// a pathologically wide CSV. Analysts who want clean columns filter to a
// single Event ID first; this is just a guardrail.
const MAX_DATA_COLUMNS = 256;

function pairsOf(rec: Record<string, string>): [string, string][] {
  return Object.entries(rec);
}

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
    dict.viewer.description,
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
      describeEvent(r.event_id, r.provider, pairsOf(p)) ?? "",
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
      description: describeEvent(r.event_id, r.provider, pairsOf(parsed[i] ?? {})),
      event_data: parsed[i] ?? {},
      xml: xmls[i] ?? "",
    })),
    null,
    2,
  );
}

function buildTxt(
  rows: IndexedRow[],
  parsed: Record<string, string>[],
  dict: Dict,
  includeXml: boolean,
  xmls: string[],
  includeSource: boolean,
): string {
  // Plain-text export: one readable block per event, blank line between
  // events — greppable and pasteable into a report or ticket.
  const blocks = rows.map((r, i) => {
    const lines = [
      `${dict.table.record}${Number(r.record_id)} | ${r.timestamp} | ${levelLabel(r.level, dict)} | ${dict.table.eventId} ${r.event_id ?? ""}`,
      `${dict.table.provider}: ${r.provider ?? ""}`,
      `${dict.table.channel}: ${r.channel ?? ""}`,
      `${dict.table.computer}: ${r.computer ?? ""}`,
    ];
    if (includeSource) lines.push(`${dict.table.source}: ${r._file}`);
    const desc = describeEvent(r.event_id, r.provider, pairsOf(parsed[i] ?? {}));
    if (desc) lines.push(`${dict.viewer.description}: ${desc}`);
    for (const [k, v] of Object.entries(parsed[i] ?? {})) {
      lines.push(`  ${k}: ${v.replace(/\r?\n/g, " ")}`);
    }
    if (includeXml && xmls[i]) lines.push(xmls[i]);
    return lines.join("\n");
  });
  return blocks.join("\n\n") + "\n";
}

function readHash(): { q: string; re: boolean } {
  if (typeof window === "undefined") return { q: "", re: false };
  const p = new URLSearchParams(window.location.hash.slice(1));
  return { q: p.get("q") ?? "", re: p.get("re") === "1" };
}

function shareLink(q: string, regex: boolean): string {
  const p = new URLSearchParams({ q });
  if (regex) p.set("re", "1");
  return `${window.location.origin}${window.location.pathname}#${p}`;
}

const mdCell = (s: string) => s.replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();

/** Markdown timeline of the bookmarked events, for the case file. */
function buildReport(
  rows: IndexedRow[],
  allPairs: [string, string][][],
  notes: Record<number, string>,
  fileNames: string[],
  dict: Dict,
): string {
  const v = dict.viewer;
  const lines = [
    `# ${v.reportTitle}`,
    "",
    `${v.reportGenerated}: ${new Date().toISOString()} · ${fileNames.join(", ")} · ${rows.length} ★`,
    "",
    `| ${dict.table.time} | ${dict.table.computer} | ${dict.table.eventId} | ${v.description} | ${v.note} |`,
    "|---|---|---|---|---|",
  ];
  for (const r of rows) {
    const pairs = allPairs[r._g] ?? [];
    const name = eventName(r.event_id, r.provider);
    const desc = describeEvent(r.event_id, r.provider, pairs) ?? "";
    lines.push(
      `| ${formatTimestamp(r.timestamp, "utc")} | ${mdCell(r.computer ?? "")} | ${r.event_id ?? ""}${name ? ` ${mdCell(name)}` : ""} | ${mdCell(desc)} | ${mdCell(notes[r._g] ?? "")} |`,
    );
  }
  lines.push("");
  for (const r of rows) {
    const pairs = allPairs[r._g] ?? [];
    lines.push(
      `## ${formatTimestamp(r.timestamp, "utc")} · ${r.event_id ?? ""} · ${r.computer ?? ""}`,
      "",
    );
    if (notes[r._g]?.trim()) lines.push(`> ${notes[r._g].trim().replace(/\n/g, "\n> ")}`, "");
    lines.push(
      "```",
      `${dict.table.provider}: ${r.provider ?? ""}`,
      `${dict.table.channel}: ${r.channel ?? ""}`,
      `${dict.table.record}${Number(r.record_id)} · ${r._file}`,
      ...pairs.map(([k, val]) => {
        const d = decodeValue(k, val);
        return `${k}: ${val}${d ? `  (${d})` : ""}`;
      }),
      "```",
      "",
    );
  }
  return lines.join("\n");
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

// Shared toggle-chip styling. Active = signal-amber wash so the eye lands on
// exactly what's filtering the view; idle is quiet until hovered.
const CHIP_ACTIVE =
  "border-amber-500 bg-amber-500/15 text-amber-700 dark:border-amber-400/60 dark:bg-amber-400/10 dark:text-amber-300";
const CHIP_IDLE =
  "border-zinc-200 text-zinc-500 hover:border-amber-400 dark:border-zinc-800 dark:hover:border-amber-400/60";

// Severity dot colours for the triage Findings panel.
const SEV_DOT: Record<Severity, string> = {
  high: "bg-red-500",
  medium: "bg-amber-500 dark:bg-amber-400",
  low: "bg-zinc-400",
};

// "Scanning" indicator shown while a file parses — animated brand bars plus an
// indeterminate sweep, so large files never look like a hung tab.
function ScanningIndicator() {
  return (
    <span className="flex items-end gap-[3px]" aria-hidden="true">
      {[0, 1, 2, 3, 4].map((i) => (
        <span
          key={i}
          className="animate-scanbar w-[3px] rounded-sm bg-amber-500 dark:bg-amber-400"
          style={{ height: 14, animationDelay: `${i * 0.12}s` }}
        />
      ))}
    </span>
  );
}

export function EvtxUploader({
  dict,
  locale,
  emptyStateAside,
}: {
  dict: Dict;
  locale: string;
  /** Rendered directly under the drop zone while no file is loaded
   *  (e.g. the "Where to find .evtx files" panel). */
  emptyStateAside?: ReactNode;
}) {
  const t = dict;
  const clientRef = useRef<EvtxClient | null>(null);
  // Files accumulate across uploads (multi-file import): each pick/drop appends
  // to the session. `loading` holds the current progress label while parsing.
  const [files, setFiles] = useState<LoadedFile[]>([]);
  const fileIdRef = useRef(1);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [windowDrag, setWindowDrag] = useState(false);
  // A shared link (#q=…&re=1) pre-fills the search; the file itself is never
  // part of the link.
  const [filter, setFilter] = useState(() => readHash().q);
  const [activeLevels, setActiveLevels] = useState<Set<number>>(new Set());
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
  const fileInputRef = useRef<HTMLInputElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  // Built-in triage: when a finding is selected, the table is restricted to the
  // exact rows it matched (by global index).
  const [findingFilter, setFindingFilter] = useState<{
    key: string;
    gids: Set<number>;
  } | null>(null);
  const [showFindings, setShowFindings] = useState(true);
  // Power-user workflow state.
  const [regexMode, setRegexMode] = useState(() => readHash().re);
  const [showFacets, setShowFacets] = useState(true);
  const [bookmarks, setBookmarks] = useState<Set<number>>(new Set());
  // Analyst notes by global row index; noting an event also bookmarks it.
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [bookmarkOnly, setBookmarkOnly] = useState(false);
  const [focusedIdx, setFocusedIdx] = useState<number | null>(null);

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
    setQuery(emptyRoot());
    setError(null);
  }, []);

  // Drop a .evtx anywhere on the page — not just on the box. We track enter/leave
  // depth so the overlay doesn't flicker as the cursor crosses child elements.
  useEffect(() => {
    const carriesFiles = (e: DragEvent) =>
      Array.from(e.dataTransfer?.types ?? []).includes("Files");
    let depth = 0;
    const onEnter = (e: DragEvent) => {
      if (!carriesFiles(e)) return;
      depth++;
      setWindowDrag(true);
    };
    const onLeave = () => {
      depth = Math.max(0, depth - 1);
      if (depth === 0) setWindowDrag(false);
    };
    const onOver = (e: DragEvent) => {
      if (carriesFiles(e)) e.preventDefault();
    };
    const onDropWin = (e: DragEvent) => {
      if (!carriesFiles(e)) return;
      e.preventDefault();
      depth = 0;
      setWindowDrag(false);
      const dropped = Array.from(e.dataTransfer?.files ?? []);
      if (dropped.length) handleFiles(dropped);
    };
    window.addEventListener("dragenter", onEnter);
    window.addEventListener("dragleave", onLeave);
    window.addEventListener("dragover", onOver);
    window.addEventListener("drop", onDropWin);
    return () => {
      window.removeEventListener("dragenter", onEnter);
      window.removeEventListener("dragleave", onLeave);
      window.removeEventListener("dragover", onOver);
      window.removeEventListener("drop", onDropWin);
    };
  }, [handleFiles]);

  // Reset every view filter (text, level/ID/provider/channel chips, time range,
  // structured query) in one action — but keep the loaded files in the session.
  const clearFilters = useCallback(() => {
    setFilter("");
    setActiveLevels(new Set());
    setQuery(emptyRoot());
    setTimeRange(null);
    setFindingFilter(null);
    setBookmarkOnly(false);
    setOpenRow(null);
    setFocusedIdx(null);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, []);

  const openFilePicker = useCallback(() => fileInputRef.current?.click(), []);

  // Jump the table to exactly the rows a finding matched. Clears other filters
  // for an unambiguous view; clicking the active finding again toggles it off.
  const viewFinding = useCallback((f: Finding) => {
    setFilter("");
    setActiveLevels(new Set());
    setQuery(emptyRoot());
    setTimeRange(null);
    setBookmarkOnly(false);
    setOpenRow(null);
    setFocusedIdx(null);
    setFindingFilter((prev) =>
      prev?.key === f.key ? null : { key: f.key, gids: new Set(f.gids) },
    );
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, []);

  const toggleBookmark = useCallback((g: number) => {
    setBookmarks((prev) => {
      const next = new Set(prev);
      if (next.has(g)) next.delete(g);
      else next.add(g);
      return next;
    });
  }, []);

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

  const [xmlCopied, setXmlCopied] = useState(false);
  const copyOpenRowXml = useCallback(async () => {
    const current = openRow;
    const client = clientRef.current;
    if (!current || !client) return;
    let xml = current.xml;
    if (xml == null) {
      try {
        ({ xml } = await client.xml(current.fileId, current.localIdx));
        setOpenRow({ ...current, xml });
      } catch {
        return;
      }
    }
    await copyText(xml ?? "");
    setXmlCopied(true);
    setTimeout(() => setXmlCopied(false), 1500);
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
      setFocusedIdx(null);
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
    setFocusedIdx(null);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, []);

  const numberFmt = useMemo(() => new Intl.NumberFormat(locale), [locale]);

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

  // Full-screen workspace: the viewer takes over the window as soon as the
  // first file is loaded, and drops back to the page when the last one goes.
  const [fullscreen, setFullscreen] = useState(false);
  // UTC by default (what EVTX stores); local time is a per-viewer preference.
  const [timeMode, setTimeMode] = useState<TimeMode>(() => {
    try {
      return localStorage.getItem("evtx-time-mode") === "local" ? "local" : "utc";
    } catch {
      return "utc";
    }
  });
  const toggleTimeMode = useCallback(() => {
    setTimeMode((m) => {
      const next = m === "utc" ? "local" : "utc";
      try {
        localStorage.setItem("evtx-time-mode", next);
      } catch {
        // storage unavailable: keep the in-memory choice
      }
      return next;
    });
  }, []);
  // Offset as of the log's first event (DST differs from "now" for old logs);
  // each cell's tooltip keeps the original UTC timestamp.
  const zone = zoneLabel(timeMode, allRows[0]?.timestamp);
  const timeHeader = t.table.time.replace("UTC", zone);
  const [prevReady, setPrevReady] = useState(ready);
  if (ready !== prevReady) {
    setPrevReady(ready);
    setFullscreen(ready);
  }
  useEffect(() => {
    if (!fullscreen) return;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = "";
    };
  }, [fullscreen]);
  // In full screen the table fills the remaining height, so the virtual
  // window has to follow the measured viewport instead of the fixed default.
  const [viewportHeight, setViewportHeight] = useState(SCROLL_HEIGHT_PX);
  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !ready) return;
    const ro = new ResizeObserver(() =>
      setViewportHeight(el.clientHeight || SCROLL_HEIGHT_PX),
    );
    ro.observe(el);
    return () => ro.disconnect();
  }, [ready, fullscreen]);
  const multiFile = files.length > 1;
  const totalSize = useMemo(
    () => files.reduce((s, f) => s + f.size, 0),
    [files],
  );

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

  // Built-in triage detections — recomputed only when the dataset changes.
  const findings = useMemo<Finding[]>(
    () => (ready ? runDetections(allRows, allPairs) : []),
    [ready, allRows, allPairs],
  );

  // Is the current regex term syntactically invalid? Drives the red input
  // border and the "matches nothing" behaviour below.
  let regexInvalid = false;
  if (filter && regexMode) {
    try {
      new RegExp(filter);
    } catch {
      regexInvalid = true;
    }
  }

  // Parsed search box (ignored in regex mode) and what to highlight.
  const parsedSearch = useMemo(
    () => (regexMode ? null : parseSearch(filter)),
    [filter, regexMode],
  );
  const compiledSearch = useMemo(
    () => (parsedSearch ? compileSearch(parsedSearch) : null),
    [parsedSearch],
  );
  const highlightRe = useMemo(
    () =>
      buildHighlightRegExp(
        parsedSearch ? highlightTerms(parsedSearch) : [],
        regexMode && filter && !regexInvalid ? filter : null,
      ),
    [parsedSearch, regexMode, filter, regexInvalid],
  );
  // Lower-cased "everything" string per row for free-text search, built on
  // first use and cached for the lifetime of the dataset.
  const haystackOf = useMemo(() => makeHaystackIndex(allPairs), [allPairs]);

  // Search-box autocomplete: field names, then each field's values by count.
  const searchFieldNames = useMemo(() => {
    // Investigation fields first, so "Targ" + Tab gives TargetUserName.
    const present = new Set(facets.eventDataKeys.map((k) => k.toLowerCase()));
    const preferred = PREFERRED_FIELDS.filter((f) => present.has(f.toLowerCase()));
    const pref = new Set(preferred.map((f) => f.toLowerCase()));
    return [
      ...META_FIELD_NAMES,
      "logonid",
      "processguid",
      "process",
      "parent",
      ...preferred,
      ...facets.eventDataKeys.filter((k) => !pref.has(k.toLowerCase())),
    ];
  }, [facets.eventDataKeys]);
  const valuesFor = useMemo(
    () => makeValueIndex(allRows, allPairs),
    [allRows, allPairs],
  );

  // Total active constraints across every filter surface — drives the
  // "Clear filters (N)" affordance and the empty-state reset.
  const activeFilterCount =
    (filter ? 1 : 0) +
    activeLevels.size +
    (timeRange ? 1 : 0) +
    (queryActive ? 1 : 0) +
    (findingFilter ? 1 : 0) +
    (bookmarkOnly ? 1 : 0);
  const anyFilter = activeFilterCount > 0;

  const filteredRows = useMemo(() => {
    if (
      !filter &&
      activeLevels.size === 0 &&
      !timeRange &&
      !queryActive &&
      !findingFilter &&
      !bookmarkOnly
    )
      return allRows;
    // Search box: a regex over every field in regex mode (invalid pattern
    // matches nothing), otherwise the field-aware query language.
    let matcher: ((r: IndexedRow) => boolean) | null = null;
    if (filter) {
      if (regexMode) {
        let re: RegExp | null = null;
        try {
          re = new RegExp(filter, "i");
        } catch {
          re = null;
        }
        matcher = re ? (r) => re.test(haystackOf(r)) : () => false;
      } else if (compiledSearch) {
        matcher = (r) =>
          compiledSearch(r, allPairs[r._g] ?? [], () => haystackOf(r));
      }
    }
    return allRows.filter((r) => {
      if (findingFilter && !findingFilter.gids.has(r._g)) return false;
      if (bookmarkOnly && !bookmarks.has(r._g)) return false;
      if (activeLevels.size > 0 && (r.level == null || !activeLevels.has(r.level)))
        return false;
      if (matcher && !matcher(r)) return false;
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
    regexMode,
    activeLevels,
    timeRange,
    query,
    queryActive,
    findingFilter,
    bookmarkOnly,
    bookmarks,
    compiledSearch,
    haystackOf,
  ]);

  const setFilterAndResetScroll = useCallback((next: string) => {
    setFilter(next);
    setOpenRow(null);
    setFocusedIdx(null);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, []);

  // Click-to-filter from any cell, facet or detail row: append a
  // `Field:value` clause (or its negation) to the search box.
  const applyClause = useCallback(
    (update: (q: string) => string) => {
      // A regex can't be combined with clauses; start a fresh query.
      const base = regexMode ? "" : filter;
      if (regexMode) setRegexMode(false);
      setFilterAndResetScroll(update(base));
    },
    [filter, regexMode, setFilterAndResetScroll],
  );
  const includeValue = useCallback(
    (field: string, value: string) =>
      applyClause((q) => withClause(q, field, value)),
    [applyClause],
  );
  const excludeValue = useCallback(
    (field: string, value: string) =>
      applyClause((q) => withClause(q, field, value, true)),
    [applyClause],
  );
  const removeValue = useCallback(
    (field: string, value: string) =>
      applyClause((q) => withoutClause(q, field, value)),
    [applyClause],
  );

  // Pivots from an event: replace every filter with a focused view.
  const pivotTo = useCallback(
    (opts: { search?: string; range?: [number, number] }) => {
      setActiveLevels(new Set());
      setQuery(emptyRoot());
      setFindingFilter(null);
      setBookmarkOnly(false);
      setRegexMode(false);
      setTimeRange(opts.range ?? null);
      setFilterAndResetScroll(opts.search ?? "");
    },
    [setFilterAndResetScroll],
  );

  const handleQueryChange = useCallback((next: Group) => {
    setQuery(next);
    setOpenRow(null);
    setFocusedIdx(null);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, []);

  const handleSelectTimeRange = useCallback((range: [number, number]) => {
    setTimeRange(range);
    setOpenRow(null);
    setFocusedIdx(null);
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
    const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT);
    const start = Math.max(
      0,
      Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN,
    );
    const end = Math.min(total, start + visibleCount + OVERSCAN * 2);
    return { start, end };
  }, [sortedRows, scrollTop, openRow, viewportHeight]);

  const visibleRows = useMemo(
    () => sortedRows.slice(visibleWindow.start, visibleWindow.end),
    [sortedRows, visibleWindow],
  );

  // --- Keyboard navigation ---------------------------------------------------
  // A ref mirrors the focused index so the document-level handler reads the
  // current value without re-subscribing on every keystroke.
  const focusedIdxRef = useRef<number | null>(null);
  useEffect(() => {
    focusedIdxRef.current = focusedIdx;
  }, [focusedIdx]);

  const scrollRowIntoView = useCallback((idx: number) => {
    const el = scrollRef.current;
    if (!el) return;
    const top = idx * ROW_HEIGHT;
    if (top < el.scrollTop) {
      el.scrollTop = top;
      setScrollTop(top);
    } else if (top + ROW_HEIGHT > el.scrollTop + el.clientHeight) {
      const next = top + ROW_HEIGHT - el.clientHeight;
      el.scrollTop = next;
      setScrollTop(next);
    }
  }, []);

  useEffect(() => {
    if (!ready) return;
    const onKey = (e: KeyboardEvent) => {
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName;
      const typing =
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        !!el?.isContentEditable;
      if (e.key === "/" && !typing) {
        e.preventDefault();
        searchInputRef.current?.focus();
        return;
      }
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      const total = sortedRows.length;
      const i = focusedIdxRef.current;
      if (e.key === "ArrowDown" || e.key === "j") {
        if (total === 0) return;
        e.preventDefault();
        const n = i == null ? 0 : Math.min(total - 1, i + 1);
        setOpenRow(null);
        setFocusedIdx(n);
        scrollRowIntoView(n);
      } else if (e.key === "ArrowUp" || e.key === "k") {
        if (total === 0) return;
        e.preventDefault();
        const n = i == null ? 0 : Math.max(0, i - 1);
        setOpenRow(null);
        setFocusedIdx(n);
        scrollRowIntoView(n);
      } else if (e.key === "Enter") {
        if (i != null && sortedRows[i]) {
          e.preventDefault();
          toggleDetailsFor(sortedRows[i]);
        }
      } else if (e.key === "b") {
        if (i != null && sortedRows[i]) toggleBookmark(sortedRows[i]._g);
      } else if (e.key === "Escape") {
        if (openRow == null && focusedIdxRef.current == null) {
          setFullscreen(false);
        }
        setOpenRow(null);
        setFocusedIdx(null);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [ready, sortedRows, scrollRowIntoView, toggleDetailsFor, toggleBookmark, openRow]);

  const setNote = useCallback((g: number, text: string) => {
    setNotes((prev) => ({ ...prev, [g]: text }));
    if (text.trim()) {
      setBookmarks((prev) => (prev.has(g) ? prev : new Set(prev).add(g)));
    }
  }, []);

  const downloadReport = useCallback(() => {
    const picked = allRows
      .filter((r) => bookmarks.has(r._g))
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    download(
      "evtx-report.md",
      "text/markdown;charset=utf-8",
      buildReport(picked, allPairs, notes, files.map((f) => f.name), t),
    );
  }, [allRows, allPairs, bookmarks, notes, files, t]);

  const runExport = useCallback(
    async (kind: "csv" | "json" | "txt") => {
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
        } else if (kind === "txt") {
          download(
            `${base}.txt`,
            "text/plain;charset=utf-8",
            buildTxt(filteredRows, parsed, t, includeXml, xmls, multiFile),
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
    <section
      aria-label={t.home.dropArea}
      className={
        ready && fullscreen
          ? "fixed inset-0 z-40 flex flex-col gap-3 overflow-y-auto bg-white p-3 sm:p-4 dark:bg-zinc-950"
          : "flex flex-col gap-4"
      }
    >
      {windowDrag && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-zinc-950/70 p-6 backdrop-blur-sm">
          <div className="flex flex-col items-center gap-3 rounded-2xl border-2 border-dashed border-amber-400 bg-zinc-900/80 px-10 py-12 text-center">
            <span className="flex items-end gap-1.5" aria-hidden="true">
              {[14, 22, 30, 18, 12].map((h, i) => (
                <span
                  key={i}
                  className={`w-2 rounded-sm ${i === 2 ? "bg-amber-400" : "bg-zinc-500"}`}
                  style={{ height: h }}
                />
              ))}
            </span>
            <span className="font-mono text-lg font-medium text-amber-300">
              {t.home.dropArea}
            </span>
            <span className="font-mono text-xs text-zinc-400">
              {t.home.privacyNote}
            </span>
          </div>
        </div>
      )}

      {!ready && (
        <label
          tabIndex={0}
          role="button"
          aria-label={t.home.dropArea}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              openFilePicker();
            }
          }}
          className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed border-zinc-300 px-4 py-10 text-center text-sm transition-colors hover:border-amber-400 hover:bg-amber-50/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500 sm:px-6 sm:py-14 dark:border-zinc-700 dark:hover:border-amber-400/60 dark:hover:bg-amber-400/[0.04]"
        >
          <span className="mb-1 flex items-end gap-1" aria-hidden="true">
            {[10, 16, 22, 14, 9].map((h, i) => (
              <span
                key={i}
                className={`w-1.5 rounded-sm ${i === 2 ? "bg-amber-500" : "bg-zinc-300 dark:bg-zinc-600"}`}
                style={{ height: h }}
              />
            ))}
          </span>
          <span className="font-medium">{t.home.dropArea}</span>
          <span className="text-zinc-500">{t.home.privacyNote}</span>
          <input
            ref={fileInputRef}
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
      )}

      {!ready && emptyStateAside}

      {loading && (
        <div className="flex flex-col gap-2 rounded-lg border border-amber-500/30 bg-amber-50/40 px-4 py-3 dark:border-amber-400/20 dark:bg-amber-400/[0.06]">
          <div className="flex items-center gap-3">
            <ScanningIndicator />
            <span className="font-mono text-sm text-zinc-700 dark:text-zinc-300">
              {loading}
            </span>
          </div>
          <div className="relative h-0.5 w-full overflow-hidden rounded-full bg-amber-500/15">
            <div className="animate-scanline absolute inset-y-0 left-0 w-1/4 rounded-full bg-amber-500 dark:bg-amber-400" />
          </div>
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
              <label
                title={t.home.dropArea}
                className="cursor-pointer rounded-md border border-zinc-300 px-2 py-1 font-mono text-xs text-zinc-600 transition-colors hover:border-amber-400 hover:text-zinc-900 dark:border-zinc-700 dark:text-zinc-300 dark:hover:border-amber-400/60 dark:hover:text-zinc-100"
              >
                + .evtx
                <input
                  type="file"
                  accept=".evtx"
                  multiple
                  className="hidden"
                  onChange={(e) => {
                    const picked = Array.from(e.target.files ?? []);
                    e.target.value = "";
                    if (picked.length) handleFiles(picked);
                  }}
                />
              </label>
            </div>
            <div className="flex items-center gap-3 text-zinc-600 dark:text-zinc-400">
              <span>
                {formatBytes(totalSize)} ·{" "}
                <span className="font-mono text-foreground">
                  {numberFmt.format(filteredRows.length)}
                </span>{" "}
                / <span className="font-mono">{numberFmt.format(allRows.length)}</span>{" "}
                {t.home.eventsLabel}
              </span>
              {anyFilter && (
                <button
                  type="button"
                  onClick={clearFilters}
                  className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-700 transition-colors hover:bg-amber-500/20 dark:text-amber-300"
                >
                  {t.home.clearFilters}
                  <span className="rounded-full bg-amber-500/20 px-1.5 font-mono text-[10px] tabular-nums">
                    {activeFilterCount}
                  </span>
                </button>
              )}
              <button
                type="button"
                onClick={toggleTimeMode}
                title={t.viewer.timeZoneToggle}
                className="rounded-md border border-zinc-300 px-2 py-1 font-mono text-xs text-zinc-700 hover:bg-zinc-100 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
              >
                🕒 {zone}
              </button>
              <button
                type="button"
                onClick={() => setShowFacets((v) => !v)}
                aria-pressed={showFacets}
                className={`rounded-md border px-2 py-1 text-xs transition-colors ${
                  showFacets ? CHIP_ACTIVE : CHIP_IDLE
                }`}
              >
                {showFacets ? t.viewer.hideFields : t.viewer.fields}
              </button>
              <button
                type="button"
                onClick={() => setFullscreen((v) => !v)}
                aria-pressed={fullscreen}
                title={fullscreen ? `${t.home.exitFullscreen} (Esc)` : t.home.enterFullscreen}
                className="inline-flex items-center gap-1.5 rounded-md border border-zinc-300 px-2 py-1 text-xs text-zinc-700 hover:bg-zinc-100 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
              >
                <span aria-hidden="true">{fullscreen ? "⤡" : "⤢"}</span>
                {fullscreen ? t.home.exitFullscreen : t.home.enterFullscreen}
              </button>
            </div>
          </div>

          {findings.length > 0 && (
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800">
              <button
                type="button"
                onClick={() => setShowFindings((v) => !v)}
                aria-expanded={showFindings}
                className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm font-medium"
              >
                <span className="text-zinc-400">{showFindings ? "▾" : "▸"}</span>
                <span>Findings</span>
                <span className="rounded-full bg-amber-500/15 px-1.5 font-mono text-[11px] text-amber-700 dark:text-amber-300">
                  {findings.length}
                </span>
                <span className="ml-auto text-xs font-normal text-zinc-500">
                  Automated triage · click to filter
                </span>
              </button>
              {showFindings && (
                <div className="flex flex-col gap-1 border-t border-zinc-100 p-2 dark:border-zinc-800/70">
                  {findings.map((f) => {
                    const active = findingFilter?.key === f.key;
                    return (
                      <button
                        key={f.key}
                        type="button"
                        onClick={() => viewFinding(f)}
                        aria-pressed={active}
                        title={f.detail}
                        className={`flex items-center gap-2.5 rounded-md border px-2.5 py-1.5 text-left text-xs transition-colors ${
                          active
                            ? "border-amber-500 bg-amber-500/10"
                            : "border-transparent hover:bg-zinc-50 dark:hover:bg-zinc-900"
                        }`}
                      >
                        <span
                          className={`h-2 w-2 shrink-0 rounded-full ${SEV_DOT[f.severity]}`}
                          aria-hidden="true"
                        />
                        <span className="shrink-0 font-medium text-zinc-800 dark:text-zinc-200">
                          {f.title}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-zinc-500">
                          {f.detail}
                        </span>
                        <span className="ml-auto shrink-0 rounded bg-zinc-100 px-1.5 font-mono text-[10px] tabular-nums text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300">
                          {numberFmt.format(f.gids.length)}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          <Timeline
            rows={allRows}
            selectedRange={timeRange}
            onSelectBucket={handleSelectTimeRange}
            locale={locale}
            utc={timeMode === "utc"}
          />

          {timeRange && (
            <div className="flex items-center gap-2 text-xs">
              <span className="rounded-md border border-zinc-300 bg-zinc-50 px-2 py-1 font-mono text-zinc-700 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
                {formatEpoch(timeRange[0], timeMode)} → {formatEpoch(timeRange[1], timeMode)} ({zone})
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
            <SearchBox
              value={filter}
              onChange={setFilterAndResetScroll}
              inputRef={searchInputRef}
              dict={t}
              regexMode={regexMode}
              invalid={regexInvalid}
              fieldNames={searchFieldNames}
              valuesFor={valuesFor}
            />
            <button
              type="button"
              onClick={() => setRegexMode((v) => !v)}
              aria-pressed={regexMode}
              title="Regular-expression search"
              className={`rounded-md border px-2 py-1 font-mono text-xs transition-colors ${
                regexMode ? CHIP_ACTIVE : CHIP_IDLE
              }`}
            >
              .*
            </button>
            <HuntsMenu
              rows={allRows}
              allPairs={allPairs}
              haystackOf={haystackOf}
              locale={locale as Locale}
              dict={t}
              activeQuery={regexMode ? "" : filter}
              onRun={(q) => pivotTo({ search: q })}
            />
            {filter && (
              <span className="rounded-md border border-zinc-200 dark:border-zinc-800">
                <CopyPathButton
                  value={() => shareLink(filter, regexMode)}
                  label={t.viewer.copyLink}
                  copiedLabel={t.viewer.linkCopied}
                  text="🔗"
                />
              </span>
            )}
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
                      active ? CHIP_ACTIVE : CHIP_IDLE
                    }`}
                  >
                    {t.levels[key]}
                  </button>
                );
              })}
            </div>
            <div className="flex flex-wrap items-center gap-2 sm:ml-auto">
              {bookmarks.size > 0 && (
                <button
                  type="button"
                  onClick={() => {
                    setBookmarkOnly((v) => !v);
                    setOpenRow(null);
                    if (scrollRef.current) scrollRef.current.scrollTop = 0;
                  }}
                  aria-pressed={bookmarkOnly}
                  title="Show bookmarked rows only"
                  className={`rounded-md border px-2 py-1 text-xs transition-colors ${
                    bookmarkOnly ? CHIP_ACTIVE : CHIP_IDLE
                  }`}
                >
                  ★ {numberFmt.format(bookmarks.size)}
                </button>
              )}
              {bookmarks.size > 0 && (
                <button
                  type="button"
                  onClick={downloadReport}
                  className="rounded-md border border-zinc-300 px-2 py-1 text-xs text-zinc-700 hover:bg-zinc-100 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
                >
                  {t.viewer.report}
                </button>
              )}
              <label className="flex items-center gap-1.5 text-zinc-500 dark:text-zinc-400">
                <input
                  type="checkbox"
                  checked={includeXml}
                  onChange={(e) => setIncludeXml(e.target.checked)}
                  className="accent-amber-500 dark:accent-amber-400"
                />
                {t.home.includeXml}
              </label>
              <button
                type="button"
                onClick={() => runExport("csv")}
                disabled={filteredRows.length === 0 || exporting}
                className="rounded-md border border-zinc-300 px-2 py-1 text-xs text-zinc-700 hover:bg-zinc-100 disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
              >
                {exporting
                  ? t.home.exporting
                  : `${t.home.exportCsv} (${numberFmt.format(filteredRows.length)})`}
              </button>
              <button
                type="button"
                onClick={() => runExport("json")}
                disabled={filteredRows.length === 0 || exporting}
                className="rounded-md border border-zinc-300 px-2 py-1 text-xs text-zinc-700 hover:bg-zinc-100 disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
              >
                {exporting
                  ? t.home.exporting
                  : `${t.home.exportJson} (${numberFmt.format(filteredRows.length)})`}
              </button>
              <button
                type="button"
                onClick={() => runExport("txt")}
                disabled={filteredRows.length === 0 || exporting}
                className="rounded-md border border-zinc-300 px-2 py-1 text-xs text-zinc-700 hover:bg-zinc-100 disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
              >
                {exporting
                  ? t.home.exporting
                  : `${t.home.exportTxt} (${numberFmt.format(filteredRows.length)})`}
              </button>
            </div>
          </div>

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
                <span
                  className="h-1.5 w-1.5 rounded-full bg-amber-500 dark:bg-amber-400"
                  aria-hidden="true"
                />
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

          <HighlightContext.Provider value={highlightRe}>
          <div
            className={`flex flex-col gap-3 lg:flex-row ${
              fullscreen ? "min-h-[320px] flex-1" : ""
            }`}
          >
          {showFacets && (
            <aside
              aria-label={t.viewer.fields}
              style={fullscreen ? undefined : { maxHeight: SCROLL_HEIGHT_PX }}
              className="max-h-72 shrink-0 overflow-y-auto lg:max-h-none lg:w-72"
            >
              <FacetSidebar
                rows={filteredRows}
                allPairs={allPairs}
                query={regexMode ? "" : filter}
                dict={t}
                multiFile={multiFile}
                levelLabel={(l) => levelLabel(l, t)}
                onInclude={includeValue}
                onExclude={excludeValue}
                onRemove={removeValue}
              />
            </aside>
          )}
          <div
            ref={scrollRef}
            onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
            style={fullscreen ? undefined : { maxHeight: SCROLL_HEIGHT_PX }}
            className="-mx-4 min-w-0 flex-1 overflow-auto border-y border-zinc-200 sm:mx-0 sm:rounded-md sm:border dark:border-zinc-800"
          >
            <table className="w-full text-left font-mono text-xs">
              <thead className="sticky top-0 z-10 bg-zinc-50 text-zinc-500 shadow-[0_1px_0_var(--tw-shadow-color)] shadow-zinc-200 dark:bg-zinc-900 dark:text-zinc-400 dark:shadow-zinc-800">
                <tr>
                  <SortHeader field="record_id" label={t.table.record} sortField={sortField} sortDir={sortDir} onSort={toggleSort} />
                  <SortHeader field="timestamp" label={timeHeader} sortField={sortField} sortDir={sortDir} onSort={toggleSort} />
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
                      className="px-3 py-8 text-center"
                    >
                      <div className="flex flex-col items-center gap-2 text-zinc-400">
                        <span>{t.home.noMatches}</span>
                        {anyFilter && (
                          <button
                            type="button"
                            onClick={clearFilters}
                            className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-700 transition-colors hover:bg-amber-500/20 dark:text-amber-300"
                          >
                            {t.home.clearFilters}
                          </button>
                        )}
                      </div>
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
                {visibleRows.map((r, vi) => {
                  const isOpen = openRow?.g === r._g;
                  const isFocused = visibleWindow.start + vi === focusedIdx;
                  const isBookmarked = bookmarks.has(r._g);
                  const resolvedName = eventName(r.event_id, r.provider);
                  const pairs = allPairs[r._g] ?? [];
                  return (
                    <Fragment key={r._g}>
                      <tr
                        className={`border-t border-zinc-100 dark:border-zinc-800 ${
                          isFocused
                            ? "bg-amber-50 ring-1 ring-inset ring-amber-400 dark:bg-amber-400/10"
                            : isOpen
                              ? "bg-zinc-50 dark:bg-zinc-950"
                              : ""
                        }`}
                      >
                        <td className="px-3 py-1.5 text-zinc-500">
                          {Number(r.record_id)}
                        </td>
                        <td
                          className="whitespace-nowrap px-3 py-1.5 text-zinc-600 dark:text-zinc-400"
                          title={r.timestamp}
                        >
                          {formatTimestamp(r.timestamp, timeMode)}
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
                          field="Provider"
                          value={r.provider}
                          onFilter={includeValue}
                          onExclude={excludeValue}
                        />
                        <FilterableCell
                          field="Channel"
                          value={r.channel}
                          onFilter={includeValue}
                          onExclude={excludeValue}
                        />
                        <FilterableCell
                          field="Computer"
                          value={r.computer}
                          onFilter={includeValue}
                          onExclude={excludeValue}
                        />
                        {multiFile && (
                          <FilterableCell
                            field="File"
                            value={r._file}
                            onFilter={includeValue}
                            onExclude={excludeValue}
                          />
                        )}
                        {dynamicKeys ? (
                          <DynamicCells
                            keys={dynamicKeys}
                            pairs={pairs}
                            onFilter={includeValue}
                            onExclude={excludeValue}
                          />
                        ) : (
                          <td className="px-3 py-1.5 text-zinc-700 dark:text-zinc-300">
                            <SummaryCell
                              row={r}
                              pairs={pairs}
                              onFilter={includeValue}
                              onExclude={excludeValue}
                            />
                          </td>
                        )}
                        <td className="px-3 py-1.5">
                          <div className="flex items-center gap-1.5">
                            <button
                              type="button"
                              onClick={() => toggleBookmark(r._g)}
                              aria-pressed={isBookmarked}
                              aria-label="Bookmark row"
                              title="Bookmark (b)"
                              className={`rounded px-1 leading-none transition-colors ${
                                isBookmarked
                                  ? "text-amber-500"
                                  : "text-zinc-300 hover:text-amber-400 dark:text-zinc-600"
                              }`}
                            >
                              {isBookmarked ? "★" : "☆"}
                            </button>
                            <button
                              type="button"
                              onClick={() => toggleDetailsFor(r)}
                              aria-expanded={isOpen}
                              className={`rounded border px-1.5 py-0.5 ${
                                isOpen ? CHIP_ACTIVE : CHIP_IDLE
                              }`}
                            >
                              {isOpen ? t.table.closeDetails : t.table.viewDetails}
                            </button>
                          </div>
                        </td>
                      </tr>
                      {isOpen && openRow && (
                        <tr className="border-t border-zinc-100 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-950">
                          <td colSpan={tableColCount} className="p-3">
                            <div className="flex flex-col gap-3">
                              <DetailsPanel
                                row={r}
                                note={notes[r._g] ?? ""}
                                onNote={(text) => setNote(r._g, text)}
                                pairs={openRow.pairs}
                                dict={t}
                                onInclude={includeValue}
                                onExclude={excludeValue}
                                onPivot={pivotTo}
                              />
                              <div className="flex flex-wrap gap-2">
                                <button
                                  type="button"
                                  onClick={copyOpenRowXml}
                                  className="rounded-md border border-zinc-200 px-2 py-1 text-xs text-zinc-600 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-900"
                                >
                                  {xmlCopied ? `✓ ${t.viewer.copied}` : t.viewer.copyXml}
                                </button>
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
          </div>
          </HighlightContext.Provider>

          <p className="hidden text-[11px] text-zinc-400 sm:block">
            <kbd className="font-mono">j</kbd>/<kbd className="font-mono">k</kbd>{" "}
            or <kbd className="font-mono">↑</kbd>/<kbd className="font-mono">↓</kbd>{" "}
            move · <kbd className="font-mono">Enter</kbd> details ·{" "}
            <kbd className="font-mono">b</kbd> bookmark ·{" "}
            <kbd className="font-mono">/</kbd> search · Shift-click a value to
            exclude it
          </p>
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
          active ? "text-amber-700 dark:text-amber-300" : ""
        }`}
      >
        <span>{label}</span>
        <span className="text-[10px]">{indicator}</span>
      </button>
    </th>
  );
}

type ValueAction = (field: string, value: string) => void;

function FilterableCell({
  field,
  value,
  onFilter,
  onExclude,
}: {
  field: string;
  value: string | null | undefined;
  onFilter: ValueAction;
  onExclude: ValueAction;
}) {
  if (!value) {
    return <td className="px-3 py-1.5 text-zinc-400">—</td>;
  }
  return (
    <td className="px-3 py-1.5 text-zinc-600 dark:text-zinc-400">
      <button
        type="button"
        onClick={(e) =>
          e.shiftKey ? onExclude(field, value) : onFilter(field, value)
        }
        title={`${value}\nClick to filter · Shift-click to exclude`}
        className="max-w-[24ch] truncate text-left hover:text-zinc-900 hover:underline dark:hover:text-zinc-100"
      >
        <Hl text={value} />
      </button>
    </td>
  );
}

function SummaryCell({
  row,
  pairs,
  onFilter,
  onExclude,
}: {
  row: EventRow;
  pairs: [string, string][];
  onFilter: ValueAction;
  onExclude: ValueAction;
}) {
  if (pairs.length === 0) {
    return <span className="text-zinc-400">—</span>;
  }
  // A readable sentence beats raw key=value pairs when we have a template.
  const desc = describeEvent(row.event_id, row.provider, pairs);
  if (desc) {
    return (
      <span title={desc} className="block max-w-[80ch] truncate">
        <Hl text={desc} />
      </span>
    );
  }
  const fields = summaryFieldsFor(row.event_id, row.provider);
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
            onClick={(e) =>
              e.shiftKey ? onExclude(k, v) : onFilter(k, v)
            }
            title={`${v}\nClick to filter · Shift-click to exclude`}
            className="hover:text-zinc-900 hover:underline dark:hover:text-zinc-100"
          >
            <Hl text={truncate(v, 60)} />
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
  onExclude,
}: {
  keys: string[];
  pairs: [string, string][];
  onFilter: ValueAction;
  onExclude: ValueAction;
}) {
  const map = new Map(pairs);
  return (
    <>
      {keys.map((k) => {
        const v = map.get(k);
        const decoded = v ? decodeValue(k, v) : null;
        return (
          <td
            key={k}
            className="whitespace-nowrap px-3 py-1.5 text-zinc-700 dark:text-zinc-300"
            title={v ?? ""}
          >
            {v != null && v !== "" ? (
              <button
                type="button"
                onClick={(e) =>
                  e.shiftKey ? onExclude(k, v) : onFilter(k, v)
                }
                title={`${v}\nClick to filter · Shift-click to exclude`}
                className="max-w-[28ch] truncate text-left hover:text-zinc-900 hover:underline dark:hover:text-zinc-100"
              >
                <Hl text={truncate(v, 80)} />
              </button>
            ) : (
              <span className="text-zinc-400">—</span>
            )}
            {decoded && (
              <span className="ml-1 text-zinc-400">
                · <Hl text={decoded} />
              </span>
            )}
          </td>
        );
      })}
    </>
  );
}

// Keys that tie events of one logon session / one process together.
const LOGON_KEYS = ["TargetLogonId", "SubjectLogonId", "LogonId"];
const PROCESS_KEYS = ["ProcessGuid", "ParentProcessGuid"];
const PIVOT_WINDOW_MS = 5 * 60 * 1000;

function DetailsPanel({
  row,
  note,
  onNote,
  pairs,
  dict,
  onInclude,
  onExclude,
  onPivot,
}: {
  row: EventRow;
  note: string;
  onNote: (text: string) => void;
  pairs: [string, string][];
  dict: Dict;
  onInclude: ValueAction;
  onExclude: ValueAction;
  onPivot: (opts: { search?: string; range?: [number, number] }) => void;
}) {
  const v = dict.viewer;
  const t = Date.parse(row.timestamp);
  // Distinct session / process ids on this event. 0x0 and SYSTEM's 0x3e7
  // are too common to be a useful pivot.
  const pick = (keys: string[], skip: string[] = []) => {
    const out = new Set<string>();
    for (const [k, val] of pairs) {
      if (keys.some((x) => x.toLowerCase() === k.toLowerCase()) && val) {
        if (!skip.includes(val.toLowerCase())) out.add(val);
      }
    }
    return [...out];
  };
  const logonIds = pick(LOGON_KEYS, ["0x0", "0x3e7"]);
  const processGuids = pick(PROCESS_KEYS);
  const pivotBtn =
    "rounded-md border border-zinc-200 px-2 py-1 text-xs text-zinc-700 hover:border-amber-400 hover:bg-amber-500/10 dark:border-zinc-800 dark:text-zinc-300";
  const desc = describeEvent(row.event_id, row.provider, pairs);
  const asJson = () =>
    JSON.stringify(
      {
        record_id: Number(row.record_id),
        timestamp: row.timestamp,
        event_id: row.event_id,
        level: row.level,
        provider: row.provider,
        channel: row.channel,
        computer: row.computer,
        description: desc,
        event_data: Object.fromEntries(pairs),
      },
      null,
      2,
    );

  return (
    <div className="flex flex-col gap-3">
      {desc && (
        <div className="flex flex-col gap-0.5">
          <div className="text-[10px] uppercase tracking-wide text-zinc-400">
            {v.description}
          </div>
          <p className="text-sm text-zinc-900 dark:text-zinc-100">
            <Hl text={desc} />
          </p>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-[10px] uppercase tracking-wide text-zinc-400">
          {v.pivots}
        </span>
        {!Number.isNaN(t) && (
          <button
            type="button"
            className={pivotBtn}
            onClick={() =>
              onPivot({ range: [t - PIVOT_WINDOW_MS, t + PIVOT_WINDOW_MS] })
            }
          >
            {v.pivotTime}
          </button>
        )}
        {logonIds.map((id) => (
          <button
            key={id}
            type="button"
            className={pivotBtn}
            onClick={() => onPivot({ search: `logonid:${id}` })}
          >
            {v.pivotLogon} <span className="font-mono text-zinc-400">{id}</span>
          </button>
        ))}
        {processGuids.map((g) => (
          <button
            key={g}
            type="button"
            className={pivotBtn}
            onClick={() => onPivot({ search: `processguid:${g}` })}
          >
            {v.pivotProcess}{" "}
            <span className="font-mono text-zinc-400">{truncate(g, 14)}</span>
          </button>
        ))}
        <span className="rounded-md border border-zinc-200 dark:border-zinc-800">
          <CopyPathButton
            value={asJson}
            label={v.copyJson}
            copiedLabel={v.copied}
            text={v.copyJson}
          />
        </span>
      </div>

      <label className="flex flex-col gap-1">
        <span className="text-[10px] uppercase tracking-wide text-zinc-400">
          {v.note}
        </span>
        <textarea
          value={note}
          onChange={(e) => onNote(e.target.value)}
          placeholder={v.notePlaceholder}
          rows={2}
          className="max-w-2xl rounded-md border border-zinc-200 bg-white px-2 py-1 font-sans text-xs text-zinc-800 outline-none focus:border-amber-500 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-200"
        />
      </label>

      {pairs.length === 0 ? (
        <div className="text-xs italic text-zinc-500">
          {dict.table.noEventData}
        </div>
      ) : (
        <div className="flex flex-col gap-1">
          <div className="text-[10px] uppercase tracking-wide text-zinc-400">
            {dict.table.eventData}
          </div>
          <div className="overflow-x-auto rounded border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-950">
            <table className="w-full border-collapse text-left font-mono text-[11px]">
              <tbody>
                {pairs.map(([k, val], i) => (
                  <tr
                    key={`${k}-${i}`}
                    className="group border-b border-zinc-100 last:border-b-0 dark:border-zinc-900"
                  >
                    <td className="w-1 whitespace-nowrap px-2 py-1 align-top text-zinc-500">
                      {k}
                    </td>
                    <td className="break-all px-2 py-1 align-top text-zinc-800 select-text dark:text-zinc-200">
                      {val ? (
                        <>
                          <Hl text={val} />
                          {decodeValue(k, val) && (
                            <span className="ml-2 text-zinc-500">
                              → <Hl text={decodeValue(k, val) ?? ""} />
                            </span>
                          )}
                        </>
                      ) : (
                        <span className="text-zinc-400">—</span>
                      )}
                    </td>
                    <td className="w-1 whitespace-nowrap px-1 py-0.5 align-top">
                      {val && (
                        <span className="flex items-center gap-0.5 opacity-40 group-hover:opacity-100 focus-within:opacity-100">
                          <CopyPathButton
                            value={val}
                            label={`${v.copy}: ${k}`}
                            copiedLabel={v.copied}
                          />
                          <button
                            type="button"
                            onClick={() => onInclude(k, val)}
                            title={v.include}
                            aria-label={`${v.include}: ${k}`}
                            className="rounded px-1.5 text-zinc-500 hover:bg-amber-500/15 hover:text-amber-700 dark:hover:text-amber-300"
                          >
                            +
                          </button>
                          <button
                            type="button"
                            onClick={() => onExclude(k, val)}
                            title={v.exclude}
                            aria-label={`${v.exclude}: ${k}`}
                            className="rounded px-1.5 text-zinc-500 hover:bg-red-500/15 hover:text-red-700 dark:hover:text-red-300"
                          >
                            −
                          </button>
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
