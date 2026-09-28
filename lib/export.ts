// Export builders (CSV / JSON / TXT) for the events currently in view. Pure
// so the export pipeline — including the time-range window — is testable.

import type { EventRow } from "@/lib/evtx-client";
import { describeEvent } from "@/lib/event-decode";
import type { Dict } from "@/src/dict/types";

/** Row shape the exports need (IndexedRow satisfies it). */
export type ExportRow = EventRow & { _file: string };

export function levelLabel(level: number | null, dict: Dict): string {
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

// Cap the number of EventData-derived columns so a heterogeneous file
// (e.g. a full Security.evtx with hundreds of distinct keys) can't produce
// a pathologically wide CSV. Analysts who want clean columns filter to a
// single Event ID first; this is just a guardrail.
const MAX_DATA_COLUMNS = 256;

function pairsOf(rec: Record<string, string>): [string, string][] {
  return Object.entries(rec);
}

export function pairsToRecord(pairs: [string, string][]): Record<string, string> {
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

export function buildCsv(
  rows: ExportRow[],
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

export function buildJson(
  rows: ExportRow[],
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

export function buildTxt(
  rows: ExportRow[],
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

