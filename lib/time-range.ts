// Custom time-range window for the viewer. Pure helpers (no React) so the
// filtering rules are unit-testable:
//
// - A range is { from, to } in epoch ms, BOTH ends inclusive. The inputs work
//   to the second, so `to` always covers its whole second (…:59.999 style):
//   an event at 10:55:00.431 is inside "→ 10:55:00".
// - Event times are parsed once per record into a Float64Array indexed by the
//   row's global index (`_g`); NaN = no value. Filtering is then a pair of
//   numeric comparisons per row.
// - The primary field is the event's System/TimeCreated. A few EventData
//   fields also carry times (Sysmon UtcTime / CreationUtcTime /
//   PreviousCreationUtcTime — the timestomp pair —, 4616 PreviousTime /
//   NewTime); "any" matches a record if any of its times is in range.

import { formatEpoch, type TimeMode } from "@/lib/time";

export type TimeRange = { from: number; to: number };

/** System/TimeCreated — the default timeline field. */
export const PRIMARY_FIELD = "TimeCreated";
/** Match if any of the record's times is in range. */
export const ANY_FIELD = "any";

/** EventData keys that hold a timestamp worth pivoting on. */
export const SECONDARY_TIME_KEYS = [
  "UtcTime",
  "CreationUtcTime",
  "PreviousCreationUtcTime",
  "NewTime",
  "PreviousTime",
] as const;

export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

/** ± windows offered by "Around…". */
export const AROUND_WINDOWS = [5 * MINUTE, HOUR, DAY] as const;

const SEC = 1000;
const floorSec = (ms: number) => Math.floor(ms / SEC) * SEC;

/** Snap to whole seconds: `from` to its second, `to` to the end of its second. */
export function normalizeRange(from: number, to: number): TimeRange {
  return { from: floorSec(from), to: floorSec(to) + SEC - 1 };
}

// "2026-09-14T10:00:00.1234567Z", "…+00:00", Sysmon's "2026-09-14 10:00:00.123"
// (UTC, no zone), with or without a fraction.
const EVENT_TS_RE =
  /^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?\s*(Z|[+-]\d\d:?\d\d)?$/i;

/** Epoch ms of an event/EventData timestamp (UTC unless it says otherwise); NaN if none. */
export function parseEventTime(value: string | null | undefined): number {
  if (!value) return NaN;
  const m = EVENT_TS_RE.exec(value.trim());
  if (!m) return NaN;
  const ms = m[7] ? Number(m[7].slice(0, 3).padEnd(3, "0")) : 0;
  let t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms);
  const zone = m[8];
  if (zone && zone.toUpperCase() !== "Z") {
    const sign = zone[0] === "-" ? -1 : 1;
    const digits = zone.slice(1).replace(":", "");
    t -= sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2))) * MINUTE;
  }
  return t;
}

/** Primary (TimeCreated) epoch per row, aligned with the rows array. */
export function buildPrimaryTimes(rows: ReadonlyArray<{ timestamp: string }>): Float64Array {
  const out = new Float64Array(rows.length);
  for (let i = 0; i < rows.length; i++) out[i] = parseEventTime(rows[i].timestamp);
  return out;
}

/** Epoch of one EventData field per row (first occurrence, case-insensitive). */
export function buildFieldTimes(
  pairsByG: ReadonlyArray<[string, string][]>,
  key: string,
): Float64Array {
  const k = key.toLowerCase();
  const out = new Float64Array(pairsByG.length).fill(NaN);
  for (let g = 0; g < pairsByG.length; g++) {
    const pairs = pairsByG[g];
    if (!pairs) continue;
    for (const [pk, pv] of pairs) {
      if (pk.toLowerCase() === k) {
        out[g] = parseEventTime(pv);
        break;
      }
    }
  }
  return out;
}

/** Secondary time fields present in the data (in SECONDARY_TIME_KEYS order). */
export function detectTimeFields(pairsByG: ReadonlyArray<[string, string][]>): string[] {
  const wanted = new Map(SECONDARY_TIME_KEYS.map((k) => [k.toLowerCase(), k]));
  const found = new Set<string>();
  for (const pairs of pairsByG) {
    if (!pairs) continue;
    for (const [k] of pairs) {
      const hit = wanted.get(k.toLowerCase());
      if (hit) found.add(hit);
    }
    if (found.size === wanted.size) break;
  }
  return SECONDARY_TIME_KEYS.filter((k) => found.has(k));
}

/** Every time array a record can match on, keyed by field name. */
export type TimeIndex = {
  primary: Float64Array;
  fields: ReadonlyMap<string, Float64Array>;
};

export function buildTimeIndex(
  rows: ReadonlyArray<{ timestamp: string }>,
  pairsByG: ReadonlyArray<[string, string][]>,
): TimeIndex {
  const fields = new Map<string, Float64Array>();
  for (const key of detectTimeFields(pairsByG)) fields.set(key, buildFieldTimes(pairsByG, key));
  return { primary: buildPrimaryTimes(rows), fields };
}

/** Time array a field reads from (primary for "any"/unknown fields). */
export function timesFor(index: TimeIndex, field: string): Float64Array {
  if (field === PRIMARY_FIELD || field === ANY_FIELD) return index.primary;
  return index.fields.get(field) ?? index.primary;
}

/** Inclusive on both ends; NaN (no value) never matches. */
export function inRange(t: number, range: TimeRange): boolean {
  return t >= range.from && t <= range.to;
}

/**
 * Predicate over a row's global index. Records with no value for the chosen
 * field are excluded; "any" matches when any of the record's times does.
 */
export function rangeMatcher(
  index: TimeIndex,
  field: string,
  range: TimeRange,
): (g: number) => boolean {
  const { from, to } = range;
  if (field === ANY_FIELD) {
    const arrays = [index.primary, ...index.fields.values()];
    return (g) => {
      for (const a of arrays) {
        const t = a[g];
        if (t >= from && t <= to) return true;
      }
      return false;
    };
  }
  const a = timesFor(index, field);
  return (g) => {
    const t = a[g];
    return t >= from && t <= to;
  };
}

/** Rows (with a global index `_g`) inside the range. */
export function filterByRange<R extends { _g: number }>(
  rows: readonly R[],
  index: TimeIndex,
  field: string,
  range: TimeRange | null,
): R[] {
  if (!range) return rows as R[];
  const match = rangeMatcher(index, field, range);
  return rows.filter((r) => match(r._g));
}

/** [min, max] of the finite values, or null. */
export function timeBounds(times: Float64Array): [number, number] | null {
  let min = Infinity;
  let max = -Infinity;
  for (let i = 0; i < times.length; i++) {
    const t = times[i];
    if (t < min) min = t;
    if (t > max) max = t;
  }
  return Number.isFinite(min) ? [min, max] : null;
}

export type PresetId = "all" | "firstHour" | "lastHour" | "last24h";

/** Presets derived from the data span (never the wall clock); null = clear. */
export function presetRange(id: PresetId, bounds: [number, number]): TimeRange | null {
  const [min, max] = bounds;
  switch (id) {
    case "all":
      return null;
    case "firstHour":
      return normalizeRange(min, Math.min(max, min + HOUR));
    case "lastHour":
      return normalizeRange(Math.max(min, max - HOUR), max);
    case "last24h":
      return normalizeRange(Math.max(min, max - DAY), max);
  }
}

/** center ± half, to the second. */
export function aroundRange(center: number, half: number): TimeRange {
  return normalizeRange(center - half, center + half);
}

// --- datetime-local inputs ---------------------------------------------------

/** "YYYY-MM-DDTHH:MM:SS" for <input type="datetime-local" step="1">. */
export function toInputValue(ms: number, mode: TimeMode): string {
  return formatEpoch(ms, mode).replace(" ", "T");
}

/**
 * Parse an input value ("YYYY-MM-DDTHH:MM[:SS]", a space also works) in the
 * viewer's time mode. Returns epoch ms of the start of that second, or null.
 */
export function fromInputValue(value: string, mode: TimeMode): number | null {
  const m = /^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)(?::(\d\d))?$/.exec(value.trim());
  if (!m) return null;
  const [y, mo, d, h, mi, s] = [+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] ?? 0)];
  if (mo > 11 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return null;
  const ms =
    mode === "utc"
      ? Date.UTC(y, mo, d, h, mi, s)
      : new Date(y, mo, d, h, mi, s).getTime();
  return Number.isNaN(ms) ? null : ms;
}

/** Range from the From/To inputs, or an error when From is after To. */
export function rangeFromInputs(
  from: string,
  to: string,
  mode: TimeMode,
): { range: TimeRange } | { error: "invalid" | "order" } {
  const a = fromInputValue(from, mode);
  const b = fromInputValue(to, mode);
  if (a == null || b == null) return { error: "invalid" };
  if (a > b) return { error: "order" };
  return { range: normalizeRange(a, b) };
}

// --- labels, file names, URL -------------------------------------------------

/** "2026-09-14 10:00:00" → "10:55:00" (the end drops its date on the same day). */
export function rangeLabel(range: TimeRange, mode: TimeMode): { from: string; to: string } {
  const a = formatEpoch(range.from, mode);
  const b = formatEpoch(range.to, mode);
  return { from: a, to: a.slice(0, 10) === b.slice(0, 10) ? b.slice(11) : b };
}

const compactUtc = (ms: number) =>
  new Date(floorSec(ms)).toISOString().replace(/\.\d{3}Z$/, "Z").replace(/:/g, "");

/** "_2026-09-14T100000Z-2026-09-14T105500Z" for export file names ("" without a range). */
export function rangeFileSuffix(range: TimeRange | null): string {
  return range ? `_${compactUtc(range.from)}-${compactUtc(range.to)}` : "";
}

const isoSec = (ms: number) => new Date(floorSec(ms)).toISOString().replace(/\.\d{3}Z$/, "Z");

/** Write (or remove) from/to/field in URL params; the field is omitted when primary. */
export function writeRangeParams(
  params: URLSearchParams,
  range: TimeRange | null,
  field: string,
): URLSearchParams {
  params.delete("from");
  params.delete("to");
  params.delete("field");
  if (range) {
    params.set("from", isoSec(range.from));
    params.set("to", isoSec(range.to));
    if (field !== PRIMARY_FIELD) params.set("field", field);
  }
  return params;
}

/** Read from/to/field back; invalid or inverted ranges are ignored. */
export function readRangeParams(params: URLSearchParams): {
  range: TimeRange | null;
  field: string;
} {
  const field = params.get("field") || PRIMARY_FIELD;
  const a = parseEventTime(params.get("from"));
  const b = parseEventTime(params.get("to"));
  if (Number.isNaN(a) || Number.isNaN(b) || a > b) return { range: null, field };
  return { range: normalizeRange(a, b), field };
}
