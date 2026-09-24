"use client";

import { useMemo } from "react";

import type { EventRow } from "@/lib/evtx-client";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const BUCKET_SIZES_MS = [
  MINUTE,
  5 * MINUTE,
  15 * MINUTE,
  HOUR,
  3 * HOUR,
  6 * HOUR,
  DAY,
  7 * DAY,
  30 * DAY,
];

const TARGET_BUCKETS = 80;

// Stack order (bottom → top in flex-col-reverse): verbose, info, warning, error, critical.
// Putting the most severe at the top makes spikes stand out visually.
const STACK_ORDER = [4, 3, 2, 1, 0];
const LEVEL_COLORS = [
  "bg-red-700 dark:bg-red-500", // 0 critical
  "bg-red-500 dark:bg-red-400", // 1 error
  "bg-amber-500 dark:bg-amber-400", // 2 warning
  "bg-zinc-500 dark:bg-zinc-400", // 3 info
  "bg-zinc-300 dark:bg-zinc-600", // 4 verbose / unknown
];

type Bucket = {
  start: number;
  counts: [number, number, number, number, number];
  total: number;
};

function pickBucketSize(spanMs: number): number {
  for (const size of BUCKET_SIZES_MS) {
    if (spanMs / size <= TARGET_BUCKETS) return size;
  }
  return BUCKET_SIZES_MS[BUCKET_SIZES_MS.length - 1];
}

function bucketSizeLabel(ms: number): string {
  if (ms < HOUR) return `${ms / MINUTE} min`;
  if (ms < DAY) return `${ms / HOUR} h`;
  if (ms < 7 * DAY) return `${ms / DAY} d`;
  return `${Math.round(ms / DAY)} d`;
}

export function Timeline({
  rows,
  selectedRange,
  onSelectBucket,
  locale,
  utc = true,
}: {
  rows: EventRow[];
  selectedRange: [number, number] | null;
  onSelectBucket: (range: [number, number]) => void;
  locale: string;
  /** Label times in UTC (default) or in the viewer's local time. */
  utc?: boolean;
}) {
  const data = useMemo(() => {
    if (rows.length === 0) return null;
    let minT = Infinity;
    let maxT = -Infinity;
    const times = new Array<number>(rows.length);
    for (let i = 0; i < rows.length; i++) {
      const t = Date.parse(rows[i].timestamp);
      times[i] = t;
      if (t < minT) minT = t;
      if (t > maxT) maxT = t;
    }
    if (!isFinite(minT) || !isFinite(maxT)) return null;
    const span = Math.max(1, maxT - minT);
    const bucketMs = pickBucketSize(span);
    const startBucket = Math.floor(minT / bucketMs) * bucketMs;
    const endBucket = Math.floor(maxT / bucketMs) * bucketMs;
    const nBuckets = Math.max(1, (endBucket - startBucket) / bucketMs + 1);

    const buckets: Bucket[] = new Array(nBuckets);
    for (let i = 0; i < nBuckets; i++) {
      buckets[i] = {
        start: startBucket + i * bucketMs,
        counts: [0, 0, 0, 0, 0],
        total: 0,
      };
    }
    for (let i = 0; i < rows.length; i++) {
      const idx = Math.floor((times[i] - startBucket) / bucketMs);
      if (idx < 0 || idx >= nBuckets) continue;
      const b = buckets[idx];
      const lvl = rows[i].level;
      const li =
        lvl != null && lvl >= 1 && lvl <= 5 ? lvl - 1 : 4; // unknown → verbose tier
      b.counts[li]++;
      b.total++;
    }
    let maxTotal = 0;
    for (const b of buckets) if (b.total > maxTotal) maxTotal = b.total;
    return { buckets, bucketMs, maxTotal: Math.max(1, maxTotal), minT, maxT };
  }, [rows]);

  const labelFmt = useMemo(
    () =>
      new Intl.DateTimeFormat(locale, {
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        timeZone: utc ? "UTC" : undefined,
      }),
    [locale, utc],
  );
  const tooltipFmt = useMemo(
    () =>
      new Intl.DateTimeFormat(locale, {
        dateStyle: "short",
        timeStyle: "medium",
        timeZone: utc ? "UTC" : undefined,
      }),
    [locale, utc],
  );

  if (!data) return null;

  const { buckets, bucketMs, maxTotal, minT, maxT } = data;

  // Pick 4 axis ticks: start, ~1/3, ~2/3, end.
  const tickIndexes =
    buckets.length >= 4
      ? [
          0,
          Math.floor(buckets.length / 3),
          Math.floor((buckets.length * 2) / 3),
          buckets.length - 1,
        ]
      : buckets.map((_, i) => i);

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex h-20 items-end gap-px rounded-md border border-zinc-200 bg-zinc-50/40 p-1 dark:border-zinc-800 dark:bg-zinc-950/40">
        {buckets.map((b) => {
          const heightPct = (b.total / maxTotal) * 100;
          const selected =
            selectedRange &&
            b.start === selectedRange[0] &&
            b.start + bucketMs === selectedRange[1];
          const empty = b.total === 0;
          const rangeLabel = `${tooltipFmt.format(b.start)} – ${tooltipFmt.format(
            b.start + bucketMs,
          )}`;
          return (
            <button
              key={b.start}
              type="button"
              onClick={() => onSelectBucket([b.start, b.start + bucketMs])}
              aria-label={`${rangeLabel}: ${b.total} events`}
              title={`${rangeLabel}\n${b.total} events`}
              className={`flex h-full min-w-[2px] flex-1 cursor-pointer flex-col-reverse overflow-hidden rounded-sm transition-opacity hover:opacity-70 ${
                selected ? "ring-2 ring-amber-500 dark:ring-amber-400" : ""
              } ${empty ? "bg-zinc-100 dark:bg-zinc-900" : ""}`}
              style={{ alignSelf: "flex-end" }}
            >
              <div
                className="flex w-full flex-col-reverse"
                style={{ height: `${Math.max(empty ? 4 : 2, heightPct)}%` }}
              >
                {STACK_ORDER.map((li) => {
                  const c = b.counts[li];
                  if (c === 0) return null;
                  return (
                    <div
                      key={li}
                      style={{ height: `${(c / b.total) * 100}%` }}
                      className={LEVEL_COLORS[li]}
                    />
                  );
                })}
              </div>
            </button>
          );
        })}
      </div>
      <div className="flex justify-between font-mono text-[10px] text-zinc-500">
        {tickIndexes.map((i, k) => (
          <span
            key={i}
            className={k === tickIndexes.length - 1 ? "text-right" : ""}
          >
            {labelFmt.format(buckets[i].start)}
          </span>
        ))}
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[10px] text-zinc-500">
        <div className="flex items-center gap-2">
          <span>{tooltipFmt.format(minT)}</span>
          <span>→</span>
          <span>{tooltipFmt.format(maxT)}</span>
          <span className="text-zinc-400">· {bucketSizeLabel(bucketMs)}/bar</span>
        </div>
      </div>
    </div>
  );
}
