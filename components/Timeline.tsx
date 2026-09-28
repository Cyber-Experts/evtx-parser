"use client";

import { useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";

import type { EventRow } from "@/lib/evtx-client";
import {
  countOutside,
  normalizeRange,
  percentileBounds,
  stripDomain,
  timeBounds,
  type StripZoom,
  type TimeRange,
} from "@/lib/time-range";

const SECOND = 1000;
const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

// Sub-minute bars only when the strip is zoomed on a selection.
const FINE_BUCKET_SIZES_MS = [SECOND, 5 * SECOND, 15 * SECOND, 30 * SECOND];
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
// Below this many px of pointer travel a press is a click (select one bar).
const DRAG_THRESHOLD_PX = 4;

// Stack order (bottom → top in flex-col-reverse): verbose, info, warning, error, critical.
// Putting the most severe at the top makes spikes stand out visually.
const STACK_ORDER = [4, 3, 2, 1, 0];
const LEVEL_COLORS = [
  "bg-red-700 dark:bg-red-500", // 0 critical
  "bg-red-500 dark:bg-red-400", // 1 error
  "bg-orange-500 dark:bg-orange-400", // 2 warning
  "bg-ink-500 dark:bg-ink-400", // 3 info
  "bg-ink-300 dark:bg-ink-600", // 4 verbose / unknown
];

type Bucket = {
  start: number;
  counts: [number, number, number, number, number];
  total: number;
};

function pickBucketSize(spanMs: number, fine = false): number {
  for (const size of fine ? [...FINE_BUCKET_SIZES_MS, ...BUCKET_SIZES_MS] : BUCKET_SIZES_MS) {
    if (spanMs / size <= TARGET_BUCKETS) return size;
  }
  return BUCKET_SIZES_MS[BUCKET_SIZES_MS.length - 1];
}

function bucketSizeLabel(ms: number): string {
  if (ms < MINUTE) return `${ms / SECOND} s`;
  if (ms < HOUR) return `${ms / MINUTE} min`;
  if (ms < DAY) return `${ms / HOUR} h`;
  if (ms < 7 * DAY) return `${ms / DAY} d`;
  return `${Math.round(ms / DAY)} d`;
}

type Drag = { mode: "new" | "from" | "to"; x0: number; a: number; b: number };

export type TimelineLabels = {
  /** Accessible name of the strip. */
  strip: string;
  start: string;
  end: string;
  /** "{n} events" */
  events: string;
  /** Toggle back to the unzoomed strip. */
  fullSpan: string;
  /** Toggle to the selection ± 50 %. */
  zoomToRange: string;
  /** "+{n} earlier" / "+{n} later": records outside the drawn strip. */
  earlier: string;
  later: string;
};

/**
 * Density strip of events over the data span, stacked by level. Drag across
 * it to select a range, click a bar to select that bar, or move the two
 * range handles with the keyboard (arrows: one bar, Shift/PageUp/PageDown:
 * ten bars, Home/End: strip edges).
 *
 * The unzoomed strip spans the 1st–99th percentile of the record times (so
 * one stray timestamp doesn't squeeze the incident into a sliver) and notes
 * how many records fall outside. A selection under 5 % of that span
 * auto-zooms the strip to the selection ± 50 %; a toggle overrides it.
 */
export function Timeline({
  rows,
  times,
  range,
  onSelect,
  locale,
  utc = true,
  labels,
}: {
  rows: EventRow[];
  /** Epoch ms of the chosen time field per row (NaN = none), aligned with rows. */
  times: Float64Array;
  range: TimeRange | null;
  onSelect: (range: TimeRange) => void;
  locale: string;
  /** Label times in UTC (default) or in the viewer's local time. */
  utc?: boolean;
  labels: TimelineLabels;
}) {
  // True span and outlier-robust (1st–99th percentile) span of the field.
  const stats = useMemo(() => {
    const bounds = timeBounds(times);
    return bounds ? { bounds, robust: percentileBounds(times) } : null;
  }, [times]);

  // Zoom override from the toggle; back to automatic once the range is cleared.
  const [zoomPref, setZoomPref] = useState<StripZoom>("auto");
  if (!range && zoomPref !== "auto") setZoomPref("auto");
  const view = stats
    ? stripDomain({ bounds: stats.bounds, robust: stats.robust, range, zoom: zoomPref })
    : null;
  const dom0 = view?.domain[0];
  const dom1 = view?.domain[1];
  const zoomed = view?.zoomed ?? false;

  const data = useMemo(() => {
    if (dom0 === undefined || dom1 === undefined) return null;
    const span = Math.max(1, dom1 - dom0);
    const bucketMs = pickBucketSize(span, zoomed);
    const startBucket = Math.floor(dom0 / bucketMs) * bucketMs;
    const endBucket = Math.floor(dom1 / bucketMs) * bucketMs;
    const nBuckets = Math.max(1, (endBucket - startBucket) / bucketMs + 1);

    const buckets: Bucket[] = new Array(nBuckets);
    for (let i = 0; i < nBuckets; i++) {
      buckets[i] = {
        start: startBucket + i * bucketMs,
        counts: [0, 0, 0, 0, 0],
        total: 0,
      };
    }
    const n = Math.min(rows.length, times.length);
    for (let i = 0; i < n; i++) {
      const t = times[i];
      if (!(t === t)) continue; // NaN: no value for this field
      const idx = Math.floor((t - startBucket) / bucketMs);
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
    const d0 = startBucket;
    const d1 = startBucket + nBuckets * bucketMs;
    return {
      buckets,
      bucketMs,
      maxTotal: Math.max(1, maxTotal),
      minT: dom0,
      maxT: dom1,
      d0,
      d1,
      outside: countOutside(times, d0, d1),
    };
  }, [rows, times, dom0, dom1, zoomed]);

  const labelFmt = useMemo(
    () =>
      new Intl.DateTimeFormat(locale, {
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        // Zoomed to sub-minute bars: ticks need the seconds.
        second: data && data.bucketMs < MINUTE ? "2-digit" : undefined,
        timeZone: utc ? "UTC" : undefined,
      }),
    [locale, utc, data],
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

  const stripRef = useRef<HTMLDivElement>(null);
  const [drag, setDrag] = useState<Drag | null>(null);

  if (!data) return null;

  const { buckets, bucketMs, maxTotal, minT, maxT, d0, d1, outside } = data;
  const span = d1 - d0;
  const clamp = (t: number) => Math.min(d1, Math.max(d0, t));
  const pct = (t: number) => ((clamp(t) - d0) / span) * 100;
  const snapDown = (t: number) => d0 + Math.floor((t - d0) / bucketMs) * bucketMs;
  const snapUp = (t: number) => d0 + Math.ceil((t - d0) / bucketMs) * bucketMs;

  const timeAt = (clientX: number) => {
    const el = stripRef.current;
    if (!el) return d0;
    const box = el.getBoundingClientRect();
    const f = box.width > 0 ? (clientX - box.left) / box.width : 0;
    return clamp(d0 + Math.min(1, Math.max(0, f)) * span);
  };

  // Live selection while dragging, else the applied range.
  let sel: [number, number] | null = range ? [range.from, range.to + 1] : null;
  if (drag) {
    if (drag.mode === "new") {
      const lo = Math.min(drag.a, drag.b);
      const hi = Math.max(drag.a, drag.b);
      sel = [snapDown(lo), Math.max(snapUp(hi), snapDown(lo) + bucketMs)];
    } else {
      sel = [Math.min(drag.a, drag.b), Math.max(drag.a, drag.b)];
    }
  }
  const handleFrom = sel ? sel[0] : d0;
  const handleTo = sel ? sel[1] : d1;

  const commit = (from: number, toExclusive: number) => {
    const lo = Math.min(from, toExclusive);
    const hi = Math.max(from, toExclusive);
    onSelect(normalizeRange(lo, Math.max(lo, hi - 1)));
  };

  const onStripDown = (e: PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    const t = timeAt(e.clientX);
    e.currentTarget.setPointerCapture(e.pointerId);
    setDrag({ mode: "new", x0: e.clientX, a: t, b: t });
  };
  const onHandleDown = (which: "from" | "to") => (e: PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    e.stopPropagation();
    stripRef.current?.setPointerCapture(e.pointerId);
    // `a` is the fixed edge, `b` follows the pointer.
    setDrag(
      which === "from"
        ? { mode: "from", x0: e.clientX, a: handleTo, b: handleFrom }
        : { mode: "to", x0: e.clientX, a: handleFrom, b: handleTo },
    );
  };
  const onMove = (e: PointerEvent<HTMLDivElement>) => {
    if (!drag) return;
    setDrag({ ...drag, b: timeAt(e.clientX) });
  };
  const onUp = (e: PointerEvent<HTMLDivElement>) => {
    if (!drag) return;
    const d = drag;
    setDrag(null);
    if (d.mode === "new" && Math.abs(e.clientX - d.x0) < DRAG_THRESHOLD_PX) {
      const b = snapDown(d.a);
      commit(b, b + bucketMs);
      return;
    }
    if (d.mode === "new") {
      if (sel) commit(sel[0], sel[1]);
      return;
    }
    commit(d.a, timeAt(e.clientX));
  };

  const onHandleKey = (which: "from" | "to") => (e: KeyboardEvent<HTMLDivElement>) => {
    // Esc must not reach the viewer (it would leave full screen).
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      (e.currentTarget as HTMLElement).blur();
      return;
    }
    const step = e.shiftKey ? bucketMs * 10 : bucketMs;
    let from = handleFrom;
    let to = handleTo;
    const move = (delta: number) => {
      if (which === "from") from = clamp(Math.min(to - 1000, from + delta));
      else to = clamp(Math.max(from + 1000, to + delta));
    };
    switch (e.key) {
      case "ArrowLeft":
      case "ArrowDown":
        move(-step);
        break;
      case "ArrowRight":
      case "ArrowUp":
        move(step);
        break;
      case "PageDown":
        move(-bucketMs * 10);
        break;
      case "PageUp":
        move(bucketMs * 10);
        break;
      case "Home":
        if (which === "from") from = d0;
        else to = from + bucketMs;
        break;
      case "End":
        if (which === "to") to = d1;
        else from = to - bucketMs;
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
    commit(from, to);
  };

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

  const handle = (which: "from" | "to", at: number) => {
    const now = which === "from" ? at : at - 1;
    return (
      <div
        role="slider"
        tabIndex={0}
        aria-label={which === "from" ? labels.start : labels.end}
        aria-valuemin={d0}
        aria-valuemax={d1}
        aria-valuenow={now}
        aria-valuetext={tooltipFmt.format(now)}
        onKeyDown={onHandleKey(which)}
        onPointerDown={onHandleDown(which)}
        className="absolute inset-y-0 z-10 -ml-1.5 flex w-3 cursor-ew-resize touch-none justify-center outline-none focus-visible:[&>span]:bg-uv-500 focus-visible:[&>span]:ring-2 focus-visible:[&>span]:ring-uv-400/50"
        style={{ left: `${pct(at)}%` }}
      >
        <span
          className={`h-full w-1 rounded-full ${
            sel ? "bg-uv-500/80 dark:bg-uv-400/80" : "bg-ink-300/80 dark:bg-ink-600/80"
          }`}
        />
      </div>
    );
  };

  return (
    <div className="flex flex-col gap-1.5">
      <div className="h-20 rounded-md border border-ink-200 bg-ink-50/40 p-1 dark:border-ink-800 dark:bg-ink-950/40">
      <div
        ref={stripRef}
        role="group"
        aria-label={labels.strip}
        title={labels.strip}
        onPointerDown={onStripDown}
        onPointerMove={onMove}
        onPointerUp={onUp}
        onPointerCancel={() => setDrag(null)}
        className="relative flex h-full cursor-crosshair touch-none select-none items-end gap-px"
      >
        {sel && (
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-y-0 rounded-sm bg-uv-500/15 ring-1 ring-inset ring-uv-500/60 dark:bg-uv-400/15 dark:ring-uv-400/60"
            style={{ left: `${pct(sel[0])}%`, width: `${Math.max(0.3, pct(sel[1]) - pct(sel[0]))}%` }}
          />
        )}
        {buckets.map((b) => {
          const heightPct = (b.total / maxTotal) * 100;
          const inSel = !sel || (b.start + bucketMs > sel[0] && b.start < sel[1]);
          const empty = b.total === 0;
          const rangeLabel = `${tooltipFmt.format(b.start)} – ${tooltipFmt.format(
            b.start + bucketMs,
          )}`;
          return (
            <div
              key={b.start}
              title={`${rangeLabel}\n${labels.events.replace("{n}", String(b.total))}`}
              className={`flex h-full min-w-[2px] flex-1 flex-col-reverse overflow-hidden rounded-sm transition-opacity motion-reduce:transition-none ${
                inSel ? "" : "opacity-35"
              } ${empty ? "bg-ink-100 dark:bg-ink-900" : ""}`}
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
            </div>
          );
        })}
        {handle("from", handleFrom)}
        {handle("to", handleTo)}
      </div>
      </div>
      <div className="flex justify-between font-mono text-[10px] text-ink-500">
        {tickIndexes.map((i, k) => (
          <span
            key={i}
            className={k === tickIndexes.length - 1 ? "text-right" : ""}
          >
            {labelFmt.format(buckets[i].start)}
          </span>
        ))}
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[10px] text-ink-500">
        <div className="flex items-center gap-2">
          <span>{tooltipFmt.format(minT)}</span>
          <span>→</span>
          <span>{tooltipFmt.format(maxT)}</span>
          <span className="text-ink-400">· {bucketSizeLabel(bucketMs)}/bar</span>
          {(outside.earlier > 0 || outside.later > 0) && (
            <span className="text-ink-400">
              ·{" "}
              {[
                outside.earlier > 0 && labels.earlier.replace("{n}", String(outside.earlier)),
                outside.later > 0 && labels.later.replace("{n}", String(outside.later)),
              ]
                .filter(Boolean)
                .join(" / ")}
            </span>
          )}
        </div>
        {view && (view.zoomed || view.canZoom) && (
          <button
            type="button"
            onClick={() => setZoomPref(view.zoomed ? "full" : "range")}
            className="rounded px-1 text-uv-600 underline decoration-dotted underline-offset-2 hover:text-uv-700 dark:text-uv-400 dark:hover:text-uv-300"
          >
            {view.zoomed ? labels.fullSpan : labels.zoomToRange}
          </button>
        )}
      </div>
    </div>
  );
}
