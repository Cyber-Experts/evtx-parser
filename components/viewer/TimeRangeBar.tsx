"use client";

import { useEffect, useId, useRef, useState } from "react";

import type { Dict } from "@/src/dict/types";
import type { TimeMode } from "@/lib/time";
import {
  ANY_FIELD,
  AROUND_WINDOWS,
  PRIMARY_FIELD,
  presetRange,
  rangeFromInputs,
  rangeLabel,
  toInputValue,
  type PresetId,
  type TimeRange,
} from "@/lib/time-range";

// Typing is applied after a short pause so each keystroke in a datetime
// segment doesn't refilter a million rows.
const DEBOUNCE_MS = 150;

export function aroundLabel(ms: number, dict: Dict): string {
  const v = dict.viewer;
  return ms <= 5 * 60_000 ? v.win5m : ms <= 3_600_000 ? v.win1h : v.win24h;
}

/**
 * The results workspace's time-range filter: From/To (to the second, in the
 * viewer's UTC/local mode), presets derived from the data, the "Around…"
 * window used by timestamp clicks, the time-field choice when records carry
 * several times, and the active-range chip. Collapses into a popover on
 * narrow screens.
 */
export function TimeRangeBar({
  dict,
  mode,
  zone,
  bounds,
  range,
  onApply,
  field,
  fields,
  onFieldChange,
  around,
  onAroundChange,
  count,
  total,
  numberFmt,
}: {
  dict: Dict;
  mode: TimeMode;
  zone: string;
  /** First / last time of the chosen field: input defaults and presets. */
  bounds: [number, number] | null;
  range: TimeRange | null;
  onApply: (range: TimeRange | null) => void;
  field: string;
  /** Secondary time fields present in the data (EventData). */
  fields: string[];
  onFieldChange: (field: string) => void;
  around: number;
  onAroundChange: (ms: number) => void;
  /** Records in range / all records. */
  count: number;
  total: number;
  numberFmt: Intl.NumberFormat;
}) {
  const v = dict.viewer;
  const id = useId();
  const [open, setOpen] = useState(false);

  const initial: [number, number] | null = range ? [range.from, range.to] : bounds;
  // Inputs are seeded from the applied range (or the data bounds) and
  // re-seeded whenever those or the time zone change.
  const seed = `${initial?.[0]}|${initial?.[1]}|${mode}`;
  const seeded = () => ({
    seed,
    from: initial ? toInputValue(initial[0], mode) : "",
    to: initial ? toInputValue(initial[1], mode) : "",
  });
  const [state, setState] = useState(seeded);
  let { from, to } = state;
  if (state.seed !== seed) {
    const next = seeded();
    ({ from, to } = next);
    setState(next);
  }
  const parsed = rangeFromInputs(from, to, mode);
  const orderError = "error" in parsed && parsed.error === "order";

  // Debounced apply of what's typed (Enter applies at once).
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);
  const applyTyped = (f: string, t: string, now = false) => {
    if (timer.current) clearTimeout(timer.current);
    const go = () => {
      const r = rangeFromInputs(f, t, mode);
      if (!("range" in r)) return;
      if (range && r.range.from === range.from && r.range.to === range.to) return;
      onApply(r.range);
    };
    if (now) go();
    else timer.current = setTimeout(go, DEBOUNCE_MS);
  };

  const inputCls =
    "w-full min-w-0 rounded-md border bg-transparent px-2 py-1 font-mono text-xs outline-none focus:border-uv-500 sm:w-auto dark:[color-scheme:dark]";
  const selectCls =
    "rounded-md border border-ink-300 bg-transparent px-1.5 py-1 text-xs text-ink-700 outline-none focus:border-uv-500 dark:border-ink-700 dark:bg-ink-950 dark:text-ink-300";

  const label = range ? rangeLabel(range, mode) : null;

  return (
    <div className="relative flex flex-wrap items-center gap-2 text-xs">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls={`${id}-panel`}
        className={`rounded-md border px-2 py-1 sm:hidden ${
          range
            ? "border-uv-500 bg-uv-500/15 text-uv-700 dark:border-uv-400/60 dark:bg-uv-400/10 dark:text-uv-300"
            : "border-ink-300 text-ink-700 dark:border-ink-700 dark:text-ink-300"
        }`}
      >
        ⏱ {v.rangeTitle} {open ? "▴" : "▾"}
      </button>

      <form
        id={`${id}-panel`}
        onSubmit={(e) => {
          e.preventDefault();
          applyTyped(from, to, true);
        }}
        onKeyDown={(e) => {
          // Esc closes the mobile popover; never leaves full screen from here.
          if (e.key === "Escape") {
            e.preventDefault();
            e.stopPropagation();
            if (open) setOpen(false);
          }
        }}
        className={`${
          open ? "flex" : "hidden"
        } absolute left-0 right-0 top-full z-30 mt-1 flex-col gap-2 rounded-lg border border-ink-200 bg-white p-3 shadow-lg sm:static sm:z-auto sm:mt-0 sm:flex sm:flex-row sm:flex-wrap sm:items-center sm:border-0 sm:bg-transparent sm:p-0 sm:shadow-none dark:border-ink-800 dark:bg-ink-950 sm:dark:bg-transparent`}
      >
        <span className="hidden text-ink-500 sm:inline">⏱ {v.rangeTitle}</span>
        <label className="flex items-center gap-1">
          <span className="w-10 shrink-0 text-ink-500 sm:w-auto">{v.rangeFrom}</span>
          <input
            type="datetime-local"
            step={1}
            value={from}
            aria-label={`${v.rangeTitle}: ${v.rangeFrom} (${zone})`}
            aria-invalid={orderError}
            aria-describedby={orderError ? `${id}-err` : undefined}
            onChange={(e) => {
              setState((s) => ({ ...s, from: e.target.value }));
              applyTyped(e.target.value, to);
            }}
            className={`${inputCls} ${orderError ? "border-red-400" : "border-ink-300 dark:border-ink-700"}`}
          />
        </label>
        <label className="flex items-center gap-1">
          <span className="w-10 shrink-0 text-ink-500 sm:w-auto">{v.rangeTo}</span>
          <input
            type="datetime-local"
            step={1}
            value={to}
            aria-label={`${v.rangeTitle}: ${v.rangeTo} (${zone})`}
            aria-invalid={orderError}
            aria-describedby={orderError ? `${id}-err` : undefined}
            onChange={(e) => {
              setState((s) => ({ ...s, to: e.target.value }));
              applyTyped(from, e.target.value);
            }}
            className={`${inputCls} ${orderError ? "border-red-400" : "border-ink-300 dark:border-ink-700"}`}
          />
        </label>
        <span className="font-mono text-ink-400">{zone}</span>
        {/* Enter in an input submits: apply at once. */}
        <button type="submit" hidden tabIndex={-1} aria-hidden="true" />

        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label={v.rangePreset}
            value=""
            disabled={!bounds}
            onChange={(e) => {
              const p = e.target.value as PresetId;
              if (bounds && p) onApply(presetRange(p, bounds));
            }}
            className={selectCls}
          >
            <option value="" disabled>
              {v.rangePreset}…
            </option>
            <option value="all">{v.presetAll}</option>
            <option value="firstHour">{v.presetFirstHour}</option>
            <option value="lastHour">{v.presetLastHour}</option>
            <option value="last24h">{v.presetLast24h}</option>
          </select>
          <label className="flex items-center gap-1" title={v.rangeAroundHint}>
            <span className="text-ink-500">{v.rangeAround}</span>
            <select
              value={around}
              onChange={(e) => onAroundChange(Number(e.target.value))}
              aria-describedby={`${id}-around`}
              className={selectCls}
            >
              {AROUND_WINDOWS.map((ms) => (
                <option key={ms} value={ms}>
                  {aroundLabel(ms, dict)}
                </option>
              ))}
            </select>
            <span id={`${id}-around`} className="sr-only">
              {v.rangeAroundHint}
            </span>
          </label>
          {fields.length > 0 && (
            <label className="flex items-center gap-1" title={v.rangeFieldHint}>
              <span className="text-ink-500">{v.rangeField}</span>
              <select
                value={field}
                onChange={(e) => onFieldChange(e.target.value)}
                aria-describedby={`${id}-field`}
                className={`${selectCls} max-w-[22ch]`}
              >
                <option value={PRIMARY_FIELD}>{v.rangeFieldPrimary}</option>
                {fields.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
                <option value={ANY_FIELD}>{v.rangeFieldAny}</option>
              </select>
              <span id={`${id}-field`} className="sr-only">
                {v.rangeFieldHint}
              </span>
            </label>
          )}
        </div>
        {orderError && (
          <span id={`${id}-err`} role="alert" className="text-red-500">
            {v.rangeInvalid}
          </span>
        )}
      </form>

      {range && label && (
        <span
          className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-uv-500 bg-uv-500/15 py-0.5 pl-2 pr-0.5 font-mono text-[11px] text-uv-700 dark:border-uv-400/60 dark:bg-uv-400/10 dark:text-uv-300"
          title={field !== PRIMARY_FIELD ? `${field === ANY_FIELD ? v.rangeFieldAny : field} · ${v.rangeFieldHint}` : undefined}
        >
          <span className="truncate">
            {label.from} → {label.to} {zone}
            {field !== PRIMARY_FIELD && (
              <span className="text-uv-600/80 dark:text-uv-300/80">
                {" "}
                · {field === ANY_FIELD ? v.rangeFieldAny : field}
              </span>
            )}
            <span className="text-ink-500 dark:text-ink-400">
              {" "}
              ·{" "}
              {v.rangeCount
                .replace("{n}", numberFmt.format(count))
                .replace("{total}", numberFmt.format(total))}
            </span>
          </span>
          <button
            type="button"
            onClick={() => onApply(null)}
            aria-label={dict.home.clearTime}
            title={dict.home.clearTime}
            className="rounded px-1.5 leading-none hover:bg-uv-500/20"
          >
            ×
          </button>
        </span>
      )}
    </div>
  );
}
