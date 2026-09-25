"use client";

import { useState } from "react";

import type { Dict } from "@/src/dict/types";
import { formatEpoch, type TimeMode } from "@/lib/time";

// <input type="datetime-local"> speaks "YYYY-MM-DDTHH:MM:SS" with no zone;
// the viewer's UTC/local toggle decides how it is interpreted.
const toInput = (ms: number, mode: TimeMode) => formatEpoch(ms, mode).replace(" ", "T");

function fromInput(value: string, mode: TimeMode): number | null {
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d)?$/.test(value)) return null;
  const withSeconds = value.length === 16 ? `${value}:00` : value;
  const ms = mode === "utc" ? Date.parse(`${withSeconds}Z`) : new Date(withSeconds).getTime();
  return Number.isNaN(ms) ? null : ms;
}

/** Typed start/end window (Timesketch-style), in UTC or local time. */
export function TimeRangeInput({
  dict,
  mode,
  zone,
  bounds,
  range,
  onApply,
}: {
  dict: Dict;
  mode: TimeMode;
  zone: string;
  /** First / last event time of the dataset, used as defaults. */
  bounds: [number, number] | null;
  range: [number, number] | null;
  onApply: (range: [number, number] | null) => void;
}) {
  const v = dict.viewer;
  const initial = range ?? bounds;
  // Inputs are seeded from the applied range (or the dataset bounds) and
  // re-seeded whenever those or the time zone change.
  const seed = `${initial?.[0]}|${initial?.[1]}|${mode}|${range ? 1 : 0}`;
  const seeded = () => ({
    seed,
    from: initial ? toInput(initial[0], mode) : "",
    // Applied ranges are end-exclusive (last second + 1 s): show the last
    // included second so re-applying doesn't drift.
    to: initial ? toInput(range ? initial[1] - 1000 : initial[1], mode) : "",
  });
  const [state, setState] = useState(seeded);
  let { from, to } = state;
  if (state.seed !== seed) {
    const next = seeded();
    ({ from, to } = next);
    setState(next);
  }
  const a = fromInput(from, mode);
  const b = fromInput(to, mode);
  const invalid = a != null && b != null && a >= b;

  const input =
    "rounded-md border border-zinc-300 bg-transparent px-2 py-1 font-mono text-xs outline-none focus:border-amber-500 dark:border-zinc-700 dark:[color-scheme:dark]";

  return (
    <form
      className="flex flex-wrap items-center gap-2 text-xs"
      onSubmit={(e) => {
        e.preventDefault();
        // The end is inclusive to the second: include events at hh:mm:ss.xxx.
        if (a != null && b != null && !invalid) onApply([a, b + 1000]);
      }}
    >
      <span className="text-zinc-500">⏱ {v.rangeTitle}</span>
      <label className="flex items-center gap-1">
        <span className="text-zinc-500">{v.rangeFrom}</span>
        <input
          type="datetime-local"
          step={1}
          value={from}
          onChange={(e) => setState((s) => ({ ...s, from: e.target.value }))}
          className={input}
        />
      </label>
      <label className="flex items-center gap-1">
        <span className="text-zinc-500">{v.rangeTo}</span>
        <input
          type="datetime-local"
          step={1}
          value={to}
          onChange={(e) => setState((s) => ({ ...s, to: e.target.value }))}
          className={`${input} ${invalid ? "border-red-400" : ""}`}
        />
      </label>
      <span className="font-mono text-zinc-400">{zone}</span>
      <button
        type="submit"
        disabled={a == null || b == null || invalid}
        className="rounded-md border border-zinc-300 px-2 py-1 text-zinc-700 hover:bg-zinc-100 disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
      >
        {v.rangeApply}
      </button>
      {range && (
        <button
          type="button"
          onClick={() => onApply(null)}
          className="rounded-md border border-zinc-200 px-2 py-1 text-zinc-600 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-900"
        >
          {dict.home.clearTime}
        </button>
      )}
      {invalid && <span className="text-red-500">{v.rangeInvalid}</span>}
    </form>
  );
}
