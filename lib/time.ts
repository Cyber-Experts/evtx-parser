// Timestamp display for the viewer. EVTX stores UTC with 100 ns precision;
// the parser gives microseconds ("2020-04-03T02:01:40.424361+00:00"). Date
// only keeps milliseconds, so the fractional part is taken from the string.

export type TimeMode = "utc" | "local";

const TS_RE = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d+)?/;

const pad = (n: number, w = 2) => String(n).padStart(w, "0");

/** "2020-04-03 02:01:40.424361" in UTC or the viewer's local time. */
export function formatTimestamp(ts: string, mode: TimeMode): string {
  const m = TS_RE.exec(ts);
  if (!m) return ts;
  const frac = m[3] ?? "";
  if (mode === "utc") return `${m[1]} ${m[2]}${frac}`;
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}${frac}`
  );
}

/** Same format for an epoch-ms value (time-range chips). */
export function formatEpoch(ms: number, mode: TimeMode): string {
  return formatTimestamp(new Date(ms).toISOString(), mode).replace(/\.\d+$/, "");
}

/** "UTC" or the local offset at `at` (an ISO timestamp; default now),
 *  e.g. "UTC+02:00". */
export function zoneLabel(mode: TimeMode, at?: string): string {
  if (mode === "utc") return "UTC";
  const t = at ? Date.parse(at) : NaN;
  const off = -new Date(Number.isNaN(t) ? Date.now() : t).getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  const a = Math.abs(off);
  return `UTC${sign}${pad(Math.floor(a / 60))}:${pad(a % 60)}`;
}
