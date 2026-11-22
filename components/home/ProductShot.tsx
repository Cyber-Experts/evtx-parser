// Static, decorative rendering of the viewer: a dark app window with the
// event timeline, a facet rail and the table, where one Sigma hit "flares".
// Pure markup (no data, no JS) so it costs nothing on the home page.

const BARS = [
  18, 22, 15, 30, 26, 20, 34, 28, 24, 19, 27, 36, 31, 22, 18, 25, 29, 33, 21, 17,
  23, 28, 35, 30, 26, 22, 19, 24, 92, 40, 27, 21, 18, 26, 31, 24, 20, 28, 33, 25,
  22, 19, 27, 30, 24, 21, 18, 23,
];

const FACETS: [string, string, number][] = [
  ["4624", "1,204", 100],
  ["4688", "913", 76],
  ["4672", "388", 32],
  ["4634", "352", 29],
  ["4104", "12", 4],
  ["7045", "3", 2],
];

type Row = { t: string; lvl: "info" | "warn" | "err"; id: string; src: string; msg: string; hit?: boolean };

const ROWS: Row[] = [
  { t: "03:51:52.591", lvl: "info", id: "4624", src: "Security", msg: "An account was successfully logged on · jdoe · Type 10" },
  { t: "03:51:52.604", lvl: "info", id: "4672", src: "Security", msg: "Special privileges assigned to new logon · jdoe" },
  { t: "03:52:07.113", lvl: "info", id: "4688", src: "Security", msg: "New process · C:\\Windows\\System32\\cmd.exe" },
  { t: "03:52:31.842", lvl: "warn", id: "4104", src: "PowerShell", msg: "IEX (New-Object Net.WebClient).DownloadString('http://…')", hit: true },
  { t: "03:52:33.017", lvl: "info", id: "4688", src: "Security", msg: "New process · powershell.exe -nop -w hidden -enc JAB…" },
  { t: "03:53:10.420", lvl: "err", id: "7045", src: "System", msg: "A service was installed · PSEXESVC · demand start" },
  { t: "03:53:44.208", lvl: "info", id: "4634", src: "Security", msg: "An account was logged off · jdoe" },
];

const LVL: Record<Row["lvl"], string> = {
  info: "bg-ink-600",
  warn: "bg-amber-400",
  err: "bg-red-500",
};

export function ProductShot() {
  return (
    <div
      aria-hidden="true"
      className="marks relative mx-auto w-full select-none"
    >
      <div className="absolute inset-x-[20%] -bottom-4 -z-10 h-24 rounded-full bg-uv-500/15 blur-3xl" />
      <div className="overflow-hidden rounded-xl border border-ink-900 bg-[#0c0c0c] font-mono text-[11px] text-ink-400 shadow-[0_40px_80px_-30px_rgb(10_10_10/0.45)] ring-1 ring-black/5 dark:border-white/10 dark:shadow-[0_40px_80px_-30px_rgb(0_0_0/0.9)]">
        {/* title bar */}
        <div className="flex items-center gap-3 border-b border-white/[0.07] px-4 py-2.5">
          <span className="flex gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
            <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
            <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
          </span>
          <span className="ml-2 flex gap-1">
            <span className="rounded-md bg-white/[0.07] px-2.5 py-1 text-ink-200">Security.evtx</span>
            <span className="rounded-md px-2.5 py-1">PowerShell%4Operational.evtx</span>
            <span className="hidden rounded-md px-2.5 py-1 md:inline">System.evtx</span>
          </span>
          <span className="ml-auto hidden items-center gap-2 sm:flex">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            4,512 events · 0 bytes uploaded
          </span>
        </div>

        {/* query */}
        <div className="flex items-center gap-2 border-b border-white/[0.07] px-4 py-2.5">
          <span className="text-uv-400">›</span>
          <span className="text-ink-200">
            <span className="text-ink-500">EventID:</span>4104 <span className="text-ink-500">OR</span>{" "}
            <span className="text-ink-500">Image:</span>*powershell*
          </span>
          <span className="ml-auto hidden rounded border border-white/10 px-1.5 text-[10px] text-ink-500 sm:inline">⌘K</span>
        </div>

        {/* timeline */}
        <div className="flex h-16 items-end gap-[3px] border-b border-white/[0.07] px-4 pt-3 pb-2">
          {BARS.map((h, i) => (
            <span
              key={i}
              className={`flex-1 rounded-[1px] ${h > 80 ? "bg-uv-500 shadow-[0_0_16px_rgb(123_76_255/0.8)]" : "bg-white/[0.12]"}`}
              style={{ height: `${Math.min(h, 100)}%` }}
            />
          ))}
        </div>

        <div className="grid md:grid-cols-[180px_1fr]">
          {/* facet rail */}
          <div className="hidden flex-col gap-2.5 border-r border-white/[0.07] p-4 md:flex">
            <span className="text-[10px] tracking-[0.12em] text-ink-500 uppercase">Event ID</span>
            {FACETS.map(([id, n, w]) => (
              <span key={id} className="flex flex-col gap-1">
                <span className="flex justify-between">
                  <span className={id === "4104" ? "text-uv-400" : "text-ink-300"}>{id}</span>
                  <span className="text-ink-500">{n}</span>
                </span>
                <span className="h-[3px] rounded-full bg-white/[0.06]">
                  <span
                    className={`block h-full rounded-full ${id === "4104" ? "bg-uv-500" : "bg-white/25"}`}
                    style={{ width: `${Math.max(w, 3)}%` }}
                  />
                </span>
              </span>
            ))}
          </div>

          {/* table */}
          <div className="min-w-0">
            <div className="grid grid-cols-[92px_44px_1fr] gap-3 border-b border-white/[0.07] px-4 py-2 text-[10px] tracking-[0.12em] text-ink-500 uppercase sm:grid-cols-[100px_48px_90px_1fr]">
              <span>Time</span>
              <span>ID</span>
              <span className="hidden sm:block">Channel</span>
              <span>Summary</span>
            </div>
            {ROWS.map((r) => (
              <div
                key={r.t}
                className={`relative grid grid-cols-[92px_44px_1fr] items-center gap-3 border-b border-white/[0.04] px-4 py-2 sm:grid-cols-[100px_48px_90px_1fr] ${r.hit ? "bg-uv-500/[0.1] text-ink-100" : ""}`}
              >
                {r.hit && <span className="absolute inset-y-0 left-0 w-[2px] bg-uv-500" />}
                <span className="flex items-center gap-2">
                  <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${LVL[r.lvl]}`} />
                  {r.t}
                </span>
                <span className={r.hit ? "text-uv-300" : "text-ink-200"}>{r.id}</span>
                <span className="hidden truncate sm:block">{r.src}</span>
                <span className="flex min-w-0 items-center gap-2">
                  <span className="truncate">{r.msg}</span>
                  {r.hit && (
                    <span className="hidden shrink-0 rounded-full border border-uv-500/50 bg-uv-500/15 px-2 py-0.5 text-[10px] text-uv-300 lg:inline">
                      Sigma · high · Download cradle
                    </span>
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
