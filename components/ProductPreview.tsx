// Decorative product shot for the homepage hero: the viewer "under the
// lamp" — a query, a timeline and a few events, the suspicious one glowing.
// Pure HTML/CSS (no image to load), always dark like a product screenshot,
// and hidden from assistive tech (the real tool is right below it).

const BARS = [
  18, 26, 22, 34, 30, 44, 38, 28, 24, 30, 36, 90, 42, 30, 26, 22, 28, 34, 26,
  20, 24, 30, 22, 18,
];

const ROWS: {
  t: string;
  id: string;
  name: string;
  detail: string;
  hit?: boolean;
}[] = [
  {
    t: "03:51:52.591",
    id: "4624",
    name: "Successful logon",
    detail: "jim.tomato · Interactive",
  },
  {
    t: "03:52:07.113",
    id: "4672",
    name: "Special privileges",
    detail: "admin · SeDebugPrivilege",
  },
  {
    t: "03:52:18.402",
    id: "4688",
    name: "Process created",
    detail: "powershell.exe -nop -w hidden",
  },
  {
    t: "03:52:31.842",
    id: "4104",
    name: "Script block",
    detail: "IEX (New-Object Net.WebClient).DownloadString(…)",
    hit: true,
  },
  {
    t: "03:53:02.017",
    id: "4720",
    name: "User account created",
    detail: "svc_backup$ by admin",
  },
];

const FACETS = [
  { id: "4624", n: 4210 },
  { id: "4672", n: 2388 },
  { id: "4688", n: 1904 },
  { id: "4634", n: 1650 },
  { id: "4769", n: 412 },
  { id: "4104", n: 1, hit: true },
];

export function ProductPreview() {
  return (
    <div aria-hidden="true" className="relative select-none">
      {/* lamp glow behind the window */}
      <div className="absolute -inset-8 -z-10 rounded-[2rem] bg-[radial-gradient(closest-side,rgb(58_107_255/0.35),transparent)] blur-2xl" />
      <div className="overflow-hidden rounded-2xl border border-white/10 bg-[#0c0d10] text-[11px] text-[#c8cdd5] sm:text-xs shadow-[0_30px_80px_-30px_rgb(0_0_0/0.8),inset_0_1px_0_rgb(255_255_255/0.06)]">
        {/* window chrome */}
        <div className="flex items-center gap-2 border-b border-white/[0.06] bg-white/[0.02] px-3.5 py-2.5">
          <span className="h-2.5 w-2.5 rounded-full bg-[#ff5f57]/80" />
          <span className="h-2.5 w-2.5 rounded-full bg-[#febc2e]/80" />
          <span className="h-2.5 w-2.5 rounded-full bg-[#28c840]/80" />
          <span className="ml-3 font-mono text-[#979eaa]">
            Security.evtx · 10,667 events
          </span>
        </div>

        <div className="flex">
          {/* facet sidebar — only when the shot is wide enough */}
          <div className="hidden w-44 shrink-0 flex-col gap-2.5 border-r border-white/[0.06] p-3.5 font-mono md:flex">
            <span className="text-[10px] tracking-[0.14em] text-[#6b727f] uppercase">
              Event ID
            </span>
            {FACETS.map((f) => (
              <div key={f.id} className="flex flex-col gap-1">
                <div className="flex justify-between">
                  <span className={f.hit ? "text-[#63eafb]" : "text-[#c8cdd5]"}>
                    {f.id}
                  </span>
                  <span className="text-[#6b727f]">
                    {f.n.toLocaleString("en-US")}
                  </span>
                </div>
                <span className="h-1 rounded-full bg-white/[0.05]">
                  <span
                    className={`block h-1 rounded-full ${f.hit ? "bg-[#22d6f0]" : "bg-[#5c8eff]/60"}`}
                    style={{
                      width: `${Math.max(4, (f.n / FACETS[0].n) * 100)}%`,
                    }}
                  />
                </span>
              </div>
            ))}
          </div>
          <div className="flex min-w-0 flex-1 flex-col gap-3 p-3.5">
            {/* query */}
            <div className="flex items-center gap-2 rounded-lg border border-[#5c8eff]/40 bg-[#5c8eff]/[0.07] px-3 py-2 font-mono">
              <span className="text-[#5c8eff]">⌕</span>
              <span className="text-[#ededf0]">EventID:4104</span>
              <span className="text-[#979eaa]">
                ScriptBlockText:*DownloadString*
              </span>
              <span className="ml-auto rounded bg-[#22d6f0]/15 px-1.5 text-[#63eafb]">
                1 hit
              </span>
            </div>

            {/* timeline */}
            <div className="flex h-14 items-end gap-[3px] rounded-lg border border-white/[0.06] bg-white/[0.02] px-2 pt-2">
              {BARS.map((h, i) => (
                <span
                  key={i}
                  className={`flex-1 rounded-t-[2px] ${
                    h > 60
                      ? "bg-[#22d6f0] shadow-[0_0_12px_rgb(34_214_240/0.6)]"
                      : "bg-[#6b727f]/50"
                  }`}
                  style={{ height: `${h}%` }}
                />
              ))}
            </div>

            {/* events */}
            <div className="flex flex-col font-mono">
              {ROWS.map((r) => (
                <div
                  key={r.id}
                  className={`grid grid-cols-[88px_40px_1fr] items-center gap-3 rounded-md px-2.5 py-1.5 ${
                    r.hit
                      ? "border-l-2 border-[#22d6f0] bg-[#22d6f0]/[0.09] text-[#a2f5fd]"
                      : "border-l-2 border-transparent text-[#979eaa]"
                  }`}
                >
                  <span>{r.t}</span>
                  <span
                    className={
                      r.hit ? "font-semibold text-[#22d6f0]" : "text-[#c8cdd5]"
                    }
                  >
                    {r.id}
                  </span>
                  <span className="truncate">
                    <span
                      className={r.hit ? "text-[#a2f5fd]" : "text-[#e3e6eb]"}
                    >
                      {r.name}
                    </span>
                    <span className="opacity-70"> · {r.detail}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
