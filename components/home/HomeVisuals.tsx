// Home page building blocks with product-style illustrations: the channel
// marquee, per-feature mini UIs for the bento grid, "How it works" and the
// "Private by architecture" diagram. Server components, decorative visuals
// are aria-hidden so screen readers get the copy only.

import {
  Bookmark,
  Check,
  Cpu,
  FileText,
  Monitor,
  Search,
  Server,
  ShieldCheck,
  X,
} from "lucide-react";

import { HUNTS } from "@/lib/hunts";
import { LOCALES } from "@/lib/i18n";
import type { Dict } from "@/src/dict/types";

import { SectionHeading } from "./HomeSections";

const CHANNELS = [
  "Security",
  "System",
  "Application",
  "Sysmon",
  "PowerShell",
  "RDP",
  "Defender",
  "Task Scheduler",
  "WMI",
  "AppLocker",
  "Kerberos",
  "BITS",
];

/* ---------------- channel marquee ---------------- */

export function ChannelMarquee({ label }: { label: string }) {
  const row = (hidden: boolean) => (
    <ul
      aria-hidden={hidden || undefined}
      className="flex shrink-0 items-center gap-3 pr-3"
    >
      {CHANNELS.map((c) => (
        <li
          key={c}
          className="flex items-center gap-2 rounded-full border border-ink-200/80 bg-card px-3.5 py-1.5 font-mono text-xs whitespace-nowrap text-ink-600 dark:border-white/[0.08] dark:bg-white/[0.02] dark:text-ink-300"
        >
          <span aria-hidden="true" className="size-1.5 rounded-full bg-uv-500/70" />
          {c}
        </li>
      ))}
    </ul>
  );
  return (
    <section aria-label={label} className="flex flex-col items-center gap-5">
      <span className="text-sm text-ink-500">{label}</span>
      <div className="relative w-full overflow-hidden [mask-image:linear-gradient(90deg,transparent,black_12%,black_88%,transparent)]">
        <div className="animate-marquee flex w-max">
          {row(false)}
          {row(true)}
        </div>
      </div>
    </section>
  );
}

/* ---------------- bento visuals ---------------- */

/** Dotted canvas every bento visual sits on. */
export function Canvas({ children, tall = false }: { children: React.ReactNode; tall?: boolean }) {
  return (
    <div
      aria-hidden="true"
      className={`relative flex items-center justify-center overflow-hidden border-b border-ink-200/70 bg-ink-50/60 px-6 dark:border-white/[0.06] dark:bg-white/[0.015] ${
        tall ? "h-60" : "h-56"
      }`}
    >
      <div className="absolute inset-0 bg-[radial-gradient(rgb(11_12_15/0.07)_1px,transparent_1px)] [background-size:14px_14px] [mask-image:radial-gradient(ellipse_at_center,black,transparent_75%)] dark:bg-[radial-gradient(rgb(255_255_255/0.07)_1px,transparent_1px)]" />
      <div className="absolute -top-20 left-1/2 h-40 w-72 -translate-x-1/2 rounded-full bg-uv-500/10 blur-3xl dark:bg-uv-500/15" />
      <div className="relative w-full">{children}</div>
    </div>
  );
}

const PANEL =
  "rounded-xl border border-ink-200 bg-card shadow-[0_1px_2px_rgb(11_12_15/0.04),0_12px_32px_-16px_rgb(11_12_15/0.18)] dark:border-white/[0.09] dark:bg-ink-900 dark:shadow-[0_16px_40px_-20px_rgb(0_0_0/0.8)]";

function HuntsVisual() {
  const rows = [
    { sev: "high", name: "Security log cleared", id: "1102", n: 1 },
    { sev: "high", name: "PowerShell download cradle", id: "4104", n: 3 },
    { sev: "med", name: "Kerberoasting (RC4 TGS)", id: "4769", n: 12 },
    { sev: "med", name: "New service installed", id: "7045", n: 2 },
  ];
  return (
    <div className={`${PANEL} mx-auto flex max-w-md flex-col gap-1 p-1.5 font-mono text-[11px]`}>
      {rows.map((r) => (
        <div
          key={r.name}
          className="flex items-center gap-3 rounded-lg px-2.5 py-1.5 even:bg-ink-50 dark:even:bg-white/[0.03]"
        >
          <span
            className={`w-10 rounded px-1 py-0.5 text-center text-[9px] font-semibold uppercase ${
              r.sev === "high"
                ? "bg-red-500/10 text-red-600 dark:text-red-400"
                : "bg-orange-500/10 text-orange-600 dark:text-orange-400"
            }`}
          >
            {r.sev}
          </span>
          <span className="truncate text-ink-800 dark:text-ink-200">{r.name}</span>
          <span className="ml-auto text-ink-400">{r.id}</span>
          <span className="min-w-6 rounded bg-glow-400/15 px-1.5 text-center text-glow-700 dark:text-glow-300">
            {r.n}
          </span>
        </div>
      ))}
    </div>
  );
}

function QueryVisual() {
  const facets = [
    ["LogonType", "10", 38],
    ["IpAddress", "10.0.4.17", 21],
    ["TargetUserName", "admin", 9],
  ] as const;
  return (
    <div className={`${PANEL} mx-auto max-w-sm overflow-hidden font-mono text-[11px]`}>
      <div className="flex items-center gap-2 border-b border-ink-200 px-3 py-2.5 dark:border-white/[0.08]">
        <Search className="size-3.5 shrink-0 text-ink-400" />
        <span className="truncate">
          <span className="text-uv-600 dark:text-uv-300">EventID</span>
          <span className="text-ink-400">:</span>
          <span className="text-ink-900 dark:text-ink-100">4624</span>{" "}
          <span className="text-uv-600 dark:text-uv-300">LogonType</span>
          <span className="text-ink-400">:</span>
          <span className="text-ink-900 dark:text-ink-100">10</span>{" "}
          <span className="text-red-500">-IpAddress</span>
          <span className="text-ink-400">:</span>
          <span className="text-ink-900 dark:text-ink-100">127.0.0.1</span>
        </span>
        <span className="animate-caret ml-0.5 h-3.5 w-px shrink-0 bg-uv-500" />
      </div>
      <div className="flex flex-col gap-1 p-2">
        {facets.map(([k, v, n], i) => (
          <div key={k} className="flex items-center gap-2 px-1">
            <span className="w-24 truncate text-ink-500">{k}</span>
            <span className="truncate text-ink-800 dark:text-ink-200">{v}</span>
            <span className="relative ml-auto h-1.5 w-16 overflow-hidden rounded-full bg-ink-100 dark:bg-white/[0.06]">
              <span
                className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-uv-500 to-glow-400"
                style={{ width: `${[100, 60, 28][i]}%` }}
              />
            </span>
            <span className="w-5 text-right text-ink-400">{n}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function PivotVisual() {
  const kids = [
    ["4672", "Special privileges"],
    ["4688", "powershell.exe -nop"],
    ["4634", "Logoff"],
  ];
  return (
    <div className="mx-auto flex max-w-xs flex-col font-mono text-[11px]">
      <div className={`${PANEL} flex items-center gap-2 px-3 py-2`}>
        <span className="rounded bg-uv-500/10 px-1.5 text-uv-700 dark:text-uv-300">4624</span>
        <span className="truncate text-ink-700 dark:text-ink-300">Logon · admin · RDP</span>
      </div>
      <div className="ml-5 flex flex-col border-l border-dashed border-uv-400/60 pt-2">
        <span className="-ml-px flex items-center gap-2 border-l border-transparent pl-3 text-[10px] text-ink-500">
          <span className="rounded-full border border-uv-300 bg-card px-2 py-0.5 text-uv-700 dark:border-uv-400/40 dark:bg-ink-900 dark:text-uv-300">
            LogonId 0x3e7a1
          </span>
        </span>
        {kids.map(([id, text]) => (
          <div key={id} className="flex items-center pt-2">
            <span className="h-px w-3 bg-uv-400/60" />
            <span className={`${PANEL} flex flex-1 items-center gap-2 px-2.5 py-1.5 !shadow-none`}>
              <span className="text-ink-500">{id}</span>
              <span className="truncate text-ink-800 dark:text-ink-200">{text}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SessionsVisual() {
  const rows = [
    { user: "admin", type: "RDP", from: 6, w: 52, hot: true },
    { user: "svc_backup", type: "Service", from: 22, w: 70, hot: false },
    { user: "jim.tomato", type: "Interactive", from: 2, w: 26, hot: false },
  ];
  return (
    <div className={`${PANEL} mx-auto flex max-w-xs flex-col gap-2.5 p-3 font-mono text-[11px]`}>
      {rows.map((r) => (
        <div key={r.user} className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <span className="text-ink-800 dark:text-ink-200">{r.user}</span>
            <span className="text-ink-400">{r.type}</span>
          </div>
          <div className="relative h-2 rounded-full bg-ink-100 dark:bg-white/[0.05]">
            <span
              className={`absolute inset-y-0 rounded-full ${
                r.hot
                  ? "bg-gradient-to-r from-uv-500 to-glow-400 shadow-[0_0_12px_rgb(34_214_240/0.5)]"
                  : "bg-ink-300 dark:bg-ink-600"
              }`}
              style={{ left: `${r.from}%`, width: `${r.w}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function ReportVisual() {
  return (
    <div className={`${PANEL} mx-auto flex max-w-xs flex-col gap-2 p-3.5 font-mono text-[11px]`}>
      <div className="flex items-center gap-2">
        <FileText className="size-3.5 text-ink-400" />
        <span className="text-ink-900 dark:text-ink-100"># Incident 2026-11-03</span>
      </div>
      <span className="h-1.5 w-11/12 rounded-full bg-ink-100 dark:bg-white/[0.06]" />
      <span className="h-1.5 w-3/4 rounded-full bg-ink-100 dark:bg-white/[0.06]" />
      <div className="mt-1 flex items-center gap-2 rounded-md border-l-2 border-uv-500 bg-uv-500/[0.07] px-2 py-1.5">
        <Bookmark className="size-3 fill-current text-uv-600 dark:text-uv-300" />
        <span className="text-ink-800 dark:text-ink-200">4104 · Script block</span>
      </div>
      <span className="h-1.5 w-2/3 rounded-full bg-ink-100 dark:bg-white/[0.06]" />
      <span className="mt-1 self-end rounded-md border border-ink-200 px-2 py-0.5 text-[10px] text-ink-500 dark:border-white/10">
        report.md ↓
      </span>
    </div>
  );
}

export const FEATURE_VISUALS = [
  <HuntsVisual key="hunts" />,
  <QueryVisual key="query" />,
  <PivotVisual key="pivots" />,
  <SessionsVisual key="sessions" />,
  <ReportVisual key="report" />,
];

/* ---------------- how it works ---------------- */

export function HowItWorks({ dict }: { dict: Dict }) {
  const h = dict.home;
  return (
    <section aria-labelledby="how-heading" className="flex flex-col gap-14">
      <SectionHeading id="how-heading" eyebrow={h.howEyebrow} title={h.howHeading} />
      <ol className="relative grid gap-10 md:grid-cols-3 md:gap-8">
        <span
          aria-hidden="true"
          className="absolute top-6 right-[16%] left-[16%] hidden h-px bg-[linear-gradient(90deg,transparent,rgb(58_107_255/0.5),rgb(34_214_240/0.5),transparent)] md:block"
        />
        {h.howSteps.map((s, i) => (
          <li key={s.title} className="relative flex flex-col items-center gap-4 text-center">
            <span className="relative flex size-12 items-center justify-center rounded-full border border-ink-200 bg-background font-mono text-sm font-medium text-ink-900 shadow-[0_0_0_6px_var(--background)] dark:border-white/10 dark:text-ink-100">
              <span className="absolute inset-0 rounded-full bg-gradient-to-b from-uv-500/15 to-glow-400/5" />
              <span className="relative">{String(i + 1).padStart(2, "0")}</span>
            </span>
            <h3 className="text-lg text-ink-950 dark:text-ink-50">{s.title}</h3>
            <p className="max-w-xs text-sm leading-relaxed text-ink-600 dark:text-ink-400">
              {s.body}
            </p>
          </li>
        ))}
      </ol>
    </section>
  );
}

/* ---------------- private by architecture ---------------- */

export function PrivacySection({ dict }: { dict: Dict }) {
  const h = dict.home;
  const stats = [
    { value: String(HUNTS.length), label: h.statHunts },
    { value: "0", label: h.statUploaded },
    { value: "Rust", label: h.statEngine },
    { value: String(LOCALES.length), label: h.statLocales },
  ];
  return (
    <section
      aria-labelledby="privacy-heading"
      className="surface relative grid items-center gap-12 overflow-hidden p-6 sm:p-10 lg:grid-cols-2 lg:gap-16 lg:p-14"
    >
      <span
        aria-hidden="true"
        className="pointer-events-none absolute -top-40 -right-40 size-[28rem] rounded-full bg-uv-500/10 blur-3xl dark:bg-uv-500/15"
      />
      <div className="relative flex flex-col gap-5">
        <span className="eyebrow flex items-center gap-2">
          <ShieldCheck className="size-4" aria-hidden="true" />
          {h.privacyEyebrow}
        </span>
        <h2
          id="privacy-heading"
          className="text-3xl leading-[1.05] tracking-[-0.04em] text-balance text-ink-950 sm:text-5xl dark:text-ink-50"
        >
          {h.privacyHeading}
        </h2>
        <p className="max-w-lg text-base leading-relaxed text-ink-600 dark:text-ink-400">
          {h.privacyBody}
        </p>
        <dl className="mt-4 grid grid-cols-2 gap-x-8 gap-y-6 border-t border-ink-200/70 pt-8 dark:border-white/[0.07]">
          {stats.map((s) => (
            <div key={s.label} className="flex flex-col gap-1">
              <dt className="order-2 text-sm text-ink-500 dark:text-ink-400">{s.label}</dt>
              <dd className="order-1 font-heading text-3xl font-semibold tracking-[-0.04em] text-ink-950 sm:text-4xl dark:text-white">
                {s.value}
              </dd>
            </div>
          ))}
        </dl>
      </div>

      {/* Diagram: everything happens inside the tab; the line to any server is cut. */}
      <div aria-hidden="true" className="relative flex flex-col items-center font-mono text-[11px]">
        <div className="w-full max-w-md rounded-2xl border border-ink-200 bg-ink-50/70 p-3 dark:border-white/[0.08] dark:bg-white/[0.02]">
          <div className="flex items-center gap-2 px-1 pb-3 text-ink-500">
            <Monitor className="size-3.5" />
            {h.privacyDevice}
          </div>
          <div className={`${PANEL} overflow-hidden`}>
            <div className="flex items-center gap-1.5 border-b border-ink-200 px-3 py-2 dark:border-white/[0.08]">
              <span className="size-2 rounded-full bg-ink-200 dark:bg-white/15" />
              <span className="size-2 rounded-full bg-ink-200 dark:bg-white/15" />
              <span className="size-2 rounded-full bg-ink-200 dark:bg-white/15" />
              <span className="ml-2 text-ink-500">{h.privacyTab}</span>
            </div>
            <div className="flex items-center justify-between gap-1.5 p-3 whitespace-nowrap sm:gap-2 sm:p-5">
              <span className="flex items-center gap-1.5 rounded-md border border-ink-200 px-2 py-1.5 text-ink-700 dark:border-white/10 dark:text-ink-300">
                <FileText className="size-3.5" />
                .evtx
              </span>
              <span className="h-px flex-1 bg-gradient-to-r from-ink-300 to-uv-400 dark:from-white/15" />
              <span className="flex items-center gap-1.5 rounded-md border border-uv-300 bg-uv-50 px-2 py-1.5 text-uv-700 shadow-[0_0_24px_-4px_rgb(58_107_255/0.5)] dark:border-uv-400/40 dark:bg-uv-500/10 dark:text-uv-200">
                <Cpu className="size-3.5" />
                <span className="hidden sm:inline">Rust · </span>WASM
              </span>
              <span className="h-px flex-1 bg-gradient-to-r from-uv-400 to-glow-400" />
              <span className="flex items-center gap-1.5 rounded-md border border-glow-400/50 bg-glow-400/10 px-2 py-1.5 text-glow-700 dark:text-glow-300">
                <Check className="hidden size-3.5 sm:block" />
                4,500 {h.eventsLabel}
              </span>
            </div>
          </div>
        </div>
        <div className="relative flex h-16 w-px items-center justify-center border-l border-dashed border-ink-300 dark:border-white/15">
          <span className="absolute flex items-center gap-1.5 rounded-full border border-red-500/30 bg-background px-2.5 py-1 whitespace-nowrap text-red-600 dark:text-red-400">
            <X className="size-3" />
            {h.privacyBlocked}
          </span>
        </div>
        <div className="flex items-center gap-2 rounded-xl border border-dashed border-ink-300 px-4 py-2.5 text-ink-400 opacity-70 dark:border-white/15">
          <Server className="size-3.5" />
          <span className="line-through decoration-ink-400/60">{h.privacyServer}</span>
        </div>
      </div>
    </section>
  );
}
