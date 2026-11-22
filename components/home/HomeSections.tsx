// "Flare" home page sections. Server components; the only interactive bit
// (opening the file picker) is OpenFileButton.

import Link from "next/link";
import type { ReactNode } from "react";
import {
  ArrowRight,
  KeyRound,
  NotebookPen,
  Radar,
  TextSearch,
  Waypoints,
  WifiOff,
} from "lucide-react";

import { GitHubMark } from "@/components/GitHubMark";
import { OpenFileButton } from "@/components/OpenFileButton";
import { HUNTS } from "@/lib/hunts";
import { LOCALES } from "@/lib/i18n";
import sigmaMeta from "@/lib/sigma/sigmahq-meta.json";
import type { Dict } from "@/src/dict/types";

export const REPO_URL = "https://github.com/Cyber-Experts/evtx-parser";

export const SIGMA_COUNT = sigmaMeta.counts.bundled;

/** Page column shared by every home section. */
export const COL = "mx-auto w-full max-w-6xl px-4 sm:px-6";

export const BTN_PRIMARY =
  "inline-flex h-11 items-center justify-center gap-2 rounded-full bg-uv-500 px-5 text-sm font-semibold text-white shadow-[inset_0_1px_0_rgb(255_255_255/0.35),0_10px_30px_-12px_rgb(123_76_255/0.7)] transition-colors hover:bg-uv-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-uv-500 focus-visible:ring-offset-2 focus-visible:ring-offset-background";

export const BTN_SECONDARY =
  "inline-flex h-11 items-center justify-center gap-2 rounded-full border border-ink-200 bg-background px-5 text-sm font-semibold text-ink-900 transition-colors hover:border-ink-300 hover:bg-ink-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-uv-500 dark:border-white/12 dark:text-white dark:hover:border-white/25 dark:hover:bg-white/[0.04]";

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
];

/** Left-aligned section header: label, headline, and an intro that sits
 *  in its own column on wide screens. */
export function SectionHeading({
  eyebrow,
  title,
  intro,
  id,
}: {
  eyebrow: string;
  title: string;
  intro?: string;
  id?: string;
}) {
  return (
    <div className="grid gap-5 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)] lg:items-end lg:gap-16">
      <div className="flex flex-col gap-4">
        <span className="eyebrow">{eyebrow}</span>
        <h2
          id={id}
          className="text-[2rem] leading-[1.05] tracking-[-0.035em] text-balance text-ink-950 sm:text-5xl dark:text-white"
        >
          {title}
        </h2>
      </div>
      {intro ? (
        <p className="max-w-md text-base leading-relaxed text-ink-600 lg:pb-1.5 dark:text-ink-400">
          {intro}
        </p>
      ) : null}
    </div>
  );
}

/** The brand spike drawn across a timeline: the hero's signature visual. */
export function FlareLine({ className = "" }: { className?: string }) {
  return (
    <div aria-hidden="true" className={`relative ${className}`}>
      <div className="ruler absolute inset-x-0 bottom-0" />
      <svg
        viewBox="0 0 1200 120"
        preserveAspectRatio="none"
        className="absolute inset-x-0 bottom-0 h-full w-full overflow-visible"
      >
        <defs>
          <linearGradient id="flare-fade" x1="0" x2="1">
            <stop offset="0" stopColor="currentColor" stopOpacity="0" />
            <stop offset="0.18" stopColor="currentColor" stopOpacity="1" />
            <stop offset="0.82" stopColor="currentColor" stopOpacity="1" />
            <stop offset="1" stopColor="currentColor" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path
          d="M0 104H760L790 104L812 14L842 116L858 72L870 104H1200"
          fill="none"
          stroke="url(#flare-fade)"
          strokeWidth="1.5"
          vectorEffect="non-scaling-stroke"
        />
        <path
          d="M790 104L812 14L842 116L858 72L870 104"
          fill="none"
          stroke="#7b4cff"
          strokeWidth="2.5"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      <span className="absolute bottom-[86%] left-[67.6%] h-24 w-24 -translate-x-1/2 translate-y-1/2 rounded-full bg-uv-500/35 blur-2xl dark:bg-uv-500/45" />
      <span className="animate-flare absolute bottom-[88.3%] left-[67.6%] h-2.5 w-2.5 -translate-x-1/2 translate-y-1/2 rounded-full bg-uv-500 ring-4 ring-uv-500/20" />
    </div>
  );
}

export function WorksWith({ label }: { label: string }) {
  return (
    <section aria-label={label} className={COL}>
      <div className="grid overflow-hidden rounded-2xl border border-ink-200 sm:grid-cols-[14rem_1fr] dark:border-white/[0.08]">
        <p className="flex items-center border-b border-ink-200 px-5 py-4 text-sm font-medium text-balance text-ink-900 sm:border-r sm:border-b-0 dark:border-white/[0.08] dark:text-white">
          {label}
        </p>
        <ul className="grid grid-cols-2 font-mono text-[13px] text-ink-600 sm:grid-cols-5 dark:text-ink-400">
          {CHANNELS.map((c) => (
            <li
              key={c}
              className="-mb-px -ml-px flex items-center gap-2 border-b border-l border-ink-200 px-4 py-3.5 dark:border-white/[0.08]"
            >
              <span aria-hidden="true" className="h-1 w-1 bg-ink-400 dark:bg-ink-600" />
              {c}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

export function StatsBand({ dict }: { dict: Dict }) {
  const stats = [
    { value: String(HUNTS.length), label: dict.home.statHunts },
    { value: SIGMA_COUNT.toLocaleString("en-US"), label: "SigmaHQ Sigma rules" },
    { value: "0", label: dict.home.statUploaded, flare: true },
    { value: String(LOCALES.length), label: dict.home.statLocales },
  ];
  return (
    <dl className="grid grid-cols-2 border-y border-ink-200 lg:grid-cols-4 dark:border-white/[0.08]">
      {stats.map((s, i) => (
        <div
          key={s.label}
          className={`flex flex-col gap-2 px-5 py-8 sm:px-8 sm:py-10 ${i % 2 === 1 ? "border-l" : ""} ${i >= 2 ? "border-t lg:border-t-0" : ""} ${i === 2 ? "lg:border-l" : ""} border-ink-200 dark:border-white/[0.08]`}
        >
          <dd
            className={`order-1 text-5xl font-semibold tracking-[-0.05em] tabular-nums sm:text-6xl ${s.flare ? "text-uv-600 dark:text-uv-400" : "text-ink-950 dark:text-white"}`}
          >
            {s.value}
          </dd>
          <dt className="order-2 font-mono text-xs tracking-wide text-ink-500 uppercase">
            {s.label}
          </dt>
        </div>
      ))}
    </dl>
  );
}

const ICONS = [Radar, TextSearch, Waypoints, KeyRound, NotebookPen, WifiOff];

export function FeatureGrid({ dict, preview }: { dict: Dict; preview?: ReactNode }) {
  const f = dict.home.features;
  return (
    <section aria-labelledby="features-heading" className={`${COL} flex flex-col gap-12`}>
      <SectionHeading
        id="features-heading"
        eyebrow={dict.home.featuresEyebrow}
        title={dict.home.featuresHeading}
        intro={dict.home.featuresIntro}
      />
      {preview}
      <ul className="grid overflow-hidden rounded-2xl border border-ink-200 sm:grid-cols-2 lg:grid-cols-3 dark:border-white/[0.08]">
        {f.map((feat, i) => {
          const Icon = ICONS[i % ICONS.length];
          return (
            <li
              key={feat.title}
              className="group -mb-px -ml-px flex flex-col gap-4 border-b border-l border-ink-200 p-6 transition-colors hover:bg-ink-50/70 sm:p-8 dark:border-white/[0.08] dark:hover:bg-white/[0.02]"
            >
              <div className="flex items-center justify-between">
                <Icon
                  aria-hidden="true"
                  strokeWidth={1.6}
                  className="size-6 text-ink-900 transition-colors group-hover:text-uv-600 dark:text-white dark:group-hover:text-uv-400"
                />
                <span className="font-mono text-xs text-ink-400 dark:text-ink-600">
                  {String(i + 1).padStart(2, "0")}
                </span>
              </div>
              <h3 className="text-lg font-semibold tracking-[-0.015em] text-ink-950 dark:text-white">
                {feat.title}
              </h3>
              <p className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">
                {feat.body
                  .replace("{n}", String(HUNTS.length))
                  .replace("{sigma}", String(SIGMA_COUNT))}
              </p>
              {i === f.length - 1 && (
                <code className="mt-auto w-fit max-w-full overflow-x-auto rounded-lg bg-ink-950 px-3 py-2 font-mono text-xs whitespace-nowrap text-ink-200 dark:bg-white/[0.06]">
                  <span className="text-uv-400">$</span> docker run --rm -p 3000:3000 evtx-parser
                </code>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/** Closing call to action. On the home page the primary button opens the
 *  file picker; elsewhere pass `href` (the tool page) to render a link. */
export function CtaBand({ dict, href }: { dict: Dict; href?: string }) {
  return (
    <section
      aria-labelledby="cta-heading"
      className="relative isolate w-full overflow-hidden rounded-[1.75rem] bg-ink-950 px-6 pt-16 pb-0 text-white ring-1 ring-white/10 sm:px-14 sm:pt-20"
      style={{ ["--mark" as string]: "rgb(255 255 255 / 0.3)", ["--border" as string]: "rgb(255 255 255 / 0.12)" }}
    >
      <div
        aria-hidden="true"
        className="absolute inset-0 -z-10 bg-[radial-gradient(600px_260px_at_68%_100%,rgb(123_76_255/0.35),transparent_70%)]"
      />
      <div className="flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
        <div className="flex max-w-2xl flex-col gap-4">
          <span className="eyebrow text-ink-400!">EVTX parser</span>
          <h2
            id="cta-heading"
            className="font-serif text-[2.6rem] leading-[1.02] tracking-[-0.02em] text-balance sm:text-6xl"
          >
            {dict.home.ctaHeading}
          </h2>
          <p className="max-w-lg text-base text-ink-400 sm:text-lg">{dict.home.ctaBody}</p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-3">
          {href ? (
            <Link href={href} className={BTN_PRIMARY}>
              {dict.home.heroCtaOpen}
              <ArrowRight aria-hidden="true" className="size-4" />
            </Link>
          ) : (
            <OpenFileButton className={BTN_PRIMARY}>
              {dict.home.heroCtaOpen}
              <ArrowRight aria-hidden="true" className="size-4" />
            </OpenFileButton>
          )}
          <a
            href={REPO_URL}
            className="inline-flex h-11 items-center gap-2 rounded-full border border-white/15 px-5 text-sm font-semibold text-white transition-colors hover:bg-white/[0.06]"
          >
            <GitHubMark className="h-4 w-4" />
            {dict.home.heroCtaGithub}
          </a>
        </div>
      </div>
      <FlareLine className="-mx-6 mt-10 h-32 text-ink-700 sm:-mx-14" />
    </section>
  );
}
