// Marketing sections of the home page (SaaS-style): channel strip, stats band,
// bento feature grid and the closing call to action. Server components; the
// only interactive bit (opening the file picker) is OpenFileButton.

import Link from "next/link";
import type { ReactNode } from "react";

import { GitHubMark } from "@/components/GitHubMark";
import { OpenFileButton } from "@/components/OpenFileButton";
import { HUNTS } from "@/lib/hunts";
import { LOCALES } from "@/lib/i18n";
import sigmaMeta from "@/lib/sigma/sigmahq-meta.json";
import type { Dict } from "@/src/dict/types";

import { Canvas, FEATURE_VISUALS } from "./HomeVisuals";

export const REPO_URL = "https://github.com/Cyber-Experts/evtx-parser";

const CHANNELS = [
  "Security",
  "System",
  "Sysmon",
  "PowerShell",
  "RDP",
  "Defender",
  "Task Scheduler",
  "WMI",
  "Application",
];

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
    <div className="mx-auto flex max-w-3xl flex-col items-center gap-4 text-center">
      <span className="eyebrow">{eyebrow}</span>
      <h2
        id={id}
        className="text-3xl leading-[1.05] tracking-[-0.04em] text-balance text-ink-950 sm:text-5xl dark:text-ink-50"
      >
        {title}
      </h2>
      {intro ? (
        <p className="max-w-2xl text-base leading-relaxed text-ink-600 sm:text-lg dark:text-ink-400">
          {intro}
        </p>
      ) : null}
    </div>
  );
}

export function WorksWith({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center gap-4">
      <span className="text-xs font-medium tracking-wide text-ink-500 dark:text-ink-500">
        {label}
      </span>
      <ul className="flex flex-wrap justify-center gap-x-7 gap-y-3 font-mono text-sm text-ink-400 dark:text-ink-500">
        {CHANNELS.map((c) => (
          <li
            key={c}
            className="flex items-center gap-2 transition-colors hover:text-ink-800 dark:hover:text-ink-200"
          >
            <span
              aria-hidden="true"
              className="h-1.5 w-1.5 rounded-full bg-current opacity-60"
            />
            {c}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function StatsBand({ dict }: { dict: Dict }) {
  const stats = [
    { value: String(HUNTS.length), label: dict.home.statHunts },
    { value: "0", label: dict.home.statUploaded },
    { value: "Rust", label: dict.home.statEngine },
    { value: String(LOCALES.length), label: dict.home.statLocales },
  ];
  return (
    <dl className="surface relative grid grid-cols-2 overflow-hidden lg:grid-cols-4">
      <span
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 top-0 h-px bg-[linear-gradient(90deg,transparent,rgb(58_107_255/0.6),rgb(34_214_240/0.5),transparent)]"
      />
      {stats.map((s, i) => (
        <div
          key={s.label}
          className={`flex flex-col items-center gap-1.5 px-6 py-8 text-center sm:px-8 ${
            i % 2 === 1 ? "border-l border-ink-200/70 dark:border-white/[0.06]" : ""
          } ${i >= 2 ? "border-t border-ink-200/70 lg:border-t-0 dark:border-white/[0.06]" : ""} ${
            i === 2 ? "lg:border-l" : ""
          }`}
        >
          <dt className="order-2 text-sm text-ink-500 dark:text-ink-400">
            {s.label}
          </dt>
          <dd className="text-gradient-uv order-1 font-heading text-4xl font-semibold tracking-[-0.02em] sm:text-5xl">
            {s.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/* ---------- feature icons (24px, stroke) ---------- */

function Icon({ children }: { children: ReactNode }) {
  return (
    <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-uv-200 bg-uv-50 text-uv-600 shadow-[inset_0_1px_0_rgb(255_255_255/0.8)] dark:border-uv-400/20 dark:bg-uv-400/10 dark:text-uv-300 dark:shadow-none">
      <svg
        viewBox="0 0 24 24"
        className="h-5 w-5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        {children}
      </svg>
    </span>
  );
}

const ICONS: ReactNode[] = [
  // hunts: crosshair
  <>
    <circle cx="12" cy="12" r="7" />
    <path d="M12 2v4M12 18v4M2 12h4M18 12h4" />
  </>,
  // query: terminal
  <>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="m7 10 3 2-3 2M13 15h4" />
  </>,
  // pivots: branch
  <>
    <circle cx="6" cy="6" r="2" />
    <circle cx="6" cy="18" r="2" />
    <circle cx="18" cy="12" r="2" />
    <path d="M6 8v8M8 6h3a5 5 0 0 1 5 5v-1" />
  </>,
  // sessions: user + clock
  <>
    <circle cx="9" cy="8" r="3.5" />
    <path d="M3 20a6 6 0 0 1 9.5-4.9" />
    <circle cx="17" cy="17" r="4" />
    <path d="M17 15v2l1.2 1.2" />
  </>,
  // report: doc
  <>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
    <path d="M14 3v5h5M9 13h6M9 17h4" />
  </>,
  // offline: shield
  <>
    <path d="M12 3 5 6v5c0 4.5 3 8.3 7 10 4-1.7 7-5.5 7-10V6z" />
    <path d="m9 12 2 2 4-4" />
  </>,
];

export function FeatureGrid({
  dict,
  preview,
}: {
  dict: Dict;
  preview?: ReactNode;
}) {
  const f = dict.home.features;
  // Bento: [hunts ×2][query] / [pivots][sessions][report] / [offline ×3]
  const span = ["lg:col-span-2", "", "", "", "", "md:col-span-2 lg:col-span-3"];
  return (
    <section
      aria-labelledby="features-heading"
      className="flex flex-col gap-12"
    >
      <SectionHeading
        id="features-heading"
        eyebrow={dict.home.featuresEyebrow}
        title={dict.home.featuresHeading}
        intro={dict.home.featuresIntro}
      />
      {preview}
      <ul className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {f.map((feat, i) => {
          const last = i === f.length - 1;
          const body = feat.body
            .replace("{n}", String(HUNTS.length))
            .replace("{sigma}", String(sigmaMeta.counts.bundled));
          if (last) {
            return (
              <li
                key={feat.title}
                className={`surface surface-interactive relative flex flex-col gap-6 overflow-hidden p-6 sm:p-8 lg:flex-row lg:items-center lg:justify-between lg:gap-10 ${span[i]}`}
              >
                <div className="flex flex-col gap-2">
                  <h3 className="flex items-center gap-2.5 text-lg text-ink-950 dark:text-ink-50">
                    <Icon>{ICONS[5]}</Icon>
                    {feat.title}
                  </h3>
                  <p className="max-w-xl text-sm leading-relaxed text-ink-600 dark:text-ink-400">
                    {body}
                  </p>
                </div>
                <code className="w-fit max-w-full shrink-0 overflow-x-auto rounded-xl border border-ink-200 bg-ink-950 px-4 py-3 font-mono text-xs whitespace-nowrap text-ink-200 shadow-[0_12px_32px_-16px_rgb(11_12_15/0.5)] dark:border-white/10">
                  <span className="text-glow-400">$</span> docker run --rm -p
                  3000:3000 evtx-parser
                </code>
              </li>
            );
          }
          return (
            <li
              key={feat.title}
              className={`surface surface-interactive group relative flex flex-col overflow-hidden ${span[i]}`}
            >
              <Canvas tall={i === 0}>{FEATURE_VISUALS[i]}</Canvas>
              <div className="flex flex-col gap-2 p-6">
                <h3 className="text-base font-semibold text-ink-950 dark:text-ink-50">
                  {feat.title}
                </h3>
                <p className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">
                  {body}
                </p>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

const CTA_PRIMARY =
  "inline-flex items-center gap-2 rounded-xl bg-white px-5 py-2.5 text-sm font-semibold text-ink-950 shadow-[0_10px_30px_-10px_rgb(255_255_255/0.5)] transition hover:bg-uv-50";

/** Closing call to action. On the home page the primary button opens the
 *  file picker; elsewhere pass `href` (the tool page) to render a link. */
export function CtaBand({ dict, href }: { dict: Dict; href?: string }) {
  return (
    <section
      aria-labelledby="cta-heading"
      className="relative isolate overflow-hidden rounded-3xl bg-ink-950 px-6 py-14 text-center shadow-[0_40px_100px_-50px_rgb(36_80_245/0.6)] ring-1 ring-white/10 sm:px-12 sm:py-20 dark:bg-[#0c0d11] dark:shadow-[0_30px_80px_-50px_rgb(36_80_245/0.5)]"
    >
      <div
        aria-hidden="true"
        className="absolute inset-0 -z-10 bg-[radial-gradient(700px_320px_at_50%_-10%,rgb(58_107_255/0.55),transparent_70%),radial-gradient(500px_260px_at_85%_120%,rgb(34_214_240/0.14),transparent_70%)]"
      />
      <div
        aria-hidden="true"
        className="absolute inset-0 -z-10 bg-[linear-gradient(to_right,rgb(255_255_255/0.04)_1px,transparent_1px),linear-gradient(to_bottom,rgb(255_255_255/0.04)_1px,transparent_1px)] [mask-image:radial-gradient(ellipse_at_center,black,transparent_75%)] bg-[size:44px_44px]"
      />
      <h2
        id="cta-heading"
        className="mx-auto max-w-2xl text-3xl leading-tight tracking-[-0.02em] text-balance text-white sm:text-5xl"
      >
        {dict.home.ctaHeading}
      </h2>
      <p className="mx-auto mt-4 max-w-xl text-base text-ink-300 sm:text-lg">
        {dict.home.ctaBody}
      </p>
      <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
        {href ? (
          <Link href={href} className={CTA_PRIMARY}>
            {dict.home.heroCtaOpen}
            <span aria-hidden="true">→</span>
          </Link>
        ) : (
          <OpenFileButton className={CTA_PRIMARY}>
            {dict.home.heroCtaOpen}
            <span aria-hidden="true">→</span>
          </OpenFileButton>
        )}
        <a
          href={REPO_URL}
          className="inline-flex items-center gap-2 rounded-xl border border-white/15 bg-white/5 px-5 py-2.5 text-sm font-medium text-white backdrop-blur transition hover:bg-white/10"
        >
          <GitHubMark className="h-4 w-4" />
          {dict.home.heroCtaGithub}
        </a>
      </div>
    </section>
  );
}
