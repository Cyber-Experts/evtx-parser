import Link from "next/link";

import type { Locale } from "@/src/dict/locales";
import { HOME_SEO } from "@/lib/landing/home-seo";
import { pickLocale } from "@/lib/landing/locale-content";

export function HomeSeo({ locale }: { locale: Locale }) {
  const c = pickLocale(HOME_SEO, locale);
  return (
    <section
      aria-labelledby="home-seo-heading"
      className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.8fr)] lg:gap-16"
    >
      <div className="flex flex-col gap-3">
        <span className="eyebrow">EVTX viewer</span>
        <h2
          id="home-seo-heading"
          className="text-3xl leading-tight tracking-[-0.02em] text-balance text-ink-950 sm:text-4xl dark:text-ink-50"
        >
          {c.heading}
        </h2>
      </div>
      <div className="flex flex-col gap-4 text-[15px] leading-relaxed text-ink-700 dark:text-ink-300">
        {c.paragraphs.map((p, i) => (
          <p key={i}>{p}</p>
        ))}
        <div className="mt-2 flex flex-col gap-3 border-t border-ink-200/70 pt-5 dark:border-white/[0.06]">
          <span className="font-mono text-[11px] tracking-[0.14em] text-ink-500 uppercase">
            {c.linksIntro.replace(/\s*[:：]\s*$/, "")}
          </span>
          <ul className="flex flex-wrap gap-2">
            {c.links.map((l) => (
              <li key={l.path}>
                <Link
                  href={`/${locale}${l.path}`}
                  className="inline-flex items-center rounded-full border border-ink-200 bg-card px-3 py-1 text-sm text-ink-700 shadow-[0_1px_2px_rgb(11_12_22/0.04)] transition-colors hover:border-uv-300 hover:text-uv-700 dark:border-white/[0.08] dark:bg-white/[0.02] dark:text-ink-300 dark:hover:border-uv-400/40 dark:hover:text-uv-200"
                >
                  {l.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
