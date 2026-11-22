import Link from "next/link";
import { ArrowUpRight } from "lucide-react";

import type { Locale } from "@/src/dict/locales";
import { HOME_SEO } from "@/lib/landing/home-seo";
import { pickLocale } from "@/lib/landing/locale-content";

export function HomeSeo({ locale }: { locale: Locale }) {
  const c = pickLocale(HOME_SEO, locale);
  return (
    <section
      aria-labelledby="home-seo-heading"
      className="grid gap-8 rounded-[1.75rem] bg-ink-50 p-6 sm:p-10 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)] lg:gap-16 lg:p-14 dark:bg-white/[0.025]"
    >
      <div className="flex flex-col gap-4">
        <span className="eyebrow">EVTX viewer</span>
        <h2
          id="home-seo-heading"
          className="text-3xl leading-[1.08] tracking-[-0.035em] text-balance text-ink-950 sm:text-4xl dark:text-white"
        >
          {c.heading}
        </h2>
      </div>
      <div className="flex flex-col gap-4 text-[15px] leading-relaxed text-ink-600 dark:text-ink-400">
        {c.paragraphs.map((p, i) => (
          <p key={i}>{p}</p>
        ))}
        <div className="mt-4 flex flex-col gap-3">
          <span className="font-mono text-[11px] tracking-[0.12em] text-ink-500 uppercase">
            {c.linksIntro.replace(/\s*[:：]\s*$/, "")}
          </span>
          <ul className="grid gap-px overflow-hidden rounded-xl border border-ink-200 bg-ink-200 sm:grid-cols-2 dark:border-white/[0.08] dark:bg-white/[0.08]">
            {c.links.map((l) => (
              <li key={l.path} className="bg-background">
                <Link
                  href={`/${locale}${l.path}`}
                  className="group flex items-center justify-between gap-3 px-4 py-3 text-sm font-medium text-ink-900 transition-colors hover:text-uv-700 dark:text-ink-100 dark:hover:text-uv-300"
                >
                  {l.label}
                  <ArrowUpRight
                    aria-hidden="true"
                    className="size-4 shrink-0 text-ink-400 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
                  />
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
