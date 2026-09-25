import Link from "next/link";

import type { Locale } from "@/src/dict/locales";
import { HOME_SEO } from "@/lib/landing/home-seo";
import { pickLocale } from "@/lib/landing/locale-content";

export function HomeSeo({ locale }: { locale: Locale }) {
  const c = pickLocale(HOME_SEO, locale);
  return (
    <section
      aria-labelledby="home-seo-heading"
      className="flex max-w-3xl flex-col gap-3 pt-6 text-[15px] leading-relaxed text-ink-700 dark:text-ink-300"
    >
      <h2
        id="home-seo-heading"
        className="text-2xl text-ink-950 dark:text-ink-50"
      >
        {c.heading}
      </h2>
      {c.paragraphs.map((p, i) => (
        <p key={i}>{p}</p>
      ))}
      <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-ink-600 dark:text-ink-400">
        <span className="text-ink-500">{c.linksIntro}</span>
        {c.links.map((l) => (
          <Link
            key={l.path}
            href={`/${locale}${l.path}`}
            className="underline-offset-2 hover:text-ink-900 hover:underline dark:hover:text-ink-100"
          >
            {l.label}
          </Link>
        ))}
      </p>
    </section>
  );
}
