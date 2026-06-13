import Link from "next/link";

import type { Locale } from "@/src/dict/locales";
import { HOME_SEO } from "@/lib/landing/home-seo";
import { pickLocale } from "@/lib/landing/locale-content";

export function HomeSeo({ locale }: { locale: Locale }) {
  const c = pickLocale(HOME_SEO, locale);
  return (
    <section
      aria-labelledby="home-seo-heading"
      className="flex flex-col gap-3 border-t border-zinc-200 pt-6 text-sm leading-relaxed text-zinc-700 dark:border-zinc-800 dark:text-zinc-300"
    >
      <h2
        id="home-seo-heading"
        className="font-mono text-base font-semibold text-zinc-900 dark:text-zinc-100"
      >
        {c.heading}
      </h2>
      {c.paragraphs.map((p, i) => (
        <p key={i}>{p}</p>
      ))}
      <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-zinc-600 dark:text-zinc-400">
        <span className="text-zinc-500">{c.linksIntro}</span>
        {c.links.map((l) => (
          <Link
            key={l.path}
            href={`/${locale}${l.path}`}
            className="underline-offset-2 hover:text-zinc-900 hover:underline dark:hover:text-zinc-100"
          >
            {l.label}
          </Link>
        ))}
      </p>
    </section>
  );
}
