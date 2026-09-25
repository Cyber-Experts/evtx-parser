"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { defaultLocale, isLocale, type Locale } from "@/src/dict/locales";
import { getDict } from "@/src/dict";
import { BTN_PRIMARY, PageHero } from "@/components/PageHero";

const CHIP =
  "inline-flex rounded-full border border-ink-200 bg-card/70 px-3 py-1 text-sm text-ink-700 transition-colors hover:border-uv-300 hover:text-uv-700 dark:border-ink-800 dark:text-ink-300 dark:hover:border-uv-500/50 dark:hover:text-uv-300";

/**
 * Wrapped by app/[lang]/layout.tsx so it inherits <html lang>, header,
 * footer and theme. Client component so we can read the locale from the
 * URL via useParams() without forcing the rest of the layout dynamic.
 */
export default function LocaleNotFound() {
  const params = useParams<{ lang?: string }>();
  const lang = params?.lang;
  const locale: Locale = lang && isLocale(lang) ? lang : defaultLocale;
  const dict = getDict(locale);
  const links = [
    { href: `/${locale}/blog`, label: dict.footer.blog },
    { href: `/${locale}/glossary`, label: dict.glossary.title },
    { href: `/${locale}/event-ids`, label: dict.eventIds.title },
    { href: `/${locale}/tools`, label: dict.tools.title },
  ];

  return (
    <main
      id="main-content"
      className="mx-auto flex w-full max-w-3xl flex-1 flex-col items-center px-4 py-16 sm:px-6 sm:py-24"
    >
      <PageHero
        align="center"
        size="md"
        top={
          <p className="text-gradient-uv font-heading text-7xl leading-none font-semibold tracking-[-0.04em] sm:text-8xl">
            404
          </p>
        }
        title={dict.notFound.heading}
        intro={<p>{dict.notFound.description}</p>}
      >
        <Link href={`/${locale}`} className={`${BTN_PRIMARY} mt-2`}>
          {dict.notFound.backHome}
          <span aria-hidden="true">→</span>
        </Link>
        <div className="mt-4 flex flex-wrap justify-center gap-2">
          {links.map((l) => (
            <Link key={l.href} href={l.href} className={CHIP}>
              {l.label}
            </Link>
          ))}
        </div>
      </PageHero>
    </main>
  );
}
