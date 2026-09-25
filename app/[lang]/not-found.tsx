"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { defaultLocale, isLocale, type Locale } from "@/src/dict/locales";
import { getDict } from "@/src/dict";

/**
 * Wrapped by app/[lang]/layout.tsx so it inherits <html lang>, header,
 * footer and theme. Client component so we can read the locale from the
 * URL via useParams() without forcing the rest of the layout dynamic.
 */
export default function LocaleNotFound() {
  const params = useParams<{ lang?: string }>();
  const lang = params?.lang;
  const locale: Locale =
    lang && isLocale(lang) ? lang : defaultLocale;
  const dict = getDict(locale);

  return (
    <main
      id="main-content"
      className="mx-auto flex w-full max-w-3xl flex-1 flex-col items-start gap-5 px-6 py-16 sm:py-24"
    >
      <p className="font-mono text-xs uppercase tracking-wider text-ink-500">
        404
      </p>
      <h1 className="font-mono text-2xl font-semibold tracking-tight text-ink-900 dark:text-ink-100 sm:text-3xl">
        {dict.notFound.heading}
      </h1>
      <p className="max-w-prose text-sm text-ink-600 dark:text-ink-400">
        {dict.notFound.description}
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-3 text-sm">
        <Link
          href={`/${locale}`}
          className="rounded border border-ink-300 bg-ink-50 px-3 py-1.5 font-medium text-ink-900 hover:bg-ink-100 dark:border-ink-700 dark:bg-ink-900 dark:text-ink-100 dark:hover:bg-ink-800"
        >
          {dict.notFound.backHome}
        </Link>
        <Link
          href={`/${locale}/blog`}
          className="rounded border border-transparent px-3 py-1.5 text-ink-700 hover:bg-ink-100 hover:text-ink-900 dark:text-ink-300 dark:hover:bg-ink-800 dark:hover:text-ink-100"
        >
          {dict.footer.blog}
        </Link>
        <Link
          href={`/${locale}/glossary`}
          className="rounded border border-transparent px-3 py-1.5 text-ink-700 hover:bg-ink-100 hover:text-ink-900 dark:text-ink-300 dark:hover:bg-ink-800 dark:hover:text-ink-100"
        >
          {dict.glossary.title}
        </Link>
        <Link
          href={`/${locale}/event-ids`}
          className="rounded border border-transparent px-3 py-1.5 text-ink-700 hover:bg-ink-100 hover:text-ink-900 dark:text-ink-300 dark:hover:bg-ink-800 dark:hover:text-ink-100"
        >
          {dict.eventIds.title}
        </Link>
        <Link
          href={`/${locale}/tools`}
          className="rounded border border-transparent px-3 py-1.5 text-ink-700 hover:bg-ink-100 hover:text-ink-900 dark:text-ink-300 dark:hover:bg-ink-800 dark:hover:text-ink-100"
        >
          {dict.tools.title}
        </Link>
      </div>
    </main>
  );
}
