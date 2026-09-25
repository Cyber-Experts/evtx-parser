import Link from "next/link";
import type { Metadata } from "next";

import {
  defaultLocale,
  locales,
  localeNames,
} from "@/src/dict/locales";
import { getDict } from "@/src/dict";
import { siteConfig } from "@/site.config";
import { fontVariables } from "@/lib/fonts";
import "./globals.css";

/**
 * Catches URLs that don't match any route in the app — including paths
 * outside the [lang] segment (those slipped past proxy.ts too). There's
 * no root layout, so we own the <html>/<body> shell.
 *
 * Rendered in the default locale (we can't statically know the user's
 * intended language for an orphan path). Locale picker below the message
 * gives them a way back into their language without guessing.
 */

const dict = getDict(defaultLocale);

export const metadata: Metadata = {
  metadataBase: new URL(siteConfig.url),
  title: dict.notFound.title,
  robots: { index: false, follow: false },
};

export default function RootNotFound() {
  return (
    <html
      lang={defaultLocale}
      className={fontVariables}
    >
      <body className="min-h-screen bg-background text-foreground antialiased">
        <main className="mx-auto flex min-h-screen max-w-2xl flex-col items-start justify-center gap-5 px-6 py-16">
          <p className="font-mono text-xs uppercase tracking-wider text-ink-500">
            404
          </p>
          <h1 className="font-mono text-2xl font-semibold tracking-tight text-ink-900 dark:text-ink-100 sm:text-3xl">
            {dict.notFound.heading}
          </h1>
          <p className="max-w-prose text-sm text-ink-600 dark:text-ink-400">
            {dict.notFound.description}
          </p>
          <Link
            href={`/${defaultLocale}`}
            className="rounded border border-ink-300 bg-ink-50 px-3 py-1.5 text-sm font-medium text-ink-900 hover:bg-ink-100 dark:border-ink-700 dark:bg-ink-900 dark:text-ink-100 dark:hover:bg-ink-800"
          >
            {dict.notFound.backHome}
          </Link>
          <nav
            aria-label="Languages"
            className="mt-8 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-ink-600 dark:text-ink-400"
          >
            {locales.map((loc) => (
              <Link
                key={loc}
                href={`/${loc}`}
                hrefLang={loc}
                className="hover:text-ink-900 hover:underline dark:hover:text-ink-100"
              >
                {localeNames[loc]}
              </Link>
            ))}
          </nav>
        </main>
      </body>
    </html>
  );
}
