import Link from "next/link";
import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";

import {
  defaultLocale,
  locales,
  localeNames,
} from "@/src/dict/locales";
import { getDict } from "@/src/dict";
import { siteConfig } from "@/site.config";
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
const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

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
      className={`${geistSans.variable} ${geistMono.variable}`}
    >
      <body className="min-h-screen bg-background text-foreground antialiased">
        <main className="mx-auto flex min-h-screen max-w-2xl flex-col items-start justify-center gap-5 px-6 py-16">
          <p className="font-mono text-xs uppercase tracking-wider text-zinc-500">
            404
          </p>
          <h1 className="font-mono text-2xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100 sm:text-3xl">
            {dict.notFound.heading}
          </h1>
          <p className="max-w-prose text-sm text-zinc-600 dark:text-zinc-400">
            {dict.notFound.description}
          </p>
          <Link
            href={`/${defaultLocale}`}
            className="rounded border border-zinc-300 bg-zinc-50 px-3 py-1.5 text-sm font-medium text-zinc-900 hover:bg-zinc-100 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:hover:bg-zinc-800"
          >
            {dict.notFound.backHome}
          </Link>
          <nav
            aria-label="Languages"
            className="mt-8 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-zinc-600 dark:text-zinc-400"
          >
            {locales.map((loc) => (
              <Link
                key={loc}
                href={`/${loc}`}
                hrefLang={loc}
                className="hover:text-zinc-900 hover:underline dark:hover:text-zinc-100"
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
