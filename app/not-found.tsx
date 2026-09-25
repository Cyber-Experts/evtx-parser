import Link from "next/link";
import type { Metadata } from "next";

import { defaultLocale, locales, localeNames } from "@/src/dict/locales";
import { getDict } from "@/src/dict";
import { siteConfig } from "@/site.config";
import { fontVariables } from "@/lib/fonts";
import { BTN_PRIMARY, PageHero } from "@/components/PageHero";
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

// No ThemeProvider here: mirror next-themes' stored choice (or the system
// preference) before paint so the page matches the rest of the site.
const THEME_SCRIPT = `try{var t=localStorage.getItem("theme");if(t==="dark"||((!t||t==="system")&&matchMedia("(prefers-color-scheme: dark)").matches))document.documentElement.classList.add("dark")}catch(e){}`;

export default function RootNotFound() {
  return (
    <html
      lang={defaultLocale}
      className={fontVariables}
      suppressHydrationWarning
    >
      <body className="min-h-screen bg-background text-foreground antialiased">
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
        <main className="mx-auto flex min-h-screen max-w-3xl flex-col items-center justify-center px-4 py-16 sm:px-6">
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
            <Link href={`/${defaultLocale}`} className={`${BTN_PRIMARY} mt-2`}>
              {dict.notFound.backHome}
              <span aria-hidden="true">→</span>
            </Link>
            <nav
              aria-label="Languages"
              className="mt-8 flex flex-wrap items-center justify-center gap-x-4 gap-y-2 text-sm text-ink-500 dark:text-ink-400"
            >
              {locales.map((loc) => (
                <Link
                  key={loc}
                  href={`/${loc}`}
                  hrefLang={loc}
                  className="transition-colors hover:text-uv-700 dark:hover:text-uv-300"
                >
                  {localeNames[loc]}
                </Link>
              ))}
            </nav>
          </PageHero>
        </main>
      </body>
    </html>
  );
}
