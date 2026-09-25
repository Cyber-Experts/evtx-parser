import Link from "next/link";

import type { Dict } from "@/src/dict/types";
import type { Locale } from "@/src/dict/locales";
import { locales, localeNames } from "@/src/dict/locales";
import { Logo } from "./Logo";

export function Footer({
  dict,
  locale,
}: {
  dict: Dict;
  locale: Locale;
}) {
  return (
    <footer className="mt-12 border-t border-ink-200 dark:border-ink-800">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-4 px-4 py-8 text-xs text-ink-500 sm:flex-row sm:items-start sm:justify-between sm:px-6 xl:max-w-[1400px] 2xl:max-w-[1600px]">
        <div className="flex max-w-md flex-col gap-3">
          <Link href={`/${locale}`} aria-label={dict.meta.siteName}>
            <Logo className="h-6 w-auto text-ink-700 dark:text-ink-300" />
          </Link>
          <div className="leading-relaxed">{dict.footer.builtWith}</div>
        </div>
        <div className="flex flex-col gap-3 sm:items-end">
          <Link
            href={`/${locale}/event-ids`}
            className="font-medium text-ink-700 underline-offset-2 hover:underline dark:text-ink-300"
          >
            {dict.eventIds.title}
          </Link>
          <Link
            href={`/${locale}/tools`}
            className="font-medium text-ink-700 underline-offset-2 hover:underline dark:text-ink-300"
          >
            {dict.tools.title}
          </Link>
          <Link
            href={`/${locale}/glossary`}
            className="font-medium text-ink-700 underline-offset-2 hover:underline dark:text-ink-300"
          >
            {dict.glossary.title}
          </Link>
          <Link
            href={`/${locale}/blog`}
            className="font-medium text-ink-700 underline-offset-2 hover:underline dark:text-ink-300"
          >
            {dict.footer.blog}
          </Link>
          <Link
            href={`/${locale}/tag`}
            className="font-medium text-ink-700 underline-offset-2 hover:underline dark:text-ink-300"
          >
            {dict.tags.indexTitle}
          </Link>
          <nav aria-label="Languages" className="flex flex-wrap gap-2">
            {locales.map((loc) => (
              <Link
                key={loc}
                href={`/${loc}`}
                hrefLang={loc}
                className={
                  loc === locale
                    ? "text-ink-900 dark:text-ink-100"
                    : "text-ink-500 hover:text-ink-800 dark:hover:text-ink-300"
                }
              >
                {localeNames[loc]}
              </Link>
            ))}
          </nav>
        </div>
      </div>
    </footer>
  );
}
