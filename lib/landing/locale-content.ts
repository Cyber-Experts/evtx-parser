import type { Locale } from "@/src/dict/locales";

/**
 * Per-locale content for the SEO landing pages. English is mandatory and acts
 * as the fallback for any locale whose translation is not yet filled in, so a
 * missing locale renders English rather than breaking the build.
 */
export type LocaleContent<T> = Partial<Record<Locale, T>> & { en: T };

export function pickLocale<T>(content: LocaleContent<T>, locale: Locale): T {
  return content[locale] ?? content.en;
}
