/**
 * Single source of truth for the locale list.
 * Re-exports `src/dict/locales.ts` so both the typed dict system and the
 * template's routing helpers stay in sync.
 */
export {
  locales as LOCALES,
  defaultLocale as DEFAULT_LOCALE,
  localeNames,
  isLocale,
  type Locale,
} from "@/src/dict/locales";

import { locales, defaultLocale, isLocale } from "@/src/dict/locales";
import type { Locale } from "@/src/dict/locales";

export function hasLocale(value: string): value is Locale {
  return isLocale(value);
}

export const localeLabels: Record<Locale, string> = {
  en: "EN",
  fr: "FR",
  es: "ES",
  de: "DE",
  it: "IT",
  pt: "PT",
  ja: "JA",
  zh: "ZH",
};

/** OpenGraph `og:locale` values (BCP-47 with region). */
export const ogLocale: Record<Locale, string> = {
  en: "en_US",
  fr: "fr_FR",
  es: "es_ES",
  de: "de_DE",
  it: "it_IT",
  pt: "pt_PT",
  ja: "ja_JP",
  zh: "zh_CN",
};

/**
 * Replace (or insert) the locale segment in a pathname.
 * "/en/blog/foo" + "fr" → "/fr/blog/foo"
 * "/blog/foo"    + "fr" → "/fr/blog/foo"
 */
export function withLocale(pathname: string, locale: Locale): string {
  const segments = pathname.split("/").filter(Boolean);
  if (segments.length && isLocale(segments[0])) {
    segments[0] = locale;
  } else {
    segments.unshift(locale);
  }
  return "/" + segments.join("/");
}

export function stripLocale(pathname: string): string {
  const segments = pathname.split("/").filter(Boolean);
  if (segments.length && isLocale(segments[0])) segments.shift();
  return "/" + segments.join("/");
}

/**
 * Build the absolute-URL hreflang map for a path that exists in every locale.
 * Useful for static pages (homepage, /blog index, etc).
 */
export function hreflangFor(siteUrl: string, pathWithoutLocale: string) {
  const base = siteUrl.replace(/\/$/, "");
  const path = pathWithoutLocale.startsWith("/")
    ? pathWithoutLocale
    : "/" + pathWithoutLocale;
  const map: Record<string, string> = {};
  for (const l of locales) {
    map[l] = `${base}/${l}${path === "/" ? "" : path}`;
  }
  map["x-default"] = `${base}/${defaultLocale}${path === "/" ? "" : path}`;
  return map;
}
