/**
 * Adapter for legacy `@/app/_lib/site` imports used by ported routes.
 * New code should reach for `siteConfig` / `lib/i18n` / `lib/og-template` directly.
 */
import { siteConfig } from "@/site.config";
import { defaultLocale, locales, type Locale } from "@/src/dict/locales";

export const SITE_URL = siteConfig.url;

export function canonicalFor(locale: Locale, path = ""): string {
  const cleanPath = path.startsWith("/") ? path : path ? `/${path}` : "";
  return `${SITE_URL}/${locale}${cleanPath}`;
}

export function localeAlternates(
  path = "",
  availableLocales?: readonly Locale[],
): Record<string, string> {
  const list = (availableLocales ?? locales).filter((l) => locales.includes(l));
  const cleanPath = path.startsWith("/") ? path : path ? `/${path}` : "";
  const languages: Record<string, string> = {};
  for (const loc of list) {
    languages[loc] = `${SITE_URL}/${loc}${cleanPath}`;
  }
  const xDefault = list.includes(defaultLocale) ? defaultLocale : list[0];
  if (xDefault) {
    languages["x-default"] = `${SITE_URL}/${xDefault}${cleanPath}`;
  }
  return languages;
}

export const OG_LOCALE: Record<Locale, string> = {
  en: "en_US",
  fr: "fr_FR",
  es: "es_ES",
  de: "de_DE",
  it: "it_IT",
  pt: "pt_PT",
  ja: "ja_JP",
  zh: "zh_CN",
};
