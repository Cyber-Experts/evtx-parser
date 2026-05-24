export const LOCALES = ["en", "fr", "es", "de"] as const;
export const DEFAULT_LOCALE = "en" as const;

export type Locale = (typeof LOCALES)[number];

export function isLocale(value: string): value is Locale {
  return (LOCALES as readonly string[]).includes(value);
}

export function hasLocale(value: string): value is Locale {
  return isLocale(value);
}

export const localeNames: Record<Locale, string> = {
  en: "English",
  fr: "Français",
  es: "Español",
  de: "Deutsch",
};

export const localeLabels: Record<Locale, string> = {
  en: "EN",
  fr: "FR",
  es: "ES",
  de: "DE",
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
  for (const l of LOCALES) {
    map[l] = `${base}/${l}${path === "/" ? "" : path}`;
  }
  map["x-default"] = `${base}/${DEFAULT_LOCALE}${path === "/" ? "" : path}`;
  return map;
}
