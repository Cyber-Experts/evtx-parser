// Client-safe lookup: which encyclopedia page documents a record, if any.
// Uses the generated manifest (npm run events:check), not the data itself.

import manifest from "./manifest.json";
import { channelForRecord, eventPath } from "./channels";

const MANIFEST = manifest as Record<string, string[]>;

/**
 * Encyclopedia URL for a record (by <Channel>/<Provider> and Event ID), in
 * `locale` when translated, else English; null when not covered.
 */
export function encyclopediaLink(
  channel: string | null | undefined,
  provider: string | null | undefined,
  id: number | null | undefined,
  locale: string,
): { href: string; fallback: boolean } | null {
  if (id == null) return null;
  const ch = channelForRecord(channel, provider);
  if (!ch) return null;
  const locales = MANIFEST[`${ch.slug}/${id}`];
  if (!locales) return null;
  const target = locale === "en" || locales.includes(locale) ? locale : "en";
  return { href: eventPath(target, ch.slug, id), fallback: target !== locale };
}

/** Locales with a page for "channel/id" (English always included). */
export function manifestLocales(key: string): string[] | null {
  const l = MANIFEST[key];
  return l ? ["en", ...l] : null;
}
