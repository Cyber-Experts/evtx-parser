// Server-side accessors for the Event ID encyclopedia (build time only).

import attack from "./attack.json";
import { channelBySlug, eventPath, type EventChannel } from "./channels";
import { loadEventDataset } from "./load";
import type { EventEntry, EventField, EventTranslation } from "./types";

export { eventPath } from "./channels";

const DEFAULT_LOCALE = "en";

/** An entry as displayed in one locale (translation merged over English). */
export type EventView = EventEntry & {
  key: string;
  channelInfo: EventChannel;
  /** Locale the prose is written in ("en" when not translated). */
  contentLocale: string;
  /** Locales with a real page for this entry, English first. */
  locales: string[];
};

export function eventKeyOf(e: Pick<EventEntry, "channel" | "id">): string {
  return `${e.channel}/${e.id}`;
}

export function allEntries(): EventEntry[] {
  return loadEventDataset().entries;
}

export function getEntry(channel: string, id: number): EventEntry | undefined {
  return allEntries().find((e) => e.channel === channel && e.id === id);
}

/** Locales that have a page for `entry` ("en" + translations). */
export function entryLocales(entry: Pick<EventEntry, "channel" | "id">): string[] {
  const t = loadEventDataset().translations.get(eventKeyOf(entry));
  return [DEFAULT_LOCALE, ...[...(t?.keys() ?? [])].sort()];
}

export function hasPage(entry: Pick<EventEntry, "channel" | "id">, locale: string): boolean {
  return entryLocales(entry).includes(locale);
}

/**
 * Where to link an entry from a page in `locale`: the localized page when it
 * exists, otherwise the English original (flagged so the UI can badge it).
 */
export function entryHref(
  entry: Pick<EventEntry, "channel" | "id">,
  locale: string,
): { href: string; locale: string; fallback: boolean } {
  const target = hasPage(entry, locale) ? locale : DEFAULT_LOCALE;
  return {
    href: eventPath(target, entry.channel, entry.id),
    locale: target,
    fallback: target !== locale,
  };
}

function mergeFields(en: EventField[], t: EventTranslation["fields"]): EventField[] {
  return en.map((f) => {
    const tf = t.find((x) => x.name === f.name);
    if (!tf) return f;
    return {
      name: f.name,
      description: tf.description,
      ...(f.values
        ? {
            values: f.values.map((v) => ({
              value: v.value,
              meaning: tf.values?.find((x) => x.value === v.value)?.meaning ?? v.meaning,
            })),
          }
        : {}),
    };
  });
}

/** Entry in `locale`, or English content when that locale isn't translated. */
export function viewEntry(entry: EventEntry, locale: string): EventView {
  const key = eventKeyOf(entry);
  const channelInfo = channelBySlug(entry.channel) as EventChannel;
  const locales = entryLocales(entry);
  const t = locale === DEFAULT_LOCALE ? undefined : loadEventDataset().translations.get(key)?.get(locale);
  if (!t) return { ...entry, key, channelInfo, contentLocale: DEFAULT_LOCALE, locales };
  return {
    ...entry,
    key,
    channelInfo,
    contentLocale: locale,
    locales,
    title: t.title,
    shortTitle: t.shortTitle,
    summary: t.summary,
    description: t.description,
    logging: { ...entry.logging, requirement: t.logging.requirement, ...(t.logging.notes ? { notes: t.logging.notes } : {}) },
    fields: mergeFields(entry.fields, t.fields),
    benign: t.benign,
    attacker: t.attacker,
    investigation: t.investigation,
  };
}

export type Technique = { id: string; name: string; tactics: string[]; url: string };

const TECHNIQUES = attack.techniques as Record<string, { name: string; tactics: string[] }>;

export function techniquesOf(entry: Pick<EventEntry, "attack">): Technique[] {
  return entry.attack
    .filter((id) => TECHNIQUES[id])
    .map((id) => ({
      id,
      name: TECHNIQUES[id].name,
      tactics: TECHNIQUES[id].tactics,
      url: `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`,
    }));
}

/** ATT&CK tactic slugs covered by an entry (ATT&CK matrix order). */
export function tacticsOf(entry: Pick<EventEntry, "attack">): string[] {
  const set = new Set(techniquesOf(entry).flatMap((t) => t.tactics));
  return ATTACK_TACTICS.filter((t) => set.has(t.slug)).map((t) => t.slug);
}

/** ATT&CK Enterprise tactics in matrix order (names are English by design). */
export const ATTACK_TACTICS: { id: string; slug: string; name: string }[] = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "stealth",
  "defense-impairment",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
]
  .map((slug) => attack.tactics.find((t) => t.slug === slug))
  .filter((t): t is { id: string; slug: string; name: string } => Boolean(t));

export const ATTACK_VERSION = attack.version;
