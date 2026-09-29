// Loads and validates data/events at build time (Node only). Invalid data
// throws — a broken entry must fail the build rather than ship a thin page.

import fs from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";

import { channelBySlug } from "./channels";
import { validateDataset, validateEntry, validateTranslation } from "./schema";
import {
  EVENT_TRANSLATION_LOCALES,
  type EventEntry,
  type EventTranslation,
} from "./types";

export const EVENTS_DIR = path.join(process.cwd(), "data/events");

const FILE_RE = /^(\d+)(?:\.([a-z]{2}))?\.yaml$/;

export type EventDataset = {
  entries: EventEntry[];
  /** "channel/id" → locale → translation. */
  translations: Map<string, Map<string, EventTranslation>>;
  errors: string[];
};

/** Read + validate everything; never throws (errors are collected). */
export function readEventDataset(dir = EVENTS_DIR): EventDataset {
  const entries: EventEntry[] = [];
  const pending: { channel: string; id: number; locale: string; raw: unknown }[] = [];
  const errors: string[] = [];
  if (!fs.existsSync(dir)) return { entries, translations: new Map(), errors: [`${dir} does not exist`] };
  for (const channel of fs.readdirSync(dir).sort()) {
    const cdir = path.join(dir, channel);
    if (!fs.statSync(cdir).isDirectory()) continue;
    if (!channelBySlug(channel)) {
      errors.push(`${channel}: folder is not a known channel slug`);
      continue;
    }
    for (const file of fs.readdirSync(cdir).sort()) {
      const m = FILE_RE.exec(file);
      if (!m) {
        errors.push(`${channel}/${file}: unexpected file name (want <id>.yaml or <id>.<locale>.yaml)`);
        continue;
      }
      const id = Number(m[1]);
      let raw: unknown;
      try {
        raw = parseYaml(fs.readFileSync(path.join(cdir, file), "utf8"));
      } catch (err) {
        errors.push(`${channel}/${file}: YAML error — ${err instanceof Error ? err.message : String(err)}`);
        continue;
      }
      if (m[2]) {
        if (!(EVENT_TRANSLATION_LOCALES as readonly string[]).includes(m[2]))
          errors.push(`${channel}/${file}: translations are only accepted for ${EVENT_TRANSLATION_LOCALES.join(", ")}`);
        else pending.push({ channel, id, locale: m[2], raw });
        continue;
      }
      const res = validateEntry(raw, { channel, id });
      errors.push(...res.errors);
      if (res.entry) entries.push(res.entry);
    }
  }
  const byKey = new Map(entries.map((e) => [`${e.channel}/${e.id}`, e]));
  const translations = new Map<string, Map<string, EventTranslation>>();
  for (const t of pending) {
    const key = `${t.channel}/${t.id}`;
    const entry = byKey.get(key);
    if (!entry) {
      errors.push(`${key}.${t.locale}: translation without an English entry`);
      continue;
    }
    const res = validateTranslation(t.raw, entry, t.locale);
    errors.push(...res.errors);
    if (!res.translation) continue;
    let m = translations.get(key);
    if (!m) translations.set(key, (m = new Map()));
    m.set(t.locale, res.translation);
  }
  errors.push(...validateDataset(entries));
  return { entries, translations, errors };
}

let cache: EventDataset | null = null;

/** Validated dataset, memoised per process; throws on any data error. */
export function loadEventDataset(): EventDataset {
  if (cache) return cache;
  const ds = readEventDataset();
  if (ds.errors.length)
    throw new Error(`Invalid Event ID encyclopedia data:\n  ${ds.errors.join("\n  ")}`);
  cache = ds;
  return ds;
}
