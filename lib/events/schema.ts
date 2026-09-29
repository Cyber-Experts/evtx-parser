// Runtime validation of the encyclopedia data (no fs here — see load.ts).
// Every check returns human-readable errors prefixed by the entry key so
// `npm run events:check` and the Vitest suite point at the offending file.

import attack from "./attack.json";
import { channelBySlug, SLUG_RE } from "./channels";
import {
  EVENT_CATEGORIES,
  type EventEntry,
  type EventTranslation,
} from "./types";

type Obj = Record<string, unknown>;

const ENTRY_KEYS = new Set([
  "id",
  "channel",
  "channelName",
  "provider",
  "title",
  "shortTitle",
  "category",
  "summary",
  "description",
  "logging",
  "fields",
  "benign",
  "attacker",
  "investigation",
  "related",
  "attack",
  "references",
]);
const TRANSLATION_KEYS = new Set([
  "title",
  "shortTitle",
  "summary",
  "description",
  "logging",
  "fields",
  "benign",
  "attacker",
  "investigation",
]);

export const SUMMARY_MIN = 50;
export const SUMMARY_MAX = 160;
export const SHORT_TITLE_MAX = 40;

const KEY_RE = /^([a-z0-9]+(?:-[a-z0-9]+)*)\/(\d+)$/;
// EventData names; spaces are allowed because some providers (Microsoft
// Defender: "Threat Name", "Detection User") use them.
const FIELD_RE = /^[A-Za-z_](?:[A-Za-z0-9_.-]| (?=[A-Za-z0-9]))*$/;
const TECHNIQUES = attack.techniques as Record<string, { name: string; tactics: string[] }>;
const REVOKED = attack.revoked as Record<string, string>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/** Parse "security/4624" into its parts (null when malformed). */
export function parseEventKey(key: string): { channel: string; id: number } | null {
  const m = KEY_RE.exec(key);
  if (!m) return null;
  const id = Number(m[2]);
  if (!Number.isInteger(id) || id < 0 || id > 65535) return null;
  return { channel: m[1], id };
}

/**
 * Drafting leftovers. Upper-case only: "todo" is an ordinary Spanish word
 * ("todo el tráfico"), so only the TODO/TBD/FIXME markers count.
 */
export function isPlaceholder(text: string): boolean {
  return /\b(TODO|TBD|FIXME)\b/.test(text) || /lorem ipsum/i.test(text);
}

class Collector {
  errors: string[] = [];
  constructor(private readonly where: string) {}
  add(msg: string) {
    this.errors.push(`${this.where}: ${msg}`);
  }
  str(o: Obj, key: string, opts: { min?: number; max?: number; optional?: boolean; oneLine?: boolean } = {}): string | undefined {
    const v = o[key];
    if (v === undefined && opts.optional) return undefined;
    if (typeof v !== "string" || !v.trim()) {
      this.add(`"${key}" must be a non-empty string`);
      return undefined;
    }
    const s = v.trim();
    if (opts.min !== undefined && s.length < opts.min) this.add(`"${key}" is ${s.length} chars (min ${opts.min})`);
    if (opts.max !== undefined && s.length > opts.max) this.add(`"${key}" is ${s.length} chars (max ${opts.max})`);
    if (opts.oneLine && /\n/.test(s)) this.add(`"${key}" must be a single line`);
    if (isPlaceholder(s)) this.add(`"${key}" contains a placeholder`);
    return s;
  }
  strList(o: Obj, key: string, min: number): string[] {
    const v = o[key];
    if (!Array.isArray(v)) {
      this.add(`"${key}" must be a list`);
      return [];
    }
    if (v.length < min) this.add(`"${key}" needs at least ${min} item(s)`);
    const out: string[] = [];
    v.forEach((item, i) => {
      if (typeof item !== "string" || !item.trim()) this.add(`"${key}[${i}]" must be a non-empty string`);
      else {
        if (isPlaceholder(item)) this.add(`"${key}[${i}]" contains a placeholder`);
        out.push(item.trim());
      }
    });
    return out;
  }
  unknownKeys(o: Obj, allowed: Set<string>, label = "") {
    for (const k of Object.keys(o)) if (!allowed.has(k)) this.add(`unknown key "${label}${k}"`);
  }
}

function fieldValues(c: Collector, raw: unknown, where: string): { value: string; meaning: string }[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw) || raw.length === 0) {
    c.add(`${where}.values must be a non-empty list`);
    return undefined;
  }
  const seen = new Set<string>();
  const out: { value: string; meaning: string }[] = [];
  raw.forEach((v, i) => {
    if (!isObj(v)) return c.add(`${where}.values[${i}] must be a mapping`);
    c.unknownKeys(v, new Set(["value", "meaning"]), `${where}.values[${i}].`);
    const value = typeof v.value === "number" ? String(v.value) : v.value;
    if (typeof value !== "string" || !value.trim()) return c.add(`${where}.values[${i}].value is required`);
    if (typeof v.meaning !== "string" || !v.meaning.trim()) return c.add(`${where}.values[${i}].meaning is required`);
    if (seen.has(value)) c.add(`${where}.values: duplicate value "${value}"`);
    seen.add(value);
    out.push({ value: value.trim(), meaning: v.meaning.trim() });
  });
  return out;
}

/**
 * Validate one English entry. `expect` is what the file path says
 * (folder = channel slug, file name = id).
 */
export function validateEntry(
  raw: unknown,
  expect: { channel: string; id: number },
): { entry: EventEntry | null; errors: string[] } {
  const c = new Collector(`${expect.channel}/${expect.id}`);
  if (!isObj(raw)) return { entry: null, errors: [`${expect.channel}/${expect.id}: file is not a YAML mapping`] };
  c.unknownKeys(raw, ENTRY_KEYS);

  if (raw.id !== expect.id) c.add(`"id" (${String(raw.id)}) does not match the file name (${expect.id})`);
  if (raw.channel !== expect.channel) c.add(`"channel" (${String(raw.channel)}) does not match the folder (${expect.channel})`);
  const channel = channelBySlug(expect.channel);
  if (!channel || !SLUG_RE.test(expect.channel)) c.add(`unknown channel slug "${expect.channel}" (add it to lib/events/channels.ts)`);
  const channelName = c.str(raw, "channelName", { optional: true, oneLine: true });
  if (channelName && channel && !channel.names.includes(channelName))
    c.add(`"channelName" "${channelName}" is not one of the channel's names`);

  const provider = c.str(raw, "provider", { oneLine: true, max: 100 });
  const title = c.str(raw, "title", { oneLine: true, max: 140 });
  const shortTitle = c.str(raw, "shortTitle", { oneLine: true, max: SHORT_TITLE_MAX });
  const category = raw.category;
  if (typeof category !== "string" || !(EVENT_CATEGORIES as readonly string[]).includes(category))
    c.add(`"category" must be one of: ${EVENT_CATEGORIES.join(", ")}`);
  const summary = c.str(raw, "summary", { min: SUMMARY_MIN, max: SUMMARY_MAX, oneLine: true });
  const description = c.str(raw, "description", { min: 150 });

  let logging: EventEntry["logging"] | null = null;
  if (!isObj(raw.logging)) c.add(`"logging" must be a mapping`);
  else {
    c.unknownKeys(raw.logging, new Set(["enabledByDefault", "requirement", "notes"]), "logging.");
    if (typeof raw.logging.enabledByDefault !== "boolean") c.add(`"logging.enabledByDefault" must be true or false`);
    const requirement = c.str(raw.logging, "requirement");
    const notes = c.str(raw.logging, "notes", { optional: true });
    logging = {
      enabledByDefault: raw.logging.enabledByDefault === true,
      requirement: requirement ?? "",
      ...(notes ? { notes } : {}),
    };
  }

  const fields: EventEntry["fields"] = [];
  if (!Array.isArray(raw.fields) || raw.fields.length === 0) c.add(`"fields" must be a non-empty list`);
  else {
    const names = new Set<string>();
    raw.fields.forEach((f, i) => {
      if (!isObj(f)) return c.add(`fields[${i}] must be a mapping`);
      c.unknownKeys(f, new Set(["name", "description", "values"]), `fields[${i}].`);
      const name = typeof f.name === "string" ? f.name.trim() : "";
      if (!FIELD_RE.test(name)) return c.add(`fields[${i}].name "${String(f.name)}" is not a valid field name`);
      if (names.has(name)) c.add(`fields: duplicate "${name}"`);
      names.add(name);
      if (typeof f.description !== "string" || !f.description.trim()) return c.add(`fields.${name}.description is required`);
      const values = fieldValues(c, f.values, `fields.${name}`);
      fields.push({ name, description: f.description.trim(), ...(values ? { values } : {}) });
    });
  }

  const benign = c.strList(raw, "benign", 1);
  const attacker = c.strList(raw, "attacker", 1);
  const investigation = c.strList(raw, "investigation", 2);

  const self = `${expect.channel}/${expect.id}`;
  const related = c.strList(raw, "related", 0);
  for (const r of related) {
    if (!parseEventKey(r)) c.add(`related "${r}" must look like "channel-slug/id"`);
    if (r === self) c.add(`related lists the entry itself`);
  }
  if (new Set(related).size !== related.length) c.add(`related has duplicates`);

  const techniques = c.strList(raw, "attack", 0);
  for (const t of techniques) {
    if (TECHNIQUES[t]) continue;
    const repl = REVOKED[t];
    c.add(
      repl
        ? `ATT&CK ${t} is revoked in v${attack.version}; use ${repl} (${TECHNIQUES[repl]?.name ?? "?"})`
        : `ATT&CK ${t} is not a current Windows Enterprise technique (v${attack.version})`,
    );
  }
  if (new Set(techniques).size !== techniques.length) c.add(`attack has duplicates`);

  const references: EventEntry["references"] = [];
  if (!Array.isArray(raw.references) || raw.references.length === 0) c.add(`"references" needs at least one source`);
  else
    raw.references.forEach((r, i) => {
      if (!isObj(r)) return c.add(`references[${i}] must be a mapping`);
      c.unknownKeys(r, new Set(["title", "url"]), `references[${i}].`);
      const t = typeof r.title === "string" ? r.title.trim() : "";
      const u = typeof r.url === "string" ? r.url.trim() : "";
      if (!t) c.add(`references[${i}].title is required`);
      if (!/^https:\/\/[^\s]+$/.test(u)) c.add(`references[${i}].url must be an https URL`);
      references.push({ title: t, url: u });
    });

  if (c.errors.length) return { entry: null, errors: c.errors };
  return {
    entry: {
      id: expect.id,
      channel: expect.channel,
      ...(channelName ? { channelName } : {}),
      provider: provider as string,
      title: title as string,
      shortTitle: shortTitle as string,
      category: category as EventEntry["category"],
      summary: summary as string,
      description: description as string,
      logging: logging as EventEntry["logging"],
      fields,
      benign,
      attacker,
      investigation,
      related,
      attack: techniques,
      references,
    },
    errors: [],
  };
}

/** Validate a translation against its English entry. */
export function validateTranslation(
  raw: unknown,
  entry: EventEntry,
  locale: string,
): { translation: EventTranslation | null; errors: string[] } {
  const where = `${entry.channel}/${entry.id}.${locale}`;
  const c = new Collector(where);
  if (!isObj(raw)) return { translation: null, errors: [`${where}: file is not a YAML mapping`] };
  c.unknownKeys(raw, TRANSLATION_KEYS);
  const title = c.str(raw, "title", { oneLine: true, max: 160 });
  const shortTitle = c.str(raw, "shortTitle", { oneLine: true, max: SHORT_TITLE_MAX + 10 });
  const summary = c.str(raw, "summary", { min: SUMMARY_MIN, max: SUMMARY_MAX, oneLine: true });
  const description = c.str(raw, "description", { min: 150 });
  let logging: EventTranslation["logging"] = { requirement: "" };
  if (!isObj(raw.logging)) c.add(`"logging" must be a mapping`);
  else {
    c.unknownKeys(raw.logging, new Set(["requirement", "notes"]), "logging.");
    const requirement = c.str(raw.logging, "requirement") ?? "";
    const notes = c.str(raw.logging, "notes", { optional: true });
    if (entry.logging.notes && !notes) c.add(`"logging.notes" is missing (the English entry has notes)`);
    logging = { requirement, ...(notes ? { notes } : {}) };
  }
  const fields: EventTranslation["fields"] = [];
  const english = new Map(entry.fields.map((f) => [f.name, f]));
  if (!Array.isArray(raw.fields)) c.add(`"fields" must be a list`);
  else
    raw.fields.forEach((f, i) => {
      if (!isObj(f)) return c.add(`fields[${i}] must be a mapping`);
      c.unknownKeys(f, new Set(["name", "description", "values"]), `fields[${i}].`);
      const name = typeof f.name === "string" ? f.name : "";
      const en = english.get(name);
      if (!en) return c.add(`fields[${i}].name "${name}" is not a field of the English entry`);
      if (typeof f.description !== "string" || !f.description.trim()) return c.add(`fields.${name}.description is required`);
      const values = fieldValues(c, f.values, `fields.${name}`);
      for (const v of values ?? [])
        if (!en.values?.some((x) => x.value === v.value)) c.add(`fields.${name}: value "${v.value}" is not in the English entry`);
      fields.push({ name, description: f.description.trim(), ...(values ? { values } : {}) });
    });
  for (const f of entry.fields)
    if (!fields.some((t) => t.name === f.name)) c.add(`fields: "${f.name}" is not translated`);
  const benign = c.strList(raw, "benign", 1);
  const attacker = c.strList(raw, "attacker", 1);
  const investigation = c.strList(raw, "investigation", 2);
  if (c.errors.length) return { translation: null, errors: c.errors };
  return {
    translation: {
      title: title as string,
      shortTitle: shortTitle as string,
      summary: summary as string,
      description: description as string,
      logging,
      fields,
      benign,
      attacker,
      investigation,
    },
    errors: [],
  };
}

/** Cross-entry checks: related keys must resolve to real entries. */
export function validateDataset(entries: EventEntry[]): string[] {
  const keys = new Set(entries.map((e) => `${e.channel}/${e.id}`));
  const errors: string[] = [];
  for (const e of entries)
    for (const r of e.related)
      if (!keys.has(r)) errors.push(`${e.channel}/${e.id}: related "${r}" has no entry`);
  return errors;
}

/** ATT&CK technique name/tactics (undefined for unknown IDs). */
export function techniqueInfo(id: string): { name: string; tactics: string[] } | undefined {
  return TECHNIQUES[id];
}
