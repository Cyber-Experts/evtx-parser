import type { EventDataset } from "./load";

export const MANIFEST_PATH = "lib/events/manifest.json";

/**
 * Client manifest: "channel/id" → translated locales (English always
 * exists). Tiny on purpose — the viewer imports it to build links without
 * shipping the encyclopedia itself.
 */
export type EventManifest = Record<string, string[]>;

export function buildManifest(ds: Pick<EventDataset, "entries" | "translations">): EventManifest {
  const keys = ds.entries
    .map((e) => `${e.channel}/${e.id}`)
    .sort((a, b) => a.localeCompare(b, "en", { numeric: true }));
  const out: EventManifest = {};
  for (const k of keys) out[k] = [...(ds.translations.get(k)?.keys() ?? [])].sort();
  return out;
}
