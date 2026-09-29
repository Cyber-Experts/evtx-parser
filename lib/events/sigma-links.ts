// Build-time link between encyclopedia entries and the bundled SigmaHQ rules.
//
// A rule targets an event when its logsource resolves to the event's channel
// (lib/sigma/logsource.ts) AND the event ID is pinned down either by the
// logsource (Sysmon-style categories: process_creation → Sysmon 1 and
// Security 4688) or by the detection's `EventID:` selections. Rules that
// accept every event of a channel (keyword-only detections) are not listed:
// they would appear on every page of that channel and say nothing about it.

import bundleJson from "@/lib/sigma/sigmahq-rules.json";
import { compileRules, type CompiledRule } from "@/lib/sigma/engine";
import { attackTags, SIGMA_LEVELS, sigmaAttribution, sigmaRuleUrl, type SigmaBundle, type SigmaLevel } from "@/lib/sigma/types";

import { channelBySlug } from "./channels";
import type { EventEntry } from "./types";

const bundle = bundleJson as unknown as SigmaBundle;

export type LinkedRule = {
  id: string;
  title: string;
  level: SigmaLevel;
  status?: string;
  author: string;
  attribution: string;
  url: string | null;
  techniques: string[];
};

export type SigmaLinks = {
  release: string;
  total: number;
  byLevel: Record<SigmaLevel, number>;
  /** Highest levels first, then title. */
  rules: LinkedRule[];
};

let compiled: CompiledRule[] | null = null;
function rules(): CompiledRule[] {
  compiled ??= compileRules(bundle.rules).compiled;
  return compiled;
}

const LEVEL_RANK = Object.fromEntries(SIGMA_LEVELS.map((l, i) => [l, i])) as Record<SigmaLevel, number>;

/** Lower-cased channel names an entry can be logged under. */
function channelNames(entry: Pick<EventEntry, "channel" | "channelName">): string[] {
  if (entry.channelName) return [entry.channelName.toLowerCase()];
  return (channelBySlug(entry.channel)?.names ?? []).map((n) => n.toLowerCase());
}

/** Does this compiled rule specifically target (channel, id)? */
export function ruleTargetsEvent(rule: CompiledRule, channels: string[], id: number): boolean {
  if (rule.eventIds && !rule.eventIds.has(id)) return false;
  for (const t of rule.targets) {
    if (t.channel !== null && !channels.includes(t.channel)) continue;
    if (t.eventIds) {
      if (t.eventIds.includes(id)) return true;
      continue;
    }
    // Channel-wide target: only specific when the detection pins the ID.
    if (rule.eventIds?.has(id)) return true;
  }
  return false;
}

const cache = new Map<string, SigmaLinks>();

export function sigmaLinksFor(entry: Pick<EventEntry, "channel" | "channelName" | "id">): SigmaLinks {
  const key = `${entry.channel}/${entry.id}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const channels = channelNames(entry);
  const matched = rules()
    .filter((r) => ruleTargetsEvent(r, channels, entry.id))
    // The bundle omits `source`; every bundled rule is SigmaHQ's (DRL 1.1).
    .map((r) => ({ ...r.rule, source: "sigmahq" as const }))
    .sort((a, b) => LEVEL_RANK[a.level] - LEVEL_RANK[b.level] || a.title.localeCompare(b.title));
  const byLevel = Object.fromEntries(SIGMA_LEVELS.map((l) => [l, 0])) as Record<SigmaLevel, number>;
  for (const r of matched) byLevel[r.level]++;
  const out: SigmaLinks = {
    release: bundle.release,
    total: matched.length,
    byLevel,
    rules: matched.map((r) => ({
      id: r.id,
      title: r.title,
      level: r.level,
      ...(r.status ? { status: r.status } : {}),
      author: r.author?.trim() || "unknown author",
      attribution: sigmaAttribution(r),
      url: sigmaRuleUrl(r, bundle.release),
      techniques: attackTags(r.tags).techniques,
    })),
  };
  cache.set(key, out);
  return out;
}

export const SIGMA_RELEASE = bundle.release;
