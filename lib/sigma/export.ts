// CSV / JSON export of Sigma matches. Every row / rule carries the DRL 1.1
// attribution ("Rule by <author>, SigmaHQ, DRL 1.1") and a link to the
// original rule, as the Detection Rule License requires for match output.

import { EventView, type Profile, normField } from "./engine";
import {
  attackTags,
  sigmaAttribution,
  sigmaRuleUrl,
  type SigmaMatch,
  type SigmaRuleMeta,
} from "./types";

export type SigmaExportRow = {
  record_id: number | bigint;
  timestamp: string;
  level: number | null;
  event_id: number | null;
  provider: string | null;
  channel: string | null;
  computer: string | null;
  _file?: string;
};

/** Profile the engine used for this (rule, event) pair. */
function profileFor(rule: SigmaRuleMeta, row: SigmaExportRow): Profile {
  return rule.logsource.category?.toLowerCase() === "process_creation" && row.event_id === 4688
    ? "security4688"
    : undefined;
}

/**
 * The event's values for the fields the rule tests (Sigma names, e.g.
 * `Image` resolves to NewProcessName on a Security 4688).
 */
export function keyFields(
  m: Pick<SigmaMatch, "rule" | "fields">,
  row: SigmaExportRow,
  pairs: [string, string][],
): [string, string][] {
  const view = new EventView({
    eventId: row.event_id,
    provider: row.provider,
    channel: row.channel,
    computer: row.computer,
    level: row.level,
    recordId: row.record_id,
    pairs,
  });
  const profile = profileFor(m.rule, row);
  const out: [string, string][] = [];
  for (const f of m.fields) {
    const v = view.get(normField(f), profile);
    if (v !== undefined && v !== "") out.push([f, v]);
  }
  return out;
}

const csvCell = (v: unknown) => {
  const s = v == null ? "" : String(v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

export function buildSigmaCsv(
  matches: SigmaMatch[],
  rowAt: (g: number) => SigmaExportRow,
  pairsAt: (g: number) => [string, string][],
  release: string,
): string {
  const header = [
    "rule_id",
    "rule_title",
    "rule_level",
    "rule_status",
    "attack_techniques",
    "event_record_id",
    "event_time",
    "computer",
    "channel",
    "event_id",
    "file",
    "key_fields",
    "attribution",
    "rule_url",
  ];
  const lines = [header.join(",")];
  for (const m of matches) {
    const attribution = sigmaAttribution(m.rule);
    const url = sigmaRuleUrl(m.rule, release) ?? "";
    const techniques = attackTags(m.rule.tags).techniques.join(" ");
    for (const g of m.gids) {
      const r = rowAt(g);
      const kf = keyFields(m, r, pairsAt(g))
        .map(([k, v]) => `${k}=${v}`)
        .join(" | ");
      lines.push(
        [
          m.rule.id,
          m.rule.title,
          m.rule.level,
          m.rule.status ?? "",
          techniques,
          Number(r.record_id),
          r.timestamp,
          r.computer ?? "",
          r.channel ?? "",
          r.event_id ?? "",
          r._file ?? "",
          kf,
          attribution,
          url,
        ]
          .map(csvCell)
          .join(","),
      );
    }
  }
  return lines.join("\r\n") + "\r\n";
}

export function buildSigmaJson(
  matches: SigmaMatch[],
  rowAt: (g: number) => SigmaExportRow,
  pairsAt: (g: number) => [string, string][],
  release: string,
): string {
  return JSON.stringify(
    {
      generator: "EVTX viewer — Sigma (in-browser)",
      generated: new Date().toISOString(),
      sigma: {
        release,
        source: "https://github.com/SigmaHQ/sigma",
        license: "Detection Rule License (DRL) 1.1 — https://github.com/SigmaHQ/Detection-Rule-License",
      },
      matches: matches.map((m) => ({
        rule: {
          id: m.rule.id,
          title: m.rule.title,
          level: m.rule.level,
          status: m.rule.status,
          description: m.rule.description,
          author: m.rule.author,
          references: m.rule.references,
          tags: m.rule.tags,
          source: m.rule.source,
          url: sigmaRuleUrl(m.rule, release),
          attribution: sigmaAttribution(m.rule),
        },
        count: m.gids.length,
        events: m.gids.map((g) => {
          const r = rowAt(g);
          return {
            record_id: Number(r.record_id),
            time: r.timestamp,
            computer: r.computer,
            channel: r.channel,
            provider: r.provider,
            event_id: r.event_id,
            file: r._file,
            key_fields: Object.fromEntries(keyFields(m, r, pairsAt(g))),
          };
        }),
      })),
    },
    null,
    2,
  );
}
