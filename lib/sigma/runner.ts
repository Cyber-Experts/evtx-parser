// Sigma run loop: streams records from one or more sources in chunks through
// the rule index, yielding between chunks so the worker keeps answering
// other requests (XML lookups, …) and a newer run can supersede this one.

import { SigmaIndex, compileRules, type CompiledRule } from "./engine";
import { parseSigmaYaml } from "./parse";
import {
  SIGMA_LEVELS,
  type SigmaBundle,
  type SigmaMatch,
  type SigmaRule,
  type SigmaRuleMeta,
  type SigmaRunResult,
  type SigmaSkipped,
} from "./types";

/** Row fields the engine reads (EventRow from the WASM parser satisfies it). */
export type SigmaRow = {
  record_id: number | bigint;
  level: number | null;
  event_id: number | null;
  provider: string | null;
  channel: string | null;
  computer: string | null;
};

/** One loaded file: `offset` is its first global row index (`_g`). */
export type SigmaSource = {
  offset: number;
  count: number;
  rows: (start: number, len: number) => SigmaRow[];
  pairs: (start: number, len: number) => [string, string][][];
};

export class SigmaAborted extends Error {}

const CHUNK = 4000;

let bundledCache: { bundle: SigmaBundle; compiled: CompiledRule[] } | null = null;

/** Compile the bundled rule set once per worker. */
export function prepareBundled(bundle: SigmaBundle): CompiledRule[] {
  if (bundledCache?.bundle === bundle) return bundledCache.compiled;
  const rules = bundle.rules.map((r) => ({ ...r, source: "sigmahq" as const }));
  const { compiled } = compileRules(rules);
  bundledCache = { bundle, compiled };
  return compiled;
}

/** Parse and validate pasted/dropped rule texts. */
export function parseCustom(texts: string[]): { rules: SigmaRule[]; errors: SigmaSkipped[] } {
  const rules: SigmaRule[] = [];
  const errors: SigmaSkipped[] = [];
  texts.forEach((text, i) => {
    const r = parseSigmaYaml(text, { source: "custom", idPrefix: `custom-${i + 1}` });
    rules.push(...r.rules);
    errors.push(...r.errors);
  });
  return { rules, errors };
}

function meta(rule: SigmaRule): SigmaRuleMeta {
  const { detection: _d, ...m } = rule;
  void _d;
  return m;
}

const LEVEL_RANK = Object.fromEntries(SIGMA_LEVELS.map((l, i) => [l, i])) as Record<string, number>;

export async function runSigma(opts: {
  bundle: SigmaBundle | null;
  customTexts: string[];
  sources: SigmaSource[];
  onProgress?: (done: number, total: number) => void;
  /** Checked between chunks; return true to abandon the run. */
  aborted?: () => boolean;
  /** Awaited between chunks (a macrotask in the worker). */
  pause?: () => Promise<void>;
  /** Literal pre-filter (default on; tests compare against off). */
  gates?: boolean;
}): Promise<SigmaRunResult> {
  const t0 = performance.now();
  const bundled = opts.bundle ? prepareBundled(opts.bundle) : [];
  const custom = parseCustom(opts.customTexts);
  const customCompiled = compileRules(custom.rules).compiled;
  // One index over bundled + custom; rule.index is its position here.
  const all: CompiledRule[] = [
    ...bundled.map((r, i) => ({ ...r, index: i })),
    ...customCompiled.map((r, i) => ({ ...r, index: bundled.length + i })),
  ];
  const index = new SigmaIndex(all, opts.gates !== false);
  const hits: number[][] = all.map(() => []);

  const total = opts.sources.reduce((s, x) => s + x.count, 0);
  let done = 0;
  for (const src of opts.sources) {
    for (let start = 0; start < src.count; start += CHUNK) {
      const len = Math.min(CHUNK, src.count - start);
      const rows = src.rows(start, len);
      const pairs = src.pairs(start, len);
      for (let i = 0; i < rows.length; i++) {
        const r = rows[i];
        const g = src.offset + start + i;
        index.evaluate(
          {
            eventId: r.event_id,
            provider: r.provider,
            channel: r.channel,
            computer: r.computer,
            level: r.level,
            recordId: r.record_id,
            pairs: pairs[i] ?? [],
          },
          (ri) => hits[ri].push(g),
        );
      }
      done += len;
      opts.onProgress?.(done, total);
      if (opts.pause) await opts.pause();
      if (opts.aborted?.()) throw new SigmaAborted("superseded");
    }
  }

  const matches: SigmaMatch[] = [];
  for (const r of all) {
    const gids = hits[r.index];
    if (gids.length) matches.push({ rule: meta(r.rule), fields: r.fields, gids });
  }
  matches.sort(
    (a, b) =>
      LEVEL_RANK[a.rule.level] - LEVEL_RANK[b.rule.level] ||
      b.gids.length - a.gids.length ||
      a.rule.title.localeCompare(b.rule.title),
  );
  return {
    matches,
    customErrors: custom.errors,
    stats: {
      bundled: bundled.length,
      custom: customCompiled.length,
      evaluated: all.length,
      events: total,
      ms: Math.round(performance.now() - t0),
      release: opts.bundle?.release ?? "",
    },
  };
}
