// Sigma YAML → SigmaRule. Used by the bundle script (scripts/sigma-update.ts)
// and, in the worker, for rules the analyst pastes or drops. Parsing and
// validation are local; nothing is ever uploaded.

import { parseAllDocuments } from "yaml";

import { compileRule, normalizeLevel } from "./engine";
import type { SigmaRule, SigmaSkipped } from "./types";

const str = (v: unknown): string | undefined =>
  v == null ? undefined : typeof v === "string" ? v : String(v);
const strList = (v: unknown): string[] | undefined => {
  if (v == null) return undefined;
  const list = Array.isArray(v) ? v : [v];
  const out = list.filter((x) => x != null).map((x) => String(x));
  return out.length ? out : undefined;
};

/** Why a parsed YAML document isn't a runnable detection rule, if it isn't. */
function shapeError(doc: Record<string, unknown>): string | null {
  if (doc.correlation) return "correlation rules are not supported";
  if (doc.action) return "rule collections (`action:`) are not supported";
  if (doc.filter && !doc.detection) return "filter rules are not supported";
  if (!doc.title) return "missing title";
  if (!doc.detection || typeof doc.detection !== "object") return "missing detection";
  if (!doc.logsource || typeof doc.logsource !== "object") return "missing logsource";
  return null;
}

/** Build a SigmaRule from a parsed YAML object (no validation). */
export function toSigmaRule(
  doc: Record<string, unknown>,
  source: SigmaRule["source"],
  fallbackId: string,
  path?: string,
): SigmaRule {
  const ls = (doc.logsource ?? {}) as Record<string, unknown>;
  return {
    id: str(doc.id) ?? fallbackId,
    title: str(doc.title) ?? fallbackId,
    status: str(doc.status),
    level: normalizeLevel(doc.level),
    description: str(doc.description)?.trim(),
    author: str(doc.author)?.trim(),
    date: str(doc.date),
    modified: str(doc.modified),
    references: strList(doc.references),
    tags: strList(doc.tags),
    falsepositives: strList(doc.falsepositives),
    logsource: {
      product: str(ls.product),
      category: str(ls.category),
      service: str(ls.service),
    },
    detection: doc.detection as Record<string, unknown>,
    path,
    source,
  };
}

/**
 * Parse one or more YAML documents (a pasted rule, a dropped .yml, or several
 * rules separated by `---`) and validate each against the engine.
 */
export function parseSigmaYaml(
  text: string,
  opts: { source?: SigmaRule["source"]; idPrefix?: string; path?: string } = {},
): { rules: SigmaRule[]; errors: SigmaSkipped[] } {
  const rules: SigmaRule[] = [];
  const errors: SigmaSkipped[] = [];
  const prefix = opts.idPrefix ?? "custom";
  let docs;
  try {
    docs = parseAllDocuments(text, { uniqueKeys: false, prettyErrors: false });
  } catch (err) {
    errors.push({ id: prefix, title: prefix, reason: `YAML: ${err instanceof Error ? err.message : err}` });
    return { rules, errors };
  }
  const list = Array.isArray(docs) ? docs : [docs];
  list.forEach((d, n) => {
    const fallbackId = `${prefix}-${n + 1}`;
    if (d.errors.length) {
      errors.push({ id: fallbackId, title: fallbackId, reason: `YAML: ${d.errors[0].message.split("\n")[0]}` });
      return;
    }
    const obj = d.toJS();
    if (obj == null) return; // empty document (trailing ---)
    if (typeof obj !== "object" || Array.isArray(obj)) {
      errors.push({ id: fallbackId, title: fallbackId, reason: "not a Sigma rule (expected a mapping)" });
      return;
    }
    const doc = obj as Record<string, unknown>;
    const bad = shapeError(doc);
    const title = str(doc.title) ?? fallbackId;
    const id = str(doc.id) ?? fallbackId;
    if (bad) {
      errors.push({ id, title, reason: bad, path: opts.path });
      return;
    }
    const rule = toSigmaRule(doc, opts.source ?? "custom", fallbackId, opts.path);
    try {
      compileRule(rule);
      rules.push(rule);
    } catch (err) {
      errors.push({ id, title, reason: err instanceof Error ? err.message : String(err), path: opts.path });
    }
  });
  return { rules, errors };
}
