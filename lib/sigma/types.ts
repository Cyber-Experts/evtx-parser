// Shared Sigma types — kept free of runtime code so the UI can import them
// without pulling the engine (which only runs in the Web Worker).

export const SIGMA_LEVELS = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
] as const;
export type SigmaLevel = (typeof SIGMA_LEVELS)[number];

export type SigmaLogsource = {
  product?: string;
  category?: string;
  service?: string;
};

/** Rule metadata as displayed and exported (DRL 1.1 fields included). */
export type SigmaRuleMeta = {
  id: string;
  title: string;
  status?: string;
  level: SigmaLevel;
  description?: string;
  author?: string;
  date?: string;
  modified?: string;
  references?: string[];
  tags?: string[];
  falsepositives?: string[];
  logsource: SigmaLogsource;
  /** Path in the SigmaHQ repository (bundled rules only). */
  path?: string;
  /** "sigmahq" for the bundled set, "custom" for rules the user pasted. */
  source: "sigmahq" | "custom";
};

/** A full rule: metadata plus the raw `detection` block. */
export type SigmaRule = SigmaRuleMeta & {
  detection: Record<string, unknown>;
};

/** A rule that could not be compiled / mapped, and why. */
export type SigmaSkipped = {
  id: string;
  title: string;
  reason: string;
  path?: string;
};

/** Minimal event shape the engine evaluates. */
export type SigmaEvent = {
  eventId: number | null;
  provider: string | null;
  channel: string | null;
  computer: string | null;
  level: number | null;
  recordId: number | bigint;
  pairs: [string, string][];
};

/** One matched rule and the global row indexes (`_g`) it fired on. */
export type SigmaMatch = {
  rule: SigmaRuleMeta;
  /** Detection field names the rule tests (for "key fields" in exports). */
  fields: string[];
  gids: number[];
};

export type SigmaRunStats = {
  /** Bundled rules available / custom rules supplied. */
  bundled: number;
  custom: number;
  /** Rules actually evaluated (bundled + valid custom). */
  evaluated: number;
  events: number;
  ms: number;
  release: string;
};

export type SigmaRunResult = {
  matches: SigmaMatch[];
  stats: SigmaRunStats;
  /** Custom rules that failed validation. */
  customErrors: SigmaSkipped[];
};

/** Bundle written by `npm run sigma:update`. */
export type SigmaBundle = {
  release: string;
  commit?: string;
  source: string;
  license: string;
  generated: string;
  counts: {
    /** Rule files scanned under rules/windows. */
    files: number;
    bundled: number;
    /** Deprecated (status or SigmaHQ deprecated/windows tree), excluded. */
    deprecated: number;
    /** SigmaHQ unsupported/windows tree, excluded. */
    sigmaUnsupported: number;
    /** Scanned rules the engine can't run on EVTX (see sigmahq-skipped.json). */
    unsupported: number;
  };
  rules: SigmaRule[];
};

/** Attribution line required by DRL 1.1 on every match message/export. */
export function sigmaAttribution(rule: Pick<SigmaRuleMeta, "author" | "source">): string {
  const author = rule.author?.trim() || "unknown author";
  return rule.source === "sigmahq"
    ? `Rule by ${author}, SigmaHQ, DRL 1.1`
    : `Rule by ${author}`;
}

/** Public URL of a bundled rule in the pinned SigmaHQ release. */
export function sigmaRuleUrl(rule: Pick<SigmaRuleMeta, "path" | "source">, release: string): string | null {
  if (rule.source !== "sigmahq" || !rule.path) return null;
  return `https://github.com/SigmaHQ/sigma/blob/${release}/${rule.path}`;
}

/** ATT&CK technique ids (T1059.001) and tactics from Sigma tags. */
export function attackTags(tags: string[] | undefined): {
  techniques: string[];
  tactics: string[];
} {
  const techniques: string[] = [];
  const tactics: string[] = [];
  for (const raw of tags ?? []) {
    const t = raw.toLowerCase();
    if (!t.startsWith("attack.")) continue;
    const v = t.slice(7);
    if (/^t\d{4}(\.\d{3})?$/.test(v)) techniques.push(v.toUpperCase());
    else if (/^[gs]\d{4}$/.test(v)) continue;
    else tactics.push(v.replace(/_/g, "-"));
  }
  return { techniques, tactics };
}

/** MITRE ATT&CK page for a technique id (T1059.001 → /techniques/T1059/001/). */
export function attackUrl(technique: string): string {
  return `https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`;
}

/** "privilege-escalation" → "Privilege Escalation" (ATT&CK names are English). */
export function tacticLabel(tactic: string): string {
  return tactic
    .split("-")
    .map((w) => (w === "and" ? w : w.charAt(0).toUpperCase() + w.slice(1)))
    .join(" ");
}
