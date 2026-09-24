// Search-box query language for the events table.
//
//   mimikatz                     free text, any field incl. EventData values
//   "net user"                   quoted phrase
//   EventID:4624                 field equals (case-insensitive)
//   TargetUserName:svc_*         * wildcard
//   EventID:>=4700               numeric comparison (> >= < <=)
//   -IpAddress:127.0.0.1         negation (also works on free text)
//   4624 OR 4625                 OR between AND-groups
//   logonid:0x3e7                pseudo-field: any *LogonId field
//   processguid:{…}              pseudo-field: any *ProcessGuid field
//
// Field names are case-insensitive. Built-in names (eventid, level,
// provider, channel, computer, file, name, record) target row metadata;
// anything else is looked up in the event's EventData.

import { eventName } from "@/lib/event-info";
import { decodedText } from "@/lib/event-decode";

export type SearchRow = {
  event_id: number | null;
  level: number | null;
  provider: string | null;
  channel: string | null;
  computer: string | null;
  record_id: number | bigint | string;
  _file: string;
};

type Cmp = ">" | ">=" | "<" | "<=";

export type Clause = {
  negate: boolean;
  /** Lower-cased field name; null for free text. */
  field: string | null;
  /** Raw value as typed (quotes removed). */
  value: string;
  cmp: Cmp | null;
};

export type ParsedSearch = {
  /** OR of AND-groups. */
  groups: Clause[][];
};

const META_ALIASES: Record<string, string> = {
  eventid: "eventid",
  id: "eventid",
  event_id: "eventid",
  level: "level",
  provider: "provider",
  source: "provider",
  channel: "channel",
  log: "channel",
  computer: "computer",
  host: "computer",
  file: "file",
  name: "name",
  record: "record",
  recordid: "record",
};

/** Pseudo-fields that match several EventData keys at once (pivots). */
export const MULTI_FIELDS: Record<string, string[]> = {
  logonid: ["targetlogonid", "subjectlogonid", "logonid"],
  processguid: [
    "processguid",
    "parentprocessguid",
    "sourceprocessguid",
    "targetprocessguid",
  ],
};

export const META_FIELD_NAMES = [
  "EventID",
  "Level",
  "Provider",
  "Channel",
  "Computer",
  "File",
  "Name",
  "Record",
];

// EventData fields worth stacking in an investigation, in display order.
// Ranked first in autocomplete and the field sidebar.
export const PREFERRED_FIELDS = [
  "TargetUserName",
  "SubjectUserName",
  "LogonType",
  "IpAddress",
  "WorkstationName",
  "AuthenticationPackageName",
  "LogonProcessName",
  "Status",
  "FailureReason",
  "TicketEncryptionType",
  "ServiceName",
  "ImagePath",
  "TaskName",
  "ProcessName",
  "NewProcessName",
  "ParentProcessName",
  "CommandLine",
  "Image",
  "ParentImage",
  "User",
  "DestinationIp",
  "DestinationPort",
  "QueryName",
  "TargetFilename",
  "ObjectName",
];

// --- Tokenizer -------------------------------------------------------------

type Token = { text: string; quoted: boolean };

/** Split on whitespace, keeping "quoted phrases" (with \" escapes) intact.
 *  A quote may start mid-token (Field:"a b"), which is kept as one token. */
function tokenize(input: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < input.length) {
    while (i < input.length && /\s/.test(input[i])) i++;
    if (i >= input.length) break;
    let text = "";
    let quoted = false;
    while (i < input.length && !/\s/.test(input[i])) {
      if (input[i] === '"') {
        quoted = true;
        i++;
        while (i < input.length && input[i] !== '"') {
          if (input[i] === "\\" && input[i + 1] === '"') {
            text += '"';
            i += 2;
          } else {
            text += input[i++];
          }
        }
        i++; // closing quote (or end of input)
      } else {
        text += input[i++];
      }
    }
    out.push({ text, quoted });
  }
  return out;
}

// Quoting in tokenize() strips the quotes, so remember where the field/value
// boundary was before stripping: re-scan the raw token for a leading field.
const FIELD_RE = /^(-?)([A-Za-z_][\w.-]*):([\s\S]*)$/;

export function parseSearch(input: string): ParsedSearch {
  const groups: Clause[][] = [[]];
  // Re-tokenize raw (unstripped) text so "Field:"a b"" still splits at ':'.
  const raw = rawTokens(input);
  const toks = tokenize(input);
  for (let n = 0; n < toks.length; n++) {
    const { text, quoted } = toks[n];
    const rawText = raw[n] ?? text;
    if (!quoted && text === "OR") {
      if (groups[groups.length - 1].length > 0) groups.push([]);
      continue;
    }
    let negate = false;
    let field: string | null = null;
    let value = text;
    const m = FIELD_RE.exec(rawText);
    if (m && !rawText.startsWith('"')) {
      negate = m[1] === "-";
      field = m[2].toLowerCase();
      value = unquote(m[3]);
    } else if (!rawText.startsWith('"') && text.startsWith("-") && text.length > 1) {
      negate = true;
      value = text.slice(1);
    }
    let cmp: Cmp | null = null;
    if (field) {
      const c = /^(>=|<=|>|<)(.+)$/.exec(value);
      if (c && !Number.isNaN(Number(c[2]))) {
        cmp = c[1] as Cmp;
        value = c[2];
      }
    }
    if (!value && !field) continue;
    groups[groups.length - 1].push({ negate, field, value, cmp });
  }
  return { groups: groups.filter((g) => g.length > 0) };
}

function rawTokens(input: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < input.length) {
    while (i < input.length && /\s/.test(input[i])) i++;
    if (i >= input.length) break;
    let text = "";
    while (i < input.length && !/\s/.test(input[i])) {
      if (input[i] === '"') {
        text += input[i++];
        while (i < input.length && input[i] !== '"') {
          if (input[i] === "\\" && input[i + 1] === '"') {
            text += '\\"';
            i += 2;
          } else {
            text += input[i++];
          }
        }
        if (i < input.length) text += input[i++];
      } else {
        text += input[i++];
      }
    }
    out.push(text);
  }
  return out;
}

function unquote(v: string): string {
  if (v.startsWith('"')) {
    const body = v.endsWith('"') && v.length > 1 ? v.slice(1, -1) : v.slice(1);
    return body.replace(/\\"/g, '"');
  }
  return v;
}

// --- Evaluation ------------------------------------------------------------

function globToRegExp(glob: string): RegExp {
  const esc = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${esc}$`, "i");
}

function valueMatcher(c: Clause): (v: string) => boolean {
  const want = c.value.toLowerCase();
  if (c.cmp) {
    const n = Number(c.value);
    return (v) => {
      const x = Number(v);
      if (Number.isNaN(x) || v === "") return false;
      switch (c.cmp) {
        case ">":
          return x > n;
        case ">=":
          return x >= n;
        case "<":
          return x < n;
        default:
          return x <= n;
      }
    };
  }
  if (want.includes("*")) {
    const re = globToRegExp(c.value);
    return (v) => re.test(v);
  }
  return (v) => v.toLowerCase() === want;
}

function metaValues(field: string, row: SearchRow): string[] | null {
  switch (META_ALIASES[field]) {
    case "eventid":
      return [row.event_id == null ? "" : String(row.event_id)];
    case "level":
      return [row.level == null ? "" : String(row.level)];
    case "provider":
      return [row.provider ?? ""];
    case "channel":
      return [row.channel ?? ""];
    case "computer":
      return [row.computer ?? ""];
    case "file":
      return [row._file];
    case "name":
      return [eventName(row.event_id, row.provider) ?? ""];
    case "record":
      return [String(row.record_id)];
    default:
      return null;
  }
}

function fieldValues(
  field: string,
  row: SearchRow,
  pairs: [string, string][],
): string[] {
  const meta = metaValues(field, row);
  if (meta) return meta;
  const keys = MULTI_FIELDS[field] ?? [field];
  const out: string[] = [];
  for (const [k, v] of pairs) {
    if (keys.includes(k.toLowerCase())) out.push(v);
  }
  return out;
}

/** Everything free text can hit, lower-cased and joined. */
export function haystackFor(row: SearchRow, pairs: [string, string][]): string {
  const parts = [
    row.event_id == null ? "" : String(row.event_id),
    row.provider ?? "",
    row.channel ?? "",
    row.computer ?? "",
    row._file,
    eventName(row.event_id, row.provider) ?? "",
  ];
  for (const [, v] of pairs) parts.push(v);
  // Decoded codes too, so "RemoteInteractive" or "bad password" match.
  parts.push(decodedText(pairs));
  return parts.join("\u0001").toLowerCase();
}

export type CompiledSearch = (
  row: SearchRow,
  pairs: [string, string][],
  haystack: () => string,
) => boolean;

export function compileSearch(parsed: ParsedSearch): CompiledSearch | null {
  if (parsed.groups.length === 0) return null;
  const groups = parsed.groups.map((g) =>
    g.map((c) => {
      const negate = c.negate;
      if (c.field == null) {
        const needle = c.value.toLowerCase();
        return (_r: SearchRow, _p: [string, string][], hay: () => string) =>
          hay().includes(needle) !== negate;
      }
      const field = c.field;
      const match = valueMatcher(c);
      return (r: SearchRow, p: [string, string][]) => {
        const hit = fieldValues(field, r, p).some(match);
        return hit !== negate;
      };
    }),
  );
  return (row, pairs, haystack) =>
    groups.some((g) => g.every((test) => test(row, pairs, haystack)));
}

/** Terms worth highlighting: positive free text and exact field values. */
export function highlightTerms(parsed: ParsedSearch): string[] {
  const out = new Set<string>();
  for (const g of parsed.groups) {
    for (const c of g) {
      if (c.negate || c.cmp) continue;
      const v = c.value.replace(/\*/g, "").trim();
      if (v.length >= 2 || (c.field == null && v.length >= 1)) out.add(v);
    }
  }
  return [...out];
}

// --- Building queries from clicks ---------------------------------------

export function quoteValue(v: string): string {
  return /[\s"():]/.test(v) || v === "" || v === "OR"
    ? `"${v.replace(/"/g, '\\"')}"`
    : v;
}

export function clauseText(field: string, value: string, negate = false): string {
  return `${negate ? "-" : ""}${field}:${quoteValue(value)}`;
}

/** Append a clause to the query, replacing its opposite (include/exclude)
 *  and skipping exact duplicates. */
export function withClause(
  query: string,
  field: string,
  value: string,
  negate = false,
): string {
  const text = clauseText(field, value, negate);
  const opposite = clauseText(field, value, !negate);
  const parts = rawTokens(query).filter(
    (t) => t.toLowerCase() !== opposite.toLowerCase(),
  );
  if (parts.some((t) => t.toLowerCase() === text.toLowerCase())) {
    return parts.join(" ");
  }
  return [...parts, text].join(" ");
}

/** Whether the query already contains this exact clause. */
export function hasClause(
  query: string,
  field: string,
  value: string,
  negate = false,
): boolean {
  const text = clauseText(field, value, negate).toLowerCase();
  return rawTokens(query).some((t) => t.toLowerCase() === text);
}

export function withoutClause(
  query: string,
  field: string,
  value: string,
  negate = false,
): string {
  const text = clauseText(field, value, negate).toLowerCase();
  return rawTokens(query)
    .filter((t) => t.toLowerCase() !== text)
    .join(" ");
}

/** The token being typed at the end of the input, for autocomplete. */
export function lastToken(query: string): string {
  if (/\s$/.test(query)) return "";
  const toks = rawTokens(query);
  return toks[toks.length - 1] ?? "";
}

export function replaceLastToken(query: string, replacement: string): string {
  const tok = lastToken(query);
  return query.slice(0, query.length - tok.length) + replacement;
}
