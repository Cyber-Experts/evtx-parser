// Sigma rule engine — compiles Sigma detections into closures and evaluates
// them against parsed EVTX records. Runs in the Web Worker (see
// lib/evtx.worker.ts); nothing here touches the DOM or the network.
//
// Supported (Sigma specification 2.x, detection part):
//   - selections as maps (AND of fields), lists of maps (OR), keyword lists
//   - value lists (OR, or AND with `|all`), null, empty string, wildcards
//     `*` / `?` with `\` escaping, numbers and booleans
//   - modifiers: contains, startswith, endswith, all, exists, re (+ i/m/s),
//     cased, base64, base64offset, utf16le / utf16be / utf16 / wide,
//     windash, cidr, gt / gte / lt / lte, fieldref
//   - conditions: and / or / not, parentheses, `1 of` / `any of` /
//     `all of` / `N of` over selection name patterns and `them`,
//     a list of conditions (OR)
// Not supported (reported, never silently ignored): aggregations
// (`| count() by …`), `near`, correlation rules, the `expand` modifier.

import {
  canonicalChannel,
  resolveLogsource,
  type LogTarget,
} from "./logsource";
import { GateIndex, type Atom } from "./gate";
import {
  SIGMA_LEVELS,
  type SigmaEvent,
  type SigmaLevel,
  type SigmaRule,
} from "./types";

export class SigmaCompileError extends Error {}

// ---------------------------------------------------------------------------
// Event field access
// ---------------------------------------------------------------------------

/** Normalized field key: lower-case, spaces removed ("Threat Name" → "threatname"). */
export function normField(name: string): string {
  return name.toLowerCase().replace(/\s+/g, "");
}
// EventData key spellings repeat across millions of records: memoize.
const normCache = new Map<string, string>();
function normKey(k: string): string {
  let n = normCache.get(k);
  if (n === undefined) {
    n = normField(k);
    if (normCache.size < 50_000) normCache.set(k, n);
  }
  return n;
}

const INTEGRITY_BY_SID: Record<string, string> = {
  "s-1-16-0": "Untrusted",
  "s-1-16-4096": "Low",
  "s-1-16-8192": "Medium",
  "s-1-16-8448": "MediumPlus",
  "s-1-16-12288": "High",
  "s-1-16-16384": "System",
  "s-1-16-20480": "ProtectedProcess",
};

function hexToDec(v: string | undefined): string | undefined {
  if (v == null) return undefined;
  const t = v.trim();
  if (/^0x[0-9a-f]+$/i.test(t)) return String(parseInt(t, 16));
  return t;
}

/** Field-mapping profile for a (rule, event) pairing. */
export type Profile = "security4688" | undefined;

/**
 * Lazily indexed view of one event. Values are looked up by normalized
 * field name; lower-cased copies and the keyword haystack are cached.
 */
export class EventView {
  private map: Map<string, string> | null = null;
  private lower = new Map<string, string | undefined>();
  private lower4688: Map<string, string | undefined> | null = null;
  private hay: string | null = null;

  constructor(readonly ev: SigmaEvent) {}

  private fields(): Map<string, string> {
    if (this.map) return this.map;
    const m = new Map<string, string>();
    let data: string[] | null = null;
    for (const [k, v] of this.ev.pairs) {
      const n = normKey(k);
      if (!m.has(n)) m.set(n, v);
      if (n.startsWith("data") && /^data\d+$/.test(n)) (data ??= []).push(v);
    }
    // Unnamed <Data> elements (classic PowerShell 400/600/800, many legacy
    // providers) are exposed as Data1..N; Sigma calls the whole blob `Data`.
    if (data && !m.has("data")) m.set("data", data.join("\n"));
    this.map = m;
    return m;
  }

  /** Raw value of a normalized field name (no profile renaming). */
  raw(name: string): string | undefined {
    const ev = this.ev;
    switch (name) {
      case "eventid":
        return ev.eventId == null ? undefined : String(ev.eventId);
      case "channel":
        return ev.channel ?? undefined;
      case "provider_name":
        return ev.provider ?? undefined;
      case "eventrecordid":
        return String(ev.recordId);
    }
    const f = this.fields();
    const v = f.get(name);
    if (v !== undefined) return v;
    switch (name) {
      case "computer":
      case "computername":
        return ev.computer ?? undefined;
      case "level":
        return ev.level == null ? undefined : String(ev.level);
      case "md5":
      case "sha1":
      case "sha256":
      case "imphash": {
        // Sysmon packs hashes as "SHA1=…,MD5=…,SHA256=…,IMPHASH=…".
        const h = f.get("hashes");
        if (!h) return undefined;
        const m = new RegExp(`(?:^|,)${name}=([0-9a-f]+)`, "i").exec(h);
        return m ? m[1] : undefined;
      }
    }
    // Classic PowerShell (400/600/800): "HostApplication=…" lines in Data.
    if (canonicalChannel(ev.channel, ev.provider) === "windows powershell") {
      const blob = f.get("data");
      if (blob) {
        for (const line of blob.split(/\r?\n/)) {
          const i = line.indexOf("=");
          if (i > 0 && normField(line.slice(0, i)) === name) return line.slice(i + 1).trim();
        }
      }
    }
    return undefined;
  }

  /** Value under a profile (Security 4688 → Sysmon field names). */
  get(name: string, profile: Profile): string | undefined {
    if (profile === "security4688") {
      switch (name) {
        case "image":
          return this.raw("newprocessname");
        case "parentimage":
          return this.raw("parentprocessname");
        case "processid":
          return hexToDec(this.raw("newprocessid"));
        case "parentprocessid":
          return hexToDec(this.raw("processid"));
        case "logonid":
          return this.raw("subjectlogonid");
        case "integritylevel": {
          const sid = this.raw("mandatorylabel");
          return sid ? (INTEGRITY_BY_SID[sid.toLowerCase()] ?? sid) : undefined;
        }
        case "user": {
          const tu = this.raw("targetusername");
          const useTarget = tu && tu !== "-";
          const u = useTarget ? tu : this.raw("subjectusername");
          const d = useTarget ? this.raw("targetdomainname") : this.raw("subjectdomainname");
          if (!u) return undefined;
          return d && d !== "-" ? `${d}\\${u}` : u;
        }
      }
    }
    return this.raw(name);
  }

  getLower(name: string, profile: Profile): string | undefined {
    const cache = profile ? (this.lower4688 ??= new Map()) : this.lower;
    const hit = cache.get(name);
    if (hit !== undefined || cache.has(name)) return hit;
    const v = this.get(name, profile)?.toLowerCase();
    cache.set(name, v);
    return v;
  }

  /** Lower-cased full text of the event, for keyword selections. */
  haystack(): string {
    if (this.hay != null) return this.hay;
    const parts: string[] = [];
    for (const [, v] of this.ev.pairs) if (v) parts.push(v);
    if (this.ev.provider) parts.push(this.ev.provider);
    if (this.ev.channel) parts.push(this.ev.channel);
    this.hay = parts.join("\n").toLowerCase();
    return this.hay;
  }
}

type Test = (view: EventView, profile: Profile) => boolean;

// ---------------------------------------------------------------------------
// Values, wildcards, modifiers
// ---------------------------------------------------------------------------

const ANY = 0; // `*`
const ONE = 1; // `?`
type Tok = string | typeof ANY | typeof ONE;

/** Split a Sigma string into literal chunks and wildcards (pySigma escaping). */
export function parseWildcards(s: string): Tok[] {
  const out: Tok[] = [];
  let lit = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\") {
      const n = s[i + 1];
      if (n === "*" || n === "?" || n === "\\") {
        lit += n;
        i++;
      } else lit += c;
    } else if (c === "*" || c === "?") {
      if (lit) out.push(lit);
      lit = "";
      if (c === "*" && out[out.length - 1] === ANY) continue;
      out.push(c === "*" ? ANY : ONE);
    } else lit += c;
  }
  if (lit) out.push(lit);
  return out;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Compile wildcard tokens into a string predicate. `cased` = exact case;
 * otherwise the predicate expects an already lower-cased value.
 */
function tokensTest(tokens: Tok[], cased: boolean): (v: string) => boolean {
  const toks = cased ? tokens : tokens.map((t) => (typeof t === "string" ? t.toLowerCase() : t));
  if (toks.length === 0) return (v) => v === "";
  if (toks.length === 1 && toks[0] === ANY) return () => true;
  const lits = toks.filter((t) => typeof t === "string") as string[];
  const hasOne = toks.includes(ONE);
  if (!hasOne) {
    const n = toks.length;
    if (n === 1) {
      const s = toks[0] as string;
      return (v) => v === s;
    }
    if (n === 2 && toks[0] === ANY) {
      const s = toks[1] as string;
      return (v) => v.endsWith(s);
    }
    if (n === 2 && toks[1] === ANY) {
      const s = toks[0] as string;
      return (v) => v.startsWith(s);
    }
    if (n === 3 && toks[0] === ANY && toks[2] === ANY) {
      const s = toks[1] as string;
      return (v) => v.includes(s);
    }
  }
  const src = toks
    .map((t) => (t === ANY ? ".*" : t === ONE ? "." : escapeRe(t)))
    .join("");
  const re = new RegExp(`^${src}$`, "s");
  // Cheap pre-filter: every literal chunk must be present.
  return (v) => {
    for (const l of lits) if (!v.includes(l)) return false;
    return re.test(v);
  };
}

// --- Encoding modifiers -----------------------------------------------------

export function utf8Bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
function utf16(s: string, be: boolean, bom: boolean): Uint8Array {
  const out = new Uint8Array(s.length * 2 + (bom ? 2 : 0));
  let o = 0;
  if (bom) {
    out[o++] = be ? 0xfe : 0xff;
    out[o++] = be ? 0xff : 0xfe;
  }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out[o++] = be ? c >> 8 : c & 0xff;
    out[o++] = be ? c & 0xff : c >> 8;
  }
  return out;
}
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
export function base64(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64[n >> 18] + B64[(n >> 12) & 63] + "==";
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + "=";
  }
  return out;
}

/** The three shifted encodings of `base64offset` (as pySigma computes them). */
export function base64Offsets(bytes: Uint8Array): string[] {
  const starts = [0, 2, 3];
  const ends = [0, -3, -2]; // 0 = no trim
  const out: string[] = [];
  for (let i = 0; i < 3; i++) {
    const shifted = new Uint8Array(i + bytes.length);
    shifted.fill(0x20, 0, i);
    shifted.set(bytes, i);
    const b = base64(shifted);
    const e = ends[(bytes.length + i) % 3];
    out.push(b.slice(starts[i], e === 0 ? undefined : e));
  }
  return out;
}

const DASHES = ["-", "/", "–", "—", "―"];
/** `windash`: every combination of dash-like characters for option flags. */
export function windashVariants(s: string): string[] {
  const idx: number[] = [];
  const re = /\B[-/]\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) idx.push(m.index);
  if (idx.length === 0) return [s];
  if (idx.length > 4) {
    // Cap the permutation blow-up: same dash everywhere.
    return DASHES.map((d) => {
      const a = s.split("");
      for (const i of idx) a[i] = d;
      return a.join("");
    });
  }
  let out = [s];
  for (const i of idx) {
    const next: string[] = [];
    for (const v of out)
      for (const d of DASHES) next.push(v.slice(0, i) + d + v.slice(i + 1));
    out = next;
  }
  return [...new Set(out)];
}

// --- CIDR -------------------------------------------------------------------

function parseIPv4(s: string): number[] | null {
  const p = s.split(".");
  if (p.length !== 4) return null;
  const out: number[] = [];
  for (const x of p) {
    if (!/^\d{1,3}$/.test(x)) return null;
    const n = Number(x);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

/** Parse an IPv4 or IPv6 address into bytes (4 or 16). */
export function parseIp(input: string): Uint8Array | null {
  let s = input.trim();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const pct = s.indexOf("%");
  if (pct >= 0) s = s.slice(0, pct);
  if (!s.includes(":")) {
    const v4 = parseIPv4(s);
    return v4 ? Uint8Array.from(v4) : null;
  }
  // IPv6 (with optional trailing dotted IPv4).
  let tail: number[] = [];
  const lastColon = s.lastIndexOf(":");
  if (s.slice(lastColon + 1).includes(".")) {
    const v4 = parseIPv4(s.slice(lastColon + 1));
    if (!v4) return null;
    tail = v4;
    s = s.slice(0, lastColon + 1) + "0:0";
  }
  const dbl = s.split("::");
  if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(":") : [];
  const back = dbl.length === 2 && dbl[1] ? dbl[1].split(":") : [];
  const fill = dbl.length === 2 ? 8 - head.length - back.length : 0;
  if (fill < 0 || (dbl.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill("0"), ...back];
  if (groups.length !== 8) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/i.test(groups[i])) return null;
    const n = parseInt(groups[i], 16);
    out[i * 2] = n >> 8;
    out[i * 2 + 1] = n & 0xff;
  }
  if (tail.length) out.set(tail, 12);
  return out;
}

function cidrTest(spec: string): (v: string) => boolean {
  const [addr, lenStr] = spec.split("/");
  const net = parseIp(addr);
  if (!net) throw new SigmaCompileError(`invalid CIDR "${spec}"`);
  const bits = lenStr == null ? net.length * 8 : Number(lenStr);
  if (!Number.isInteger(bits) || bits < 0 || bits > net.length * 8)
    throw new SigmaCompileError(`invalid CIDR prefix "${spec}"`);
  return (v) => {
    let ip = parseIp(v);
    if (!ip) return false;
    // IPv4-mapped IPv6 (::ffff:a.b.c.d) against an IPv4 network.
    if (net.length === 4 && ip.length === 16) {
      const mapped = ip.slice(0, 10).every((b) => b === 0) && ip[10] === 0xff && ip[11] === 0xff;
      if (!mapped) return false;
      ip = ip.slice(12);
    }
    if (ip.length !== net.length) return false;
    let rem = bits;
    for (let i = 0; i < net.length && rem > 0; i++) {
      const take = Math.min(8, rem);
      const mask = (0xff << (8 - take)) & 0xff;
      if ((ip[i] & mask) !== (net[i] & mask)) return false;
      rem -= take;
    }
    return true;
  };
}

// --- Numbers ----------------------------------------------------------------

function toNumber(v: string): number {
  const t = v.trim();
  if (/^-?0x[0-9a-f]+$/i.test(t)) return parseInt(t, 16);
  if (t === "") return NaN;
  return Number(t);
}

// --- Regex ------------------------------------------------------------------

/** Translate a PCRE-flavoured Sigma regex to a JS RegExp. */
export function compileRegex(pattern: string, flags: string): RegExp {
  let p = pattern;
  let f = flags;
  // Leading inline flags: (?i), (?s), (?im) … are not valid JS syntax.
  const inline = /^\(\?([imsx]+)\)/.exec(p);
  if (inline) {
    for (const c of inline[1]) if (c !== "x" && !f.includes(c)) f += c;
    p = p.slice(inline[0].length);
  }
  p = p.replace(/\(\?P<([A-Za-z_]\w*)>/g, "(?<$1>");
  try {
    return new RegExp(p, f);
  } catch (err) {
    throw new SigmaCompileError(
      `unsupported regular expression /${pattern}/: ${err instanceof Error ? err.message : err}`,
    );
  }
}

// --- Field test compiler -----------------------------------------------------

const TRANSFORMS = new Set([
  "base64",
  "base64offset",
  "utf16le",
  "utf16be",
  "utf16",
  "wide",
  "windash",
]);
const KNOWN = new Set([
  ...TRANSFORMS,
  "contains",
  "startswith",
  "endswith",
  "all",
  "exists",
  "re",
  "i",
  "m",
  "s",
  "cased",
  "cidr",
  "gt",
  "gte",
  "lt",
  "lte",
  "fieldref",
]);

type Primitive = string | number | boolean | null;

function asList(v: unknown): Primitive[] {
  const list = Array.isArray(v) ? v : [v];
  for (const x of list) {
    if (x !== null && typeof x === "object")
      throw new SigmaCompileError("nested objects are not valid Sigma values");
  }
  return list as Primitive[];
}

/**
 * Compile one `Field|mod|mod: value(s)` entry. `field` null = keyword
 * (full-text) search.
 */
export function compileFieldTest(
  fieldSpec: string | null,
  modifiers: string[],
  rawValue: unknown,
): Test {
  const mods = modifiers.map((m) => m.toLowerCase());
  for (const m of mods) {
    if (m === "expand")
      throw new SigmaCompileError("the `expand` modifier needs placeholder values (unsupported)");
    if (!KNOWN.has(m)) throw new SigmaCompileError(`unknown modifier "${m}"`);
  }
  const has = (m: string) => mods.includes(m);
  const field = fieldSpec == null ? null : normField(fieldSpec);
  const values = asList(rawValue);
  if (values.length === 0) return () => false;
  const useAll = has("all");

  // Value accessor: keyword search reads the whole haystack.
  const lowerOf = field == null
    ? (view: EventView) => view.haystack()
    : (view: EventView, p: Profile) => view.getLower(field, p);
  const rawOf = field == null
    ? (view: EventView) => view.haystack()
    : (view: EventView, p: Profile) => view.get(field, p);

  if (has("exists")) {
    if (field == null) throw new SigmaCompileError("`exists` needs a field");
    const want = values[0] === true || String(values[0]).toLowerCase() === "true";
    return (view, p) => (view.get(field, p) !== undefined) === want;
  }

  const numericOp = mods.find((m) => m === "gt" || m === "gte" || m === "lt" || m === "lte");

  // Fast path for the common shape — an OR-list of plain literals under
  // (no modifier | contains | startswith | endswith) — which dominates the
  // SigmaHQ set (`Image|endswith: [...]`). Literals become Set lookups by
  // length instead of one closure per value.
  let rest = values;
  let fast: Test | null = null;
  const plain = !useAll && !numericOp && field != null &&
    mods.every((m) => m === "contains" || m === "startswith" || m === "endswith");
  if (plain) {
    const lits: string[] = [];
    rest = [];
    for (const v of values) {
      const toks = typeof v === "string" ? parseWildcards(v) : null;
      if (toks && toks.length === 1 && typeof toks[0] === "string") lits.push(toks[0].toLowerCase());
      else if (typeof v === "string" && toks && toks.length === 0 && !has("contains") && !has("startswith") && !has("endswith")) lits.push("");
      else rest.push(v);
    }
    if (lits.length >= 2) fast = literalListTest(field, lits, has("contains") ? "c" : has("startswith") ? "s" : has("endswith") ? "e" : "=");
    else rest = values;
  }

  const perValue: Test[] = rest.map((val): Test => {
    if (val === null) {
      if (field == null) throw new SigmaCompileError("null is not a valid keyword");
      return (view, p) => {
        const v = view.get(field, p);
        return v === undefined || v === "";
      };
    }
    if (numericOp) {
      const n = typeof val === "number" ? val : toNumber(String(val));
      if (Number.isNaN(n)) throw new SigmaCompileError(`"${numericOp}" needs a number`);
      const cmp =
        numericOp === "gt" ? (x: number) => x > n
        : numericOp === "gte" ? (x: number) => x >= n
        : numericOp === "lt" ? (x: number) => x < n
        : (x: number) => x <= n;
      return (view, p) => {
        const v = rawOf(view, p);
        if (v === undefined) return false;
        const x = toNumber(v);
        return !Number.isNaN(x) && cmp(x);
      };
    }
    if (has("cidr")) {
      const t = cidrTest(String(val));
      return (view, p) => {
        const v = rawOf(view, p);
        return v !== undefined && t(v);
      };
    }
    if (has("re")) {
      const flags = (has("i") ? "i" : "") + (has("m") ? "m" : "") + (has("s") ? "s" : "");
      const re = compileRegex(String(val), flags);
      return (view, p) => {
        const v = rawOf(view, p);
        return v !== undefined && re.test(v);
      };
    }
    if (has("fieldref")) {
      if (field == null) throw new SigmaCompileError("`fieldref` needs a field");
      const other = normField(String(val));
      const mode = has("contains") ? "c" : has("startswith") ? "s" : has("endswith") ? "e" : "=";
      return (view, p) => {
        const a = view.getLower(field, p);
        const b = view.getLower(other, p);
        if (a === undefined || b === undefined) return false;
        return mode === "=" ? a === b : mode === "c" ? a.includes(b) : mode === "s" ? a.startsWith(b) : a.endsWith(b);
      };
    }

    // String matching with optional encoding transforms.
    let variants: string[];
    let wildcards = true;
    if (typeof val === "boolean") variants = [String(val)];
    else if (typeof val === "number") variants = [String(val)];
    else variants = [val];

    if (has("windash")) variants = variants.flatMap(windashVariants);
    const enc16 = has("utf16le") || has("wide") ? "le" : has("utf16be") ? "be" : has("utf16") ? "bom" : null;
    if (has("base64") || has("base64offset")) {
      wildcards = false;
      variants = variants.flatMap((s) => {
        const bytes = enc16 === "le" ? utf16(s, false, false)
          : enc16 === "be" ? utf16(s, true, false)
          : enc16 === "bom" ? utf16(s, false, true)
          : utf8Bytes(s);
        return has("base64offset") ? base64Offsets(bytes) : [base64(bytes)];
      });
    } else if (enc16) {
      throw new SigmaCompileError("utf16 modifiers are only meaningful with base64");
    }

    const cased = has("cased");
    const contains = has("contains") || field == null; // keywords = substring
    const starts = has("startswith");
    const ends = has("endswith");
    const tests = variants.map((s) => {
      let toks: Tok[] = wildcards
        ? parseWildcards(s)
        : [s];
      if ((contains || ends) && toks[0] !== ANY) toks = [ANY, ...toks];
      if ((contains || starts) && toks[toks.length - 1] !== ANY) toks = [...toks, ANY];
      return tokensTest(toks, cased);
    });
    const isNum = typeof val === "number";
    const n = isNum ? (val as number) : NaN;
    const read = cased ? rawOf : lowerOf;
    return (view, p) => {
      const v = read(view, p);
      if (v === undefined) return false;
      for (const t of tests) if (t(v)) return true;
      // 0x-hex or padded numbers in EventData vs a numeric rule value.
      if (isNum && !contains && !starts && !ends) return toNumber(v) === n;
      return false;
    };
  });

  if (fast) {
    if (perValue.length === 0) return fast;
    perValue.unshift(fast);
  }
  if (perValue.length === 1) return perValue[0];
  if (useAll) return (view, p) => perValue.every((t) => t(view, p));
  return (view, p) => {
    for (const t of perValue) if (t(view, p)) return true;
    return false;
  };
}

/** OR over plain lower-cased literals: Set lookups keyed by length. */
function literalListTest(field: string, lits: string[], mode: "=" | "s" | "e" | "c"): Test {
  if (mode === "=") {
    const set = new Set(lits);
    return (view, p) => {
      const v = view.getLower(field, p);
      return v !== undefined && set.has(v);
    };
  }
  if (mode === "c") {
    const arr = [...new Set(lits)];
    return (view, p) => {
      const v = view.getLower(field, p);
      if (v === undefined) return false;
      for (const l of arr) if (v.includes(l)) return true;
      return false;
    };
  }
  const byLen = new Map<number, Set<string>>();
  for (const l of lits) {
    const s = byLen.get(l.length);
    if (s) s.add(l);
    else byLen.set(l.length, new Set([l]));
  }
  const groups = [...byLen].sort((a, b) => a[0] - b[0]);
  const suffix = mode === "e";
  return (view, p) => {
    const v = view.getLower(field, p);
    if (v === undefined) return false;
    const n = v.length;
    for (const [len, set] of groups) {
      if (len > n) break;
      if (set.has(suffix ? v.slice(n - len) : v.slice(0, len))) return true;
    }
    return false;
  };
}

// ---------------------------------------------------------------------------
// Selections
// ---------------------------------------------------------------------------

type CompiledSelection = {
  test: Test;
  /** EventIDs this selection requires (null = unconstrained). */
  eventIds: Set<number> | null;
  fields: string[];
  /** Necessary literal atoms (one must hold if the selection matches). */
  gate: Atom[] | null;
};

// --- Gates (see gate.ts) ------------------------------------------------------

function longestChunk(toks: Tok[]): string {
  let best = "";
  for (const t of toks) if (typeof t === "string" && t.length > best.length) best = t;
  return best.toLowerCase();
}

/** Atom a single value implies, or null when none can be derived. */
function valueAtom(field: string | null, kind: Atom["kind"], val: Primitive): Atom | null {
  if (val === null || typeof val === "number") return null;
  const toks = parseWildcards(String(val));
  const exact = toks.length === 1 && typeof toks[0] === "string";
  if (exact && kind === "=") return { field, kind, lit: (toks[0] as string).toLowerCase() };
  if (toks.length === 0) return kind === "=" ? { field, kind, lit: "" } : null;
  if (exact) return { field, kind, lit: (toks[0] as string).toLowerCase() };
  const chunk = longestChunk(toks);
  return chunk.length >= 2 ? { field, kind: "c", lit: chunk } : null;
}

/** Necessary atoms of one `Field|mods: values` entry (null = no gate). */
function fieldGate(fieldSpec: string | null, mods: string[], rawValue: unknown): Atom[] | null {
  const m = mods.map((x) => x.toLowerCase());
  if (m.some((x) => x !== "contains" && x !== "startswith" && x !== "endswith" && x !== "all")) return null;
  const field = fieldSpec == null ? null : normField(fieldSpec);
  const kind: Atom["kind"] =
    field == null || m.includes("contains") ? "c" : m.includes("startswith") ? "s" : m.includes("endswith") ? "e" : "=";
  let values: Primitive[];
  try {
    values = asList(rawValue);
  } catch {
    return null;
  }
  if (values.length === 0) return null;
  const atoms = values.map((v) => valueAtom(field, kind, v));
  if (m.includes("all")) {
    // Every value must hold: the longest one alone is a valid gate.
    let best: Atom | null = null;
    for (const a of atoms) if (a && (!best || a.lit.length > best.lit.length)) best = a;
    return best ? [best] : null;
  }
  if (atoms.some((a) => a === null || (a.kind !== "=" && a.lit.length === 0))) return null;
  return atoms as Atom[];
}

const KIND_COST = { "=": 0, s: 1, e: 1, c: 2 } as const;
function gateCost(g: Atom[]): number {
  let kind = 0;
  let shortest = Infinity;
  for (const a of g) {
    kind = Math.max(kind, KIND_COST[a.kind]);
    shortest = Math.min(shortest, a.lit.length);
  }
  return kind * 1000 + (shortest < 3 ? 500 : 0) + g.length;
}
/** AND: any child's gate is necessary — keep the most selective one. */
function bestGate(gates: (Atom[] | null)[]): Atom[] | null {
  let best: Atom[] | null = null;
  for (const g of gates) if (g && (!best || gateCost(g) < gateCost(best))) best = g;
  return best;
}
/** OR: every branch must be gated; the union is necessary. */
function unionGate(gates: (Atom[] | null)[]): Atom[] | null {
  if (gates.some((g) => !g)) return null;
  return (gates as Atom[][]).flat();
}

function splitKey(key: string): { field: string | null; mods: string[] } {
  const parts = key.split("|");
  const field = parts[0] === "" ? null : parts[0];
  return { field, mods: parts.slice(1).filter((m) => m !== "") };
}

function eventIdsOf(value: unknown, mods: string[]): Set<number> | null {
  if (mods.length) return null;
  const list = Array.isArray(value) ? value : [value];
  const out = new Set<number>();
  for (const v of list) {
    const n = typeof v === "number" ? v : typeof v === "string" && /^\d+$/.test(v) ? Number(v) : NaN;
    if (!Number.isInteger(n)) return null;
    out.add(n);
  }
  return out.size ? out : null;
}

function compileMap(map: Record<string, unknown>): CompiledSelection {
  const tests: Test[] = [];
  let eventIds: Set<number> | null = null;
  const fields: string[] = [];
  const gates: (Atom[] | null)[] = [];
  // EventID / Channel first: cheapest and most selective.
  const entries = Object.entries(map).sort(([a], [b]) => rank(a) - rank(b));
  for (const [key, value] of entries) {
    const { field, mods } = splitKey(key);
    tests.push(compileFieldTest(field, mods, value));
    gates.push(fieldGate(field, mods, value));
    if (field && field.toLowerCase() === "eventid") eventIds = eventIdsOf(value, mods);
    if (field && !/^(eventid|channel|provider_name)$/i.test(field)) fields.push(field);
  }
  if (tests.length === 0) throw new SigmaCompileError("empty selection");
  const test: Test =
    tests.length === 1
      ? tests[0]
      : (view, p) => {
          for (const t of tests) if (!t(view, p)) return false;
          return true;
        };
  return { test, eventIds, fields, gate: bestGate(gates) };
}
function rank(key: string): number {
  const f = key.split("|")[0].toLowerCase();
  return f === "eventid" ? 0 : f === "channel" || f === "provider_name" ? 1 : 2;
}

export function compileSelection(def: unknown): CompiledSelection {
  if (def === null || def === undefined) throw new SigmaCompileError("empty selection");
  if (Array.isArray(def)) {
    if (def.length === 0) throw new SigmaCompileError("empty selection");
    const allPrimitive = def.every((x) => x === null || typeof x !== "object");
    if (allPrimitive) {
      // Keyword list: any keyword anywhere in the event.
      return {
        test: compileFieldTest(null, [], def),
        eventIds: null,
        fields: [],
        gate: fieldGate(null, [], def),
      };
    }
    const parts = def.map((x) =>
      x !== null && typeof x === "object" && !Array.isArray(x)
        ? compileMap(x as Record<string, unknown>)
        : compileSelection(x),
    );
    const ids = parts.every((p) => p.eventIds)
      ? new Set(parts.flatMap((p) => [...(p.eventIds as Set<number>)]))
      : null;
    return {
      test: (view, p) => {
        for (const s of parts) if (s.test(view, p)) return true;
        return false;
      },
      eventIds: ids,
      fields: [...new Set(parts.flatMap((p) => p.fields))],
      gate: unionGate(parts.map((p) => p.gate)),
    };
  }
  if (typeof def === "object") return compileMap(def as Record<string, unknown>);
  // A single keyword.
  return { test: compileFieldTest(null, [], def), eventIds: null, fields: [], gate: fieldGate(null, [], def) };
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

export type CondNode =
  | { t: "and"; items: CondNode[] }
  | { t: "or"; items: CondNode[] }
  | { t: "not"; item: CondNode }
  | { t: "sel"; name: string }
  | { t: "of"; count: number | "all"; pattern: string };

const TOKEN_RE = /\s*(\(|\)|[^\s()]+)/y;

export function parseCondition(src: string): CondNode {
  if (/\|/.test(src))
    throw new SigmaCompileError("aggregation conditions (`| count() …`) are not supported");
  const toks: string[] = [];
  let pos = 0;
  for (;;) {
    TOKEN_RE.lastIndex = pos;
    const m = TOKEN_RE.exec(src);
    if (!m) break;
    toks.push(m[1]);
    pos = TOKEN_RE.lastIndex;
  }
  if (src.slice(pos).trim()) throw new SigmaCompileError(`cannot parse condition "${src}"`);
  let i = 0;
  const peek = () => toks[i]?.toLowerCase();
  const next = () => toks[i++];

  function parseOr(): CondNode {
    const items = [parseAnd()];
    while (peek() === "or") {
      i++;
      items.push(parseAnd());
    }
    return items.length === 1 ? items[0] : { t: "or", items };
  }
  function parseAnd(): CondNode {
    const items = [parseNot()];
    while (peek() === "and") {
      i++;
      items.push(parseNot());
    }
    return items.length === 1 ? items[0] : { t: "and", items };
  }
  function parseNot(): CondNode {
    if (peek() === "not") {
      i++;
      return { t: "not", item: parseNot() };
    }
    return parseAtom();
  }
  function parseAtom(): CondNode {
    const tok = next();
    if (tok === undefined) throw new SigmaCompileError(`unexpected end of condition "${src}"`);
    if (tok === "(") {
      const n = parseOr();
      if (next() !== ")") throw new SigmaCompileError(`missing ")" in condition "${src}"`);
      return n;
    }
    const low = tok.toLowerCase();
    if (low === "near") throw new SigmaCompileError("`near` conditions are not supported");
    if ((/^\d+$/.test(low) || low === "all" || low === "any") && peek() === "of") {
      i++;
      const pattern = next();
      if (!pattern || pattern === "(" || pattern === ")")
        throw new SigmaCompileError(`missing selection after "${tok} of"`);
      return {
        t: "of",
        count: low === "all" ? "all" : low === "any" ? 1 : Number(low),
        pattern,
      };
    }
    if (low === "and" || low === "or" || low === ")" || low === "of")
      throw new SigmaCompileError(`unexpected "${tok}" in condition "${src}"`);
    return { t: "sel", name: tok };
  }

  const node = parseOr();
  if (i < toks.length) throw new SigmaCompileError(`unexpected "${toks[i]}" in condition "${src}"`);
  return node;
}

function globToRe(p: string): RegExp {
  return new RegExp(`^${p.split("*").map(escapeRe).join(".*")}$`);
}

type Compiled = { test: Test; eventIds: Set<number> | null; gate: Atom[] | null };

function intersect(sets: Set<number>[]): Set<number> {
  const [first, ...rest] = sets;
  return new Set([...first].filter((x) => rest.every((s) => s.has(x))));
}

function compileNode(node: CondNode, sels: Map<string, CompiledSelection>): Compiled {
  switch (node.t) {
    case "sel": {
      const s = sels.get(node.name);
      if (!s) throw new SigmaCompileError(`condition references unknown selection "${node.name}"`);
      return { test: s.test, eventIds: s.eventIds, gate: s.gate };
    }
    case "not": {
      const inner = compileNode(node.item, sels);
      return { test: (v, p) => !inner.test(v, p), eventIds: null, gate: null };
    }
    case "and": {
      const parts = node.items.map((n) => compileNode(n, sels));
      const known = parts.map((x) => x.eventIds).filter((x): x is Set<number> => !!x);
      return {
        test: (v, p) => {
          for (const x of parts) if (!x.test(v, p)) return false;
          return true;
        },
        eventIds: known.length ? intersect(known) : null,
        gate: bestGate(parts.map((x) => x.gate)),
      };
    }
    case "or": {
      const parts = node.items.map((n) => compileNode(n, sels));
      return {
        test: (v, p) => {
          for (const x of parts) if (x.test(v, p)) return true;
          return false;
        },
        eventIds: parts.every((x) => x.eventIds)
          ? new Set(parts.flatMap((x) => [...(x.eventIds as Set<number>)]))
          : null,
        gate: unionGate(parts.map((x) => x.gate)),
      };
    }
    case "of": {
      const names =
        node.pattern.toLowerCase() === "them"
          ? [...sels.keys()].filter((k) => !k.startsWith("_"))
          : [...sels.keys()].filter((k) => globToRe(node.pattern).test(k));
      if (names.length === 0)
        throw new SigmaCompileError(`"${node.pattern}" matches no selection`);
      const parts = names.map((n) => sels.get(n) as CompiledSelection);
      if (node.count === "all") {
        const known = parts.map((x) => x.eventIds).filter((x): x is Set<number> => !!x);
        return {
          test: (v, p) => {
            for (const x of parts) if (!x.test(v, p)) return false;
            return true;
          },
          eventIds: known.length ? intersect(known) : null,
          gate: bestGate(parts.map((x) => x.gate)),
        };
      }
      const need = node.count;
      return {
        test: (v, p) => {
          let hits = 0;
          for (const x of parts) if (x.test(v, p) && ++hits >= need) return true;
          return false;
        },
        eventIds:
          need === 1 && parts.every((x) => x.eventIds)
            ? new Set(parts.flatMap((x) => [...(x.eventIds as Set<number>)]))
            : null,
        // At least one selection must match: the union is necessary.
        gate: unionGate(parts.map((x) => x.gate)),
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

export type CompiledRule = {
  index: number;
  rule: SigmaRule;
  targets: LogTarget[];
  /** Event IDs required by the detection (null = any). */
  eventIds: Set<number> | null;
  /** Field names the detection tests (original spelling). */
  fields: string[];
  /** Pre-filter atoms (null = always evaluated). */
  gate: Atom[] | null;
  test: Test;
};

export function normalizeLevel(level: unknown): SigmaLevel {
  const l = String(level ?? "").toLowerCase().trim();
  return (SIGMA_LEVELS as readonly string[]).includes(l) ? (l as SigmaLevel) : "informational";
}

/** Compile a rule or throw SigmaCompileError with the reason. */
export function compileRule(rule: SigmaRule, index = 0): CompiledRule {
  const ls = resolveLogsource(rule.logsource);
  if ("unsupported" in ls) throw new SigmaCompileError(ls.unsupported);
  const det = rule.detection;
  if (!det || typeof det !== "object") throw new SigmaCompileError("missing detection");
  const cond = det.condition;
  if (cond == null) throw new SigmaCompileError("missing detection.condition");
  const sels = new Map<string, CompiledSelection>();
  for (const [name, def] of Object.entries(det)) {
    if (name === "condition" || name === "timeframe") continue;
    try {
      sels.set(name, compileSelection(def));
    } catch (err) {
      if (err instanceof SigmaCompileError)
        throw new SigmaCompileError(`${name}: ${err.message}`);
      throw err;
    }
  }
  const conds = (Array.isArray(cond) ? cond : [cond]).map(String);
  const compiled = conds.map((c) => compileNode(parseCondition(c), sels));
  const test: Test =
    compiled.length === 1
      ? compiled[0].test
      : (v, p) => compiled.some((c) => c.test(v, p));
  const eventIds = compiled.every((c) => c.eventIds)
    ? new Set(compiled.flatMap((c) => [...(c.eventIds as Set<number>)]))
    : null;
  const fields = [...new Set([...sels.values()].flatMap((s) => s.fields))];
  const gate = unionGate(compiled.map((c) => c.gate));
  return { index, rule, targets: ls.targets, eventIds, fields, gate, test };
}

// ---------------------------------------------------------------------------
// Index + evaluation
// ---------------------------------------------------------------------------

type Candidate = { rule: CompiledRule; profile: Profile };
type Bucket = { cands: Candidate[]; gate: GateIndex<Profile> };

/**
 * Rules bucketed by (channel, Event ID): each distinct pair seen in the data
 * resolves its candidate list — and the gate index over it — once, so a
 * record only runs the full detection of rules whose literal gate fired.
 */
export class SigmaIndex {
  private cache = new Map<string, Bucket>();
  constructor(
    readonly rules: CompiledRule[],
    /** Disable pre-filtering (tests compare both paths). */
    private readonly useGates = true,
  ) {}

  candidates(channel: string, eventId: number | null): Candidate[] {
    return this.bucket(channel, eventId).cands;
  }

  private bucket(channel: string, eventId: number | null): Bucket {
    const key = `${channel}\u0000${eventId ?? ""}`;
    const hit = this.cache.get(key);
    if (hit) return hit;
    const cands: Candidate[] = [];
    for (const r of this.rules) {
      if (r.eventIds && (eventId == null || !r.eventIds.has(eventId))) continue;
      for (const t of r.targets) {
        if (t.channel !== null && t.channel !== channel) continue;
        if (t.eventIds && (eventId == null || !t.eventIds.includes(eventId))) continue;
        cands.push({ rule: r, profile: t.profile });
        break;
      }
    }
    const gate = new GateIndex<Profile>(
      cands.map((c) => (this.useGates ? c.rule.gate : null)),
      cands.map((c) => c.profile),
    );
    const b = { cands, gate };
    this.cache.set(key, b);
    return b;
  }

  /** Calls `onMatch` with the index of every rule matching the event. */
  evaluate(ev: SigmaEvent, onMatch: (ruleIndex: number) => void): void {
    const b = this.bucket(canonicalChannel(ev.channel, ev.provider), ev.eventId);
    if (b.cands.length === 0) return;
    const view = new EventView(ev);
    const picked = b.gate.select((field, profile) =>
      field === null ? view.haystack() : view.getLower(field, profile),
    );
    for (const i of picked) {
      const c = b.cands[i];
      if (c.rule.test(view, c.profile)) onMatch(c.rule.index);
    }
  }
}

/** Compile many rules; failures are returned with their reason. */
export function compileRules(rules: SigmaRule[]): {
  compiled: CompiledRule[];
  failed: { rule: SigmaRule; reason: string }[];
} {
  const compiled: CompiledRule[] = [];
  const failed: { rule: SigmaRule; reason: string }[] = [];
  for (const rule of rules) {
    try {
      compiled.push(compileRule(rule, compiled.length));
    } catch (err) {
      failed.push({ rule, reason: err instanceof Error ? err.message : String(err) });
    }
  }
  return { compiled, failed };
}
