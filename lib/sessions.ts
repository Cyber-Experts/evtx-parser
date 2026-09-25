// Logon session reconstruction: group every event by (computer, LogonId) and
// read the session's story from it — who logged on (4624), how and from
// where, whether it got admin rights (4672), what it did (events carrying the
// same LogonId as Subject) and when it ended (4634 / 4647).

import { decodeValue } from "@/lib/event-decode";

export type SessionRow = {
  event_id: number | null;
  timestamp: string;
  computer: string | null;
  _g: number;
};

export type LogonSession = {
  /** `${computer}|${logonId}` — LogonIds are only unique per host boot. */
  key: string;
  logonId: string;
  /** All LogonIds of the logical session (both halves of a UAC split). */
  logonIds: string[];
  computer: string;
  user: string;
  logonType: string | null;
  logonTypeLabel: string | null;
  sourceIp: string | null;
  workstation: string | null;
  authPackage: string | null;
  /** UAC split token: the other half of an admin logon. */
  linkedLogonId: string | null;
  elevated: boolean | null;
  /** A 4672 (special privileges) was issued for this session. */
  admin: boolean;
  /** 4624 time, or null when the logon predates the log. */
  start: string | null;
  firstSeen: string;
  lastSeen: string;
  end: string | null;
  endEventId: number | null;
  events: number;
  /** Event IDs in this session, most frequent first. */
  eventIds: [number, number][];
  /** Background session: SYSTEM, services, machine accounts, DWM/UMFD. */
  system: boolean;
};

// Well-known LogonIds: SYSTEM, LOCAL SERVICE, NETWORK SERVICE, and "none".
const SYSTEM_LOGON_IDS = new Set(["0x3e7", "0x3e5", "0x3e4"]);
const SYSTEM_USERS = new Set([
  "system",
  "local service",
  "network service",
  "anonymous logon",
]);
const LOGON_KEYS = new Set(["targetlogonid", "subjectlogonid", "logonid"]);

const norm = (v: string) => v.trim().toLowerCase();
const blank = (v: string | undefined) => !v || v === "-" || v === "";

type Draft = LogonSession & { idCounts: Map<number, number>; subjectUser: string };

function account(get: (k: string) => string | undefined, prefix: string) {
  const user = get(`${prefix.toLowerCase()}username`);
  const dom = get(`${prefix.toLowerCase()}domainname`);
  if (blank(user)) return "";
  return blank(dom) ? user! : `${dom}\\${user}`;
}

function isSystem(s: Draft): boolean {
  if (SYSTEM_LOGON_IDS.has(s.logonId)) return true;
  if (s.logonType === "0" || s.logonType === "5") return true;
  const name = (s.user || s.subjectUser).split("\\").pop()!.toLowerCase();
  if (!name) return true;
  if (SYSTEM_USERS.has(name)) return true;
  if (name.endsWith("$")) return true;
  return /^(dwm|umfd)-\d+$/.test(name);
}

export function buildSessions<R extends SessionRow>(
  rows: R[],
  pairsByG: [string, string][][],
): LogonSession[] {
  const sessions = new Map<string, Draft>();

  const touch = (r: R, logonId: string): Draft => {
    const computer = r.computer ?? "";
    const key = `${computer}|${logonId}`;
    let s = sessions.get(key);
    if (!s) {
      s = {
        key,
        logonId,
        logonIds: [logonId],
        computer,
        user: "",
        subjectUser: "",
        logonType: null,
        logonTypeLabel: null,
        sourceIp: null,
        workstation: null,
        authPackage: null,
        linkedLogonId: null,
        elevated: null,
        admin: false,
        start: null,
        firstSeen: r.timestamp,
        lastSeen: r.timestamp,
        end: null,
        endEventId: null,
        events: 0,
        eventIds: [],
        system: false,
        idCounts: new Map(),
      };
      sessions.set(key, s);
    }
    s.events++;
    if (r.timestamp < s.firstSeen) s.firstSeen = r.timestamp;
    if (r.timestamp > s.lastSeen) s.lastSeen = r.timestamp;
    if (r.event_id != null) {
      s.idCounts.set(r.event_id, (s.idCounts.get(r.event_id) ?? 0) + 1);
    }
    return s;
  };

  for (const r of rows) {
    const pairs = pairsByG[r._g] ?? [];
    if (pairs.length === 0) continue;
    const map = new Map<string, string>();
    for (const [k, v] of pairs) map.set(k.toLowerCase(), v);
    const get = (k: string) => map.get(k);

    // Each distinct LogonId on the event counts once for that session.
    const ids = new Set<string>();
    for (const [k, v] of map) {
      if (LOGON_KEYS.has(k) && !blank(v) && norm(v) !== "0x0") ids.add(norm(v));
    }
    const target = get("targetlogonid");
    const subject = get("subjectlogonid");

    for (const id of ids) {
      const s = touch(r, id);
      if (!s.subjectUser && subject && norm(subject) === id) {
        s.subjectUser = account(get, "Subject");
      }
    }

    const tId = target && !blank(target) ? norm(target) : null;
    const sId = subject && !blank(subject) ? norm(subject) : null;
    const byId = (id: string) => sessions.get(`${r.computer ?? ""}|${id}`);

    if (r.event_id === 4624 && tId) {
      const s = byId(tId);
      if (s && !s.start) {
        s.start = r.timestamp;
        s.user = account(get, "Target");
        const lt = get("logontype") ?? null;
        s.logonType = lt;
        s.logonTypeLabel = lt ? decodeValue("LogonType", lt) : null;
        const ip = get("ipaddress");
        s.sourceIp = blank(ip) ? null : ip!;
        const ws = get("workstationname");
        s.workstation = blank(ws) ? null : ws!;
        const auth = get("authenticationpackagename");
        s.authPackage = blank(auth) ? null : auth!;
        const linked = get("targetlinkedlogonid");
        s.linkedLogonId =
          blank(linked) || norm(linked!) === "0x0" ? null : norm(linked!);
        const elev = get("elevatedtoken");
        s.elevated =
          elev === "%%1842" ? true : elev === "%%1843" ? false : null;
      }
    } else if (r.event_id === 4672 && sId) {
      const s = byId(sId);
      if (s) s.admin = true;
    } else if ((r.event_id === 4634 || r.event_id === 4647) && tId) {
      const s = byId(tId);
      if (s && (!s.end || r.timestamp > s.end)) {
        s.end = r.timestamp;
        s.endEventId = r.event_id;
      }
    }
  }

  mergeLinked(sessions);

  const out: LogonSession[] = [];
  for (const d of sessions.values()) {
    if (!d.user) d.user = d.subjectUser;
    d.system = isSystem(d);
    d.eventIds = [...d.idCounts.entries()].sort((a, b) => b[1] - a[1]);
    const { idCounts: _ids, subjectUser: _su, ...session } = d;
    void _ids;
    void _su;
    out.push(session);
  }
  return out.sort((a, b) =>
    (a.start ?? a.firstSeen).localeCompare(b.start ?? b.firstSeen),
  );
}

/**
 * An admin logon under UAC creates two linked sessions (elevated + limited
 * token) that point at each other via TargetLinkedLogonId. Fold each pair
 * into one logical session, keeping the elevated half as the primary.
 */
function mergeLinked(sessions: Map<string, Draft>) {
  for (const s of [...sessions.values()]) {
    if (!s.linkedLogonId || !sessions.has(s.key)) continue;
    const partnerKey = `${s.computer}|${s.linkedLogonId}`;
    const p = sessions.get(partnerKey);
    if (!p || p.linkedLogonId !== s.logonId) continue;
    const [keep, drop] = s.elevated === false && p.elevated !== false ? [p, s] : [s, p];
    keep.logonIds = [keep.logonId, drop.logonId];
    keep.admin ||= drop.admin;
    keep.events += drop.events;
    for (const [id, n] of drop.idCounts) {
      keep.idCounts.set(id, (keep.idCounts.get(id) ?? 0) + n);
    }
    if (drop.firstSeen < keep.firstSeen) keep.firstSeen = drop.firstSeen;
    if (drop.lastSeen > keep.lastSeen) keep.lastSeen = drop.lastSeen;
    if (drop.start && (!keep.start || drop.start < keep.start)) keep.start = drop.start;
    if (drop.end && (!keep.end || drop.end > keep.end)) {
      keep.end = drop.end;
      keep.endEventId = drop.endEventId;
    }
    sessions.delete(drop.key);
  }
}

/** Search query selecting every event of a session. */
export function sessionQuery(s: LogonSession): string {
  const ids = s.logonIds.map((id) => `logonid:${id}`).join(" OR ");
  return ids;
}

/** Session length in ms (logon → logoff, else logon → last event). */
export function sessionDurationMs(s: LogonSession): number | null {
  const from = s.start ?? s.firstSeen;
  const to = s.end ?? s.lastSeen;
  const a = Date.parse(from);
  const b = Date.parse(to);
  return Number.isNaN(a) || Number.isNaN(b) ? null : Math.max(0, b - a);
}

/** "3 h 12 min", "4 min 05 s", "12 s". */
export function formatDuration(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ${String(s % 60).padStart(2, "0")} s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ${String(m % 60).padStart(2, "0")} min`;
  return `${Math.floor(h / 24)} d ${h % 24} h`;
}
