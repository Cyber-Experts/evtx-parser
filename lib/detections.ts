// Built-in triage detections — a curated, low-false-positive rule set derived
// from the DFIR event-ID cheat sheet. Runs entirely in the browser over the
// already-parsed rows + EventData; no rule text or data ever leaves the device.
//
// Each rule returns the global row indices (`_g`) it matched, so the UI can
// filter the table to exactly those events. Rule text is English by design —
// the same convention the event-name table (event-info.ts) already follows.

import { providerHint } from "./event-info";

export type Severity = "high" | "medium" | "low";

export type Finding = {
  key: string;
  severity: Severity;
  title: string;
  detail: string;
  gids: number[];
};

// Minimal row shape the engine needs; IndexedRow satisfies it structurally.
export type DetectRow = {
  _g: number;
  event_id: number | null;
  provider: string | null;
};

const SEVERITY_RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2 };

function field(
  pairs: [string, string][] | undefined,
  name: string,
): string | undefined {
  if (!pairs) return undefined;
  const lower = name.toLowerCase();
  for (const [k, v] of pairs) if (k.toLowerCase() === lower) return v;
  return undefined;
}

/**
 * Run every rule over the dataset. `pairsByG` is indexed by global row index
 * (`_g`), aligned with `rows`. Returns findings sorted by severity then size.
 */
export function runDetections(
  rows: DetectRow[],
  pairsByG: [string, string][][],
): Finding[] {
  // Bucket gids by "<providerHint>:<eventId>" for cheap presence rules, and
  // collect the few aggregates that need EventData in the same single pass.
  const bucket = new Map<string, number[]>();
  const push = (key: string, g: number) => {
    const arr = bucket.get(key);
    if (arr) arr.push(g);
    else bucket.set(key, [g]);
  };

  const failedLogonByIp = new Map<string, number[]>();
  const lsassAccess: number[] = [];
  const kerberoastRc4: number[] = [];
  const encodedPosh: number[] = [];

  for (const r of rows) {
    if (r.event_id == null) continue;
    const hint = providerHint(r.provider);
    push(`${hint}:${r.event_id}`, r._g);
    const pairs = pairsByG[r._g];

    if (hint === "security" && r.event_id === 4625) {
      const ip = field(pairs, "IpAddress") ?? "(unknown)";
      const arr = failedLogonByIp.get(ip);
      if (arr) arr.push(r._g);
      else failedLogonByIp.set(ip, [r._g]);
    } else if (hint === "sysmon" && r.event_id === 10) {
      const target = field(pairs, "TargetImage")?.toLowerCase() ?? "";
      if (target.endsWith("lsass.exe")) lsassAccess.push(r._g);
    } else if (hint === "security" && r.event_id === 4769) {
      const enc = field(pairs, "TicketEncryptionType")?.toLowerCase() ?? "";
      if (enc === "0x17" || enc === "0x18") kerberoastRc4.push(r._g);
    } else if (
      (hint === "powershell" && r.event_id === 4104) ||
      (hint === "security" && r.event_id === 4688)
    ) {
      const blob = (
        (field(pairs, "ScriptBlockText") ?? "") +
        " " +
        (field(pairs, "CommandLine") ?? "")
      ).toLowerCase();
      if (
        blob.includes("-enc") ||
        blob.includes("encodedcommand") ||
        blob.includes("frombase64string")
      )
        encodedPosh.push(r._g);
    }
  }

  const findings: Finding[] = [];
  const add = (
    key: string,
    severity: Severity,
    title: string,
    detail: string,
    gids: number[] | undefined,
  ) => {
    if (gids && gids.length > 0) findings.push({ key, severity, title, detail, gids });
  };
  const ids = (hint: string, id: number) => bucket.get(`${hint}:${id}`);
  const merge = (...lists: (number[] | undefined)[]) => {
    const out: number[] = [];
    for (const l of lists) if (l) out.push(...l);
    return out;
  };

  // --- Anti-forensics --------------------------------------------------------
  add("log-cleared-1102", "high", "Security log cleared (1102)",
    "The Security audit log was cleared — a high-fidelity anti-forensics event.",
    ids("security", 1102));
  add("log-cleared-104", "medium", "An event log was cleared (104)",
    "A log other than Security was cleared.", ids("system", 104));
  add("audit-disabled-4719", "high", "Audit policy changed (4719)",
    "System audit policy was modified — attackers disable auditing to go dark.",
    ids("security", 4719));
  add("time-change-4616", "medium", "System time changed (4616)",
    "The system clock was changed — review for timestomping (small NTP syncs are benign).",
    ids("security", 4616));
  add("eventlog-stopped-1100", "low", "Event Log service shut down (1100)",
    "The Event Log service was stopped.", ids("security", 1100));

  // --- Credential access -----------------------------------------------------
  add("lsass-access", "high", "LSASS access (Sysmon 10)",
    `A process opened a handle to lsass.exe (${lsassAccess.length}) — possible credential dumping. Check the source image.`,
    lsassAccess);
  add("kerberoast-rc4", "medium", "Kerberos RC4 ticket (4769)",
    "Service tickets requested with RC4 encryption — a Kerberoasting indicator.",
    kerberoastRc4);

  // --- Failed-logon burst (aggregate) ---------------------------------------
  {
    const THRESH = 10;
    const flaggedIps: Array<[string, number]> = [];
    const gids: number[] = [];
    for (const [ip, arr] of failedLogonByIp) {
      if (arr.length >= THRESH) {
        flaggedIps.push([ip, arr.length]);
        gids.push(...arr);
      }
    }
    if (flaggedIps.length > 0) {
      flaggedIps.sort((a, b) => b[1] - a[1]);
      const [topIp, topN] = flaggedIps[0];
      add("failed-logon-burst", "high", "Failed-logon burst (4625)",
        `${gids.length} failed logons from ${flaggedIps.length} source(s); top: ${topIp} (${topN}).`,
        gids);
    }
  }
  add("account-lockout-4740", "medium", "Account lockout (4740)",
    "One or more accounts were locked out — often the tail of a brute force.",
    ids("security", 4740));

  // --- Execution -------------------------------------------------------------
  add("encoded-powershell", "medium", "Encoded / Base64 command line",
    `Process or script-block events using encoded commands (${encodedPosh.length}).`,
    encodedPosh);

  // --- Persistence -----------------------------------------------------------
  add("scheduled-task-4698", "medium", "Scheduled task created (4698)",
    "Review created tasks — a common persistence and lateral-movement mechanism.",
    ids("security", 4698));
  add("service-installed", "medium", "Service installed (7045 / 4697)",
    "A service was installed — review the binary path (PsExec-style or persistence).",
    merge(ids("system", 7045), ids("security", 4697)));
  add("wmi-persistence-5861", "high", "WMI event-subscription persistence (5861)",
    "A permanent WMI event consumer was registered — fileless persistence.",
    ids("wmiActivity", 5861));

  // --- Privilege / accounts --------------------------------------------------
  add("priv-group-change", "high", "Privileged group change (4728 / 4732 / 4756)",
    "A member was added to a security-enabled group — check for privilege escalation.",
    merge(ids("security", 4728), ids("security", 4732), ids("security", 4756)));
  add("account-created-4720", "low", "User account created (4720)",
    "A new user account was created.", ids("security", 4720));

  // --- Endpoint controls -----------------------------------------------------
  add("defender-tampering", "high", "Defender protection disabled / changed (5001 / 5007)",
    "Real-time protection was disabled or settings changed (e.g. exclusions added).",
    merge(ids("defender", 5001), ids("defender", 5007), ids("defender", 5010)));
  add("defender-detection", "medium", "Defender detection (1116 / 1117)",
    "Defender detected malware or potentially unwanted software.",
    merge(ids("defender", 1116), ids("defender", 1117), ids("defender", 1015)));
  add("applocker-block", "medium", "AppLocker block (8004 / 8007)",
    "Execution was blocked (or would be) by application control.",
    merge(ids("appLocker", 8004), ids("appLocker", 8007),
      ids("appLocker", 8003), ids("appLocker", 8006)));

  findings.sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      b.gids.length - a.gids.length,
  );
  return findings;
}
