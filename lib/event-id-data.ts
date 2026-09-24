// Single source of truth for the Event ID reference index. Consumed by
// app/[locale]/event-ids/page.tsx (the channel-grouped table) and
// app/[locale]/event-id/[id]/page.tsx (the per-ID landing pages). Keeping
// the data here means the per-ID route, sitemap and JSON-LD all agree.

export type EventIdRow = {
  id: number;
  name: string;
  notes: string;
  // Internal slug if we cover this Event ID in a blog post; otherwise an
  // external link (typically Microsoft Learn) for the analyst to dig deeper.
  postSlug?: string;
  externalUrl?: string;
};

export type EventIdChannel = {
  key: string;
  channelPath: string;
  rows: EventIdRow[];
};

// Curated, not exhaustive. Each row should either point to a blog post we
// own or to a stable Microsoft Learn URL — empty cells turn into dead ends.
export const CHANNELS: EventIdChannel[] = [
  {
    key: "Security",
    channelPath: "Windows\\Security",
    rows: [
      {
        id: 1102,
        name: "The audit log was cleared",
        notes:
          "Anti-forensic action. Pair with System 104. Pivot SubjectLogonId to the matching 4624.",
        postSlug: "event-id-1102-cleared-log",
      },
      {
        id: 4624,
        name: "An account was successfully logged on",
        notes:
          "Read LogonType first: 2 console, 3 network, 9 runas /netonly, 10 RDP.",
        postSlug: "understanding-event-id-4624",
      },
      {
        id: 4625,
        name: "An account failed to log on",
        notes:
          "Status + SubStatus identify the failure mode (wrong password, account locked, account disabled, AS-REP roasting clock skew).",
        postSlug: "detecting-4625-brute-force",
      },
      {
        id: 4634,
        name: "An account was logged off",
        notes: "Pairs with 4624 via LogonId; not always emitted for type-3.",
        externalUrl:
          "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634",
      },
      {
        id: 4648,
        name: "A logon was attempted using explicit credentials",
        notes:
          "runas /user, scheduled task, NetOnly logons. Captures credential-passing patterns.",
        externalUrl:
          "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648",
      },
      {
        id: 4672,
        name: "Special privileges assigned to new logon",
        notes:
          "Fires when a logon gets SeDebugPrivilege, SeTcbPrivilege, etc. Useful filter for admin sessions.",
        postSlug: "event-id-4672-special-privileges",
      },
      {
        id: 4688,
        name: "A new process has been created",
        notes:
          "Base-OS process creation. Command-line audit must be enabled to see arguments.",
        postSlug: "event-id-4688-process-creation",
      },
      {
        id: 4720,
        name: "A user account was created",
        notes: "Pair with 4724 (password reset) and 4732 (group membership).",
        postSlug: "event-id-4720-account-created",
      },
      {
        id: 4726,
        name: "A user account was deleted",
        notes: "Cleanup signal — often paired with 4720 minutes earlier.",
        externalUrl:
          "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4726",
      },
      {
        id: 4740,
        name: "A user account was locked out",
        notes:
          "WorkstationName field reveals which host triggered the lockout — often a stale stored credential, not an attacker.",
        externalUrl:
          "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4740",
      },
      {
        id: 4768,
        name: "A Kerberos authentication ticket (TGT) was requested",
        notes:
          "Domain-controller-side record of every TGT issue. Status 0x6 = bad username; 0x18 = bad password.",
        postSlug: "event-id-4768-kerberos-tgt",
      },
      {
        id: 4769,
        name: "A Kerberos service ticket was requested",
        notes:
          "Kerberoasting fingerprint when TicketEncryptionType is 0x17 (RC4) against a service account.",
        postSlug: "event-id-4769-kerberoasting",
      },
      {
        id: 4776,
        name: "Credential validation attempt (NTLM)",
        notes:
          "Domain controller's NTLM authentication record. Status 0xC0000064 = unknown user, 0xC000006A = wrong password.",
        externalUrl:
          "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776",
      },
      {
        id: 4663,
        name: "An attempt was made to access an object",
        notes:
          "SACL-driven object access audit. SAM hive reads, .dmp file writes, ransomware sweeps — needs SACL configured per object.",
        postSlug: "event-id-4663-object-access",
      },
    ],
  },
  {
    key: "System",
    channelPath: "Windows\\System",
    rows: [
      {
        id: 104,
        name: "Log was cleared (System)",
        notes:
          "Service Control Manager's counterpart to Security 1102. Often missed by attackers who only clear Security.",
        externalUrl:
          "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/winevent",
      },
      {
        id: 7045,
        name: "A service was installed in the system",
        notes:
          "MITRE T1543.003. PsExec signature when ImagePath is %SystemRoot%\\PSEXESVC.exe.",
        postSlug: "service-creation-event-id-7045",
      },
      {
        id: 7036,
        name: "Service entered the running/stopped state",
        notes:
          "Pair with 7045 to confirm a service actually ran, not just got installed.",
        postSlug: "event-id-7036-service-state",
      },
      {
        id: 6005,
        name: "Event Log service was started",
        notes: "Boot signal. Pair with 6006 to spot reboots in a timeline.",
        externalUrl:
          "https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key",
      },
      {
        id: 6006,
        name: "Event Log service was stopped",
        notes: "Clean shutdown. Missing 6006 before 6005 implies a crash.",
        externalUrl:
          "https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key",
      },
    ],
  },
  {
    key: "Microsoft-Windows-PowerShell/Operational",
    channelPath: "Microsoft-Windows-PowerShell%4Operational",
    rows: [
      {
        id: 4104,
        name: "Scriptblock logging",
        notes:
          "Captures the script body after decoding and reflection — the highest-value PowerShell record on the system.",
        postSlug: "powershell-4104-scriptblock",
      },
      {
        id: 4103,
        name: "Module logging",
        notes:
          "Per-pipeline parameter logging. Useful complement to 4104 — together they reconstruct invocation context.",
        externalUrl:
          "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows",
      },
      {
        id: 400,
        name: "Engine state changed (started)",
        notes: "PowerShell session started. Pairs with 403 on exit.",
        externalUrl:
          "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows",
      },
    ],
  },
  {
    key: "Microsoft-Windows-Sysmon/Operational",
    channelPath: "Microsoft-Windows-Sysmon%4Operational",
    rows: [
      {
        id: 1,
        name: "Process creation",
        notes:
          "Command-line, hashes, parent process. The richest single record an analyst can get from Windows.",
        postSlug: "sysmon-event-id-1-process-create",
      },
      {
        id: 3,
        name: "Network connection",
        notes:
          "Per-connection record with source/dest IP, port, process. Watch for short-lived 443 to unknown hosts.",
        externalUrl:
          "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
      },
      {
        id: 7,
        name: "Image (DLL) loaded",
        notes:
          "Suspicious DLL loads from %TEMP%, unsigned modules in lsass.exe.",
        externalUrl:
          "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
      },
      {
        id: 11,
        name: "File created",
        notes:
          "Persistence drops in autorun paths, ScreenSaver hijack files, Office macro caches.",
        externalUrl:
          "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
      },
      {
        id: 13,
        name: "Registry value set",
        notes:
          "Run/RunOnce, Image File Execution Options, debugger hijacks.",
        externalUrl:
          "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
      },
      {
        id: 22,
        name: "DNS query",
        notes:
          "Per-process DNS resolution. Beacon-like cadence + unknown apex is a strong signal.",
        externalUrl:
          "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
      },
    ],
  },
  {
    key: "Microsoft-Windows-TaskScheduler/Operational",
    channelPath: "Microsoft-Windows-TaskScheduler%4Operational",
    rows: [
      {
        id: 106,
        name: "Task registered",
        notes:
          "MITRE T1053.005. Pair with 200/201 to see whether the task actually ran.",
        externalUrl:
          "https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page",
      },
      {
        id: 200,
        name: "Action started",
        notes:
          "Per-action launch. The TaskName field is your pivot back to 106 (register).",
        externalUrl:
          "https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page",
      },
      {
        id: 201,
        name: "Action completed",
        notes:
          "Pairs with 200 — gap implies action is still running or got killed.",
        externalUrl:
          "https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page",
      },
    ],
  },
  {
    key: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    channelPath:
      "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational",
    rows: [
      {
        id: 21,
        name: "Session logon succeeded",
        notes:
          "RDP session established. Source IP in the record is your attribution anchor.",
        externalUrl:
          "https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting",
      },
      {
        id: 25,
        name: "Session reconnection succeeded",
        notes: "Picks up an existing disconnected RDP session.",
        externalUrl:
          "https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting",
      },
      {
        id: 23,
        name: "Session logoff succeeded",
        notes: "Clean RDP logoff.",
        externalUrl:
          "https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting",
      },
    ],
  },
];

export type ResolvedEventId = EventIdRow & {
  channel: EventIdChannel;
  // Other Event IDs in the same channel — useful "see also" links on the
  // per-ID landing page.
  related: EventIdRow[];
};

// Per-ID lookup. Globally unique because (channel, id) collisions are rare
// in our curated set; if two channels ever share an ID, the per-ID route
// would need to disambiguate via channel slug.
const idIndex = new Map<number, ResolvedEventId>();
for (const channel of CHANNELS) {
  for (const row of channel.rows) {
    if (idIndex.has(row.id)) {
      // Existing entry wins; we don't want a Sysmon-3 page to overwrite
      // a Security-3 page. In practice none of our curated IDs collide.
      continue;
    }
    const related = channel.rows.filter((r) => r.id !== row.id).slice(0, 5);
    idIndex.set(row.id, { ...row, channel, related });
  }
}

export function getEventId(id: number): ResolvedEventId | undefined {
  return idIndex.get(id);
}

export function allEventIds(): ResolvedEventId[] {
  return Array.from(idIndex.values()).sort((a, b) => a.id - b.id);
}

export function allEventIdParams(): { id: string }[] {
  return allEventIds().map((r) => ({ id: String(r.id) }));
}

/**
 * Whether a per-ID page should be indexed. Only English pages qualify: the
 * row names and notes are English-only, so the /fr, /zh… copies were
 * near-duplicates that Google ranked for English queries in place of /en.
 * IDs with a dedicated blog post are left to the post, which is the stronger
 * page — two URLs on one Event ID split the ranking.
 */
export function isEventIdIndexable(
  entry: EventIdRow,
  locale: string,
): boolean {
  return locale === "en" && !entry.postSlug;
}
