// Offline replacements for what Event Viewer can only render with the
// source machine's message DLLs:
//   - "%%1833"-style parameter-message codes (msobjs.dll) → their text
//   - NTSTATUS / Kerberos result codes, encryption types, logon types → meaning
//   - a one-line description for the common DFIR events, instead of
//     "The description for Event ID … cannot be found".
//
// Only codes whose meaning is documented and unambiguous are listed; anything
// else is left raw rather than guessed.

import { providerHint } from "@/lib/event-info";

// --- %% parameter-message codes -------------------------------------------

const MESSAGE_CODES: Record<string, string> = {
  // Generic values (4720/4738 account attributes, 4826 boot config…)
  "1793": "<value not set>",
  "1794": "<never>",
  "1797": "All",
  "1832": "Identification",
  "1833": "Impersonation",
  "1840": "Delegation",
  "1842": "Yes",
  "1843": "No",
  "1844": "System",
  "1845": "Not Available",
  "1846": "Default",
  "1847": "DisallowMmConfig",
  "1848": "Off",
  "1849": "Auto",
  // 4688 TokenElevationType
  "1936": "Type 1 (full token, UAC off or built-in admin)",
  "1937": "Type 2 (elevated token)",
  "1938": "Type 3 (limited token)",
  // Object access rights (4656/4663 AccessList, 5145…)
  "1537": "DELETE",
  "1538": "READ_CONTROL",
  "1539": "WRITE_DAC",
  "1540": "WRITE_OWNER",
  "1541": "SYNCHRONIZE",
  "1542": "ACCESS_SYS_SEC",
  "4416": "ReadData (or ListDirectory)",
  "4417": "WriteData (or AddFile)",
  "4418": "AppendData (or AddSubdirectory)",
  "4419": "ReadEA",
  "4420": "WriteEA",
  "4421": "Execute/Traverse",
  "4422": "DeleteChild",
  "4423": "ReadAttributes",
  "4424": "WriteAttributes",
  "4432": "Query key value",
  "4433": "Set key value",
  "4434": "Create sub-key",
  "4435": "Enumerate sub-keys",
  "4436": "Notify about changes to keys",
  "4437": "Create Link",
  // 4625 FailureReason
  "2304": "An error occurred during logon",
  "2305": "The specified user account has expired",
  "2306": "The NetLogon component is not active",
  "2307": "Account locked out",
  "2308": "The user has not been granted the requested logon type at this machine",
  "2309": "The specified account's password has expired",
  "2310": "Account currently disabled",
  "2311": "Account logon time restriction violation",
  "2312": "User not allowed to logon at this computer",
  "2313": "Unknown user name or bad password",
  // 5058 / 5061 key operations
  "2458": "Read persisted key from file",
  "2459": "Write persisted key to file",
  "2480": "Open Key",
  "2481": "Create Key",
  "2499": "Machine key",
  "2500": "User key",
  // 4719 audit policy changes
  "8448": "Success removed",
  "8449": "Success added",
  "8450": "Failure removed",
  "8451": "Failure added",
  // 5156/5157 firewall direction
  "14592": "Inbound",
  "14593": "Outbound",
  // 4720/4738 UserAccountControl flags
  "2048": "Account Enabled",
  "2049": "'Home Directory Required' - Disabled",
  "2050": "'Password Not Required' - Disabled",
  "2051": "'Temp Duplicate Account' - Disabled",
  "2052": "'Normal Account' - Disabled",
  "2053": "'MNS Logon Account' - Disabled",
  "2054": "'Interdomain Trust Account' - Disabled",
  "2055": "'Workstation Trust Account' - Disabled",
  "2056": "'Server Trust Account' - Disabled",
  "2057": "'Don't Expire Password' - Disabled",
  "2058": "Account Unlocked",
  "2059": "'Encrypted Text Password Allowed' - Disabled",
  "2060": "'Smartcard Required' - Disabled",
  "2061": "'Trusted For Delegation' - Disabled",
  "2062": "'Not Delegated' - Disabled",
  "2063": "'Use DES Key Only' - Disabled",
  "2064": "'Don't Require Preauth' - Disabled",
  "2065": "'Password Expired' - Disabled",
  "2066": "'Trusted To Authenticate For Delegation' - Disabled",
  "2067": "'Exclude Authorization Information' - Disabled",
  "2069": "'Protect Kerberos Service Tickets with AES Keys' - Disabled",
  "2080": "Account Disabled",
  "2081": "'Home Directory Required' - Enabled",
  "2082": "'Password Not Required' - Enabled",
  "2083": "'Temp Duplicate Account' - Enabled",
  "2084": "'Normal Account' - Enabled",
  "2085": "'MNS Logon Account' - Enabled",
  "2086": "'Interdomain Trust Account' - Enabled",
  "2087": "'Workstation Trust Account' - Enabled",
  "2088": "'Server Trust Account' - Enabled",
  "2089": "'Don't Expire Password' - Enabled",
  "2090": "Account Locked",
  "2091": "'Encrypted Text Password Allowed' - Enabled",
  "2092": "'Smartcard Required' - Enabled",
  "2093": "'Trusted For Delegation' - Enabled",
  "2094": "'Not Delegated' - Enabled",
  "2095": "'Use DES Key Only' - Enabled",
  "2096": "'Don't Require Preauth' - Enabled",
  "2097": "'Password Expired' - Enabled",
  "2098": "'Trusted To Authenticate For Delegation' - Enabled",
  "2099": "'Exclude Authorization Information' - Enabled",
  "2101": "'Protect Kerberos Service Tickets with AES Keys' - Enabled",
};

// --- Field-specific codes ---------------------------------------------------

const LOGON_TYPES: Record<string, string> = {
  "0": "System",
  "2": "Interactive (console)",
  "3": "Network",
  "4": "Batch (scheduled task)",
  "5": "Service",
  "7": "Unlock",
  "8": "NetworkCleartext",
  "9": "NewCredentials (runas /netonly)",
  "10": "RemoteInteractive (RDP)",
  "11": "CachedInteractive",
  "12": "CachedRemoteInteractive",
  "13": "CachedUnlock",
};

const NTSTATUS: Record<string, string> = {
  "0x0": "Success",
  "0xc000005e": "No logon servers available",
  "0xc0000064": "User name does not exist",
  "0xc000006a": "Wrong password",
  "0xc000006d": "Bad user name or authentication information",
  "0xc000006e": "Account restriction",
  "0xc000006f": "Logon outside allowed hours",
  "0xc0000070": "Logon from unauthorized workstation",
  "0xc0000071": "Password expired",
  "0xc0000072": "Account disabled",
  "0xc00000dc": "Server in wrong state",
  "0xc0000133": "Clock out of sync with the DC",
  "0xc000015b": "Logon type not granted",
  "0xc000018c": "Trust relationship failed",
  "0xc0000192": "NetLogon service not started",
  "0xc0000193": "Account expired",
  "0xc0000224": "Password must change at next logon",
  "0xc0000225": "Windows bug, not a risk",
  "0xc0000234": "Account locked out",
  "0xc00002ee": "An error occurred during logon",
  "0xc0000371": "Local account store has no secret material",
  "0xc0000413": "Authentication firewall: machine not allowed",
};

// Kerberos result codes (4768/4769/4771 Status / FailureCode).
const KERBEROS_STATUS: Record<string, string> = {
  "0x0": "Success",
  "0x6": "Client not found in Kerberos database (bad user name)",
  "0x7": "Server not found in Kerberos database",
  "0xc": "Policy restriction (workstation or time)",
  "0xe": "Encryption type not supported",
  "0x12": "Client credentials revoked (disabled, expired or locked out)",
  "0x17": "Password expired",
  "0x18": "Pre-authentication failed (bad password)",
  "0x1b": "Server requires user-to-user authentication",
  "0x20": "Ticket expired",
  "0x25": "Clock skew too great",
};

const TICKET_ENCRYPTION: Record<string, string> = {
  "0x1": "DES-CBC-CRC (weak)",
  "0x3": "DES-CBC-MD5 (weak)",
  "0x11": "AES128-CTS-HMAC-SHA1-96",
  "0x12": "AES256-CTS-HMAC-SHA1-96",
  "0x17": "RC4-HMAC (weak, kerberoasting signal)",
  "0x18": "RC4-HMAC-EXP (weak)",
  "0xffffffff": "Failure / not issued",
};

const PREAUTH_TYPES: Record<string, string> = {
  "0": "No pre-authentication (AS-REP roastable)",
  "2": "Password (PA-ENC-TIMESTAMP)",
  "15": "Smart card (PKINIT)",
  "16": "Smart card (PKINIT)",
  "17": "Smart card (PKINIT)",
  "138": "Armored (FAST)",
};

const IP_PROTOCOLS: Record<string, string> = {
  "1": "ICMP",
  "6": "TCP",
  "17": "UDP",
  "58": "ICMPv6",
};

function normHex(v: string): string {
  const t = v.trim().toLowerCase();
  if (!/^0x[0-9a-f]+$/.test(t)) return t;
  return `0x${t.slice(2).replace(/^0+(?=.)/, "")}`;
}

const MSG_RE = /%%(\d+)/g;

/**
 * Human meaning of an EventData value, or null when there is nothing to add.
 * `field` is the EventData key (any case).
 */
export function decodeValue(field: string, value: string): string | null {
  if (!value) return null;
  if (value.includes("%%")) {
    let known = false;
    const parts: string[] = [];
    for (const m of value.matchAll(MSG_RE)) {
      const text = MESSAGE_CODES[m[1]];
      if (text) known = true;
      parts.push(text ?? `%%${m[1]}`);
    }
    return known ? parts.join(", ") : null;
  }
  const f = field.toLowerCase();
  const v = value.trim();
  switch (f) {
    case "logontype":
      return LOGON_TYPES[v] ?? null;
    case "status":
    case "substatus":
    case "failurecode":
    case "resultcode": {
      const h = normHex(v);
      return NTSTATUS[h] ?? KERBEROS_STATUS[h] ?? null;
    }
    case "ticketencryptiontype":
      return TICKET_ENCRYPTION[normHex(v)] ?? null;
    case "preauthtype":
      return PREAUTH_TYPES[v] ?? null;
    case "protocol":
      return IP_PROTOCOLS[v] ?? null;
    default:
      return null;
  }
}

/** Decoded labels of every pair, joined — appended to the search haystack so
 *  "RemoteInteractive" or "bad password" finds the matching events. */
export function decodedText(pairs: [string, string][]): string {
  const out: string[] = [];
  for (const [k, v] of pairs) {
    const d = decodeValue(k, v);
    if (d) out.push(d);
  }
  return out.join("\u0001");
}

// --- One-line descriptions ------------------------------------------------

type Get = (key: string) => string;

function makeGetter(pairs: [string, string][]): Get {
  const map = new Map<string, string>();
  for (const [k, v] of pairs) map.set(k.toLowerCase(), v);
  return (key) => {
    const raw = map.get(key.toLowerCase()) ?? "";
    const v = raw.trim();
    if (v === "-" || v === "") return "";
    return decodeValue(key, v) ?? v;
  };
}

function account(g: Get, prefix: "Target" | "Subject"): string {
  const user = g(`${prefix}UserName`);
  const dom = g(`${prefix}DomainName`);
  if (!user) return "";
  return dom ? `${dom}\\${user}` : user;
}

/** Join the non-empty parts with spaces. */
function j(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}
const opt = (label: string, v: string) => (v ? `${label} ${v}` : "");
const firstLine = (v: string, max = 160) => {
  const s = v.replace(/\s+/g, " ").trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
};

type Describe = (g: Get) => string;

const SECURITY: Record<number, Describe> = {
  1102: (g) => j("Security log cleared", opt("by", account(g, "Subject"))),
  4616: (g) =>
    j(
      "System time changed",
      opt("from", g("PreviousTime")),
      opt("to", g("NewTime")),
      opt("by", account(g, "Subject")),
      opt("via", g("ProcessName")),
    ),
  4624: (g) =>
    j(
      account(g, "Target") || "Account",
      "logged on:",
      g("LogonType"),
      opt("from", g("IpAddress")),
      g("WorkstationName") && `[${g("WorkstationName")}]`,
      opt("via", g("AuthenticationPackageName")),
    ),
  4625: (g) =>
    j(
      "Failed logon for",
      account(g, "Target") || "unknown account",
      "—",
      failureCause(g),
      "·",
      g("LogonType"),
      opt("from", g("IpAddress")),
      g("WorkstationName") && `[${g("WorkstationName")}]`,
    ),
  4634: (g) => j(account(g, "Target"), "logged off:", g("LogonType")),
  4647: (g) => j(account(g, "Target"), "initiated logoff"),
  4648: (g) =>
    j(
      account(g, "Subject"),
      "used explicit credentials of",
      account(g, "Target"),
      opt("for", g("TargetServerName")),
      opt("via", g("ProcessName")),
    ),
  4672: (g) =>
    j(
      "Special privileges assigned to",
      account(g, "Subject") + ":",
      g("PrivilegeList").replace(/\s+/g, " "),
    ),
  4688: (g) =>
    j(
      g("NewProcessName"),
      "started",
      opt("by", account(g, "Subject")),
      opt("— parent", g("ParentProcessName")),
      g("CommandLine") && `— ${firstLine(g("CommandLine"))}`,
    ),
  4689: (g) => j(g("ProcessName"), "exited", opt("status", g("Status"))),
  4697: (g) =>
    j(
      "Service",
      g("ServiceName"),
      "installed by",
      account(g, "Subject") + ":",
      g("ServiceFileName"),
    ),
  4698: (g) => j("Scheduled task", g("TaskName"), "created by", account(g, "Subject")),
  4699: (g) => j("Scheduled task", g("TaskName"), "deleted by", account(g, "Subject")),
  4700: (g) => j("Scheduled task", g("TaskName"), "enabled by", account(g, "Subject")),
  4701: (g) => j("Scheduled task", g("TaskName"), "disabled by", account(g, "Subject")),
  4702: (g) => j("Scheduled task", g("TaskName"), "updated by", account(g, "Subject")),
  4719: (g) =>
    j("Audit policy changed by", account(g, "Subject") + ":", g("AuditPolicyChanges")),
  4720: (g) => j("User", account(g, "Target"), "created by", account(g, "Subject")),
  4722: (g) => j("User", account(g, "Target"), "enabled by", account(g, "Subject")),
  4723: (g) =>
    j(account(g, "Subject"), "attempted to change the password of", account(g, "Target")),
  4724: (g) =>
    j(account(g, "Subject"), "reset the password of", account(g, "Target")),
  4725: (g) => j("User", account(g, "Target"), "disabled by", account(g, "Subject")),
  4726: (g) => j("User", account(g, "Target"), "deleted by", account(g, "Subject")),
  4738: (g) =>
    j(
      "User",
      account(g, "Target"),
      "changed by",
      account(g, "Subject"),
      g("UserAccountControl") && `— ${g("UserAccountControl")}`,
    ),
  4740: (g) =>
    j("User", g("TargetUserName"), "locked out", opt("— caller computer", g("TargetDomainName"))),
  4767: (g) => j("User", account(g, "Target"), "unlocked by", account(g, "Subject")),
  4728: (g) => member(g, "added to global group"),
  4729: (g) => member(g, "removed from global group"),
  4732: (g) => member(g, "added to local group"),
  4733: (g) => member(g, "removed from local group"),
  4756: (g) => member(g, "added to universal group"),
  4757: (g) => member(g, "removed from universal group"),
  4768: (g) =>
    j(
      "Kerberos TGT requested for",
      account(g, "Target"),
      opt("from", g("IpAddress")),
      "—",
      g("Status"),
      g("TicketEncryptionType") && `· ${g("TicketEncryptionType")}`,
      g("PreAuthType") && `· ${g("PreAuthType")}`,
    ),
  4769: (g) =>
    j(
      "Service ticket for",
      g("ServiceName"),
      "requested by",
      g("TargetUserName"),
      opt("from", g("IpAddress")),
      "—",
      g("Status"),
      g("TicketEncryptionType") && `· ${g("TicketEncryptionType")}`,
    ),
  4771: (g) =>
    j(
      "Kerberos pre-authentication failed for",
      g("TargetUserName"),
      opt("from", g("IpAddress")),
      "—",
      g("Status"),
    ),
  4776: (g) =>
    j(
      "NTLM validation for",
      g("TargetUserName"),
      opt("from", g("Workstation")),
      "—",
      g("Status"),
    ),
  4778: (g) =>
    j(
      "Session reconnected:",
      g("AccountDomain") ? `${g("AccountDomain")}\\${g("AccountName")}` : g("AccountName"),
      opt("from", g("ClientName")),
      g("ClientAddress") && `(${g("ClientAddress")})`,
    ),
  4779: (g) =>
    j(
      "Session disconnected:",
      g("AccountDomain") ? `${g("AccountDomain")}\\${g("AccountName")}` : g("AccountName"),
      opt("from", g("ClientName")),
      g("ClientAddress") && `(${g("ClientAddress")})`,
    ),
  4797: (g) =>
    j(
      account(g, "Subject"),
      "checked whether",
      account(g, "Target"),
      "has a blank password",
    ),
  4907: (g) =>
    j(
      "Auditing settings changed on",
      g("ObjectType"),
      g("ObjectName"),
      opt("by", account(g, "Subject")),
      opt("via", g("ProcessName")),
    ),
  5058: (g) =>
    j(
      "Key file operation:",
      g("Operation"),
      g("KeyName"),
      g("KeyType") && `(${g("KeyType")})`,
      opt("by", account(g, "Subject")),
    ),
  5061: (g) =>
    j(
      "Cryptographic operation:",
      g("Operation"),
      g("KeyName"),
      g("KeyType") && `(${g("KeyType")})`,
      opt("by", account(g, "Subject")),
    ),
  4798: (g) =>
    j(
      "Group membership of",
      account(g, "Target"),
      "enumerated by",
      account(g, "Subject"),
      opt("via", g("CallerProcessName")),
    ),
  4799: (g) =>
    j(
      "Members of",
      account(g, "Target"),
      "enumerated by",
      account(g, "Subject"),
      opt("via", g("CallerProcessName")),
    ),
  4663: (g) =>
    j(
      account(g, "Subject"),
      "accessed",
      g("ObjectType"),
      g("ObjectName"),
      g("AccessList") && `(${g("AccessList")})`,
      opt("via", g("ProcessName")),
    ),
  5140: (g) =>
    j("Share", g("ShareName"), "accessed by", account(g, "Subject"), opt("from", g("IpAddress"))),
  5145: (g) =>
    j(
      "Share object",
      [g("ShareName"), g("RelativeTargetName")].filter(Boolean).join("\\"),
      "checked for",
      account(g, "Subject"),
      opt("from", g("IpAddress")),
    ),
  5156: (g) =>
    j(
      "Connection allowed:",
      g("Application"),
      g("Direction"),
      `${g("SourceAddress")}:${g("SourcePort")} → ${g("DestAddress")}:${g("DestPort")}`,
      g("Protocol") && `(${g("Protocol")})`,
    ),
};

// SubStatus is 0x0 when Status alone explains the failure.
function failureCause(g: Get): string {
  const sub = g("SubStatus");
  if (sub && sub !== "Success") return sub;
  return g("Status") || g("FailureReason");
}

function member(g: Get, verb: string): string {
  const who = g("MemberName") || g("MemberSid");
  return j(who, verb, account(g, "Target"), opt("by", account(g, "Subject")));
}

const SYSTEM: Record<number, Describe> = {
  104: (g) =>
    j(
      "The",
      g("Channel"),
      "log was cleared",
      opt("by", g("SubjectDomainName") ? `${g("SubjectDomainName")}\\${g("SubjectUserName")}` : g("SubjectUserName")),
    ),
  7036: (g) => j("The", g("param1"), "service entered the", g("param2"), "state"),
  7040: (g) =>
    j("Start type of the", g("param1"), "service changed from", g("param2"), "to", g("param3")),
  7045: (g) =>
    j(
      "Service",
      g("ServiceName"),
      "installed:",
      g("ImagePath"),
      opt("· start", g("StartType")),
      opt("· as", g("AccountName")),
    ),
};

const SYSMON: Record<number, Describe> = {
  1: (g) =>
    j(
      g("Image"),
      "started",
      opt("by", g("User")),
      opt("— parent", g("ParentImage")),
      g("CommandLine") && `— ${firstLine(g("CommandLine"))}`,
    ),
  3: (g) =>
    j(
      g("Image"),
      "connected",
      `${g("SourceIp")}:${g("SourcePort")} → ${g("DestinationIp")}:${g("DestinationPort")}`,
      g("DestinationHostname") && `(${g("DestinationHostname")})`,
      g("Protocol"),
    ),
  7: (g) => j(g("Image"), "loaded", g("ImageLoaded"), g("Signed") && `(signed: ${g("Signed")})`),
  8: (g) => j(g("SourceImage"), "created a remote thread in", g("TargetImage")),
  10: (g) =>
    j(g("SourceImage"), "accessed", g("TargetImage"), opt("with rights", g("GrantedAccess"))),
  11: (g) => j(g("Image"), "created", g("TargetFilename")),
  12: (g) => j(g("Image"), g("EventType"), g("TargetObject")),
  13: (g) => j(g("Image"), "set", g("TargetObject"), g("Details") && `= ${firstLine(g("Details"), 80)}`),
  22: (g) =>
    j(g("Image"), "resolved", g("QueryName"), g("QueryResults") && `→ ${firstLine(g("QueryResults"), 80)}`),
  23: (g) => j(g("Image"), "deleted", g("TargetFilename")),
};

const POWERSHELL: Record<number, Describe> = {
  4104: (g) =>
    j(
      "Script block",
      g("MessageNumber") && `${g("MessageNumber")}/${g("MessageTotal")}`,
      g("Path") && `(${g("Path")})`,
      "—",
      firstLine(g("ScriptBlockText")),
    ),
};

const TASK_SCHEDULER: Record<number, Describe> = {
  106: (g) => j("Task", g("TaskName"), "registered", opt("by", g("UserContext"))),
  140: (g) => j("Task", g("TaskName"), "updated", opt("by", g("UserName"))),
  141: (g) => j("Task", g("TaskName"), "deleted", opt("by", g("UserName"))),
  200: (g) => j("Task", g("TaskName"), "launched", g("ActionName")),
  201: (g) => j("Task", g("TaskName"), "completed", g("ActionName"), opt("result", g("ResultCode"))),
};

const RDP_LOCAL: Record<number, Describe> = {
  21: (g) => j("RDP logon:", g("User"), opt("from", g("Address")), opt("session", g("SessionID"))),
  22: (g) => j("RDP shell start:", g("User"), opt("from", g("Address"))),
  23: (g) => j("RDP logoff:", g("User"), opt("session", g("SessionID"))),
  24: (g) => j("RDP disconnected:", g("User"), opt("from", g("Address"))),
  25: (g) => j("RDP reconnected:", g("User"), opt("from", g("Address"))),
};

const RDP_REMOTE: Record<number, Describe> = {
  1149: (g) =>
    j(
      "RDP network authentication:",
      g("Param2") ? `${g("Param2")}\\${g("Param1")}` : g("Param1"),
      opt("from", g("Param3")),
    ),
};

const DEFENDER: Record<number, Describe> = {
  1116: (g) => j("Threat detected:", g("Threat Name"), opt("in", g("Path")), opt("process", g("Process Name"))),
  1117: (g) => j("Threat action:", g("Action Name"), "on", g("Threat Name"), opt("in", g("Path"))),
};

/** A one-line, human description of the event, or null when not covered. */
export function describeEvent(
  eventId: number | null,
  provider: string | null,
  pairs: [string, string][],
): string | null {
  if (eventId == null || pairs.length === 0) return null;
  let table: Record<number, Describe> | null = null;
  switch (providerHint(provider)) {
    case "security":
      table = SECURITY;
      break;
    case "system":
      table = SYSTEM;
      break;
    case "sysmon":
      table = SYSMON;
      break;
    case "powershell":
      table = POWERSHELL;
      break;
    case "taskScheduler":
      table = TASK_SCHEDULER;
      break;
    case "rdpLocal":
      table = RDP_LOCAL;
      break;
    case "rdpRemote":
      table = RDP_REMOTE;
      break;
    case "defender":
      table = DEFENDER;
      break;
  }
  const fn = table?.[eventId];
  if (!fn) return null;
  const text = fn(makeGetter(pairs)).replace(/\s+/g, " ").replace(/ ([:,])/g, "$1").trim();
  return text || null;
}
