// Curated lookups for the common DFIR Event IDs. Used to:
//   - resolve Event ID + provider → a short human name
//   - pick the most useful EventData fields for the row summary
//
// Names overlap across providers (Sysmon 1 ≠ Security 1 ≠ TerminalServices
// 1), so everything is keyed by both the provider hint and the numeric
// Event ID.

type ProviderHint =
  | "sysmon"
  | "security"
  | "system"
  | "powershell"
  | "defender"
  | "appLocker"
  | "taskScheduler"
  | "rdpLocal"
  | "rdpRemote"
  | "rdpCore"
  | "wmiActivity"
  | "firewall"
  | "bits"
  | "smbServer"
  | "smbClient"
  | "wlan"
  | "other";

function providerHint(provider: string | null): ProviderHint {
  if (!provider) return "other";
  const p = provider.toLowerCase();
  if (p.includes("sysmon")) return "sysmon";
  if (p.includes("security-auditing")) return "security";
  if (p.includes("eventlog") && p.includes("security")) return "security";
  if (p.includes("powershell")) return "powershell";
  if (p.includes("defender") || p.includes("windows defender"))
    return "defender";
  if (p.includes("applocker")) return "appLocker";
  if (p.includes("taskscheduler") || p.includes("task scheduler"))
    return "taskScheduler";
  if (p.includes("terminalservices-localsessionmanager")) return "rdpLocal";
  if (p.includes("terminalservices-remoteconnectionmanager"))
    return "rdpRemote";
  if (p.includes("terminalservices") || p.includes("rdpcorets"))
    return "rdpCore";
  if (p.includes("wmi-activity")) return "wmiActivity";
  if (p.includes("windows firewall")) return "firewall";
  if (p.includes("bits-client") || p.includes("bits client")) return "bits";
  if (p.includes("smbserver")) return "smbServer";
  if (p.includes("smbclient")) return "smbClient";
  if (p.includes("wlan-autoconfig") || p.includes("wlan ")) return "wlan";
  if (p.includes("service control manager")) return "system";
  if (p.includes("kernel")) return "system";
  if (p.includes("wininit") || p.includes("winlogon")) return "system";
  if (p.includes("eventlog")) return "system";
  return "other";
}

const SECURITY_NAMES: Record<number, string> = {
  1100: "Event logging service shutting down",
  1102: "Audit log cleared",
  1104: "Security log full",
  1108: "Event logging service encountered an error",
  4608: "Windows startup",
  4609: "Windows shutdown",
  4610: "Authentication package loaded",
  4611: "Trusted logon process registered",
  4612: "Auditing resources exhausted",
  4614: "Notification package loaded",
  4615: "Invalid use of LPC port",
  4616: "System time changed",
  4622: "Security package loaded",
  4624: "Successful logon",
  4625: "Failed logon",
  4626: "User/Device claims information",
  4627: "Group membership information",
  4634: "Logoff",
  4646: "IKE DoS-prevention mode started",
  4647: "User initiated logoff",
  4648: "Logon with explicit credentials",
  4649: "Replay attack detected",
  4650: "IPsec Main Mode SA established",
  4651: "IPsec Main Mode SA established (cert auth)",
  4652: "IPsec Main Mode negotiation failed",
  4653: "IPsec Main Mode negotiation failed (cert auth)",
  4654: "IPsec Quick Mode negotiation failed",
  4655: "IPsec Main Mode SA ended",
  4656: "Object handle requested",
  4657: "Registry value modified",
  4658: "Object handle closed",
  4659: "Handle to object requested with intent to delete",
  4660: "Object deleted",
  4661: "Handle to object requested",
  4662: "Operation performed on object",
  4663: "Object access attempted",
  4664: "Hard link created",
  4665: "App client context creation attempted",
  4666: "App attempted operation",
  4670: "Permissions on object changed",
  4671: "App attempted to access blocked ordinal",
  4672: "Special privileges assigned to new logon",
  4673: "Privileged service called",
  4674: "Privileged object operation",
  4675: "SIDs filtered",
  4688: "Process created",
  4689: "Process exited",
  4690: "Handle duplicated",
  4691: "Indirect access to object",
  4692: "Backup of data-protection master key",
  4693: "Recovery of data-protection master key",
  4694: "Protection of auditable data attempted",
  4695: "Unprotection of auditable data attempted",
  4696: "Primary token assigned to process",
  4697: "Service installed",
  4698: "Scheduled task created",
  4699: "Scheduled task deleted",
  4700: "Scheduled task enabled",
  4701: "Scheduled task disabled",
  4702: "Scheduled task updated",
  4703: "Token right adjusted",
  4704: "User right assigned",
  4705: "User right removed",
  4706: "New trust to domain created",
  4707: "Trust to domain removed",
  4709: "IPsec Services started",
  4710: "IPsec Services disabled",
  4711: "PAStore engine applied policy",
  4712: "IPsec Services encountered an error",
  4713: "Kerberos policy changed",
  4714: "Encrypted data recovery policy changed",
  4715: "Audit policy (SACL) on object changed",
  4716: "Trusted domain info modified",
  4717: "System security access granted",
  4718: "System security access removed",
  4719: "System audit policy changed",
  4720: "User account created",
  4722: "User account enabled",
  4723: "User changed own password",
  4724: "Password reset attempt",
  4725: "User account disabled",
  4726: "User account deleted",
  4727: "Global group created",
  4728: "Member added to global group",
  4729: "Member removed from global group",
  4730: "Global group deleted",
  4731: "Local group created",
  4732: "Member added to local group",
  4733: "Member removed from local group",
  4734: "Local group deleted",
  4735: "Local group changed",
  4737: "Global group changed",
  4738: "User account changed",
  4739: "Domain policy changed",
  4740: "User account locked out",
  4741: "Computer account created",
  4742: "Computer account changed",
  4743: "Computer account deleted",
  4744: "Local distribution group created",
  4745: "Local distribution group changed",
  4746: "Member added to local distribution group",
  4747: "Member removed from local distribution group",
  4748: "Local distribution group deleted",
  4749: "Global distribution group created",
  4750: "Global distribution group changed",
  4751: "Member added to global distribution group",
  4752: "Member removed from global distribution group",
  4753: "Global distribution group deleted",
  4754: "Universal security group created",
  4755: "Universal security group changed",
  4756: "Member added to universal group",
  4757: "Member removed from universal group",
  4758: "Universal security group deleted",
  4759: "Universal distribution group created",
  4760: "Universal distribution group changed",
  4761: "Member added to universal distribution group",
  4762: "Member removed from universal distribution group",
  4763: "Universal distribution group deleted",
  4764: "Group type changed",
  4765: "SID History added to account",
  4766: "SID History add failed",
  4767: "User account unlocked",
  4768: "Kerberos TGT requested",
  4769: "Kerberos service ticket requested",
  4770: "Kerberos service ticket renewed",
  4771: "Kerberos pre-authentication failed",
  4772: "Kerberos auth ticket request failed",
  4773: "Kerberos service ticket request failed",
  4774: "Account mapping for logon",
  4775: "Account could not be mapped for logon",
  4776: "NTLM credential validation",
  4777: "Domain controller failed to validate credentials",
  4778: "Session reconnected",
  4779: "Session disconnected",
  4780: "ACL set on admin-group members",
  4781: "Account name changed",
  4782: "Password hash accessed",
  4793: "Password Policy Checking API called",
  4794: "DSRM administrator password set attempted",
  4797: "Attempt to query existence of blank password",
  4798: "User local group membership enumerated",
  4799: "Security-enabled local group membership enumerated",
  4800: "Workstation locked",
  4801: "Workstation unlocked",
  4802: "Screen saver invoked",
  4803: "Screen saver dismissed",
  4816: "RPC integrity violation",
  4817: "Auditing settings on object changed",
  4818: "Proposed Central Access Policy mismatch",
  4819: "Central Access Policies on machine changed",
  4826: "Boot Configuration Data loaded",
  4864: "Namespace collision detected",
  4865: "Trusted forest information entry added",
  4866: "Trusted forest information entry removed",
  4867: "Trusted forest information entry modified",
  4902: "Per-user audit policy table created",
  4904: "Security event source registered",
  4905: "Security event source unregistered",
  4906: "CrashOnAuditFail value changed",
  4907: "Auditing settings on object changed",
  4908: "Special Groups Logon table modified",
  4909: "Local policy settings (TBS) changed",
  4910: "Group policy settings (TBS) changed",
  4911: "Resource attributes on object changed",
  4912: "Per-user audit policy changed",
  4913: "Central Access Policy on object changed",
  4928: "AD replication source naming context established",
  4929: "AD replication source naming context removed",
  4930: "AD replication source naming context modified",
  4931: "AD replication destination naming context modified",
  4932: "AD replication of naming context began",
  4933: "AD replication of naming context ended",
  4934: "AD object attributes replicated",
  4935: "Replication failure begins",
  4936: "Replication failure ends",
  4937: "Lingering object removed from replica",
  5024: "Windows Firewall service started",
  5025: "Windows Firewall service stopped",
  5027: "Windows Firewall could not retrieve security policy",
  5028: "Windows Firewall could not parse new policy",
  5029: "Windows Firewall driver failed to start",
  5030: "Windows Firewall service failed to start",
  5031: "Windows Firewall blocked an application",
  5032: "Windows Firewall could not notify user of block",
  5033: "Windows Firewall driver started",
  5034: "Windows Firewall driver stopped",
  5035: "Windows Firewall driver failed",
  5037: "Windows Firewall driver detected critical runtime error",
  5038: "Code integrity image file hash invalid",
  5039: "Registry key virtualized",
  5051: "File virtualized",
  5056: "Cryptographic self-test performed",
  5057: "Cryptographic primitive operation failed",
  5058: "Key file operation",
  5059: "Key migration operation",
  5061: "Cryptographic operation",
  5062: "Kernel-mode crypto self-test performed",
  5136: "Directory service object modified",
  5137: "Directory service object created",
  5138: "Directory service object undeleted",
  5139: "Directory service object moved",
  5140: "Network share accessed",
  5141: "Directory service object deleted",
  5142: "Network share added",
  5143: "Network share modified",
  5144: "Network share deleted",
  5145: "Network share object accessed (detailed)",
  5146: "WFP blocked a packet",
  5147: "WFP blocked a more restrictive packet",
  5148: "WFP DoS attack detected",
  5149: "WFP DoS attack subsided",
  5150: "WFP blocked a packet",
  5151: "More restrictive WFP filter blocked packet",
  5152: "WFP blocked a packet",
  5153: "Default WFP filter blocked packet",
  5154: "WFP permitted application to listen",
  5155: "WFP blocked application from listening",
  5156: "WFP permitted connection",
  5157: "WFP blocked connection",
  5158: "WFP permitted bind",
  5159: "WFP blocked bind",
  5168: "SPN check for SMB/SMB2 failed",
  5376: "Credential Manager backup",
  5377: "Credential Manager restore",
  5378: "Requested credential delegation disallowed",
  5379: "Credential Manager: credentials read",
  5380: "Vault Find Credential",
  5381: "Vault credentials read",
  5382: "Vault credentials read",
  5447: "WFP filter changed",
  5478: "IPsec Services started",
  5479: "IPsec Services shut down",
  5483: "IPsec Services failed to initialize RPC",
  5484: "IPsec Services critical failure",
  5485: "IPsec Services failed to process filters",
  5632: "Wireless network association requested",
  5633: "Wired network association requested",
  5712: "RPC attempted",
  5888: "COM+ object in catalog modified",
  5889: "COM+ object removed from catalog",
  5890: "COM+ object added to catalog",
  6144: "Group Policy security settings applied",
  6145: "Errors when processing Group Policy security",
  6272: "NPS granted access",
  6273: "NPS denied access",
  6274: "NPS discarded request",
  6275: "NPS discarded accounting request",
  6276: "NPS quarantined user",
  6277: "NPS granted access (quarantine)",
  6278: "NPS granted full access (health check)",
  6279: "NPS account locked",
  6280: "NPS account unlocked",
  6281: "Code integrity invalid page hashes",
  6400: "BranchCache message error",
  6401: "BranchCache: invalid hash data",
  6402: "BranchCache: improperly formatted hashes",
  6403: "BranchCache: improperly formatted response",
  6404: "BranchCache: hosted cache cert validation failed",
  6405: "BranchCache: bulk events",
  6406: "BranchCache: registered with firewall",
  6407: "BranchCache: error registering with firewall",
  6408: "BranchCache: registered as content server",
  6409: "BranchCache: could not start",
  6410: "Code integrity image file unreadable",
  6416: "New external device recognized",
  6417: "FIPS mode crypto self-test successful",
  6418: "Device installation blocked by policy",
  6419: "Request to disable a device",
  6420: "Device disabled",
  6421: "Request to enable a device",
  6422: "Device enabled",
  6423: "Installation of device forbidden by policy",
  6424: "Device installation allowed after previously forbidden",
};

const SYSTEM_NAMES: Record<number, string> = {
  // Kernel-General / Power
  1: "System time changed",
  12: "Operating system started",
  13: "Operating system shutting down",
  41: "System rebooted without clean shutdown",
  42: "System entering sleep",
  43: "Installation started",
  104: "Log cleared",
  1074: "System shutdown initiated",
  1076: "Shutdown reason supplied",
  6005: "Event log service started",
  6006: "Event log service stopped",
  6008: "Unexpected shutdown",
  6009: "OS boot information",
  6013: "System uptime",
  // Service Control Manager
  7000: "Service failed to start",
  7001: "Service depends on another service that failed",
  7009: "Service start timeout",
  7011: "Service did not respond in time",
  7022: "Service hung at start",
  7023: "Service terminated with error",
  7024: "Service terminated with service-specific error",
  7025: "At least one service failed during startup",
  7026: "Boot-start or system-start drivers failed",
  7030: "Service marked interactive but not allowed",
  7031: "Service terminated unexpectedly",
  7032: "Service Control Manager corrective action",
  7034: "Service crashed",
  7035: "Service control command sent",
  7036: "Service state change",
  7039: "Service start attempted in different account context",
  7040: "Service start type changed",
  7041: "Service start type changed",
  7042: "Stop control sent to service",
  7043: "Service did not shut down properly",
  7045: "Service installed",
};

const SYSMON_NAMES: Record<number, string> = {
  1: "Process create",
  2: "File creation time changed",
  3: "Network connection",
  4: "Sysmon service state",
  5: "Process terminated",
  6: "Driver loaded",
  7: "Image loaded",
  8: "CreateRemoteThread",
  9: "RawAccessRead",
  10: "ProcessAccess",
  11: "FileCreate",
  12: "Registry object created/deleted",
  13: "Registry value set",
  14: "Registry key/value renamed",
  15: "FileCreateStreamHash",
  16: "Sysmon config changed",
  17: "Pipe created",
  18: "Pipe connected",
  19: "WMI event filter",
  20: "WMI event consumer",
  21: "WMI consumer-to-filter binding",
  22: "DNS query",
  23: "FileDelete (archived)",
  24: "Clipboard change",
  25: "Process tampering",
  26: "FileDelete (logged only)",
  27: "FileBlockExecutable",
  28: "FileBlockShredding",
  29: "FileExecutableDetected",
  255: "Sysmon internal error",
};

const POWERSHELL_NAMES: Record<number, string> = {
  // Microsoft-Windows-PowerShell/Operational
  4100: "PowerShell error record",
  4101: "PowerShell warning record",
  4102: "PowerShell verbose record",
  4103: "Module logging — pipeline execution",
  4104: "Script block logging",
  4105: "Script block invocation start",
  4106: "Script block invocation end",
  // Windows PowerShell classic log
  400: "Engine state changed (started)",
  403: "Engine state changed (stopped)",
  600: "Provider lifecycle",
  800: "Pipeline execution details",
  53504: "Authenticating user",
};

const DEFENDER_NAMES: Record<number, string> = {
  1000: "Scan started",
  1001: "Scan completed",
  1002: "Scan stopped before completion",
  1006: "Malware detected",
  1007: "Action taken on malware",
  1008: "Action on malware failed",
  1009: "Item restored from quarantine",
  1010: "Could not restore item",
  1011: "Item deleted from quarantine",
  1012: "Could not delete item from quarantine",
  1013: "History deleted",
  1015: "Suspicious behaviour detected",
  1116: "Malware detected",
  1117: "Action taken on malware",
  1118: "Action on malware failed",
  1119: "Critical error on malware action",
  1150: "Endpoint health report",
  2000: "Antimalware platform updated",
  2001: "Antimalware platform update failed",
  2002: "Antimalware engine updated",
  2003: "Antimalware engine update failed",
  2004: "Signature reverted",
  2010: "Antimalware platform load failed",
  2011: "Antimalware platform check failed",
  2030: "Limited periodic scanning updated",
  3002: "Real-time protection error",
  5000: "Real-time protection enabled",
  5001: "Real-time protection disabled",
  5004: "Real-time protection config changed",
  5007: "Configuration changed",
  5010: "Antimalware scanning disabled",
  5011: "Antimalware scanning enabled",
  5012: "Antispyware scanning disabled",
  5013: "Antispyware scanning enabled",
};

const APPLOCKER_NAMES: Record<number, string> = {
  // EXE/DLL channel
  8001: "AppLocker policy applied (no rules)",
  8002: "Allowed by AppLocker (exe/dll)",
  8003: "Audited (would have been blocked) — exe/dll",
  8004: "Blocked by AppLocker (exe/dll)",
  // MSI/Script channel
  8005: "Allowed by AppLocker (script/msi)",
  8006: "Audited (would have been blocked) — script/msi",
  8007: "Blocked by AppLocker (script/msi)",
  // Packaged apps
  8020: "Packaged app allowed by AppLocker",
  8021: "Packaged app audited by AppLocker",
  8022: "Packaged app blocked by AppLocker",
  8023: "Packaged app deployment allowed",
  8024: "Packaged app deployment audited",
  8025: "Packaged app deployment blocked",
};

const TASK_SCHEDULER_NAMES: Record<number, string> = {
  100: "Task started",
  101: "Task start failed",
  102: "Task completed",
  103: "Action start failed",
  104: "Logon failure",
  106: "Task registered",
  107: "Task triggered on schedule",
  108: "Task triggered on event",
  110: "Task triggered by user",
  111: "Task terminated",
  118: "Task triggered by computer startup",
  119: "Task triggered on logon",
  129: "Task process created",
  140: "Task updated",
  141: "Task deleted",
  142: "Task disabled",
  200: "Action started",
  201: "Action completed",
  202: "Action failed to complete",
  203: "Action failed to start",
  314: "Task missed scheduled time",
  322: "Launch refused — already running",
};

const RDP_LOCAL_NAMES: Record<number, string> = {
  // Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
  21: "Session logon succeeded",
  22: "Shell start notification",
  23: "Session logoff succeeded",
  24: "Session disconnected",
  25: "Session reconnection succeeded",
  39: "Session disconnected by another session",
  40: "Session disconnect reason",
  41: "Session begin reconnect",
  42: "Session reconnect succeeded",
};

const RDP_REMOTE_NAMES: Record<number, string> = {
  // Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
  261: "Listener received connection",
  1149: "Remote desktop authentication succeeded",
};

const RDP_CORE_NAMES: Record<number, string> = {
  // Microsoft-Windows-RemoteDesktopServices-RdpCoreTS / RDPClient
  65: "Connection state changed",
  98: "Connection complete",
  131: "Connection established",
  140: "Connection from client failed",
};

const WMI_ACTIVITY_NAMES: Record<number, string> = {
  // Microsoft-Windows-WMI-Activity/Operational
  5857: "WMI provider started",
  5858: "WMI operation error",
  5859: "Notification query subscription",
  5860: "Temporary subscription registered",
  5861: "Permanent subscription created",
};

const FIREWALL_NAMES: Record<number, string> = {
  // Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
  2002: "Setting in profile changed",
  2003: "Firewall setting changed",
  2004: "Firewall rule added",
  2005: "Firewall rule changed",
  2006: "Firewall rule deleted",
  2009: "Failed to load IPsec settings",
  2010: "Network profile changed",
  2011: "Could not notify user of block",
  2033: "Group policy IPsec settings ignored",
  2052: "All firewall rules deleted",
};

const BITS_NAMES: Record<number, string> = {
  3: "BITS job created",
  4: "BITS transfer error",
  16403: "BITS started",
  59: "BITS job started",
  60: "BITS job cancelled",
  61: "BITS job resumed",
};

const SMB_SERVER_NAMES: Record<number, string> = {
  1006: "SMB server denied access",
  1009: "SMB session timed out",
  1011: "SMB share opened",
  31001: "Failed authentication to SMB server",
};

const SMB_CLIENT_NAMES: Record<number, string> = {
  30801: "SMB client timeout",
  30803: "Network connection disconnected",
  30804: "Network connection failed",
};

const WLAN_NAMES: Record<number, string> = {
  8000: "WLAN connection started",
  8001: "WLAN connection succeeded",
  8002: "WLAN connection failed",
  8003: "WLAN disconnected",
  11000: "WLAN association started",
  11001: "WLAN association succeeded",
  11002: "WLAN association failed",
};

export function eventName(
  eventId: number | null,
  provider: string | null,
): string | null {
  if (eventId == null) return null;
  const hint = providerHint(provider);
  switch (hint) {
    case "sysmon":
      return SYSMON_NAMES[eventId] ?? null;
    case "powershell":
      return POWERSHELL_NAMES[eventId] ?? null;
    case "defender":
      return DEFENDER_NAMES[eventId] ?? null;
    case "appLocker":
      return APPLOCKER_NAMES[eventId] ?? null;
    case "taskScheduler":
      return TASK_SCHEDULER_NAMES[eventId] ?? null;
    case "rdpLocal":
      return RDP_LOCAL_NAMES[eventId] ?? null;
    case "rdpRemote":
      return RDP_REMOTE_NAMES[eventId] ?? null;
    case "rdpCore":
      return RDP_CORE_NAMES[eventId] ?? null;
    case "wmiActivity":
      return WMI_ACTIVITY_NAMES[eventId] ?? null;
    case "firewall":
      return FIREWALL_NAMES[eventId] ?? null;
    case "bits":
      return BITS_NAMES[eventId] ?? null;
    case "smbServer":
      return SMB_SERVER_NAMES[eventId] ?? null;
    case "smbClient":
      return SMB_CLIENT_NAMES[eventId] ?? null;
    case "wlan":
      return WLAN_NAMES[eventId] ?? null;
    case "security":
      return SECURITY_NAMES[eventId] ?? null;
    case "system":
      return SYSTEM_NAMES[eventId] ?? null;
    default:
      return (
        SECURITY_NAMES[eventId] ??
        SYSTEM_NAMES[eventId] ??
        POWERSHELL_NAMES[eventId] ??
        null
      );
  }
}

const SECURITY_SUMMARY: Record<number, string[]> = {
  1102: ["SubjectUserName"],
  4616: ["SubjectUserName", "PreviousTime", "NewTime"],
  4624: ["TargetUserName", "LogonType", "IpAddress", "WorkstationName"],
  4625: ["TargetUserName", "LogonType", "IpAddress", "Status", "SubStatus"],
  4634: ["TargetUserName", "LogonType"],
  4647: ["TargetUserName"],
  4648: ["TargetUserName", "TargetServerName", "IpAddress"],
  4656: ["ObjectName", "ObjectType", "AccessMask"],
  4657: ["ObjectName", "OldValue", "NewValue"],
  4658: ["ObjectName"],
  4660: ["ObjectName"],
  4663: ["ObjectName", "AccessMask", "SubjectUserName"],
  4670: ["ObjectName", "SubjectUserName"],
  4672: ["SubjectUserName", "PrivilegeList"],
  4673: ["SubjectUserName", "Service"],
  4688: [
    "NewProcessName",
    "CommandLine",
    "ParentProcessName",
    "SubjectUserName",
  ],
  4689: ["ProcessName", "SubjectUserName", "Status"],
  4696: ["TargetProcessName", "SubjectUserName"],
  4697: ["ServiceName", "ServiceFileName", "ServiceType", "ServiceStartType"],
  4698: ["TaskName", "TaskContent", "SubjectUserName"],
  4699: ["TaskName", "SubjectUserName"],
  4700: ["TaskName"],
  4701: ["TaskName"],
  4702: ["TaskName", "TaskContent"],
  4704: ["TargetSid", "PrivilegeList"],
  4705: ["TargetSid", "PrivilegeList"],
  4717: ["TargetSid", "AccessGranted"],
  4719: ["SubcategoryGuid", "AuditPolicyChanges"],
  4720: ["TargetUserName"],
  4722: ["TargetUserName"],
  4723: ["TargetUserName"],
  4724: ["TargetUserName"],
  4725: ["TargetUserName"],
  4726: ["TargetUserName"],
  4727: ["TargetUserName"],
  4728: ["MemberName", "TargetUserName"],
  4729: ["MemberName", "TargetUserName"],
  4730: ["TargetUserName"],
  4731: ["TargetUserName"],
  4732: ["MemberName", "TargetUserName"],
  4733: ["MemberName", "TargetUserName"],
  4734: ["TargetUserName"],
  4737: ["TargetUserName"],
  4738: ["TargetUserName", "SamAccountName"],
  4740: ["TargetUserName", "TargetDomainName"],
  4741: ["TargetUserName"],
  4742: ["TargetUserName"],
  4743: ["TargetUserName"],
  4756: ["MemberName", "TargetUserName"],
  4757: ["MemberName", "TargetUserName"],
  4767: ["TargetUserName"],
  4768: ["TargetUserName", "IpAddress", "Status"],
  4769: ["TargetUserName", "IpAddress", "ServiceName", "Status"],
  4770: ["TargetUserName", "ServiceName"],
  4771: ["TargetUserName", "IpAddress", "Status"],
  4776: ["TargetUserName", "Workstation", "Status"],
  4778: ["AccountName", "ClientName", "ClientAddress"],
  4779: ["AccountName", "ClientName", "ClientAddress"],
  4781: ["OldTargetUserName", "NewTargetUserName"],
  4782: ["TargetUserName"],
  4793: ["TargetUserName"],
  4798: ["TargetUserName"],
  4799: ["TargetUserName", "TargetSid"],
  4800: ["TargetUserName"],
  4801: ["TargetUserName"],
  4825: ["AccountName", "ClientAddress"],
  5136: ["ObjectDN", "AttributeLDAPDisplayName", "AttributeValue"],
  5137: ["ObjectDN"],
  5140: ["ShareName", "IpAddress", "AccessMask"],
  5141: ["ObjectDN"],
  5142: ["ShareName"],
  5144: ["ShareName"],
  5145: ["ShareName", "RelativeTargetName", "AccessMask"],
  5152: ["Application", "SourceAddress", "DestAddress", "DestPort"],
  5154: ["Application", "SourcePort", "Protocol"],
  5155: ["Application", "SourcePort"],
  5156: ["Application", "SourceAddress", "DestAddress", "DestPort"],
  5157: ["Application", "SourceAddress", "DestAddress", "DestPort"],
  5158: ["Application", "SourceAddress", "SourcePort"],
  5159: ["Application", "SourcePort"],
  5379: ["SubjectUserName", "TargetName"],
  6416: ["DeviceID", "DeviceDescription", "ClassName"],
  6423: ["DeviceID", "DeviceDescription"],
};

const SYSTEM_SUMMARY: Record<number, string[]> = {
  1: ["NewTime", "OldTime"],
  41: ["BugcheckCode"],
  104: ["Channel", "SubjectUserName"],
  1074: ["param1", "param2", "param5"],
  6005: [],
  6006: [],
  6008: ["param1", "param2"],
  6013: ["param4"],
  7000: ["param1", "param2"],
  7022: ["param1"],
  7023: ["param1", "param2"],
  7024: ["param1", "param2"],
  7031: ["param1", "param2"],
  7034: ["param1"],
  7035: ["param1", "param2"],
  7036: ["param1", "param2"],
  7040: ["param1", "param2", "param3"],
  7041: ["param1", "param2"],
  7045: ["ServiceName", "ImagePath", "ServiceType", "AccountName"],
};

const SYSMON_SUMMARY: Record<number, string[]> = {
  1: ["Image", "CommandLine", "ParentImage"],
  2: ["Image", "TargetFilename"],
  3: ["Image", "DestinationIp", "DestinationPort", "DestinationHostname"],
  4: ["State"],
  5: ["Image"],
  6: ["ImageLoaded", "Signed", "Signature"],
  7: ["Image", "ImageLoaded", "Signed"],
  8: ["SourceImage", "TargetImage", "NewThreadId"],
  9: ["Image", "Device"],
  10: ["SourceImage", "TargetImage", "GrantedAccess"],
  11: ["Image", "TargetFilename"],
  12: ["Image", "TargetObject"],
  13: ["Image", "TargetObject", "Details"],
  14: ["Image", "TargetObject", "NewName"],
  15: ["Image", "TargetFilename"],
  16: ["State", "SchemaVersion"],
  17: ["Image", "PipeName"],
  18: ["Image", "PipeName"],
  19: ["Operation", "User", "EventNamespace", "Name"],
  20: ["Operation", "User", "Name", "Type"],
  21: ["Operation", "User", "Consumer", "Filter"],
  22: ["Image", "QueryName", "QueryResults"],
  23: ["Image", "TargetFilename"],
  24: ["Image", "Session", "ClientInfo"],
  25: ["Image", "Type"],
  26: ["Image", "TargetFilename"],
};

const POWERSHELL_SUMMARY: Record<number, string[]> = {
  4100: ["Error", "UserId"],
  4103: ["UserId", "Payload"],
  4104: ["ScriptBlockText", "Path"],
  800: ["HostApplication", "CommandLine"],
};

const DEFENDER_SUMMARY: Record<number, string[]> = {
  1006: ["Threat Name", "Path", "Action Name"],
  1007: ["Threat Name", "Path", "Action Name"],
  1015: ["Threat Name", "Path", "Detection User"],
  1116: ["Threat Name", "Path", "Detection User"],
  1117: ["Threat Name", "Path", "Action Name"],
  5001: [],
  5007: ["Old Value", "New Value"],
};

const APPLOCKER_SUMMARY: Record<number, string[]> = {
  8002: ["TargetUser", "FileName"],
  8003: ["TargetUser", "FileName"],
  8004: ["TargetUser", "FileName"],
  8005: ["TargetUser", "FileName"],
  8006: ["TargetUser", "FileName"],
  8007: ["TargetUser", "FileName"],
};

const TASK_SCHEDULER_SUMMARY: Record<number, string[]> = {
  100: ["TaskName", "UserContext"],
  101: ["TaskName", "ResultCode"],
  102: ["TaskName", "UserContext"],
  106: ["TaskName", "UserContext"],
  107: ["TaskName"],
  108: ["TaskName"],
  110: ["TaskName", "UserName"],
  118: ["TaskName"],
  119: ["TaskName", "UserName"],
  129: ["TaskName", "ProcessID", "Path"],
  140: ["TaskName", "UserName"],
  141: ["TaskName", "UserName"],
  200: ["TaskName", "ActionName", "TaskInstanceId"],
  201: ["TaskName", "ActionName", "ResultCode"],
  202: ["TaskName", "ActionName", "ResultCode"],
  203: ["TaskName", "ActionName", "ResultCode"],
};

const RDP_LOCAL_SUMMARY: Record<number, string[]> = {
  21: ["User", "SessionID", "Address"],
  22: ["User", "SessionID"],
  23: ["User", "SessionID"],
  24: ["User", "SessionID", "Address"],
  25: ["User", "SessionID", "Address"],
  39: ["TargetSession", "Source"],
  40: ["Session", "Reason"],
};

const RDP_REMOTE_SUMMARY: Record<number, string[]> = {
  261: ["ListenerName", "Address"],
  1149: ["User", "Domain", "IPAddress"],
};

const WMI_ACTIVITY_SUMMARY: Record<number, string[]> = {
  5857: ["Provider", "Operation", "User"],
  5858: ["Operation", "User", "Namespace"],
  5859: ["Query", "User", "Namespace"],
  5860: ["Query", "User"],
  5861: ["EventConsumer", "EventFilter", "Query"],
};

const FIREWALL_SUMMARY: Record<number, string[]> = {
  2003: ["ProfileChanged", "SettingType"],
  2004: ["RuleId", "RuleName", "ApplicationPath"],
  2005: ["RuleId", "RuleName", "ApplicationPath"],
  2006: ["RuleId", "RuleName"],
};

const BITS_SUMMARY: Record<number, string[]> = {
  3: ["jobTitle", "jobOwner", "jobId"],
  4: ["jobTitle", "errorCode"],
  59: ["jobTitle"],
  60: ["jobTitle"],
  61: ["jobTitle"],
};

const SMB_SERVER_SUMMARY: Record<number, string[]> = {
  1006: ["UserName", "ShareName", "ClientName"],
  1009: ["UserName", "ShareName"],
};

const SMB_CLIENT_SUMMARY: Record<number, string[]> = {
  30801: ["ServerName", "ShareName"],
  30803: ["ServerName"],
  30804: ["ServerName", "Reason"],
};

const WLAN_SUMMARY: Record<number, string[]> = {
  8001: ["SSID", "InterfaceGuid", "AuthenticationAlgorithm"],
  8002: ["SSID", "FailureReason"],
  8003: ["SSID"],
};

export function summaryFieldsFor(
  eventId: number | null,
  provider: string | null,
): string[] {
  if (eventId == null) return [];
  const hint = providerHint(provider);
  switch (hint) {
    case "sysmon":
      return SYSMON_SUMMARY[eventId] ?? [];
    case "powershell":
      return POWERSHELL_SUMMARY[eventId] ?? [];
    case "system":
      return SYSTEM_SUMMARY[eventId] ?? [];
    case "security":
      return SECURITY_SUMMARY[eventId] ?? [];
    case "defender":
      return DEFENDER_SUMMARY[eventId] ?? [];
    case "appLocker":
      return APPLOCKER_SUMMARY[eventId] ?? [];
    case "taskScheduler":
      return TASK_SCHEDULER_SUMMARY[eventId] ?? [];
    case "rdpLocal":
      return RDP_LOCAL_SUMMARY[eventId] ?? [];
    case "rdpRemote":
      return RDP_REMOTE_SUMMARY[eventId] ?? [];
    case "wmiActivity":
      return WMI_ACTIVITY_SUMMARY[eventId] ?? [];
    case "firewall":
      return FIREWALL_SUMMARY[eventId] ?? [];
    case "bits":
      return BITS_SUMMARY[eventId] ?? [];
    case "smbServer":
      return SMB_SERVER_SUMMARY[eventId] ?? [];
    case "smbClient":
      return SMB_CLIENT_SUMMARY[eventId] ?? [];
    case "wlan":
      return WLAN_SUMMARY[eventId] ?? [];
    default:
      return SECURITY_SUMMARY[eventId] ?? SYSTEM_SUMMARY[eventId] ?? [];
  }
}
