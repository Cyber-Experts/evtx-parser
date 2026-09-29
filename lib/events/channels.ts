// Channels covered by the Event ID encyclopedia (data/events/<slug>/).
//
// The slug is the URL segment (/en/events/<slug>/<id>) and the folder name.
// `names` are the EVTX channel names (as written in <Channel>) that map to the
// slug; the first one is the canonical name shown on the page. Kept free of
// runtime dependencies so the viewer can import it.

export type EventChannel = {
  slug: string;
  /** Channel names as they appear in the <Channel> element; [0] = canonical. */
  names: string[];
  /** Short, human label ("Sysmon", "Security"). */
  label: string;
  /** Prefix for page titles: "Sysmon Event ID 1". Empty for Security. */
  seoPrefix: string;
  /** Default provider for the channel (events may override). */
  provider: string;
  /** File name under %SystemRoot%\System32\winevt\Logs. */
  file: string;
};

export const EVENT_CHANNELS: EventChannel[] = [
  {
    slug: "security",
    names: ["Security"],
    label: "Security",
    seoPrefix: "",
    provider: "Microsoft-Windows-Security-Auditing",
    file: "Security.evtx",
  },
  {
    slug: "system",
    names: ["System"],
    label: "System",
    seoPrefix: "System",
    provider: "Service Control Manager",
    file: "System.evtx",
  },
  {
    slug: "application",
    names: ["Application"],
    label: "Application",
    seoPrefix: "Application",
    provider: "Application Error",
    file: "Application.evtx",
  },
  {
    slug: "sysmon",
    names: ["Microsoft-Windows-Sysmon/Operational"],
    label: "Sysmon",
    seoPrefix: "Sysmon",
    provider: "Microsoft-Windows-Sysmon",
    file: "Microsoft-Windows-Sysmon%4Operational.evtx",
  },
  {
    slug: "powershell",
    names: ["Microsoft-Windows-PowerShell/Operational", "PowerShellCore/Operational"],
    label: "PowerShell Operational",
    seoPrefix: "PowerShell",
    provider: "Microsoft-Windows-PowerShell",
    file: "Microsoft-Windows-PowerShell%4Operational.evtx",
  },
  {
    slug: "windows-powershell",
    names: ["Windows PowerShell"],
    label: "Windows PowerShell",
    seoPrefix: "PowerShell",
    provider: "PowerShell",
    file: "Windows PowerShell.evtx",
  },
  {
    slug: "task-scheduler",
    names: ["Microsoft-Windows-TaskScheduler/Operational"],
    label: "Task Scheduler",
    seoPrefix: "Task Scheduler",
    provider: "Microsoft-Windows-TaskScheduler",
    file: "Microsoft-Windows-TaskScheduler%4Operational.evtx",
  },
  {
    slug: "rdp-local-session-manager",
    names: ["Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"],
    label: "RDP LocalSessionManager",
    seoPrefix: "RDP",
    provider: "Microsoft-Windows-TerminalServices-LocalSessionManager",
    file: "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
  },
  {
    slug: "rdp-remote-connection-manager",
    names: ["Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"],
    label: "RDP RemoteConnectionManager",
    seoPrefix: "RDP",
    provider: "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
    file: "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
  },
  {
    slug: "rdp-client",
    names: ["Microsoft-Windows-TerminalServices-RDPClient/Operational"],
    label: "RDP Client",
    seoPrefix: "RDP client",
    provider: "Microsoft-Windows-TerminalServices-ClientActiveXCore",
    file: "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",
  },
  {
    slug: "rdp-core-ts",
    names: ["Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"],
    label: "RDP RdpCoreTS",
    seoPrefix: "RDP",
    provider: "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
    file: "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
  },
  {
    slug: "wmi-activity",
    names: ["Microsoft-Windows-WMI-Activity/Operational"],
    label: "WMI-Activity",
    seoPrefix: "WMI",
    provider: "Microsoft-Windows-WMI-Activity",
    file: "Microsoft-Windows-WMI-Activity%4Operational.evtx",
  },
  {
    slug: "defender",
    names: ["Microsoft-Windows-Windows Defender/Operational"],
    label: "Microsoft Defender",
    seoPrefix: "Defender",
    provider: "Microsoft-Windows-Windows Defender",
    file: "Microsoft-Windows-Windows Defender%4Operational.evtx",
  },
  {
    slug: "bits-client",
    names: ["Microsoft-Windows-Bits-Client/Operational"],
    label: "BITS Client",
    seoPrefix: "BITS",
    provider: "Microsoft-Windows-Bits-Client",
    file: "Microsoft-Windows-Bits-Client%4Operational.evtx",
  },
  {
    slug: "winrm",
    names: ["Microsoft-Windows-WinRM/Operational"],
    label: "WinRM",
    seoPrefix: "WinRM",
    provider: "Microsoft-Windows-WinRM",
    file: "Microsoft-Windows-WinRM%4Operational.evtx",
  },
  {
    slug: "applocker",
    names: [
      "Microsoft-Windows-AppLocker/EXE and DLL",
      "Microsoft-Windows-AppLocker/MSI and Script",
      "Microsoft-Windows-AppLocker/Packaged app-Execution",
      "Microsoft-Windows-AppLocker/Packaged app-Deployment",
    ],
    label: "AppLocker",
    seoPrefix: "AppLocker",
    provider: "Microsoft-Windows-AppLocker",
    file: "Microsoft-Windows-AppLocker%4EXE and DLL.evtx",
  },
  {
    slug: "firewall",
    names: ["Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"],
    label: "Windows Firewall",
    seoPrefix: "Firewall",
    provider: "Microsoft-Windows-Windows Firewall With Advanced Security",
    file: "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
  },
  {
    slug: "partition",
    names: ["Microsoft-Windows-Partition/Diagnostic"],
    label: "Partition",
    seoPrefix: "Partition",
    provider: "Microsoft-Windows-Partition",
    file: "Microsoft-Windows-Partition%4Diagnostic.evtx",
  },
  {
    slug: "kernel-pnp",
    names: ["Microsoft-Windows-Kernel-PnP/Configuration"],
    label: "Kernel-PnP",
    seoPrefix: "Kernel-PnP",
    provider: "Microsoft-Windows-Kernel-PnP",
    file: "Microsoft-Windows-Kernel-PnP%4Configuration.evtx",
  },
  {
    slug: "ntlm",
    names: ["Microsoft-Windows-NTLM/Operational"],
    label: "NTLM",
    seoPrefix: "NTLM",
    provider: "Microsoft-Windows-NTLM",
    file: "Microsoft-Windows-NTLM%4Operational.evtx",
  },
  {
    slug: "code-integrity",
    names: ["Microsoft-Windows-CodeIntegrity/Operational"],
    label: "Code Integrity",
    seoPrefix: "Code Integrity",
    provider: "Microsoft-Windows-CodeIntegrity",
    file: "Microsoft-Windows-CodeIntegrity%4Operational.evtx",
  },
  {
    slug: "smb-client",
    names: ["Microsoft-Windows-SMBClient/Security", "Microsoft-Windows-SMBClient/Connectivity"],
    label: "SMB Client",
    seoPrefix: "SMB client",
    provider: "Microsoft-Windows-SMBClient",
    file: "Microsoft-Windows-SMBClient%4Security.evtx",
  },
  {
    slug: "smb-server",
    names: ["Microsoft-Windows-SMBServer/Security", "Microsoft-Windows-SMBServer/Operational"],
    label: "SMB Server",
    seoPrefix: "SMB server",
    provider: "Microsoft-Windows-SMBServer",
    file: "Microsoft-Windows-SMBServer%4Security.evtx",
  },
  {
    slug: "print-service",
    names: ["Microsoft-Windows-PrintService/Operational", "Microsoft-Windows-PrintService/Admin"],
    label: "PrintService",
    seoPrefix: "PrintService",
    provider: "Microsoft-Windows-PrintService",
    file: "Microsoft-Windows-PrintService%4Operational.evtx",
  },
  {
    slug: "dns-client",
    names: ["Microsoft-Windows-DNS-Client/Operational"],
    label: "DNS Client",
    seoPrefix: "DNS client",
    provider: "Microsoft-Windows-DNS-Client",
    file: "Microsoft-Windows-DNS-Client%4Operational.evtx",
  },
  {
    slug: "openssh",
    names: ["OpenSSH/Operational"],
    label: "OpenSSH",
    seoPrefix: "OpenSSH",
    provider: "OpenSSH",
    file: "OpenSSH%4Operational.evtx",
  },
];

const bySlug = new Map(EVENT_CHANNELS.map((c) => [c.slug, c]));
const byName = new Map<string, EventChannel>();
for (const c of EVENT_CHANNELS) for (const n of c.names) byName.set(n.toLowerCase(), c);

export function channelBySlug(slug: string): EventChannel | undefined {
  return bySlug.get(slug);
}

/**
 * Encyclopedia channel for a record's <Channel> (case-insensitive), with a
 * provider fallback for logs whose channel was rewritten on forwarding.
 */
export function channelForRecord(
  channel: string | null | undefined,
  provider?: string | null,
): EventChannel | undefined {
  const hit = channel ? byName.get(channel.trim().toLowerCase()) : undefined;
  if (hit) return hit;
  const p = (provider ?? "").toLowerCase();
  if (p === "microsoft-windows-sysmon") return bySlug.get("sysmon");
  if (p === "microsoft-windows-security-auditing") return bySlug.get("security");
  return undefined;
}

/** Canonical path segment for one entry: "security/4624". */
export function eventKey(slug: string, id: number): string {
  return `${slug}/${id}`;
}

/** Locale-prefixed URL path of an entry: "/en/events/security/4624". */
export function eventPath(locale: string, slug: string, id: number): string {
  return `/${locale}/events/${slug}/${id}`;
}

/** Slugs are lower-case ASCII words separated by single hyphens. */
export const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
