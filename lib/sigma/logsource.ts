// Sigma logsource → EVTX mapping.
//
// A Sigma rule names *what* it looks at (`category: process_creation`,
// `service: security`, …), not where the record lives. This table resolves
// those names to the EVTX channel(s) and, for Sysmon-style categories, the
// Event ID(s) that carry them — the same mapping Hayabusa, Chainsaw and
// pySigma's Windows pipelines apply. Channels are compared lower-cased.

export const CH = {
  security: "security",
  system: "system",
  application: "application",
  sysmon: "microsoft-windows-sysmon/operational",
  psOperational: "microsoft-windows-powershell/operational",
  psCore: "powershellcore/operational",
  psClassic: "windows powershell",
} as const;

/** One place a logsource can be found: a channel and optional Event IDs. */
export type LogTarget = {
  /** Lower-cased channel name; `null` = any channel. */
  channel: string | null;
  /** Event IDs carrying the category; `null` = every Event ID. */
  eventIds: number[] | null;
  /** Field-mapping profile (e.g. Security 4688 → Sysmon field names). */
  profile?: "security4688";
};

const sysmon = (...ids: number[]): LogTarget => ({ channel: CH.sysmon, eventIds: ids });
const powershell = (...ids: number[]): LogTarget[] => [
  { channel: CH.psOperational, eventIds: ids },
  { channel: CH.psCore, eventIds: ids },
];

/** `category:` → targets. Categories absent here have no EVTX source. */
export const CATEGORY_TARGETS: Record<string, LogTarget[]> = {
  process_creation: [
    sysmon(1),
    // Native process auditing; fields are renamed by the "security4688"
    // profile (NewProcessName → Image, ParentProcessName → ParentImage, …).
    { channel: CH.security, eventIds: [4688], profile: "security4688" },
  ],
  process_termination: [sysmon(5)],
  network_connection: [sysmon(3)],
  sysmon_status: [sysmon(4, 16)],
  sysmon_error: [sysmon(255)],
  driver_load: [sysmon(6)],
  image_load: [sysmon(7)],
  create_remote_thread: [sysmon(8)],
  raw_access_thread: [sysmon(9)],
  process_access: [sysmon(10)],
  file_event: [sysmon(11)],
  file_change: [sysmon(2)],
  registry_event: [sysmon(12, 13, 14)],
  registry_add: [sysmon(12)],
  registry_delete: [sysmon(12)],
  registry_set: [sysmon(13)],
  registry_rename: [sysmon(14)],
  create_stream_hash: [sysmon(15)],
  pipe_created: [sysmon(17, 18)],
  wmi_event: [sysmon(19, 20, 21)],
  dns_query: [sysmon(22)],
  file_delete: [sysmon(23, 26)],
  clipboard_capture: [sysmon(24)],
  process_tampering: [sysmon(25)],
  file_delete_detected: [sysmon(26)],
  file_block_executable: [sysmon(27)],
  file_block_shredding: [sysmon(28)],
  file_executable_detected: [sysmon(29)],
  ps_module: powershell(4103),
  ps_script: powershell(4104),
  ps_classic_start: [{ channel: CH.psClassic, eventIds: [400] }],
  ps_classic_provider_start: [{ channel: CH.psClassic, eventIds: [600] }],
  ps_classic_script: [{ channel: CH.psClassic, eventIds: [800] }],
};

/**
 * `service:` → channel(s). Event IDs come from the rule's detection (they
 * are narrowed later from `EventID:` selections for indexing).
 */
export const SERVICE_CHANNELS: Record<string, string[]> = {
  security: [CH.security],
  system: [CH.system],
  application: [CH.application],
  sysmon: [CH.sysmon],
  powershell: [CH.psOperational, CH.psCore],
  "powershell-classic": [CH.psClassic],
  windefend: ["microsoft-windows-windows defender/operational"],
  "codeintegrity-operational": ["microsoft-windows-codeintegrity/operational"],
  "appxdeployment-server": ["microsoft-windows-appxdeploymentserver/operational"],
  "appxpackaging-om": ["microsoft-windows-appxpackaging/operational"],
  "appmodel-runtime": ["microsoft-windows-appmodel-runtime/admin"],
  "firewall-as": ["microsoft-windows-windows firewall with advanced security/firewall"],
  "bits-client": ["microsoft-windows-bits-client/operational"],
  "msexchange-management": ["msexchange management"],
  "dns-client": ["microsoft-windows-dns client events/operational"],
  "dns-server": ["dns server"],
  "dns-server-analytic": ["microsoft-windows-dns-server/analytical"],
  "dns-server-audit": ["microsoft-windows-dns-server/audit"],
  "iis-configuration": ["microsoft-iis-configuration/operational"],
  ntlm: ["microsoft-windows-ntlm/operational"],
  taskscheduler: ["microsoft-windows-taskscheduler/operational"],
  applocker: [
    "microsoft-windows-applocker/exe and dll",
    "microsoft-windows-applocker/msi and script",
    "microsoft-windows-applocker/packaged app-deployment",
    "microsoft-windows-applocker/packaged app-execution",
  ],
  "security-mitigations": [
    "microsoft-windows-security-mitigations/kernel mode",
    "microsoft-windows-security-mitigations/user mode",
  ],
  wmi: ["microsoft-windows-wmi-activity/operational"],
  capi2: ["microsoft-windows-capi2/operational"],
  "certificateservicesclient-lifecycle-system": [
    "microsoft-windows-certificateservicesclient-lifecycle-system/operational",
  ],
  "diagnosis-scripted": ["microsoft-windows-diagnosis-scripted/operational"],
  "driver-framework": ["microsoft-windows-driverframeworks-usermode/operational"],
  ldap: ["microsoft-windows-ldap-client/debug"],
  ldap_debug: ["microsoft-windows-ldap-client/debug"],
  "lsa-server": ["microsoft-windows-lsa/operational"],
  openssh: ["openssh/operational"],
  "microsoft-servicebus-client": ["microsoft-servicebus-client"],
  "shell-core": ["microsoft-windows-shell-core/operational"],
  "smbclient-security": ["microsoft-windows-smbclient/security"],
  "smbclient-connectivity": ["microsoft-windows-smbclient/connectivity"],
  "smbserver-connectivity": ["microsoft-windows-smbserver/connectivity"],
  "smbserver-security": ["microsoft-windows-smbserver/security"],
  "terminalservices-localsessionmanager": [
    "microsoft-windows-terminalservices-localsessionmanager/operational",
  ],
  "terminalservices-remoteconnectionmanager": [
    "microsoft-windows-terminalservices-remoteconnectionmanager/operational",
  ],
  "rdp-corets": ["microsoft-windows-remotedesktopservices-rdpcorets/operational"],
  "printservice-admin": ["microsoft-windows-printservice/admin"],
  "printservice-operational": ["microsoft-windows-printservice/operational"],
  "dhcp": ["microsoft-windows-dhcp-server/operational"],
  vhdmp: ["microsoft-windows-vhdmp/operational"],
  "kernel-shimengine": ["microsoft-windows-kernel-shimengine/operational"],
  "hyper-v-worker": ["microsoft-windows-hyper-v-worker-admin"],
  "bitlocker": ["microsoft-windows-bitlocker/bitlocker management"],
  "wmi-activity": ["microsoft-windows-wmi-activity/operational"],
  "winrm": ["microsoft-windows-winrm/operational"],
  "ntfs": ["microsoft-windows-ntfs/operational"],
};

export type LogsourceSpec = {
  product?: string;
  category?: string;
  service?: string;
};

/**
 * Resolve a rule's logsource to EVTX targets, or a reason it can't run on
 * event logs (e.g. ETW-only categories like `file_access`).
 */
export function resolveLogsource(
  ls: LogsourceSpec | undefined,
): { targets: LogTarget[] } | { unsupported: string } {
  const product = ls?.product?.toLowerCase();
  if (product && product !== "windows")
    return { unsupported: `logsource product "${ls?.product}" is not Windows` };
  const category = ls?.category?.toLowerCase();
  const service = ls?.service?.toLowerCase();
  if (category && service)
    return { unsupported: `logsource with both category and service is not mapped` };
  if (category) {
    const t = CATEGORY_TARGETS[category];
    if (!t) return { unsupported: `category "${category}" has no EVTX source` };
    return { targets: t };
  }
  if (service) {
    const chans = SERVICE_CHANNELS[service];
    if (!chans) return { unsupported: `service "${service}" is not mapped to an EVTX channel` };
    return { targets: chans.map((channel) => ({ channel, eventIds: null })) };
  }
  // `product: windows` alone: every Windows event (the detection narrows it).
  return { targets: [{ channel: null, eventIds: null }] };
}

/**
 * The canonical (lower-cased) channel an event is indexed under. Falls back
 * to the provider for the few sources whose channel may be missing or
 * rewritten (e.g. Sysmon forwarded with a custom channel).
 */
export function canonicalChannel(
  channel: string | null | undefined,
  provider: string | null | undefined,
): string {
  const c = (channel ?? "").toLowerCase();
  if (c) return c;
  const p = (provider ?? "").toLowerCase();
  if (p === "microsoft-windows-sysmon") return CH.sysmon;
  if (p === "microsoft-windows-security-auditing") return CH.security;
  if (p === "microsoft-windows-powershell") return CH.psOperational;
  return "";
}
