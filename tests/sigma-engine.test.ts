import { describe, expect, it } from "vitest";

import {
  EventView,
  SigmaCompileError,
  SigmaIndex,
  base64Offsets,
  compileRule,
  parseCondition,
  parseIp,
  utf8Bytes,
  windashVariants,
} from "@/lib/sigma/engine";
import { parseSigmaYaml } from "@/lib/sigma/parse";
import { attackTags, sigmaAttribution, type SigmaEvent, type SigmaRule } from "@/lib/sigma/types";

const SYSMON = "Microsoft-Windows-Sysmon/Operational";

function ev(partial: Partial<SigmaEvent> & { data?: Record<string, string> }): SigmaEvent {
  return {
    eventId: partial.eventId ?? 1,
    provider: partial.provider ?? "Microsoft-Windows-Sysmon",
    channel: partial.channel ?? SYSMON,
    computer: partial.computer ?? "WS01",
    level: partial.level ?? 4,
    recordId: partial.recordId ?? 1,
    pairs: partial.pairs ?? Object.entries(partial.data ?? {}),
  };
}

function rule(detection: Record<string, unknown>, logsource: SigmaRule["logsource"] = { product: "windows", category: "process_creation" }): SigmaRule {
  return { id: "t", title: "t", level: "high", logsource, detection, source: "custom" };
}

/** Does `detection` (condition defaults to `selection`) match the event? */
function hit(detection: Record<string, unknown>, e: SigmaEvent, logsource?: SigmaRule["logsource"]): boolean {
  const det = "condition" in detection ? detection : { ...detection, condition: "selection" };
  const r = compileRule(rule(det, logsource));
  const idx = new SigmaIndex([r]);
  let matched = false;
  idx.evaluate(e, () => (matched = true));
  return matched;
}

const proc = (data: Record<string, string>) => ev({ eventId: 1, data });

describe("sigma modifiers", () => {
  const cmd = proc({ Image: "C:\\Windows\\System32\\cmd.exe", CommandLine: "cmd.exe /c whoami /all" });

  it("plain value is a case-insensitive exact match", () => {
    expect(hit({ selection: { Image: "c:\\windows\\system32\\CMD.EXE" } }, cmd)).toBe(true);
    expect(hit({ selection: { Image: "cmd.exe" } }, cmd)).toBe(false);
  });

  it("contains / startswith / endswith", () => {
    expect(hit({ selection: { "CommandLine|contains": "WHOAMI" } }, cmd)).toBe(true);
    expect(hit({ selection: { "CommandLine|startswith": "cmd.exe /c" } }, cmd)).toBe(true);
    expect(hit({ selection: { "CommandLine|startswith": "/c" } }, cmd)).toBe(false);
    expect(hit({ selection: { "Image|endswith": "\\cmd.exe" } }, cmd)).toBe(true);
    expect(hit({ selection: { "Image|endswith": "\\cmd" } }, cmd)).toBe(false);
  });

  it("value lists are OR, `all` makes them AND", () => {
    expect(hit({ selection: { "CommandLine|contains": ["nope", "whoami"] } }, cmd)).toBe(true);
    expect(hit({ selection: { "CommandLine|contains|all": ["whoami", "/all"] } }, cmd)).toBe(true);
    expect(hit({ selection: { "CommandLine|contains|all": ["whoami", "/priv"] } }, cmd)).toBe(false);
  });

  it("wildcards * and ?, with escaping", () => {
    // `\\*` = literal backslash + wildcard; `\*` alone is a literal star.
    expect(hit({ selection: { Image: "C:\\Windows\\\\*\\cmd.exe" } }, cmd)).toBe(true);
    expect(hit({ selection: { Image: "C:\\Windows*cmd.exe" } }, cmd)).toBe(true);
    expect(hit({ selection: { Image: "C:\\Windows\\*\\cmd.exe" } }, cmd)).toBe(false);
    expect(hit({ selection: { Image: "C:\\Windows\\System3?\\cmd.exe" } }, cmd)).toBe(true);
    expect(hit({ selection: { Image: "C:\\Windows\\System3?\\cm.exe" } }, cmd)).toBe(false);
    const star = proc({ CommandLine: "echo a*b" });
    expect(hit({ selection: { CommandLine: "echo a\\*b" } }, star)).toBe(true);
    expect(hit({ selection: { CommandLine: "echo a\\*b" } }, proc({ CommandLine: "echo axxb" }))).toBe(false);
    expect(hit({ selection: { CommandLine: "echo a*b" } }, proc({ CommandLine: "echo axxb" }))).toBe(true);
  });

  it("re (case-sensitive by default) and re|i, inline (?i)", () => {
    expect(hit({ selection: { "CommandLine|re": "whoami\\s+/all$" } }, cmd)).toBe(true);
    expect(hit({ selection: { "CommandLine|re": "WHOAMI" } }, cmd)).toBe(false);
    expect(hit({ selection: { "CommandLine|re|i": "WHOAMI" } }, cmd)).toBe(true);
    expect(hit({ selection: { "CommandLine|re": "(?i)WHOAMI" } }, cmd)).toBe(true);
  });

  it("cased", () => {
    expect(hit({ selection: { "CommandLine|contains|cased": "whoami" } }, cmd)).toBe(true);
    expect(hit({ selection: { "CommandLine|contains|cased": "WHOAMI" } }, cmd)).toBe(false);
  });

  it("base64 and base64offset (utf8 and utf16le)", () => {
    const b64 = proc({ CommandLine: "powershell -enc aHR0cDovL2V2aWwuZXhhbXBsZQ==" });
    expect(hit({ selection: { "CommandLine|base64|contains": "http://evil.example" } }, b64)).toBe(true);
    expect(hit({ selection: { "CommandLine|base64offset|contains": "evil" } }, b64)).toBe(true);
    expect(hit({ selection: { "CommandLine|base64offset|contains": "good" } }, b64)).toBe(false);
    // "IEX (" UTF-16LE at every alignment.
    expect(base64Offsets(utf8Bytes("http://"))).toEqual(["aHR0cDovL", "h0dHA6Ly", "odHRwOi8v"]);
    const wide = proc({ CommandLine: "powershell -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA" });
    expect(hit({ selection: { "CommandLine|utf16le|base64offset|contains": "IEX (New-Object" } }, wide)).toBe(true);
    expect(hit({ selection: { "CommandLine|wide|base64offset|contains": "New-Object" } }, wide)).toBe(true);
    expect(() => compileRule(rule({ s: { "CommandLine|utf16le|contains": "x" }, condition: "s" }))).toThrow(SigmaCompileError);
  });

  it("windash", () => {
    expect(windashVariants("-enc")).toEqual(["-enc", "/enc", "\u2013enc", "\u2014enc", "\u2015enc"]);
    const slash = proc({ CommandLine: "powershell.exe /EncodedCommand AAAA" });
    const endash = proc({ CommandLine: "powershell.exe \u2013EncodedCommand AAAA" });
    const sel = { selection: { "CommandLine|windash|contains": " -EncodedCommand " } };
    expect(hit(sel, slash)).toBe(true);
    expect(hit(sel, endash)).toBe(true);
    expect(hit(sel, proc({ CommandLine: "powershell.exe EncodedCommand AAAA" }))).toBe(false);
  });

  it("cidr (IPv4, IPv6, v4-mapped)", () => {
    const net = (ip: string) => ev({ eventId: 3, data: { DestinationIp: ip } });
    const ls = { product: "windows", category: "network_connection" };
    const sel = { selection: { "DestinationIp|cidr": ["10.0.0.0/8", "fe80::/10"] } };
    expect(hit(sel, net("10.20.30.40"), ls)).toBe(true);
    expect(hit(sel, net("11.0.0.1"), ls)).toBe(false);
    expect(hit(sel, net("fe80::1c2b:3a4d"), ls)).toBe(true);
    expect(hit(sel, net("2001:db8::1"), ls)).toBe(false);
    expect(hit(sel, net("::ffff:10.1.2.3"), ls)).toBe(true);
    expect(parseIp("::1")?.length).toBe(16);
    expect(parseIp("300.1.1.1")).toBeNull();
    expect(() => compileRule(rule({ s: { "DestinationIp|cidr": "nonsense/8" }, condition: "s" }))).toThrow(SigmaCompileError);
  });

  it("gt / gte / lt / lte", () => {
    const e = ev({ eventId: 3, data: { DestinationPort: "4444" } });
    const ls = { product: "windows", category: "network_connection" };
    expect(hit({ selection: { "DestinationPort|gt": 1024 } }, e, ls)).toBe(true);
    expect(hit({ selection: { "DestinationPort|gte": 4444 } }, e, ls)).toBe(true);
    expect(hit({ selection: { "DestinationPort|lt": 4444 } }, e, ls)).toBe(false);
    expect(hit({ selection: { "DestinationPort|lte": 4444 } }, e, ls)).toBe(true);
  });

  it("exists, null and empty values", () => {
    const e = proc({ Image: "x.exe", Description: "" });
    expect(hit({ selection: { "Image|exists": true } }, e)).toBe(true);
    expect(hit({ selection: { "Company|exists": true } }, e)).toBe(false);
    expect(hit({ selection: { "Company|exists": false } }, e)).toBe(true);
    expect(hit({ selection: { Company: null } }, e)).toBe(true);
    expect(hit({ selection: { Description: null } }, e)).toBe(true);
    expect(hit({ selection: { Image: null } }, e)).toBe(false);
    expect(hit({ selection: { Description: "" } }, e)).toBe(true);
    expect(hit({ selection: { Image: "" } }, e)).toBe(false);
  });

  it("fieldref", () => {
    const same = ev({ eventId: 23, data: { Image: "C:\\a.exe", TargetFilename: "c:\\A.exe" } });
    const diff = ev({ eventId: 23, data: { Image: "C:\\a.exe", TargetFilename: "C:\\b.exe" } });
    const ls = { product: "windows", category: "file_delete" };
    expect(hit({ selection: { "TargetFilename|fieldref": "Image" } }, same, ls)).toBe(true);
    expect(hit({ selection: { "TargetFilename|fieldref": "Image" } }, diff, ls)).toBe(false);
  });

  it("numbers match decimal and hex field values", () => {
    const e = ev({ eventId: 4624, channel: "Security", provider: "Microsoft-Windows-Security-Auditing", data: { LogonType: "3", Status: "0x0" } });
    const ls = { product: "windows", service: "security" };
    expect(hit({ selection: { EventID: 4624, LogonType: 3 } }, e, ls)).toBe(true);
    expect(hit({ selection: { EventID: 4624, LogonType: [2, 10] } }, e, ls)).toBe(false);
    expect(hit({ selection: { Status: 0 } }, e, ls)).toBe(true);
  });

  it("keywords (list, single, `|all`) search every field", () => {
    const e = ev({ eventId: 4104, channel: "Microsoft-Windows-PowerShell/Operational", provider: "Microsoft-Windows-PowerShell", data: { ScriptBlockText: "Invoke-Mimikatz -DumpCreds" } });
    const ls = { product: "windows", service: "powershell" };
    expect(hit({ keywords: ["sekurlsa::", "invoke-mimikatz"], condition: "keywords" }, e, ls)).toBe(true);
    expect(hit({ keywords: "dumpcreds", condition: "keywords" }, e, ls)).toBe(true);
    expect(hit({ keywords: { "|all": ["mimikatz", "dumpcreds"] }, condition: "keywords" }, e, ls)).toBe(true);
    expect(hit({ keywords: { "|all": ["mimikatz", "lsadump"] }, condition: "keywords" }, e, ls)).toBe(false);
  });

  it("rejects unsupported constructs with a reason", () => {
    const bad = (detection: Record<string, unknown>, ls?: SigmaRule["logsource"]) => {
      try {
        compileRule(rule(detection, ls));
        return null;
      } catch (err) {
        return (err as Error).message;
      }
    };
    expect(bad({ s: { "Image|expand": "%x%" }, condition: "s" })).toMatch(/expand/);
    expect(bad({ s: { "Image|nosuch": "x" }, condition: "s" })).toMatch(/unknown modifier/);
    expect(bad({ s: { Image: "x" }, condition: "s | count() by Computer > 5" })).toMatch(/aggregation/);
    expect(bad({ s: { Image: "x" }, condition: "s near t" })).toBeTruthy();
    expect(bad({ s: { Image: "x" }, condition: "missing" })).toMatch(/unknown selection/);
    expect(bad({ s: { "Image|re": "(?<!x" }, condition: "s" })).toMatch(/regular expression/);
    expect(bad({ s: { Image: "x" }, condition: "s" }, { product: "windows", category: "file_access" })).toMatch(/no EVTX source/);
    expect(bad({ s: { Image: "x" }, condition: "s" }, { product: "linux", category: "process_creation" })).toMatch(/not Windows/);
  });
});

describe("sigma conditions", () => {
  const e = proc({ Image: "C:\\x\\rundll32.exe", CommandLine: "rundll32 foo.dll,Entry", ParentImage: "C:\\x\\winword.exe" });
  const sel = {
    sel_img: { "Image|endswith": "\\rundll32.exe" },
    sel_parent: { "ParentImage|endswith": "\\winword.exe" },
    sel_other: { "Image|endswith": "\\regsvr32.exe" },
    filter_ok: { "CommandLine|contains": "shell32.dll" },
    _private: { "Image|endswith": "\\nothing.exe" },
  };
  const c = (condition: string | string[]) => hit({ ...sel, condition }, e);

  it("and / or / not with precedence and parentheses", () => {
    expect(c("sel_img and sel_parent")).toBe(true);
    expect(c("sel_img and sel_other")).toBe(false);
    expect(c("sel_other or sel_img")).toBe(true);
    expect(c("sel_img and not filter_ok")).toBe(true);
    expect(c("not sel_img")).toBe(false);
    // not > and > or: (sel_other and sel_img) or sel_parent
    expect(c("sel_other and sel_img or sel_parent")).toBe(true);
    expect(c("sel_other and (sel_img or sel_parent)")).toBe(false);
    expect(c("not (sel_other or filter_ok) and sel_img")).toBe(true);
  });

  it("1 of / any of / all of / N of with wildcards and them", () => {
    expect(c("1 of sel_*")).toBe(true);
    expect(c("any of sel_*")).toBe(true);
    expect(c("all of sel_*")).toBe(false);
    expect(c("all of sel_i* and all of sel_p*")).toBe(true);
    expect(c("2 of sel_*")).toBe(true);
    expect(c("3 of sel_*")).toBe(false);
    expect(c("1 of them")).toBe(true);
    // `them` ignores selections starting with "_".
    expect(hit({ a: { "Image|endswith": "rundll32.exe" }, _b: { Image: "no" }, condition: "all of them" }, e)).toBe(true);
    expect(c("sel_img and not 1 of filter_*")).toBe(true);
  });

  it("a list of conditions is OR", () => {
    expect(c(["sel_other", "sel_parent"])).toBe(true);
    expect(c(["sel_other", "filter_ok"])).toBe(false);
  });

  it("parser rejects malformed conditions", () => {
    expect(() => parseCondition("a and")).toThrow(SigmaCompileError);
    expect(() => parseCondition("(a or b")).toThrow(SigmaCompileError);
    expect(() => parseCondition("a b")).toThrow(SigmaCompileError);
    expect(parseCondition("not a and b or c")).toEqual({
      t: "or",
      items: [{ t: "and", items: [{ t: "not", item: { t: "sel", name: "a" } }, { t: "sel", name: "b" }] }, { t: "sel", name: "c" }],
    });
  });
});

describe("logsource and field mapping", () => {
  const r = compileRule(rule({ selection: { "Image|endswith": "\\whoami.exe", User: "NT AUTHORITY\\SYSTEM", IntegrityLevel: "System", ParentProcessId: 1234 }, condition: "selection" }));
  const idx = new SigmaIndex([r]);
  const run = (e: SigmaEvent) => {
    let n = 0;
    idx.evaluate(e, () => n++);
    return n;
  };

  it("process_creation runs on Sysmon 1", () => {
    expect(run(proc({ Image: "C:\\Windows\\System32\\whoami.exe", User: "NT AUTHORITY\\SYSTEM", IntegrityLevel: "System", ParentProcessId: "1234" }))).toBe(1);
    // Wrong Event ID / channel never reaches the rule.
    expect(run(ev({ eventId: 3, data: { Image: "C:\\Windows\\System32\\whoami.exe", User: "NT AUTHORITY\\SYSTEM", IntegrityLevel: "System", ParentProcessId: "1234" } }))).toBe(0);
    expect(idx.candidates("application", 1)).toHaveLength(0);
  });

  it("process_creation runs on Security 4688 with Sysmon field names", () => {
    const e = ev({
      eventId: 4688,
      channel: "Security",
      provider: "Microsoft-Windows-Security-Auditing",
      data: {
        SubjectUserName: "WS01$",
        SubjectDomainName: "CORP",
        TargetUserName: "SYSTEM",
        TargetDomainName: "NT AUTHORITY",
        NewProcessName: "C:\\Windows\\System32\\whoami.exe",
        ProcessId: "0x4d2",
        MandatoryLabel: "S-1-16-16384",
        CommandLine: "whoami",
      },
    });
    expect(run(e)).toBe(1);
  });

  it("service rules use the raw EventData names", () => {
    const view = new EventView(ev({ eventId: 4688, channel: "Security", data: { NewProcessName: "a.exe" } }));
    expect(view.get("newprocessname", undefined)).toBe("a.exe");
    expect(view.get("image", undefined)).toBeUndefined();
    expect(view.get("image", "security4688")).toBe("a.exe");
  });

  it("Defender field names with spaces, Sysmon hashes, classic PowerShell Data", () => {
    const v = new EventView(ev({ data: { "Threat Name": "EICAR", Hashes: "SHA1=AB,MD5=CD,IMPHASH=EF" } }));
    expect(v.get("threatname", undefined)).toBe("EICAR");
    expect(v.get("imphash", undefined)).toBe("EF");
    expect(v.get("md5", undefined)).toBe("CD");
    const classic = new EventView(
      ev({
        eventId: 400,
        channel: "Windows PowerShell",
        provider: "PowerShell",
        pairs: [["Data1", "Available"], ["Data2", "None"], ["Data3", "\tNewEngineState=Available\n\tHostName=ConsoleHost\n\tHostApplication=powershell.exe -nop -w hidden"]],
      }),
    );
    expect(classic.get("data", undefined)).toContain("HostApplication=powershell.exe");
    expect(classic.get("hostapplication", undefined)).toBe("powershell.exe -nop -w hidden");
  });

  it("indexes by Event IDs required by the detection", () => {
    const sec = compileRule(
      rule({ a: { EventID: 4624, LogonType: 10 }, b: { EventID: [4625, 4771] }, condition: "a or b" }, { product: "windows", service: "security" }),
    );
    expect([...(sec.eventIds ?? [])].sort()).toEqual([4624, 4625, 4771]);
    const any = compileRule(rule({ a: { EventID: 4624 }, b: { Foo: "x" }, condition: "a or b" }, { product: "windows", service: "security" }));
    expect(any.eventIds).toBeNull();
    const and = compileRule(rule({ a: { EventID: [4624, 4625] }, f: { EventID: 4625 }, condition: "a and not f" }, { product: "windows", service: "security" }));
    expect([...(and.eventIds ?? [])].sort()).toEqual([4624, 4625]);
  });
});

describe("custom YAML rules", () => {
  it("parses, validates and reports errors per document", () => {
    const { rules, errors } = parseSigmaYaml(`title: Whoami
id: 11111111-2222-3333-4444-555555555555
author: Analyst
level: medium
logsource: { product: windows, category: process_creation }
detection:
  selection:
    Image|endswith: '\\whoami.exe'
  condition: selection
---
title: Broken
logsource: { product: windows, category: process_creation }
detection:
  selection:
    Image|foo: x
  condition: selection
---
title: Correlation
correlation: { type: event_count, rules: [x], group-by: [User], timespan: 5m, condition: { gte: 10 } }
---
not: [valid
`);
    expect(rules.map((r) => r.title)).toEqual(["Whoami"]);
    expect(rules[0].source).toBe("custom");
    expect(errors.map((e) => e.title)).toEqual(["Broken", "Correlation", "custom-4"]);
    expect(errors[1].reason).toMatch(/correlation/);
  });

  it("attribution and ATT&CK tags", () => {
    expect(sigmaAttribution({ author: "Florian Roth (Nextron Systems)", source: "sigmahq" })).toBe(
      "Rule by Florian Roth (Nextron Systems), SigmaHQ, DRL 1.1",
    );
    expect(attackTags(["attack.execution", "attack.t1059.001", "attack.g0016", "car.2016-04-005"])).toEqual({
      techniques: ["T1059.001"],
      tactics: ["execution"],
    });
  });
});
