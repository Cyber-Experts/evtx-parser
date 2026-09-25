import { describe, expect, it } from "vitest";

import { decodeValue, decodedText, describeEvent } from "@/lib/event-decode";

import { loadFixtures, HAS_FIXTURES } from "./helpers";

describe("decodeValue", () => {
  it.each([
    ["ImpersonationLevel", "%%1833", "Impersonation"],
    ["ElevatedToken", "%%1842", "Yes"],
    ["VirtualAccount", "%%1843", "No"],
    ["FailureReason", "%%2313", "Unknown user name or bad password"],
    ["TokenElevationType", "%%1937", "Type 2 (elevated token)"],
    [
      "UserAccountControl",
      "\r\n\t\t%%2080\r\n\t\t%%2082\r\n\t\t%%2084",
      "Account Disabled, 'Password Not Required' - Enabled, 'Normal Account' - Enabled",
    ],
    ["LogonType", "10", "RemoteInteractive (RDP)"],
    ["SubStatus", "0xC000006A", "Wrong password"],
    ["Status", "0xc0000064", "User name does not exist"],
    ["Status", "0x18", "Pre-authentication failed (bad password)"],
    ["TicketEncryptionType", "0x00000017", "RC4-HMAC (weak, kerberoasting signal)"],
    ["PreAuthType", "0", "No pre-authentication (AS-REP roastable)"],
    ["Protocol", "6", "TCP"],
  ])("%s=%s → %s", (field, value, want) => {
    expect(decodeValue(field, value)).toBe(want);
  });

  it("leaves unknown or plain values alone", () => {
    expect(decodeValue("x", "%%9999")).toBeNull();
    expect(decodeValue("TargetUserName", "admin")).toBeNull();
    expect(decodeValue("LogonType", "99")).toBeNull();
    expect(decodeValue("x", "")).toBeNull();
  });

  it("keeps unknown codes raw next to known ones", () => {
    expect(decodeValue("AccessList", "%%1537 %%9999")).toBe("DELETE, %%9999");
  });

  it("decodedText joins every decoded label", () => {
    expect(
      decodedText([
        ["LogonType", "2"],
        ["ImpersonationLevel", "%%1833"],
        ["TargetUserName", "bob"],
      ]),
    ).toBe("Interactive (console)\u0001Impersonation");
  });
});

describe.skipIf(!HAS_FIXTURES)("describeEvent on real logs", () => {
  const sec = loadFixtures("security.evtx");
  const byRecord = (n: number) => sec.rows.find((r) => Number(r.record_id) === n)!;
  const describe_ = (n: number) => {
    const r = byRecord(n);
    return describeEvent(r.event_id, r.provider, sec.pairs[r._g]);
  };

  it("covers ≥ 95% of Security.evtx", () => {
    const described = sec.rows.filter((r) =>
      describeEvent(r.event_id, r.provider, sec.pairs[r._g]),
    ).length;
    expect(described).toBe(10275);
    expect(described / sec.rows.length).toBeGreaterThan(0.95);
  });

  it("4720 account created", () => {
    expect(describe_(40)).toBe("User MINWINPC\\WDAGUtilityAccount created by MINWINPC$");
  });

  it("4624 successful logon reads like a sentence", () => {
    const r = sec.rows.find(
      (x) =>
        x.event_id === 4624 &&
        sec.pairs[x._g].some(([k, v]) => k === "TargetLogonId" && v === "0x1707891"),
    )!;
    expect(describeEvent(r.event_id, r.provider, sec.pairs[r._g])).toBe(
      "DESKTOP-3A4NLVQ\\jim.tomato logged on: Interactive (console) from 127.0.0.1 [DESKTOP-3A4NLVQ] via Negotiate",
    );
  });

  it("4616 time change carries both times", () => {
    const r = sec.rows.find((x) => x.event_id === 4616)!;
    expect(describeEvent(r.event_id, r.provider, sec.pairs[r._g])).toMatch(
      /^System time changed from \S+ to \S+ by .+ via .+svchost\.exe$/,
    );
  });

  it("never leaves dangling words when fields are empty", () => {
    for (const r of sec.rows) {
      const d = describeEvent(r.event_id, r.provider, sec.pairs[r._g]);
      if (!d) continue;
      expect(d).not.toMatch(/\b(by|from|via|for)$/);
      expect(d).not.toMatch(/\s{2,}/);
    }
  });

  it("System 7045 service install", () => {
    const sys = loadFixtures("system.evtx");
    const r = sys.rows.find((x) => x.event_id === 7045)!;
    expect(describeEvent(r.event_id, r.provider, sys.pairs[r._g])).toBe(
      "Service Intel(R) PRO/1000 PCI Express Network Connection Driver I installed: \\SystemRoot\\System32\\drivers\\e1i63x64.sys · start demand start",
    );
  });

  it("returns null for providers without templates", () => {
    const app = loadFixtures("application.evtx");
    const described = app.rows.filter((r) =>
      describeEvent(r.event_id, r.provider, app.pairs[r._g]),
    );
    expect(described).toHaveLength(0);
  });
});
