import { describe, expect, it } from "vitest";

import { compileSearch, parseSearch } from "@/lib/search-query";
import {
  buildSessions,
  formatDuration,
  sessionDurationMs,
  sessionQuery,
} from "@/lib/sessions";

import { haystackGetter, loadFixtures } from "./helpers";

describe("logon sessions on Security.evtx", () => {
  const ds = loadFixtures("security.evtx");
  const sessions = buildSessions(ds.rows, ds.pairs);
  const user = sessions.filter((s) => !s.system);
  const byId = (id: string) => sessions.find((s) => s.logonIds.includes(id))!;

  it("finds every session and separates background ones", () => {
    expect(sessions).toHaveLength(87);
    expect(user).toHaveLength(33);
    expect(user.filter((s) => s.admin)).toHaveLength(12);
    // SYSTEM, services, DWM/UMFD and machine accounts are background.
    for (const id of ["0x3e7", "0x3e4"]) expect(byId(id).system).toBe(true);
    expect(sessions.find((s) => s.user.endsWith("\\UMFD-1"))!.system).toBe(true);
  });

  it("reconstructs jim.tomato's interactive session", () => {
    const s = byId("0x1707891");
    expect(s).toMatchObject({
      user: "DESKTOP-3A4NLVQ\\jim.tomato",
      computer: "DESKTOP-3A4NLVQ",
      logonType: "2",
      logonTypeLabel: "Interactive (console)",
      sourceIp: "127.0.0.1",
      authPackage: "Negotiate",
      admin: false,
      endEventId: 4647,
      events: 37,
      logonIds: ["0x1707891"],
    });
    expect(s.start).toBe("2020-04-05T03:51:52.591559+00:00");
    expect(formatDuration(sessionDurationMs(s)!)).toBe("44 min 48 s");
    expect(Object.fromEntries(s.eventIds)).toMatchObject({ 4797: 27, 4798: 8, 4624: 1, 4647: 1 });
  });

  it("merges the two halves of a UAC admin logon", () => {
    const s = byId("0xd480d");
    expect(s.logonIds).toEqual(["0xd480d", "0xd482b"]);
    expect(byId("0xd482b")).toBe(s);
    expect(s.admin).toBe(true);
    expect(s.elevated).toBe(true);
    expect(s.events).toBe(120);
    // The account-management burst belongs to this admin session.
    expect(Object.fromEntries(s.eventIds)).toMatchObject({
      4720: 5,
      4724: 10,
      4728: 5,
      4738: 20,
    });
  });

  it("session queries select exactly the session's events", () => {
    const hay = haystackGetter(ds);
    for (const s of [byId("0x1707891"), byId("0xd480d"), byId("0x39fc7")]) {
      const test = compileSearch(parseSearch(sessionQuery(s)))!;
      const n = ds.rows.filter((r) => test(r, ds.pairs[r._g], () => hay(r))).length;
      expect(n).toBe(s.events);
    }
  });

  it("is sorted by logon time", () => {
    const keys = sessions.map((s) => s.start ?? s.firstSeen);
    expect(keys).toEqual([...keys].sort());
  });

  it("returns nothing for logs without logon events", () => {
    const app = loadFixtures("application.evtx");
    expect(buildSessions(app.rows, app.pairs).filter((s) => !s.system)).toEqual([]);
  });
});

describe("formatDuration", () => {
  it.each([
    [0, "0 s"],
    [12_000, "12 s"],
    [245_000, "4 min 05 s"],
    [3 * 3600_000 + 12 * 60_000, "3 h 12 min"],
    [50 * 3600_000, "2 d 2 h"],
  ])("%i ms → %s", (ms, want) => {
    expect(formatDuration(ms)).toBe(want);
  });
});
