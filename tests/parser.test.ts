import { describe, expect, it } from "vitest";

import { FIXTURE_FILES, loadFixtures, HAS_FIXTURES } from "./helpers";

// Snapshot of the fixture set (see tests/fixtures/evtx/README.md).
const EXPECTED: Record<(typeof FIXTURE_FILES)[number], {
  count: number;
  channel?: string;
  first?: string;
  last?: string;
}> = {
  "security.evtx": {
    count: 10667,
    channel: "Security",
    first: "2020-04-03T02:01:40.424361+00:00",
    last: "2020-04-16T05:08:12.254932+00:00",
  },
  "application.evtx": {
    count: 1934,
    channel: "Application",
    first: "2020-04-03T02:02:01.443565+00:00",
    last: "2020-04-16T05:08:12.277499+00:00",
  },
  "system.evtx": {
    count: 1416,
    channel: "System",
    first: "2020-04-03T02:02:01.240441+00:00",
    last: "2020-04-16T05:08:12.276790+00:00",
  },
  "setup.evtx": {
    count: 24,
    channel: "Setup",
    first: "2020-04-05T03:04:03.092617+00:00",
    last: "2020-04-15T04:10:35.955079+00:00",
  },
  "hardware-events.evtx": { count: 0 },
  "internet-explorer.evtx": { count: 0 },
  "key-management-service.evtx": { count: 0 },
};

describe.skipIf(!HAS_FIXTURES)("WASM parser on real logs", () => {
  for (const name of FIXTURE_FILES) {
    const want = EXPECTED[name];
    it(`${name}: ${want.count} events`, () => {
      const { rows, pairs } = loadFixtures(name);
      expect(rows).toHaveLength(want.count);
      expect(pairs).toHaveLength(want.count);
      if (want.count === 0) return;
      expect(rows[0].timestamp).toBe(want.first);
      expect(rows.at(-1)!.timestamp).toBe(want.last);
      // Record numbers are contiguous from 1 in these (never-cleared) logs.
      expect(Number(rows[0].record_id)).toBe(1);
      expect(Number(rows.at(-1)!.record_id)).toBe(want.count);
      expect(new Set(rows.map((r) => r.channel))).toEqual(new Set([want.channel]));
    });
  }

  it("timestamps keep microsecond precision and are UTC", () => {
    const { rows } = loadFixtures("security.evtx");
    for (const r of rows.slice(0, 200)) {
      expect(r.timestamp).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}\+00:00$/);
    }
  });

  it("Security.evtx Event ID distribution", () => {
    const { rows } = loadFixtures("security.evtx");
    const counts = new Map<number, number>();
    for (const r of rows) counts.set(r.event_id!, (counts.get(r.event_id!) ?? 0) + 1);
    expect(counts.get(4907)).toBe(5222);
    expect(counts.get(4624)).toBe(1219);
    expect(counts.get(4672)).toBe(1147);
    expect(counts.get(4720)).toBe(8);
  });

  it("rebuilds the event XML", () => {
    const { handles } = loadFixtures("security.evtx");
    const xml = handles.get("security.evtx")!.get_xml(BigInt(0));
    expect(xml).toContain('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">');
    expect(xml).toContain("<EventID>4826</EventID>");
  });

  it("flattens UserData events (Setup servicing) into pairs", () => {
    const { rows, pairs } = loadFixtures("setup.evtx");
    expect(rows[0].provider).toBe("Microsoft-Windows-Servicing");
    expect(Object.fromEntries(pairs[0])).toMatchObject({
      PackageIdentifier: "KB4295110",
      InitialPackageStateTextized: "Absent",
      IntendedPackageStateTextized: "Staged",
    });
  });

  it("merges several files with a global index", () => {
    const ds = loadFixtures("security.evtx", "system.evtx", "hardware-events.evtx");
    expect(ds.rows).toHaveLength(10667 + 1416);
    ds.rows.forEach((r, i) => expect(r._g).toBe(i));
    expect(ds.rows[10667]._file).toBe("system.evtx");
  });
});
