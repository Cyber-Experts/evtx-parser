import { describe, expect, it } from "vitest";

import { runDetections } from "@/lib/detections";
import type { EventRow } from "@/lib/evtx-client";
import { buildCsv, buildJson, pairsToRecord } from "@/lib/export";
import {
  ANY_FIELD,
  DAY,
  HOUR,
  MINUTE,
  PRIMARY_FIELD,
  aroundRange,
  buildTimeIndex,
  detectTimeFields,
  filterByRange,
  fromInputValue,
  normalizeRange,
  parseEventTime,
  presetRange,
  rangeFileSuffix,
  rangeFromInputs,
  rangeLabel,
  rangeMatcher,
  readRangeParams,
  toInputValue,
  writeRangeParams,
} from "@/lib/time-range";
import { en } from "@/src/dict/en";

// vitest.config.mts pins TZ=Europe/Paris (UTC+1 winter, UTC+2 summer).

type Row = EventRow & { _g: number; _file: string };

const row = (g: number, timestamp: string, event_id = 4624): Row => ({
  _g: g,
  _file: "Security.evtx",
  record_id: g + 1,
  timestamp,
  level: 4,
  event_id,
  provider: "Microsoft-Windows-Security-Auditing",
  channel: "Security",
  computer: "WS01",
});

// An incident morning; the second record carries Sysmon-style EventData times.
const rows: Row[] = [
  row(0, "2026-09-14T09:59:59.999000+00:00"),
  row(1, "2026-09-14T10:00:00.000000+00:00", 1),
  row(2, "2026-09-14T10:30:12.500000+00:00", 1102),
  row(3, "2026-09-14T10:55:00.431000+00:00"),
  row(4, "2026-09-14T10:55:01.000000+00:00"),
  row(5, "2026-09-15T08:00:00.000000+00:00", 2),
];
const pairs: [string, string][][] = [
  [],
  [
    ["UtcTime", "2026-09-14 10:00:00.000"],
    ["Image", "C:\\evil.exe"],
  ],
  [["SubjectUserName", "bob"]],
  [],
  [],
  [
    ["UtcTime", "2026-09-15 08:00:00.000"],
    // Timestomped: file creation time set back into the incident window.
    ["CreationUtcTime", "2026-09-14 10:10:00.000"],
    ["PreviousCreationUtcTime", "2026-09-15 07:59:58.000"],
  ],
];
const index = buildTimeIndex(rows, pairs);
const utc = (s: string) => Date.parse(s);
const incident = normalizeRange(utc("2026-09-14T10:00:00Z"), utc("2026-09-14T10:55:00Z"));
const gids = (rs: Row[]) => rs.map((r) => r._g);

describe("event time parsing", () => {
  it("reads EVTX, ISO Z / offset and Sysmon (zone-less = UTC) timestamps", () => {
    expect(parseEventTime("2026-09-14T10:00:00.1234567+00:00")).toBe(utc("2026-09-14T10:00:00.123Z"));
    expect(parseEventTime("2026-09-14T10:00:00Z")).toBe(utc("2026-09-14T10:00:00Z"));
    expect(parseEventTime("2026-09-14T12:00:00+02:00")).toBe(utc("2026-09-14T10:00:00Z"));
    expect(parseEventTime("2026-09-14 10:00:00.500")).toBe(utc("2026-09-14T10:00:00.500Z"));
    expect(parseEventTime("")).toBeNaN();
    expect(parseEventTime("yesterday")).toBeNaN();
  });

  it("detects the EventData time fields present", () => {
    expect(detectTimeFields(pairs)).toEqual(["UtcTime", "CreationUtcTime", "PreviousCreationUtcTime"]);
  });
});

describe("range filter", () => {
  it("is inclusive at both ends, to the whole last second", () => {
    // 09:59:59.999 is out; 10:00:00.000 is in; 10:55:00.431 is in (same
    // second as the To input); 10:55:01 is out.
    expect(gids(filterByRange(rows, index, PRIMARY_FIELD, incident))).toEqual([1, 2, 3]);
  });

  it("no range = every record", () => {
    expect(filterByRange(rows, index, PRIMARY_FIELD, null)).toBe(rows);
  });

  it("a one-second range (From = To) matches that second", () => {
    const r = rangeFromInputs("2026-09-14T10:30:12", "2026-09-14T10:30:12", "utc");
    expect("range" in r && gids(filterByRange(rows, index, PRIMARY_FIELD, r.range))).toEqual([2]);
  });

  it("excludes records with no value for the chosen field", () => {
    // Only rows 1 and 5 have UtcTime; row 5's is outside the window.
    expect(gids(filterByRange(rows, index, "UtcTime", incident))).toEqual([1]);
    // CreationUtcTime (timestomped into the window) only exists on row 5.
    expect(gids(filterByRange(rows, index, "CreationUtcTime", incident))).toEqual([5]);
  });

  it('"Any" matches when any of the record\'s times is in range', () => {
    expect(gids(filterByRange(rows, index, ANY_FIELD, incident))).toEqual([1, 2, 3, 5]);
  });

  it("an unknown field falls back to TimeCreated", () => {
    expect(gids(filterByRange(rows, index, "NoSuchField", incident))).toEqual([1, 2, 3]);
  });

  it("scopes findings: kept if ≥1 event in range, count reflects the range", () => {
    const all = runDetections(rows, pairs);
    const cleared = all.find((f) => f.key === "log-cleared-1102");
    expect(cleared?.gids).toEqual([2]);
    const match = rangeMatcher(index, PRIMARY_FIELD, normalizeRange(utc("2026-09-15T00:00:00Z"), utc("2026-09-15T23:59:59Z")));
    expect(cleared!.gids.filter(match)).toEqual([]);
  });
});

describe("time-zone handling of the inputs", () => {
  it("interprets the inputs in UTC or local time", () => {
    expect(fromInputValue("2026-09-14T10:00:00", "utc")).toBe(utc("2026-09-14T10:00:00Z"));
    // Paris is UTC+2 in September.
    expect(fromInputValue("2026-09-14T12:00:00", "local")).toBe(utc("2026-09-14T10:00:00Z"));
    // …and UTC+1 in January (DST aware).
    expect(fromInputValue("2026-01-14T12:00", "local")).toBe(utc("2026-01-14T11:00:00Z"));
    expect(fromInputValue("2026-13-01T00:00", "utc")).toBeNull();
    expect(fromInputValue("", "utc")).toBeNull();
  });

  it("round-trips through the input format", () => {
    const t = utc("2026-09-14T10:00:05Z");
    expect(toInputValue(t, "utc")).toBe("2026-09-14T10:00:05");
    expect(toInputValue(t, "local")).toBe("2026-09-14T12:00:05");
    expect(fromInputValue(toInputValue(t, "local"), "local")).toBe(t);
  });

  it("rejects From after To", () => {
    expect(rangeFromInputs("2026-09-14T11:00:00", "2026-09-14T10:00:00", "utc")).toEqual({ error: "order" });
    expect(rangeFromInputs("2026-09-14T10:00", "", "utc")).toEqual({ error: "invalid" });
  });

  it("labels the range in the chosen zone", () => {
    expect(rangeLabel(incident, "utc")).toEqual({ from: "2026-09-14 10:00:00", to: "10:55:00" });
    expect(rangeLabel(incident, "local")).toEqual({ from: "2026-09-14 12:00:00", to: "12:55:00" });
  });
});

describe("presets and Around", () => {
  const bounds: [number, number] = [utc("2026-09-14T09:59:59.999Z"), utc("2026-09-15T08:00:00Z")];

  it("derive from the data span, not the wall clock", () => {
    expect(presetRange("all", bounds)).toBeNull();
    expect(presetRange("firstHour", bounds)).toEqual(normalizeRange(bounds[0], bounds[0] + HOUR));
    expect(presetRange("lastHour", bounds)).toEqual(normalizeRange(bounds[1] - HOUR, bounds[1]));
    // The data spans < 24 h: the window is clamped to its start.
    expect(presetRange("last24h", bounds)).toEqual(normalizeRange(bounds[0], bounds[1]));
    const long: [number, number] = [bounds[0] - 7 * DAY, bounds[1]];
    expect(presetRange("last24h", long)).toEqual(normalizeRange(bounds[1] - DAY, bounds[1]));
  });

  it("centers a ± window on an event", () => {
    const r = aroundRange(utc("2026-09-14T10:30:12.500Z"), 5 * MINUTE);
    expect(r).toEqual({ from: utc("2026-09-14T10:25:12Z"), to: utc("2026-09-14T10:35:12.999Z") });
  });
});

describe("URL persistence", () => {
  it("round-trips from/to/field through the hash, keeping other params", () => {
    const p = writeRangeParams(new URLSearchParams("q=eventid:4624"), incident, "UtcTime");
    expect(p.toString()).toBe(
      "q=eventid%3A4624&from=2026-09-14T10%3A00%3A00Z&to=2026-09-14T10%3A55%3A00Z&field=UtcTime",
    );
    expect(readRangeParams(new URLSearchParams(p.toString()))).toEqual({ range: incident, field: "UtcTime" });
    expect(writeRangeParams(p, null, PRIMARY_FIELD).toString()).toBe("q=eventid%3A4624");
  });

  it("ignores missing or inverted ranges", () => {
    expect(readRangeParams(new URLSearchParams("from=2026-09-14T11:00:00Z&to=2026-09-14T10:00:00Z")).range).toBeNull();
    expect(readRangeParams(new URLSearchParams("")).range).toBeNull();
  });
});

describe("exports honour the range", () => {
  it("export only in-range records and name the file after the range", () => {
    const inRange = filterByRange(rows, index, PRIMARY_FIELD, incident);
    const parsed = inRange.map((r) => pairsToRecord(pairs[r._g] ?? []));

    const csv = buildCsv(inRange, parsed, en, false, [], false);
    const lines = csv.replace(/^\uFEFF/, "").split("\n");
    expect(lines).toHaveLength(1 + 3);
    expect(lines.slice(1).map((l) => l.split(",")[1])).toEqual([
      "2026-09-14T10:00:00.000000+00:00",
      "2026-09-14T10:30:12.500000+00:00",
      "2026-09-14T10:55:00.431000+00:00",
    ]);

    const json = JSON.parse(buildJson(inRange, parsed, [], false)) as { record_id: number }[];
    expect(json.map((e) => e.record_id)).toEqual([2, 3, 4]);

    expect(`Security${rangeFileSuffix(incident)}.csv`).toBe(
      "Security_2026-09-14T100000Z-2026-09-14T105500Z.csv",
    );
    expect(rangeFileSuffix(null)).toBe("");
  });
});
