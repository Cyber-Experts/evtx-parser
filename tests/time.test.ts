import { describe, expect, it } from "vitest";

import { formatEpoch, formatTimestamp, zoneLabel } from "@/lib/time";

// vitest.config.ts pins TZ=Europe/Paris (UTC+1 winter, UTC+2 summer).
describe("time formatting", () => {
  const ts = "2020-04-03T02:01:40.424361+00:00";

  it("keeps microseconds in UTC", () => {
    expect(formatTimestamp(ts, "utc")).toBe("2020-04-03 02:01:40.424361");
  });

  it("converts to local time and keeps the fraction", () => {
    expect(formatTimestamp(ts, "local")).toBe("2020-04-03 04:01:40.424361");
  });

  it("labels the offset at the event's date (DST aware)", () => {
    expect(zoneLabel("utc")).toBe("UTC");
    expect(zoneLabel("local", ts)).toBe("UTC+02:00");
    expect(zoneLabel("local", "2020-01-15T12:00:00.000000+00:00")).toBe("UTC+01:00");
  });

  it("formats epoch ranges without fractions", () => {
    expect(formatEpoch(Date.parse("2020-04-03T02:01:40Z"), "utc")).toBe("2020-04-03 02:01:40");
  });

  it("passes unknown formats through", () => {
    expect(formatTimestamp("not a date", "utc")).toBe("not a date");
  });
});
