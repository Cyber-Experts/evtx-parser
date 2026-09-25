import { describe, expect, it } from "vitest";

import { runDetections } from "@/lib/detections";

import { loadFixtures } from "./helpers";

describe("built-in findings on real logs", () => {
  it("Security.evtx", () => {
    const ds = loadFixtures("security.evtx");
    const got = runDetections(ds.rows, ds.pairs).map((f) => [f.key, f.severity, f.gids.length]);
    expect(got).toEqual([
      ["priv-group-change", "high", 20],
      ["time-change-4616", "medium", 24],
      ["account-created-4720", "low", 8],
    ]);
  });

  it("across Security + System + Application + Setup", () => {
    const ds = loadFixtures("security.evtx", "application.evtx", "system.evtx", "setup.evtx");
    const got = Object.fromEntries(
      runDetections(ds.rows, ds.pairs).map((f) => [f.key, f.gids.length]),
    );
    expect(got).toEqual({
      "priv-group-change": 20,
      "time-change-4616": 24,
      "service-installed": 7,
      "account-created-4720": 8,
    });
  });

  it("finding row indexes point at the right events", () => {
    const ds = loadFixtures("security.evtx");
    const f = runDetections(ds.rows, ds.pairs).find((x) => x.key === "account-created-4720")!;
    for (const g of f.gids) expect(ds.rows[g].event_id).toBe(4720);
  });
});
