import { describe, expect, it } from "vitest";

import { eventName } from "@/lib/event-info";

import { HAS_FIXTURES, loadFixtures } from "./helpers";

describe("eventName", () => {
  it("names events per provider", () => {
    expect(eventName(4624, "Microsoft-Windows-Security-Auditing")).toBe("Successful logon");
    expect(eventName(1, "Microsoft-Windows-Sysmon")).toBeTruthy();
  });

  it("never guesses a name from another provider's table", () => {
    // Servicing 1 is not Kernel-General 1 ("System time changed").
    expect(eventName(1, "Microsoft-Windows-Servicing")).toBeNull();
    expect(eventName(4624, "Some-Third-Party-Agent")).toBeNull();
  });

  it.skipIf(!HAS_FIXTURES)("leaves Setup servicing events unnamed", () => {
    const { rows } = loadFixtures("setup.evtx");
    for (const r of rows) expect(eventName(r.event_id, r.provider)).toBeNull();
  });
});
