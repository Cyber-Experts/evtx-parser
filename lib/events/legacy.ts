// The Event ID reference that preceded the encyclopedia lived at
// /[lang]/event-id/<id> (IDs were unique across its channels) and
// /[lang]/event-ids. next.config.ts redirects those URLs here. Plain module
// (no path aliases): it is imported by next.config.ts.

import manifest from "./manifest.json";

/** Old /event-id/<id> → encyclopedia key. */
export const LEGACY_EVENT_IDS: Record<number, string> = {
  1: "sysmon/1",
  3: "sysmon/3",
  7: "sysmon/7",
  11: "sysmon/11",
  13: "sysmon/13",
  21: "rdp-local-session-manager/21",
  22: "sysmon/22",
  23: "rdp-local-session-manager/23",
  25: "rdp-local-session-manager/25",
  104: "system/104",
  106: "task-scheduler/106",
  200: "task-scheduler/200",
  201: "task-scheduler/201",
  400: "windows-powershell/400",
  1102: "security/1102",
  4103: "powershell/4103",
  4104: "powershell/4104",
  4624: "security/4624",
  4625: "security/4625",
  4634: "security/4634",
  4648: "security/4648",
  4663: "security/4663",
  4672: "security/4672",
  4688: "security/4688",
  4720: "security/4720",
  4726: "security/4726",
  4740: "security/4740",
  4768: "security/4768",
  4769: "security/4769",
  4776: "security/4776",
  6005: "system/6005",
  6006: "system/6006",
  7036: "system/7036",
  7045: "system/7045",
};

type Redirect = { source: string; destination: string; permanent: boolean };

/**
 * 308s for the legacy reference: to the same locale when the entry is
 * translated there, otherwise to the English entry (the old non-English
 * copies were untranslated anyway).
 */
export function legacyEventRedirects(): Redirect[] {
  const m = manifest as Record<string, string[]>;
  const out: Redirect[] = [
    { source: "/:lang/event-ids", destination: "/:lang/events", permanent: true },
  ];
  for (const [id, key] of Object.entries(LEGACY_EVENT_IDS)) {
    if (!m[key]) continue;
    for (const l of ["en", ...m[key]])
      out.push({ source: `/${l}/event-id/${id}`, destination: `/${l}/events/${key}`, permanent: true });
    out.push({ source: `/:lang/event-id/${id}`, destination: `/en/events/${key}`, permanent: true });
  }
  // Anything else under the old route goes to the index.
  out.push({ source: "/:lang/event-id/:id", destination: "/:lang/events", permanent: true });
  return out;
}
