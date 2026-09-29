import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { readEventDataset } from "@/lib/events/load";
import { buildManifest, MANIFEST_PATH } from "@/lib/events/manifest-build";
import {
  EVENT_CHANNELS,
  SLUG_RE,
  channelBySlug,
  channelForRecord,
  eventPath,
} from "@/lib/events/channels";
import { isPlaceholder, parseEventKey, validateEntry, validateTranslation } from "@/lib/events/schema";
import { encyclopediaLink } from "@/lib/events/link";
import { LEGACY_EVENT_IDS, legacyEventRedirects } from "@/lib/events/legacy";
import { EVENT_BLOG_POSTS } from "@/lib/events/blog-links";
import { eventMetaTitle, renderedTitle, TITLE_MAX } from "@/lib/events/seo";
import { sigmaLinksFor } from "@/lib/events/sigma-links";
import { EVENTS_DICT } from "@/src/dict/events";
import { EVENT_TRANSLATION_LOCALES, type EventEntry } from "@/lib/events/types";
import { locales } from "@/src/dict/locales";

const ds = readEventDataset();
const keys = new Set(ds.entries.map((e) => `${e.channel}/${e.id}`));

// A valid entry to mutate in the negative tests.
const base = (): Record<string, unknown> => ({
  id: 9999,
  channel: "security",
  provider: "Microsoft-Windows-Security-Auditing",
  title: "Example event",
  shortTitle: "Example",
  category: "logon",
  summary: "Example summary long enough to pass the fifty character minimum length.",
  description:
    "A paragraph that is long enough to satisfy the description minimum. It explains what the event means and why an analyst would care about it at all, in detail.",
  logging: { enabledByDefault: true, requirement: "Audit Logon (Success)." },
  fields: [{ name: "LogonType", description: "How.", values: [{ value: "2", meaning: "Interactive" }] }],
  benign: ["Users."],
  attacker: ["Attackers."],
  investigation: ["Look here.", "Then there."],
  related: [],
  attack: ["T1078"],
  references: [{ title: "Doc", url: "https://learn.microsoft.com/" }],
});

describe("event dataset", () => {
  it("loads without validation errors", () => {
    expect(ds.errors).toEqual([]);
    expect(ds.entries.length).toBeGreaterThanOrEqual(150);
  });

  it("stores every entry under its channel folder and id", () => {
    for (const e of ds.entries) {
      const file = path.join(process.cwd(), "data/events", e.channel, `${e.id}.yaml`);
      expect(fs.existsSync(file), file).toBe(true);
    }
  });

  it("has summaries usable as meta descriptions (50–160 chars) in every language", () => {
    for (const e of ds.entries) {
      expect(e.summary.length, e.channel + e.id).toBeGreaterThanOrEqual(50);
      expect(e.summary.length, e.channel + e.id).toBeLessThanOrEqual(160);
    }
    for (const [key, m] of ds.translations)
      for (const [l, t] of m) {
        expect(t.summary.length, `${key}.${l}`).toBeGreaterThanOrEqual(50);
        expect(t.summary.length, `${key}.${l}`).toBeLessThanOrEqual(160);
      }
  });

  it("keeps rendered page titles within 60 characters", () => {
    const ch = (e: EventEntry) => channelBySlug(e.channel)!;
    for (const e of ds.entries) {
      const t = renderedTitle(eventMetaTitle({ ...e, channelInfo: ch(e) }, EVENTS_DICT.en));
      expect(t.length, t).toBeLessThanOrEqual(TITLE_MAX);
      for (const [l, tr] of ds.translations.get(`${e.channel}/${e.id}`) ?? []) {
        const lt = renderedTitle(
          eventMetaTitle({ ...e, shortTitle: tr.shortTitle, channelInfo: ch(e) }, EVENTS_DICT[l as "fr"]),
        );
        expect(lt.length, lt).toBeLessThanOrEqual(TITLE_MAX);
      }
    }
  });

  it("only translates into the supported locales", () => {
    for (const m of ds.translations.values())
      for (const l of m.keys()) expect(EVENT_TRANSLATION_LOCALES).toContain(l);
  });

  it("resolves every related key", () => {
    for (const e of ds.entries) for (const r of e.related) expect(keys.has(r), `${e.channel}/${e.id} → ${r}`).toBe(true);
  });

  it("has an up-to-date client manifest", () => {
    const onDisk = JSON.parse(fs.readFileSync(path.join(process.cwd(), MANIFEST_PATH), "utf8"));
    expect(onDisk).toEqual(buildManifest(ds));
  });

  it("links blog posts and legacy URLs only to existing entries", () => {
    for (const k of Object.keys(EVENT_BLOG_POSTS)) expect(keys.has(k), k).toBe(true);
    for (const k of Object.values(LEGACY_EVENT_IDS)) expect(keys.has(k), k).toBe(true);
    for (const slug of new Set(Object.values(EVENT_BLOG_POSTS)))
      expect(fs.existsSync(path.join(process.cwd(), "content/blog/en", `${slug}.md`)), slug).toBe(true);
  });
});

describe("schema validation", () => {
  const ok = (raw: unknown) => validateEntry(raw, { channel: "security", id: 9999 });

  it("accepts a valid entry", () => {
    expect(ok(base()).errors).toEqual([]);
  });

  it("rejects id / folder mismatches and unknown keys", () => {
    expect(ok({ ...base(), id: 1 }).errors.join()).toMatch(/does not match the file name/);
    expect(ok({ ...base(), channel: "system" }).errors.join()).toMatch(/does not match the folder/);
    expect(ok({ ...base(), extra: 1 }).errors.join()).toMatch(/unknown key "extra"/);
  });

  it("enforces summary length", () => {
    expect(ok({ ...base(), summary: "Too short." }).errors.join()).toMatch(/min 50/);
    expect(ok({ ...base(), summary: "x".repeat(161) }).errors.join()).toMatch(/max 160/);
  });

  it("rejects revoked ATT&CK techniques with the replacement", () => {
    expect(ok({ ...base(), attack: ["T1070.001"] }).errors.join()).toMatch(/revoked.*T1685\.005/);
    expect(ok({ ...base(), attack: ["T9999"] }).errors.join()).toMatch(/not a current/);
  });

  it("catches YAML list items that became mappings", () => {
    expect(ok({ ...base(), benign: [{ "Users logging on": "noise" }] }).errors.join()).toMatch(/benign\[0\]/);
  });

  it("flags drafting markers but not the Spanish word todo", () => {
    expect(isPlaceholder("TODO: write this")).toBe(true);
    expect(isPlaceholder("Lorem ipsum dolor")).toBe(true);
    expect(isPlaceholder("Registra todo el tráfico SMB.")).toBe(false);
    expect(isPlaceholder("Todo proceso creado queda registrado.")).toBe(false);
  });

  it("rejects bad category, related keys and references", () => {
    expect(ok({ ...base(), category: "nope" }).errors.join()).toMatch(/category/);
    expect(ok({ ...base(), related: ["Security 4624"] }).errors.join()).toMatch(/channel-slug\/id/);
    expect(ok({ ...base(), related: ["security/9999"] }).errors.join()).toMatch(/itself/);
    expect(ok({ ...base(), references: [{ title: "x", url: "http://x" }] }).errors.join()).toMatch(/https/);
  });

  it("validates translations against the English entry", () => {
    const entry = ok(base()).entry!;
    const t = {
      title: "Exemple",
      shortTitle: "Exemple",
      summary: "Résumé suffisamment long pour dépasser le minimum de cinquante caractères.",
      description: entry.description,
      logging: { requirement: "Audit" },
      fields: [{ name: "LogonType", description: "Comment.", values: [{ value: "2", meaning: "Interactif" }] }],
      benign: ["a"],
      attacker: ["b"],
      investigation: ["c", "d"],
    };
    expect(validateTranslation(t, entry, "fr").errors).toEqual([]);
    expect(validateTranslation({ ...t, fields: [] }, entry, "fr").errors.join()).toMatch(/not translated/);
    expect(
      validateTranslation({ ...t, fields: [{ name: "Nope", description: "x" }] }, entry, "fr").errors.join(),
    ).toMatch(/not a field/);
  });
});

describe("slugs and URLs", () => {
  it("uses lower-case hyphenated channel slugs, unique names", () => {
    const names = new Set<string>();
    for (const c of EVENT_CHANNELS) {
      expect(c.slug).toMatch(SLUG_RE);
      for (const n of c.names) {
        expect(names.has(n.toLowerCase()), n).toBe(false);
        names.add(n.toLowerCase());
      }
    }
  });

  it("builds canonical entry paths", () => {
    expect(eventPath("en", "security", 4624)).toBe("/en/events/security/4624");
    expect(eventPath("fr", "sysmon", 1)).toBe("/fr/events/sysmon/1");
    expect(parseEventKey("rdp-remote-connection-manager/1149")).toEqual({
      channel: "rdp-remote-connection-manager",
      id: 1149,
    });
    expect(parseEventKey("Security/4624")).toBeNull();
    expect(parseEventKey("security/70000")).toBeNull();
  });

  it("maps record channels and providers to slugs", () => {
    expect(channelForRecord("Security")?.slug).toBe("security");
    expect(channelForRecord("microsoft-windows-sysmon/operational")?.slug).toBe("sysmon");
    expect(channelForRecord(null, "Microsoft-Windows-Sysmon")?.slug).toBe("sysmon");
    expect(channelForRecord("Microsoft-Windows-AppLocker/MSI and Script")?.slug).toBe("applocker");
    expect(channelForRecord("Unknown/Channel")).toBeUndefined();
  });

  it("links viewer records to the right locale", () => {
    const en = encyclopediaLink("Security", null, 4624, "en");
    expect(en).toEqual({ href: "/en/events/security/4624", fallback: false });
    const ja = encyclopediaLink("Security", null, 4624, "ja");
    expect(ja).toEqual({ href: "/en/events/security/4624", fallback: true });
    expect(encyclopediaLink("Security", null, 1, "en")).toBeNull();
    expect(encyclopediaLink("Security", null, null, "en")).toBeNull();
  });

  it("redirects every legacy URL to an existing entry", () => {
    for (const r of legacyEventRedirects()) {
      const m = /^\/(\w\w|:lang)\/events\/(.+)$/.exec(r.destination);
      if (!m) continue;
      expect(keys.has(m[2]), r.destination).toBe(true);
    }
  });
});

describe("Sigma linking", () => {
  it("links process_creation rules to Sysmon 1 and Security 4688", () => {
    const s1 = sigmaLinksFor({ channel: "sysmon", id: 1 });
    const s4688 = sigmaLinksFor({ channel: "security", id: 4688 });
    expect(s1.total).toBeGreaterThan(500);
    expect(s4688.total).toBe(s1.total);
    expect(s1.rules[0].attribution).toMatch(/SigmaHQ, DRL 1\.1$/);
    expect(s1.rules[0].url).toMatch(/^https:\/\/github\.com\/SigmaHQ\/sigma\/blob\//);
  });

  it("links EventID-scoped service rules and skips channel-wide ones", () => {
    const cleared = sigmaLinksFor({ channel: "security", id: 1102 });
    expect(cleared.rules.map((r) => r.title)).toContain("Security Eventlog Cleared");
    // An ID no rule names must get no rule, even though keyword-only
    // rules on the Security channel accept every event.
    expect(sigmaLinksFor({ channel: "security", id: 65000 }).total).toBe(0);
  });

  it("sorts by severity", () => {
    const order = ["critical", "high", "medium", "low", "informational"];
    const levels = sigmaLinksFor({ channel: "sysmon", id: 1 }).rules.map((r) => order.indexOf(r.level));
    expect([...levels].sort((a, b) => a - b)).toEqual(levels);
  });
});

describe("encyclopedia UI strings", () => {
  it("exist for every locale with SEO-safe index metadata", () => {
    for (const l of locales) {
      const d = EVENTS_DICT[l];
      expect(d, l).toBeTruthy();
      expect(d.indexMetaTitle.length + " | EVTX parser".length, l).toBeLessThanOrEqual(60);
      expect(d.indexDescription.length, l).toBeGreaterThanOrEqual(50);
      expect(d.indexDescription.length, l).toBeLessThanOrEqual(160);
      expect(d.heading).toContain("{id}");
    }
  });
});
