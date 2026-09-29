---
title: "SEO plan: Windows Event ID encyclopedia"
description: "Keyword, URL, title and internal-linking plan for the evtxparser.com Event ID encyclopedia (/[lang]/events), with cannibalisation rules against the blog."
date: "2026-09-29"
---

Internal planning document. It lives in `content/` but outside `content/blog` and `content/glossary`, so it is never rendered on the site. It carries frontmatter only so `npm run lint:content` stays green.

## Why an encyclopedia

Search Console (June–September 2026) already shows demand for per-ID queries that the site only half answers:

| Query | Page ranking today | Impressions | Position |
|---|---|---|---|
| event id 4104 | /en/blog/powershell-4104-scriptblock | 254 | 7.0 |
| event id 4624 | /fr/blog/understanding-event-id-4624 | 174 | 9.2 |
| event id 4768 | /zh/event-id/4768 (old, untranslated) | 163 | 11.4 |
| event id 4769 | /zh/event-id/4769 (old, untranslated) | 40 | 33.5 |
| eventcode=4104 | /en/blog/powershell-4104-scriptblock | 17 | 7.9 |
| event id 5140 and 5145 | /en/blog/file-share-access-5140-5145 | 6 | 5.0 |

Two problems are visible: the wrong locale ranks (a French post and a Chinese copy for English queries), and the pages that rank are either long how-to posts or thin one-line rows. The head term for each ID ("event id 4624") wants a reference answer: what the event means, when it is logged, the fields and codes, and what to do with it. That is what the encyclopedia pages are.

## Keyword strategy

One page per (channel, event ID). Each page targets the ID-level cluster; the blog keeps the task-level cluster.

| Intent | Query patterns | Target |
|---|---|---|
| Definition (head) | event id 4624, windows event 4624, eventid 4624, event 4624 | `/en/events/security/4624` |
| Meaning | event id 4688 meaning, what is event id 4625, windows event 4720 meaning | encyclopedia entry (H2 "What event N means") |
| Field / code lookup | 4625 status 0xc000006a, 4768 result code 0x18, 4769 ticket encryption type 0x17, logon type 10 | encyclopedia entry field tables |
| Enablement | how to enable event 4688, event 4104 not logged, audit policy for 4663 | encyclopedia entry "When it is logged" |
| Channel-qualified | sysmon event id 1, sysmon event 3, powershell event id 4104, rdp event 1149, task scheduler event 106, defender event 1116 | channel-prefixed titles (`Sysmon Event ID 1: …`) |
| Detection | 4769 kerberoasting detection, sigma rule 4688, detect event log cleared 1102 | entry "Sigma rules" + "Investigation tips"; blog for the long form |
| How-to / investigation | how to investigate 4625 brute force, rdp lateral movement event logs | blog posts (unchanged) |
| Hub | windows event id list, windows security event id cheat sheet, windows event id encyclopedia | `/[lang]/events` index; cheat-sheet post stays for "cheat sheet" |

Localized head terms follow the same pattern: "event id 4624" is used as-is by French, Spanish and German analysts, so localized titles keep "Event ID"/"Event-ID" plus the translated short title ("Event ID 4624 : Ouverture de session réussie").

## URL scheme

- Index: `/[lang]/events` in all 8 locales (the UI is localized; entries in untranslated locales link to the English page with an "English" badge).
- Entry: `/[lang]/events/<channel-slug>/<id>`, e.g. `/en/events/security/4624`, `/en/events/sysmon/1`, `/en/events/rdp-remote-connection-manager/1149`. The channel segment disambiguates IDs that exist in several logs (Sysmon 1 vs System 1, Security 1102 vs RDPClient 1102).
- Entries exist in English for every event and in fr/es/de only where a real translation exists (`data/events/<channel>/<id>.<locale>.yaml`). No other locale gets a copy, so there is no duplicate content; hreflang lists only real translations plus `x-default` → English. Requests for an untranslated locale are redirected (307) to English by `proxy.ts`, and the static route returns 404 for anything not generated.
- Legacy `/[lang]/event-id/<id>` and `/[lang]/event-ids` URLs 308 to the new entries/index (see `lib/events/legacy.ts`), to the same locale when translated, otherwise English.

## Titles and descriptions

- Title template: `{prefix}Event ID {id}: {shortTitle}` + ` | EVTX parser` when the total fits in 60 characters; otherwise the heading alone. `shortTitle` is capped at 40 characters by the schema, and the test suite checks every rendered title (all locales) is ≤ 60 characters. Examples: "Event ID 4624: Successful logon | EVTX parser" (45), "Sysmon Event ID 1: Process creation | EVTX parser" (49), "RDP Event ID 1149: Connection authenticated | EVTX parser" (57).
- Channel prefixes (`seoPrefix` in `lib/events/channels.ts`) match how people search: Sysmon, PowerShell, RDP, Task Scheduler, WMI, Defender, BITS, WinRM, AppLocker. Security has none — "event id 4624" already implies it.
- Meta description = the entry's `summary`, validated at 50–160 characters (plain text, one line, mentions the ID).
- H1 repeats the title pattern; the official Microsoft message title appears right under it so exact-message searches ("An account was successfully logged on") also match.

## On-page structure (every entry)

Key facts (ID, channel, provider, log file, category, default logging) · What event N means · When it is logged (audit subcategory / GPO) · Key fields with value tables (LogonType, Status, encryption types…) · Common benign sources · What attackers do that produces it · Investigation tips · MITRE ATT&CK techniques (v19 IDs, validated) · Sigma rules for this event (bundled SigmaHQ rules, computed at build time, DRL attribution) with the "Run these rules on your logs" call to action · Related events · In-depth blog post · Sources.

Structured data: `WebPage` + `TechArticle` (about a `DefinedTerm` for "Event ID N", in the index's `DefinedTermSet`) + `BreadcrumbList`. The index is a `CollectionPage` whose main entity is the `DefinedTermSet`. OG image per entry (ID, channel, title, summary).

## Cannibalisation rules with the blog

Several IDs have both an entry and a post (`lib/events/blog-links.ts`): 4624, 4625, 4663, 4672, 4688, 4697, 4698, 4719, 4720, 4732, 4740, 4768, 4769, 5136, 5140/5145, 1102, 4616, 7036, 7045, 4104, Sysmon 1/3/7/8/10/22, AppLocker 8003/8004, Code Integrity 3077, WMI 5861, RDP 1149/21.

- The **entry** owns "event id N", "event N meaning", field and code lookups. Its title starts with "Event ID N".
- The **post** owns the task: "how to detect / investigate / hunt …", with long-form examples. Post titles should lead with the task, not with "Event ID N" alone; retitle any post whose title is a bare definition when it next gets updated.
- The entry links to the post ("In-depth guide"); posts should link back to the entry the first time they mention the ID.
- Watch in Search Console, eight weeks after launch: for each pair, the query "event id N" should resolve to the entry. If a post keeps outranking its entry for the head term and the entry does not gain, merge the definition content into the entry and refocus the post rather than keeping two definitions.

## Internal linking

- Header navigation link ("Event IDs") on every page, home page SEO block, HTML sitemap, 404 page, channel landing pages (`/security-evtx`, `/system-evtx`) link to entries.
- Each entry links to 3–10 related entries (validated to exist) and to the viewer (`/[lang]#tool`, and `#q=EventID:N` pre-filtered).
- The viewer links back: the event details panel shows "What is event N?" for every covered record, opening the entry in a new tab (localized when translated, otherwise English).

## Translation priority

Translated to fr, es, de first (≈40 most-searched entries): Security 4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4719, 4720, 4722, 4724, 4726, 4728, 4732, 4738, 4740, 4756, 4768, 4769, 4771, 4776, 4778, 5140, 5145, 1102, 4663; System 7045, 7036, 104, 1074; Sysmon 1, 3, 10, 11, 13, 22; PowerShell 4104, 4103; RDP 1149, 21, 24, 25. Next candidates come from Search Console: localized impressions on an English entry for "event id N" in fr/es/de markets. it/pt/ja/zh stay English-only until there is demand.

## Measurement

- GSC page filter `/events/`: impressions and average position per entry, weekly.
- Queries containing "event id" / "eventid" / "sysmon event": which URL ranks (entry vs post vs legacy).
- Legacy `/event-id/` URLs should drop out of the index within a few weeks of the 308s.
- Re-run `npm run attack:update` when MITRE publishes a new ATT&CK version and `npm run sigma:update` for new SigmaHQ releases; entries and Sigma links are rebuilt from those at build time.
