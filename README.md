# EVTX parser

[![CI](https://github.com/Cyber-Experts/evtx-parser/actions/workflows/ci.yml/badge.svg)](https://github.com/Cyber-Experts/evtx-parser/actions/workflows/ci.yml)
[![License: Elastic 2.0](https://img.shields.io/badge/license-Elastic%202.0-blue)](LICENSE)

**A fast Windows Event Log (`.evtx`) viewer for incident response that runs
entirely in your browser.** Drop one file or hundreds, and search, hunt and
triage them without uploading anything, installing anything or needing a
Windows host.

**Try it: <https://www.evtxparser.com>** — or [run it yourself](#run-it-locally-offline--air-gapped),
fully offline.

The parser core is the Rust [`evtx`](https://github.com/omerbenamram/evtx) crate
compiled to WebAssembly and run in a web worker, so the evidence never leaves
the analyst's machine.

## Features

**Viewer**
- Open many `.evtx` files at once and work on them as one merged timeline
  (Security, System, Sysmon, PowerShell, RDP, Defender, Task Scheduler…).
- Virtualised table that stays responsive on very large logs, a timeline
  (click a bar to zoom into that window) and a typed start/end time range.
- Microsecond timestamps, switchable between UTC and local time.
- Resizable layout, resizable and pinnable columns, full-screen workspace.
- Raw XML for every event, one click away.

**Search and hunting**
- Full-text search across every field, including EventData values, with hits
  highlighted.
- A small query language with autocomplete: `EventID:4624 LogonType:10
  -IpAddress:10.*` (see [Search syntax](#search-syntax)).
- Field sidebar with value counts and a *Rare* sort for stack counting.
- **86 ready-made hunts** mapped to MITRE ATT&CK — kerberoasting, AS-REP
  roasting, DCSync, PsExec, WMI/WinRM lateral movement, Run keys, encoded
  PowerShell, AMSI bypass, cleared logs, shadow-copy deletion and more — each
  showing its hit count on your data.
- Built-in findings for common high-signal events.
- **Sigma rules, in the browser**: 2,395 SigmaHQ Windows rules (pinned
  release, bundled at build time) run on every load, like Hayabusa or
  Chainsaw but with nothing to install — matches grouped by level with the
  rule's description, ATT&CK techniques, false positives, references and
  author, filters by level/tactic, one click to the matched events or to the
  time window around one, CSV/JSON export with attribution. Paste or drop
  your own Sigma YAML too; it is validated and run locally, never uploaded.
  See [Sigma](#sigma).

**Investigation**
- **Logon sessions**: logon → activity → logoff per session, UAC split tokens
  merged, one click to see every event of a session.
- Pivots from any event: ±5 minutes around it, same logon session, same
  process.
- Bookmarks and analyst notes, exported as a **Markdown report**.
- Export the filtered events to CSV, JSON or plain text.
- **Save a session locally** (browser IndexedDB) and resume it later — files,
  search, filters, bookmarks and notes.

**Readable offline — no message DLLs needed**
- One-line descriptions for ~60 common DFIR events instead of *"The
  description for Event ID … cannot be found"*.
- `%%` parameter codes (e.g. `%%1833` → Impersonation), NTSTATUS failure
  codes, Kerberos result codes, ticket encryption types and logon types
  decoded inline — and searchable.

## Privacy

`.evtx` files are read and parsed in your browser, inside a web worker. Their
content, file names and parsed events are never sent to a server. Saved
sessions live only in your browser's IndexedDB. See the
[privacy policy](https://www.evtxparser.com/en/privacy) for the hosted site.

## Run it locally (offline / air-gapped)

On evtxparser.com your files are already processed only in your browser. Running
your own instance is for everything else: air-gapped forensic workstations,
organisational policies that only allow approved or self-hosted tools, or
simply keeping a pinned, auditable version in your case documentation.
Requirements: Node.js ≥ 20.9.

```bash
git clone https://github.com/Cyber-Experts/evtx-parser.git
cd evtx-parser
npm ci
NEXT_PUBLIC_OFFLINE=1 npm run build
NEXT_PUBLIC_OFFLINE=1 npm start      # http://localhost:3000
```

`NEXT_PUBLIC_OFFLINE=1` removes every third-party script and beacon (analytics,
performance and web-vitals reporting): once the page has loaded, the app makes
no outbound requests. The build itself needs network access once (it
downloads the web fonts, which are then served locally), so build on a
connected machine and copy the whole folder, `node_modules` and `.next`
included, to the isolated one; `npm start` there needs no network.

No Rust toolchain is needed: the compiled WebAssembly module is committed in
`lib/evtx-wasm/` and `public/evtx_wasm_bg.wasm`.

### With Docker

The image is built in offline mode and runs as a non-root user:

```bash
docker build -t evtx-parser .                 # needs network once (npm + web fonts)
docker run --rm -p 3000:3000 evtx-parser      # http://localhost:3000
```

For an air-gapped workstation, build on a connected machine and carry the
image across as a single file:

```bash
docker save evtx-parser | gzip > evtx-parser.tar.gz
# on the isolated machine
docker load < evtx-parser.tar.gz
docker run --rm -p 127.0.0.1:3000:3000 evtx-parser
```

## Search syntax

| Query | Meaning |
|---|---|
| `mimikatz` | free text in any field, including EventData values |
| `"net user"` | quoted phrase |
| `TargetUserName:j.doe` | field equals value (case-insensitive) |
| `Image:*\powershell.exe` | `*` wildcard (matches across lines too) |
| `-IpAddress:127.0.0.1` | exclude with a leading `-` (works on free text too) |
| `4624 OR 4625` | `OR` between groups; terms within a group are ANDed |
| `EventID:>=4720` | numeric comparison: `>` `>=` `<` `<=` |
| `LogonType:RemoteInteractive*` | field clauses also match decoded values |
| `logonid:0x3e7` | any `TargetLogonId` / `SubjectLogonId` / `LogonId` |
| `processguid:{…}` | any Sysmon `*ProcessGuid` field |
| `process:*\cmd.exe` | 4688 `NewProcessName` or Sysmon `Image` |
| `parent:*\winword.exe` | `ParentProcessName` or Sysmon `ParentImage` |

Built-in fields: `EventID`, `Level`, `Provider`, `Channel`, `Computer`, `File`,
`Name`, `Record`. Any other name is looked up in the event's EventData. A
regular-expression mode (`.*` button) is also available.

## Sigma

The Sigma tab runs [SigmaHQ](https://github.com/SigmaHQ/sigma) detection rules
over the loaded events, inside the same web worker that parses them.

- **Rule set**: `rules/windows/**` of a pinned SigmaHQ release (currently
  `r2026-07-01`), fetched by `npm run sigma:update` and committed as
  `lib/sigma/sigmahq-rules.json` — never fetched at runtime (the CSP forbids
  it). 2,403 rule files scanned → **2,395 bundled**; excluded: 8 whose
  logsource has no EVTX channel (`file_access`, `file_rename` are ETW-only),
  plus SigmaHQ's own `deprecated/` (152) and `unsupported/` (55) Windows
  trees. The script lists every skipped rule and why in
  `lib/sigma/sigmahq-skipped.json`.
- **Log sources**: `category:` maps to Sysmon Event IDs (process_creation →
  Sysmon 1 *and* Security 4688, network_connection → 3, image_load → 7,
  process_access → 10, file_event → 11, registry_* → 12/13/14, dns_query →
  22, …), `ps_script`/`ps_module` → PowerShell 4104/4103, `ps_classic_*` →
  Windows PowerShell 400/600/800; `service:` maps to its channel (security,
  system, application, windefend, taskscheduler, bits-client, …).
- **Fields**: Sigma's Windows taxonomy is the EventData names; Security 4688
  is mapped to it (`Image` ← NewProcessName, `ParentImage` ←
  ParentProcessName, `User`, `IntegrityLevel` ← MandatoryLabel, hex PIDs),
  `Provider_Name`/`Channel`/`EventID`/`Computer` come from System, `Hashes`
  is split into `md5`/`sha1`/`sha256`/`Imphash`, classic PowerShell `Data`
  is joined and its `HostApplication=`… lines exposed as fields, and names
  are matched case- and space-insensitively (Defender's "Threat Name").
- **Engine** (`lib/sigma/engine.ts`): selections, lists, keywords, wildcards
  and escaping, modifiers `contains` `startswith` `endswith` `all` `exists`
  `re` (+`i`/`m`/`s`) `cased` `base64` `base64offset` `utf16le`/`utf16be`/
  `utf16`/`wide` `windash` `cidr` `gt`/`gte`/`lt`/`lte` `fieldref`;
  conditions with `and`/`or`/`not`, parentheses, `1 of`/`any of`/`all of`/
  `N of` over patterns and `them`. Not supported (reported, never silently
  ignored): aggregations (`| count() by …`), `near`, correlation rules and the
  `expand` modifier — none of the bundled Windows rules use them.
- **Speed**: rules are compiled once and bucketed by (channel, Event ID);
  each rule also gets a literal pre-filter (an Aho–Corasick / hash index of
  values one of which must be present), so an event only runs the few rules
  that can match. 200,000 synthetic events × 2,395 rules take ~5 s in the
  test suite; the worker yields between chunks and reports progress.
- **License**: SigmaHQ rules are under the
  [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
  Every match shows "Rule by *author*, SigmaHQ, DRL 1.1" and a link to the
  rule, and exports carry the same on every row — see
  [LICENSE-SIGMA](LICENSE-SIGMA).

## How it works

```
.evtx file ──▶ Web Worker ──▶ evtx crate (Rust → WebAssembly)
                                  │  records, EventData, lazy XML
                                  ▼
               React UI: virtualised table, search engine, hunts,
               decoders, sessions — all in the browser tab
```

- `crates/evtx-wasm/` — thin `wasm-bindgen` wrapper around the `evtx` crate.
- `lib/evtx.worker.ts`, `lib/evtx-client.ts` — worker and its client.
- `lib/search-query.ts` — query language (parser, matcher, highlighting).
- `lib/hunts.ts` — hunt catalogue; `lib/detections.ts` — built-in findings.
- `lib/sigma/` — Sigma engine, logsource mapping, runner, exports and the
  bundled SigmaHQ rules; `scripts/sigma-update.ts` refreshes them.
- `lib/event-decode.ts` — `%%`/NTSTATUS/Kerberos decoding and descriptions.
- `lib/sessions.ts` — logon-session reconstruction.
- `lib/saved-sessions.ts` — local session save/restore (IndexedDB).
- `components/EvtxUploader.tsx`, `components/viewer/` — the viewer UI.

The repository also contains the evtxparser.com website around the tool
(Next.js 16, 8 locales, blog, glossary and Event ID reference in `content/`
and `app/[lang]/`).

## Development

```bash
npm install
npm run dev            # http://localhost:3000
npm test               # Vitest
npm run lint           # ESLint
npm run lint:content   # Markdown content lint (blog, glossary)
npm run sigma:update   # re-bundle SigmaHQ rules (pinned release)
npm run build          # production build
```

**Tests** cover the query language, decoding, event descriptions, hunts (an
attack case for every hunt, plus benign look-alikes), logon sessions, time
formatting and the Sigma engine (every modifier and condition form, real
SigmaHQ rules against positive and negative events, pre-filter equivalence,
and a 200k-event performance run). Suites that run against real `.evtx` files skip automatically when
the fixtures are absent — they come from a training disk image and are not
distributed (see [`tests/fixtures/evtx/README.md`](tests/fixtures/evtx/README.md)).

**Rebuilding the WebAssembly module** is only needed when changing the Rust
code:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
npm run wasm:build     # → lib/evtx-wasm/ and public/evtx_wasm_bg.wasm
```

**Website content** (blog posts, glossary, Event ID pages, landing pages) and
the hosted site's configuration are documented in
[`docs/CONTENT.md`](docs/CONTENT.md).

**Updating the Sigma rules**: bump `PINNED_RELEASE` in
`scripts/sigma-update.ts`, run `npm run sigma:update`, check the printed
counts and `npm test`, and commit the regenerated `lib/sigma/*.json`.

**Adding a hunt**: add an entry to `lib/hunts.ts` (query in the search syntax,
MITRE technique, name in all locales) and a positive and negative case in
`tests/hunts.test.ts`.

## Contributing

Bug reports, feature requests and pull requests are welcome — feedback from
people using it on real cases is what shapes the roadmap. Please run
`npm test` and `npm run lint` before opening a PR.

**Security issues**: please report them privately to
[contact@cyberexperts.io](mailto:contact@cyberexperts.io) rather than in a
public issue.

## Credits

- [`evtx`](https://github.com/omerbenamram/evtx) by Omer Ben-Amram — the Rust
  EVTX parser at the core of this tool (MIT/Apache-2.0).
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — the Sigma rules bundled in
  `lib/sigma/`, by their respective authors, under the Detection Rule License
  1.1 ([LICENSE-SIGMA](LICENSE-SIGMA)).
- Third-party dependencies are listed in `package.json` and
  `crates/evtx-wasm/Cargo.toml`; see [NOTICE](NOTICE).

## License

© 2026 [Cyber Experts](https://github.com/Cyber-Experts) —
[contact@cyberexperts.io](mailto:contact@cyberexperts.io)

Licensed under the [Elastic License 2.0](LICENSE). You may use, modify and run
it — including for commercial incident-response work — but you may not offer
it to third parties as a hosted or managed service, or remove the licensing
notices. The bundled Sigma rules are under the Detection Rule License 1.1
([LICENSE-SIGMA](LICENSE-SIGMA)).
