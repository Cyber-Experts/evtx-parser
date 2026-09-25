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
- **56 ready-made hunts** mapped to MITRE ATT&CK — kerberoasting, AS-REP
  roasting, DCSync, PsExec, WMI/WinRM lateral movement, Run keys, encoded
  PowerShell, AMSI bypass, cleared logs, shadow-copy deletion and more — each
  showing its hit count on your data.
- Built-in findings for common high-signal events.

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
npm run build          # production build
```

**Tests** cover the query language, decoding, event descriptions, hunts (an
attack case for every hunt, plus benign look-alikes), logon sessions and time
formatting. Suites that run against real `.evtx` files skip automatically when
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
- Third-party dependencies are listed in `package.json` and
  `crates/evtx-wasm/Cargo.toml`; see [NOTICE](NOTICE).

## License

© 2026 [Cyber Experts](https://github.com/Cyber-Experts) —
[contact@cyberexperts.io](mailto:contact@cyberexperts.io)

Licensed under the [Elastic License 2.0](LICENSE). You may use, modify and run
it — including for commercial incident-response work — but you may not offer
it to third parties as a hosted or managed service, or remove the licensing
notices.
