# evtxparser.com

In-browser parser for Windows Event Log (`.evtx`) files. Drop a file, get a readable triage view of logons, services, PowerShell and the rest — without uploading anything, installing anything, or owning a Windows host. The Rust parser ships as a WebAssembly module and runs entirely in a web worker on the visitor's machine.

Live site: <https://www.evtxparser.com>

## Stack

- Next.js 16 (App Router, Turbopack) + React 19 + TypeScript strict
- Tailwind v4, shadcn-derived primitives (`@base-ui/react`)
- `@next-md-blog/core` for the blog, glossary, and event-ID library
- Rust + `wasm-bindgen` (crate at `crates/evtx-wasm/`), built with `wasm-pack`
- 8 locales: `en, fr, es, de, it, pt, ja, zh`
- Built on top of the [`website-template`](https://github.com/FAKGR0UP/website-template) SEO/i18n base

## Repo layout

```
app/
  [lang]/                   one tree per locale, generated at build
    page.tsx                landing page (the parser UI lives here)
    blog/                   long-form posts
    glossary/               128 glossary terms (one .md per term)
    event-id/[id]/          dynamic event-ID reference pages
    event-ids/              event-ID index
    tools/                  hand-curated tool directory
    topics/[series]/        pillar pages for topic clusters
    authors/[slug]/         author profiles
    search, contact, privacy, terms, sitemap
crates/evtx-wasm/           Rust crate compiled to wasm
lib/evtx-wasm/              wasm-pack output (committed — see note below)
content/blog/{locale}/      markdown sources for blog
content/glossary/{locale}/  markdown sources for glossary
src/dict/                   typed dictionaries (i18n)
scripts/                    content-lint, glossary extractor, IndexNow ping
```

## Local development

```bash
npm install
npm run dev          # http://localhost:3000 → redirects to /<accept-language>
```

The committed wasm artifacts are enough to run `dev` and `build` without a Rust toolchain. You only need Rust + `wasm-pack` if you change the parser itself.

### Rebuilding the WASM module

```bash
# one-time setup
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

npm run wasm:build
```

This compiles `crates/evtx-wasm/` to `lib/evtx-wasm/` and copies the `.wasm` binary into `public/` so the worker can fetch it. The four generated files in `lib/evtx-wasm/` are checked into git on purpose — `wasm-pack` ships a `.gitignore: *` that we override, so Vercel doesn't need a Rust toolchain to deploy.

## Self-hosting / offline use

Everything runs in the browser: the `.evtx` file is parsed by WebAssembly in a
web worker and never leaves the machine. To run your own instance — e.g. on an
analysis workstation for cases where evidence may not touch externally hosted
services:

```bash
npm ci
NEXT_PUBLIC_OFFLINE=1 npm run build
NEXT_PUBLIC_OFFLINE=1 npm start      # http://localhost:3000
```

`NEXT_PUBLIC_OFFLINE=1` removes every third-party script and beacon (Vercel
Analytics, Speed Insights, Ahrefs, web-vitals reporting), so once the page is
loaded the app makes no outbound requests. After `npm ci`, the build and the
app need no network access.

## Tests

```bash
npm test
```

Vitest suites cover the query language, event decoding, descriptions, hunts,
logon sessions and time formatting. Suites that run against real `.evtx`
fixtures skip automatically when `tests/fixtures/evtx/` is absent (as in the
public repository).

## Adding content

### Blog post

```bash
content/blog/en/my-post.md
content/blog/fr/my-post.md   # same slug per locale you want translated
```

Frontmatter the project relies on (everything `@next-md-blog/core` recognises also works):

```yaml
---
title: "…"
description: "…"               # ≤ 200 chars — content lint blocks longer
date: "2026-05-24"
updated: "2026-05-25"          # optional, drives sitemap lastmod
tags: ["dfir", "evtx"]
image: "/img/hero.jpg"         # optional, preloaded as LCP
series: "evtx-101"             # optional, joins a topic cluster
seriesOrder: 1
faq: [ … ]                     # optional, emits FAQPage JSON-LD
howto: { steps: [ … ] }        # optional, emits HowTo JSON-LD
---
```

### Glossary term

One `.md` per term under `content/glossary/{locale}/`. The full source list is in `lib/glossary-data.ts`; `npm run` the extractor below to regenerate the files from it:

```bash
tsx scripts/extract-glossary.ts
```

### Event-ID page

The event-ID pages are generated from a data file in `lib/`. Add the entry there and a route is produced at `/[lang]/event-id/<id>` at build.

## Operating

```bash
npm run dev           # local dev
npm run build         # Turbopack production build
npm start             # serve the build
npm run lint          # ESLint
npm run lint:content  # frontmatter / heading / alt-text / thin-content lint
npm run wasm:build    # rebuild the Rust → WASM module
npm run indexnow      # ping Bing/Yandex after deploy (needs NEXT_PUBLIC_INDEXNOW_KEY)
```

A husky `pre-commit` hook runs `lint:content` on staged `content/**/*.md` only.

## Environment

```bash
# Optional — falls back to VERCEL_PROJECT_PRODUCTION_URL / VERCEL_URL / localhost.
NEXT_PUBLIC_SITE_URL=https://www.evtxparser.com

# Search consoles
NEXT_PUBLIC_GSC_VERIFICATION=…
NEXT_PUBLIC_BING_VERIFICATION=…
NEXT_PUBLIC_YANDEX_VERIFICATION=…

# IndexNow key (and drop public/<KEY>.txt alongside)
NEXT_PUBLIC_INDEXNOW_KEY=<32–128 hex chars>

# Self-hosted / air-gapped builds: drop every third-party script and beacon
NEXT_PUBLIC_OFFLINE=1

# Optional 3rd-party analytics (Vercel Analytics is on unless NEXT_PUBLIC_OFFLINE=1)
NEXT_PUBLIC_ANALYTICS_PROVIDER=plausible   # or umami | ga4
NEXT_PUBLIC_ANALYTICS_DOMAIN=evtxparser.com
NEXT_PUBLIC_ANALYTICS_ID=…
```

## Privacy

Files never leave the browser. The parser is a WASM module executing in a web worker on the visitor's device; the server never sees the file bytes, the filename, or the parsed records. No analytics event carries any field from a parsed log.

## License

[Elastic License 2.0](LICENSE). You may use, modify and run it — including
for commercial incident-response work — but you may not offer it to third
parties as a hosted or managed service, or remove the licensing notices.
See [NOTICE](NOTICE) for third-party credits: the parser core is the
[`evtx`](https://github.com/omerbenamram/evtx) crate by Omer Ben-Amram
(MIT/Apache-2.0).

