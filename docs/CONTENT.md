# Site content and operations

How to add content to the evtxparser.com website (blog, glossary, Event ID
reference) and how the hosted site is operated. For the tool itself, see the
[README](../README.md).

## Adding content

Content lives in `content/` as Markdown, one folder per locale
(`en, fr, es, de, it, pt, ja, zh`). A husky `pre-commit` hook runs
`npm run lint:content` on staged `content/**/*.md` files (frontmatter,
headings, alt text, thin content); run it yourself with:

```bash
npm run lint:content                  # all content
npm run lint:content content/blog/en  # one folder
```

### Blog post

```bash
content/blog/en/my-post.md
content/blog/fr/my-post.md   # same slug per locale you want translated
```

Frontmatter the project relies on (everything `@next-md-blog/core` recognises
also works):

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

Link to other posts with locale-prefixed paths (`/en/blog/<slug>`); in a
translation, only link to posts that exist in that locale.

### Glossary term

One `.md` per term under `content/glossary/{locale}/`. The source list is in
`lib/glossary-data.ts`; regenerate the files from it with:

```bash
npx tsx scripts/extract-glossary.ts
```

### Event ID page

Event ID reference pages are generated from `lib/event-id-data.ts`. Add an
entry there and a page is produced at `/[lang]/event-id/<id>` at build time.

### Landing pages

Single-intent landing pages (EVTX to CSV/TXT/JSON/XML, evtx_dump online,
Mac/Linux viewer) share `components/landing/LandingPage.tsx`. Their content is
in `lib/landing/*.ts` (one object per locale) and registered in
`lib/landing/registry.ts`.

## Operating the hosted site

```bash
npm run dev           # local dev
npm run build         # production build
npm start             # serve the build
npm run lint          # ESLint
npm run lint:content  # content lint
npm test              # Vitest
npm run wasm:build    # rebuild the Rust → WASM module
npm run indexnow      # ping Bing/Yandex after deploy (needs NEXT_PUBLIC_INDEXNOW_KEY)
```

### Environment

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
