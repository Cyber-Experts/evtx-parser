# SEO-First i18n Next.js Template

A Next.js 16 / React 19 starter built for SEO out of the box, using only shadcn defaults for design and `@next-md-blog/core` for the blog. Multilingual by default (English, French, Spanish, German) with full hreflang.

## What's wired up

| Group | Item | Where |
|---|---|---|
| **Meta & indexing** | Dynamic `<title>` with site template | `app/[lang]/layout.tsx`, per-page `generateMetadata` |
| | Dynamic meta descriptions | per-page `generateMetadata` |
| | Canonical URLs (locale-aware) | `metadata.alternates.canonical` |
| | Robots meta + per-post `noindex`/`nofollow` | `metadata.robots`, frontmatter |
| | Open Graph + Twitter Card tags | `metadata.openGraph` / `metadata.twitter` |
| | Dynamic OG image per post (year-long cache) | `app/[lang]/blog/[slug]/opengraph-image.tsx` |
| | Hreflang on every translated page | sitemap + per-page `alternates.languages` |
| | JSON-LD: Organization + BlogPosting + Breadcrumb (`@graph`) | `generateBlogPostSchemaGraph` |
| | JSON-LD: WebSite + SearchAction (site-wide) | `components/seo/website-jsonld.tsx` |
| | JSON-LD: CollectionPage + ItemList (blog index, tags, authors) | `components/seo/collection-jsonld.tsx` |
| | JSON-LD: Person (author pages) | `components/seo/person-jsonld.tsx` |
| | JSON-LD: FAQPage helper | `components/seo/faq-jsonld.tsx` |
| | JSON-LD: Speakable on posts | `[slug]/page.tsx` (patches the post graph) |
| | Pagination metadata | `rel="prev"/"next"` in `[lang]/blog/page/[page]/page.tsx` |
| | Per-locale RSS feed `<link rel="alternate">` | `[lang]/layout.tsx` metadata |
| | `llms.txt` + `llms-full.txt` (llmstxt.org spec) | `app/llms.txt/route.ts`, `app/llms-full.txt/route.ts` |
| **URL & routing** | Clean slug URLs | filename → slug (override via `canonicalUrl`) |
| | Lowercase enforcement + trailing-slash strip | `proxy.ts` (308 redirects); www↔apex left to DNS/CDN |
| | Locale detection from `Accept-Language` | `proxy.ts` |
| | 301 redirect map | `redirects.json` → `next.config.ts` |
| | XML sitemap (single shard, sharding template inline) | `app/sitemap.ts` |
| | `<lastmod>` uses `max(date, updated)` | `app/sitemap.ts` `freshestDate()` |
| | HTML sitemap | `app/[lang]/sitemap/page.tsx` |
| **Content** | Blog engine + per-locale posts | `@next-md-blog/core`, `posts/{locale}/*` |
| | Tag pages with `CollectionPage` JSON-LD | `app/[lang]/blog/tags/[tag]/page.tsx` |
| | Author pages + `Person` JSON-LD | `app/[lang]/authors/[slug]/page.tsx` |
| | **Topic clusters** via `series` frontmatter + pillar pages | `lib/series.ts`, `app/[lang]/topics/[series]/page.tsx`, banner on `[slug]` |
| | Related articles (tag overlap, top 3) | `[slug]/page.tsx` |
| | Auto TOC + auto-anchor IDs | `lib/toc.ts` + `rehype-slug` |
| | Site search | `app/[lang]/search/page.tsx` |
| **Performance** | SSG via `generateStaticParams` everywhere | every dynamic route |
| | `experimental.optimizePackageImports` (lucide, react-markdown, blog) | `next.config.ts` |
| | `<link rel="preconnect">` to analytics + image CDNs | `components/resource-hints.tsx` |
| | `<link rel="preload" as="image" fetchPriority="high">` for post hero (LCP) | `[slug]/page.tsx` |
| | Per-image real dimensions (CLS = 0) | `lib/image-dims.ts` + `components/markdown/img.tsx` |
| | Cache-Control on RSS (`max-age=3600, swr=86400`) and OG (`immutable, 1y`) | route handlers |
| | AVIF/WebP image optimization | `next.config.ts` `images.formats` |
| | `next/font` Geist | `[lang]/layout.tsx` |
| | Stable scrollbar gutter (CLS) | `globals.css` |
| **Crawlability** | `robots.txt` | `app/robots.ts` |
| | Per-page `noindex` via frontmatter | `@next-md-blog/core` |
| | 404 returns status 404 (verified) | `notFound()` |
| | IndexNow ping for Bing/Yandex | `npm run indexnow` |
| **Accessibility / UX signals** | Skip-to-content link | `[lang]/layout.tsx` |
| | Mobile-first | Tailwind defaults |
| | Theme toggle without FOUC/CLS | `next-themes` + `suppressHydrationWarning` |
| | Sticky TOC ≥ `lg` | `[slug]/page.tsx` |
| | `aria-current` on pager + locale switcher | components |
| **Analytics** | Vercel Analytics + Speed Insights (default on Vercel, no-op locally) | `@vercel/analytics`, `@vercel/speed-insights` |
| | Plausible / Umami / GA4 (env-driven) | `components/analytics.tsx` |
| | Web Vitals → analytics provider | `components/web-vitals.tsx` |
| **Security** | HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy | `next.config.ts` `headers()` |
| | JSON-LD XSS escaping (`<`, `>`, `&`, LS, PS) | `components/seo/json-ld.tsx` |

## Quick start

```bash
npm install
npm run dev
```

Visit http://localhost:3000 — proxy.ts redirects to `/en` (or your `Accept-Language` match).

## Configuration

Edit **`site.config.ts`** to set:

- `name`, `description`, `url`
- `twitter` handle
- `defaultAuthor` and `authors` (with bios, avatars, social)
- `organization.{legalName, logo, sameAs}`
- `verification.{google, bing}` (set via env)
- `analytics.{provider, domain, id}` (set via env)

### Environment variables

```bash
# Site URL (auto-resolves on Vercel: VERCEL_PROJECT_PRODUCTION_URL in prod,
# VERCEL_URL on preview. NEXT_PUBLIC_SITE_URL always wins if set.)
NEXT_PUBLIC_SITE_URL=https://yourdomain.com

# Search Console / Bing Webmaster
NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION=...
NEXT_PUBLIC_BING_SITE_VERIFICATION=...

# Optional analytics provider (Vercel Analytics is on by default)
NEXT_PUBLIC_ANALYTICS_PROVIDER=plausible    # or umami | ga4
NEXT_PUBLIC_ANALYTICS_DOMAIN=yourdomain.com # for plausible
NEXT_PUBLIC_ANALYTICS_ID=...                # for umami / ga4

# IndexNow (Bing + Yandex) — optional
NEXT_PUBLIC_INDEXNOW_KEY=<32-128 hex chars>
```

If you set `NEXT_PUBLIC_INDEXNOW_KEY`, also drop `public/<KEY>.txt` containing the same key (per IndexNow spec).

## Adding a post

```bash
# Same slug in every locale you want indexed:
posts/en/my-new-post.md
posts/fr/my-new-post.md
```

Minimum frontmatter:

```yaml
---
title: "My new post"
description: "Snappy one-sentence summary."
date: "2026-06-01"
updated: "2026-06-15"      # optional — drives lastmod
tags: ["seo", "guide"]
image: "/img/hero.jpg"     # optional — preloaded as LCP
series: "getting-started"  # optional — joins a topic cluster
seriesTitle: "Getting started"  # optional — display name on the pillar
seriesOrder: 1             # optional — sort within the cluster
---
```

Other fields recognized by `@next-md-blog/core`: `author`/`authors`, `ogImage`, `canonicalUrl`, `noindex`, `nofollow`, `robots`, `alternateLanguages`.

## Topic clusters (pillar pages)

Any post with a `series` frontmatter field is automatically part of a topic cluster:

- A pillar page is generated at `/[lang]/topics/<series-slug>` listing every post in that series, sorted by `seriesOrder` (or `date` as fallback).
- Each post in the series gets an on-page banner ("Part 2 of 5 in …") linking back to the pillar and to its prev/next sibling.
- The post's `BlogPosting` JSON-LD gets an `isPartOf` reference to the pillar `CollectionPage`.

Use this pattern to build topical authority: one foundational pillar + 5–10 deep cluster posts all linking back. Google rewards this far more than scattered standalone posts.

## Adding a locale

1. Add the code to `lib/i18n.ts` (`LOCALES`, `localeNames`, `localeLabels`).
2. Copy `app/[lang]/dictionaries/en.json` → `{code}.json` and translate.
3. Add a loader entry in `app/[lang]/dictionaries.ts`.
4. Create `posts/{code}/` and translate posts.

## Adding redirects

Edit `redirects.json` — example entries are ignored. `permanent: true` → 301, omit/`false` → 307.

## Adding an author page

Add the author to `site.config.ts` `authors[]`. The slug is derived from `name` (kebab-cased). All locales of `/[lang]/authors/{slug}` are generated at build.

## Partial Pre-Rendering (PPR) opt-in

Next 16 unified PPR / `dynamicIO` / `use cache` under one flag: `cacheComponents: true` in `next.config.ts`. With it on, every data fetch becomes dynamic-by-default unless wrapped in `'use cache'`. For a fully-static content site this is more migration cost than gain, so the template ships with it **off**. To opt in:

1. Set `cacheComponents: true` in `next.config.ts`.
2. Mark every page-level loader (`getAllBlogPosts`, etc.) with `'use cache'` — either at file level or function level.
3. Remove `export const revalidate = N` from route handlers; replace with `cacheLife({ revalidate: N })` inside the cached function.
4. Ensure every `generateStaticParams` returns at least one entry (the pagination route in particular).

## 103 Early Hints

The template doesn't ship code for 103 Early Hints because the framework can't send a 103 status — that's the host's job. What we ship is the inputs hosts read:

- `<link rel="preconnect">` for analytics + image CDNs (`<ResourceHints />`).
- `<link rel="preload" as="image" fetchPriority="high">` for the post hero (LCP).
- `<link rel="preload">` for fonts (auto, via `next/font`).

Vercel and Cloudflare both promote in-document `<link rel="preload">` tags to a 103 response automatically. Nothing else is needed.

## Operating

```bash
npm run dev           # local dev, port 3000
npm run build         # production build (Turbopack)
npm start             # serve the production build
npm run lint          # ESLint on code
npm run lint:content  # content lint on all .md/.mdx in content/
npm run indexnow      # ping Bing/Yandex with all current URLs (requires deploy)
```

## Content lint (pre-commit)

`scripts/lint-content.ts` walks every markdown file under `content/` and flags the quality bugs that quietly kneecap SEO:

- Missing required frontmatter (`title`, `description`, `date`)
- Description > 200 chars (Google truncates around 155–160)
- Images without alt text, or with placeholder alt (`"image"`, `"photo"`, …)
- A body `<h1>` (the page already gets one from `frontmatter.title`)
- Skipped heading levels (h2 → h4)
- Thin content (warn, collection-aware: `blog ≥ 300 words`, `glossary ≥ 40`)
- Malformed `faq` / `howto` frontmatter (matches `@next-md-blog/core` schema)

Wired into a husky `pre-commit` hook via `lint-staged` — only staged `content/**/*.{md,mdx}` files run, so the hook stays fast. Errors block the commit; warnings don't.

Run manually on the whole tree:

```bash
npm run lint:content
```

Or narrow scope:

```bash
npm run lint:content content/blog/en
npm run lint:content content/blog/en/welcome-to-the-blog.md
```

## FAQ + HowTo rich results

Drop two optional frontmatter blocks on any post to emit `FAQPage` and `HowTo` JSON-LD alongside the article schema. Both are independently SERP-eligible rich results.

```yaml
faq:
  - question: "…"
    answer: "…"

howto:
  totalTime: "PT30M"                 # ISO 8601 duration, optional
  tool: ["Lighthouse", "Search Console"]
  yield: "A prioritized punch-list"
  steps:
    - name: "Run a crawl"
      text: "Export the report. Filter for 4xx, 5xx, redirects."
    - name: "Check canonicals"
      text: "Find every URL where the canonical doesn't match itself."
```

See `content/blog/en/seo-checklist.md` for a working example. The library (`@next-md-blog/core@1.3+`) handles emission — no app-side wiring needed.

## Verifying SEO

1. `npm run build && npm start`
2. View source on any blog post and confirm:
   - One `<link rel="canonical">` with absolute, locale-prefixed URL.
   - One `<link rel="alternate" hreflang="...">` per translated locale + `x-default`.
   - `<meta property="og:url">` matches the canonical.
   - Three `<script type="application/ld+json">`: post `@graph` (Organization + BlogPosting + BreadcrumbList + Speakable), site `WebSite` + SearchAction, standalone Organization. Duplication merges by `@id`.
   - `<link rel="preload" as="image" fetchPriority="high">` for the post's hero image.
3. `curl -I http://localhost:3000/en/blog/does-not-exist` → `HTTP/1.1 404`.
4. `curl -I http://localhost:3000/en/blog/` → `308` to `/en/blog`.
5. `curl http://localhost:3000/sitemap.xml | head` — every entry has `<xhtml:link rel="alternate" hreflang="...">` and post lastmods reflect `updated` when newer than `date`.
6. `curl http://localhost:3000/fr/feed.xml | head` — locale-specific RSS.
7. `curl http://localhost:3000/llms.txt | head` — LLM index per llmstxt.org spec.
8. Run https://search.google.com/test/rich-results on a post URL — `@graph` should validate as Organization + BlogPosting + BreadcrumbList + Speakable.
9. Run https://validator.schema.org/ on `/en/contact` — should validate as ContactPage with full Organization.

## Deferred (not in the template — by design)

These need account hookups, external services, or deployment choices that don't belong in a starter:

- **Search Console / Bing Webmaster verification** — set `NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION` / `NEXT_PUBLIC_BING_SITE_VERIFICATION` and submit the sitemap in their consoles.
- **Broken-link / orphan detection** — wire `linkinator` into CI: `npx linkinator https://yourdomain.com --recurse --skip "^(?!https://yourdomain.com)"`.
- **CDN edge caching** — host-specific (Vercel does it automatically).
- **EXIF stripping** — add `sharp` to any image upload pipeline.
- **Video transcripts / news / video sitemaps** — extend `app/sitemap.ts` + add `VideoObject` JSON-LD.
- **SERP rank tracking** — external (Ahrefs/Semrush/SerpAPI).
- **Spam protection** — no commenting system ships; add only if needed.

## Stack

- Next.js 16 (Turbopack), React 19, TypeScript strict
- Tailwind v4 + shadcn/ui (neutral, CSS variables)
- `@next-md-blog/core` for blog
- `next-themes` for dark mode without CLS
- `@formatjs/intl-localematcher` + `negotiator` for locale detection
- `rehype-slug` for heading anchors
- `image-size` for build-time CLS-safe image dimensions
- `lucide-react` for icons
- `@vercel/analytics` + `@vercel/speed-insights` for first-party metrics
