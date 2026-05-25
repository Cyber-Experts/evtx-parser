/**
 * IndexNow: ping Bing / Yandex / Seznam with every public URL.
 *
 * Run after a production deploy to nudge search engines into recrawling
 * stale pages and discovering new ones.
 *
 *   1. Pick a key (any random hex string, 8–128 chars).
 *   2. Drop it as `public/<KEY>.txt` containing the same key as its body.
 *   3. Set NEXT_PUBLIC_INDEXNOW_KEY=<KEY> and NEXT_PUBLIC_SITE_URL.
 *   4. `npm run indexnow` from CI.
 *
 * The script enumerates URLs from the filesystem (content/blog,
 * content/glossary, lib/event-id-data.ts, the static page list). It
 * intentionally avoids importing next-md-blog.config because that pulls in
 * an ESM-only dependency tsx can't always resolve.
 */
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { siteConfig } from "../site.config";
import { LOCALES } from "../lib/i18n";
import { allEventIds } from "../lib/event-id-data";

const KEY = process.env.NEXT_PUBLIC_INDEXNOW_KEY;
const HOST = siteConfig.url.replace(/^https?:\/\//, "");
const DRY_RUN = process.argv.includes("--dry-run");

async function slugsIn(dir: string): Promise<string[]> {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    return entries
      .filter((e) => e.isFile() && e.name.endsWith(".md"))
      .map((e) => e.name.replace(/\.md$/, ""));
  } catch {
    return [];
  }
}

// Pull `tags: [...]` out of a YAML frontmatter block with a cheap regex.
// We're only scanning files that already passed `lint:content`, so the
// structure is predictable enough to avoid pulling in gray-matter just
// for one field.
const FM_RE = /^---\s*\n([\s\S]*?)\n---/;
const TAGS_LINE_RE = /^tags:\s*(\[.*\]|.+)$/m;

async function tagsInPost(file: string): Promise<string[]> {
  try {
    const raw = await readFile(file, "utf8");
    const fm = raw.match(FM_RE)?.[1] ?? "";
    const line = fm.match(TAGS_LINE_RE)?.[1];
    if (!line) return [];
    if (line.trim().startsWith("[")) {
      return line
        .replace(/^\[|\]$/g, "")
        .split(",")
        .map((s) => s.trim().replace(/^["']|["']$/g, ""))
        .filter(Boolean);
    }
    // List-style YAML: collect "- tag" lines that follow.
    const lines = fm.split("\n");
    const idx = lines.findIndex((l) => /^tags:\s*$/.test(l));
    if (idx < 0) return [];
    const out: string[] = [];
    for (let i = idx + 1; i < lines.length; i++) {
      const m = lines[i].match(/^\s*-\s*(.+?)\s*$/);
      if (!m) break;
      out.push(m[1].replace(/^["']|["']$/g, ""));
    }
    return out;
  } catch {
    return [];
  }
}

async function main() {
  if (!DRY_RUN && !KEY) {
    console.error("Missing NEXT_PUBLIC_INDEXNOW_KEY");
    process.exit(1);
  }
  if (!DRY_RUN && siteConfig.url.startsWith("http://localhost")) {
    console.error("Refusing to ping IndexNow for localhost");
    process.exit(1);
  }
  if (!DRY_RUN && KEY) {
    // Verify the key file is reachable so search engines can validate it
    // when they fetch back. This is a deploy smoke test, not a strict
    // requirement of IndexNow itself.
    const keyUrl = `${siteConfig.url}/${KEY}.txt`;
    try {
      const probe = await fetch(keyUrl);
      const body = (await probe.text()).trim();
      if (!probe.ok || body !== KEY) {
        console.warn(
          `Warning: key file at ${keyUrl} doesn't match NEXT_PUBLIC_INDEXNOW_KEY (status ${probe.status}). Continuing anyway.`,
        );
      }
    } catch {
      console.warn(`Warning: couldn't reach ${keyUrl}. Continuing anyway.`);
    }
  }

  const urls = new Set<string>();
  urls.add(siteConfig.url);

  const eventIds = allEventIds();
  const tagsAcross = new Set<string>();

  for (const lang of LOCALES) {
    // Static lang routes.
    urls.add(`${siteConfig.url}/${lang}`);
    urls.add(`${siteConfig.url}/${lang}/blog`);
    urls.add(`${siteConfig.url}/${lang}/glossary`);
    urls.add(`${siteConfig.url}/${lang}/event-ids`);
    urls.add(`${siteConfig.url}/${lang}/tools`);
    urls.add(`${siteConfig.url}/${lang}/authors`);
    urls.add(`${siteConfig.url}/${lang}/sitemap`);
    urls.add(`${siteConfig.url}/${lang}/contact`);
    urls.add(`${siteConfig.url}/${lang}/privacy`);
    urls.add(`${siteConfig.url}/${lang}/terms`);
    urls.add(`${siteConfig.url}/${lang}/search`);

    // Blog posts. Harvest tags while we're already reading frontmatter.
    const blogDir = join(process.cwd(), "content/blog", lang);
    const blogSlugs = await slugsIn(blogDir);
    for (const slug of blogSlugs) {
      urls.add(`${siteConfig.url}/${lang}/blog/${slug}`);
      const tags = await tagsInPost(join(blogDir, `${slug}.md`));
      for (const t of tags) tagsAcross.add(t.toLowerCase());
    }

    // Glossary terms.
    const glossarySlugs = await slugsIn(
      join(process.cwd(), "content/glossary", lang),
    );
    for (const slug of glossarySlugs) {
      urls.add(`${siteConfig.url}/${lang}/glossary/${slug}`);
    }

    // Event-ID landing pages.
    for (const event of eventIds) {
      urls.add(`${siteConfig.url}/${lang}/event-id/${event.id}`);
    }
  }

  // Tag archives — one URL per (locale, tag) once we know every tag in
  // play. The page only renders if posts exist for that locale+tag, but
  // submitting them all is cheap and IndexNow tolerates 404s.
  for (const lang of LOCALES) {
    for (const tag of tagsAcross) {
      urls.add(`${siteConfig.url}/${lang}/blog/tags/${encodeURIComponent(tag)}`);
    }
  }

  const urlList = [...urls];

  if (DRY_RUN) {
    console.log(`[dry-run] would submit ${urlList.length} URLs to IndexNow`);
    for (const u of urlList.slice(0, 10)) console.log(`  ${u}`);
    if (urlList.length > 10) console.log(`  …and ${urlList.length - 10} more`);
    return;
  }

  // Fetch is required to be globally available in Node 20+.
  const res = await fetch("https://api.indexnow.org/IndexNow", {
    method: "POST",
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify({
      host: HOST,
      key: KEY,
      keyLocation: `${siteConfig.url}/${KEY}.txt`,
      urlList,
    }),
  });

  if (res.ok || res.status === 202) {
    console.log(`IndexNow OK (${res.status}) — submitted ${urlList.length} URLs`);
  } else {
    const body = await readBody(res);
    console.error(`IndexNow failed: ${res.status} ${body}`);
    process.exit(1);
  }
}

async function readBody(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
