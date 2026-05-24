/**
 * IndexNow: ping Bing/Yandex/Seznam with changed URLs.
 * https://www.indexnow.org/documentation
 *
 * Setup:
 *   1. Pick a key (any random hex string, 8–128 chars).
 *   2. Host it at https://yourdomain.com/<KEY>.txt with that same key as the body.
 *      (Put the file in /public/<KEY>.txt — Next.js serves it as-is.)
 *   3. Set NEXT_PUBLIC_INDEXNOW_KEY=<KEY> + NEXT_PUBLIC_SITE_URL.
 *   4. Run `npm run indexnow` from CI after deploy.
 *
 * The endpoint accepts up to 10,000 URLs per request.
 */
import { blog, glossary } from "../next-md-blog.config";
import { siteConfig } from "../site.config";
import { LOCALES } from "../lib/i18n";

const KEY = process.env.NEXT_PUBLIC_INDEXNOW_KEY;
const HOST = siteConfig.url.replace(/^https?:\/\//, "");

async function main() {
  if (!KEY) {
    console.error("Missing NEXT_PUBLIC_INDEXNOW_KEY");
    process.exit(1);
  }
  if (siteConfig.url.startsWith("http://localhost")) {
    console.error("Refusing to ping IndexNow for localhost");
    process.exit(1);
  }

  const urls = new Set<string>();
  urls.add(siteConfig.url);
  for (const lang of LOCALES) {
    urls.add(`${siteConfig.url}/${lang}`);
    urls.add(`${siteConfig.url}/${lang}/blog`);
    urls.add(`${siteConfig.url}/${lang}/glossary`);
    for (const collection of [blog, glossary]) {
      const docs = await collection.getAll({ locale: lang });
      for (const d of docs) urls.add(collection.url(d.slug, lang));
    }
  }

  const body = {
    host: HOST,
    key: KEY,
    keyLocation: `${siteConfig.url}/${KEY}.txt`,
    urlList: [...urls],
  };

  const res = await fetch("https://api.indexnow.org/IndexNow", {
    method: "POST",
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  });

  if (res.ok || res.status === 202) {
    console.log(`IndexNow OK (${res.status}) — submitted ${urls.size} URLs`);
  } else {
    console.error(`IndexNow failed: ${res.status} ${await res.text()}`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
