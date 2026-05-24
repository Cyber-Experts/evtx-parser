/**
 * /llms.txt — index per https://llmstxt.org
 * Pairs with /llms-full.txt. Walks every collection on the site.
 */
import { composeLlmsTxt } from "@next-md-blog/core";
import { blog, glossary, site } from "@/next-md-blog.config";
import { LOCALES, DEFAULT_LOCALE } from "@/lib/i18n";

export const dynamic = "force-static";
export const revalidate = 3600;

export async function GET() {
  const body = await composeLlmsTxt({
    site,
    collections: [blog, glossary],
    locales: LOCALES,
    defaultLocale: DEFAULT_LOCALE,
  });
  return new Response(body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control":
        "public, max-age=3600, s-maxage=3600, stale-while-revalidate=86400",
    },
  });
}
