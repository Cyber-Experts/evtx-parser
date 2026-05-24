/**
 * /llms-full.txt — concatenated post bodies for LLM ingestion.
 * Default locale only; widen with `locales: LOCALES` if useful.
 */
import { composeLlmsFullTxt } from "@next-md-blog/core";
import { blog, glossary, site } from "@/next-md-blog.config";
import { DEFAULT_LOCALE } from "@/lib/i18n";

export const dynamic = "force-static";
export const revalidate = 3600;

export async function GET() {
  const body = await composeLlmsFullTxt({
    site,
    collections: [blog, glossary],
    locales: [DEFAULT_LOCALE],
  });
  return new Response(body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control":
        "public, max-age=3600, s-maxage=3600, stale-while-revalidate=86400",
    },
  });
}
