import type { MetadataRoute } from "next";
import { composeSitemap } from "@next-md-blog/core";
import { blog, glossary } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, DEFAULT_LOCALE, hreflangFor } from "@/lib/i18n";
import { allEventIdParams } from "@/lib/event-id-data";

const STATIC_PATHS = [
  "",
  "/blog",
  "/glossary",
  "/event-ids",
  "/tools",
  "/evtx-to-xml",
  "/security-evtx",
  "/system-evtx",
  "/authors",
  "/search",
  "/sitemap",
];

function staticEntry(
  path: string,
  changeFrequency: MetadataRoute.Sitemap[number]["changeFrequency"] = "weekly",
  priority = 0.7,
): MetadataRoute.Sitemap[number] {
  const url = `${siteConfig.url}/${DEFAULT_LOCALE}${path === "" ? "" : path}`;
  return {
    url,
    lastModified: new Date(),
    changeFrequency,
    priority,
    alternates: {
      languages: hreflangFor(siteConfig.url, path === "" ? "/" : path),
    },
  };
}

/**
 * Per-Event-ID landing pages — curated, finite, available in every locale.
 * Each gets a sitemap row with the full hreflang map.
 */
function eventIdEntries(): MetadataRoute.Sitemap {
  const out: MetadataRoute.Sitemap = [];
  for (const { id } of allEventIdParams()) {
    out.push(
      staticEntry(`/event-id/${id}`, "monthly", 0.6),
    );
  }
  return out;
}

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const staticEntries = [
    ...STATIC_PATHS.map((p) =>
      staticEntry(p, p === "" ? "daily" : "weekly", p === "" ? 1 : 0.7),
    ),
    ...eventIdEntries(),
  ];
  return composeSitemap({
    collections: [blog, glossary],
    locales: LOCALES,
    staticEntries,
  });
}
