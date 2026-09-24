import type { MetadataRoute } from "next";
import { composeSitemap } from "@next-md-blog/core";
import { blog, glossary } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, DEFAULT_LOCALE, hreflangFor } from "@/lib/i18n";
import { allEventIds, isEventIdIndexable } from "@/lib/event-id-data";

const STATIC_PATHS = [
  "",
  "/blog",
  "/glossary",
  "/event-ids",
  "/tools",
  "/evtx-to-xml",
  "/evtx-to-csv",
  "/evtx-to-txt",
  "/evtx-to-json",
  "/evtx-dump-online",
  "/evtx-viewer-mac-linux",
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
 * Per-Event-ID landing pages — English only, and only for IDs without a
 * dedicated blog post (see isEventIdIndexable). The other variants are
 * noindex, so they stay out of the sitemap.
 */
function eventIdEntries(): MetadataRoute.Sitemap {
  return allEventIds()
    .filter((e) => isEventIdIndexable(e, DEFAULT_LOCALE))
    .map((e) => ({
      url: `${siteConfig.url}/${DEFAULT_LOCALE}/event-id/${e.id}`,
      lastModified: new Date(),
      changeFrequency: "monthly" as const,
      priority: 0.6,
    }));
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
