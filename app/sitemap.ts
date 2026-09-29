import type { MetadataRoute } from "next";
import { composeSitemap } from "@next-md-blog/core";
import { blog, glossary } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, DEFAULT_LOCALE, hreflangFor } from "@/lib/i18n";
import { allEntries, entryLocales } from "@/lib/events";

const STATIC_PATHS = [
  "",
  "/blog",
  "/glossary",
  "/events",
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
 * Event ID encyclopedia entries: every locale that has a real page (English
 * + translations), each advertising only those alternates. Untranslated
 * locales have no page, so they are neither listed nor used as hreflang.
 */
function eventEntries(): MetadataRoute.Sitemap {
  const out: MetadataRoute.Sitemap = [];
  for (const e of allEntries()) {
    const locales = entryLocales(e);
    const path = `/events/${e.channel}/${e.id}`;
    const languages: Record<string, string> = {};
    for (const l of locales) languages[l] = `${siteConfig.url}/${l}${path}`;
    languages["x-default"] = `${siteConfig.url}/${DEFAULT_LOCALE}${path}`;
    for (const l of locales)
      out.push({
        url: `${siteConfig.url}/${l}${path}`,
        lastModified: new Date(),
        changeFrequency: "monthly",
        priority: 0.6,
        alternates: { languages },
      });
  }
  return out;
}

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const staticEntries = [
    ...STATIC_PATHS.map((p) =>
      staticEntry(p, p === "" ? "daily" : "weekly", p === "" ? 1 : 0.7),
    ),
    ...eventEntries(),
  ];
  return composeSitemap({
    collections: [blog, glossary],
    locales: LOCALES,
    staticEntries,
  });
}
