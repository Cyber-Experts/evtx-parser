import { defineSite, defineCollection } from "@next-md-blog/core";
import { siteConfig } from "./site.config";
import { LOCALES } from "./lib/i18n";

/**
 * Site-wide settings. Shared across every collection.
 */
export const site = defineSite({
  siteName: siteConfig.name,
  siteUrl: siteConfig.url,
  defaultAuthor: siteConfig.defaultAuthor,
  authors: [...siteConfig.authors],
  ...(siteConfig.twitter ? { twitterHandle: siteConfig.twitter } : {}),
  defaultLang: "en",
  organization: {
    legalName: siteConfig.organization.legalName,
    logo: `${siteConfig.url}${siteConfig.organization.logo}`,
    sameAs: [...siteConfig.organization.sameAs],
    ...(siteConfig.organization.founder
      ? { founder: siteConfig.organization.founder }
      : {}),
    foundingDate: siteConfig.organization.foundingDate,
    address: { ...siteConfig.organization.address },
    contactPoint: {
      ...siteConfig.organization.contactPoint,
      areaServed: [...siteConfig.organization.contactPoint.areaServed],
      availableLanguage: [...siteConfig.organization.contactPoint.availableLanguage],
    },
    ...(siteConfig.organization.wikidata
      ? { wikidata: siteConfig.organization.wikidata }
      : {}),
  },
});

/**
 * Blog collection — Article schema, RSS enabled.
 */
export const blog = defineCollection({
  id: "blog",
  contentDir: "content/blog",
  pathSegment: "blog",
  indexPath: "/blog",
  site,
  defaults: { speakable: true },
});

/**
 * Glossary collection — DefinedTerm schema (Schema.org), no RSS.
 */
export const glossary = defineCollection({
  id: "glossary",
  contentDir: "content/glossary",
  pathSegment: "glossary",
  indexPath: "/glossary",
  schemaType: "DefinedTerm",
  rss: false,
  site,
});

export const collections = [blog, glossary] as const;
export { LOCALES };

export default site;
