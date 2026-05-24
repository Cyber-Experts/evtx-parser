import "server-only";
import { isLocale, type Locale } from "@/lib/i18n";

export type Dictionary = {
  metadata: {
    homeTitle: string;
    homeDescription: string;
    blogTitle: string;
    blogDescription: string;
    searchTitle: string;
    searchDescription: string;
    sitemapTitle: string;
    sitemapDescription: string;
  };
  nav: { home: string; blog: string; search: string };
  toggleTheme: string;
  footer: { rights: string; sitemap: string; rss: string };
  blog: {
    tableOfContents: string;
    relatedArticles: string;
    readMore: string;
    readingTime: string;
    publishedOn: string;
    updatedOn: string;
    byAuthor: string;
    tags: string;
    share: string;
    noPosts: string;
    previous: string;
    next: string;
    page: string;
  };
  tag: { title: string; back: string };
  search: { placeholder: string; noResults: string };
  notFound: { title: string; cta: string };
  home: { heading: string; subheading: string; readBlog: string };
};

const loaders: Record<Locale, () => Promise<Dictionary>> = {
  en: () =>
    import("./dictionaries/en.json").then((m) => m.default as Dictionary),
  fr: () =>
    import("./dictionaries/fr.json").then((m) => m.default as Dictionary),
  es: () =>
    import("./dictionaries/es.json").then((m) => m.default as Dictionary),
  de: () =>
    import("./dictionaries/de.json").then((m) => m.default as Dictionary),
};

export function hasLocale(value: string): value is Locale {
  return isLocale(value);
}

export async function getDictionary(locale: Locale): Promise<Dictionary> {
  return loaders[locale]();
}
