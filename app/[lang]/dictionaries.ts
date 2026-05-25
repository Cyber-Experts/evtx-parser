import "server-only";
import { isLocale, type Locale } from "@/lib/i18n";
import { getDict, type Dict } from "@/src/dict";

/**
 * The shape the template's UI components expect. We adapt the richer
 * evtx-parser `Dict` into this shape so the existing template components
 * (SiteHeader, SiteFooter, blog list, pagination, breadcrumbs labels…) keep
 * working without forcing edits across 8 locale files for template-y strings.
 *
 * Strings absent from the evtx-parser dict get English defaults — translate
 * by extending `src/dict/types.ts` + each locale's file.
 */
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
  nav: { home: string; blog: string; authors: string; search: string };
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
  authors: {
    indexTitle: string;
    indexDescription: string;
    postsCount: string;
    backToIndex: string;
  };
  search: { placeholder: string; noResults: string };
  notFound: { title: string; cta: string };
  home: { heading: string; subheading: string; readBlog: string };
};

export function hasLocale(value: string): value is Locale {
  return isLocale(value);
}

function adapt(dict: Dict): Dictionary {
  return {
    metadata: {
      homeTitle: dict.meta.title,
      homeDescription: dict.meta.description,
      blogTitle: dict.blog.indexTitle,
      blogDescription: dict.blog.indexIntro,
      searchTitle: "Search",
      searchDescription: "Search the blog.",
      sitemapTitle: "Sitemap",
      sitemapDescription: "All pages on the site.",
    },
    nav: {
      home: dict.breadcrumb.home,
      blog: dict.footer.blog,
      authors: "Authors",
      search: "Search",
    },
    toggleTheme: "Toggle theme",
    footer: {
      rights: "All rights reserved.",
      sitemap: "Sitemap",
      rss: "RSS",
    },
    blog: {
      tableOfContents: dict.toc.heading,
      relatedArticles: dict.blog.relatedHeading,
      readMore: dict.blog.readMore,
      readingTime: dict.blog.readingTime,
      publishedOn: dict.blog.publishedOn,
      updatedOn: dict.blog.updatedOn,
      byAuthor: dict.blog.byLine,
      tags: dict.tags.tagsOnPost,
      share: "Share",
      noPosts: "No posts yet.",
      previous: dict.blog.prevPost,
      next: dict.blog.nextPost,
      page: "Page",
    },
    tag: { title: dict.tags.tagTitleTemplate, back: dict.blog.backToBlog },
    authors: {
      indexTitle: "Authors",
      indexDescription: `The people writing on ${dict.meta.siteName}.`,
      postsCount: dict.tags.postsCount,
      backToIndex: "← All authors",
    },
    search: { placeholder: "Search posts…", noResults: "No results." },
    notFound: {
      title: dict.notFound.heading,
      cta: dict.notFound.backHome,
    },
    home: {
      heading: dict.home.heading,
      subheading: dict.home.intro,
      readBlog: dict.blog.readMore,
    },
  };
}

export async function getDictionary(locale: Locale): Promise<Dictionary> {
  return adapt(getDict(locale));
}
