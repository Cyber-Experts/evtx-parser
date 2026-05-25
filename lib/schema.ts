import type { Dict } from "@/src/dict/types";
import type { Locale } from "@/src/dict/locales";

import { siteConfig } from "@/site.config";
import pkg from "../package.json" with { type: "json" };

const SITE_URL = siteConfig.url;
const APP_VERSION = pkg.version;

// Single connected JSON-LD @graph per page. Nodes are cross-linked by @id
// (Organization ← WebSite ← WebPage ← {SoftwareApplication | FAQPage |
// BlogPosting | BreadcrumbList}) so Google resolves one entity model
// instead of several disjoint script blocks.

const LOGO_URL = `${SITE_URL}/logo.svg`;
const LOGO_SIZE = 256;
const ORG_ID = `${SITE_URL}#organization`;
const LOGO_ID = `${SITE_URL}#logo`;
const AUTHOR_ID = `${SITE_URL}#author-florian-amette`;
// Real Person — named E-E-A-T signal for DFIR content. sameAs anchors the
// entity to off-site identities so Google can build a confident graph.
const AUTHOR_NAME = "Florian Amette";
const AUTHOR_GIVEN_NAME = "Florian";
const AUTHOR_FAMILY_NAME = "Amette";
const AUTHOR_ALIAS = "F4K";
const AUTHOR_URL = "https://www.f4k.fr/en";
const AUTHOR_SAME_AS = [AUTHOR_URL];

const websiteId = (locale: Locale) => `${SITE_URL}/${locale}#website`;
const pageId = (url: string) => `${url}#webpage`;

type Crumb = { name: string; url?: string };

type PostInput = {
  locale: Locale;
  slug: string;
  title: string;
  description?: string;
  date: string;
  updated?: string;
  wordCount: number;
  readingMinutes?: number;
  howto?: { name?: string; steps: { name: string; text: string }[] };
  // Display labels (resolved per-locale at the call site so the schema
  // module stays unaware of the dictionary structure).
  tags?: string[];
};

function authorNode(dict: Dict) {
  return {
    "@type": "Person",
    "@id": AUTHOR_ID,
    name: AUTHOR_NAME,
    givenName: AUTHOR_GIVEN_NAME,
    familyName: AUTHOR_FAMILY_NAME,
    alternateName: AUTHOR_ALIAS,
    description: `Author at ${dict.meta.siteName} — DFIR practitioner writing on Windows Event Log forensics.`,
    url: AUTHOR_URL,
    sameAs: AUTHOR_SAME_AS,
    worksFor: { "@id": ORG_ID },
    knowsAbout: [
      "Windows Event Log",
      "EVTX",
      "Digital forensics and incident response",
      "Sysmon",
      "PowerShell logging",
      "MITRE ATT&CK",
    ],
  };
}

export const editorialAuthor = {
  name: AUTHOR_NAME,
  alias: AUTHOR_ALIAS,
  url: AUTHOR_URL,
};

function organizationNode(dict: Dict) {
  return {
    "@type": "Organization",
    "@id": ORG_ID,
    name: dict.meta.siteName,
    url: SITE_URL,
    sameAs: ["https://github.com/omerbenamram/evtx"],
    logo: {
      "@type": "ImageObject",
      "@id": LOGO_ID,
      url: LOGO_URL,
      width: LOGO_SIZE,
      height: LOGO_SIZE,
      caption: dict.meta.siteName,
    },
    image: { "@id": LOGO_ID },
  };
}

function websiteNode(locale: Locale, dict: Dict) {
  return {
    "@type": "WebSite",
    "@id": websiteId(locale),
    url: `${SITE_URL}/${locale}`,
    name: dict.meta.siteName,
    description: dict.meta.description,
    inLanguage: locale,
    publisher: { "@id": ORG_ID },
  };
}

function webPageNode(opts: {
  url: string;
  name: string;
  description: string;
  locale: Locale;
  breadcrumbId?: string;
  speakableSelectors?: string[];
  primaryImage?: string;
}) {
  return {
    "@type": "WebPage",
    "@id": pageId(opts.url),
    url: opts.url,
    name: opts.name,
    description: opts.description,
    inLanguage: opts.locale,
    isPartOf: { "@id": websiteId(opts.locale) },
    ...(opts.primaryImage
      ? {
          primaryImageOfPage: {
            "@type": "ImageObject",
            url: opts.primaryImage,
          },
        }
      : {}),
    ...(opts.breadcrumbId ? { breadcrumb: { "@id": opts.breadcrumbId } } : {}),
    ...(opts.speakableSelectors
      ? {
          speakable: {
            "@type": "SpeakableSpecification",
            cssSelector: opts.speakableSelectors,
          },
        }
      : {}),
  };
}

function breadcrumbNode(id: string, items: Crumb[]) {
  return {
    "@type": "BreadcrumbList",
    "@id": id,
    itemListElement: items.map((item, i) => ({
      "@type": "ListItem",
      position: i + 1,
      name: item.name,
      ...(item.url ? { item: item.url } : {}),
    })),
  };
}

function softwareApplicationNode(locale: Locale, dict: Dict, pageUrl: string) {
  const appUrl = `${SITE_URL}/${locale}`;
  // OG image is the closest thing we have to a product screenshot; using
  // the same URL twice (image + screenshot) is the canonical pattern for
  // web apps that don't ship a separate marketing shot.
  const heroImage = `${appUrl}/opengraph-image`;
  return {
    "@type": ["SoftwareApplication", "WebApplication"],
    "@id": `${SITE_URL}/${locale}#app`,
    name: dict.meta.siteName,
    description: dict.meta.description,
    url: appUrl,
    image: heroImage,
    screenshot: {
      "@type": "ImageObject",
      url: heroImage,
      caption: dict.meta.siteName,
    },
    applicationCategory: "SecurityApplication",
    applicationSubCategory: "Digital Forensics",
    operatingSystem: "Any (web browser)",
    browserRequirements: "Requires JavaScript, WebAssembly, and Web Workers.",
    softwareVersion: APP_VERSION,
    softwareRequirements:
      "Modern browser with WebAssembly support (Chrome, Edge, Firefox, Safari).",
    permissions: "No external permissions; file is read locally.",
    availableOnDevice: ["Desktop", "Tablet", "Mobile"],
    countriesSupported: "Worldwide",
    inLanguage: locale,
    isAccessibleForFree: true,
    offers: {
      "@type": "Offer",
      price: "0",
      priceCurrency: "USD",
      availability: "https://schema.org/InStock",
      url: appUrl,
    },
    featureList: [
      "Browser-side .evtx parsing",
      "WebAssembly (Rust)",
      "No upload — files never leave your device",
      "Event timeline with click-to-filter",
      "EventData flattened to CSV/JSON export",
      "Per-event XML inspection",
    ],
    keywords: [
      "evtx",
      "evtx parser",
      "evtx viewer",
      "Windows Event Log",
      "Windows Event Log viewer",
      "DFIR",
      "digital forensics",
      "incident response",
      "Sysmon",
      "PowerShell",
      "Kerberos",
      "Security audit",
    ].join(", "),
    audience: {
      "@type": "Audience",
      audienceType:
        "DFIR analysts, incident responders, SOC engineers, threat hunters",
    },
    softwareHelp: {
      "@type": "CreativeWork",
      url: `${appUrl}/blog`,
      name: dict.blog.indexTitle,
    },
    creator: { "@id": `${SITE_URL}#author-florian-amette` },
    author: { "@id": `${SITE_URL}#author-florian-amette` },
    maintainer: { "@id": ORG_ID },
    publisher: { "@id": ORG_ID },
    mainEntityOfPage: { "@id": pageId(pageUrl) },
  };
}

function faqPageNode(pageUrl: string, items: { q: string; a: string }[]) {
  return {
    "@type": "FAQPage",
    "@id": `${pageUrl}#faq`,
    isPartOf: { "@id": pageId(pageUrl) },
    mainEntity: items.map((item) => ({
      "@type": "Question",
      name: item.q,
      acceptedAnswer: { "@type": "Answer", text: item.a },
    })),
  };
}

function howToNode(input: PostInput) {
  if (!input.howto) return null;
  const url = `${SITE_URL}/${input.locale}/blog/${input.slug}`;
  return {
    "@type": "HowTo",
    "@id": `${url}#howto`,
    name: input.howto.name ?? input.title,
    description: input.description,
    inLanguage: input.locale,
    ...(input.readingMinutes
      ? { totalTime: `PT${input.readingMinutes}M` }
      : {}),
    step: input.howto.steps.map((s, i) => ({
      "@type": "HowToStep",
      position: i + 1,
      name: s.name,
      text: s.text,
      url: `${url}#step-${i + 1}`,
    })),
    mainEntityOfPage: { "@id": pageId(url) },
  };
}

function blogPostingNode(input: PostInput) {
  const url = `${SITE_URL}/${input.locale}/blog/${input.slug}`;
  return {
    "@type": ["BlogPosting", "TechArticle"],
    "@id": `${url}#article`,
    headline: input.title,
    description: input.description,
    inLanguage: input.locale,
    datePublished: input.date,
    dateModified: input.updated ?? input.date,
    wordCount: input.wordCount,
    ...(input.readingMinutes
      ? { timeRequired: `PT${input.readingMinutes}M` }
      : {}),
    proficiencyLevel: "Expert",
    ...(input.tags && input.tags.length > 0
      ? { keywords: input.tags.join(", "), articleSection: input.tags }
      : {}),
    image: [`${url}/opengraph-image`],
    mainEntityOfPage: { "@id": pageId(url) },
    isPartOf: { "@id": pageId(url) },
    author: { "@id": AUTHOR_ID },
    publisher: { "@id": ORG_ID },
  };
}

function graph(nodes: unknown[]) {
  return { "@context": "https://schema.org", "@graph": nodes };
}

export function jsonLdScript(schema: unknown) {
  return { __html: JSON.stringify(schema) };
}

export function homeGraph(locale: Locale, dict: Dict) {
  const url = `${SITE_URL}/${locale}`;
  return graph([
    organizationNode(dict),
    // SoftwareApplication references AUTHOR_ID via creator/author — keep
    // the Person node in the same graph so the reference resolves.
    authorNode(dict),
    websiteNode(locale, dict),
    webPageNode({
      url,
      name: dict.meta.title,
      description: dict.meta.description,
      locale,
      speakableSelectors: [".faq dt", ".faq dd"],
    }),
    softwareApplicationNode(locale, dict, url),
    faqPageNode(url, dict.faq.items),
  ]);
}

export function blogIndexGraph(locale: Locale, dict: Dict) {
  const url = `${SITE_URL}/${locale}/blog`;
  const breadcrumbId = `${url}#breadcrumb`;
  return graph([
    organizationNode(dict),
    websiteNode(locale, dict),
    webPageNode({
      url,
      name: dict.blog.indexTitle,
      description: dict.blog.indexIntro,
      locale,
      breadcrumbId,
    }),
    breadcrumbNode(breadcrumbId, [
      { name: dict.meta.siteName, url: `${SITE_URL}/${locale}` },
      { name: dict.blog.indexTitle, url },
    ]),
  ]);
}

export function blogPostGraph(opts: {
  locale: Locale;
  dict: Dict;
  post: PostInput;
}) {
  const { locale, dict, post } = opts;
  const url = `${SITE_URL}/${locale}/blog/${post.slug}`;
  const breadcrumbId = `${url}#breadcrumb`;
  const howTo = howToNode(post);
  const nodes: unknown[] = [
    organizationNode(dict),
    authorNode(dict),
    websiteNode(locale, dict),
    webPageNode({
      url,
      name: post.title,
      description: post.description ?? dict.blog.indexIntro,
      locale,
      breadcrumbId,
      primaryImage: `${url}/opengraph-image`,
    }),
    blogPostingNode(post),
    breadcrumbNode(breadcrumbId, [
      { name: dict.meta.siteName, url: `${SITE_URL}/${locale}` },
      { name: dict.blog.indexTitle, url: `${SITE_URL}/${locale}/blog` },
      { name: post.title },
    ]),
  ];
  if (howTo) nodes.push(howTo);
  return graph(nodes);
}
