function resolveSiteUrl(): string {
  if (process.env.NEXT_PUBLIC_SITE_URL) {
    return process.env.NEXT_PUBLIC_SITE_URL.replace(/\/$/, "");
  }
  if (
    process.env.VERCEL_ENV === "production" &&
    process.env.VERCEL_PROJECT_PRODUCTION_URL
  ) {
    return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`;
  }
  if (process.env.VERCEL_URL) {
    return `https://${process.env.VERCEL_URL}`;
  }
  return "http://localhost:3000";
}

export const siteConfig = {
  name: "EVTX parser",
  shortName: "EVTX parser",
  description:
    "Free in-browser .evtx parser for Windows Event Log forensics. No upload, no install — drop a file and triage logons, services and PowerShell in seconds.",
  url: resolveSiteUrl(),
  twitter: undefined as string | undefined,
  // Named author for E-E-A-T — the schema graph resolves this string
  // against the `authors` array below so JSON-LD emits a full Person node
  // (with sameAs pointing at f4k.fr) on every post that doesn't override
  // it in frontmatter.
  defaultAuthor: "Florian Amette",
  authors: [
    {
      name: "Florian Amette",
      bio: "DFIR practitioner writing on Windows Event Log forensics. Alias: F4K.",
      url: "https://www.f4k.fr",
    },
  ] as Array<{
    name: string;
    email?: string;
    bio?: string;
    avatar?: string;
    twitter?: string;
    github?: string;
    url?: string;
  }>,
  defaultOgImage: "/opengraph-image",
  organization: {
    legalName: "EVTX parser",
    logo: "/icon",
    foundingDate: "2025-01-01",
    founder: "Florian Amette" as string | undefined,
    wikidata: undefined as string | undefined,
    sameAs: [] as string[],
    address: {
      streetAddress: undefined as string | undefined,
      addressLocality: undefined as string | undefined,
      addressRegion: undefined as string | undefined,
      postalCode: undefined as string | undefined,
      addressCountry: undefined as string | undefined,
    },
    contactPoint: {
      email: undefined as string | undefined,
      telephone: undefined as string | undefined,
      contactType: "customer support",
      areaServed: [] as string[],
      availableLanguage: ["en", "fr", "es", "de", "it", "pt", "ja", "zh"],
    },
  },
  verification: {
    google: process.env.NEXT_PUBLIC_GSC_VERIFICATION,
    bing: process.env.NEXT_PUBLIC_BING_VERIFICATION,
    yandex: process.env.NEXT_PUBLIC_YANDEX_VERIFICATION,
  },
  analytics: {
    provider: process.env.NEXT_PUBLIC_ANALYTICS_PROVIDER as
      | "plausible"
      | "umami"
      | "ga4"
      | undefined,
    domain: process.env.NEXT_PUBLIC_ANALYTICS_DOMAIN,
    id: process.env.NEXT_PUBLIC_ANALYTICS_ID,
  },
} as const;

export type SiteConfig = typeof siteConfig;
