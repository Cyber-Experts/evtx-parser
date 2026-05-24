function resolveSiteUrl(): string {
  // 1. Explicit override always wins.
  if (process.env.NEXT_PUBLIC_SITE_URL) {
    return process.env.NEXT_PUBLIC_SITE_URL.replace(/\/$/, "");
  }
  // 2. On Vercel production, use the project's stable production URL.
  if (
    process.env.VERCEL_ENV === "production" &&
    process.env.VERCEL_PROJECT_PRODUCTION_URL
  ) {
    return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`;
  }
  // 3. On any other Vercel deployment (preview, branch), use the per-deploy URL
  //    so OG / canonical / sitemap point to the preview itself.
  if (process.env.VERCEL_URL) {
    return `https://${process.env.VERCEL_URL}`;
  }
  // 4. Local dev fallback.
  return "http://localhost:3000";
}

export const siteConfig = {
  name: "SEO Template",
  shortName: "SEO Template",
  description:
    "An SEO-optimized, internationalized Next.js starter built on shadcn/ui and @next-md-blog/core.",
  url: resolveSiteUrl(),
  twitter: "@your_handle",
  defaultAuthor: "Your Name",
  authors: [
    {
      name: "Your Name",
      url: "https://example.com",
      twitter: "@your_handle",
    },
  ],
  defaultOgImage: "/opengraph-image",
  organization: {
    legalName: "Your Company, Inc.",
    logo: "/icon",
    foundingDate: "2020-01-01",
    founder: "Your Name",
    // Optional but high-impact: populate this once you have a Wikidata entity.
    // Example: "https://www.wikidata.org/wiki/Q1234567"
    wikidata: undefined as string | undefined,
    sameAs: [
      "https://twitter.com/your_handle",
      "https://github.com/your-org",
    ],
    address: {
      streetAddress: "1 Example Street",
      addressLocality: "Paris",
      addressRegion: "Île-de-France",
      postalCode: "75000",
      addressCountry: "FR",
    },
    contactPoint: {
      email: "hello@example.com",
      telephone: undefined as string | undefined,
      contactType: "customer support",
      areaServed: ["FR", "EU"],
      availableLanguage: ["en", "fr", "es", "de"],
    },
  },
  verification: {
    google: process.env.NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION,
    bing: process.env.NEXT_PUBLIC_BING_SITE_VERIFICATION,
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
