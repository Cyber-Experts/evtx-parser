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
  return "https://www.evtxparser.com";
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
    legalName: "CE Cyber Experts",
    /** Company website (the publisher of this site). */
    url: "https://www.cyberexperts.io",
    logo: "/icon",
    foundingDate: "2023-05-30",
    founder: "Florian Amette" as string | undefined,
    wikidata: undefined as string | undefined,
    sameAs: [
      "https://www.cyberexperts.io",
      "https://github.com/Cyber-Experts",
    ] as string[],
    address: {
      streetAddress: "12 rue de Port-Mahon" as string | undefined,
      addressLocality: "Paris" as string | undefined,
      addressRegion: "Île-de-France" as string | undefined,
      postalCode: "75002" as string | undefined,
      addressCountry: "FR" as string | undefined,
    },
    /** French company register details (legal notice + JSON-LD identifiers). */
    legal: {
      form: "SASU (société par actions simplifiée unipersonnelle)",
      capital: "42 €",
      siren: "953 156 791",
      siret: "953 156 791 00014",
      rcs: "953 156 791 R.C.S. Paris",
      naf: "62.02A",
      president: "FAKGROUP",
    },
    contactPoint: {
      email: "contact@evtxparser.com" as string | undefined,
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
      "plausible" | "umami" | "ga4" | undefined,
    domain: process.env.NEXT_PUBLIC_ANALYTICS_DOMAIN,
    id: process.env.NEXT_PUBLIC_ANALYTICS_ID,
  },
} as const;

export type SiteConfig = typeof siteConfig;
