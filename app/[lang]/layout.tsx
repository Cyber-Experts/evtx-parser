import type { Metadata, Viewport } from "next";
import { notFound } from "next/navigation";
import Script from "next/script";
import "../globals.css";

import { siteConfig } from "@/site.config";
import { fontVariables } from "@/lib/fonts";
import { getDict } from "@/src/dict";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { ThemeProvider } from "@/components/theme-provider";
import { SiteHeader } from "@/components/site-header";
import { SiteFooter } from "@/components/site-footer";
import { Analytics } from "@/components/analytics";
import { WebVitals } from "@/components/web-vitals";
import { ResourceHints } from "@/components/resource-hints";
import { Analytics as VercelAnalytics } from "@vercel/analytics/next";
import { SpeedInsights } from "@vercel/speed-insights/next";
import { WebsiteJsonLd } from "@/components/seo/website-jsonld";
import { JsonLd } from "@/components/seo/json-ld";
import { generateOrganizationSchema } from "@next-md-blog/core";
import { site } from "@/next-md-blog.config";
import { getDictionary, hasLocale } from "./dictionaries";

type Params = { lang: string };

export async function generateStaticParams() {
  return LOCALES.map((lang) => ({ lang }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { lang } = await params;
  if (!hasLocale(lang)) return {};
  const url = `${siteConfig.url}/${lang}`;
  return {
    metadataBase: new URL(siteConfig.url),
    title: {
      default: siteConfig.name,
      template: `%s | ${siteConfig.name}`,
    },
    description: siteConfig.description,
    applicationName: siteConfig.name,
    referrer: "strict-origin-when-cross-origin",
    formatDetection: { email: false, address: false, telephone: false },
    verification: {
      google: siteConfig.verification.google,
      other: siteConfig.verification.bing
        ? { "msvalidate.01": siteConfig.verification.bing }
        : undefined,
    },
    alternates: {
      canonical: url,
      languages: hreflangFor(siteConfig.url, "/"),
      types: {
        "application/rss+xml": [
          { url: `/${lang}/feed.xml`, title: `${siteConfig.name} — ${lang}` },
          ...LOCALES.filter((l) => l !== lang).map((l) => ({
            url: `/${l}/feed.xml`,
            title: `${siteConfig.name} — ${l}`,
          })),
        ],
      },
    },
    openGraph: {
      type: "website",
      siteName: siteConfig.name,
      title: siteConfig.name,
      description: siteConfig.description,
      url,
      locale: lang,
      alternateLocale: LOCALES.filter((l) => l !== lang) as unknown as string[],
    },
    twitter: {
      card: "summary_large_image",
      site: siteConfig.twitter,
      creator: siteConfig.twitter,
      title: siteConfig.name,
      description: siteConfig.description,
    },
    robots: {
      index: true,
      follow: true,
      googleBot: { index: true, follow: true, "max-image-preview": "large" },
    },
  };
}

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#fcfcfe" },
    { media: "(prefers-color-scheme: dark)", color: "#0a0b14" },
  ],
  colorScheme: "light dark",
  width: "device-width",
  initialScale: 1,
};

export default async function LangLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const dict = await getDictionary(lang as Locale);
  return (
    <html
      lang={lang}
      suppressHydrationWarning
      className={fontVariables}
    >
      <head>
        <ResourceHints />
      </head>
      <body className="min-h-screen flex flex-col antialiased">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-background focus:px-3 focus:py-2 focus:ring-2 focus:ring-ring"
        >
          Skip to content
        </a>
        <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
          <SiteHeader locale={lang as Locale} dict={dict} />
          <div className="flex-1">{children}</div>
          <SiteFooter
            locale={lang as Locale}
            dict={dict}
            tagline={getDict(lang as Locale).home.footerTagline}
          />
        </ThemeProvider>
        <WebsiteJsonLd locale={lang} />
        <JsonLd data={generateOrganizationSchema(site)} />
        {/* NEXT_PUBLIC_OFFLINE=1 (self-hosted / air-gapped builds): no
            third-party scripts or beacons at all. */}
        {process.env.NEXT_PUBLIC_OFFLINE !== "1" && (
          <>
            <Analytics />
            <WebVitals />
            <VercelAnalytics />
            <SpeedInsights />
            <Script
              src="https://analytics.ahrefs.com/analytics.js"
              data-key="W+lz3lBWLPK1AkW6UtoO9w"
              strategy="afterInteractive"
            />
          </>
        )}
      </body>
    </html>
  );
}
