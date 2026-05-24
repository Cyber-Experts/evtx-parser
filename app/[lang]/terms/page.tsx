import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { JsonLd } from "@/components/seo/json-ld";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { getDictionary, hasLocale } from "../dictionaries";

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
  const url = `${siteConfig.url}/${lang}/terms`;
  return {
    metadataBase: new URL(siteConfig.url),
    title: "Terms of Service",
    description: `The terms under which you may use ${siteConfig.name}.`,
    alternates: {
      canonical: url,
      languages: hreflangFor(siteConfig.url, "/terms"),
    },
    openGraph: { type: "website", url, title: "Terms of Service" },
  };
}

export default async function TermsPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const url = `${siteConfig.url}/${lang}/terms`;
  return (
    <>
      <JsonLd
        data={{
          "@context": "https://schema.org",
          "@type": "WebPage",
          "@id": url,
          url,
          name: "Terms of Service",
          inLanguage: locale,
          isPartOf: { "@id": `${siteConfig.url}/#website` },
          about: { "@id": `${siteConfig.url}/#organization` },
          datePublished: "2026-01-01",
        }}
      />
      <main
        id="main-content"
        className="container mx-auto px-4 py-12 max-w-3xl prose dark:prose-invert"
      >
        <Breadcrumbs
          items={[
            { name: dict.nav.home, href: `/${locale}` },
            { name: "Terms" },
          ]}
        />
        <h1>Terms of Service</h1>
        <p>
          <em>Last updated: January 2026.</em>
        </p>
        <p>
          By using {siteConfig.name}, you agree to these terms. Content on this
          site is provided as-is, without warranties.
        </p>
        <h2>Acceptable use</h2>
        <p>
          Do not scrape excessively, attempt to disrupt the service, or
          republish content without attribution.
        </p>
        <h2>Liability</h2>
        <p>
          {siteConfig.organization.legalName} is not liable for any indirect
          damages arising from your use of this site.
        </p>
        <p>
          <strong>This text is a placeholder.</strong> Replace with terms
          reviewed by counsel before launch.
        </p>
      </main>
    </>
  );
}
