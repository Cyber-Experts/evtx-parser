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
  const url = `${siteConfig.url}/${lang}/privacy`;
  return {
    metadataBase: new URL(siteConfig.url),
    title: "Privacy Policy",
    description: `How ${siteConfig.name} collects, uses, and protects your data.`,
    alternates: {
      canonical: url,
      languages: hreflangFor(siteConfig.url, "/privacy"),
    },
    openGraph: { type: "website", url, title: "Privacy Policy" },
  };
}

export default async function PrivacyPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const url = `${siteConfig.url}/${lang}/privacy`;
  return (
    <>
      <JsonLd
        data={{
          "@context": "https://schema.org",
          "@type": "WebPage",
          "@id": url,
          url,
          name: "Privacy Policy",
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
            { name: "Privacy" },
          ]}
        />
        <h1>Privacy Policy</h1>
        <p>
          <em>Last updated: January 2026.</em>
        </p>
        <p>
          {siteConfig.name} ({siteConfig.organization.legalName}) respects your
          privacy. This page explains what data we collect, why, and how to
          exercise your rights under GDPR/CCPA.
        </p>
        <h2>Data we collect</h2>
        <ul>
          <li>Server logs (IP, user-agent) for security and rate-limiting.</li>
          <li>
            Aggregate analytics (page views, web vitals) via{" "}
            {siteConfig.analytics.provider ?? "our analytics provider"}.
          </li>
        </ul>
        <h2>Your rights</h2>
        <p>
          You can request access, correction, or deletion of your data by
          emailing{" "}
          <a href={`mailto:${siteConfig.organization.contactPoint.email}`}>
            {siteConfig.organization.contactPoint.email}
          </a>
          .
        </p>
        <p>
          <strong>This text is a placeholder.</strong> Replace it with a policy
          reviewed by counsel before launch.
        </p>
      </main>
    </>
  );
}
