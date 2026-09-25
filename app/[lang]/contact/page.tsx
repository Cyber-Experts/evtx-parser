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
  const url = `${siteConfig.url}/${lang}/contact`;
  return {
    metadataBase: new URL(siteConfig.url),
    title: "Contact",
    description: `Get in touch with ${siteConfig.name}.`,
    alternates: {
      canonical: url,
      languages: hreflangFor(siteConfig.url, "/contact"),
    },
    openGraph: { type: "website", url, title: "Contact" },
  };
}

export default async function ContactPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const url = `${siteConfig.url}/${lang}/contact`;
  const { contactPoint, address } = siteConfig.organization;
  return (
    <>
      <JsonLd
        data={{
          "@context": "https://schema.org",
          "@type": "ContactPage",
          "@id": url,
          url,
          name: "Contact",
          inLanguage: locale,
          isPartOf: { "@id": `${siteConfig.url}/#website` },
          about: { "@id": `${siteConfig.url}/#organization` },
          mainEntity: {
            "@type": "Organization",
            "@id": `${siteConfig.url}/#organization`,
            name: siteConfig.name,
            contactPoint: {
              "@type": "ContactPoint",
              email: contactPoint.email,
              telephone: contactPoint.telephone,
              contactType: contactPoint.contactType,
              areaServed: contactPoint.areaServed,
              availableLanguage: contactPoint.availableLanguage,
            },
            address: {
              "@type": "PostalAddress",
              ...address,
            },
          },
        }}
      />
      <main
        id="main-content"
        className="container mx-auto px-4 py-12 max-w-3xl prose dark:prose-invert"
      >
        <Breadcrumbs
          items={[
            { name: dict.nav.home, href: `/${locale}` },
            { name: "Contact" },
          ]}
        />
        <h1>Contact</h1>
        <p>
          {siteConfig.name} is built by {siteConfig.organization.legalName}.
          Feedback from people using it on real cases is what shapes the
          roadmap — feature requests, bug reports and questions are all
          welcome.
        </p>
        <ul>
          <li>
            Email:{" "}
            <a href={`mailto:${contactPoint.email}`}>{contactPoint.email}</a>
          </li>
          <li>
            GitHub:{" "}
            <a href="https://github.com/Cyber-Experts">github.com/Cyber-Experts</a>
          </li>
          {contactPoint.telephone && (
            <li>
              Phone:{" "}
              <a href={`tel:${contactPoint.telephone}`}>
                {contactPoint.telephone}
              </a>
            </li>
          )}
        </ul>
        <h2>Security issues</h2>
        <p>
          If you find a vulnerability, please report it privately to{" "}
          <a href={`mailto:${contactPoint.email}`}>{contactPoint.email}</a>{" "}
          rather than opening a public issue.
        </p>
        {address.streetAddress && (
          <>
            <h2>Postal address</h2>
            <address className="not-italic">
              {siteConfig.organization.legalName}
              <br />
              {address.streetAddress}
              <br />
              {address.postalCode} {address.addressLocality}
              <br />
              {address.addressCountry}
            </address>
          </>
        )}
      </main>
    </>
  );
}
