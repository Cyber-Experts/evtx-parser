import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { JsonLd } from "@/components/seo/json-ld";
import { GitHubMark } from "@/components/GitHubMark";
import { PageHero } from "@/components/PageHero";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { getDictionary, hasLocale } from "../dictionaries";

type Params = { lang: string };

const CARD =
  "surface surface-interactive flex h-full flex-col gap-1.5 px-6 py-5";
const CARD_LABEL = "eyebrow flex items-center gap-1.5";
const CARD_VALUE = "font-medium break-all text-ink-950 dark:text-ink-50";
const LINK =
  "font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700";

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
        className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-10 px-4 py-6 sm:px-6 sm:py-10"
      >
        <PageHero
          top={
            <Breadcrumbs
              items={[
                { name: dict.nav.home, href: `/${locale}` },
                { name: "Contact" },
              ]}
            />
          }
          title="Contact"
          size="md"
          intro={
            <p>
              {siteConfig.name} is built by {siteConfig.organization.legalName}.
              Feedback from people using it on real cases is what shapes the
              roadmap — feature requests, bug reports and questions are all
              welcome.
            </p>
          }
        />
        <ul className="grid gap-4 sm:grid-cols-2">
          <li>
            <a href={`mailto:${contactPoint.email}`} className={CARD}>
              <span className={CARD_LABEL}>Email</span>
              <span className={CARD_VALUE}>{contactPoint.email}</span>
            </a>
          </li>
          <li>
            <a href="https://github.com/Cyber-Experts" className={CARD}>
              <span className={CARD_LABEL}>
                <GitHubMark className="h-3.5 w-3.5" />
                GitHub
              </span>
              <span className={CARD_VALUE}>github.com/Cyber-Experts</span>
            </a>
          </li>
          {contactPoint.telephone && (
            <li>
              <a href={`tel:${contactPoint.telephone}`} className={CARD}>
                <span className={CARD_LABEL}>Phone</span>
                <span className={CARD_VALUE}>{contactPoint.telephone}</span>
              </a>
            </li>
          )}
        </ul>
        <section className="surface flex flex-col gap-3 px-6 py-8 sm:px-10">
          <h2 className="text-xl text-ink-950 dark:text-ink-50">
            Security issues
          </h2>
          <p className="leading-relaxed text-ink-700 dark:text-ink-300">
            If you find a vulnerability, please report it privately to{" "}
            <a href={`mailto:${contactPoint.email}`} className={LINK}>
              {contactPoint.email}
            </a>{" "}
            rather than opening a public issue.
          </p>
          {address.streetAddress && (
            <>
              <h2 className="mt-6 text-xl text-ink-950 dark:text-ink-50">
                Postal address
              </h2>
              <address className="leading-relaxed text-ink-700 not-italic dark:text-ink-300">
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
        </section>
      </main>
    </>
  );
}
