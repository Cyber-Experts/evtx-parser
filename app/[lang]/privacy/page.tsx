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
          <em>Last updated: 25 September 2026.</em>
        </p>
        <p>
          {siteConfig.name} is operated by {siteConfig.organization.legalName} (
          <a href="https://github.com/Cyber-Experts">github.com/Cyber-Experts</a>
          ). This policy explains what data is processed when you use the site,
          and what is not.
        </p>

        <h2>Your event log files never leave your device</h2>
        <p>
          The <code>.evtx</code> files you open are parsed inside your browser
          by a WebAssembly module running in a web worker. Their content, file
          names and parsed events are never uploaded to us or to anyone else.
          Searching, filtering, hunts, exports and reports are all computed
          locally. Once the page has loaded you can disconnect from the network
          and the viewer keeps working.
        </p>

        <h2>Data stored in your browser</h2>
        <ul>
          <li>
            <strong>Saved sessions</strong> — only if you click{" "}
            <em>Save session</em>: the files and your analysis state (search,
            filters, bookmarks, notes) are stored in your browser&apos;s
            IndexedDB on this device. They are not synchronised or sent
            anywhere. Delete them from the start screen or by clearing this
            site&apos;s data in your browser.
          </li>
          <li>
            <strong>Preferences</strong> — theme, UTC/local time display and
            column layout are kept in <code>localStorage</code>.
          </li>
        </ul>
        <p>We do not use advertising or tracking cookies.</p>

        <h2>Analytics</h2>
        <p>
          To understand how the site is used, we collect aggregate, cookieless
          statistics with Vercel Web Analytics, Vercel Speed Insights
          (performance metrics) and Ahrefs Web Analytics: pages viewed,
          referrer, country, browser and device type. Two usage events are
          recorded: that a file was parsed (with a file-size bucket and the
          number of records) and that an export was made (format and number of
          rows). These events never include file names or any event content.
        </p>

        <h2>Hosting</h2>
        <p>
          The site is hosted by Vercel, which processes technical request data
          (such as IP address and user agent) to deliver the site and protect
          it against abuse.
        </p>

        <h2>Self-hosted instances</h2>
        <p>
          The source code is available, so you can run your own instance. Built
          with <code>NEXT_PUBLIC_OFFLINE=1</code>, it loads no third-party
          script and sends no analytics at all.
        </p>

        <h2>Your rights</h2>
        <p>
          Under the GDPR you can request access to, correction or deletion of
          personal data we hold about you, or object to its processing, by
          emailing{" "}
          <a href={`mailto:${siteConfig.organization.contactPoint.email}`}>
            {siteConfig.organization.contactPoint.email}
          </a>
          . Because log files are processed only on your device, we hold no
          copy of them.
        </p>
      </main>
    </>
  );
}
