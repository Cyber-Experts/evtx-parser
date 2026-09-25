import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { JsonLd } from "@/components/seo/json-ld";
import { PageHero } from "@/components/PageHero";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { getDictionary, hasLocale } from "../dictionaries";

type Params = { lang: string };

const PROSE =
  "surface prose max-w-none px-6 py-8 sm:px-10 dark:prose-invert prose-p:leading-relaxed prose-p:text-ink-700 dark:prose-p:text-ink-300 prose-li:leading-relaxed prose-li:text-ink-700 dark:prose-li:text-ink-300 prose-h2:mt-10 prose-h2:mb-3 prose-h2:text-xl prose-h2:font-semibold prose-h2:tracking-[-0.01em] prose-h2:text-ink-950 dark:prose-h2:text-ink-50 prose-strong:text-ink-900 dark:prose-strong:text-ink-100 prose-a:font-medium prose-a:text-uv-700 prose-a:underline prose-a:decoration-uv-300 prose-a:underline-offset-4 prose-a:hover:decoration-uv-500 dark:prose-a:text-uv-300 dark:prose-a:decoration-uv-700 prose-code:rounded prose-code:bg-ink-100 prose-code:px-1 prose-code:py-0.5 prose-code:font-normal prose-code:text-ink-800 prose-code:before:content-none prose-code:after:content-none dark:prose-code:bg-ink-800 dark:prose-code:text-ink-200 [&>:first-child]:mt-0 [&>:last-child]:mb-0";

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
        className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-10 px-4 py-6 sm:px-6 sm:py-10"
      >
        <PageHero
          top={
            <Breadcrumbs
              items={[
                { name: dict.nav.home, href: `/${locale}` },
                { name: "Terms" },
              ]}
            />
          }
          title="Terms of Service"
          size="md"
        >
          <p className="text-sm text-ink-500 dark:text-ink-400">
            <em>Last updated: 25 September 2026.</em>
          </p>
        </PageHero>
        <article className={PROSE}>
          <p>
            {siteConfig.name} is provided by {siteConfig.organization.legalName}
            . By using the site you agree to these terms.
          </p>

          <h2>The tool</h2>
          <p>
            {siteConfig.name} is a free, browser-based viewer for Windows event
            log files. Files are processed locally in your browser and are not
            uploaded (see the <a href={`/${locale}/privacy`}>privacy policy</a>
            ).
          </p>

          <h2>Your responsibilities</h2>
          <ul>
            <li>
              Only open logs you are authorised to process, and handle them in
              line with your legal, contractual and evidence-handling
              obligations.
            </li>
            <li>
              Parsed output, decoded values, descriptions, detections and hunts
              are aids to analysis. Verify findings against the original
              evidence before relying on them.
            </li>
            <li>
              Do not attempt to disrupt the service, probe it for
              vulnerabilities without permission, or scrape it excessively.
            </li>
          </ul>

          <h2>Source code and license</h2>
          <p>
            The application&apos;s source code is published on{" "}
            <a href="https://github.com/Cyber-Experts">GitHub</a> under the
            Elastic License 2.0: you may use, modify and run it — including for
            commercial incident-response work — but you may not offer it to
            third parties as a hosted or managed service, or remove its
            licensing notices.
          </p>

          <h2>Content</h2>
          <p>
            Articles, guides and reference pages may be quoted with attribution
            and a link to the original page.
          </p>

          <h2>No warranty and limitation of liability</h2>
          <p>
            The site and the tool are provided “as is”, without warranty of any
            kind. To the extent permitted by law,{" "}
            {siteConfig.organization.legalName} is not liable for any indirect
            or consequential damages, or for decisions made on the basis of the
            tool&apos;s output.
          </p>

          <h2>Contact</h2>
          <p>
            Questions about these terms:{" "}
            <a href={`mailto:${siteConfig.organization.contactPoint.email}`}>
              {siteConfig.organization.contactPoint.email}
            </a>
            .
          </p>
        </article>
      </main>
    </>
  );
}
