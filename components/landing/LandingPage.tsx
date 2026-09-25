import Link from "next/link";
import type { Metadata } from "next";

import { getDict } from "@/src/dict";
import type { Locale } from "@/src/dict/locales";
import { jsonLdScript } from "@/lib/schema";
import { Breadcrumbs } from "@/components/BreadcrumbsEvtx";
import { RELATED_HEADING, type LandingContent } from "@/lib/landing/landing";
import {
  LANDINGS,
  LANDING_PATHS,
  type LandingPath,
} from "@/lib/landing/registry";
import { pickLocale } from "@/lib/landing/locale-content";
import {
  SITE_URL,
  canonicalFor,
  localeAlternates,
  OG_LOCALE,
} from "@/app/_lib/site";

export function landingMetadata(path: LandingPath, locale: Locale): Metadata {
  const c = pickLocale(LANDINGS[path], locale);
  const url = canonicalFor(locale, path);
  return {
    metadataBase: new URL(SITE_URL),
    title: c.metaTitle,
    description: c.metaDescription,
    alternates: {
      canonical: url,
      languages: localeAlternates(path),
    },
    openGraph: {
      type: "website",
      siteName: getDict(locale).meta.siteName,
      title: c.metaTitle,
      description: c.metaDescription,
      url,
      locale: OG_LOCALE[locale],
      images: [
        {
          url: `${canonicalFor(locale)}/opengraph-image`,
          width: 1200,
          height: 630,
          alt: c.metaTitle,
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: c.metaTitle,
      description: c.metaDescription,
      images: [`${canonicalFor(locale)}/opengraph-image`],
    },
  };
}

function buildGraph(
  locale: Locale,
  url: string,
  c: LandingContent,
  siteName: string,
) {
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebPage",
        "@id": `${url}#webpage`,
        url,
        name: c.metaTitle,
        description: c.metaDescription,
        inLanguage: locale,
        isPartOf: { "@id": `${SITE_URL}/${locale}#website` },
      },
      {
        "@type": "HowTo",
        "@id": `${url}#howto`,
        name: c.stepsHeading,
        step: c.steps.map((s, i) => ({
          "@type": "HowToStep",
          position: i + 1,
          name: s.title,
          text: s.body,
        })),
      },
      {
        "@type": "FAQPage",
        "@id": `${url}#faq`,
        mainEntity: c.faq.map((f) => ({
          "@type": "Question",
          name: f.q,
          acceptedAnswer: { "@type": "Answer", text: f.a },
        })),
      },
      {
        "@type": "BreadcrumbList",
        "@id": `${url}#breadcrumb`,
        itemListElement: [
          {
            "@type": "ListItem",
            position: 1,
            name: siteName,
            item: `${SITE_URL}/${locale}`,
          },
          { "@type": "ListItem", position: 2, name: c.h1, item: url },
        ],
      },
    ],
  };
}

export function LandingPage({
  path,
  locale,
}: {
  path: LandingPath;
  locale: Locale;
}) {
  const dict = getDict(locale);
  const c = pickLocale(LANDINGS[path], locale);
  const url = canonicalFor(locale, path);
  const ld = buildGraph(locale, url, c, dict.meta.siteName);
  const related = LANDING_PATHS.filter((p) => p !== path);

  return (
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-8 px-4 py-6 sm:px-6 sm:py-10">
      <Breadcrumbs
        dict={dict}
        items={[
          { label: dict.breadcrumb.home, href: `/${locale}` },
          { label: c.h1 },
        ]}
      />

      <header className="flex flex-col gap-3">
        <h1 className="text-2xl font-semibold tracking-tight text-ink-900 dark:text-ink-100 sm:text-3xl">
          {c.h1}
        </h1>
        <p className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">
          {c.intro}
        </p>
        <div>
          <Link
            href={`/${locale}`}
            className="inline-block rounded-md border border-ink-900 bg-ink-900 px-4 py-2 text-sm font-medium text-ink-50 hover:bg-ink-700 dark:border-ink-100 dark:bg-ink-100 dark:text-ink-900 dark:hover:bg-ink-300"
          >
            {c.ctaLabel} ↗
          </Link>
        </div>
      </header>

      <section
        aria-labelledby="formats-heading"
        className="flex flex-col gap-4 border-t border-ink-200 pt-6 dark:border-ink-800"
      >
        <h2 id="formats-heading" className="font-mono text-base font-semibold">
          {c.formatsHeading}
        </h2>
        {c.formats.map((f) => (
          <div key={f.name} className="flex flex-col gap-1">
            <h3 className="text-sm font-semibold text-ink-900 dark:text-ink-100">
              {f.name}
            </h3>
            <p className="text-sm leading-relaxed text-ink-700 dark:text-ink-300">
              {f.body}
            </p>
            {f.code ? (
              <pre className="mt-1 overflow-x-auto rounded border border-ink-200 bg-ink-50 p-3 font-mono text-xs text-ink-800 dark:border-ink-800 dark:bg-ink-900 dark:text-ink-200">
                <code>{f.code}</code>
              </pre>
            ) : null}
          </div>
        ))}
      </section>

      <section
        aria-labelledby="steps-heading"
        className="flex flex-col gap-4 border-t border-ink-200 pt-6 dark:border-ink-800"
      >
        <h2 id="steps-heading" className="font-mono text-base font-semibold">
          {c.stepsHeading}
        </h2>
        <ol className="flex flex-col gap-3">
          {c.steps.map((s, i) => (
            <li key={s.title} className="flex gap-3">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-ink-300 font-mono text-xs text-ink-600 dark:border-ink-700 dark:text-ink-400">
                {i + 1}
              </span>
              <div className="flex flex-col gap-1">
                <span className="text-sm font-semibold text-ink-900 dark:text-ink-100">
                  {s.title}
                </span>
                <span className="text-sm leading-relaxed text-ink-700 dark:text-ink-300">
                  {s.body}
                </span>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section
        aria-labelledby="faq-heading"
        className="faq flex flex-col gap-4 border-t border-ink-200 pt-6 dark:border-ink-800"
      >
        <h2 id="faq-heading" className="font-mono text-base font-semibold">
          {c.faqHeading}
        </h2>
        <dl className="flex flex-col gap-4">
          {c.faq.map((f) => (
            <div key={f.q} className="flex flex-col gap-1">
              <dt className="text-sm font-semibold text-ink-900 dark:text-ink-100">
                {f.q}
              </dt>
              <dd className="text-sm leading-relaxed text-ink-700 dark:text-ink-300">
                {f.a}
              </dd>
            </div>
          ))}
        </dl>
      </section>

      <nav
        aria-labelledby="related-heading"
        className="flex flex-col gap-3 border-t border-ink-200 pt-6 dark:border-ink-800"
      >
        <h2 id="related-heading" className="font-mono text-base font-semibold">
          {pickLocale(RELATED_HEADING, locale)}
        </h2>
        <ul className="flex flex-wrap gap-x-4 gap-y-2 text-sm">
          {related.map((p) => (
            <li key={p}>
              <Link
                href={`/${locale}${p}`}
                className="text-ink-700 underline underline-offset-2 hover:text-ink-900 dark:text-ink-300 dark:hover:text-ink-100"
              >
                {pickLocale(LANDINGS[p], locale).h1}
              </Link>
            </li>
          ))}
        </ul>
      </nav>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={jsonLdScript(ld)}
      />
    </main>
  );
}
