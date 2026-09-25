import Link from "next/link";
import type { Metadata } from "next";

import { getDict } from "@/src/dict";
import type { Locale } from "@/src/dict/locales";
import { jsonLdScript } from "@/lib/schema";
import { Breadcrumbs } from "@/components/BreadcrumbsEvtx";
import { GitHubMark } from "@/components/GitHubMark";
import { CtaBand, REPO_URL } from "@/components/home/HomeSections";
import {
  BTN_PRIMARY,
  BTN_SECONDARY,
  PageHero,
  SectionTitle,
} from "@/components/PageHero";
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
    <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-16 px-4 py-6 sm:gap-20 sm:px-6 sm:py-10">
      <PageHero
        top={
          <Breadcrumbs
            dict={dict}
            items={[
              { label: dict.breadcrumb.home, href: `/${locale}` },
              { label: c.h1 },
            ]}
          />
        }
        title={c.h1}
        intro={<p>{c.intro}</p>}
      >
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <Link href={`/${locale}`} className={BTN_PRIMARY}>
            {c.ctaLabel}
            <span aria-hidden="true">→</span>
          </Link>
          <a href={REPO_URL} className={BTN_SECONDARY}>
            <GitHubMark className="h-4 w-4" />
            {dict.home.heroCtaGithub}
          </a>
        </div>
      </PageHero>

      <section
        aria-labelledby="formats-heading"
        className="flex flex-col gap-6"
      >
        <SectionTitle id="formats-heading">{c.formatsHeading}</SectionTitle>
        <div className="grid gap-4 md:grid-cols-2">
          {c.formats.map((f) => (
            <div
              key={f.name}
              className="surface flex min-w-0 flex-col gap-2 p-5 sm:p-6"
            >
              <h3 className="text-base font-semibold text-ink-950 dark:text-ink-50">
                {f.name}
              </h3>
              <p className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">
                {f.body}
              </p>
              {f.code ? (
                <pre className="mt-2 overflow-x-auto rounded-lg border border-ink-200 bg-ink-50 p-3 font-mono text-xs text-ink-800 dark:border-ink-800 dark:bg-ink-950/60 dark:text-ink-200">
                  <code>{f.code}</code>
                </pre>
              ) : null}
            </div>
          ))}
        </div>
      </section>

      <section aria-labelledby="steps-heading" className="flex flex-col gap-6">
        <SectionTitle id="steps-heading">{c.stepsHeading}</SectionTitle>
        <ol
          className={`grid gap-4 ${
            c.steps.length >= 3 ? "md:grid-cols-3" : "md:grid-cols-2"
          }`}
        >
          {c.steps.map((s, i) => (
            <li
              key={s.title}
              className="surface flex flex-col gap-3 p-5 sm:p-6"
            >
              <span
                aria-hidden="true"
                className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-uv-600 text-sm font-semibold text-white shadow-[0_6px_16px_-6px_rgb(106_51_245/0.8)] dark:bg-uv-500"
              >
                {i + 1}
              </span>
              <span className="text-base font-semibold text-ink-950 dark:text-ink-50">
                {s.title}
              </span>
              <span className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">
                {s.body}
              </span>
            </li>
          ))}
        </ol>
      </section>

      <section
        aria-labelledby="faq-heading"
        className="faq flex flex-col gap-6"
      >
        <SectionTitle id="faq-heading">{c.faqHeading}</SectionTitle>
        <dl className="surface flex flex-col divide-y divide-ink-100 px-5 sm:px-6 dark:divide-ink-800">
          {c.faq.map((f) => (
            <div key={f.q} className="flex flex-col gap-1.5 py-4">
              <dt className="font-medium text-ink-900 dark:text-ink-100">
                {f.q}
              </dt>
              <dd className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">
                {f.a}
              </dd>
            </div>
          ))}
        </dl>
      </section>

      <nav aria-labelledby="related-heading" className="flex flex-col gap-4">
        <h2
          id="related-heading"
          className="text-lg tracking-[-0.01em] text-ink-950 dark:text-ink-50"
        >
          {pickLocale(RELATED_HEADING, locale)}
        </h2>
        <ul className="flex flex-wrap gap-2">
          {related.map((p) => (
            <li key={p}>
              <Link
                href={`/${locale}${p}`}
                className="inline-flex rounded-full border border-ink-200 bg-card/70 px-3 py-1 text-sm text-ink-700 transition-colors hover:border-uv-300 hover:text-uv-700 dark:border-ink-800 dark:text-ink-300 dark:hover:border-uv-500/50 dark:hover:text-uv-300"
              >
                {pickLocale(LANDINGS[p], locale).h1}
              </Link>
            </li>
          ))}
        </ul>
      </nav>

      <CtaBand dict={dict} href={`/${locale}`} />

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={jsonLdScript(ld)}
      />
    </main>
  );
}
