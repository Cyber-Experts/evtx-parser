import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";

import { getDict } from "@/src/dict";
import { isLocale, locales, type Locale } from "@/src/dict/locales";
import {
  allEventIdParams,
  getEventId,
  isEventIdIndexable,
} from "@/lib/event-id-data";
import { blog } from "@/next-md-blog.config";
import { jsonLdScript } from "@/lib/schema";
import { Breadcrumbs } from "@/components/BreadcrumbsEvtx";
import {
  SITE_URL,
  canonicalFor,
  localeAlternates,
  OG_LOCALE,
} from "../../../_lib/site";

// Every (locale × id) pair is a curated page in our reference. We don't
// host arbitrary IDs — only what's in lib/event-id-data.ts — so this is a
// safe Cartesian product.
export function generateStaticParams() {
  const out: { locale: Locale; id: string }[] = [];
  const ids = allEventIdParams();
  for (const locale of locales) {
    for (const { id } of ids) {
      out.push({ locale, id });
    }
  }
  return out;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ lang: string; id: string }>;
}): Promise<Metadata> {
  const { lang: locale, id } = await params;
  if (!isLocale(locale)) return {};
  const numericId = Number(id);
  const entry = getEventId(numericId);
  if (!entry) return { title: getDict(locale).eventId.notFoundTitle };
  const dict = getDict(locale);
  const subPath = `/event-id/${numericId}`;
  const url = canonicalFor(locale, subPath);
  const title = format(dict.eventId.title, {
    id: String(numericId),
    name: entry.name,
    channel: entry.channel.key,
  });
  const description = format(dict.eventId.description, {
    id: String(numericId),
    name: entry.name,
    channel: entry.channel.key,
  });
  return {
    metadataBase: new URL(SITE_URL),
    title,
    description,
    alternates: {
      canonical: url,
      // Only /en is indexed (see isEventIdIndexable), so there are no
      // translated alternates to advertise.
      languages: localeAlternates(subPath, ["en"]),
    },
    ...(isEventIdIndexable(entry, locale)
      ? {}
      : { robots: { index: false, follow: true } }),
    openGraph: {
      type: "article",
      siteName: dict.meta.siteName,
      title,
      description,
      url,
      locale: OG_LOCALE[locale as Locale],
      images: [
        {
          url: `${canonicalFor(locale)}/opengraph-image`,
          width: 1200,
          height: 630,
          alt: title,
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [`${canonicalFor(locale)}/opengraph-image`],
    },
  };
}

function format(template: string, values: Record<string, string>): string {
  return template.replace(/\{(\w+)\}/g, (_m, k: string) => values[k] ?? "");
}

function buildGraph(opts: {
  locale: Locale;
  dict: ReturnType<typeof getDict>;
  url: string;
  id: number;
  entry: NonNullable<ReturnType<typeof getEventId>>;
}) {
  const { locale, dict, url, id, entry } = opts;
  const title = format(dict.eventId.title, {
    id: String(id),
    name: entry.name,
    channel: entry.channel.key,
  });
  const description = format(dict.eventId.description, {
    id: String(id),
    name: entry.name,
    channel: entry.channel.key,
  });
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebPage",
        "@id": `${url}#webpage`,
        url,
        name: title,
        description,
        inLanguage: locale,
        isPartOf: { "@id": `${SITE_URL}/${locale}#website` },
        about: {
          "@type": "Thing",
          name: `Windows Event ID ${id}`,
          alternateName: entry.name,
        },
      },
      {
        "@type": "TechArticle",
        "@id": `${url}#article`,
        headline: title,
        description,
        inLanguage: locale,
        articleSection: entry.channel.key,
        proficiencyLevel: "Expert",
        mainEntityOfPage: { "@id": `${url}#webpage` },
        publisher: { "@id": `${SITE_URL}#organization` },
      },
      {
        "@type": "BreadcrumbList",
        "@id": `${url}#breadcrumb`,
        itemListElement: [
          {
            "@type": "ListItem",
            position: 1,
            name: dict.meta.siteName,
            item: `${SITE_URL}/${locale}`,
          },
          {
            "@type": "ListItem",
            position: 2,
            name: dict.eventIds.title,
            item: `${SITE_URL}/${locale}/event-ids`,
          },
          {
            "@type": "ListItem",
            position: 3,
            name: `Event ID ${id}`,
            item: url,
          },
        ],
      },
    ],
  };
}

export default async function EventIdPage({
  params,
}: {
  params: Promise<{ lang: string; id: string }>;
}) {
  const { lang: locale, id } = await params;
  if (!isLocale(locale)) notFound();
  const numericId = Number(id);
  if (!Number.isInteger(numericId) || numericId < 0) notFound();
  const entry = getEventId(numericId);
  if (!entry) notFound();

  const dict = getDict(locale);
  const subPath = `/event-id/${numericId}`;
  const url = canonicalFor(locale, subPath);
  const title = format(dict.eventId.title, {
    id: String(numericId),
    name: entry.name,
    channel: entry.channel.key,
  });

  // Resolve the linked blog post (if any) in this locale; fall back to
  // English when the translation isn't authored yet so users still land on
  // useful content. The CTA copy is localized regardless.
  let coveredHref: string | null = null;
  let coveredTitle: string | null = null;
  if (entry.postSlug) {
    const localePosts = await blog.getAll({ locale });
    const localeMatch = localePosts.find((p) => p.slug === entry.postSlug);
    if (localeMatch) {
      coveredHref = `/${locale}/blog/${localeMatch.slug}`;
      coveredTitle = (localeMatch.frontmatter.title as string) ?? localeMatch.slug;
    } else {
      const enPosts = await blog.getAll({ locale: "en" });
      const enMatch = enPosts.find((p) => p.slug === entry.postSlug);
      if (enMatch) {
        coveredHref = `/en/blog/${enMatch.slug}`;
        coveredTitle = (enMatch.frontmatter.title as string) ?? enMatch.slug;
      }
    }
  }

  return (
    <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col gap-8 px-4 py-6 sm:px-6 sm:py-10">
      <Breadcrumbs
        dict={dict}
        items={[
          { label: dict.breadcrumb.home, href: `/${locale}` },
          { label: dict.eventIds.title, href: `/${locale}/event-ids` },
          { label: `Event ID ${numericId}` },
        ]}
      />

      <header className="flex flex-col gap-2">
        <h1 className="text-2xl font-semibold tracking-tight text-ink-900 dark:text-ink-100 sm:text-3xl">
          {title}
        </h1>
        <p className="text-sm text-ink-600 dark:text-ink-400">
          {dict.eventId.intro}
        </p>
      </header>

      <dl className="grid grid-cols-1 gap-3 border-t border-ink-200 pt-6 text-sm sm:grid-cols-[max-content_1fr] sm:gap-x-6 dark:border-ink-800">
        <dt className="font-mono text-xs uppercase tracking-wide text-ink-500">
          {dict.eventId.channelLabel}
        </dt>
        <dd className="font-mono text-ink-900 dark:text-ink-100">
          {entry.channel.key}
        </dd>
        <dt className="font-mono text-xs uppercase tracking-wide text-ink-500">
          {dict.eventId.providerLabel}
        </dt>
        <dd className="font-mono break-all text-ink-900 dark:text-ink-100">
          {entry.channel.channelPath}
        </dd>
        <dt className="font-mono text-xs uppercase tracking-wide text-ink-500">
          {dict.eventId.notesLabel}
        </dt>
        <dd className="text-ink-700 dark:text-ink-300">{entry.notes}</dd>
      </dl>

      {coveredHref && coveredTitle && (
        <section
          aria-labelledby="indepth-heading"
          className="flex flex-col gap-3 border-t border-ink-200 pt-6 dark:border-ink-800"
        >
          <h2
            id="indepth-heading"
            className="font-mono text-base font-semibold"
          >
            {dict.eventId.inDepthHeading}
          </h2>
          <Link
            href={coveredHref}
            className="group flex flex-col gap-1 rounded border border-ink-200 p-3 hover:border-ink-400 dark:border-ink-800 dark:hover:border-ink-600"
          >
            <span className="text-sm font-medium text-ink-900 group-hover:underline dark:text-ink-100">
              {coveredTitle}
            </span>
            <span className="font-mono text-xs text-ink-500">
              {dict.eventId.inDepthCta} →
            </span>
          </Link>
        </section>
      )}

      {entry.externalUrl && (
        <section
          aria-labelledby="mslearn-heading"
          className="flex flex-col gap-3 border-t border-ink-200 pt-6 dark:border-ink-800"
        >
          <h2
            id="mslearn-heading"
            className="font-mono text-base font-semibold"
          >
            {dict.eventId.microsoftLearnHeading}
          </h2>
          <a
            href={entry.externalUrl}
            target="_blank"
            rel="external noopener"
            className="group flex flex-col gap-1 rounded border border-ink-200 p-3 hover:border-ink-400 dark:border-ink-800 dark:hover:border-ink-600"
          >
            <span className="font-mono break-all text-xs text-ink-700 dark:text-ink-300">
              {entry.externalUrl}
            </span>
            <span className="font-mono text-xs text-ink-500">
              {dict.eventId.microsoftLearnCta} ↗
            </span>
          </a>
        </section>
      )}

      {!coveredHref && !entry.externalUrl && (
        <p className="border-t border-ink-200 pt-6 text-sm text-ink-500 dark:border-ink-800">
          {dict.eventId.notCoveredYet}
        </p>
      )}

      {entry.related.length > 0 && (
        <section
          aria-labelledby="related-heading"
          className="flex flex-col gap-3 border-t border-ink-200 pt-6 dark:border-ink-800"
        >
          <h2
            id="related-heading"
            className="font-mono text-base font-semibold"
          >
            {dict.eventId.relatedHeading}
          </h2>
          <ul className="flex flex-col gap-2 text-sm">
            {entry.related.map((r) => (
              <li key={r.id}>
                <Link
                  href={`/${locale}/event-id/${r.id}`}
                  className="text-ink-700 underline-offset-2 hover:underline dark:text-ink-300"
                >
                  <span className="font-mono">{r.id}</span>
                  {" — "}
                  {r.name}
                </Link>
              </li>
            ))}
          </ul>
        </section>
      )}

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={jsonLdScript(
          buildGraph({ locale, dict, url, id: numericId, entry }),
        )}
      />
    </main>
  );
}
