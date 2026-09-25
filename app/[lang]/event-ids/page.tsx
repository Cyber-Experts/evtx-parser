import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";

import { getDict } from "@/src/dict";
import { isLocale, type Locale } from "@/src/dict/locales";
import { jsonLdScript } from "@/lib/schema";
import { Breadcrumbs } from "@/components/BreadcrumbsEvtx";
import { PageHero } from "@/components/PageHero";
import { CHANNELS } from "@/lib/event-id-data";
import {
  SITE_URL,
  canonicalFor,
  localeAlternates,
  OG_LOCALE,
} from "../../_lib/site";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ lang: string }>;
}): Promise<Metadata> {
  const { lang: locale } = await params;
  if (!isLocale(locale)) return {};
  const dict = getDict(locale);
  const url = canonicalFor(locale, "/event-ids");
  return {
    metadataBase: new URL(SITE_URL),
    title: dict.eventIds.title,
    description: dict.eventIds.description,
    alternates: {
      canonical: url,
      languages: localeAlternates("/event-ids"),
    },
    openGraph: {
      type: "website",
      siteName: dict.meta.siteName,
      title: dict.eventIds.title,
      description: dict.eventIds.description,
      url,
      locale: OG_LOCALE[locale as Locale],
      images: [
        {
          url: `${canonicalFor(locale)}/opengraph-image`,
          width: 1200,
          height: 630,
          alt: dict.eventIds.title,
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: dict.eventIds.title,
      description: dict.eventIds.description,
      images: [`${canonicalFor(locale)}/opengraph-image`],
    },
  };
}

function buildItemListGraph(
  locale: Locale,
  url: string,
  dict: ReturnType<typeof getDict>,
) {
  const items = CHANNELS.flatMap((c) => c.rows).map((r, i) => ({
    "@type": "ListItem",
    position: i + 1,
    name: `Event ID ${r.id} — ${r.name}`,
    // Every ID now has an on-site landing page; external resources are
    // surfaced from there. This keeps internal link flow concentrated.
    url: `${SITE_URL}/${locale}/event-id/${r.id}`,
  }));
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebPage",
        "@id": `${url}#webpage`,
        url,
        name: dict.eventIds.title,
        description: dict.eventIds.description,
        inLanguage: locale,
        isPartOf: { "@id": `${SITE_URL}/${locale}#website` },
      },
      {
        "@type": "ItemList",
        "@id": `${url}#itemlist`,
        name: dict.eventIds.title,
        itemListOrder: "https://schema.org/ItemListUnordered",
        numberOfItems: items.length,
        itemListElement: items,
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
            item: url,
          },
        ],
      },
    ],
  };
}

export default async function EventIdsPage({
  params,
}: {
  params: Promise<{ lang: string }>;
}) {
  const { lang: locale } = await params;
  if (!isLocale(locale)) notFound();
  const dict = getDict(locale);
  const url = canonicalFor(locale, "/event-ids");
  const ld = buildItemListGraph(locale, url, dict);

  return (
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-12 px-4 py-6 sm:px-6 sm:py-10">
      <PageHero
        top={
          <Breadcrumbs
            dict={dict}
            items={[
              { label: dict.breadcrumb.home, href: `/${locale}` },
              { label: dict.eventIds.title },
            ]}
          />
        }
        eyebrow="Event ID"
        title={dict.eventIds.title}
        intro={dict.eventIds.intro}
      >
        <ul className="flex flex-wrap gap-2 pt-2">
          {CHANNELS.map((channel) => (
            <li key={channel.key}>
              <a
                href={`#ch-${channel.channelPath}`}
                className="inline-flex items-center gap-1.5 rounded-full border border-ink-200 bg-card/70 px-2.5 py-0.5 font-mono text-xs text-ink-700 transition-colors hover:border-uv-300 hover:text-uv-700 dark:border-ink-800 dark:text-ink-300 dark:hover:border-uv-400/40 dark:hover:text-uv-300"
              >
                {channel.key}
                <span className="text-ink-400 dark:text-ink-500">
                  {channel.rows.length}
                </span>
              </a>
            </li>
          ))}
        </ul>
      </PageHero>

      {CHANNELS.map((channel) => (
        <section
          key={channel.key}
          aria-labelledby={`ch-${channel.channelPath}`}
          className="flex flex-col gap-4"
        >
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2
              id={`ch-${channel.channelPath}`}
              className="scroll-mt-24 text-2xl tracking-[-0.015em] text-ink-950 dark:text-ink-50"
            >
              {channel.key}
            </h2>
            <span className="font-mono text-xs break-all text-ink-500 dark:text-ink-400">
              {channel.channelPath}
            </span>
          </div>
          <div className="surface overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr className="bg-ink-50/70 text-left font-mono text-[0.6875rem] tracking-[0.12em] text-ink-500 uppercase dark:bg-ink-900/60 dark:text-ink-400">
                    <th className="px-4 py-2.5 font-medium">
                      {dict.eventIds.columnId}
                    </th>
                    <th className="px-4 py-2.5 font-medium">
                      {dict.eventIds.columnName}
                    </th>
                    <th className="px-4 py-2.5 font-medium">
                      {dict.eventIds.columnNotes}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-100 dark:divide-ink-800">
                  {channel.rows.map((row) => (
                    <tr
                      key={row.id}
                      className="align-top transition-colors hover:bg-uv-50/40 dark:hover:bg-uv-400/[0.04]"
                    >
                      <td className="px-4 py-3 whitespace-nowrap">
                        <Link
                          href={`/${locale}/event-id/${row.id}`}
                          className="rounded-md bg-uv-50 px-1.5 py-0.5 font-mono text-uv-700 transition-colors hover:bg-uv-100 dark:bg-uv-400/10 dark:text-uv-300 dark:hover:bg-uv-400/20"
                        >
                          {row.id}
                        </Link>
                      </td>
                      <td className="px-4 py-3 font-medium text-ink-900 dark:text-ink-100">
                        <Link
                          href={`/${locale}/event-id/${row.id}`}
                          className="underline-offset-4 hover:text-uv-700 hover:underline hover:decoration-uv-300 dark:hover:text-uv-300 dark:hover:decoration-uv-700"
                        >
                          {row.name}
                        </Link>
                      </td>
                      <td className="px-4 py-3 text-ink-600 dark:text-ink-400">
                        {row.notes}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      ))}

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={jsonLdScript(ld)}
      />
    </main>
  );
}
