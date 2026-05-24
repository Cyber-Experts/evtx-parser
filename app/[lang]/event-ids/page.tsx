import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";

import { getDict } from "@/src/dict";
import { isLocale, type Locale } from "@/src/dict/locales";
import { jsonLdScript } from "@/lib/schema";
import { Breadcrumbs } from "@/components/BreadcrumbsEvtx";
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
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-8 px-4 py-6 sm:px-6 sm:py-10">
      <Breadcrumbs
        dict={dict}
        items={[
          { label: dict.breadcrumb.home, href: `/${locale}` },
          { label: dict.eventIds.title },
        ]}
      />
      <header className="flex flex-col gap-2">
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100 sm:text-3xl">
          {dict.eventIds.title}
        </h1>
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          {dict.eventIds.intro}
        </p>
      </header>

      {CHANNELS.map((channel) => (
        <section
          key={channel.key}
          aria-labelledby={`ch-${channel.channelPath}`}
          className="flex flex-col gap-3 border-t border-zinc-200 pt-6 dark:border-zinc-800"
        >
          <h2
            id={`ch-${channel.channelPath}`}
            className="font-mono text-base font-semibold"
          >
            {channel.key}
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-zinc-200 text-left text-xs font-medium text-zinc-500 dark:border-zinc-800">
                  <th className="py-2 pr-3 font-mono">
                    {dict.eventIds.columnId}
                  </th>
                  <th className="py-2 pr-3">{dict.eventIds.columnName}</th>
                  <th className="py-2">{dict.eventIds.columnNotes}</th>
                </tr>
              </thead>
              <tbody>
                {channel.rows.map((row) => (
                  <tr
                    key={row.id}
                    className="border-b border-zinc-100 align-top dark:border-zinc-900"
                  >
                    <td className="whitespace-nowrap py-2 pr-3 font-mono text-zinc-900 dark:text-zinc-100">
                      <Link
                        href={`/${locale}/event-id/${row.id}`}
                        className="underline-offset-2 hover:underline"
                      >
                        {row.id}
                      </Link>
                    </td>
                    <td className="py-2 pr-3 text-zinc-800 dark:text-zinc-200">
                      <Link
                        href={`/${locale}/event-id/${row.id}`}
                        className="underline-offset-2 hover:underline"
                      >
                        {row.name}
                      </Link>
                    </td>
                    <td className="py-2 text-zinc-600 dark:text-zinc-400">
                      {row.notes}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
