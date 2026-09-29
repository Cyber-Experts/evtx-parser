import { notFound } from "next/navigation";
import type { Metadata } from "next";

import { getDict } from "@/src/dict";
import { isLocale } from "@/src/dict/locales";
import { fill, getEventsDict } from "@/src/dict/events";
import { jsonLdScript } from "@/lib/schema";
import { Breadcrumbs } from "@/components/BreadcrumbsEvtx";
import { PageHero } from "@/components/PageHero";
import { EventIndex, type IndexItem } from "@/components/events/EventIndex";
import { EVENT_CHANNELS } from "@/lib/events/channels";
import { EVENT_CATEGORIES } from "@/lib/events/types";
import {
  ATTACK_TACTICS,
  allEntries,
  entryHref,
  tacticsOf,
  viewEntry,
} from "@/lib/events";
import { SITE_URL, canonicalFor, localeAlternates, OG_LOCALE } from "../../_lib/site";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ lang: string }>;
}): Promise<Metadata> {
  const { lang: locale } = await params;
  if (!isLocale(locale)) return {};
  const d = getEventsDict(locale);
  const dict = getDict(locale);
  const url = canonicalFor(locale, "/events");
  return {
    metadataBase: new URL(SITE_URL),
    title: d.indexMetaTitle,
    description: d.indexDescription,
    alternates: { canonical: url, languages: localeAlternates("/events") },
    openGraph: {
      type: "website",
      siteName: dict.meta.siteName,
      title: d.indexMetaTitle,
      description: d.indexDescription,
      url,
      locale: OG_LOCALE[locale],
      images: [{ url: `${canonicalFor(locale)}/opengraph-image`, width: 1200, height: 630, alt: d.indexH1 }],
    },
    twitter: {
      card: "summary_large_image",
      title: d.indexMetaTitle,
      description: d.indexDescription,
      images: [`${canonicalFor(locale)}/opengraph-image`],
    },
  };
}

export default async function EventsIndexPage({ params }: { params: Promise<{ lang: string }> }) {
  const { lang: locale } = await params;
  if (!isLocale(locale)) notFound();
  const dict = getDict(locale);
  const d = getEventsDict(locale);
  const url = canonicalFor(locale, "/events");

  const channelOrder = new Map(EVENT_CHANNELS.map((c, i) => [c.slug, i]));
  const entries = [...allEntries()].sort(
    (a, b) => (channelOrder.get(a.channel) ?? 0) - (channelOrder.get(b.channel) ?? 0) || a.id - b.id,
  );
  const items: IndexItem[] = entries.map((e) => {
    const link = entryHref(e, locale);
    const v = viewEntry(e, link.locale);
    return {
      key: v.key,
      id: e.id,
      channel: e.channel,
      channelLabel: v.channelInfo.label,
      title: v.shortTitle,
      summary: v.summary,
      category: e.category,
      tactics: tacticsOf(e),
      href: link.href,
      fallback: link.fallback,
    };
  });

  const usedChannels = new Set(entries.map((e) => e.channel));
  const usedCategories = new Set(entries.map((e) => e.category));
  const usedTactics = new Set(items.flatMap((i) => i.tactics));
  const channels = EVENT_CHANNELS.filter((c) => usedChannels.has(c.slug)).map((c) => ({
    value: c.slug,
    label: `${c.label} (${entries.filter((e) => e.channel === c.slug).length})`,
  }));
  const categories = EVENT_CATEGORIES.filter((c) => usedCategories.has(c))
    .map((c) => ({ value: c, label: d.categories[c] }))
    .sort((a, b) => a.label.localeCompare(b.label, locale));
  const tactics = ATTACK_TACTICS.filter((t) => usedTactics.has(t.slug)).map((t) => ({
    value: t.slug,
    label: `${t.name} (${t.id})`,
  }));

  const ld = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "CollectionPage",
        "@id": `${url}#webpage`,
        url,
        name: d.indexH1,
        description: d.indexDescription,
        inLanguage: locale,
        isPartOf: { "@id": `${SITE_URL}/${locale}#website` },
        mainEntity: { "@id": `${url}#termset` },
      },
      {
        "@type": "DefinedTermSet",
        "@id": `${url}#termset`,
        name: d.indexH1,
        url,
        hasDefinedTerm: items.map((i) => ({
          "@type": "DefinedTerm",
          name: `${i.channelLabel} Event ID ${i.id}`,
          description: i.title,
          url: `${SITE_URL}${i.href}`,
          termCode: String(i.id),
        })),
      },
      {
        "@type": "BreadcrumbList",
        "@id": `${url}#breadcrumb`,
        itemListElement: [
          { "@type": "ListItem", position: 1, name: dict.meta.siteName, item: `${SITE_URL}/${locale}` },
          { "@type": "ListItem", position: 2, name: d.navTitle, item: url },
        ],
      },
    ],
  };

  return (
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-10 px-4 py-6 sm:px-6 sm:py-10">
      <PageHero
        top={
          <Breadcrumbs
            dict={dict}
            items={[{ label: dict.breadcrumb.home, href: `/${locale}` }, { label: d.navTitle }]}
          />
        }
        eyebrow="Event ID"
        title={d.indexH1}
        intro={fill(d.indexIntro, { count: items.length })}
      />
      <EventIndex items={items} channels={channels} categories={categories} tactics={tactics} dict={d} />
      <script type="application/ld+json" dangerouslySetInnerHTML={jsonLdScript(ld)} />
    </main>
  );
}
