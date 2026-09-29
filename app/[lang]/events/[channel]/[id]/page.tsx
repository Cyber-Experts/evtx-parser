import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";

import { getDict } from "@/src/dict";
import { isLocale, type Locale } from "@/src/dict/locales";
import { fill, getEventsDict, type EventsDict } from "@/src/dict/events";
import { blog } from "@/next-md-blog.config";
import { jsonLdScript } from "@/lib/schema";
import { Breadcrumbs } from "@/components/BreadcrumbsEvtx";
import { BTN_PRIMARY, BTN_SECONDARY, PageHero, SectionTitle } from "@/components/PageHero";
import { Inline, Paragraphs, plainText } from "@/components/events/Rich";
import {
  ATTACK_TACTICS,
  ATTACK_VERSION,
  allEntries,
  entryHref,
  getEntry,
  techniquesOf,
  viewEntry,
  type EventView,
} from "@/lib/events";
import { eventHeadingText, eventMetaTitle } from "@/lib/events/seo";
import { EVENT_BLOG_POSTS } from "@/lib/events/blog-links";
import { sigmaLinksFor } from "@/lib/events/sigma-links";
import sigmaMeta from "@/lib/sigma/sigmahq-meta.json";
import type { SigmaLevel } from "@/lib/sigma/types";
import { SITE_URL, canonicalFor, localeAlternates, OG_LOCALE } from "../../../../_lib/site";

type Params = { lang: string; channel: string; id: string };

// Only real pages: English for every entry, fr/es/de where a translation
// exists. Untranslated locales link to the English page instead (no
// duplicate-content copies), so anything else is a 404.
export const dynamicParams = false;

export function generateStaticParams(): Params[] {
  const out: Params[] = [];
  for (const e of allEntries()) {
    const v = viewEntry(e, "en");
    for (const lang of v.locales) out.push({ lang, channel: e.channel, id: String(e.id) });
  }
  return out;
}

/** Resolve params to a view, or null when this locale has no page. */
function resolve(p: Params): EventView | null {
  if (!isLocale(p.lang) || !/^\d+$/.test(p.id)) return null;
  const entry = getEntry(p.channel, Number(p.id));
  if (!entry) return null;
  const view = viewEntry(entry, p.lang);
  return view.contentLocale === p.lang ? view : null;
}

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const p = await params;
  const view = resolve(p);
  if (!view) return {};
  const locale = p.lang as Locale;
  const d = getEventsDict(locale);
  const dict = getDict(locale);
  const subPath = `/events/${view.channel}/${view.id}`;
  const url = canonicalFor(locale, subPath);
  const title = eventMetaTitle(view, d);
  const description = view.summary;
  const image = `${url}/opengraph-image`;
  return {
    metadataBase: new URL(SITE_URL),
    title,
    description,
    alternates: {
      canonical: url,
      // hreflang only to real translations.
      languages: localeAlternates(subPath, view.locales as Locale[]),
    },
    openGraph: {
      type: "article",
      siteName: dict.meta.siteName,
      title: typeof title === "string" ? title : title.absolute,
      description,
      url,
      locale: OG_LOCALE[locale],
      images: [{ url: image, width: 1200, height: 630, alt: view.title }],
    },
    twitter: {
      card: "summary_large_image",
      title: typeof title === "string" ? title : title.absolute,
      description,
      images: [image],
    },
  };
}

const LEVEL_STYLE: Record<SigmaLevel, string> = {
  critical: "bg-red-600/15 text-red-700 dark:text-red-300",
  high: "bg-orange-500/15 text-orange-700 dark:text-orange-300",
  medium: "bg-amber-400/20 text-amber-800 dark:text-amber-200",
  low: "bg-sky-500/15 text-sky-700 dark:text-sky-300",
  informational: "bg-ink-200/60 text-ink-700 dark:bg-ink-800 dark:text-ink-300",
};

const SIGMA_SHOWN = 25;

function Section({
  id,
  title,
  children,
}: {
  id: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section aria-labelledby={id} className="flex flex-col gap-4">
      <SectionTitle id={id}>{title}</SectionTitle>
      {children}
    </section>
  );
}

function Bullets({ items }: { items: string[] }) {
  return (
    <ul className="flex list-disc flex-col gap-2 pl-5 leading-relaxed text-ink-700 marker:text-uv-500 dark:text-ink-300">
      {items.map((t, i) => (
        <li key={i}>
          <Inline text={t} />
        </li>
      ))}
    </ul>
  );
}

async function blogLink(key: string, locale: Locale) {
  const slug = EVENT_BLOG_POSTS[key];
  if (!slug) return null;
  for (const l of locale === "en" ? ["en" as const] : [locale, "en" as const]) {
    const post = (await blog.getAll({ locale: l })).find((x) => x.slug === slug);
    if (post) return { href: `/${l}/blog/${slug}`, title: String(post.frontmatter.title ?? slug), locale: l };
  }
  return null;
}

function buildGraph(view: EventView, locale: Locale, url: string, heading: string, d: EventsDict, siteName: string) {
  const indexUrl = `${SITE_URL}/${locale}/events`;
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebPage",
        "@id": `${url}#webpage`,
        url,
        name: heading,
        description: view.summary,
        inLanguage: locale,
        isPartOf: { "@id": `${SITE_URL}/${locale}#website` },
        breadcrumb: { "@id": `${url}#breadcrumb` },
        mainEntity: { "@id": `${url}#article` },
      },
      {
        "@type": "TechArticle",
        "@id": `${url}#article`,
        headline: heading,
        description: view.summary,
        inLanguage: locale,
        articleSection: view.channelInfo.label,
        proficiencyLevel: "Expert",
        mainEntityOfPage: { "@id": `${url}#webpage` },
        about: { "@id": `${url}#term` },
        author: { "@id": `${SITE_URL}#author-florian-amette` },
        publisher: { "@id": `${SITE_URL}#organization` },
        image: `${url}/opengraph-image`,
        citation: view.references.map((r) => r.url),
      },
      {
        "@type": "DefinedTerm",
        "@id": `${url}#term`,
        name: `${view.channelInfo.seoPrefix ? `${view.channelInfo.seoPrefix} ` : ""}Event ID ${view.id}`,
        alternateName: view.title,
        description: plainText(view.summary),
        termCode: String(view.id),
        inDefinedTermSet: { "@type": "DefinedTermSet", "@id": `${indexUrl}#termset`, name: d.indexH1, url: indexUrl },
      },
      {
        "@type": "BreadcrumbList",
        "@id": `${url}#breadcrumb`,
        itemListElement: [
          { "@type": "ListItem", position: 1, name: siteName, item: `${SITE_URL}/${locale}` },
          { "@type": "ListItem", position: 2, name: d.navTitle, item: indexUrl },
          { "@type": "ListItem", position: 3, name: heading, item: url },
        ],
      },
    ],
  };
}

export default async function EventPage({ params }: { params: Promise<Params> }) {
  const p = await params;
  const view = resolve(p);
  if (!view) notFound();
  const locale = p.lang as Locale;
  const dict = getDict(locale);
  const d = getEventsDict(locale);
  const url = canonicalFor(locale, `/events/${view.channel}/${view.id}`);
  const heading = eventHeadingText(view, d);
  const techniques = techniquesOf(view);
  const tacticName = new Map(ATTACK_TACTICS.map((t) => [t.slug, t.name]));
  const sigma = sigmaLinksFor(view);
  const post = await blogLink(view.key, locale);
  const related = view.related
    .map((key) => {
      const [channel, id] = key.split("/");
      const e = getEntry(channel, Number(id));
      if (!e) return null;
      const link = entryHref(e, locale);
      const rv = viewEntry(e, link.locale);
      return { key, id: e.id, label: rv.channelInfo.label, title: rv.shortTitle, ...link };
    })
    .filter((x): x is NonNullable<typeof x> => x !== null);
  const channelName = view.channelName ?? view.channelInfo.names[0];

  const facts: [string, React.ReactNode][] = [
    [d.factsEventId, <span key="id" className="font-mono">{view.id}</span>],
    [d.factsChannel, <span key="ch" className="font-mono break-all">{channelName}</span>],
    [d.factsProvider, <span key="pr" className="font-mono break-all">{view.provider}</span>],
    [d.factsLogFile, <span key="lf" className="font-mono break-all">{view.channelInfo.file}</span>],
    [d.factsCategory, d.categories[view.category]],
    [
      d.factsLogging,
      <span
        key="lg"
        className={
          view.logging.enabledByDefault
            ? "text-emerald-700 dark:text-emerald-300"
            : "text-amber-700 dark:text-amber-300"
        }
      >
        {view.logging.enabledByDefault ? d.loggedByDefault : d.notLoggedByDefault}
      </span>,
    ],
  ];

  const viewerHref = `/${locale}#tool`;
  const filterHref = `/${locale}#q=${encodeURIComponent(`EventID:${view.id}`)}`;

  return (
    <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col gap-12 px-4 py-6 sm:px-6 sm:py-10">
      <PageHero
        top={
          <Breadcrumbs
            dict={dict}
            items={[
              { label: dict.breadcrumb.home, href: `/${locale}` },
              { label: d.navTitle, href: `/${locale}/events` },
              { label: `${view.channelInfo.label} ${view.id}` },
            ]}
          />
        }
        eyebrow={view.channelInfo.label}
        title={heading}
        intro={
          <>
            <span className="block text-ink-800 dark:text-ink-200">{view.title}</span>
            <span className="mt-2 block">{view.summary}</span>
          </>
        }
        size="md"
      />

      <div className="surface grid overflow-hidden sm:grid-cols-[auto_1fr]">
        <div className="flex items-center justify-center border-b border-ink-100 bg-uv-50/50 px-8 py-6 sm:border-r sm:border-b-0 dark:border-ink-800 dark:bg-uv-400/[0.05]">
          <span className="text-gradient-uv font-mono text-5xl font-semibold tracking-[-0.03em]">{view.id}</span>
        </div>
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 p-6 text-sm sm:grid-cols-[max-content_1fr] sm:gap-y-3">
          {facts.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="eyebrow self-center">{k}</dt>
              <dd className="text-ink-900 dark:text-ink-100">{v}</dd>
            </div>
          ))}
        </dl>
      </div>

      <Section id="meaning" title={fill(d.sectionMeaning, { id: view.id })}>
        <div className="flex flex-col gap-4 leading-relaxed text-ink-700 dark:text-ink-300">
          <Paragraphs text={view.description} />
        </div>
      </Section>

      <Section id="logging" title={d.sectionLogging}>
        <div className="surface flex flex-col gap-2 p-5 text-sm leading-relaxed">
          <span className="eyebrow">{d.requirementLabel}</span>
          <p className="text-ink-900 dark:text-ink-100">
            <Inline text={view.logging.requirement} />
          </p>
          {view.logging.notes && (
            <p className="text-ink-600 dark:text-ink-400">
              <Inline text={view.logging.notes} />
            </p>
          )}
        </div>
      </Section>

      <Section id="fields" title={d.sectionFields}>
        <div className="surface overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="bg-ink-50/70 text-left font-mono text-[0.6875rem] tracking-[0.12em] text-ink-500 uppercase dark:bg-ink-900/60 dark:text-ink-400">
                  <th scope="col" className="px-4 py-2.5 font-medium">{d.fieldColumn}</th>
                  <th scope="col" className="px-4 py-2.5 font-medium">{d.descriptionColumn}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-100 dark:divide-ink-800">
                {view.fields.map((f) => (
                  <tr key={f.name} className="align-top">
                    <th scope="row" className="px-4 py-3 text-left font-mono text-[0.8125rem] font-medium whitespace-nowrap text-uv-700 dark:text-uv-300">
                      {f.name}
                    </th>
                    <td className="px-4 py-3 leading-relaxed text-ink-700 dark:text-ink-300">
                      <Inline text={f.description} />
                      {f.values && (
                        <table className="mt-3 w-full border-collapse text-[0.8125rem]">
                          <thead className="sr-only">
                            <tr>
                              <th scope="col">{d.valueColumn}</th>
                              <th scope="col">{d.meaningColumn}</th>
                            </tr>
                          </thead>
                          <tbody>
                            {f.values.map((v) => (
                              <tr key={v.value} className="border-t border-ink-100 dark:border-ink-800">
                                <td className="py-1.5 pr-3 align-top font-mono whitespace-nowrap text-ink-900 dark:text-ink-100">
                                  {v.value}
                                </td>
                                <td className="py-1.5 align-top">
                                  <Inline text={v.meaning} />
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Section>

      <Section id="benign" title={d.sectionBenign}>
        <Bullets items={view.benign} />
      </Section>

      <Section id="attacker" title={d.sectionAttacker}>
        <Bullets items={view.attacker} />
      </Section>

      <Section id="investigation" title={d.sectionInvestigation}>
        <Bullets items={view.investigation} />
      </Section>

      {techniques.length > 0 && (
        <Section id="attack" title={d.sectionAttack}>
          <div className="surface overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr className="bg-ink-50/70 text-left font-mono text-[0.6875rem] tracking-[0.12em] text-ink-500 uppercase dark:bg-ink-900/60 dark:text-ink-400">
                    <th scope="col" className="px-4 py-2.5 font-medium">{d.techniqueColumn}</th>
                    <th scope="col" className="px-4 py-2.5 font-medium">{d.tacticColumn}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-100 dark:divide-ink-800">
                  {techniques.map((t) => (
                    <tr key={t.id} className="align-top">
                      <td className="px-4 py-3">
                        <a href={t.url} target="_blank" rel="external noopener" className="font-mono text-uv-700 hover:underline dark:text-uv-300">
                          {t.id}
                        </a>{" "}
                        <span className="text-ink-800 dark:text-ink-200">{t.name}</span>
                      </td>
                      <td className="px-4 py-3 text-ink-600 dark:text-ink-400">
                        {t.tactics.map((s) => tacticName.get(s) ?? s).join(", ")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <p className="text-xs text-ink-500 dark:text-ink-400">{fill(d.attackNote, { version: ATTACK_VERSION })}</p>
        </Section>
      )}

      <Section id="sigma" title={d.sectionSigma}>
        {sigma.total === 0 ? (
          <p className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">{d.sigmaNone}</p>
        ) : (
          <>
            <p className="text-sm leading-relaxed text-ink-700 dark:text-ink-300">
              {fill(d.sigmaIntro, { count: sigma.total, release: sigma.release })}{" "}
              {sigma.total > SIGMA_SHOWN && fill(d.sigmaShowing, { shown: SIGMA_SHOWN })}
            </p>
            <ul className="flex flex-wrap gap-2">
              {(Object.keys(sigma.byLevel) as SigmaLevel[])
                .filter((l) => sigma.byLevel[l] > 0)
                .map((l) => (
                  <li key={l} className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${LEVEL_STYLE[l]}`}>
                    {d.levels[l]} · {sigma.byLevel[l]}
                  </li>
                ))}
            </ul>
            <ul className="surface divide-y divide-ink-100 dark:divide-ink-800">
              {sigma.rules.slice(0, SIGMA_SHOWN).map((r) => (
                <li key={r.id} className="flex flex-col gap-1 px-4 py-3 text-sm sm:flex-row sm:items-baseline sm:gap-3">
                  <span className={`w-fit shrink-0 rounded px-1.5 text-[0.6875rem] font-medium uppercase ${LEVEL_STYLE[r.level]}`}>
                    {d.levels[r.level]}
                  </span>
                  <span className="flex min-w-0 flex-col">
                    {r.url ? (
                      <a href={r.url} target="_blank" rel="external noopener" className="font-medium text-ink-900 hover:text-uv-700 hover:underline dark:text-ink-100 dark:hover:text-uv-300" lang="en">
                        {r.title}
                      </a>
                    ) : (
                      <span className="font-medium text-ink-900 dark:text-ink-100" lang="en">{r.title}</span>
                    )}
                    <span className="text-xs text-ink-500 dark:text-ink-400" lang="en">{r.attribution}</span>
                  </span>
                </li>
              ))}
            </ul>
            <p className="text-xs text-ink-500 dark:text-ink-400">{d.sigmaLicense}</p>
          </>
        )}
        <div className="surface flex flex-col gap-3 border-uv-300/60 bg-uv-50/40 p-5 dark:border-uv-400/30 dark:bg-uv-400/[0.05]">
          <h3 className="text-lg font-semibold tracking-[-0.01em] text-ink-950 dark:text-ink-50">{d.ctaTitle}</h3>
          <p className="text-sm leading-relaxed text-ink-700 dark:text-ink-300">
            {fill(d.ctaText, { total: sigmaMeta.counts.bundled.toLocaleString(locale) })}
          </p>
          <div className="flex flex-wrap gap-3">
            <Link href={viewerHref} className={BTN_PRIMARY}>
              {d.ctaButton} <span aria-hidden="true">→</span>
            </Link>
            <Link href={filterHref} className={BTN_SECONDARY}>
              {fill(d.ctaFilter, { id: view.id })}
            </Link>
          </div>
        </div>
      </Section>

      {(related.length > 0 || post) && (
        <Section id="related" title={d.sectionRelated}>
          {post && (
            <Link href={post.href} hrefLang={post.locale !== locale ? post.locale : undefined} className="surface surface-interactive group flex flex-col gap-1 p-5">
              <span className="eyebrow">{d.inDepth}</span>
              <span className="font-medium text-ink-900 dark:text-ink-100" lang={post.locale !== locale ? post.locale : undefined}>
                {post.title}
              </span>
            </Link>
          )}
          {related.length > 0 && (
            <ul className="grid gap-3 sm:grid-cols-2">
              {related.map((r) => (
                <li key={r.key}>
                  <Link
                    href={r.href}
                    hrefLang={r.fallback ? "en" : undefined}
                    className="surface surface-interactive group flex h-full items-center gap-3 px-4 py-3 text-sm"
                  >
                    <span className="rounded-md bg-uv-50 px-1.5 font-mono text-uv-700 dark:bg-uv-400/10 dark:text-uv-300">{r.id}</span>
                    <span className="flex flex-1 flex-col">
                      <span className="text-ink-800 dark:text-ink-200" lang={r.fallback ? "en" : undefined}>{r.title}</span>
                      <span className="font-mono text-[0.6875rem] text-ink-500 dark:text-ink-400">
                        {r.label}
                        {r.fallback && (
                          <span title={d.englishTitle} className="ml-2 rounded-full border border-ink-200 px-1.5 font-sans dark:border-ink-700">
                            {d.englishBadge}
                          </span>
                        )}
                      </span>
                    </span>
                    <span aria-hidden="true" className="text-uv-500 transition-transform group-hover:translate-x-0.5">→</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Section>
      )}

      <Section id="references" title={d.sectionReferences}>
        <ul className="flex flex-col gap-2 text-sm">
          {view.references.map((r) => (
            <li key={r.url}>
              <a href={r.url} target="_blank" rel="external noopener" className="text-uv-700 hover:underline dark:text-uv-300" lang="en">
                {r.title}
              </a>
            </li>
          ))}
        </ul>
      </Section>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={jsonLdScript(buildGraph(view, locale, url, heading, d, dict.meta.siteName))}
      />
    </main>
  );
}
