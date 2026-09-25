import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import type { ContentMetadata } from "@next-md-blog/core";

import { PostCard } from "@/components/post-card";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { PageHero, SectionTitle } from "@/components/PageHero";
import { CollectionJsonLd } from "@/components/seo/collection-jsonld";
import { blog } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { getDictionary, hasLocale } from "../../dictionaries";

type Params = { lang: string; series: string };

/** Recover the human-readable series title from the first matching post. */
function seriesTitleFromPosts(
  posts: ContentMetadata[],
  fallback: string,
): string {
  for (const p of posts) {
    const t = p.frontmatter.seriesTitle;
    if (typeof t === "string" && t) return t;
    const raw = p.frontmatter.series;
    if (typeof raw === "string" && raw) return raw;
  }
  return fallback;
}

export async function generateStaticParams() {
  const slugs = await blog.getAllSeriesSlugs(LOCALES);
  const out: Params[] = [];
  for (const lang of LOCALES) {
    for (const series of slugs) out.push({ lang, series });
  }
  return out;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { lang, series } = await params;
  if (!hasLocale(lang)) return {};
  const locale = lang as Locale;
  const posts = await blog.getBySeries(series, { locale });
  const title = seriesTitleFromPosts(posts, series);
  const url = `${siteConfig.url}/${lang}/topics/${series}`;
  return {
    metadataBase: new URL(siteConfig.url),
    title,
    description: `All posts in the "${title}" series.`,
    alternates: {
      canonical: url,
      languages: hreflangFor(siteConfig.url, `/topics/${series}`),
    },
    openGraph: { type: "website", url, title },
  };
}

export default async function SeriesPillar({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang, series } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const posts = await blog.getBySeries(series, { locale });
  if (!posts.length) notFound();
  const title = seriesTitleFromPosts(posts, series);
  const url = `${siteConfig.url}/${lang}/topics/${series}`;

  return (
    <>
      <CollectionJsonLd
        url={url}
        name={title}
        description={`All posts in the "${title}" series.`}
        inLanguage={locale}
        items={posts.map((p) => ({
          name: (p.frontmatter.title as string) ?? p.slug,
          url: blog.url(p.slug, locale),
        }))}
      />
      <main
        id="main-content"
        className="container mx-auto flex flex-col gap-16 px-4 py-12"
      >
        <PageHero
          top={
            <Breadcrumbs
              items={[
                { name: dict.nav.home, href: `/${locale}` },
                { name: dict.metadata.blogTitle, href: `/${locale}/blog` },
                { name: title },
              ]}
            />
          }
          eyebrow="Series"
          title={title}
          intro={
            <p>
              {posts.length} post{posts.length === 1 ? "" : "s"} in this series.
              Read them in order or jump to any one.
            </p>
          }
        />
        <ol className="flex max-w-3xl flex-col gap-3">
          {posts.map((p, i) => (
            <li key={p.slug}>
              <Link
                href={`/${locale}/blog/${p.slug}`}
                className="surface surface-interactive group flex items-start gap-4 p-5"
              >
                <span
                  aria-hidden="true"
                  className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-uv-200 bg-uv-50 font-mono text-xs font-semibold text-uv-700 dark:border-uv-400/30 dark:bg-uv-500/10 dark:text-uv-300"
                >
                  {String(i + 1).padStart(2, "0")}
                </span>
                <span className="flex min-w-0 flex-1 flex-col gap-1">
                  <span className="font-semibold text-ink-950 dark:text-ink-50">
                    {(p.frontmatter.title as string) ?? p.slug}
                  </span>
                  {typeof p.frontmatter.description === "string" && (
                    <span className="text-sm text-ink-600 dark:text-ink-400">
                      {p.frontmatter.description}
                    </span>
                  )}
                </span>
                <span
                  aria-hidden="true"
                  className="mt-1 shrink-0 text-uv-500 transition-transform group-hover:translate-x-1"
                >
                  →
                </span>
              </Link>
            </li>
          ))}
        </ol>
        <section className="flex flex-col gap-6">
          <SectionTitle>All posts in this series</SectionTitle>
          <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {posts.map((p) => (
              <PostCard key={p.slug} post={p} locale={locale} />
            ))}
          </div>
        </section>
      </main>
    </>
  );
}
