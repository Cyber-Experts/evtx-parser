import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import type { ContentMetadata } from "@next-md-blog/core";

import { PostCard } from "@/components/post-card";
import { Breadcrumbs } from "@/components/breadcrumbs";
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
      <main id="main-content" className="container mx-auto px-4 py-12">
        <Breadcrumbs
          items={[
            { name: dict.nav.home, href: `/${locale}` },
            { name: dict.metadata.blogTitle, href: `/${locale}/blog` },
            { name: title },
          ]}
        />
        <header className="mt-6 space-y-3">
          <p className="text-sm uppercase tracking-wide text-muted-foreground">
            Series
          </p>
          <h1 className="text-3xl md:text-4xl font-semibold tracking-tight">
            {title}
          </h1>
          <p className="text-muted-foreground max-w-2xl">
            {posts.length} post{posts.length === 1 ? "" : "s"} in this series.
            Read them in order or jump to any one.
          </p>
        </header>
        <ol className="mt-10 space-y-3 list-decimal pl-6">
          {posts.map((p) => (
            <li key={p.slug}>
              <Link
                href={`/${locale}/blog/${p.slug}`}
                className="font-medium hover:underline"
              >
                {(p.frontmatter.title as string) ?? p.slug}
              </Link>
              {typeof p.frontmatter.description === "string" && (
                <p className="text-sm text-muted-foreground mt-1">
                  {p.frontmatter.description}
                </p>
              )}
            </li>
          ))}
        </ol>
        <section className="mt-16">
          <h2 className="text-xl font-semibold mb-4">All posts in this series</h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {posts.map((p) => (
              <PostCard key={p.slug} post={p} locale={locale} />
            ))}
          </div>
        </section>
      </main>
    </>
  );
}
