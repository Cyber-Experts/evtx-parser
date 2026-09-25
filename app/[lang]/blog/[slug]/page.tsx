import type { Metadata } from "next";
import { notFound } from "next/navigation";
import Link from "next/link";
import { cache } from "react";
import rehypeSlug from "rehype-slug";
import { MarkdownContent, slugifySeries } from "@next-md-blog/core";

import { rehypeGlossaryLinker } from "@/lib/rehype-glossary-linker";

import { blog } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, type Locale } from "@/lib/i18n";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { TableOfContents } from "@/components/table-of-contents";
import { ReadingProgress } from "@/components/reading-progress";
import { PostCard, TAG_CHIP } from "@/components/post-card";
import { PageHero, SectionTitle } from "@/components/PageHero";
import { JsonLd } from "@/components/seo/json-ld";
import { Separator } from "@/components/ui/separator";
import { markdownComponents } from "@/components/markdown/components";
import { extractHeadings } from "@/lib/toc";
import { getDictionary, hasLocale } from "../../dictionaries";

type Params = { lang: string; slug: string };

const SERIES_PILL =
  "rounded-full border border-ink-200 bg-card/70 px-3 py-1 text-xs font-medium text-ink-700 transition-colors hover:border-uv-300 hover:text-uv-700 dark:border-ink-800 dark:text-ink-300 dark:hover:border-uv-400/40 dark:hover:text-uv-300";

const fetchPost = cache((locale: Locale, slug: string) =>
  blog.getOne(slug, { locale }),
);

const fetchAll = cache((locale: Locale) => blog.getAll({ locale }));

export async function generateStaticParams() {
  const all: { lang: string; slug: string }[] = [];
  for (const lang of LOCALES) {
    const posts = await blog.getAll({ locale: lang });
    for (const p of posts) all.push({ lang, slug: p.slug });
  }
  return all;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { lang, slug } = await params;
  if (!hasLocale(lang)) return {};
  const locale = lang as Locale;
  const post = await fetchPost(locale, slug);
  if (!post) return { title: "Not found" };

  // Hreflang: only locales that actually have a translation.
  const languages = await blog.hreflangMap(slug, LOCALES);
  languages["x-default"] = languages.en ?? blog.url(slug, locale);

  return {
    metadataBase: new URL(siteConfig.url),
    ...(await blog.metadata(post, {
      locale,
      titleTemplate: "absolute",
      alternateLanguages: languages,
    })),
  };
}

function tagOverlap(a: string[], b: string[]) {
  const set = new Set(a.map((t) => t.toLowerCase()));
  return b.reduce((n, t) => n + (set.has(t.toLowerCase()) ? 1 : 0), 0);
}

export default async function BlogPostPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang, slug } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const post = await fetchPost(locale, slug);
  if (!post) notFound();

  const fm = post.frontmatter;
  const date = typeof fm.date === "string" ? fm.date : undefined;
  const updated = typeof fm.updated === "string" ? fm.updated : undefined;
  const tags = (fm.tags as string[] | undefined) ?? [];
  const headings = extractHeadings(post.content);

  // Related: same locale, sharing ≥1 tag, top 3 by overlap.
  const all = await fetchAll(locale);
  const related = all
    .filter((p) => p.slug !== post.slug)
    .map((p) => ({
      post: p,
      score: tagOverlap(tags, (p.frontmatter.tags as string[]) ?? []),
    }))
    .filter((r) => r.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map((r) => r.post);

  // Series: discover from frontmatter, pull sibling posts.
  const rawSeries = typeof fm.series === "string" ? fm.series : null;
  const seriesSlug = rawSeries ? slugifySeries(rawSeries) : null;
  const seriesTitle =
    (typeof fm.seriesTitle === "string" && fm.seriesTitle) || rawSeries;
  const seriesPosts = seriesSlug
    ? await blog.getBySeries(seriesSlug, { locale })
    : [];
  const currentIndex = seriesSlug
    ? seriesPosts.findIndex((p) => p.slug === post.slug)
    : -1;

  const breadcrumbs = [
    { name: dict.nav.home, url: `${siteConfig.url}/${locale}` },
    { name: dict.metadata.blogTitle, url: `${siteConfig.url}/${locale}/blog` },
    { name: fm.title ?? slug, url: blog.url(slug, locale) },
  ];

  // The collection already handles locale URLs, inLanguage, speakable, and
  // isPartOf (when frontmatter.series is set) — no post-mutation needed.
  const jsonLd = blog.schemaGraph(post, breadcrumbs, {
    locale,
    speakable: true,
  });

  const heroImage =
    (typeof fm.ogImage === "string" && fm.ogImage) ||
    (typeof fm.image === "string" && fm.image) ||
    null;

  return (
    <>
      <ReadingProgress />
      <JsonLd data={jsonLd} />
      {heroImage && (
        <link rel="preload" as="image" href={heroImage} fetchPriority="high" />
      )}
      <main id="main-content" className="container mx-auto px-4 py-12">
        <Breadcrumbs
          items={[
            { name: dict.nav.home, href: `/${locale}` },
            { name: dict.metadata.blogTitle, href: `/${locale}/blog` },
            ...(seriesSlug
              ? [
                  {
                    name: seriesTitle ?? rawSeries ?? seriesSlug,
                    href: `/${locale}/topics/${seriesSlug}`,
                  },
                ]
              : []),
            { name: fm.title ?? slug },
          ]}
        />

        {seriesSlug && currentIndex >= 0 && (
          <aside
            className="surface mt-6 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 px-5 py-3.5 text-sm"
            aria-label="Series"
          >
            <span className="text-ink-600 dark:text-ink-400">
              Part {currentIndex + 1} of {seriesPosts.length} in{" "}
              <Link
                href={`/${locale}/topics/${seriesSlug}`}
                className="font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700"
              >
                {seriesTitle ?? rawSeries}
              </Link>
            </span>
            <span className="flex gap-2">
              {currentIndex > 0 && (
                <Link
                  href={`/${locale}/blog/${seriesPosts[currentIndex - 1].slug}`}
                  className={SERIES_PILL}
                  rel="prev"
                >
                  ← {dict.blog.previous}
                </Link>
              )}
              {currentIndex < seriesPosts.length - 1 && (
                <Link
                  href={`/${locale}/blog/${seriesPosts[currentIndex + 1].slug}`}
                  className={SERIES_PILL}
                  rel="next"
                >
                  {dict.blog.next} →
                </Link>
              )}
            </span>
          </aside>
        )}

        <div className="mt-8 grid gap-10 lg:grid-cols-[1fr_260px]">
          <article>
            <PageHero
              eyebrow={seriesTitle ?? dict.metadata.blogTitle}
              title={fm.title ?? slug}
              intro={
                fm.description ? <p>{fm.description as string}</p> : undefined
              }
            >
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-ink-500 dark:text-ink-400">
                {(() => {
                  // Resolve author display from the normalized array
                  // @next-md-blog/core returns. Prefer the Author object
                  // when we have a profile URL (E-E-A-T anchor).
                  const author = post.authors?.[0];
                  if (!author) return null;
                  const name =
                    typeof author === "string" ? author : author.name;
                  const url =
                    typeof author === "object" && author.url
                      ? author.url
                      : null;
                  return (
                    <span>
                      {dict.blog.byAuthor}{" "}
                      {url ? (
                        <a
                          href={url}
                          target="_blank"
                          rel="author noopener"
                          className="font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700"
                        >
                          {name}
                        </a>
                      ) : (
                        name
                      )}
                    </span>
                  );
                })()}
                {date && (
                  <span>
                    {dict.blog.publishedOn}{" "}
                    <time dateTime={date}>
                      {new Date(date).toLocaleDateString(locale, {
                        year: "numeric",
                        month: "long",
                        day: "numeric",
                      })}
                    </time>
                  </span>
                )}
                {updated && updated !== date && (
                  <span>
                    {dict.blog.updatedOn}{" "}
                    <time dateTime={updated}>
                      {new Date(updated).toLocaleDateString(locale)}
                    </time>
                  </span>
                )}
                <span>
                  {post.readingTime} {dict.blog.readingTime}
                </span>
              </div>
              {tags.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {tags.map((t) => (
                    <Link
                      key={t}
                      href={`/${locale}/blog/tags/${encodeURIComponent(t.toLowerCase())}`}
                      className={TAG_CHIP}
                    >
                      {t}
                    </Link>
                  ))}
                </div>
              )}
            </PageHero>
            <Separator className="my-8 bg-ink-200 dark:bg-ink-800" />
            <div className="prose dark:prose-invert max-w-none prose-headings:scroll-mt-20">
              {/*
                rehype-slug — heading anchors so in-page #links work.
                glossary linker — first-occurrence-only anchor inserter;
                  skips code/pre/headings.
                TODO: Shiki highlighting. `MarkdownContent` runs its rehype
                pipeline synchronously (react-markdown sync mode), and
                Shiki is async. To re-enable, either swap the renderer for
                an async-capable one or wire highlighting via a custom
                `pre`/`code` component override in markdownComponents.
              */}
              <MarkdownContent
                content={post.content}
                components={markdownComponents}
                rehypePlugins={[
                  rehypeSlug,
                  [rehypeGlossaryLinker, { locale, selfSlug: slug }],
                ]}
              />
            </div>
          </article>

          <aside className="hidden lg:block">
            <div className="sticky top-24 space-y-6">
              <TableOfContents
                items={headings}
                title={dict.blog.tableOfContents}
              />
            </div>
          </aside>
        </div>

        {related.length > 0 && (
          <section className="mt-20 flex flex-col gap-6">
            <SectionTitle>{dict.blog.relatedArticles}</SectionTitle>
            <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
              {related.map((r) => (
                <PostCard key={r.slug} post={r} locale={locale} />
              ))}
            </div>
          </section>
        )}
      </main>
    </>
  );
}
