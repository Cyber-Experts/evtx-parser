import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { slugifyAuthor, type Author } from "@next-md-blog/core";

import { PostCard } from "@/components/post-card";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { PageHero } from "@/components/PageHero";
import { PersonJsonLd } from "@/components/seo/person-jsonld";
import { CollectionJsonLd } from "@/components/seo/collection-jsonld";
import { blog, site } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { getDictionary, hasLocale } from "../../dictionaries";

type Params = { lang: string; slug: string };

const CHIP =
  "rounded-full border border-ink-200 bg-card/70 px-3 py-1 font-medium text-ink-700 transition-colors hover:border-uv-300 hover:text-uv-700 dark:border-ink-800 dark:text-ink-300 dark:hover:border-uv-400/40 dark:hover:text-uv-300";

/** Resolve an author by slug from site.config.authors. App-specific glue. */
function resolveAuthorBySlug(slug: string): Author | null {
  for (const a of site.authors ?? []) {
    if (slugifyAuthor(a.name) === slug) return a;
  }
  return null;
}

export async function generateStaticParams() {
  const slugs = await blog.getAllAuthorSlugs(LOCALES);
  const out: Params[] = [];
  for (const lang of LOCALES) {
    for (const slug of slugs) out.push({ lang, slug });
  }
  return out;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { lang, slug } = await params;
  if (!hasLocale(lang)) return {};
  const author = resolveAuthorBySlug(slug);
  if (!author) return { title: "Author not found" };
  const url = `${siteConfig.url}/${lang}/authors/${slug}`;
  return {
    metadataBase: new URL(siteConfig.url),
    title: author.name,
    description: author.bio ?? `Posts by ${author.name}.`,
    alternates: {
      canonical: url,
      languages: hreflangFor(siteConfig.url, `/authors/${slug}`),
    },
    openGraph: {
      type: "profile",
      url,
      title: author.name,
      ...(author.bio ? { description: author.bio } : {}),
    },
  };
}

export default async function AuthorPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang, slug } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const author = resolveAuthorBySlug(slug);
  if (!author) notFound();
  const posts = await blog.getByAuthor(slug, { locale });
  const url = `${siteConfig.url}/${lang}/authors/${slug}`;

  return (
    <>
      <PersonJsonLd author={author} url={url} inLanguage={locale} />
      <CollectionJsonLd
        url={url}
        name={`${author.name} — ${dict.metadata.blogTitle}`}
        items={posts.map((p) => ({
          name: (p.frontmatter.title as string) ?? p.slug,
          url: `${siteConfig.url}/${locale}/blog/${p.slug}`,
        }))}
        inLanguage={locale}
      />
      <main
        id="main-content"
        className="container mx-auto flex flex-col gap-12 px-4 py-12"
      >
        <PageHero
          top={
            <Breadcrumbs
              items={[
                { name: dict.nav.home, href: `/${locale}` },
                { name: dict.metadata.blogTitle, href: `/${locale}/blog` },
                { name: dict.authors.indexTitle, href: `/${locale}/authors` },
                { name: author.name },
              ]}
            />
          }
          eyebrow={dict.authors.indexTitle}
          title={author.name}
          intro={author.bio ? <p>{author.bio}</p> : undefined}
        >
          <div className="flex flex-wrap gap-2 text-sm">
            {author.url && (
              <Link href={author.url} className={CHIP}>
                Website
              </Link>
            )}
            {author.twitter && (
              <Link
                href={`https://twitter.com/${author.twitter.replace(/^@/, "")}`}
                className={CHIP}
              >
                Twitter
              </Link>
            )}
            {author.github && (
              <Link
                href={`https://github.com/${author.github.replace(/^@/, "")}`}
                className={CHIP}
              >
                GitHub
              </Link>
            )}
          </div>
        </PageHero>
        {posts.length === 0 ? (
          <p className="surface p-8 text-center text-ink-500 dark:text-ink-400">
            {dict.blog.noPosts}
          </p>
        ) : (
          <section className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {posts.map((p) => (
              <PostCard key={p.slug} post={p} locale={locale} />
            ))}
          </section>
        )}
      </main>
    </>
  );
}
