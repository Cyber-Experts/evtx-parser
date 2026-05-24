import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { slugifyAuthor, type Author } from "@next-md-blog/core";

import { PostCard } from "@/components/post-card";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { PersonJsonLd } from "@/components/seo/person-jsonld";
import { CollectionJsonLd } from "@/components/seo/collection-jsonld";
import { blog, site } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { getDictionary, hasLocale } from "../../dictionaries";

type Params = { lang: string; slug: string };

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
      <main id="main-content" className="container mx-auto px-4 py-12">
        <Breadcrumbs
          items={[
            { name: dict.nav.home, href: `/${locale}` },
            { name: dict.metadata.blogTitle, href: `/${locale}/blog` },
            { name: author.name },
          ]}
        />
        <header className="mt-6 space-y-3">
          <h1 className="text-3xl md:text-4xl font-semibold tracking-tight">
            {author.name}
          </h1>
          {author.bio && (
            <p className="text-muted-foreground max-w-2xl">{author.bio}</p>
          )}
          <div className="flex gap-3 text-sm">
            {author.url && (
              <Link href={author.url} className="underline">
                Website
              </Link>
            )}
            {author.twitter && (
              <Link
                href={`https://twitter.com/${author.twitter.replace(/^@/, "")}`}
                className="underline"
              >
                Twitter
              </Link>
            )}
            {author.github && (
              <Link
                href={`https://github.com/${author.github.replace(/^@/, "")}`}
                className="underline"
              >
                GitHub
              </Link>
            )}
          </div>
        </header>
        {posts.length === 0 ? (
          <p className="mt-12 text-muted-foreground">{dict.blog.noPosts}</p>
        ) : (
          <section className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {posts.map((p) => (
              <PostCard key={p.slug} post={p} locale={locale} />
            ))}
          </section>
        )}
      </main>
    </>
  );
}
