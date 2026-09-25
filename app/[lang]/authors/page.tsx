import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { slugifyAuthor, type Author } from "@next-md-blog/core";

import { blog, site } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { PageHero } from "@/components/PageHero";
import { CollectionJsonLd } from "@/components/seo/collection-jsonld";
import { getDictionary, hasLocale } from "../dictionaries";

type Params = { lang: string };

export async function generateStaticParams() {
  return LOCALES.map((lang) => ({ lang }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { lang } = await params;
  if (!hasLocale(lang)) return {};
  const dict = await getDictionary(lang as Locale);
  const url = `${siteConfig.url}/${lang}/authors`;
  return {
    metadataBase: new URL(siteConfig.url),
    title: dict.authors.indexTitle,
    description: dict.authors.indexDescription,
    alternates: {
      canonical: url,
      languages: hreflangFor(siteConfig.url, "/authors"),
    },
    openGraph: {
      type: "website",
      url,
      title: dict.authors.indexTitle,
      description: dict.authors.indexDescription,
    },
  };
}

type AuthorCard = {
  slug: string;
  name: string;
  bio?: string;
  postCount: number;
};

function readableName(a: Author): string {
  return typeof a === "string" ? a : a.name;
}

function readableBio(a: Author): string | undefined {
  return typeof a === "object" ? a.bio : undefined;
}

function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]!.toUpperCase())
    .join("");
}

export default async function AuthorsIndexPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);

  const authors = site.authors ?? [];
  const cards: AuthorCard[] = await Promise.all(
    authors.map(async (author) => {
      const name = readableName(author);
      const slug = slugifyAuthor(name);
      const posts = await blog.getByAuthor(slug, { locale });
      return { slug, name, bio: readableBio(author), postCount: posts.length };
    }),
  );

  const url = `${siteConfig.url}/${locale}/authors`;

  return (
    <>
      <CollectionJsonLd
        url={url}
        name={dict.authors.indexTitle}
        description={dict.authors.indexDescription}
        inLanguage={locale}
        items={cards.map((a) => ({
          name: a.name,
          url: `${siteConfig.url}/${locale}/authors/${a.slug}`,
        }))}
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
                { name: dict.authors.indexTitle },
              ]}
            />
          }
          eyebrow={dict.metadata.blogTitle}
          title={dict.authors.indexTitle}
          intro={<p>{dict.authors.indexDescription}</p>}
        />

        {cards.length === 0 ? (
          <p className="surface p-8 text-center text-ink-500 dark:text-ink-400">
            {dict.blog.noPosts}
          </p>
        ) : (
          <section className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {cards.map((a) => (
              <Link
                key={a.slug}
                href={`/${locale}/authors/${a.slug}`}
                className="surface surface-interactive group flex flex-col gap-3 p-6"
              >
                <div className="flex items-center gap-3">
                  <span
                    aria-hidden="true"
                    className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-uv-200 bg-uv-50 text-sm font-semibold text-uv-700 dark:border-uv-400/30 dark:bg-uv-500/10 dark:text-uv-300"
                  >
                    {initials(a.name)}
                  </span>
                  <h2 className="text-lg font-semibold text-ink-950 dark:text-ink-50">
                    {a.name}
                  </h2>
                </div>
                {a.bio && (
                  <p className="line-clamp-3 text-sm leading-relaxed text-ink-600 dark:text-ink-400">
                    {a.bio}
                  </p>
                )}
                <div className="mt-auto flex items-center justify-between pt-2">
                  <span className="eyebrow">
                    {dict.authors.postsCount.replace(
                      "{n}",
                      String(a.postCount),
                    )}
                  </span>
                  <span
                    aria-hidden="true"
                    className="text-uv-500 transition-transform group-hover:translate-x-1"
                  >
                    →
                  </span>
                </div>
              </Link>
            ))}
          </section>
        )}
      </main>
    </>
  );
}
