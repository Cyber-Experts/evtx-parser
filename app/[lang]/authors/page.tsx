import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { slugifyAuthor, type Author } from "@next-md-blog/core";

import { blog, site } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { Breadcrumbs } from "@/components/breadcrumbs";
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
      <main id="main-content" className="container mx-auto px-4 py-12">
        <Breadcrumbs
          items={[
            { name: dict.nav.home, href: `/${locale}` },
            { name: dict.metadata.blogTitle, href: `/${locale}/blog` },
            { name: dict.authors.indexTitle },
          ]}
        />
        <header className="mt-6 space-y-3">
          <h1 className="text-3xl md:text-4xl font-semibold tracking-tight">
            {dict.authors.indexTitle}
          </h1>
          <p className="text-muted-foreground max-w-2xl">
            {dict.authors.indexDescription}
          </p>
        </header>

        {cards.length === 0 ? (
          <p className="mt-12 text-muted-foreground">{dict.blog.noPosts}</p>
        ) : (
          <section className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {cards.map((a) => (
              <Link
                key={a.slug}
                href={`/${locale}/authors/${a.slug}`}
                className="block rounded-lg border p-5 hover:bg-muted/40 transition-colors"
              >
                <h2 className="font-semibold text-lg">{a.name}</h2>
                {a.bio && (
                  <p className="mt-2 text-sm text-muted-foreground line-clamp-3">
                    {a.bio}
                  </p>
                )}
                <p className="mt-3 text-xs text-muted-foreground">
                  {dict.authors.postsCount.replace("{n}", String(a.postCount))}
                </p>
              </Link>
            ))}
          </section>
        )}
      </main>
    </>
  );
}
