import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { PostCard } from "@/components/post-card";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { Pagination } from "@/components/pagination";
import { PageHero } from "@/components/PageHero";
import { CollectionJsonLd } from "@/components/seo/collection-jsonld";
import { blog } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { getDictionary, hasLocale } from "../dictionaries";

const PAGE_SIZE = 9;

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
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const posts = await blog.getAll({ locale });
  const base = blog.listMetadata(posts, { locale });
  return {
    ...base,
    metadataBase: new URL(siteConfig.url),
    title: dict.metadata.blogTitle,
    description: dict.metadata.blogDescription,
    alternates: {
      canonical: `${siteConfig.url}/${lang}/blog`,
      languages: hreflangFor(siteConfig.url, "/blog"),
    },
  };
}

export default async function BlogIndex({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const posts = await blog.getAll({ locale });
  const totalPages = Math.max(1, Math.ceil(posts.length / PAGE_SIZE));
  const page = posts.slice(0, PAGE_SIZE);
  const url = `${siteConfig.url}/${locale}/blog`;
  return (
    <>
      <CollectionJsonLd
        url={url}
        name={dict.metadata.blogTitle}
        description={dict.metadata.blogDescription}
        inLanguage={locale}
        items={posts.map((p) => ({
          name: (p.frontmatter.title as string) ?? p.slug,
          url: `${siteConfig.url}/${locale}/blog/${p.slug}`,
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
                { name: dict.metadata.blogTitle },
              ]}
            />
          }
          eyebrow="DFIR"
          title={dict.metadata.blogTitle}
          intro={<p>{dict.metadata.blogDescription}</p>}
        />

        {posts.length === 0 ? (
          <p className="surface p-8 text-center text-ink-500 dark:text-ink-400">
            {dict.blog.noPosts}
          </p>
        ) : (
          <div>
            <section className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
              {page.map((p) => (
                <PostCard key={p.slug} post={p} locale={locale} />
              ))}
            </section>
            <Pagination
              current={1}
              totalPages={totalPages}
              basePath={`/${locale}/blog`}
              labels={{
                previous: dict.blog.previous,
                next: dict.blog.next,
                page: dict.blog.page,
              }}
            />
          </div>
        )}
      </main>
    </>
  );
}
