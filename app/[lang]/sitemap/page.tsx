import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { blog } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { getDictionary, hasLocale } from "../dictionaries";
import { PageHero } from "@/components/PageHero";

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
  return {
    title: dict.metadata.sitemapTitle,
    description: dict.metadata.sitemapDescription,
    alternates: {
      canonical: `${siteConfig.url}/${lang}/sitemap`,
      languages: hreflangFor(siteConfig.url, "/sitemap"),
    },
  };
}

export default async function HtmlSitemap({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const posts = await blog.getAll({ locale });
  return (
    <main
      id="main-content"
      className="container mx-auto flex max-w-3xl flex-col gap-12 px-4 py-12"
    >
      <PageHero
        title={dict.metadata.sitemapTitle}
        intro={dict.metadata.sitemapDescription}
        size="md"
      />

      <div className="grid gap-6 sm:grid-cols-2">
        <section className="surface flex flex-col gap-4 p-6">
          <h2 className="text-xl tracking-[-0.015em] text-ink-950 dark:text-ink-50">
            {dict.nav.home}
          </h2>
          <ul className="flex flex-col gap-2 text-sm">
            <li>
              <Link
                href={`/${locale}`}
                className="font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700"
              >
                {dict.nav.home}
              </Link>
            </li>
            <li>
              <Link
                href={`/${locale}/blog`}
                className="font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700"
              >
                {dict.metadata.blogTitle}
              </Link>
            </li>
            <li>
              <Link
                href={`/${locale}/search`}
                className="font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700"
              >
                {dict.metadata.searchTitle}
              </Link>
            </li>
          </ul>
        </section>

        <section className="surface flex flex-col gap-4 p-6">
          <h2 className="text-xl tracking-[-0.015em] text-ink-950 dark:text-ink-50">
            {dict.metadata.blogTitle}
          </h2>
          {posts.length === 0 ? (
            <p className="text-sm text-ink-600 dark:text-ink-400">
              {dict.blog.noPosts}
            </p>
          ) : (
            <ul className="flex flex-col gap-2 text-sm">
              {posts.map((p) => (
                <li key={p.slug}>
                  <Link
                    href={`/${locale}/blog/${p.slug}`}
                    className="font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700"
                  >
                    {(p.frontmatter.title as string) ?? p.slug}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </main>
  );
}
