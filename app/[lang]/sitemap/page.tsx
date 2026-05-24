import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { blog } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
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
    <main id="main-content" className="container mx-auto px-4 py-12 max-w-3xl">
      <h1 className="text-3xl md:text-4xl font-semibold tracking-tight">
        {dict.metadata.sitemapTitle}
      </h1>
      <p className="mt-2 text-muted-foreground">{dict.metadata.sitemapDescription}</p>

      <section className="mt-8">
        <h2 className="text-xl font-semibold mb-3">{dict.nav.home}</h2>
        <ul className="list-disc pl-6 space-y-1">
          <li><Link href={`/${locale}`} className="underline">{dict.nav.home}</Link></li>
          <li><Link href={`/${locale}/blog`} className="underline">{dict.metadata.blogTitle}</Link></li>
          <li><Link href={`/${locale}/search`} className="underline">{dict.metadata.searchTitle}</Link></li>
        </ul>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold mb-3">{dict.metadata.blogTitle}</h2>
        {posts.length === 0 ? (
          <p className="text-muted-foreground">{dict.blog.noPosts}</p>
        ) : (
          <ul className="list-disc pl-6 space-y-1">
            {posts.map((p) => (
              <li key={p.slug}>
                <Link href={`/${locale}/blog/${p.slug}`} className="underline">
                  {(p.frontmatter.title as string) ?? p.slug}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}
