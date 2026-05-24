import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { blog } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { getDictionary, hasLocale } from "../dictionaries";
import { SearchClient } from "./search-client";

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
    title: dict.metadata.searchTitle,
    description: dict.metadata.searchDescription,
    alternates: {
      canonical: `${siteConfig.url}/${lang}/search`,
      languages: hreflangFor(siteConfig.url, "/search"),
    },
    // Searches over user input shouldn't be indexed individually.
    robots: { index: true, follow: true },
  };
}

export default async function SearchPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const posts = await blog.getAll({ locale });
  const items = posts.map((p) => ({
    slug: p.slug,
    title: (p.frontmatter.title as string) ?? p.slug,
    description: (p.frontmatter.description as string) ?? "",
    tags: ((p.frontmatter.tags as string[]) ?? []).map((t) => t.toLowerCase()),
    date: (p.frontmatter.date as string) ?? "",
  }));
  return (
    <main id="main-content" className="container mx-auto px-4 py-12 max-w-3xl">
      <h1 className="text-3xl md:text-4xl font-semibold tracking-tight">
        {dict.metadata.searchTitle}
      </h1>
      <p className="mt-2 text-muted-foreground">{dict.metadata.searchDescription}</p>
      <SearchClient
        items={items}
        locale={locale}
        placeholder={dict.search.placeholder}
        noResults={dict.search.noResults}
      />
    </main>
  );
}
