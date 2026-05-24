import type { Metadata } from "next";
import { notFound } from "next/navigation";
import rehypeSlug from "rehype-slug";
import { MarkdownContent } from "@next-md-blog/core";

import { glossary } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, type Locale } from "@/lib/i18n";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { JsonLd } from "@/components/seo/json-ld";
import { markdownComponents } from "@/components/markdown/components";
import { getDictionary, hasLocale } from "../../dictionaries";

type Params = { lang: string; slug: string };

export async function generateStaticParams() {
  const all: Params[] = [];
  for (const lang of LOCALES) {
    const terms = await glossary.getAll({ locale: lang });
    for (const t of terms) all.push({ lang, slug: t.slug });
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
  const term = await glossary.getOne(slug, { locale });
  if (!term) return { title: "Not found" };
  const languages = await glossary.hreflangMap(slug, LOCALES);
  languages["x-default"] = languages.en ?? glossary.url(slug, locale);
  return {
    metadataBase: new URL(siteConfig.url),
    ...(await glossary.metadata(term, {
      locale,
      titleTemplate: "absolute",
      alternateLanguages: languages,
    })),
  };
}

export default async function GlossaryTerm({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang, slug } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const term = await glossary.getOne(slug, { locale });
  if (!term) notFound();

  // DefinedTerm + Organization + Breadcrumb graph.
  const jsonLd = glossary.schemaGraph(
    term,
    [
      { name: dict.nav.home, url: `${siteConfig.url}/${locale}` },
      { name: "Glossary", url: glossary.indexUrl(locale) },
      {
        name: (term.frontmatter.title as string) ?? slug,
        url: glossary.url(slug, locale),
      },
    ],
    { locale },
  );

  return (
    <>
      <JsonLd data={jsonLd} />
      <main id="main-content" className="container mx-auto px-4 py-10 max-w-3xl">
        <Breadcrumbs
          items={[
            { name: dict.nav.home, href: `/${locale}` },
            { name: "Glossary", href: `/${locale}/glossary` },
            { name: (term.frontmatter.title as string) ?? slug },
          ]}
        />
        <article className="mt-6">
          <header className="space-y-3 mb-8">
            <p className="text-xs uppercase tracking-wide text-muted-foreground">
              Glossary
            </p>
            <h1 className="text-3xl md:text-5xl font-semibold tracking-tight">
              {(term.frontmatter.title as string) ?? slug}
            </h1>
            {term.frontmatter.description && (
              <p className="text-lg text-muted-foreground">
                {term.frontmatter.description as string}
              </p>
            )}
          </header>
          <div className="prose dark:prose-invert max-w-none prose-headings:scroll-mt-20">
            <MarkdownContent
              content={term.content}
              components={markdownComponents}
              rehypePlugins={[rehypeSlug]}
            />
          </div>
        </article>
      </main>
    </>
  );
}
