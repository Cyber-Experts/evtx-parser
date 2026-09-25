import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { PageHero } from "@/components/PageHero";
import { CollectionJsonLd } from "@/components/seo/collection-jsonld";
import { glossary } from "@/next-md-blog.config";
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
  return {
    metadataBase: new URL(siteConfig.url),
    title: "Glossary",
    description: "Plain-language definitions of SEO terms.",
    alternates: {
      canonical: `${siteConfig.url}/${lang}/glossary`,
      languages: hreflangFor(siteConfig.url, "/glossary"),
    },
  };
}

export default async function GlossaryIndex({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const terms = await glossary.getAll({ locale });
  const url = `${siteConfig.url}/${lang}/glossary`;

  return (
    <>
      <CollectionJsonLd
        url={url}
        name="Glossary"
        description="Plain-language definitions of SEO terms."
        inLanguage={locale}
        items={terms.map((t) => ({
          name: (t.frontmatter.title as string) ?? t.slug,
          url: glossary.url(t.slug, locale),
        }))}
      />
      <main
        id="main-content"
        className="container mx-auto flex max-w-3xl flex-col gap-12 px-4 py-12"
      >
        <PageHero
          top={
            <Breadcrumbs
              items={[
                { name: dict.nav.home, href: `/${locale}` },
                { name: "Glossary" },
              ]}
            />
          }
          eyebrow="DFIR"
          title="Glossary"
          intro="Plain-language definitions of SEO terms used across the blog."
        />
        <dl className="grid gap-4 sm:grid-cols-2">
          {terms.map((term) => (
            <div
              key={term.slug}
              className="surface surface-interactive group relative flex flex-col gap-2 p-5"
            >
              <dt className="flex items-center justify-between gap-3 text-lg font-semibold text-ink-950 dark:text-ink-50">
                <Link
                  href={`/${locale}/glossary/${term.slug}`}
                  className="after:absolute after:inset-0 after:rounded-2xl focus-visible:outline-none"
                >
                  {(term.frontmatter.title as string) ?? term.slug}
                </Link>
                <span
                  aria-hidden="true"
                  className="text-uv-500 transition-transform group-hover:translate-x-0.5"
                >
                  →
                </span>
              </dt>
              {term.frontmatter.description && (
                <dd className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">
                  {term.frontmatter.description as string}
                </dd>
              )}
            </div>
          ))}
        </dl>
      </main>
    </>
  );
}
