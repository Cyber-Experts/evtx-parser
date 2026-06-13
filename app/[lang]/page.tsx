import Link from "next/link";
import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { EvtxUploader } from "@/components/EvtxUploader";
import { Faq } from "@/components/Faq";
import { HomeSeo } from "@/components/HomeSeo";
import { Logo } from "@/components/Logo";
import { JsonLd } from "@/components/seo/json-ld";
import { blog, site } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { hreflangFor, type Locale } from "@/lib/i18n";
import { getDict } from "@/src/dict";
import { hasLocale } from "./dictionaries";

/**
 * Cornerstone posts, in display priority. The home page renders the first
 * few that exist in the current locale — keeps blog posts one click from
 * root and gives every page a hub of inbound internal links.
 */
const FEATURED_SLUGS = [
  "understanding-event-id-4624",
  "event-id-4688-process-creation",
  "event-id-4769-kerberoasting",
  "evtx-file-format-chunks",
  "detecting-4625-brute-force",
  "sysmon-event-id-1-process-create",
  "powershell-4104-scriptblock",
  "service-creation-event-id-7045",
];

type Params = { lang: string };

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { lang } = await params;
  if (!hasLocale(lang)) return {};
  const dict = getDict(lang as Locale);
  return {
    metadataBase: new URL(siteConfig.url),
    // Absolute so the root page isn't suffixed with "| EVTX parser" by the
    // layout template (the title already leads with the brand cluster).
    title: { absolute: dict.meta.title },
    description: dict.meta.description,
    alternates: {
      canonical: `${siteConfig.url}/${lang}`,
      languages: hreflangFor(siteConfig.url, "/"),
    },
    openGraph: {
      type: "website",
      siteName: site.siteName,
      title: dict.meta.title,
      description: dict.meta.description,
      url: `${siteConfig.url}/${lang}`,
      locale: lang,
    },
  };
}

export default async function Home({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = getDict(locale);

  const posts = await blog.getAll({ locale });
  const bySlug = new Map(posts.map((p) => [p.slug, p]));
  const featured = FEATURED_SLUGS.map((s) => bySlug.get(s))
    .filter((p): p is NonNullable<typeof p> => p != null)
    .slice(0, 4);

  // Site-level WebSite + Organization JSON-LD is emitted by [lang]/layout;
  // here we add a SoftwareApplication node for the parser itself.
  const homeGraph = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: dict.meta.siteName,
    description: dict.meta.description,
    applicationCategory: "SecurityApplication",
    operatingSystem: "Any (browser)",
    url: `${siteConfig.url}/${locale}`,
    offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
  };

  return (
    <>
      <JsonLd data={homeGraph} />
      <main
        id="main-content"
        className="mx-auto flex w-full max-w-6xl flex-1 flex-col gap-6 px-4 py-6 sm:gap-8 sm:px-6 sm:py-10 xl:max-w-[1400px] 2xl:max-w-[1600px]"
      >
        <header className="flex flex-col gap-3">
          <Logo className="h-8 w-auto text-zinc-900 dark:text-zinc-100" />
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100 sm:text-3xl">
            {dict.home.headline}
          </h1>
          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            {dict.home.intro}
          </p>
        </header>

        <EvtxUploader dict={dict} locale={locale} />

        {featured.length > 0 && (
          <section
            aria-labelledby="featured-heading"
            className="flex flex-col gap-3 border-t border-zinc-200 pt-6 dark:border-zinc-800"
          >
            <h2
              id="featured-heading"
              className="font-mono text-base font-semibold"
            >
              {dict.home.featuredHeading}
            </h2>
            <ul className="grid gap-3 sm:grid-cols-2">
              {featured.map((p) => (
                <li key={p.slug}>
                  <Link
                    href={`/${locale}/blog/${p.slug}`}
                    className="group flex flex-col gap-1 rounded border border-zinc-200 p-3 hover:border-zinc-400 dark:border-zinc-800 dark:hover:border-zinc-600"
                  >
                    <span className="text-sm font-medium text-zinc-900 group-hover:underline dark:text-zinc-100">
                      {(p.frontmatter.title as string) ?? p.slug}
                    </span>
                    {p.frontmatter.description ? (
                      <span className="line-clamp-2 text-xs text-zinc-600 dark:text-zinc-400">
                        {p.frontmatter.description as string}
                      </span>
                    ) : null}
                  </Link>
                </li>
              ))}
            </ul>
          </section>
        )}

        <HomeSeo locale={locale} />

        <Faq dict={dict} />
      </main>
    </>
  );
}
