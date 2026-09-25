import Link from "next/link";
import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { EvtxLocations } from "@/components/EvtxLocations";
import { EvtxUploader } from "@/components/EvtxUploader";
import { Faq } from "@/components/Faq";
import {
  CtaBand,
  FeatureGrid,
  REPO_URL,
  SectionHeading,
  StatsBand,
  WorksWith,
} from "@/components/home/HomeSections";
import { ProductPreview } from "@/components/ProductPreview";
import { HomeSeo } from "@/components/HomeSeo";
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
  "windows-event-id-cheat-sheet-dfir",
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

export default async function Home({ params }: { params: Promise<Params> }) {
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

  // "EVTX parser — Windows Event Log viewer…": brand part in ultraviolet.
  const [headlineBrand, headlineRest] = dict.home.headline.includes(" — ")
    ? dict.home.headline.split(" — ", 2)
    : [null, null];

  return (
    <>
      <JsonLd data={homeGraph} />
      <main
        id="main-content"
        className="mx-auto flex w-full max-w-6xl flex-1 flex-col gap-20 px-4 py-6 sm:gap-28 sm:px-6 sm:py-10 xl:max-w-[1400px] 2xl:max-w-[1600px]"
      >
        {/* Hero — the case file under an ultraviolet lamp. */}
        <header className="relative isolate flex flex-col items-center gap-6 pt-4 text-center sm:pt-8">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -top-40 left-1/2 -z-10 h-[640px] w-[1200px] -translate-x-1/2 bg-[radial-gradient(closest-side,rgb(123_76_255/0.16),transparent)] dark:bg-[radial-gradient(closest-side,rgb(123_76_255/0.32),transparent)]"
          />
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -top-24 left-1/2 -z-10 h-[620px] w-[1400px] -translate-x-1/2 bg-[linear-gradient(to_right,rgb(123_76_255/0.08)_1px,transparent_1px),linear-gradient(to_bottom,rgb(123_76_255/0.08)_1px,transparent_1px)] [mask-image:radial-gradient(ellipse_50%_60%_at_50%_30%,black,transparent)] bg-[size:48px_48px]"
          />
          <a
            href={REPO_URL}
            className="inline-flex items-center gap-2 rounded-full border border-ink-200 bg-card/70 py-1 pr-3 pl-1.5 text-xs text-ink-600 shadow-sm backdrop-blur transition hover:border-uv-300 dark:border-ink-800 dark:text-ink-300 dark:hover:border-uv-400/40"
          >
            <span className="inline-flex items-center gap-1.5 rounded-full bg-glow-400/20 px-2 py-0.5 font-medium text-glow-800 dark:text-glow-300">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-glow-400 opacity-70 motion-reduce:hidden" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-glow-500" />
              </span>
              DFIR
            </span>
            {dict.home.heroTag}
            <span aria-hidden="true" className="text-ink-400">
              →
            </span>
          </a>
          <h1 className="text-gradient max-w-5xl text-[2.6rem] leading-[1.02] font-semibold tracking-[-0.03em] text-balance sm:text-6xl lg:text-7xl">
            {headlineBrand ? (
              <>
                <span className="text-gradient-uv">{headlineBrand}</span>
                <span className="text-ink-300 dark:text-ink-700"> — </span>
                {headlineRest}
              </>
            ) : (
              dict.home.headline
            )}
          </h1>
          <p className="max-w-2xl text-lg leading-relaxed text-ink-600 sm:text-xl dark:text-ink-400">
            {dict.home.intro}
          </p>
        </header>

        {/* The tool is the hero's centrepiece: the drop zone is the main
            call to action, directly under the headline. */}
        <section
          id="tool"
          aria-label={dict.home.dropArea}
          className="-mt-10 scroll-mt-24 sm:-mt-16"
        >
          <EvtxUploader dict={dict} locale={locale} />
        </section>

        <WorksWith label={dict.home.worksWith} />

        {/* "evtx" is a mostly-informational query and this page is the one
            Google ranks for it, so answer "what is it" high on the page. */}
        <section
          aria-labelledby="what-is-evtx"
          className="surface mx-auto -mt-8 flex w-full max-w-4xl flex-col gap-2 px-6 py-5 text-sm leading-relaxed text-ink-700 sm:-mt-12 dark:text-ink-300"
        >
          <h2 id="what-is-evtx" className="eyebrow">
            {dict.home.whatIsHeading}
          </h2>
          <p>
            {dict.home.whatIsBody}{" "}
            <Link
              href={`/${locale}/blog/what-is-an-evtx-file`}
              className="font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700"
            >
              {dict.home.whatIsMore} →
            </Link>
          </p>
        </section>

        <FeatureGrid
          dict={dict}
          preview={
            <div className="mx-auto hidden w-full max-w-5xl rounded-[1.25rem] border border-ink-200/70 bg-white/40 p-2 shadow-[0_50px_120px_-50px_rgb(106_51_245/0.55)] backdrop-blur sm:block dark:border-white/10 dark:bg-white/[0.03]">
              <ProductPreview />
            </div>
          }
        />

        <StatsBand dict={dict} />

        <EvtxLocations dict={dict} locale={locale} />

        {featured.length > 0 && (
          <section
            aria-labelledby="featured-heading"
            className="flex flex-col gap-8"
          >
            <SectionHeading
              id="featured-heading"
              eyebrow="DFIR"
              title={dict.home.featuredHeading}
            />
            <ul className="grid gap-4 sm:grid-cols-2">
              {featured.map((p) => (
                <li key={p.slug}>
                  <Link
                    href={`/${locale}/blog/${p.slug}`}
                    className="surface surface-interactive group flex h-full flex-col gap-2 p-6"
                  >
                    <span className="flex items-start justify-between gap-3 font-medium text-ink-900 dark:text-ink-100">
                      {(p.frontmatter.title as string) ?? p.slug}
                      <span
                        aria-hidden="true"
                        className="text-uv-500 transition-transform group-hover:translate-x-1"
                      >
                        →
                      </span>
                    </span>
                    {p.frontmatter.description ? (
                      <span className="line-clamp-2 text-sm leading-relaxed text-ink-600 dark:text-ink-400">
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

        <CtaBand dict={dict} />
      </main>
    </>
  );
}
