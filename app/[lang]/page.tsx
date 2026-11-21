import Link from "next/link";
import { Check, ChevronDown } from "lucide-react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { CollectGuide } from "@/components/CollectGuide";
import { EvtxLocations } from "@/components/EvtxLocations";
import { EvtxUploader } from "@/components/EvtxUploader";
import { Faq } from "@/components/Faq";
import {
  CtaBand,
  FeatureGrid,
  REPO_URL,
  SectionHeading,
} from "@/components/home/HomeSections";
import {
  ChannelMarquee,
  HowItWorks,
  PrivacySection,
} from "@/components/home/HomeVisuals";
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

  // "EVTX parser — Windows Event Log viewer…": the dash is set lighter.
  const [headlineBrand, headlineRest] = dict.home.headline.includes(" — ")
    ? dict.home.headline.split(" — ", 2)
    : [null, null];

  return (
    <>
      <JsonLd data={homeGraph} />
      <main
        id="main-content"
        className="container mx-auto flex flex-1 flex-col gap-20 px-4 py-6 sm:gap-28 sm:py-10"
      >
        {/* Hero — spotlight from the top, hairline grid, then the tool
            itself framed as the product window. */}
        <header className="relative isolate flex flex-col items-center gap-7 pt-8 text-center sm:pt-16">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -top-56 left-1/2 -z-10 h-[720px] w-[1100px] -translate-x-1/2 bg-[radial-gradient(ellipse_50%_45%_at_50%_30%,rgb(58_107_255/0.18),transparent_70%)] dark:bg-[radial-gradient(ellipse_50%_45%_at_50%_30%,rgb(58_107_255/0.35),transparent_70%)]"
          />
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -top-24 left-1/2 -z-10 h-[680px] w-[1400px] -translate-x-1/2 bg-[linear-gradient(to_right,rgb(11_12_15/0.05)_1px,transparent_1px),linear-gradient(to_bottom,rgb(11_12_15/0.05)_1px,transparent_1px)] [mask-image:radial-gradient(ellipse_45%_55%_at_50%_25%,black,transparent)] bg-[size:56px_56px] dark:bg-[linear-gradient(to_right,rgb(255_255_255/0.05)_1px,transparent_1px),linear-gradient(to_bottom,rgb(255_255_255/0.05)_1px,transparent_1px)]"
          />
          <a
            href={REPO_URL}
            className="group inline-flex items-center gap-2 rounded-full border border-ink-200 bg-card/80 py-1 pr-3 pl-1 text-xs text-ink-600 shadow-[0_1px_2px_rgb(11_12_15/0.05)] backdrop-blur transition hover:border-uv-300 dark:border-white/10 dark:bg-white/[0.03] dark:text-ink-300 dark:hover:border-uv-400/40"
          >
            <span className="inline-flex items-center gap-1.5 rounded-full bg-ink-950 px-2 py-0.5 font-medium text-white dark:bg-white dark:text-ink-950">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-glow-400 opacity-70 motion-reduce:hidden" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-glow-400" />
              </span>
              DFIR
            </span>
            {dict.home.heroTag}
            <span
              aria-hidden="true"
              className="text-ink-400 transition-transform group-hover:translate-x-0.5"
            >
              →
            </span>
          </a>
          {/* The full headline stays in the h1 for SEO; the brand half is set
              as a small label above the display line. */}
          <h1 className="flex flex-col items-center gap-5">
            {headlineBrand ? (
              <>
                <span className="font-mono text-xs font-medium tracking-[0.22em] text-uv-600 uppercase sm:text-sm dark:text-uv-300">
                  {headlineBrand}
                  <span className="sr-only"> — </span>
                </span>
                <span className="text-gradient max-w-5xl pb-1 text-[2.75rem] leading-[0.98] font-semibold tracking-[-0.05em] text-balance sm:text-7xl lg:text-[5.5rem]">
                  {headlineRest}
                </span>
              </>
            ) : (
              <span className="text-gradient max-w-5xl pb-1 text-[2.75rem] leading-[0.98] font-semibold tracking-[-0.05em] text-balance sm:text-7xl lg:text-[5.5rem]">
                {dict.home.headline}
              </span>
            )}
          </h1>
          <p className="max-w-2xl text-lg leading-relaxed text-ink-600 sm:text-xl dark:text-ink-400">
            {dict.home.intro}
          </p>
          <ul className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-sm text-ink-600 dark:text-ink-400">
            {dict.home.trust.map((t) => (
              <li key={t} className="flex items-center gap-2">
                <span className="flex size-4 items-center justify-center rounded-full bg-uv-500/10 text-uv-600 dark:text-uv-300">
                  <Check className="size-2.5" strokeWidth={3} aria-hidden="true" />
                </span>
                {t}
              </li>
            ))}
          </ul>
        </header>

        {/* The tool is the hero's centrepiece: the drop zone is the main
            call to action, directly under the headline. */}
        <section
          id="tool"
          aria-label={dict.home.dropArea}
          className="-mt-6 scroll-mt-24 sm:-mt-10"
        >
          <EvtxUploader
            dict={dict}
            locale={locale}
            emptyStateAside={
              <details className="group mx-auto w-full max-w-5xl">
                <summary className="mx-auto flex w-fit cursor-pointer list-none items-center gap-2 rounded-full border border-ink-200 bg-card px-4 py-2 text-sm text-ink-700 shadow-[0_1px_2px_rgb(11_12_15/0.05)] transition-colors select-none hover:border-uv-300 hover:text-ink-950 dark:border-white/10 dark:bg-white/[0.03] dark:text-ink-300 dark:hover:border-uv-400/40 dark:hover:text-ink-50 [&::-webkit-details-marker]:hidden">
                  {dict.home.collectToggle}
                  <ChevronDown
                    aria-hidden="true"
                    className="size-4 text-ink-400 transition-transform group-open:rotate-180 motion-reduce:transition-none"
                  />
                </summary>
                <div className="mt-4">
                  <CollectGuide dict={dict} locale={locale} />
                </div>
              </details>
            }
          />
        </section>

        {/* Everything below the tool reads as an editorial column: narrower
            than the (wide) workspace so line lengths and cards stay calm. */}
        <div className="mx-auto flex w-full max-w-6xl flex-col gap-24 sm:gap-32">
          <ChannelMarquee label={dict.home.worksWith} />

          {/* "evtx" is a mostly-informational query and this page is the one
              Google ranks for it, so answer "what is it" high on the page. */}
          <section
            aria-labelledby="what-is-evtx"
            className="surface mx-auto -mt-10 flex w-full max-w-3xl flex-col gap-2 px-6 py-5 text-sm leading-relaxed text-ink-700 sm:-mt-16 dark:text-ink-300"
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
              <div className="relative mx-auto hidden w-full max-w-5xl rounded-[1.25rem] border border-ink-200/70 bg-white/50 p-2 shadow-[0_60px_140px_-60px_rgb(36_80_245/0.6)] ring-1 ring-black/[0.02] backdrop-blur sm:block dark:border-white/10 dark:bg-white/[0.03] dark:ring-white/[0.03]">
                <ProductPreview />
              </div>
            }
          />

          <HowItWorks dict={dict} />

          <PrivacySection dict={dict} />

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
                {featured.map((p, i) => (
                  <li key={p.slug}>
                    <Link
                      href={`/${locale}/blog/${p.slug}`}
                      className="surface surface-interactive group flex h-full flex-col gap-3 p-6 sm:p-7"
                    >
                      <span className="flex items-center justify-between gap-3">
                        <span className="font-mono text-[11px] tracking-[0.14em] text-uv-600 dark:text-uv-300">
                          {String(i + 1).padStart(2, "0")}
                        </span>
                        <span
                          aria-hidden="true"
                          className="flex size-7 items-center justify-center rounded-full border border-ink-200 text-ink-400 transition-all group-hover:translate-x-0.5 group-hover:border-uv-300 group-hover:bg-uv-50 group-hover:text-uv-600 dark:border-white/[0.08] dark:group-hover:border-uv-400/40 dark:group-hover:bg-uv-400/10 dark:group-hover:text-uv-300"
                        >
                          →
                        </span>
                      </span>
                      <span className="font-heading text-lg leading-snug font-semibold text-ink-900 dark:text-ink-50">
                        {(p.frontmatter.title as string) ?? p.slug}
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
        </div>
      </main>
    </>
  );
}
