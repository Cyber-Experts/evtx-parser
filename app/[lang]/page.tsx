import Link from "next/link";
import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { ArrowRight, ArrowUpRight } from "lucide-react";

import { CollectGuide } from "@/components/CollectGuide";
import { EvtxLocations } from "@/components/EvtxLocations";
import { EvtxUploader } from "@/components/EvtxUploader";
import { Faq } from "@/components/Faq";
import {
  COL,
  CtaBand,
  FeatureGrid,
  FlareLine,
  REPO_URL,
  SIGMA_COUNT,
  SectionHeading,
  StatsBand,
  WorksWith,
} from "@/components/home/HomeSections";
import { ProductShot } from "@/components/home/ProductShot";
import { HUNTS } from "@/lib/hunts";
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

  // "EVTX parser — Windows Event Log viewer…": the brand set in the serif
  // voice on its own line, the description in the sans below it.
  const [headlineBrand, headlineRest] = dict.home.headline.includes(" — ")
    ? dict.home.headline.split(" — ", 2)
    : [null, null];

  const specs = [
    `0 ${dict.home.statUploaded}`,
    `${HUNTS.length} hunts`,
    `${SIGMA_COUNT.toLocaleString("en-US")} Sigma rules`,
    "Rust → WebAssembly",
  ];

  return (
    <>
      <JsonLd data={homeGraph} />
      <main
        id="main-content"
        className="flex flex-1 flex-col gap-24 pb-8 sm:gap-36"
      >
        {/* Hero: a report-white (or black) page with a single flare on the
            event baseline. */}
        <div className="relative">
          <div className="relative isolate">
            <div
              aria-hidden="true"
              className="pointer-events-none absolute inset-x-0 -top-24 -z-10 h-[720px] bg-[linear-gradient(to_right,rgb(10_10_10/0.045)_1px,transparent_1px)] bg-[size:calc(100%/12)_100%] [mask-image:linear-gradient(to_bottom,black,transparent_85%)] dark:bg-[linear-gradient(to_right,rgb(255_255_255/0.045)_1px,transparent_1px)]"
            />
            <header className={`${COL} flex flex-col gap-6 pt-8 sm:gap-7 sm:pt-12`}>
              <a
                href={REPO_URL}
                className="group inline-flex w-fit items-center gap-2.5 rounded-full border border-ink-200 bg-background py-1 pr-3 pl-1 text-xs text-ink-600 transition-colors hover:border-ink-300 dark:border-white/10 dark:text-ink-400 dark:hover:border-white/20"
              >
                <span className="rounded-full bg-ink-950 px-2 py-0.5 font-mono text-[10px] font-medium tracking-wider text-white dark:bg-white dark:text-ink-950">
                  DFIR
                </span>
                {dict.home.heroTag}
                <ArrowUpRight
                  aria-hidden="true"
                  className="size-3.5 text-ink-400 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
                />
              </a>
              <h1 className="max-w-5xl text-[2.5rem] leading-[0.98] font-semibold tracking-[-0.045em] text-balance text-ink-950 sm:text-6xl lg:text-[4.5rem] dark:text-white">
                {headlineBrand ? (
                  <>
                    <span className="font-serif block text-[1.08em] leading-[0.9] tracking-[-0.02em] text-uv-600 dark:text-uv-400">
                      {headlineBrand}
                    </span>
                    <span className="sr-only"> — </span>
                    <span className="text-gradient">{headlineRest}</span>
                  </>
                ) : (
                  dict.home.headline
                )}
              </h1>
              {/* The drop zone right below is the primary action, so the hero
                  carries no duplicate CTA: intro on the left, specs on the right. */}
              <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end lg:gap-12">
                <p className="max-w-xl text-base leading-relaxed text-ink-600 sm:text-lg dark:text-ink-400">
                  {dict.home.intro}
                </p>
                <ul className="flex flex-wrap gap-x-5 gap-y-2 font-mono text-xs text-ink-500 lg:justify-end lg:pb-1">
                  {specs.map((s) => (
                    <li key={s} className="flex items-center gap-2">
                      <span aria-hidden="true" className="h-1 w-1 bg-uv-500" />
                      {s}
                    </li>
                  ))}
                </ul>
              </div>
            </header>
            <FlareLine className="mt-2 mb-5 h-14 text-ink-300 sm:h-20 dark:text-ink-700" />
          </div>

          {/* The tool itself, framed like evidence. */}
          <section
            id="tool"
            aria-label={dict.home.dropArea}
            className={`${COL} scroll-mt-24`}
          >
            <EvtxUploader
              dict={dict}
              locale={locale}
              emptyStateAside={
                <a
                  href="#collect"
                  className="group mx-auto inline-flex items-center gap-2 text-sm text-ink-600 transition-colors hover:text-ink-950 dark:text-ink-400 dark:hover:text-white"
                >
                  {dict.collect.heading}
                  <ArrowRight
                    aria-hidden="true"
                    className="size-3.5 rotate-90 transition-transform group-hover:translate-y-0.5"
                  />
                </a>
              }
            />
          </section>
        </div>

        <WorksWith label={dict.home.worksWith} />

        {/* "evtx" is a mostly-informational query and this page is the one
            Google ranks for it, so answer "what is it" high on the page. */}
        <section
          aria-labelledby="what-is-evtx"
          className={`${COL} grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)] lg:gap-16`}
        >
          <h2
            id="what-is-evtx"
            className="text-3xl leading-[1.08] tracking-[-0.035em] text-balance text-ink-950 sm:text-4xl dark:text-white"
          >
            {dict.home.whatIsHeading}
          </h2>
          <p className="text-base leading-relaxed text-ink-600 sm:text-lg dark:text-ink-400">
            {dict.home.whatIsBody}{" "}
            <Link
              href={`/${locale}/blog/what-is-an-evtx-file`}
              className="font-medium text-ink-950 underline decoration-uv-500 decoration-2 underline-offset-4 transition-colors hover:text-uv-700 dark:text-white dark:hover:text-uv-300"
            >
              {dict.home.whatIsMore} →
            </Link>
          </p>
        </section>

        <FeatureGrid dict={dict} preview={<ProductShot />} />

        <div className={COL}>
          <StatsBand dict={dict} />
        </div>

        <div className={`${COL} flex flex-col gap-16`}>
          <EvtxLocations dict={dict} locale={locale} />
          <div className="scroll-mt-24">
            <CollectGuide dict={dict} locale={locale} />
          </div>
        </div>

        {featured.length > 0 && (
          <section
            aria-labelledby="featured-heading"
            className={`${COL} flex flex-col gap-10`}
          >
            <SectionHeading
              id="featured-heading"
              eyebrow="DFIR"
              title={dict.home.featuredHeading}
            />
            <ul className="flex flex-col border-t border-ink-200 dark:border-white/[0.08]">
              {featured.map((p, i) => (
                <li key={p.slug}>
                  <Link
                    href={`/${locale}/blog/${p.slug}`}
                    className="group grid gap-2 border-b border-ink-200 py-6 transition-colors sm:grid-cols-[3rem_minmax(0,1fr)_minmax(0,1fr)_2rem] sm:gap-6 dark:border-white/[0.08]"
                  >
                    <span className="font-mono text-xs text-ink-400 sm:pt-1.5">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <span className="text-lg font-semibold tracking-[-0.015em] text-ink-950 transition-colors group-hover:text-uv-700 dark:text-white dark:group-hover:text-uv-300">
                      {(p.frontmatter.title as string) ?? p.slug}
                    </span>
                    {p.frontmatter.description ? (
                      <span className="line-clamp-2 text-sm leading-relaxed text-ink-600 dark:text-ink-400">
                        {p.frontmatter.description as string}
                      </span>
                    ) : (
                      <span />
                    )}
                    <ArrowUpRight
                      aria-hidden="true"
                      className="hidden size-5 text-ink-400 transition-[color,transform] group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-uv-600 sm:block dark:group-hover:text-uv-400"
                    />
                  </Link>
                </li>
              ))}
            </ul>
          </section>
        )}

        <div className={COL}>
          <HomeSeo locale={locale} />
        </div>

        <div className={COL}>
          <Faq dict={dict} />
        </div>

        <div className={COL}>
          <CtaBand dict={dict} />
        </div>
      </main>
    </>
  );
}
