import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";

import { getDict } from "@/src/dict";
import { isLocale, type Locale } from "@/src/dict/locales";
import { jsonLdScript } from "@/lib/schema";
import { Breadcrumbs } from "@/components/BreadcrumbsEvtx";
import { PageHero } from "@/components/PageHero";
import {
  SITE_URL,
  canonicalFor,
  localeAlternates,
  OG_LOCALE,
} from "../../_lib/site";

type Tool = {
  id: string;
  name: string;
  url: string;
  internal?: boolean;
  platform: string;
  useCase: string;
  license: string;
  body: React.ReactNode;
};

const TOOLS: Tool[] = [
  {
    id: "evtx-parser",
    name: "EVTX parser (this site)",
    url: "/",
    internal: true,
    platform: "Browser (any OS)",
    useCase: "Ad-hoc triage of a single .evtx without a Windows host",
    license: "Free, MIT-licensed parser core",
    body: (
      <>
        <p>
          A Rust EVTX parser ({" "}
          <a
            href="https://github.com/omerbenamram/evtx"
            target="_blank"
            rel="external noopener"
            className="font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700"
          >
            omerbenamram/evtx
          </a>
          ) compiled to WebAssembly and run in a Web Worker — the same parser
          used by SANS and CCDC blue teams when they need a non-Windows parser.
          Files never leave the browser; useful when you're working on a host
          you don't own (a customer laptop, a forensic image you can't export)
          or when standing up tooling on a fresh workstation would take longer
          than the triage.
        </p>
        <p className="mt-2">
          <strong>Best for:</strong> one .evtx, one analyst, no install. Limited
          to what one browser tab can hold in memory; for {">"}1 GB collections,
          prefer evtx_dump.
        </p>
      </>
    ),
  },
  {
    id: "kape",
    name: "KAPE (Kroll Artifact Parser and Extractor)",
    url: "https://www.kroll.com/en/services/cyber/incident-response-recovery/kroll-artifact-parser-and-extractor-kape",
    platform: "Windows",
    useCase: "Live-host artifact collection (then parsing) at IR scale",
    license: "Free for non-commercial; paid for commercial use",
    body: (
      <>
        <p>
          The default first move on most engagements: KAPE's <em>Targets</em>{" "}
          define what to copy (the <code>EventLogs</code> target pulls all{" "}
          <code>winevt\Logs\*.evtx</code> in one pass with chain-of-custody
          metadata), and its <em>Modules</em> run downstream parsers (Eric
          Zimmerman's <code>EvtxECmd</code>, <code>RECmd</code>, etc.) against
          the collected data. Designed to run from removable media against a
          live system, including locked files.
        </p>
        <p className="mt-2">
          <strong>Best for:</strong> live-host collection where you need
          forensically-sound copies plus immediate parsing. Not
          Linux/macOS-friendly. The community config repo (
          <a
            href="https://github.com/EricZimmerman/KapeFiles"
            target="_blank"
            rel="external noopener"
            className="font-medium text-uv-700 underline decoration-uv-300 underline-offset-4 hover:decoration-uv-500 dark:text-uv-300 dark:decoration-uv-700"
          >
            EricZimmerman/KapeFiles
          </a>
          ) is where you get most of the practical targets.
        </p>
      </>
    ),
  },
  {
    id: "ftk-imager",
    name: "FTK Imager",
    url: "https://www.exterro.com/digital-forensics-software/ftk-imager",
    platform: "Windows",
    useCase: "Disk imaging + targeted file export from live or mounted volumes",
    license: "Free (registration required)",
    body: (
      <>
        <p>
          The classic free GUI for full-disk imaging (E01, RAW, AFF) and for
          pulling specific files out of a mounted or live system. Reads locked
          system files (including the live{" "}
          <code>winevt\Logs\Security.evtx</code>) because it talks to the volume
          below the file lock. Use it when you need a verifiable disk image, not
          just artifact copies.
        </p>
        <p className="mt-2">
          <strong>Best for:</strong> court-admissible disk images, or pulling a
          single locked file off a live host. Not a parser — feed the output
          into KAPE/EvtxECmd or this site.
        </p>
      </>
    ),
  },
  {
    id: "wevtutil",
    name: "wevtutil",
    url: "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil",
    platform: "Windows (built-in)",
    useCase: "Local enumeration, channel export, XML dump on a live host",
    license: "Free (Windows component)",
    body: (
      <>
        <p>
          Microsoft's built-in CLI for the event log. The two commands you'll
          actually use: <code>wevtutil epl Security C:\out\Security.evtx</code>{" "}
          (export a live channel to a portable file) and{" "}
          <code>wevtutil qe Security /c:100 /rd:true /f:xml</code> (dump records
          as XML for piping into a parser). Available on every supported Windows
          version, no install.
        </p>
        <p className="mt-2">
          <strong>Best for:</strong> scripted live-host collection where you
          can't drop binaries on the system. Limited filtering syntax (XPath 1.0
          subset) and slow on large channels.
        </p>
      </>
    ),
  },
  {
    id: "evtx-dump",
    name: "evtx_dump (omerbenamram/evtx)",
    url: "https://github.com/omerbenamram/evtx",
    platform: "Linux, macOS, Windows",
    useCase: "Cross-platform CLI parser for batch / pipeline use",
    license: "MIT",
    body: (
      <>
        <p>
          The Rust parser the EVTX format actually deserved.{" "}
          <code>evtx_dump --json file.evtx</code> emits one JSON document per
          record; pipe into <code>jq</code>, <code>ripgrep</code>, or your SIEM
          ingestion path. Multi-threaded, deterministic, handles partial /
          corrupt chunks gracefully. The same code that powers this site's
          in-browser parser.
        </p>
        <p className="mt-2">
          <strong>Best for:</strong> ingesting many .evtx into a pipeline, or
          for one-off triage on Linux/macOS. No GUI, no built-in dashboard —
          bring your own tooling for filtering and pivoting.
        </p>
      </>
    ),
  },
  {
    id: "python-evtx",
    name: "python-evtx (libyal)",
    url: "https://github.com/williballenthin/python-evtx",
    platform: "Linux, macOS, Windows (Python ≥3.7)",
    useCase: "Programmatic parsing inside Python investigation notebooks",
    license: "Apache 2.0",
    body: (
      <>
        <p>
          Willi Ballenthin's pure-Python EVTX parser. Slower than{" "}
          <code>evtx_dump</code>, but trivial to embed in a Jupyter notebook and
          to extend for unusual analyses (custom event-data field extraction,
          cross-channel correlation). The reference Python implementation for
          the format spec.
        </p>
        <p className="mt-2">
          <strong>Best for:</strong> bespoke analysis in Python.
          Performance-bound on large datasets — prefer <code>evtx_dump</code>{" "}
          for high-throughput work.
        </p>
      </>
    ),
  },
  {
    id: "rawcopy",
    name: "RawCopy",
    url: "https://github.com/jschicht/RawCopy",
    platform: "Windows",
    useCase: "Copy locked system files (including live .evtx) on Windows",
    license: "Open source (no formal license)",
    body: (
      <>
        <p>
          A tiny, portable Windows utility that copies files directly through{" "}
          NTFS internals, bypassing the file lock that prevents normal{" "}
          <code>copy</code> on live event logs. Useful when you only have shell
          access on a host and can't deploy KAPE or FTK Imager.
        </p>
        <p className="mt-2">
          <strong>Best for:</strong> minimum-footprint live-system copies.
          Windows only; no parsing — feed the output into a real parser.
        </p>
      </>
    ),
  },
  {
    id: "event-viewer",
    name: "Event Viewer (built-in)",
    url: "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc766042(v=ws.11)",
    platform: "Windows (built-in)",
    useCase: "Manual browsing on a live host",
    license: "Free (Windows component)",
    body: (
      <>
        <p>
          The MMC snap-in. Fine for clicking through a few records on a live
          server during a tactical investigation, but slow on million-record
          channels, awkward to filter, and unable to load <code>.evtx</code>{" "}
          from an air-gapped Linux/Mac. Useful as the final ground-truth
          renderer (it knows every provider's message manifest); not useful as
          an investigation surface.
        </p>
        <p className="mt-2">
          <strong>Best for:</strong> confirming a single record's full rendered
          message text on a live host. Almost any other workflow is faster in
          another tool.
        </p>
      </>
    ),
  },
];

export async function generateMetadata({
  params,
}: {
  params: Promise<{ lang: string }>;
}): Promise<Metadata> {
  const { lang: locale } = await params;
  if (!isLocale(locale)) return {};
  const dict = getDict(locale);
  const url = canonicalFor(locale, "/tools");
  return {
    metadataBase: new URL(SITE_URL),
    title: dict.tools.title,
    description: dict.tools.description,
    alternates: {
      canonical: url,
      languages: localeAlternates("/tools"),
    },
    openGraph: {
      type: "website",
      siteName: dict.meta.siteName,
      title: dict.tools.title,
      description: dict.tools.description,
      url,
      locale: OG_LOCALE[locale as Locale],
      images: [
        {
          url: `${canonicalFor(locale)}/opengraph-image`,
          width: 1200,
          height: 630,
          alt: dict.tools.title,
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: dict.tools.title,
      description: dict.tools.description,
      images: [`${canonicalFor(locale)}/opengraph-image`],
    },
  };
}

function buildToolsGraph(
  locale: Locale,
  url: string,
  dict: ReturnType<typeof getDict>,
) {
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebPage",
        "@id": `${url}#webpage`,
        url,
        name: dict.tools.title,
        description: dict.tools.description,
        inLanguage: locale,
        isPartOf: { "@id": `${SITE_URL}/${locale}#website` },
      },
      {
        "@type": "ItemList",
        "@id": `${url}#itemlist`,
        name: dict.tools.title,
        numberOfItems: TOOLS.length,
        itemListElement: TOOLS.map((t, i) => ({
          "@type": "ListItem",
          position: i + 1,
          name: t.name,
          url: t.internal ? `${SITE_URL}/${locale}` : t.url,
        })),
      },
      {
        "@type": "BreadcrumbList",
        "@id": `${url}#breadcrumb`,
        itemListElement: [
          {
            "@type": "ListItem",
            position: 1,
            name: dict.meta.siteName,
            item: `${SITE_URL}/${locale}`,
          },
          {
            "@type": "ListItem",
            position: 2,
            name: dict.tools.title,
            item: url,
          },
        ],
      },
    ],
  };
}

export default async function ToolsPage({
  params,
}: {
  params: Promise<{ lang: string }>;
}) {
  const { lang: locale } = await params;
  if (!isLocale(locale)) notFound();
  const dict = getDict(locale);
  const url = canonicalFor(locale, "/tools");
  const ld = buildToolsGraph(locale, url, dict);

  return (
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-12 px-4 py-6 sm:px-6 sm:py-10">
      <PageHero
        top={
          <Breadcrumbs
            dict={dict}
            items={[
              { label: dict.breadcrumb.home, href: `/${locale}` },
              { label: dict.tools.title },
            ]}
          />
        }
        eyebrow="DFIR"
        title={dict.tools.title}
        intro={dict.tools.intro}
      />

      <section aria-labelledby="tools-summary" className="flex flex-col gap-3">
        <h2 id="tools-summary" className="sr-only">
          {dict.tools.title}
        </h2>
        <div className="surface overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="bg-ink-50/70 text-left font-mono text-[0.6875rem] tracking-[0.12em] text-ink-500 uppercase dark:bg-ink-900/60 dark:text-ink-400">
                  <th className="px-4 py-2.5 font-medium">
                    {dict.tools.columnTool}
                  </th>
                  <th className="px-4 py-2.5 font-medium">
                    {dict.tools.columnPlatform}
                  </th>
                  <th className="px-4 py-2.5 font-medium">
                    {dict.tools.columnUseCase}
                  </th>
                  <th className="px-4 py-2.5 font-medium">
                    {dict.tools.columnLicense}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-100 dark:divide-ink-800">
                {TOOLS.map((t) => (
                  <tr
                    key={t.id}
                    className="align-top transition-colors hover:bg-uv-50/40 dark:hover:bg-uv-400/[0.04]"
                  >
                    <td className="px-4 py-3 font-medium text-ink-900 dark:text-ink-100">
                      <a
                        href={`#${t.id}`}
                        className="underline-offset-4 hover:text-uv-700 hover:underline hover:decoration-uv-300 dark:hover:text-uv-300 dark:hover:decoration-uv-700"
                      >
                        {t.name}
                      </a>
                    </td>
                    <td className="px-4 py-3 text-ink-600 dark:text-ink-400">
                      {t.platform}
                    </td>
                    <td className="px-4 py-3 text-ink-600 dark:text-ink-400">
                      {t.useCase}
                    </td>
                    <td className="px-4 py-3 text-ink-600 dark:text-ink-400">
                      {t.license}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <div className="flex flex-col gap-6">
        {TOOLS.map((t) => (
          <section
            key={t.id}
            id={t.id}
            aria-labelledby={`${t.id}-heading`}
            className={`surface flex scroll-mt-24 flex-col gap-4 p-6 sm:p-8 ${
              t.internal ? "edge-glow" : ""
            }`}
          >
            <div className="flex flex-col gap-3">
              <h2
                id={`${t.id}-heading`}
                className="text-2xl tracking-[-0.015em] text-ink-950 dark:text-ink-50"
              >
                {t.internal ? (
                  <Link
                    href={`/${locale}`}
                    className="group inline-flex items-center gap-2 hover:text-uv-700 dark:hover:text-uv-300"
                  >
                    {t.name}
                    <span
                      aria-hidden="true"
                      className="text-base text-uv-500 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
                    >
                      ↗
                    </span>
                  </Link>
                ) : (
                  <a
                    href={t.url}
                    target="_blank"
                    rel="external noopener"
                    className="group inline-flex items-center gap-2 hover:text-uv-700 dark:hover:text-uv-300"
                  >
                    {t.name}
                    <span
                      aria-hidden="true"
                      className="text-base text-uv-500 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
                    >
                      ↗
                    </span>
                  </a>
                )}
              </h2>
              <ul className="flex flex-wrap gap-2">
                {[t.platform, t.license].map((chip) => (
                  <li
                    key={chip}
                    className="rounded-full border border-ink-200 bg-card/70 px-2.5 py-0.5 text-xs text-ink-600 dark:border-ink-800 dark:text-ink-400"
                  >
                    {chip}
                  </li>
                ))}
              </ul>
            </div>
            <div className="text-sm leading-relaxed text-ink-700 dark:text-ink-300">
              {t.body}
            </div>
          </section>
        ))}
      </div>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={jsonLdScript(ld)}
      />
    </main>
  );
}
