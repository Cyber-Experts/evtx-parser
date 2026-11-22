import Link from "next/link";
import { siteConfig } from "@/site.config";
import { Logo } from "./Logo";
import { GitHubMark } from "./GitHubMark";
import type { Locale } from "@/lib/i18n";
import { getEventsDict } from "@/src/dict/events";

type Dict = {
  footer: { rights: string; sitemap: string; rss: string };
  nav: { authors: string; blog: string; search: string };
};

const LINK =
  "text-ink-600 transition-colors hover:text-ink-950 dark:text-ink-400 dark:hover:text-white";

const HEAD =
  "font-mono text-[11px] font-medium tracking-[0.12em] text-ink-400 uppercase dark:text-ink-500";

export function SiteFooter({
  locale,
  dict,
  tagline,
}: {
  locale: Locale;
  dict: Dict;
  tagline: string;
}) {
  const year = new Date().getFullYear();
  const cols: { title: string; links: { href: string; label: React.ReactNode; external?: boolean }[] }[] = [
    {
      title: "Product",
      links: [
        { href: `/${locale}#tool`, label: "Viewer" },
        { href: `/${locale}/events`, label: getEventsDict(locale).navShort },
        { href: `/${locale}/search`, label: dict.nav.search },
      ],
    },
    {
      title: "Resources",
      links: [
        { href: `/${locale}/blog`, label: dict.nav.blog },
        { href: `/${locale}/authors`, label: dict.nav.authors },
        { href: `/${locale}/sitemap`, label: dict.footer.sitemap },
        { href: `/${locale}/feed.xml`, label: dict.footer.rss },
      ],
    },
    {
      title: "Company",
      links: [
        { href: `/${locale}/contact`, label: "Contact" },
        { href: `/${locale}/privacy`, label: "Privacy" },
        { href: `/${locale}/terms`, label: "Terms" },
        {
          href: "https://github.com/Cyber-Experts/evtx-parser",
          external: true,
          label: (
            <span className="inline-flex items-center gap-1.5">
              <GitHubMark className="h-3.5 w-3.5" />
              GitHub
            </span>
          ),
        },
      ],
    },
  ];

  return (
    <footer className="relative mt-32 overflow-hidden border-t border-ink-200 dark:border-white/[0.08]">
      <div className="mx-auto grid max-w-6xl gap-12 px-4 pt-16 pb-10 sm:px-6 md:grid-cols-[1.4fr_repeat(3,1fr)]">
        <div className="flex flex-col items-start gap-4">
          <Logo className="h-8 w-auto text-ink-950 dark:text-white" />
          <p className="max-w-xs text-sm leading-relaxed text-ink-600 dark:text-ink-400">
            {tagline}
          </p>
          <span className="inline-flex items-center gap-2 rounded-full border border-ink-200 px-2.5 py-1 font-mono text-[11px] text-ink-600 dark:border-white/10 dark:text-ink-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
            0 bytes uploaded
          </span>
        </div>
        {cols.map((c) => (
          <nav key={c.title} aria-label={c.title} className="flex flex-col gap-3 text-sm">
            <span className={HEAD}>{c.title}</span>
            {c.links.map((l) =>
              l.external ? (
                <a key={l.href} href={l.href} className={LINK}>
                  {l.label}
                </a>
              ) : (
                <Link key={l.href} href={l.href} className={LINK}>
                  {l.label}
                </Link>
              ),
            )}
          </nav>
        ))}
      </div>
      <div className="mx-auto flex max-w-6xl flex-col gap-2 border-t border-ink-200 px-4 py-6 text-xs text-ink-500 sm:flex-row sm:items-center sm:justify-between sm:px-6 dark:border-white/[0.08]">
        <span>
          © {year} {siteConfig.organization.legalName}. {dict.footer.rights}
        </span>
        <span className="font-mono">Rust → WebAssembly · Elastic License 2.0</span>
      </div>
      {/* Oversized wordmark, cropped by the page edge. */}
      <div
        aria-hidden="true"
        className="pointer-events-none mx-auto -mb-[0.32em] max-w-6xl px-4 text-center font-serif text-[22vw] leading-none text-ink-100 select-none sm:px-6 lg:text-[15rem] dark:text-white/[0.04]"
      >
        evtx parser
      </div>
    </footer>
  );
}
