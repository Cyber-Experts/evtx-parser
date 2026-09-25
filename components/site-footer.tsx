import Link from "next/link";
import { siteConfig } from "@/site.config";
import { Logo } from "./Logo";
import { GitHubMark } from "./GitHubMark";
import type { Locale } from "@/lib/i18n";

type Dict = {
  footer: { rights: string; sitemap: string; rss: string };
  nav: { authors: string };
};

const LINK =
  "text-ink-600 transition-colors hover:text-ink-950 dark:text-ink-400 dark:hover:text-ink-50";

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
  return (
    <footer className="mt-24 border-t border-ink-200/70 dark:border-white/[0.06]">
      <div className="container mx-auto grid gap-8 px-4 py-12 md:grid-cols-[1fr_auto] md:items-end">
        <div className="flex flex-col gap-3">
          <Logo className="h-7 w-auto text-ink-900 dark:text-ink-100" />
          <p className="max-w-sm text-sm leading-relaxed text-ink-600 dark:text-ink-400">
            {tagline}
          </p>
          <p className="text-xs text-ink-500">
            © {year} {siteConfig.organization.legalName}. {dict.footer.rights}
          </p>
        </div>
        <nav
          className="flex flex-wrap gap-x-6 gap-y-2 text-sm md:justify-end"
          aria-label="Footer"
        >
          <Link href={`/${locale}/authors`} className={LINK}>
            {dict.nav.authors}
          </Link>
          <Link href={`/${locale}/sitemap`} className={LINK}>
            {dict.footer.sitemap}
          </Link>
          <Link href={`/${locale}/contact`} className={LINK}>
            Contact
          </Link>
          <Link href={`/${locale}/privacy`} className={LINK}>
            Privacy
          </Link>
          <Link href={`/${locale}/terms`} className={LINK}>
            Terms
          </Link>
          <Link href={`/${locale}/feed.xml`} className={LINK}>
            {dict.footer.rss}
          </Link>
          <a
            href="https://github.com/Cyber-Experts/evtx-parser"
            className={`${LINK} inline-flex items-center gap-1.5`}
          >
            <GitHubMark className="h-3.5 w-3.5" />
            GitHub
          </a>
        </nav>
      </div>
    </footer>
  );
}
