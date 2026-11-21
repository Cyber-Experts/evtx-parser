import Link from "next/link";
import { siteConfig } from "@/site.config";
import { Logo } from "./Logo";
import { GitHubMark } from "./GitHubMark";
import { LocaleSwitcher } from "./locale-switcher";
import { ThemeToggle } from "./theme-toggle";
import { MobileNav } from "./mobile-nav";
import type { Locale } from "@/lib/i18n";
import { getEventsDict } from "@/src/dict/events";

type Dict = {
  nav: { home: string; blog: string; search: string };
  toggleTheme: string;
};

const NAV_LINK =
  "rounded-full px-3 py-1.5 text-ink-600 transition-colors hover:text-ink-950 dark:text-ink-400 dark:hover:text-white";

/**
 * Floating command bar: a hairline pill that sits over the page instead of
 * a full-width bar, so the hero reads edge to edge underneath it.
 */
export function SiteHeader({
  locale,
  dict,
  ctaLabel,
}: {
  locale: Locale;
  dict: Dict;
  ctaLabel: string;
}) {
  const links = [
    { href: `/${locale}/events`, label: getEventsDict(locale).navShort },
    { href: `/${locale}/blog`, label: dict.nav.blog },
    { href: `/${locale}/search`, label: dict.nav.search },
  ];
  return (
    <header className="sticky top-0 z-40 px-3 pt-3 sm:px-4">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-3 rounded-full border border-ink-200/80 bg-white/75 pr-2 pl-4 shadow-[0_8px_30px_-12px_rgb(10_10_10/0.18)] backdrop-blur-xl backdrop-saturate-150 dark:border-white/[0.08] dark:bg-[#111]/70 dark:shadow-[0_8px_30px_-12px_rgb(0_0_0/0.8)]">
        <div className="flex min-w-0 items-center gap-5">
          <Link
            href={`/${locale}`}
            aria-label={siteConfig.shortName}
            className="flex shrink-0 items-center"
          >
            <Logo className="h-7 w-auto text-ink-950 dark:text-white" />
          </Link>
          <nav className="hidden items-center text-sm md:flex" aria-label="Primary">
            {links.map((l) => (
              <Link key={l.href} href={l.href} className={NAV_LINK}>
                {l.label}
              </Link>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-0.5">
          <a
            href="https://github.com/Cyber-Experts/evtx-parser"
            aria-label="GitHub"
            title="GitHub"
            className="hidden h-9 w-9 items-center justify-center rounded-full text-ink-600 transition-colors hover:bg-ink-100 hover:text-ink-950 sm:inline-flex dark:text-ink-400 dark:hover:bg-white/[0.06] dark:hover:text-white"
          >
            <GitHubMark className="h-[18px] w-[18px]" />
          </a>
          <LocaleSwitcher current={locale} />
          <ThemeToggle label={dict.toggleTheme} />
          <MobileNav links={links} label="Menu" />
          <Link
            href={`/${locale}#tool`}
            className="ml-1.5 hidden h-9 items-center rounded-full bg-uv-500 px-4 text-sm font-semibold text-ink-950 shadow-[inset_0_1px_0_rgb(255_255_255/0.35)] transition-colors hover:bg-uv-400 sm:inline-flex"
          >
            {ctaLabel}
          </Link>
        </div>
      </div>
    </header>
  );
}
