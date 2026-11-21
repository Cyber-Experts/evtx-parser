import Link from "next/link";
import { siteConfig } from "@/site.config";
import { Logo } from "./Logo";
import { GitHubMark } from "./GitHubMark";
import { LocaleSwitcher } from "./locale-switcher";
import { MobileNav } from "./mobile-nav";
import { ThemeToggle } from "./theme-toggle";
import type { Locale } from "@/lib/i18n";
import { getEventsDict } from "@/src/dict/events";

type Dict = {
  nav: { home: string; blog: string; search: string };
  toggleTheme: string;
};

/** Shared with the home page and footer so every edge lines up. */
export const SHELL = "container mx-auto px-4";

const NAV_LINK =
  "rounded-md px-3 py-1.5 text-ink-600 transition-colors hover:bg-ink-100/70 hover:text-ink-950 dark:text-ink-400 dark:hover:bg-white/[0.06] dark:hover:text-ink-50";

const ICON_BTN =
  "inline-flex h-8 w-8 items-center justify-center rounded-md text-ink-600 transition-colors hover:bg-ink-100/70 hover:text-ink-950 dark:text-ink-400 dark:hover:bg-white/[0.06] dark:hover:text-ink-50";

export function SiteHeader({
  locale,
  dict,
  ctaLabel,
}: {
  locale: Locale;
  dict: Dict;
  /** Primary action ("Open .evtx files"), links to the drop zone. */
  ctaLabel: string;
}) {
  const links = [
    { href: `/${locale}`, label: dict.nav.home },
    { href: `/${locale}/blog`, label: dict.nav.blog },
    { href: `/${locale}/events`, label: getEventsDict(locale).navShort },
    { href: `/${locale}/search`, label: dict.nav.search },
  ];
  return (
    <header className="sticky top-0 z-40 border-b border-ink-200/70 bg-background/75 backdrop-blur-xl backdrop-saturate-150 dark:border-white/[0.07]">
      <div className={`${SHELL} flex h-14 items-center justify-between gap-4`}>
        <div className="flex items-center gap-6">
          <Link
            href={`/${locale}`}
            aria-label={siteConfig.shortName}
            className="flex items-center rounded-md"
          >
            <Logo className="h-7 w-auto text-ink-950 dark:text-white" />
          </Link>
          <nav className="hidden items-center gap-0.5 text-sm md:flex" aria-label="Primary">
            {links.map((l) => (
              <Link key={l.href} href={l.href} className={NAV_LINK}>
                {l.label}
              </Link>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-1">
          <a
            href="https://github.com/Cyber-Experts/evtx-parser"
            aria-label="GitHub"
            title="GitHub"
            className={`${ICON_BTN} hidden sm:inline-flex`}
          >
            <GitHubMark className="h-[17px] w-[17px]" />
          </a>
          <LocaleSwitcher current={locale} />
          <ThemeToggle label={dict.toggleTheme} />
          <Link
            href={`/${locale}#tool`}
            className="ml-2 hidden h-8 items-center rounded-md bg-ink-950 px-3.5 text-sm font-medium text-white shadow-[0_1px_2px_rgb(11_12_15/0.2),inset_0_1px_0_rgb(255_255_255/0.12)] transition-colors hover:bg-ink-800 sm:inline-flex dark:bg-white dark:text-ink-950 dark:hover:bg-ink-200"
          >
            {ctaLabel}
          </Link>
          <MobileNav links={links} label="Menu" />
        </div>
      </div>
    </header>
  );
}
