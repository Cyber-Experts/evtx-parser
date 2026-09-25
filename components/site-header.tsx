import Link from "next/link";
import { siteConfig } from "@/site.config";
import { Logo } from "./Logo";
import { GitHubMark } from "./GitHubMark";
import { LocaleSwitcher } from "./locale-switcher";
import { ThemeToggle } from "./theme-toggle";
import type { Locale } from "@/lib/i18n";

type Dict = {
  nav: { home: string; blog: string; search: string };
  toggleTheme: string;
};

const NAV_LINK =
  "rounded-md px-2.5 py-1.5 text-ink-600 transition-colors hover:bg-ink-100/70 hover:text-ink-950 dark:text-ink-400 dark:hover:bg-white/[0.05] dark:hover:text-ink-50";

export function SiteHeader({ locale, dict }: { locale: Locale; dict: Dict }) {
  return (
    <header className="sticky top-0 z-40 border-b border-ink-200/70 bg-background/70 backdrop-blur-xl dark:border-white/[0.06]">
      <div className="container mx-auto flex h-16 items-center justify-between px-4">
        <div className="flex items-center gap-6">
          <Link
            href={`/${locale}`}
            aria-label={siteConfig.shortName}
            className="flex items-center"
          >
            <Logo className="h-7 w-auto text-ink-900 dark:text-ink-100" />
          </Link>
          <nav className="hidden items-center gap-1 text-sm md:flex" aria-label="Primary">
            <Link href={`/${locale}`} className={NAV_LINK}>
              {dict.nav.home}
            </Link>
            <Link href={`/${locale}/blog`} className={NAV_LINK}>
              {dict.nav.blog}
            </Link>
            <Link href={`/${locale}/search`} className={NAV_LINK}>
              {dict.nav.search}
            </Link>
          </nav>
        </div>
        <div className="flex items-center gap-1">
          <a
            href="https://github.com/Cyber-Experts/evtx-parser"
            aria-label="GitHub"
            title="GitHub"
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg text-ink-600 transition-colors hover:bg-ink-100/70 hover:text-ink-950 dark:text-ink-400 dark:hover:bg-white/[0.05] dark:hover:text-ink-50"
          >
            <GitHubMark className="h-[18px] w-[18px]" />
          </a>
          <LocaleSwitcher current={locale} />
          <ThemeToggle label={dict.toggleTheme} />
        </div>
      </div>
    </header>
  );
}
