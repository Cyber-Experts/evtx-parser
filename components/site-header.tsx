import Link from "next/link";
import { siteConfig } from "@/site.config";
import { Logo } from "./Logo";
import { LocaleSwitcher } from "./locale-switcher";
import { ThemeToggle } from "./theme-toggle";
import type { Locale } from "@/lib/i18n";

type Dict = {
  nav: { home: string; blog: string; search: string };
  toggleTheme: string;
};

export function SiteHeader({ locale, dict }: { locale: Locale; dict: Dict }) {
  return (
    <header className="border-b sticky top-0 z-40 backdrop-blur bg-background/80">
      <div className="container mx-auto flex h-14 items-center justify-between px-4">
        <div className="flex items-center gap-6">
          <Link
            href={`/${locale}`}
            aria-label={siteConfig.shortName}
            className="flex items-center"
          >
            <Logo className="h-6 w-auto text-zinc-900 dark:text-zinc-100" />
          </Link>
          <nav className="hidden md:flex items-center gap-4 text-sm" aria-label="Primary">
            <Link href={`/${locale}`} className="hover:underline">
              {dict.nav.home}
            </Link>
            <Link href={`/${locale}/blog`} className="hover:underline">
              {dict.nav.blog}
            </Link>
            <Link href={`/${locale}/search`} className="hover:underline">
              {dict.nav.search}
            </Link>
          </nav>
        </div>
        <div className="flex items-center gap-1">
          <LocaleSwitcher current={locale} />
          <ThemeToggle label={dict.toggleTheme} />
        </div>
      </div>
    </header>
  );
}
