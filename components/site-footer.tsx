import Link from "next/link";
import { siteConfig } from "@/site.config";
import type { Locale } from "@/lib/i18n";

type Dict = {
  footer: { rights: string; sitemap: string; rss: string };
  nav: { authors: string };
};

export function SiteFooter({ locale, dict }: { locale: Locale; dict: Dict }) {
  const year = new Date().getFullYear();
  return (
    <footer className="border-t mt-16">
      <div className="container mx-auto px-4 py-8 text-sm text-muted-foreground flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <p>
          © {year} {siteConfig.name}. {dict.footer.rights}
        </p>
        <nav className="flex gap-4 flex-wrap" aria-label="Footer">
          <Link href={`/${locale}/authors`} className="hover:underline">
            {dict.nav.authors}
          </Link>
          <Link href={`/${locale}/sitemap`} className="hover:underline">
            {dict.footer.sitemap}
          </Link>
          <Link href={`/${locale}/contact`} className="hover:underline">
            Contact
          </Link>
          <Link href={`/${locale}/privacy`} className="hover:underline">
            Privacy
          </Link>
          <Link href={`/${locale}/terms`} className="hover:underline">
            Terms
          </Link>
          <Link href={`/${locale}/feed.xml`} className="hover:underline">
            {dict.footer.rss}
          </Link>
        </nav>
      </div>
    </footer>
  );
}
