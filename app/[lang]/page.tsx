import Link from "next/link";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { buttonVariants } from "@/components/ui/button";
import { PostCard } from "@/components/post-card";
import { blog } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { getDictionary, hasLocale } from "./dictionaries";

type Params = { lang: string };

export async function generateStaticParams() {
  return LOCALES.map((lang) => ({ lang }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { lang } = await params;
  if (!hasLocale(lang)) return {};
  const dict = await getDictionary(lang as Locale);
  return {
    metadataBase: new URL(siteConfig.url),
    title: dict.metadata.homeTitle,
    description: dict.metadata.homeDescription,
    alternates: {
      canonical: `${siteConfig.url}/${lang}`,
      languages: hreflangFor(siteConfig.url, "/"),
    },
  };
}

export default async function HomePage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const posts = await blog.getAll({ locale });
  const featured = posts.slice(0, 3);
  return (
    <main id="main-content" className="container mx-auto px-4 py-16">
      <section className="max-w-3xl space-y-6">
        <h1 className="text-4xl md:text-5xl font-semibold tracking-tight">
          {dict.home.heading}
        </h1>
        <p className="text-lg text-muted-foreground">{dict.home.subheading}</p>
        <div>
          <Link href={`/${locale}/blog`} className={buttonVariants()}>
            {dict.home.readBlog}
          </Link>
        </div>
      </section>

      {featured.length > 0 && (
        <section className="mt-16 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {featured.map((p) => (
            <PostCard key={p.slug} post={p} locale={locale} />
          ))}
        </section>
      )}
    </main>
  );
}
