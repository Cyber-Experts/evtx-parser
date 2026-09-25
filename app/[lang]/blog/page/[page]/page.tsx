import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { blog } from "@/next-md-blog.config";
import { PostCard } from "@/components/post-card";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { Pagination } from "@/components/pagination";
import { PageHero } from "@/components/PageHero";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor, type Locale } from "@/lib/i18n";
import { getDictionary, hasLocale } from "../../../dictionaries";

const PAGE_SIZE = 9;

type Params = { lang: string; page: string };

export async function generateStaticParams() {
  const out: { lang: string; page: string }[] = [];
  for (const lang of LOCALES) {
    const posts = await blog.getAll({ locale: lang });
    const totalPages = Math.max(1, Math.ceil(posts.length / PAGE_SIZE));
    for (let n = 2; n <= totalPages; n++) {
      out.push({ lang, page: String(n) });
    }
  }
  return out;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { lang, page } = await params;
  if (!hasLocale(lang)) return {};
  const locale = lang as Locale;
  const dict = await getDictionary(locale);
  const n = Number(page);
  const url = `${siteConfig.url}/${lang}/blog/page/${n}`;
  return {
    title: `${dict.metadata.blogTitle} — ${dict.blog.page} ${n}`,
    description: dict.metadata.blogDescription,
    alternates: {
      canonical: url,
      languages: hreflangFor(siteConfig.url, `/blog/page/${n}`),
    },
    robots: { index: true, follow: true },
  };
}

export default async function BlogIndexPaginated({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang, page } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang as Locale;
  const n = Math.max(1, Number(page) || 1);
  const dict = await getDictionary(locale);
  const posts = await blog.getAll({ locale });
  const totalPages = Math.max(1, Math.ceil(posts.length / PAGE_SIZE));
  if (n > totalPages) notFound();
  const slice = posts.slice((n - 1) * PAGE_SIZE, n * PAGE_SIZE);
  const prevHref =
    n === 2 ? `/${locale}/blog` : `/${locale}/blog/page/${n - 1}`;
  const nextHref = n < totalPages ? `/${locale}/blog/page/${n + 1}` : null;
  return (
    <>
      <link rel="prev" href={prevHref} />
      {nextHref && <link rel="next" href={nextHref} />}
      <main
        id="main-content"
        className="container mx-auto flex flex-col gap-12 px-4 py-12"
      >
        <PageHero
          top={
            <Breadcrumbs
              items={[
                { name: dict.nav.home, href: `/${locale}` },
                { name: dict.metadata.blogTitle, href: `/${locale}/blog` },
                { name: `${dict.blog.page} ${n}` },
              ]}
            />
          }
          eyebrow={`${dict.blog.page} ${n} / ${totalPages}`}
          title={dict.metadata.blogTitle}
        />
        <div>
          <section className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {slice.map((p) => (
              <PostCard key={p.slug} post={p} locale={locale} />
            ))}
          </section>
          <Pagination
            current={n}
            totalPages={totalPages}
            basePath={`/${locale}/blog`}
            labels={{
              previous: dict.blog.previous,
              next: dict.blog.next,
              page: dict.blog.page,
            }}
          />
        </div>
      </main>
    </>
  );
}
