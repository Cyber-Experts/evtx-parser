import { notFound } from "next/navigation";

import { blog } from "@/next-md-blog.config";
import { isLocale } from "@/src/dict/locales";
import { LOCALES, type Locale } from "@/lib/i18n";
import { ogContentType, ogSize, renderPostOg } from "@/lib/og-template";

export const size = ogSize;
export const contentType = ogContentType;
export const alt = "EVTX parser blog post";

export async function generateStaticParams() {
  const out: { lang: string; slug: string }[] = [];
  for (const lang of LOCALES) {
    const posts = await blog.getAll({ locale: lang });
    for (const p of posts) out.push({ lang, slug: p.slug });
  }
  return out;
}

export default async function PostOpengraphImage({
  params,
}: {
  params: Promise<{ lang: string; slug: string }>;
}) {
  const { lang, slug } = await params;
  if (!isLocale(lang)) notFound();
  const post = await blog.getOne(slug, { locale: lang as Locale });
  if (!post) notFound();

  return renderPostOg({
    title: (post.frontmatter.title as string) ?? slug,
    description: (post.frontmatter.description as string) ?? "",
    locale: lang as Locale,
    minutes: post.readingTime,
  });
}
