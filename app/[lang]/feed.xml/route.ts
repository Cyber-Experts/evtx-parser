import { notFound } from "next/navigation";
import { blog } from "@/next-md-blog.config";
import { LOCALES, hasLocale, type Locale } from "@/lib/i18n";

export const dynamic = "force-static";
export const revalidate = 3600;

export async function generateStaticParams() {
  return LOCALES.map((lang) => ({ lang }));
}

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ lang: string }> },
) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  return blog.rssResponse({ locale: lang as Locale });
}
