import { blog } from "@/next-md-blog.config";
import { DEFAULT_LOCALE } from "@/lib/i18n";

export const dynamic = "force-static";
export const revalidate = 3600;

export async function GET() {
  return blog.rssResponse({ locale: DEFAULT_LOCALE });
}
