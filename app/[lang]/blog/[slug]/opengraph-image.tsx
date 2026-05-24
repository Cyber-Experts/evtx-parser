import { ImageResponse } from "next/og";
import { OgImage } from "@next-md-blog/core";
import { blog } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { hasLocale } from "../../dictionaries";

export const runtime = "nodejs";
export const alt = "Blog post";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

type Params = { lang: string; slug: string };

export default async function Image({ params }: { params: Params }) {
  const { lang, slug } = params;
  if (!hasLocale(lang)) {
    return new ImageResponse(<OgImage title={siteConfig.name} />, size);
  }
  const post = await blog.getOne(slug, { locale: lang });
  const title = (post?.frontmatter.title as string) ?? slug;
  const description =
    (post?.frontmatter.description as string) ?? siteConfig.description;
  return new ImageResponse(
    (
      <OgImage
        title={title}
        description={description}
        siteName={siteConfig.name}
      />
    ),
    {
      ...size,
      headers: {
        // OG images are content-addressed by URL; safe to cache forever.
        "Cache-Control": "public, max-age=31536000, immutable",
      },
    },
  );
}
