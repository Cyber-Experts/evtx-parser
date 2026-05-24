import { ImageResponse } from "next/og";
import { OgImage } from "@next-md-blog/core";
import { siteConfig } from "@/site.config";
import { LOCALES } from "@/lib/i18n";

export const runtime = "nodejs";
export const alt = siteConfig.name;
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export async function generateImageMetadata() {
  return LOCALES.map((lang) => ({
    id: lang,
    alt: siteConfig.name,
    size,
    contentType,
  }));
}

export default function Image({ params }: { params: { lang: string } }) {
  void params;
  return new ImageResponse(
    (
      <OgImage
        title={siteConfig.name}
        description={siteConfig.description}
        siteName={siteConfig.name}
      />
    ),
    {
      ...size,
      headers: {
        "Cache-Control": "public, max-age=31536000, immutable",
      },
    },
  );
}
