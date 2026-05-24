import { ImageResponse } from "next/og";
import { OgImage } from "@next-md-blog/core";
import { siteConfig } from "@/site.config";

export const runtime = "nodejs";
export const alt = siteConfig.name;
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
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
