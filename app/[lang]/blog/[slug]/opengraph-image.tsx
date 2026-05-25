import { notFound } from "next/navigation";
import { ImageResponse } from "next/og";

import { blog } from "@/next-md-blog.config";
import { isLocale } from "@/src/dict/locales";
import { LOCALES, type Locale } from "@/lib/i18n";
import { ogContentType, ogSize } from "@/lib/og-template";

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

  const title = (post.frontmatter.title as string) ?? slug;
  const description = (post.frontmatter.description as string) ?? "";
  const readingMinutes = post.readingTime;

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "linear-gradient(135deg, #0a0a0a 0%, #18181b 100%)",
          padding: "72px",
          color: "#ffffff",
          fontFamily: "ui-sans-serif, system-ui, sans-serif",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "16px",
            fontSize: "26px",
            color: "#a1a1aa",
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
          }}
        >
          <div
            style={{
              padding: "6px 14px",
              border: "1px solid #3f3f46",
              borderRadius: "8px",
              color: "#e4e4e7",
            }}
          >
            BLOG
          </div>
          <div>{`www.evtxparser.com/${lang}/blog`}</div>
        </div>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "20px",
            maxWidth: "1056px",
          }}
        >
          <div
            style={{
              fontSize: title.length > 60 ? "56px" : "68px",
              fontWeight: 700,
              lineHeight: 1.1,
              letterSpacing: "-0.02em",
              color: "#fafafa",
            }}
          >
            {title}
          </div>
          {description && (
            <div
              style={{
                fontSize: "26px",
                lineHeight: 1.4,
                color: "#a1a1aa",
                display: "-webkit-box",
                WebkitLineClamp: 3,
                WebkitBoxOrient: "vertical",
                overflow: "hidden",
              }}
            >
              {description}
            </div>
          )}
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            fontSize: "22px",
            color: "#71717a",
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
          }}
        >
          <div>Windows Event Log forensics</div>
          <div style={{ color: "#a1a1aa" }}>
            {`${readingMinutes} min · ${lang.toUpperCase()}`}
          </div>
        </div>
      </div>
    ),
    size,
  );
}
