import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { ContentMetadata } from "@next-md-blog/core";
import type { Locale } from "@/lib/i18n";

export function PostCard({
  post,
  locale,
}: {
  post: ContentMetadata;
  locale: Locale;
}) {
  const fm = post.frontmatter;
  const date = typeof fm.date === "string" ? fm.date : undefined;
  const tags = (fm.tags as string[] | undefined) ?? [];
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Link
            href={`/${locale}/blog/${post.slug}`}
            className="hover:underline underline-offset-4"
          >
            {fm.title ?? post.slug}
          </Link>
        </CardTitle>
        {fm.description && <CardDescription>{fm.description as string}</CardDescription>}
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground flex flex-wrap items-center gap-2">
        {date && <time dateTime={date}>{new Date(date).toLocaleDateString(locale)}</time>}
        {tags.length > 0 && (
          <div className="flex gap-1 flex-wrap">
            {tags.slice(0, 4).map((t) => (
              <Badge key={t} variant="secondary">
                <Link href={`/${locale}/blog/tags/${encodeURIComponent(t.toLowerCase())}`}>
                  {t}
                </Link>
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
