import Link from "next/link";
import type { ContentMetadata } from "@next-md-blog/core";
import type { Locale } from "@/lib/i18n";

export const TAG_CHIP =
  "rounded-full border border-ink-200 bg-card/70 px-2.5 py-0.5 text-xs text-ink-600 transition-colors hover:border-uv-300 hover:text-uv-700 dark:border-ink-800 dark:text-ink-400 dark:hover:border-uv-400/40 dark:hover:text-uv-300";

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
    <article className="surface surface-interactive group relative flex h-full flex-col gap-3 p-6">
      {date && (
        <time dateTime={date} className="eyebrow">
          {new Date(date).toLocaleDateString(locale)}
        </time>
      )}
      <h3 className="text-lg leading-snug font-semibold tracking-[-0.01em] text-ink-950 dark:text-ink-50">
        {/* Stretched link: the whole card is clickable, tag chips stay on top. */}
        <Link
          href={`/${locale}/blog/${post.slug}`}
          className="after:absolute after:inset-0 after:rounded-2xl focus-visible:outline-none"
        >
          {fm.title ?? post.slug}
        </Link>
      </h3>
      {fm.description && (
        <p className="line-clamp-3 text-sm leading-relaxed text-ink-600 dark:text-ink-400">
          {fm.description as string}
        </p>
      )}
      <div className="mt-auto flex items-end justify-between gap-3 pt-2">
        {tags.length > 0 ? (
          <div className="relative z-10 flex flex-wrap gap-1.5">
            {tags.slice(0, 4).map((t) => (
              <Link
                key={t}
                href={`/${locale}/blog/tags/${encodeURIComponent(t.toLowerCase())}`}
                className={TAG_CHIP}
              >
                {t}
              </Link>
            ))}
          </div>
        ) : (
          <span />
        )}
        <span
          aria-hidden="true"
          className="shrink-0 text-uv-500 transition-transform group-hover:translate-x-1"
        >
          →
        </span>
      </div>
    </article>
  );
}
