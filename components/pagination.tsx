import Link from "next/link";
import { cn } from "@/lib/utils";

const PILL =
  "inline-flex h-9 items-center justify-center rounded-full border border-ink-200 bg-card/70 px-4 text-sm font-medium text-ink-700 transition-colors hover:border-uv-300 hover:text-uv-700 dark:border-ink-800 dark:text-ink-300 dark:hover:border-uv-400/40 dark:hover:text-uv-300";

export function Pagination({
  current,
  totalPages,
  basePath,
  labels,
}: {
  current: number;
  totalPages: number;
  /** e.g. "/en/blog" — page 1 → basePath; page n → basePath/page/n */
  basePath: string;
  labels: { previous: string; next: string; page: string };
}) {
  if (totalPages <= 1) return null;
  const hrefFor = (n: number) => (n <= 1 ? basePath : `${basePath}/page/${n}`);
  const prev = current > 1 ? hrefFor(current - 1) : null;
  const next = current < totalPages ? hrefFor(current + 1) : null;
  return (
    <nav
      aria-label="Pagination"
      className="mt-12 flex flex-wrap items-center justify-between gap-4"
    >
      <div>
        {prev && (
          <Link href={prev} rel="prev" className={PILL}>
            ← {labels.previous}
          </Link>
        )}
      </div>
      <ol className="flex items-center gap-1.5 text-sm" role="list">
        {Array.from({ length: totalPages }, (_, i) => i + 1).map((n) => (
          <li key={n}>
            <Link
              href={hrefFor(n)}
              aria-label={`${labels.page} ${n}`}
              aria-current={n === current ? "page" : undefined}
              className={cn(
                "inline-flex h-9 min-w-9 items-center justify-center rounded-full px-3 font-medium tabular-nums transition-colors",
                n === current
                  ? "bg-uv-600 text-white shadow-[0_8px_20px_-8px_rgb(106_51_245/0.7)] dark:bg-uv-500"
                  : "text-ink-600 hover:bg-ink-100 hover:text-ink-900 dark:text-ink-400 dark:hover:bg-ink-800/60 dark:hover:text-ink-100",
              )}
            >
              {n}
            </Link>
          </li>
        ))}
      </ol>
      <div>
        {next && (
          <Link href={next} rel="next" className={PILL}>
            {labels.next} →
          </Link>
        )}
      </div>
    </nav>
  );
}
