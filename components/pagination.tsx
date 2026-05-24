import Link from "next/link";
import { cn } from "@/lib/utils";

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
    <nav aria-label="Pagination" className="flex items-center justify-between mt-12">
      <div>
        {prev && (
          <Link
            href={prev}
            rel="prev"
            className="text-sm hover:underline underline-offset-4"
          >
            ← {labels.previous}
          </Link>
        )}
      </div>
      <ol className="flex items-center gap-1 text-sm" role="list">
        {Array.from({ length: totalPages }, (_, i) => i + 1).map((n) => (
          <li key={n}>
            <Link
              href={hrefFor(n)}
              aria-label={`${labels.page} ${n}`}
              aria-current={n === current ? "page" : undefined}
              className={cn(
                "h-8 min-w-8 inline-flex items-center justify-center rounded-md px-2",
                n === current
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-muted",
              )}
            >
              {n}
            </Link>
          </li>
        ))}
      </ol>
      <div>
        {next && (
          <Link
            href={next}
            rel="next"
            className="text-sm hover:underline underline-offset-4"
          >
            {labels.next} →
          </Link>
        )}
      </div>
    </nav>
  );
}
