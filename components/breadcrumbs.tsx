import Link from "next/link";
import { ChevronRight } from "lucide-react";

export type Crumb = { name: string; href?: string };

export function Breadcrumbs({
  items,
  label = "Breadcrumb",
}: {
  items: Crumb[];
  label?: string;
}) {
  return (
    <nav aria-label={label} className="text-sm text-ink-500 dark:text-ink-400">
      <ol className="flex flex-wrap items-center gap-1.5">
        {items.map((item, i) => {
          const last = i === items.length - 1;
          return (
            <li key={i} className="flex min-w-0 items-center gap-1.5">
              {item.href && !last ? (
                <Link
                  href={item.href}
                  className="transition-colors hover:text-uv-700 dark:hover:text-uv-300"
                >
                  {item.name}
                </Link>
              ) : (
                <span
                  aria-current={last ? "page" : undefined}
                  className={
                    last ? "line-clamp-1 text-ink-800 dark:text-ink-200" : ""
                  }
                >
                  {item.name}
                </span>
              )}
              {!last && (
                <ChevronRight
                  className="h-3 w-3 shrink-0 text-ink-300 dark:text-ink-600"
                  aria-hidden
                />
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
