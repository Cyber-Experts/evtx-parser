import Link from "next/link";

import type { Dict } from "@/src/dict/types";

export type Crumb = {
  // Visible label. Pass the localized string from the page that mounts the
  // component — Breadcrumbs intentionally does no translation lookup of
  // its own to keep the data path explicit at the call site.
  label: string;
  // Absolute path including the locale segment, e.g. /en/blog/foo. Omit
  // href for the current page (rendered as plain text and marked
  // aria-current="page").
  href?: string;
};

// Visible breadcrumb trail. The JSON-LD BreadcrumbList lives in each page's
// schema graph; this component is the HTML counterpart so users (and Google
// for sitelink rendering) see the same hierarchy.
export function Breadcrumbs({
  dict,
  items,
}: {
  dict: Dict;
  items: Crumb[];
}) {
  if (items.length === 0) return null;
  return (
    <nav
      aria-label={dict.breadcrumb.label}
      className="font-mono text-xs text-ink-500"
    >
      <ol className="flex flex-wrap items-center gap-1">
        {items.map((item, i) => {
          const isLast = i === items.length - 1;
          return (
            <li key={`${item.label}-${i}`} className="flex items-center gap-1">
              {item.href && !isLast ? (
                <Link
                  href={item.href}
                  className="text-ink-500 underline-offset-2 hover:text-ink-800 hover:underline dark:hover:text-ink-300"
                >
                  {item.label}
                </Link>
              ) : (
                <span
                  aria-current={isLast ? "page" : undefined}
                  className={
                    isLast
                      ? "text-ink-700 dark:text-ink-300"
                      : "text-ink-500"
                  }
                >
                  {item.label}
                </span>
              )}
              {!isLast && (
                <span aria-hidden="true" className="text-ink-400">
                  /
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
