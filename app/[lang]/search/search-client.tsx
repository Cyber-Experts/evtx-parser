"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { Input } from "@/components/ui/input";
import type { Locale } from "@/lib/i18n";

type Item = {
  slug: string;
  title: string;
  description: string;
  tags: string[];
  date: string;
};

export function SearchClient({
  items,
  locale,
  placeholder,
  noResults,
}: {
  items: Item[];
  locale: Locale;
  placeholder: string;
  noResults: string;
}) {
  const [q, setQ] = useState("");
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((i) =>
      [i.title, i.description, ...i.tags].some((s) =>
        s.toLowerCase().includes(needle),
      ),
    );
  }, [items, q]);
  return (
    <div className="flex flex-col gap-6">
      <Input
        type="search"
        autoFocus
        placeholder={placeholder}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        aria-label={placeholder}
        className="h-auto rounded-xl border border-ink-200 bg-card px-4 py-2.5 text-base shadow-sm focus-visible:border-uv-400 focus-visible:ring-2 focus-visible:ring-uv-500/30 dark:border-ink-800 dark:bg-card"
      />
      {filtered.length === 0 ? (
        <p className="surface p-5 text-sm text-ink-600 dark:text-ink-400">
          {noResults}
        </p>
      ) : (
        <ul className="flex flex-col gap-3" role="list">
          {filtered.map((i) => (
            <li key={i.slug}>
              <Link
                href={`/${locale}/blog/${i.slug}`}
                className="surface surface-interactive group flex items-start gap-4 p-5"
              >
                <div className="flex min-w-0 flex-1 flex-col gap-1.5">
                  <h2 className="text-lg leading-snug text-ink-950 dark:text-ink-50">
                    {i.title}
                  </h2>
                  {i.description && (
                    <p className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">
                      {i.description}
                    </p>
                  )}
                  {i.tags.length > 0 && (
                    <ul className="flex flex-wrap gap-1.5 pt-1">
                      {i.tags.map((t) => (
                        <li
                          key={t}
                          className="rounded-full border border-ink-200 bg-card/70 px-2.5 py-0.5 text-xs text-ink-600 dark:border-ink-800 dark:text-ink-400"
                        >
                          {t}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <span
                  aria-hidden="true"
                  className="pt-1 text-uv-500 transition-transform group-hover:translate-x-0.5"
                >
                  →
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
