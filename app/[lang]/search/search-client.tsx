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
    <div className="mt-8 space-y-6">
      <Input
        type="search"
        autoFocus
        placeholder={placeholder}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        aria-label={placeholder}
      />
      {filtered.length === 0 ? (
        <p className="text-muted-foreground">{noResults}</p>
      ) : (
        <ul className="space-y-4" role="list">
          {filtered.map((i) => (
            <li key={i.slug}>
              <Link
                href={`/${locale}/blog/${i.slug}`}
                className="block group"
              >
                <h2 className="font-semibold group-hover:underline">{i.title}</h2>
                {i.description && (
                  <p className="text-sm text-muted-foreground">{i.description}</p>
                )}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
