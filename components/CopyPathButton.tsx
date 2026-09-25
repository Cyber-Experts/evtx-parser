"use client";

import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";

import { copyText } from "@/lib/clipboard";

/** Small icon button that copies `value` and flashes a "Copied" state. */
export function CopyPathButton({
  value,
  label,
  copiedLabel,
  text,
}: {
  /** Text to copy, or a function computing it at click time. */
  value: string | (() => string);
  label: string;
  copiedLabel: string;
  /** Optional visible label next to the icon. */
  text?: string;
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  async function copy() {
    await copyText(typeof value === "function" ? value() : value);
    setCopied(true);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(false), 1500);
  }

  return (
    <button
      type="button"
      onClick={copy}
      aria-label={label}
      title={copied ? copiedLabel : label}
      className="inline-flex h-6 shrink-0 items-center gap-1 rounded px-1.5 text-ink-400 transition-colors hover:bg-ink-200 hover:text-ink-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-uv-500 dark:hover:bg-ink-800 dark:hover:text-ink-100"
    >
      {copied ? (
        <>
          <Check
            className="size-3.5 text-uv-600 dark:text-uv-400"
            aria-hidden="true"
          />
          <span
            aria-hidden="true"
            className="font-mono text-[11px] text-uv-700 dark:text-uv-300"
          >
            {copiedLabel}
          </span>
        </>
      ) : (
        <>
          <Copy className="size-3.5" aria-hidden="true" />
          {text && <span className="text-xs">{text}</span>}
        </>
      )}
      <span className="sr-only" aria-live="polite">
        {copied ? copiedLabel : ""}
      </span>
    </button>
  );
}
