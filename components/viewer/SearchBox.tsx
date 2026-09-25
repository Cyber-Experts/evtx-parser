"use client";

import { useMemo, useState, type RefObject } from "react";

import type { Dict } from "@/src/dict/types";
import { lastToken, quoteValue, replaceLastToken } from "@/lib/search-query";

type Suggestion = { label: string; hint?: string; insert: string };

const FIELD_TOKEN = /^(-?)([A-Za-z_][\w.-]*)$/;
const VALUE_TOKEN = /^(-?)([A-Za-z_][\w.-]*):"?([^"]*)$/;

export function SearchBox({
  value,
  onChange,
  inputRef,
  dict,
  regexMode,
  invalid,
  fieldNames,
  valuesFor,
}: {
  value: string;
  onChange: (v: string) => void;
  inputRef: RefObject<HTMLInputElement | null>;
  dict: Dict;
  regexMode: boolean;
  invalid: boolean;
  /** Every searchable field name, in display casing. */
  fieldNames: string[];
  /** Distinct values of a field (lower-cased name), most frequent first. */
  valuesFor: (field: string) => [string, number][];
}) {
  const [focused, setFocused] = useState(false);
  const [active, setActive] = useState(0);
  const [dismissed, setDismissed] = useState<string | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const v = dict.viewer;

  const token = lastToken(value);
  const suggestions = useMemo<Suggestion[]>(() => {
    if (regexMode || !token) return [];
    const val = VALUE_TOKEN.exec(token);
    if (val) {
      const [, neg, field, partial] = val;
      const p = partial.replace(/\*/g, "").toLowerCase();
      return valuesFor(field.toLowerCase())
        .filter(([x]) => x.toLowerCase().includes(p) && x !== partial)
        .slice(0, 8)
        .map(([x, n]) => ({
          label: x,
          hint: String(n),
          insert: `${neg}${field}:${quoteValue(x)} `,
        }));
    }
    const f = FIELD_TOKEN.exec(token);
    if (f) {
      const [, neg, partial] = f;
      const p = partial.toLowerCase();
      return fieldNames
        .filter((n) => n.toLowerCase().startsWith(p))
        .slice(0, 8)
        .map((n) => ({ label: `${n}:`, insert: `${neg}${n}:` }));
    }
    return [];
  }, [token, regexMode, fieldNames, valuesFor]);

  const open =
    focused && suggestions.length > 0 && dismissed !== token;
  const activeIdx = Math.min(active, suggestions.length - 1);

  const accept = (s: Suggestion) => {
    onChange(replaceLastToken(value, s.insert));
    setActive(0);
    inputRef.current?.focus();
  };

  return (
    <div className="relative w-full min-w-0 flex-1 basis-full sm:basis-64">
      <div className="flex items-center gap-1">
        <input
          ref={inputRef}
          type="search"
          role="combobox"
          aria-expanded={open}
          aria-autocomplete="list"
          aria-controls="search-suggestions"
          placeholder={dict.home.filterPlaceholder}
          value={value}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => {
            onChange(e.target.value);
            setActive(0);
            setDismissed(null);
          }}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          onKeyDown={(e) => {
            if (!open) return;
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setActive((activeIdx + 1) % suggestions.length);
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setActive(
                (activeIdx - 1 + suggestions.length) % suggestions.length,
              );
            } else if (e.key === "Enter" || e.key === "Tab") {
              e.preventDefault();
              accept(suggestions[activeIdx]);
            } else if (e.key === "Escape") {
              e.preventDefault();
              setDismissed(token);
            }
          }}
          className={`w-full min-w-0 rounded-md border bg-transparent px-3 py-1.5 font-mono text-xs outline-none ${
            invalid
              ? "border-red-400 focus:border-red-500"
              : "border-ink-300 focus:border-uv-500 dark:border-ink-700 dark:focus:border-uv-400"
          }`}
        />
        <button
          type="button"
          onClick={() => setShowHelp((s) => !s)}
          aria-expanded={showHelp}
          aria-label={v.syntaxHelp}
          title={v.syntaxHelp}
          className="shrink-0 rounded-md border border-ink-200 px-2 py-1 font-mono text-xs text-ink-500 hover:border-uv-400 dark:border-ink-800"
        >
          ?
        </button>
      </div>

      {open && (
        <ul
          id="search-suggestions"
          role="listbox"
          aria-label={v.suggestions}
          className="absolute left-0 right-0 top-full z-30 mt-1 max-h-72 overflow-auto rounded-md border border-ink-200 bg-white py-1 font-mono text-xs shadow-lg dark:border-ink-800 dark:bg-ink-900"
        >
          {suggestions.map((s, i) => (
            <li
              key={s.insert}
              role="option"
              aria-selected={i === activeIdx}
              // mousedown (not click) so the input doesn't blur first.
              onMouseDown={(e) => {
                e.preventDefault();
                accept(s);
              }}
              onMouseEnter={() => setActive(i)}
              className={`flex cursor-pointer items-center justify-between gap-3 px-3 py-1 ${
                i === activeIdx
                  ? "bg-uv-500/15 text-uv-800 dark:text-uv-200"
                  : "text-ink-700 dark:text-ink-300"
              }`}
            >
              <span className="truncate">{s.label}</span>
              {s.hint && (
                <span className="shrink-0 tabular-nums text-ink-400">
                  {s.hint}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}

      {showHelp && (
        <div className="absolute left-0 top-full z-30 mt-1 w-full max-w-md rounded-md border border-ink-200 bg-white p-3 text-xs shadow-lg dark:border-ink-800 dark:bg-ink-900">
          <div className="mb-2 font-semibold text-ink-900 dark:text-ink-100">
            {v.syntaxHelp}
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5">
            {(
              [
                ["mimikatz  \"net user\"", v.helpFree],
                ["TargetUserName:j.doe", v.helpField],
                ["Image:*\\powershell.exe", v.helpWildcard],
                ["-IpAddress:127.0.0.1", v.helpNot],
                ["4624 OR 4625", v.helpOr],
                ["EventID:>=4720", v.helpCompare],
                ["logonid:0x3e7", v.helpPivot],
                ["parent:*\\winword.exe", v.helpProcess],
              ] as const
            ).map(([code, desc]) => (
              <div key={code} className="contents">
                <dt>
                  <code className="whitespace-pre rounded bg-ink-100 px-1 font-mono text-[11px] text-ink-800 dark:bg-ink-800 dark:text-ink-200">
                    {code}
                  </code>
                </dt>
                <dd className="text-ink-600 dark:text-ink-400">{desc}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}
