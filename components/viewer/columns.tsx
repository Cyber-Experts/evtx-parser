"use client";

import { useCallback, useEffect, useMemo, useState, type PointerEvent } from "react";

import type { Dict } from "@/src/dict/types";

export const EVENTS_TABLE_ID = "evtx-events";
const STORAGE_KEY = "evtx-columns";
const MIN_WIDTH = 48;
const MAX_FIT_WIDTH = 900;

type Layout = { widths: Record<string, number>; pinned: string[] };

function readLayout(): Layout {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<Layout>;
      return { widths: parsed.widths ?? {}, pinned: parsed.pinned ?? [] };
    }
  } catch {
    // storage blocked or corrupt: start from auto widths
  }
  return { widths: {}, pinned: [] };
}

const esc = (s: string) =>
  typeof CSS !== "undefined" && CSS.escape ? CSS.escape(s) : s.replace(/["\\]/g, "\\$&");

/**
 * Per-column widths and pins for the events table. Cells and headers carry
 * `data-col`; the layout is applied through one generated stylesheet so no
 * cell component needs width props. Remembered per viewer (localStorage).
 */
export function useColumnLayout(order: string[]) {
  const [layout, setLayout] = useState<Layout>(readLayout);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(layout));
    } catch {
      // not persisted; still applies for this page view
    }
  }, [layout]);

  const measure = (col: string) => {
    const th = document.querySelector<HTMLElement>(
      `#${EVENTS_TABLE_ID} th[data-col="${esc(col)}"]`,
    );
    return th ? Math.round(th.getBoundingClientRect().width) : 160;
  };

  const startResize = useCallback((col: string, e: PointerEvent<HTMLElement>) => {
    e.preventDefault();
    e.stopPropagation();
    const th = e.currentTarget.closest("th");
    const startWidth = th ? th.getBoundingClientRect().width : 160;
    const x0 = e.clientX;
    let frame = 0;
    const move = (ev: globalThis.PointerEvent) => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const w = Math.max(MIN_WIDTH, Math.round(startWidth + ev.clientX - x0));
        setLayout((l) => ({ ...l, widths: { ...l.widths, [col]: w } }));
      });
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      document.body.style.cursor = "";
    };
    document.body.style.cursor = "col-resize";
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }, []);

  /**
   * Double-click on the handle: fit the column to its widest value among the
   * rendered rows (Excel-style), so long values are shown untruncated.
   */
  const autoSize = useCallback((col: string) => {
    const cells = document.querySelectorAll<HTMLElement>(
      `#${EVENTS_TABLE_ID} [data-col="${esc(col)}"]`,
    );
    let widest = MIN_WIDTH;
    cells.forEach((cell) => {
      const style = getComputedStyle(cell);
      const pad = parseFloat(style.paddingLeft) + parseFloat(style.paddingRight);
      // Truncated children still report their full width in scrollWidth.
      let content = 0;
      for (const child of Array.from(cell.children) as HTMLElement[]) {
        content += child.scrollWidth;
      }
      widest = Math.max(widest, (content || cell.scrollWidth) + pad + 2);
    });
    const width = Math.min(MAX_FIT_WIDTH, Math.ceil(widest));
    setLayout((l) => ({ ...l, widths: { ...l.widths, [col]: width } }));
  }, []);

  const togglePin = useCallback((col: string) => {
    setLayout((l) => {
      if (l.pinned.includes(col)) {
        return { ...l, pinned: l.pinned.filter((c) => c !== col) };
      }
      const width = l.widths[col] ?? measure(col);
      return { widths: { ...l.widths, [col]: width }, pinned: [...l.pinned, col] };
    });
  }, []);

  const reset = useCallback(() => setLayout({ widths: {}, pinned: [] }), []);

  const css = useMemo(() => {
    const t = `#${EVENTS_TABLE_ID}`;
    const rules: string[] = [
      `${t}{--pin-bg:#fff;--pin-head:#fafafa}`,
      `.dark ${t}{--pin-bg:#09090b;--pin-head:#18181b}`,
    ];
    for (const [col, w] of Object.entries(layout.widths)) {
      if (!order.includes(col)) continue;
      const sel = `${t} [data-col="${esc(col)}"]`;
      rules.push(`${sel}{width:${w}px;min-width:${w}px;max-width:${w}px;overflow:hidden}`);
      rules.push(`${sel}>*{max-width:100%!important}`);
    }
    // Pinned columns stick in visual order, each after the previous ones.
    let left = 0;
    const pinnedVisible = order.filter((c) => layout.pinned.includes(c));
    pinnedVisible.forEach((col, i) => {
      const last = i === pinnedVisible.length - 1;
      const shadow = last ? "box-shadow:1px 0 0 rgb(161 161 170/.5);" : "";
      rules.push(`${t} td[data-col="${esc(col)}"]{position:sticky;left:${left}px;z-index:2;background-color:var(--pin-bg);${shadow}}`);
      rules.push(`${t} th[data-col="${esc(col)}"]{position:sticky;left:${left}px;z-index:3;background-color:var(--pin-head);${shadow}}`);
      left += layout.widths[col] ?? 0;
    });
    return rules.join("\n");
  }, [layout, order]);

  return {
    css,
    pinned: layout.pinned,
    customized: layout.pinned.length > 0 || Object.keys(layout.widths).length > 0,
    startResize,
    autoSize,
    togglePin,
    reset,
  };
}

/** Pin button + drag handle rendered inside a `th` (which must be `relative`). */
export function ColumnTools({
  col,
  pinned,
  dict,
  onPin,
  onResizeStart,
  onAutoSize,
}: {
  col: string;
  pinned: boolean;
  dict: Dict;
  onPin: (col: string) => void;
  onResizeStart: (col: string, e: PointerEvent<HTMLElement>) => void;
  onAutoSize: (col: string) => void;
}) {
  const v = dict.viewer;
  return (
    <>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          onPin(col);
        }}
        aria-pressed={pinned}
        aria-label={pinned ? v.unpinColumn : v.pinColumn}
        title={pinned ? v.unpinColumn : v.pinColumn}
        className={`ml-1 rounded px-0.5 text-[10px] leading-none transition-opacity ${
          pinned
            ? "opacity-100"
            : "opacity-0 group-hover/th:opacity-60 hover:!opacity-100 focus:opacity-100"
        }`}
      >
        📌
      </button>
      <span
        role="separator"
        aria-orientation="vertical"
        aria-label={v.resizeColumn}
        title={v.resizeColumn}
        onPointerDown={(e) => onResizeStart(col, e)}
        onDoubleClick={() => onAutoSize(col)}
        className="absolute inset-y-0 right-0 w-1.5 cursor-col-resize touch-none select-none hover:bg-amber-400/60"
      />
    </>
  );
}
