"use client";

import { useEffect, useState } from "react";

export function ReadingProgress() {
  const [pct, setPct] = useState(0);
  useEffect(() => {
    const onScroll = () => {
      const h = document.documentElement;
      const total = h.scrollHeight - h.clientHeight;
      setPct(total > 0 ? (h.scrollTop / total) * 100 : 0);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  return (
    <div
      aria-hidden
      className="fixed top-0 left-0 z-50 h-0.5 bg-gradient-to-r from-uv-600 via-uv-500 to-uv-400 shadow-[0_0_10px_rgb(123_76_255/0.6)] transition-[width] dark:from-uv-500 dark:to-uv-300"
      style={{ width: `${pct}%` }}
    />
  );
}
