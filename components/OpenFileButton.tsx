"use client";

import type { ReactNode } from "react";

// Opens the uploader's own file picker (its #dropzone label) so every entry
// point shares one file-input code path. Falls back to scrolling to the tool.
export function OpenFileButton({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <button
      type="button"
      className={className}
      onClick={() => {
        const zone = document.getElementById("dropzone");
        if (zone) zone.click();
        else document.getElementById("tool")?.scrollIntoView({ behavior: "smooth" });
      }}
    >
      {children}
    </button>
  );
}
