import { ImageResponse } from "next/og";

import { getDict } from "@/src/dict";
import type { Locale } from "@/src/dict/locales";

export const ogSize = { width: 1200, height: 630 };
export const ogContentType = "image/png";

export async function renderOg(locale: Locale) {
  const dict = getDict(locale);
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "linear-gradient(135deg, #0a0a0a 0%, #18181b 100%)",
          padding: "72px",
          color: "#ffffff",
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "16px",
            fontSize: "28px",
            color: "#a1a1aa",
          }}
        >
          <div
            style={{
              padding: "8px 16px",
              border: "1px solid #3f3f46",
              borderRadius: "8px",
              color: "#e4e4e7",
            }}
          >
            .evtx
          </div>
          <div>www.evtxparser.com</div>
        </div>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "24px",
            maxWidth: "1000px",
          }}
        >
          <div
            style={{
              fontSize: "84px",
              fontWeight: 700,
              lineHeight: 1.05,
              letterSpacing: "-0.02em",
              color: "#fafafa",
            }}
          >
            {dict.meta.siteName}
          </div>
          <div
            style={{
              fontSize: "32px",
              lineHeight: 1.35,
              color: "#a1a1aa",
              fontFamily: "ui-sans-serif, system-ui, sans-serif",
            }}
          >
            {dict.meta.description}
          </div>
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            fontSize: "22px",
            color: "#71717a",
          }}
        >
          <div style={{ display: "flex", gap: "32px" }}>
            <span>Windows Event Log</span>
            <span>WebAssembly</span>
            <span>100% client-side</span>
          </div>
          <div style={{ color: "#a1a1aa" }}>{locale.toUpperCase()}</div>
        </div>
      </div>
    ),
    ogSize,
  );
}
