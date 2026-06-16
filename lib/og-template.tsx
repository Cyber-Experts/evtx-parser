import { ImageResponse } from "next/og";

import { getDict } from "@/src/dict";
import type { Locale } from "@/src/dict/locales";

export const ogSize = { width: 1200, height: 630 };
export const ogContentType = "image/png";

// The brand histogram, recreated with flex bars so it renders in Satori.
const BARS = [
  { h: 46, brand: false },
  { h: 78, brand: false },
  { h: 116, brand: true },
  { h: 64, brand: false },
  { h: 40, brand: false },
];

function Histogram() {
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 8, height: 116 }}>
      {BARS.map((b, i) => (
        <div
          key={i}
          style={{
            width: 16,
            height: b.h,
            borderRadius: 3,
            background: b.brand ? "#f59e0b" : "rgba(231,233,238,0.45)",
          }}
        />
      ))}
    </div>
  );
}

export async function renderOg(locale: Locale) {
  const dict = getDict(locale);
  return new ImageResponse(
    (
      <div
        style={{
          position: "relative",
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "#0a0d14",
          backgroundImage:
            "radial-gradient(900px 500px at 12% -10%, rgba(245,158,11,0.16), transparent 60%), radial-gradient(700px 700px at 110% 120%, rgba(56,189,248,0.10), transparent 55%)",
          padding: "68px 72px",
          color: "#ffffff",
          fontFamily: "ui-sans-serif, system-ui, sans-serif",
        }}
      >
        {/* scanline overlay — the forensic console texture */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            backgroundImage:
              "repeating-linear-gradient(0deg, rgba(255,255,255,0.04) 0px, rgba(255,255,255,0.04) 1px, transparent 1px, transparent 4px)",
          }}
        />

        {/* top bar: mark + wordmark + domain */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 20,
            fontSize: 26,
            color: "#9aa4b2",
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 14,
              padding: "10px 18px",
              border: "1px solid rgba(255,255,255,0.12)",
              borderRadius: 12,
              background: "rgba(255,255,255,0.03)",
              color: "#e7e9ee",
            }}
          >
            <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 26 }}>
              <div style={{ width: 5, height: 12, borderRadius: 1, background: "rgba(231,233,238,0.5)" }} />
              <div style={{ width: 5, height: 20, borderRadius: 1, background: "rgba(231,233,238,0.5)" }} />
              <div style={{ width: 5, height: 26, borderRadius: 1, background: "#f59e0b" }} />
              <div style={{ width: 5, height: 16, borderRadius: 1, background: "rgba(231,233,238,0.5)" }} />
            </div>
            <span style={{ fontWeight: 700, letterSpacing: "-0.03em" }}>.evtx</span>
          </div>
          <div>www.evtxparser.com</div>
        </div>

        {/* headline cluster */}
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 26,
            maxWidth: 1000,
          }}
        >
          <Histogram />
          <div
            style={{
              fontSize: 82,
              fontWeight: 800,
              lineHeight: 1.04,
              letterSpacing: "-0.03em",
              color: "#fafafa",
            }}
          >
            {dict.meta.siteName}
          </div>
          <div style={{ fontSize: 31, lineHeight: 1.35, color: "#9aa4b2", maxWidth: 880 }}>
            {dict.meta.description}
          </div>
        </div>

        {/* footer: feature tags + locale */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            fontSize: 22,
            color: "#7c8696",
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
          }}
        >
          <div style={{ display: "flex", gap: 30, alignItems: "center" }}>
            <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ display: "flex", width: 8, height: 8, borderRadius: 8, background: "#f59e0b" }} />
              Windows Event Log
            </span>
            <span>WebAssembly</span>
            <span>100% client-side</span>
          </div>
          <div style={{ color: "#9aa4b2" }}>{locale.toUpperCase()}</div>
        </div>
      </div>
    ),
    ogSize,
  );
}
