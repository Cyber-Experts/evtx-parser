import { ImageResponse } from "next/og";

export const size = { width: 180, height: 180 };
export const contentType = "image/png";

const BARS = [
  { h: 34, brand: false },
  { h: 58, brand: false },
  { h: 86, brand: true },
  { h: 48, brand: false },
  { h: 30, brand: false },
];

export default function AppleIcon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 18,
          background: "linear-gradient(150deg, #0a0d14 0%, #121826 100%)",
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        }}
      >
        <div style={{ display: "flex", alignItems: "flex-end", gap: 9, height: 86 }}>
          {BARS.map((b, i) => (
            <div
              key={i}
              style={{
                width: 15,
                height: b.h,
                borderRadius: 3,
                background: b.brand ? "#f59e0b" : "rgba(231,233,238,0.5)",
              }}
            />
          ))}
        </div>
        <div
          style={{
            fontSize: 30,
            fontWeight: 700,
            letterSpacing: "-0.04em",
            color: "#e7e9ee",
          }}
        >
          .evtx
        </div>
      </div>
    ),
    size,
  );
}
