import { ImageResponse } from "next/og";

export const size = { width: 64, height: 64 };
export const contentType = "image/png";

export default function Icon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#0a0a0a",
          color: "#fafafa",
          fontSize: 26,
          fontWeight: 700,
          letterSpacing: "-0.05em",
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
          borderRadius: 8,
        }}
      >
        .evtx
      </div>
    ),
    size,
  );
}
