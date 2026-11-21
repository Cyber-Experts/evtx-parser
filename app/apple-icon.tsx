import { ImageResponse } from "next/og";

export const size = { width: 180, height: 180 };
export const contentType = "image/png";

// Same mark as app/icon.svg, full-bleed (iOS applies its own rounded mask).
const MARK = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" fill="#ff5a1a"/>
  <path d="M12 40.5H23.8L28.9 20L34.8 45L38.4 33.8L40.8 40.5H52" fill="none" stroke="#0a0a0a" stroke-width="4.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

export default function AppleIcon() {
  const src = `data:image/svg+xml;base64,${Buffer.from(MARK).toString("base64")}`;
  return new ImageResponse(
    <img src={src} width={180} height={180} alt="" />,
    size,
  );
}
