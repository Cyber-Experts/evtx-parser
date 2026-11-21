import { ImageResponse } from "next/og";

export const size = { width: 180, height: 180 };
export const contentType = "image/png";

// Same mark as app/icon.svg, full-bleed (iOS applies its own rounded mask).
const MARK = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="lit" x1="0" x2="1" y1="0" y2="0">
      <stop offset="0" stop-color="#3a6bff"/>
      <stop offset="1" stop-color="#22d6f0"/>
    </linearGradient>
    <radialGradient id="haze" cx="0.75" cy="0.55" r="0.6">
      <stop offset="0" stop-color="#3a6bff" stop-opacity="0.35"/>
      <stop offset="1" stop-color="#3a6bff" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="64" height="64" fill="#0b0c0f"/>
  <rect width="64" height="64" fill="url(#haze)"/>
  <rect x="15" y="17" width="20" height="5.5" rx="2.75" fill="#ededf0" opacity="0.4"/>
  <rect x="15" y="25.5" width="27" height="5.5" rx="2.75" fill="#ededf0" opacity="0.6"/>
  <rect x="15" y="34" width="33" height="5.5" rx="2.75" fill="url(#lit)"/>
  <rect x="15" y="42.5" width="14" height="5.5" rx="2.75" fill="#ededf0" opacity="0.4"/>
</svg>`;

export default function AppleIcon() {
  const src = `data:image/svg+xml;base64,${Buffer.from(MARK).toString("base64")}`;
  return new ImageResponse(
    (
      <img src={src} width={180} height={180} alt="" />
    ),
    size,
  );
}
