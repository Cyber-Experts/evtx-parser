import { ImageResponse } from "next/og";

export const size = { width: 180, height: 180 };
export const contentType = "image/png";

// Same mark as app/icon.svg, full-bleed (iOS applies its own rounded mask).
const MARK = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <radialGradient id="h" cx="0.3" cy="0.25" r="0.85">
      <stop offset="0" stop-color="#7b4cff" stop-opacity="0.55"/>
      <stop offset="1" stop-color="#7b4cff" stop-opacity="0"/>
    </radialGradient>
    <clipPath id="l"><circle cx="30" cy="30" r="14.5"/></clipPath>
  </defs>
  <rect width="64" height="64" fill="#0b0c16"/>
  <rect width="64" height="64" fill="url(#h)"/>
  <g clip-path="url(#l)">
    <rect x="18.5" y="32" width="4.5" height="14" rx="1.3" fill="#d8dbe7" opacity="0.4"/>
    <rect x="25" y="25" width="4.5" height="21" rx="1.3" fill="#d8dbe7" opacity="0.6"/>
    <rect x="31.5" y="17" width="4.5" height="29" rx="1.3" fill="#bdf01e"/>
    <rect x="38" y="27" width="4.5" height="19" rx="1.3" fill="#d8dbe7" opacity="0.5"/>
  </g>
  <circle cx="30" cy="30" r="16" fill="none" stroke="#9772ff" stroke-width="4"/>
  <line x1="42" y1="42" x2="51" y2="51" stroke="#9772ff" stroke-width="5.5" stroke-linecap="round"/>
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
