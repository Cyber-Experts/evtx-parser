import { useId } from "react";

// Brand mark: a tile of log lines where one line lights up (cobalt → luminol
// cyan), the event you were looking for. The tile takes currentColor and the
// lines take the page background, so the mark inverts with the theme: black
// tile on light pages, white tile on dark ones. The canonical
// externally-served mark is app/icon.svg (always the dark tile).

export function Logo({
  className = "h-6 w-auto",
  withWordmark = true,
}: {
  className?: string;
  withWordmark?: boolean;
}) {
  const id = useId();
  const lit = `${id}-lit`;
  return (
    <svg
      viewBox={withWordmark ? "0 0 132 32" : "0 0 32 32"}
      className={className}
      role="img"
      aria-label="EVTX parser"
    >
      <defs>
        <linearGradient id={lit} x1="0" x2="1" y1="0" y2="0">
          <stop offset="0" stopColor="#3a6bff" />
          <stop offset="1" stopColor="#22d6f0" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="8" fill="currentColor" />
      <g fill="var(--background)">
        <rect x="7" y="8" width="11" height="3" rx="1.5" opacity="0.45" />
        <rect x="7" y="12.5" width="15" height="3" rx="1.5" opacity="0.65" />
        <rect x="7" y="21.5" width="8" height="3" rx="1.5" opacity="0.45" />
      </g>
      <rect x="7" y="17" width="18" height="3" rx="1.5" fill={`url(#${lit})`} />
      {withWordmark && (
        <text
          x="41"
          y="21.5"
          style={{ fontFamily: "var(--font-geist-sans), ui-sans-serif, sans-serif" }}
          fontSize="17.5"
          letterSpacing="-0.5"
        >
          <tspan fill="currentColor" fontWeight="600">
            evtx
          </tspan>
          <tspan fill="currentColor" fontWeight="400" opacity="0.55">
            {" "}parser
          </tspan>
        </text>
      )}
    </svg>
  );
}
