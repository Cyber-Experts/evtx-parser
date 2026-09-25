// Inline brand mark — an event histogram seen through an investigator's lens.
// The lens is ultraviolet (--brand), the peak bar glows fluorescent lime: the
// trace the light reveals. Bars and wordmark use currentColor so the mark is
// theme-aware. The canonical externally-served mark is app/icon.svg.

export function Logo({
  className = "h-6 w-auto",
  withWordmark = true,
}: {
  className?: string;
  withWordmark?: boolean;
}) {
  return (
    <svg
      viewBox={withWordmark ? "0 0 148 32" : "0 0 32 32"}
      className={className}
      role="img"
      aria-label="EVTX parser"
    >
      <defs>
        <clipPath id="evtx-lens">
          <circle cx="13.5" cy="13.5" r="9.5" />
        </clipPath>
      </defs>
      {/* bars inside the lens */}
      <g clipPath="url(#evtx-lens)">
        <rect x="6" y="15" width="3" height="10" rx="1" fill="currentColor" opacity="0.35" />
        <rect x="10.5" y="10" width="3" height="15" rx="1" fill="currentColor" opacity="0.55" />
        <rect x="15" y="6" width="3" height="19" rx="1" className="fill-glow-500 dark:fill-glow-400" />
        <rect x="19.5" y="12" width="3" height="13" rx="1" fill="currentColor" opacity="0.45" />
      </g>
      {/* lens + handle */}
      <circle cx="13.5" cy="13.5" r="10.5" fill="none" stroke="var(--brand)" strokeWidth="2.6" />
      <line
        x1="21.3"
        y1="21.3"
        x2="28.5"
        y2="28.5"
        stroke="var(--brand)"
        strokeWidth="3.4"
        strokeLinecap="round"
      />
      {withWordmark && (
        <text
          x="38"
          y="22"
          style={{ fontFamily: "var(--font-plex-mono), ui-monospace, monospace" }}
          fontSize="19"
          letterSpacing="-0.6"
        >
          <tspan fill="currentColor" fontWeight="600">
            evtx
          </tspan>
          <tspan fill="var(--brand)" fontWeight="400">
            parser
          </tspan>
        </text>
      )}
    </svg>
  );
}
