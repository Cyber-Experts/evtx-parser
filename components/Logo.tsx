// "Flare" brand mark: a flat event baseline with one sharp spike, the record
// that lights up in a quiet log, on a signal-orange tile. The wordmark pairs
// Inter caps with an Instrument Serif italic, the site's two voices.
// The canonical externally-served mark is app/icon.svg.

export const MARK_PATH = "M5.5 20.5H11.6L14.4 9.5L17.6 23L19.6 16.8L20.9 20.5H26.5";

export function Logo({
  className = "h-6 w-auto",
  withWordmark = true,
}: {
  className?: string;
  withWordmark?: boolean;
}) {
  return (
    <svg
      viewBox={withWordmark ? "0 0 142 32" : "0 0 32 32"}
      className={className}
      role="img"
      aria-label="EVTX parser"
    >
      <rect width="32" height="32" rx="8" fill="#ff5a1a" />
      <path
        d={MARK_PATH}
        fill="none"
        stroke="#0a0a0a"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {withWordmark && (
        <text x="41" y="22.5" fill="currentColor">
          <tspan
            style={{ fontFamily: "var(--font-inter), system-ui, sans-serif" }}
            fontSize="17"
            fontWeight="700"
            letterSpacing="-0.4"
          >
            EVTX
          </tspan>
          <tspan
            dx="5"
            style={{
              fontFamily: "var(--font-instrument), Georgia, serif",
              fontStyle: "italic",
            }}
            fontSize="22"
            letterSpacing="-0.2"
          >
            parser
          </tspan>
        </text>
      )}
    </svg>
  );
}
