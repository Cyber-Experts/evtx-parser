// Inline brand mark — an event-frequency histogram with one bar spiking: the
// anomaly the parser surfaces. Bars + wordmark use currentColor (theme-aware);
// the spike is the signature signal-amber (#f59e0b), holding on both light and
// dark backgrounds. The canonical externally-served logo is app/icon.svg.

export function Logo({
  className = "h-6 w-auto",
  withWordmark = true,
}: {
  className?: string;
  withWordmark?: boolean;
}) {
  return (
    <svg
      viewBox={withWordmark ? "0 0 156 32" : "0 0 56 32"}
      className={className}
      role="img"
      aria-label="EVTX parser"
    >
      <g transform="translate(0 4)">
        <rect x="0" y="14" width="6" height="10" rx="1" fill="currentColor" opacity="0.4" />
        <rect x="10" y="6" width="6" height="18" rx="1" fill="currentColor" opacity="0.4" />
        <rect x="20" y="0" width="6" height="24" rx="1" fill="#f59e0b" />
        <rect x="30" y="10" width="6" height="14" rx="1" fill="currentColor" opacity="0.4" />
        <rect x="40" y="16" width="6" height="8" rx="1" fill="currentColor" opacity="0.4" />
      </g>
      {withWordmark && (
        <text
          x="56"
          y="24"
          fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
          fontSize="22"
          fontWeight="700"
          fill="currentColor"
          letterSpacing="-1"
        >
          .evtx
        </text>
      )}
    </svg>
  );
}
