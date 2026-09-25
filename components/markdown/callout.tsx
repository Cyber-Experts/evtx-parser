import { cn } from "@/lib/utils";
import { Info, AlertTriangle, Lightbulb } from "lucide-react";
import type { ReactNode } from "react";

type Variant = "info" | "warn" | "tip";

const ICONS: Record<Variant, typeof Info> = {
  info: Info,
  warn: AlertTriangle,
  tip: Lightbulb,
};

const STYLES: Record<Variant, string> = {
  info: "border-l-uv-500 bg-uv-50/60 dark:bg-uv-500/10",
  warn: "border-l-orange-500 bg-orange-50/70 dark:bg-orange-500/10",
  tip: "border-l-glow-500 bg-glow-50/70 dark:border-l-glow-400 dark:bg-glow-400/10",
};

const ICON_STYLES: Record<Variant, string> = {
  info: "text-uv-600 dark:text-uv-300",
  warn: "text-orange-600 dark:text-orange-400",
  tip: "text-glow-700 dark:text-glow-400",
};

export function Callout({
  variant = "info",
  title,
  children,
}: {
  variant?: Variant;
  title?: string;
  children: ReactNode;
}) {
  const Icon = ICONS[variant];
  return (
    <aside
      role="note"
      className={cn(
        "my-6 flex items-start gap-3 rounded-xl border border-l-4 border-ink-200 px-4 py-3 dark:border-ink-800",
        STYLES[variant],
      )}
    >
      <Icon
        className={cn("mt-1 h-4 w-4 shrink-0", ICON_STYLES[variant])}
        aria-hidden
      />
      <div className="flex-1 [&>*:first-child]:mt-0 [&>*:last-child]:mb-0">
        {title && (
          <p className="mb-1 font-semibold text-ink-900 dark:text-ink-100">
            {title}
          </p>
        )}
        {children}
      </div>
    </aside>
  );
}
