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
  info: "border-l-blue-500/60 bg-blue-500/5",
  warn: "border-l-orange-500/60 bg-orange-500/5",
  tip: "border-l-emerald-500/60 bg-emerald-500/5",
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
        "my-6 border-l-4 rounded-r-md px-4 py-3 flex gap-3 items-start",
        STYLES[variant],
      )}
    >
      <Icon className="h-4 w-4 mt-1 shrink-0" aria-hidden />
      <div className="flex-1 [&>*:first-child]:mt-0 [&>*:last-child]:mb-0">
        {title && <p className="font-semibold mb-1">{title}</p>}
        {children}
      </div>
    </aside>
  );
}
