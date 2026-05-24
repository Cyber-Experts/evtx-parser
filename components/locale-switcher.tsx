"use client";

import { usePathname, useRouter } from "next/navigation";
import { Languages } from "lucide-react";
import { buttonVariants } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { LOCALES, localeNames, withLocale, type Locale } from "@/lib/i18n";

export function LocaleSwitcher({ current }: { current: Locale }) {
  const router = useRouter();
  const pathname = usePathname() ?? "/";
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        aria-label="Change language"
        className={buttonVariants({ variant: "ghost", size: "icon" })}
      >
        <Languages className="h-4 w-4" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {LOCALES.map((l) => (
          <DropdownMenuItem
            key={l}
            disabled={l === current}
            onClick={() => router.push(withLocale(pathname, l))}
          >
            {localeNames[l]}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
