"use client";

import { useRouter } from "next/navigation";
import { Menu } from "lucide-react";

import { buttonVariants } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

/** Primary navigation below md, where the inline nav is hidden. */
export function MobileNav({
  links,
  label,
}: {
  links: { href: string; label: string }[];
  label: string;
}) {
  const router = useRouter();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        aria-label={label}
        className={`${buttonVariants({ variant: "ghost", size: "icon" })} md:hidden`}
      >
        <Menu className="h-4 w-4" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-44">
        {links.map((l) => (
          <DropdownMenuItem key={l.href} onClick={() => router.push(l.href)}>
            {l.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
