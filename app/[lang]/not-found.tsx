import Link from "next/link";
import { DEFAULT_LOCALE } from "@/lib/i18n";

export default function NotFound() {
  return (
    <main id="main-content" className="container mx-auto px-4 py-24 text-center space-y-4">
      <p className="text-sm text-muted-foreground">404</p>
      <h1 className="text-3xl font-semibold">Page not found</h1>
      <Link href={`/${DEFAULT_LOCALE}`} className="underline">
        Go home
      </Link>
    </main>
  );
}
