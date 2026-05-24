import Link from "next/link";
import { DEFAULT_LOCALE } from "@/lib/i18n";

export default function NotFound() {
  return (
    <html lang={DEFAULT_LOCALE}>
      <body className="min-h-screen flex items-center justify-center">
        <main className="text-center space-y-3">
          <p className="text-sm text-muted-foreground">404</p>
          <h1 className="text-3xl font-semibold">Page not found</h1>
          <Link href={`/${DEFAULT_LOCALE}`} className="underline">
            Go home
          </Link>
        </main>
      </body>
    </html>
  );
}
