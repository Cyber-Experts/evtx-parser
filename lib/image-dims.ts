import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { imageSize } from "image-size";

export type Dims = { width: number; height: number };

const cache = new Map<string, Dims | null>();

const DEFAULT: Dims = { width: 1200, height: 630 };

function isAbsoluteHttp(src: string): boolean {
  return /^https?:\/\//i.test(src);
}

async function loadLocal(src: string): Promise<Buffer | null> {
  try {
    const path = join(process.cwd(), "public", src.replace(/^\//, ""));
    return await readFile(path);
  } catch {
    return null;
  }
}

async function loadRemote(src: string): Promise<Buffer | null> {
  try {
    const res = await fetch(src, {
      // Aggressive cache — same URL = same bytes.
      cache: "force-cache",
      headers: { accept: "image/*" },
    });
    if (!res.ok) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    return buf;
  } catch {
    return null;
  }
}

/**
 * Returns image dimensions for any URL. Local paths read from /public, remote
 * URLs fetched once and cached. Falls back to a 1200×630 OG-sized default
 * when nothing else works (and `null` is never returned to callers — CLS-safe).
 */
export async function getImageDims(src: string | undefined): Promise<Dims> {
  if (!src) return DEFAULT;
  if (cache.has(src)) return cache.get(src) ?? DEFAULT;

  const buf = isAbsoluteHttp(src)
    ? await loadRemote(src)
    : await loadLocal(src);

  if (!buf) {
    cache.set(src, null);
    return DEFAULT;
  }

  try {
    const meta = imageSize(buf);
    if (meta.width && meta.height) {
      const dims = { width: meta.width, height: meta.height };
      cache.set(src, dims);
      return dims;
    }
  } catch {
    // fall through
  }
  cache.set(src, null);
  return DEFAULT;
}
