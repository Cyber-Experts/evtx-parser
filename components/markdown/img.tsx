import Image from "next/image";
import type { ComponentProps } from "react";
import { getImageDims } from "@/lib/image-dims";

type Props = Omit<ComponentProps<"img">, "src"> & {
  src?: string;
  width?: number | `${number}`;
  height?: number | `${number}`;
};

/**
 * RSC: resolves real image dimensions at render time (cached) so the layout is
 * stable and CLS = 0 — no more 1200×630 placeholders that get the aspect ratio
 * wrong.
 */
export async function MdImage({
  src,
  alt,
  title,
  width,
  height,
  ...rest
}: Props) {
  if (!src) return null;
  const explicit =
    width && height ? { width: Number(width), height: Number(height) } : null;
  const dims = explicit ?? (await getImageDims(src));
  const isExternal = /^https?:\/\//.test(src);
  const img = (
    <Image
      src={src}
      alt={alt ?? ""}
      width={dims.width}
      height={dims.height}
      sizes="(min-width: 1024px) 768px, 100vw"
      unoptimized={isExternal ? false : undefined}
      className="my-6 h-auto w-full rounded-xl border border-ink-200 shadow-[0_12px_32px_-18px_rgb(11_12_22/0.25)] dark:border-ink-800"
      {...rest}
    />
  );
  if (title) {
    return (
      <figure className="my-6">
        {img}
        <figcaption className="mt-2 text-center text-sm text-ink-500 dark:text-ink-400">
          {title}
        </figcaption>
      </figure>
    );
  }
  return img;
}
