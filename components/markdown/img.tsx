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
      className="rounded-md w-full h-auto my-6"
      {...rest}
    />
  );
  if (title) {
    return (
      <figure className="my-6">
        {img}
        <figcaption className="text-sm text-muted-foreground text-center mt-2">
          {title}
        </figcaption>
      </figure>
    );
  }
  return img;
}
