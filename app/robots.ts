import type { MetadataRoute } from "next";
import { getRobots } from "@next-md-blog/core/next";
import { site } from "@/next-md-blog.config";

export default function robots(): MetadataRoute.Robots {
  return getRobots(site);
}
