import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  return [{ url: "https://focusboard.example/" }, { url: "https://focusboard.example/privacy" }, { url: "https://focusboard.example/terms" }];
}
