import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return { name: "FocusBoard", short_name: "FocusBoard", start_url: "/", display: "standalone", icons: [{ src: "/icon.svg", sizes: "any", type: "image/svg+xml" }] };
}
