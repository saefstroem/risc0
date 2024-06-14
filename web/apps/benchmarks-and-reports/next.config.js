import withBundleAnalyzer from "@next/bundle-analyzer";
import { nextConfigBase } from "@risc0/ui/config/next.config.base.js";
import deepmerge from "deepmerge";
import createJiti from "jiti";
import { latestVersion } from "./src/versions.js";

const jiti = createJiti(new URL(import.meta.url).pathname);

// Import env here to validate during build. Using jiti we can import .ts files :)
jiti("./src/env");

/** @type {import("next").NextConfig} */
let config = deepmerge(nextConfigBase, {
  experimental: {
    ppr: false, // DO NOT USE PPR, breaks everything, don't bother with it
    staleTimes: {
      dynamic: 30,
      static: 180,
    },
  },

  // biome-ignore lint/suspicious/useAwait: needs to be async
  async redirects() {
    return [
      {
        source: "/",
        destination: latestVersion ? `/${latestVersion}` : "/",
        permanent: true,
      },
    ];
  },
});

if (process.env.ANALYZE === "true") {
  config = withBundleAnalyzer({
    enabled: true,
  })(config);
}

export default config;
