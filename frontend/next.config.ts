import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { parseEnv } from "node:util";

import type { NextConfig } from "next";

const PUBLIC_PREFIX = "NEXT_PUBLIC_";

// Local development keeps one `.env` at the repository root, shared with the
// backend. Only NEXT_PUBLIC_* keys are forwarded, so backend secrets in that
// file never enter the frontend build. Real environment variables win.
function publicEnvFromRepoRoot(): Record<string, string> {
  const envFile = path.join(__dirname, "..", ".env");
  if (!existsSync(envFile)) return {};

  const parsed = parseEnv(readFileSync(envFile, "utf8"));
  const publicEntries = Object.entries(parsed).filter(
    (entry): entry is [string, string] =>
      entry[0].startsWith(PUBLIC_PREFIX) &&
      Boolean(entry[1]) &&
      process.env[entry[0]] === undefined,
  );
  return Object.fromEntries(publicEntries);
}

const nextConfig: NextConfig = {
  env: publicEnvFromRepoRoot(),
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
