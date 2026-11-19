import type { NextConfig } from "next";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.dirname(fileURLToPath(import.meta.url));

const nextConfig: NextConfig = {
  turbopack: {
    root: projectRoot,
  },
  experimental: {
    turbopackPluginRuntimeStrategy: "workerThreads",
  },
  outputFileTracingRoot: projectRoot,
  allowedDevOrigins: [
    "localhost:3000",
    "127.0.0.1:3000",
    "localhost:3001",
    "127.0.0.1:3001",
    "localhost",
    "127.0.0.1",
  ],
};

export default nextConfig;
