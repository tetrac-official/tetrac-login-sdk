import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "core/index": "src/core/index.ts",
    "client/index": "src/client/index.ts",
    "server/index": "src/server/index.ts",
    "storage/index": "src/storage/index.ts",
    "react/index": "src/react/index.ts",
    "next/index": "src/next/index.ts",
    "ui/index": "src/ui/index.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  // Peer deps must stay external so consumers supply a single copy.
  external: [
    "@solana/web3.js",
    "viem",
    "tweetnacl",
    "react",
    "react/jsx-runtime",
    "next",
    "ioredis",
    "@vercel/kv",
    "@upstash/redis",
  ],
});
