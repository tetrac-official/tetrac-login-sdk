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
    // The /ui entry imports useAuth from the /react subpath. Marking it
    // external prevents tsup from re-inlining `useAuth` + `AuthContext` into
    // dist/ui/index.js, which would otherwise produce two AuthContext
    // instances at runtime (only the one in dist/react/* is populated by
    // <AuthProvider>).
    "@tetrac/login-sdk/react",
  ],
});
