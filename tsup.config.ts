import { defineConfig } from "tsup";

// Peer deps must stay external so consumers supply a single copy.
const external = [
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
];

const shared = {
  format: ["esm", "cjs"] as ("esm" | "cjs")[],
  dts: true,
  splitting: false,
  // Deliberately off: files:["dist"] would otherwise publish .map files (and the
  // original TS) in the npm tarball. Flip to true only if you intend to ship maps.
  sourcemap: false,
  treeshake: true,
  external,
};

// Two passes so only the React-facing entries carry the "use client" banner —
// without it, Next.js App Router consumers importing hooks from a server
// component get opaque RSC errors. Server/core entries must NOT carry it.
export default defineConfig([
  {
    ...shared,
    entry: {
      index: "src/index.ts",
      "core/index": "src/core/index.ts",
      "client/index": "src/client/index.ts",
      "server/index": "src/server/index.ts",
      "storage/index": "src/storage/index.ts",
      "next/index": "src/next/index.ts",
    },
    clean: true,
  },
  {
    ...shared,
    entry: {
      "react/index": "src/react/index.ts",
      "ui/index": "src/ui/index.ts",
    },
    clean: false, // the first pass already cleaned dist
    // tsup's rollup treeshake pass drops `banner` from the output, so it stays
    // off here — consumers still tree-shake these entries via sideEffects:false.
    treeshake: false,
    banner: { js: '"use client";' },
  },
]);
