/** @type {import('jest').Config} */
export default {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  // Polyfills TextEncoder/TextDecoder + WebCrypto.subtle for the jsdom env (guarded,
  // no-op under node). Required by the React-hook suite (jsdom) which transitively
  // imports @solana/web3.js → @noble at module load.
  setupFiles: ["<rootDir>/tests/jest.setup.ts"],
  extensionsToTreatAsEsm: [".ts", ".tsx"],
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  transform: {
    // Transform our TS and the ESM JS in select node_modules (see transformIgnorePatterns).
    "^.+\\.[cm]?[jt]sx?$": [
      "ts-jest",
      {
        useESM: true,
        diagnostics: false,
        tsconfig: {
          module: "ESNext",
          moduleResolution: "Bundler",
          allowJs: true,
          verbatimModuleSyntax: false,
          jsx: "react-jsx", // enable JSX in .tsx test files (React hook tests)
        },
      },
    ],
  },
  // By default node_modules is not transformed; allow the ESM-only deps pulled in
  // by @solana/web3.js so they can be transpiled to something Jest can run.
  transformIgnorePatterns: [
    "/node_modules/(?!(@solana|rpc-websockets|uuid|jayson|superstruct|borsh|@noble|@solana-program)/)",
  ],
  testMatch: ["**/tests/**/*.test.ts?(x)"],
};
