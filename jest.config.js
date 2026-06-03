/** @type {import('jest').Config} */
export default {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
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
        },
      },
    ],
  },
  // By default node_modules is not transformed; allow the ESM-only deps pulled in
  // by @solana/web3.js so they can be transpiled to something Jest can run.
  transformIgnorePatterns: [
    "/node_modules/(?!(@solana|rpc-websockets|uuid|jayson|superstruct|borsh|@noble|@solana-program|crypto-es)/)",
  ],
  testMatch: ["**/tests/**/*.test.ts"],
};
