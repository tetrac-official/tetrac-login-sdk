---
name: node-sdk
description: Author, package, and publish portable third-party Node.js / TypeScript SDKs (libraries consumed by other apps via npm/yarn/pnpm). Covers the dependency-classification rules (dependencies vs peerDependencies vs devDependencies) that prevent duplicate-package bugs at runtime AND duplicate-type bugs at build time — especially `@types/react` version drift causing errors like `Type 'bigint' is not assignable to type 'ReactNode'` in consumer apps. Also covers `files` allowlists, building against the lowest supported peer version, `exports` maps, and a pre-publish checklist. Use when: authoring or reviewing a publishable npm package's `package.json`; debugging "duplicate React" / "Invalid hook call" / "two copies of X" errors in a consumer app; debugging `ReactNode` / `JSX.Element` / framework-type mismatches between an SDK and the app that consumes it; deciding whether something belongs in `dependencies`, `peerDependencies`, or `devDependencies`; preparing an SDK for `npm publish`; setting up a sibling SDK consumed via `file:` or workspaces and seeing types diverge from the host app. Triggers — "build an SDK", "publish a package", "library package.json", "peer dependency", "duplicate React types", "two @types/react", "bigint not assignable to ReactNode", "@types/react version mismatch", "module not found from SDK dist", "SDK works locally but breaks when published", "consumer app type errors after upgrading React".
---

# Authoring third-party Node.js / TypeScript SDKs

A library is not an app. Apply app rules (pin everything, bundle everything) to a library and you will create duplicate-package bugs in consumer projects — runtime ones (two copies of React → "Invalid hook call") and build-time ones (two copies of `@types/react` → `bigint is not assignable to ReactNode`). This skill captures the rules that prevent both.

## When to invoke

- Writing or reviewing the `package.json` of a publishable library (anything you'd `npm publish`).
- A consumer app reports errors that smell like "two copies of the same thing": `Invalid hook call`, `Hooks can only be called inside a function component`, `Type X is not assignable to type X`, `instanceof` failing for objects from the SDK, two different singletons.
- Setting up a sibling SDK consumed via `"my-sdk": "file:../my-sdk"` or workspaces, and seeing types/runtime diverge from the host.
- Migrating a private internal library toward public publish.

## The mental model

Every package in `node_modules` is independent — npm/yarn/pnpm can install N copies of the same package at different paths. TypeScript and Node both resolve by walking up the tree from the importing file, so two files in the same build can resolve "react" or "@types/react" to two different versions. That is the entire root cause of most "duplicate package" bugs.

A library's job is to **defer to the host** for shared singletons (React, react-dom, the framework, the framework's types) and to **own** its private utilities. The classification system in `package.json` is how you express this.

## Classifying dependencies — the three buckets

| Bucket | Installed in consumer? | Use for |
|---|---|---|
| `dependencies` | Yes, automatically | Private runtime utilities your SDK owns end-to-end (e.g. `@noble/hashes`, `nanoid`, an internal helper lib). Safe to duplicate. **Keep this list as short as you can** — every entry is supply-chain surface you impose on every consumer. |
| `peerDependencies` | No — consumer must install | Shared singletons that **must not** be duplicated: React, react-dom, the framework (Next.js), GraphQL, the framework's types. Anything where two copies = bugs. **Also: heavy, swappable backends** (database drivers) — see below. |
| `devDependencies` | No | Build-time tools: TypeScript, tsup, jest, eslint, `@types/*` you compile against. |

> **A `dependency` is a decision you make on behalf of every consumer.** This repo's own SDK ships
> exactly **one** runtime dependency (`@noble/hashes`); it previously carried `crypto-es` and removed
> it precisely to shrink that surface. When you can implement something against a platform API (Web
> Crypto, `fetch`) instead of taking a dep, do that.

### Optional peers: swappable backends and drivers

The peer rule is usually taught for React. It applies just as well to anything **large, swappable,
and chosen by the consumer** — database drivers being the common case. Declare them as peers, mark
them optional, and load them with a lazy `import()` so a consumer who doesn't use them pays nothing
at install time *or* in bundle size:

This repo's own SDK supports five storage engines and a hardware wallet. **None** of those are
`dependencies` — a consumer on Postgres should not install `ioredis`, `mysql2`, `better-sqlite3`, and
three Ledger transports to use it:

```jsonc
{
  "peerDependencies": {
    "ioredis": "^5.6.0",
    "@upstash/redis": "^1.34.0",
    "@vercel/kv": "^3.0.0",
    "pg": "^8",
    "mysql2": "^3",
    "better-sqlite3": ">=9",
    "@ledgerhq/hw-app-solana": "^7.10.4",
    "next": ">=14",
    "react": ">=18"
  },
  "peerDependenciesMeta": {
    "ioredis": { "optional": true },
    "@upstash/redis": { "optional": true },
    "@vercel/kv": { "optional": true },
    "pg": { "optional": true },
    "mysql2": { "optional": true },
    "better-sqlite3": { "optional": true },
    "@ledgerhq/hw-app-solana": { "optional": true },
    "next": { "optional": true },
    "react": { "optional": true }
  }
}
```

```ts
// Never a top-level import — that would pull the driver into every consumer's bundle.
const { default: Redis } = await import("ioredis");
```

The corollary, and the part that makes this scale: **depend on a structural interface, not on the
driver's types.** Define a minimal `PgLike` / `MysqlLike` / `RedisLike` describing the handful of
methods you actually call, and accept anything that structurally matches:

```ts
// The SDK never imports `pg`'s types. It accepts anything shaped like a pool — which is
// also why one function covers node-postgres, @vercel/postgres, and @neondatabase/serverless.
export interface PgLike {
  query(text: string, values?: readonly unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
  connect?(): Promise<PgClientLike>;   // optional — present only when you need transactions
  end?(): Promise<void>;
}
```

Two payoffs: a consumer on a different driver major cannot break your build, and one implementation
covers every wire-compatible service you never explicitly supported.

### The peerDependencies rule, expanded

A peer dependency means: *"I will use whatever version the host has installed; I don't carry my own copy."* Use it whenever:

1. The package has **shared state** that breaks when duplicated (React's hooks dispatcher, react-dom's roots, Apollo's cache, anything using module-level globals).
2. The package's **types leak across the API boundary**. If your SDK exports a component whose `children: ReactNode` ends up in the consumer's tsc graph, the host's `@types/react` must win — otherwise nominal-type-equality fails.
3. The package is large and version-coupled (Next.js, Vite). Bundling your own copy is bloat and version skew.

Use a wide range and mark optional where applicable:

```jsonc
{
  "peerDependencies": {
    "react": ">=18",
    "react-dom": ">=18",
    "next": ">=14"
  },
  "peerDependenciesMeta": {
    "next": { "optional": true }
  }
}
```

### The devDependencies pitfall: `@types/react`

`@types/react` is **always** a devDependency, **never** a peerDependency (in most cases) and **never** a regular dependency. Why:

- Consumers already have `@types/react` for their own React. They want their version to win.
- TS resolution walks up `node_modules` per-file. The SDK's compiled `.d.ts` files at `node_modules/my-sdk/dist/...` will find the host's `node_modules/@types/react` via the upward walk — **as long as** the SDK doesn't ship its own copy nested below.
- If you list it as a peer, you force consumers to install it even when their app is pure JS. Annoying and pointless.

**Build the SDK against the LOWEST supported `@types/react` version.** v18 types are a subset of v19's. An SDK built against v18 types works in v19 apps. An SDK built against v19 types breaks v18 apps (and emits v19-only type tokens like `bigint` in `ReactNode`, which v18 apps don't have).

```jsonc
{
  "peerDependencies": { "react": ">=18" },
  "devDependencies":  { "@types/react": "^18.3.0" }  // lowest supported
}
```

Same logic applies to `@types/node`, `@types/express`, any framework `@types/*`.

## The `files` allowlist — ship only `dist/`

Every published library should explicitly allowlist what gets packed:

```jsonc
{
  "files": ["dist"]
}
```

Without `files`, npm packs almost everything not in `.gitignore` — including, critically, a developer's local `node_modules` if it slipped in. (Yarn classic's `file:` protocol also copies the source dir verbatim — `node_modules` and all. `files` doesn't help there, but `.npmignore` and a clean source tree do.)

Verify before publish:

```bash
npm pack --dry-run
```

The output should list only `dist/`, `package.json`, `README.md`, `LICENSE`. If you see `src/`, `node_modules/`, `tsconfig.json`, `.env*`, tests, fixtures — fix `files` before publishing.

## `exports` map — define every entry point

Modern SDKs should declare entry points explicitly with `exports`, in the order `types → import → require`:

```jsonc
{
  "type": "module",
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js",
      "require": "./dist/index.cjs"
    },
    "./react": {
      "types": "./dist/react/index.d.ts",
      "import": "./dist/react/index.js",
      "require": "./dist/react/index.cjs"
    }
  },
  "sideEffects": false
}
```

Notes:
- `"types"` must come **first** in each entry, or TS may pick the wrong file (especially under `moduleResolution: "bundler"` / `"node16"`).
- Keep `main` / `module` / `types` at the top level as fallbacks for older tooling.
- `"sideEffects": false` enables tree-shaking in bundlers. Only set this if your SDK truly has no side effects on import.
- **Every subpath needs its own build entry.** An `exports` entry pointing at a `dist/` file your bundler never emits is a 404 that only shows up in a consumer's install, not in your build. Adding the export and adding the entry are one change, not two.

### Ship test kits on their own subpath — never from the main barrel

If your SDK asks third parties to implement an interface (a storage adapter, a plugin, a transport),
ship them an **executable conformance suite** so they can self-certify. But put it on a **dedicated
subpath**, and do **not** re-export it from the package root or from the module it tests:

```jsonc
{
  "exports": {
    "./storage": { "types": "./dist/storage/index.d.ts", "import": "./dist/storage/index.js", "require": "./dist/storage/index.cjs" },
    "./storage/conformance": {
      "types": "./dist/storage/conformance.d.ts",
      "import": "./dist/storage/conformance.js",
      "require": "./dist/storage/conformance.cjs"
    }
  }
}
```

Two reasons, and the first is the one people miss:

1. **A barrel re-export drags the test kit into production bundles.** If `storage/index.ts` re-exports
   the suite, then `import { RedisAdapter } from "pkg/storage"` in a server route pulls the entire
   suite — fixtures, assertion helpers, and all — into the deployed bundle. `sideEffects: false` and
   tree-shaking *usually* save you; "usually" is not a guarantee you want to rely on for dead code
   that ships to production. A separate entry point makes it structurally impossible.
2. **The suite must not depend on a test framework.** Return an array of `{ name, run(): Promise<void> }`
   cases that **throw** on failure, rather than calling `describe`/`it`. Consumers then run it under
   Jest, Vitest, or `node:test` — whatever they already use — without inheriting your runner:

   ```ts
   import { authStoreConformanceCases } from "@scope/my-sdk/storage/conformance";
   for (const c of authStoreConformanceCases(() => new MyStore(client))) {
     it(c.name, () => c.run());
   }
   ```

**And write the cases failing-first.** A conformance suite that cannot fail is decoration: 24 green
checkmarks give exactly as much confidence as 24 empty functions. Keep a **negative control** in your
own test suite — a deliberately-naive implementation with the bugs you're warning about — and assert
the suite *catches* each one. That test is what makes the suite an acceptance bar rather than a
formality.

## Canonical SDK package.json

```jsonc
{
  "name": "@scope/my-sdk",
  "version": "0.1.0",
  "license": "MIT",
  "description": "What this SDK does, in one line.",
  "type": "module",
  "sideEffects": false,

  "files": ["dist"],

  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js",
      "require": "./dist/index.cjs"
    }
  },

  "scripts": {
    "build": "tsup",
    "test": "jest",
    "prepublishOnly": "npm run build"
  },

  "dependencies": {
    "@noble/hashes": "2.2.0"
  },

  "peerDependencies": {
    "react": ">=18",
    "ioredis": "^5.6.0"
  },
  "peerDependenciesMeta": {
    "react": { "optional": true },
    "ioredis": { "optional": true }
  },

  "devDependencies": {
    "@types/react": "^18.3.0",
    "tsup": "^8.3.0",
    "typescript": "^5.8.3"
  },

  "engines": { "node": ">=18" }
}
```

Note especially what's **absent**: `@types/react` is not in dependencies or peerDependencies. React is a peer (optional, in case the SDK has non-React entry points). No bundled framework.

## What NOT to do (common SDK author mistakes)

1. **Putting React or `@types/react` in `dependencies`.** Causes "Invalid hook call" at runtime and duplicate-type errors at build time. *Always* a peer (React) or devDep (types).
2. **Omitting `files`.** Ships your `src/`, tests, fixtures, and sometimes `.env*`. Inflates package size and can leak secrets.
3. **Putting a database driver in `dependencies`.** You've now installed `ioredis` (or `pg`, or `mongodb`) into every consumer, including the ones using a different backend entirely. Optional peer + lazy `import()`.
4. **Re-exporting a test kit from the main barrel.** It follows your production imports into the consumer's server bundle. Give it its own subpath.
5. **Adding an `exports` subpath without a build entry.** The map points at a file that is never emitted; your build stays green and the consumer's install 404s.
6. **Building against the latest `@types/react`.** Forces consumers to upgrade. Build against the lowest supported version.
7. **Pinning peer versions (`"react": "18.2.0"`).** Use ranges: `">=18"`, `"^18 || ^19"`. Pinning forces version churn on consumers.
8. **Forgetting `prepublishOnly: "npm run build"`.** Ship a stale `dist/` and consumers get yesterday's code.
9. **Committing the SDK's `node_modules/`.** Doesn't matter if `files` excludes it for normal publish — but `file:` consumers (yarn classic) will copy it verbatim. Keep the SDK source tree clean before any `file:` install.
10. **Using `"types"` last in `exports` entries.** TS may pick the JS file as types. `"types"` first, always.

## Why duplicate-package bugs happen — three cases

### Case 1: peer declared correctly, consumer installs a different major

Consumer app has React 19; SDK's peer is `">=18"`. Works — one React copy.
Consumer app has React 18; SDK's peer is `">=18"`. Works — one React copy.

### Case 2: SDK declares React as a regular `dependency` (BUG)

Consumer has React 19. SDK depends on `react@^18`. npm installs React 18 nested under `node_modules/my-sdk/node_modules/react/`. Now there are two Reacts. Hooks break.

### Case 3: SDK installed via `file:` from a dev directory

Consumer has `"my-sdk": "file:../my-sdk"`. Yarn classic copies `../my-sdk/` verbatim into `node_modules/my-sdk/`, **including its own `node_modules/`** (devDeps and all). Even if the SDK's `package.json` is perfect, the physical copy ships `@types/react@18` nested below the consumer's `@types/react@19`. TS walks up from the SDK's `.d.ts` files and finds the wrong types.

This is the most surprising case — the SDK looks correct but the install pathway is the problem. Mitigations:
- Use **pnpm** or **yarn berry workspaces** — they symlink instead of copying. The duplicate doesn't appear.
- Or run `rm -rf node_modules` inside the SDK source dir before each consumer install.
- Or add a `prepack` script that cleans before tarball creation. (Doesn't help `file:`; only `npm publish`.)

## Consumer-side mitigations (when you don't own the SDK)

In order of preference:

1. **Switch the consumer to `pnpm`.** Symlinked installs eliminate the entire class of "nested duplicate" bugs.
2. **`overrides` (npm) / `resolutions` (yarn classic).** Forces a single version across the hoisted tree:
   ```jsonc
   { "resolutions": { "@types/react": "19.x" } }
   ```
   Caveat: does **not** rewrite files inside a `file:`-installed package's nested `node_modules` (those are physical copies, not resolved).
3. **`tsconfig.json` `paths`.** Force TS to resolve a shared package from one location:
   ```jsonc
   {
     "compilerOptions": {
       "paths": {
         "react": ["./node_modules/@types/react"],
         "react/*": ["./node_modules/@types/react/*"]
       }
     }
   }
   ```
   Works regardless of install strategy. Build-time only.
4. **Postinstall scrub.** Last resort:
   ```jsonc
   { "scripts": { "postinstall": "rm -rf node_modules/<sdk>/node_modules/@types" } }
   ```
5. **Open an upstream PR.** The proper fix is in the SDK's `package.json`.

## Pre-publish checklist

Run through this before every `npm publish`:

- [ ] `files: ["dist"]` set; `npm pack --dry-run` lists only `dist/`, `package.json`, `README.md`, `LICENSE`.
- [ ] No React/Next/framework in `dependencies`. They're peers, or absent.
- [ ] `dependencies` is as short as it can be — every entry is supply-chain surface imposed on every consumer.
- [ ] Optional backends/drivers are **optional peers** + lazy `import()`, and are typed structurally (`RedisLike`) rather than by importing the driver's own types.
- [ ] `@types/react` (and other framework `@types/*`) only in `devDependencies`, pinned to the **lowest** supported version.
- [ ] `peerDependencies` uses ranges (`">=18"`), not pins.
- [ ] `exports` map present, every entry has `types` listed **first**.
- [ ] **Every `exports` subpath has a matching build entry** — grep the built `dist/` for each path in the map. A missing artifact fails only in the consumer's install.
- [ ] Test kits / conformance suites live on their **own subpath**, are **not** re-exported from the main barrel, and depend on **no** test framework.
- [ ] `prepublishOnly` (or `prepack`) runs the build.
- [ ] `sideEffects: false` if accurate (enables consumer tree-shaking).
- [ ] `engines.node` declared.
- [ ] Build the SDK fresh in a clean clone, then install it into a throwaway consumer app and run that consumer's `tsc --noEmit` and dev server.
- [ ] Repeat the consumer test with both the lowest supported React/framework version and the latest.
- [ ] Verify `dist/` does **not** contain transitive `node_modules` (e.g. from a sloppy bundler config).
- [ ] If you ship CJS + ESM, smoke-test both: `require("@scope/my-sdk")` from a CJS file and `import` from an ESM file.

## Diagnosing a reported "duplicate" error

When a consumer reports one of these, walk the diagnosis in order:

1. **`find node_modules -type d -name <pkg>`** in the consumer. More than one hit → duplicate confirmed; figure out which dep nested its own copy.
2. **Read the offending `.d.ts` or `.js`** at the nested path. Its `package.json` shows which package pulled it in.
3. **Check the SDK's `package.json`** at `node_modules/<sdk>/package.json` (the installed copy, not your source). Is `<pkg>` listed in `dependencies` (bug — should be peer)? Or is `<pkg>` *not* listed but a nested `node_modules/<pkg>` exists anyway (likely a `file:`-install artifact)?
4. **Apply the right fix:** SDK-side reclassification, consumer-side `resolutions`/`paths`/`pnpm`, or scrub-on-install — depending on which case from "three cases" above this matches.
