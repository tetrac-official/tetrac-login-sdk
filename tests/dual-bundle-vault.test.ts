// dual-bundle-vault.test.ts
//
// Regression guard for the "two memoryAppKey copies" vault-separation bug — now FIXED
// via the globalThis vault singleton (fix 2a; see features/sdk-vault-singleton.md).
//
// THE BUG (historical)
// --------------------
// getAppKey() and the in-memory vault state were shipped in TWO independently-bundled
// copies: one in dist/client/index.js ("@tetrac/login-sdk/client") and one in
// dist/react/index.js ("@tetrac/login-sdk/react", consumed by the hooks). tsup builds
// with `splitting:false` and does NOT externalize the internal session module, so
// src/client/session.ts is INLINED into both bundles. When the vault state was a plain
// module-scope `var memoryAppKey`, each copy owned its own: login (via the React layer)
// armed the react copy, while a consumer calling getAppKey() from "@tetrac/login-sdk/client"
// read a different, never-armed copy and got null forever. That made "Register with DEX"
// throw "Vault is locked" for flows that read getAppKey() from /client.
//
// THE FIX (2a — globalThis singleton)
// -----------------------------------
// The vault's mutable state was moved off module scope onto a process-global keyed by a
// cross-realm Symbol.for("tetrac.vault"). session.ts is STILL inlined into both bundles
// (that's inherent to splitting:false), but every inlined copy now resolves the SAME
// registered symbol and therefore the SAME state object — so arming via /react is visible
// to getAppKey() from /client. The fix is about runtime sharing, not de-duplicating code.
//
// WHY THIS TEST IS STRUCTURAL (reads the built dist), NOT a normal source import
// ------------------------------------------------------------------------------
// Both the bug and its fix are BUILD/runtime-sharing artifacts. Every other SDK test
// imports from ../src/client/session, which resolves to ONE module instance — so at the
// source level the vault always appears shared and neither the defect nor the fix is
// observable. To assert the real, consumer-facing invariant you must inspect the BUILT
// output. This test reads the dist files directly. Run `npm run build` first.
//
// WHAT A FAILURE MEANS
// --------------------
// If "binds the shared globalThis slot" fails, the singleton indirection was removed.
// If "no private per-bundle vault var" fails, someone reverted the state to a module-scope
// `let/var memoryAppKey` — reintroducing the two-independent-copies bug. Either way the
// "Vault is locked from /client" regression is back.

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

// dist lives at the repo root; jest runs with cwd = repo root, so resolve from there.
const DIST = resolve(process.cwd(), "dist");
const clientPath = resolve(DIST, "client/index.js");
const reactPath = resolve(DIST, "react/index.js");
const uiPath = resolve(DIST, "ui/index.js");

// The cross-realm key both bundle copies must share for the singleton to work.
const VAULT_SLOT = 'Symbol.for("tetrac.vault")';

// Count non-overlapping occurrences of a literal substring.
function countOccurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

// Fail fast with a clear message if the build hasn't run — a missing dist would otherwise
// produce a confusing ENOENT mid-assertion.
beforeAll(() => {
  for (const p of [clientPath, reactPath, uiPath]) {
    if (!existsSync(p)) {
      throw new Error(
        `Built dist not found at ${p}. Run \`npm run build\` before this test ` +
          `(it inspects the BUILT output, not src — the invariant is a bundling artifact).`,
      );
    }
  }
});

describe("@tetrac/login-sdk vault singleton across subpath bundles (BUILT dist)", () => {
  // The core of fix 2a: state no longer lives in a per-bundle module-scope var.
  it("declares NO private per-bundle `var memoryAppKey` in /client or /react", () => {
    const clientSrc = readFileSync(clientPath, "utf8");
    const reactSrc = readFileSync(reactPath, "utf8");

    // A module-scope `let memoryAppKey` compiles to `var memoryAppKey` and would mean a
    // private, per-bundle vault state again — the exact root cause of the original bug.
    expect(clientSrc).not.toContain("var memoryAppKey");
    expect(reactSrc).not.toContain("var memoryAppKey");

    // eslint-disable-next-line no-console
    console.log(
      "[INVARIANT] Neither dist/client/index.js nor dist/react/index.js owns a module-scope " +
        "`var memoryAppKey` — the vault state is not a per-bundle private variable.",
    );
  });

  // Both inlined copies must coordinate through the SAME global Symbol-keyed slot, so
  // arming one is visible from the other (login via /react ⇒ getAppKey() from /client).
  it("binds BOTH /client and /react to the same globalThis Symbol.for(\"tetrac.vault\") slot", () => {
    const clientSrc = readFileSync(clientPath, "utf8");
    const reactSrc = readFileSync(reactPath, "utf8");

    expect(clientSrc).toContain(VAULT_SLOT);
    expect(reactSrc).toContain(VAULT_SLOT);

    // eslint-disable-next-line no-console
    console.log(
      "[INVARIANT] Both bundles resolve Symbol.for(\"tetrac.vault\") — one shared vault state, " +
        "so arming via /react's login is visible to getAppKey() imported from /client.",
    );
  });

  // The export-surface asymmetry that made the bug consumer-visible is unchanged and fine
  // now: /client still exposes the raw vault fns, /react only hooks. With the singleton they
  // read ONE state, so the asymmetry is no longer a footgun.
  it("/client still exports the raw vault fns; /react exports only hooks", () => {
    const clientSrc = readFileSync(clientPath, "utf8");
    const reactSrc = readFileSync(reactPath, "utf8");

    expect(clientSrc).toMatch(/export\s*\{[^}]*\bgetAppKey\b/s);
    expect(clientSrc).toMatch(/export\s*\{[^}]*\barmAppKey\b/s);

    const reactExportBlock = reactSrc.slice(reactSrc.lastIndexOf("export {"));
    expect(reactExportBlock).toContain("useSigner");
    expect(reactExportBlock).toContain("AuthProvider");
    expect(reactExportBlock).not.toMatch(/\bgetAppKey\b/);
    expect(reactExportBlock).not.toMatch(/\barmAppKey\b/);
  });

  // CONTRAST: /ui externalizes /react, so it inlines zero vault state and zero slot ref —
  // it reaches the one populated vault only through the external @tetrac/login-sdk/react.
  it("/ui inlines NO vault state (externalizes /react)", () => {
    const uiSrc = readFileSync(uiPath, "utf8");

    expect(countOccurrences(uiSrc, "memoryAppKey")).toBe(0);
    expect(countOccurrences(uiSrc, VAULT_SLOT)).toBe(0);
    expect(uiSrc).toMatch(/from\s+["']@tetrac\/login-sdk\/react["']/);
  });
});
