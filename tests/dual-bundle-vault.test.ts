// dual-bundle-vault.test.ts
//
// Regression test for the "two memoryAppKey copies" vault-separation bug.
//
// THEORY UNDER TEST
// -----------------
// getAppKey() and the in-memory vault state (`var memoryAppKey`) are shipped in TWO
// independently-bundled copies: one in dist/client/index.js (the "@tetrac/login-sdk/client"
// subpath) and one in dist/react/index.js (the "@tetrac/login-sdk/react" subpath consumed by
// the hooks). Because tsup builds with `splitting:false` and does NOT externalize the internal
// session module, src/client/session.ts is INLINED into both bundles. Arming the vault on one
// copy (what login/reauthenticate do, via the React layer) is therefore invisible to a consumer
// that calls getAppKey() from "@tetrac/login-sdk/client" — it reads a different, never-armed copy
// and gets null forever. This is what made "Register with DEX" throw "Vault is locked" for the
// flows that read getAppKey() from /client, while the ones using the /react hooks worked.
//
// WHY THIS TEST IS STRUCTURAL (reads the built dist), NOT a normal source import
// ------------------------------------------------------------------------------
// The duplication is a BUILD artifact. Every other SDK test imports from ../src/client/session,
// which resolves to ONE module instance — so at the source level the vault appears shared and the
// bug is invisible. To observe the real consumer-facing defect you must inspect the BUILT output.
// This test reads the dist files and asserts the duplication directly, so it cannot false-pass the
// way a source-level test would. Run `npm run build` first (the dist must exist).
//
// CONTRAST / FIX TEMPLATE
// -----------------------
// dist/ui/index.js does NOT inline the vault: tsup.config.ts marks "@tetrac/login-sdk/react"
// external for the /ui pass, so /ui imports the one populated AuthContext/vault from /react
// instead of duplicating it. The fix for THIS bug is the same move applied to the /react pass:
// externalize (or code-split into a shared chunk) the client session module so /client and /react
// share ONE memoryAppKey.
//
// EXPECTED LIFECYCLE
// ------------------
// While the bug exists, this whole suite PASSES (it documents/proves the duplication). Once the
// SDK is fixed so /react no longer inlines its own vault, the "react bundle inlines a SECOND copy"
// assertion will start FAILING — that is the intended signal to flip this file to assert the
// single-shared-copy invariant (see the commented `DESIRED INVARIANT` block at the bottom).

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

// dist lives at the repo root; jest runs with cwd = repo root, so resolve from there.
const DIST = resolve(process.cwd(), "dist");
const clientPath = resolve(DIST, "client/index.js");
const reactPath = resolve(DIST, "react/index.js");
const uiPath = resolve(DIST, "ui/index.js");

// Count non-overlapping occurrences of a literal substring (how many times the inlined
// `var memoryAppKey` / function bodies appear in a bundle).
function countOccurrences(haystack: string, needle: string): number {
  // split-length-1 is the simplest correct count of non-overlapping literal matches.
  return haystack.split(needle).length - 1;
}

// Fail fast with a clear message if the build hasn't run — a missing dist would otherwise
// produce a confusing ENOENT mid-assertion.
beforeAll(() => {
  for (const p of [clientPath, reactPath, uiPath]) {
    if (!existsSync(p)) {
      throw new Error(
        `Built dist not found at ${p}. Run \`npm run build\` before this test ` +
          `(it inspects the BUILT output, not src — the bug is a bundling artifact).`,
      );
    }
  }
});

describe("@tetrac/login-sdk dual-bundle vault separation (BUILT dist)", () => {
  // The whole point: the vault module-state is duplicated across two subpath bundles.
  it("inlines a SEPARATE `var memoryAppKey` into BOTH /client and /react bundles", () => {
    const clientSrc = readFileSync(clientPath, "utf8");
    const reactSrc = readFileSync(reactPath, "utf8");

    // Each bundle declares its OWN module-scope vault variable. Two declarations across two
    // files == two independent runtime states (the root of the bug).
    expect(clientSrc).toContain("var memoryAppKey");
    expect(reactSrc).toContain("var memoryAppKey");

    // Each bundle also carries its OWN arm/read implementation (not a re-export of the other),
    // so arming one never touches the other.
    expect(clientSrc).toMatch(/function armAppKey\b/);
    expect(clientSrc).toMatch(/function getAppKey\b/);
    expect(reactSrc).toMatch(/function armAppKey\b/);
    expect(reactSrc).toMatch(/function getAppKey\b/);

    // eslint-disable-next-line no-console
    console.log(
      "[PROOF] Both dist/client/index.js and dist/react/index.js declare their own " +
        "`var memoryAppKey` + armAppKey/getAppKey — two independent vault states.",
    );
  });

  // The /react bundle does NOT import the session/vault from the /client bundle or a shared
  // chunk; it inlines a full private copy. This is the precise root cause.
  it("/react bundle inlines its own session module instead of importing /client's", () => {
    const reactSrc = readFileSync(reactPath, "utf8");

    // No relative import of the client bundle, no shared-chunk import of a session module.
    expect(reactSrc).not.toMatch(/from\s+["']\.\.\/client/);
    expect(reactSrc).not.toMatch(/require\(\s*["']\.\.\/client/);
    // (Sanity: the only "session" mention is the inlined source header comment, not an import.)

    // The session module is physically present (inlined) in the react bundle — its header
    // comment from src/client/session.ts rides along with the duplicated code.
    expect(reactSrc).toContain("src/client/session.ts");

    // eslint-disable-next-line no-console
    console.log(
      "[PROOF] dist/react/index.js inlines src/client/session.ts (no import of /client's vault) " +
        "— so login arms the react copy while getAppKey() from /client reads a never-armed copy.",
    );
  });

  // The export-surface asymmetry that forces consumers onto the never-armed /client copy:
  // /client exports the raw vault fns; /react exports only hooks.
  it("/client exports the raw vault fns; /react exports none (only hooks)", () => {
    const clientSrc = readFileSync(clientPath, "utf8");
    const reactSrc = readFileSync(reactPath, "utf8");

    // /client publicly exports armAppKey + getAppKey (consumers import these and hit the
    // client copy).
    expect(clientSrc).toMatch(/export\s*\{[^}]*\bgetAppKey\b/s);
    expect(clientSrc).toMatch(/export\s*\{[^}]*\barmAppKey\b/s);

    // /react's export block exposes hooks/provider but NOT the vault fns, so the react copy is
    // reachable only through useSigner/useAuth — never as getAppKey().
    const reactExportBlock = reactSrc.slice(reactSrc.lastIndexOf("export {"));
    expect(reactExportBlock).toContain("useSigner");
    expect(reactExportBlock).toContain("AuthProvider");
    expect(reactExportBlock).not.toMatch(/\bgetAppKey\b/);
    expect(reactExportBlock).not.toMatch(/\barmAppKey\b/);
  });

  // CONTRAST: /ui already does it right — it externalizes /react and so does NOT inline the
  // vault. This is the template for fixing /react -> /client.
  it("/ui does NOT inline the vault (externalizes /react) — the fix template", () => {
    const uiSrc = readFileSync(uiPath, "utf8");

    // Zero vault state in /ui: it imports useAuth from the EXTERNAL bare specifier instead of
    // re-bundling the AuthContext/vault.
    expect(countOccurrences(uiSrc, "memoryAppKey")).toBe(0);
    expect(uiSrc).toMatch(/from\s+["']@tetrac\/login-sdk\/react["']/);

    // eslint-disable-next-line no-console
    console.log(
      "[FIX TEMPLATE] dist/ui/index.js has 0 memoryAppKey and imports @tetrac/login-sdk/react " +
        "as an external — apply the same externalization to the /react build for /client's session.",
    );
  });
});

// DESIRED INVARIANT (enable AFTER the SDK is fixed; delete the assertions above that prove the bug):
//
// it("/react shares ONE vault with /client (no duplicate copy)", () => {
//   const reactSrc = readFileSync(reactPath, "utf8");
//   // After the fix, the session module is shared (externalized or a single chunk), so the react
//   // bundle no longer declares its own vault state.
//   expect(reactSrc).not.toContain("var memoryAppKey");
//   // ...and it imports the shared session/vault instead of inlining it.
//   expect(reactSrc).toMatch(/from\s+["']@tetrac\/login-sdk\/client["']|\/(chunk|session)-[\w-]+\.js/);
// });
