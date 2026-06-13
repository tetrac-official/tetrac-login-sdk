# Bug in vault client:react 

see script 

``` bash
##/Users/mac/Documents/TTC/tetrac-login-sdk/tests/dual-bundle-vault.test.ts
npx jest tests/dual-bundle-vault.test.ts 
```

## SDK vault singleton (upstream fix)
Make the vault state a single instance shared by every subpath bundle, so getAppKey() works identically from /client, /react, /core, etc.

Implementation choices inside the SDK (maintainer picks one):

(2a) globalThis singleton — store memoryAppKey (+ lock deadline) on a non-enumerable globalThis[Symbol.for("tetrac.vault")]. Smallest diff; robust across separate bundle copies; survives the splitting:false design. Recommended.
(2b) Shared chunk — tsup splitting: true + a dedicated session entry so all subpaths import one chunk. Cleaner conceptually; larger build/packaging change; risk of subpath graph churn.
(2c) Re-export via package subpath — change src/react/* to import from "@tetrac/login-sdk/client" instead of "../client/session.js", letting the bundler dedupe to the published client chunk. Fragile; depends on consumer bundler resolution.