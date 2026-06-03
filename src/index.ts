// Root entry — re-exports the framework-agnostic core. For tree-shaking and to
// avoid pulling server/browser-only code into the wrong environment, prefer the
// subpath imports: @tetrac/login-sdk/{core,client,server,storage,react,next}.
export * from "./core/index.js";
