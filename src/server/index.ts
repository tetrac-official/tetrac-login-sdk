// Server-only entry. Import from your API routes / backend, never the browser.
export { createAuthHandlers, type AuthHandlers, type AuthHandlerOptions } from "./routes.js";
export { verifySession, getUserByPublicKey, resolvePublicKeyByEmail, issueSession, revokeSession, persistUser } from "./session.js";
export { issueChallenge, consumeChallenge } from "./challenge.js";
export { verifySolanaSignature } from "./signature.js";
export { checkRateLimit, type RateLimitResult } from "./rateLimit.js";
export { json, error, clientIp, readJson } from "./http.js";
