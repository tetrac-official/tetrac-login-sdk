// Small Web-standard (Request/Response) helpers shared by the route handlers.

/**
 * A JSON response, never cacheable.
 *
 * `no-store` is not optional here. `GET /user-data` returns the full user record —
 * including every encrypted wallet blob — and a response carrying NO cache directives is
 * heuristically cacheable, so any shared cache keyed on URL alone could serve one user's
 * record to another. Auth is header-based rather than cookie-based, so Next's own route
 * cache does not apply and this is hardening rather than a live bug; it is also one line.
 */
export function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

export function error(message: string, status = 400): Response {
  return json({ error: message }, status);
}

/**
 * Best-effort client IP for rate limiting, or `null` when there isn't a trustworthy one.
 *
 * 🚨 `null`, NOT a `"unknown"` sentinel. The sentinel was a global-lockout vector: a
 * deployment that set `trustProxyHeaders: true` but received a request WITHOUT the proxy
 * headers (direct origin access, a health check, a bypassed CDN, local dev) put every
 * caller into one shared `"unknown"` bucket. At the default 10/60s, one client — or just
 * ordinary traffic — locked out the entire deployment. Returning `null` makes "no usable
 * IP" impossible to mistake for an identity, so callers must decide explicitly.
 *
 * Proxy headers are only honored when the deployment explicitly trusts them
 * (`trustProxyHeaders`); otherwise they are ignored, because a client can set
 * `x-forwarded-for` freely and would otherwise get a fresh bucket per request.
 *
 * When trusted, the client IP is the rightmost x-forwarded-for entry AFTER
 * skipping `trustedProxyHops` hops. Proxies append to XFF on the right, so the
 * rightmost entries are set by infrastructure we control and are not
 * client-spoofable; the leftmost entry is attacker-controlled and never trusted.
 */
export function clientIp(
  req: Request,
  trustProxyHeaders = false,
  trustedProxyHops = 0,
): string | null {
  if (!trustProxyHeaders) return null;
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) {
    const parts = fwd
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    const idx = parts.length - 1 - trustedProxyHops;
    if (idx >= 0 && parts[idx]) return parts[idx]!;
  }
  return req.headers.get("x-real-ip") ?? null;
}

/**
 * Largest request body any route accepts. The biggest legitimate payload is a
 * registration carrying four wallet slots at the 8 KB ciphertext bound — ~33 KB — so
 * 128 KB is generous headroom.
 */
export const MAX_BODY_BYTES = 128 * 1024;

/**
 * Parse a JSON body, bounded.
 *
 * Unbounded `req.json()` buffers and parses whatever arrives BEFORE any validator or rate
 * limiter runs, on routes that are all unauthenticated. `content-length` is a hint an
 * attacker controls, so it is only a cheap early out — the decoded text is measured too.
 */
export async function readJson<T>(req: Request, maxBytes = MAX_BODY_BYTES): Promise<T | null> {
  const declared = Number(req.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) return null;
  try {
    const text = await req.text();
    if (text.length > maxBytes) return null;
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}
