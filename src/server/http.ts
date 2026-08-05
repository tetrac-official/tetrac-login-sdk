// Small Web-standard (Request/Response) helpers shared by the route handlers.

export function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export function error(message: string, status = 400): Response {
  return json({ error: message }, status);
}

/**
 * Best-effort client IP for rate limiting. Proxy headers are only honored when
 * the deployment explicitly trusts them (trustProxyHeaders); otherwise they are
 * ignored so a client can't spoof x-forwarded-for to dodge per-IP limits. When
 * untrusted we fall back to a stable "unknown" bucket.
 *
 * When trusted, the client IP is the rightmost x-forwarded-for entry AFTER
 * skipping `trustedProxyHops` hops. Proxies append to XFF on the right, so the
 * rightmost entries are set by infrastructure we control and are not
 * client-spoofable; the leftmost entry is attacker-controlled and never trusted.
 */
export function clientIp(req: Request, trustProxyHeaders = false, trustedProxyHops = 0): string {
  if (!trustProxyHeaders) return "unknown";
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) {
    const parts = fwd
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    const idx = parts.length - 1 - trustedProxyHops;
    if (idx >= 0 && parts[idx]) return parts[idx]!;
  }
  return req.headers.get("x-real-ip") ?? "unknown";
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
