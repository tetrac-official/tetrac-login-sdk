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
export function clientIp(req: Request, trustProxyHeaders = false, trustedProxyHops = 0): string | null {
  if (!trustProxyHeaders) return null;
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) {
    const parts = fwd
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    const idx = parts.length - 1 - trustedProxyHops;
    if (idx >= 0 && parts[idx]) return parts[idx]!;
    // The chain is SHORTER than trustedProxyHops + 1 — i.e. this request did not traverse
    // the proxy chain the operator configured. That is precisely when x-real-ip is
    // caller-controlled, so falling back to it would silently undo trustedProxyHops and let
    // the caller name their own bucket. Return null — "no trustworthy IP" — instead (F-6).
    return null;
  }
  // x-forwarded-for absent entirely. Consult x-real-ip ONLY for a single trusted edge
  // (hops 0). With hops > 0 the operator declared a multi-proxy chain; a lone x-real-ip did
  // not traverse it and is not trustworthy either.
  return trustedProxyHops === 0 ? (req.headers.get("x-real-ip") ?? null) : null;
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
 * attacker controls, so it is only a cheap early out — the body is measured for real too.
 */
export async function readJson<T>(req: Request, maxBytes = MAX_BODY_BYTES): Promise<T | null> {
  const declared = Number(req.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) return null;
  const text = await readBounded(req, maxBytes);
  if (text === null) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

/**
 * Read the body as UTF-8 text, enforcing `maxBytes` in BYTES and aborting the moment the
 * cumulative count crosses it. Two fixes over `req.text()` + `text.length` (audit F-9):
 *
 *   • Bytes, not UTF-16 code units. `String.length` counts code units, so a body of 128k
 *     three-byte characters — ~384 KB on the wire — measured as 128k and slipped past a
 *     128 KB cap.
 *   • Bounded DURING the read. A chunked request with no `content-length` used to be
 *     buffered in full before the size check ran; the stream is now dropped as soon as it
 *     exceeds the cap, so nothing larger than `maxBytes` is ever held.
 *
 * Falls back to a buffered read (still measured in bytes) when the body is not an
 * incrementally readable stream — a synthetic request, or a runtime that does not expose
 * `body.getReader`.
 */
async function readBounded(req: Request, maxBytes: number): Promise<string | null> {
  const body = req.body as ReadableStream<Uint8Array> | null;
  if (!body || typeof body.getReader !== "function") {
    try {
      const text = await req.text();
      return new TextEncoder().encode(text).byteLength > maxBytes ? null : text;
    } catch {
      return null;
    }
  }
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8");
  let total = 0;
  let out = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        return null;
      }
      // `stream: true` keeps a multi-byte character split across chunk boundaries intact.
      out += decoder.decode(value, { stream: true });
    }
    out += decoder.decode();
    return out;
  } catch {
    return null;
  }
}
