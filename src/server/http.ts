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

export async function readJson<T>(req: Request): Promise<T | null> {
  try {
    return (await req.json()) as T;
  } catch {
    return null;
  }
}
