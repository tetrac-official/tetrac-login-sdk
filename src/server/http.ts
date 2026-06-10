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
 */
export function clientIp(req: Request, trustProxyHeaders = false): string {
  if (!trustProxyHeaders) return "unknown";
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0]!.trim();
  return req.headers.get("x-real-ip") ?? "unknown";
}

export async function readJson<T>(req: Request): Promise<T | null> {
  try {
    return (await req.json()) as T;
  } catch {
    return null;
  }
}
