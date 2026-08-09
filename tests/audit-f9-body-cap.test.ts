// Audit 2026-08-08 F-9 — the request body cap must count BYTES and bound DURING the read.
//
// `req.text()` + `text.length` measured UTF-16 code units, so a body of N multi-byte
// characters passed a byte cap it was well over on the wire; and the measurement ran only
// after the whole (possibly chunked, content-length-less) stream had been buffered.
import { readJson, MAX_BODY_BYTES } from "../src/server/http";

function jsonReq(body: string, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
}

describe("F-9 — the cap is measured in bytes, not UTF-16 code units", () => {
  it("🚨 a multibyte body over the byte cap is rejected even though its .length is under it", async () => {
    // '€' is 3 bytes in UTF-8 but ONE UTF-16 code unit. Build a JSON string whose
    // char-length is comfortably under the cap but whose byte-length is over it.
    const chars = 60_000; // well under MAX_BODY_BYTES as a count…
    const payload = JSON.stringify({ x: "€".repeat(chars) });
    expect(payload.length).toBeLessThan(MAX_BODY_BYTES); // …passed the old UTF-16 check…
    expect(new TextEncoder().encode(payload).byteLength).toBeGreaterThan(MAX_BODY_BYTES); // …but is oversized

    expect(await readJson(jsonReq(payload))).toBeNull();
  });

  it("an honest body of the same character count is still accepted", async () => {
    const payload = JSON.stringify({ x: "a".repeat(60_000) }); // 1 byte/char, under the cap
    const parsed = await readJson<{ x: string }>(jsonReq(payload));
    expect(parsed?.x.length).toBe(60_000);
  });
});

describe("F-9 — a content-length-free body is still bounded", () => {
  it("🚨 rejects an oversized body even with no content-length header", async () => {
    const payload = JSON.stringify({ x: "a".repeat(MAX_BODY_BYTES + 1_000) });
    // Force the absence of the hint so only the real measurement can catch it.
    const req = jsonReq(payload);
    req.headers.delete("content-length");
    expect(await readJson(req)).toBeNull();
  });

  it("a valid multibyte body under the cap round-trips with characters intact", async () => {
    // Guards the streaming decoder against corrupting a multi-byte character that lands on
    // a chunk boundary.
    const payload = JSON.stringify({ msg: "héllo wörld 你好 😀".repeat(100) });
    const parsed = await readJson<{ msg: string }>(jsonReq(payload));
    expect(parsed?.msg).toBe(JSON.parse(payload).msg);
  });
});
