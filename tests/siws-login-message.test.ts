// The wallet login message is Sign In With Solana (SIWS) text (src/core/index.ts).
// Phantom parses any signMessage payload that looks like SIWS and refuses to display one
// that fails its field checks, so the message must parse with the reference parser and
// rebuild byte-for-byte through the reference builder. Line 1 carries the bare authority
// and the URI line keeps the scheme; both come from one parseOrigin() URL. The builder
// throws rather than emit a field outside the grammar.
import { PublicKey } from "@solana/web3.js";
import { createSignInMessageText, parseSignInMessageText } from "@solana/wallet-standard-util";
import {
  WALLET_LOGIN_STATEMENT,
  generateChallenge,
  offchainMessageCandidates,
  parseOrigin,
  walletLoginMessage,
} from "../src/core/index";

const ADDRESS = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"; // 44 base58 characters
const CHALLENGE = "d49a44e9".repeat(8);
const ORIGIN = "https://x.example";

/** Origins parseOrigin rejects — and therefore origins the builder refuses to build for. */
const INVALID_ORIGINS = ["myapp.example", "https://x.example/app", "capacitor://localhost", "null"];

const encode = (s: string) => new TextEncoder().encode(s);
const build = (input: Partial<{ challenge: string; origin: string; address: string }>) => () =>
  walletLoginMessage({ challenge: CHALLENGE, origin: ORIGIN, address: ADDRESS, ...input });

describe("walletLoginMessage — golden string", () => {
  it("emits the exact SIWS text for a fixed input", () => {
    const m = walletLoginMessage({
      challenge: CHALLENGE,
      origin: "https://www.tetrac.xyz",
      address: ADDRESS,
    });
    expect(m).toBe(
      "www.tetrac.xyz wants you to sign in with your Solana account:\n" +
        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\n" +
        "\n" +
        "Sign in to prove you own this wallet. This request does not send a transaction or cost any fees.\n" +
        "\n" +
        "URI: https://www.tetrac.xyz\n" +
        "Version: 1\n" +
        "Nonce: d49a44e9d49a44e9d49a44e9d49a44e9d49a44e9d49a44e9d49a44e9d49a44e9",
    );
    expect(encode(m).length).toBe(316);
  });
});

describe("walletLoginMessage — reference SIWS parser round-trip", () => {
  it.each([
    ["http://localhost:3000", "localhost:3000", "http://localhost:3000"],
    ["https://www.tetrac.xyz", "www.tetrac.xyz", "https://www.tetrac.xyz"],
    ["HTTPS://WWW.Tetrac.xyz:443/", "www.tetrac.xyz", "https://www.tetrac.xyz"],
    ["http://[::1]:3000", "[::1]:3000", "http://[::1]:3000"],
  ])("%s parses into every field and rebuilds byte-for-byte", (origin, domain, uri) => {
    const m = walletLoginMessage({ challenge: CHALLENGE, origin, address: ADDRESS });
    const parsed = parseSignInMessageText(m);
    expect(parsed).not.toBeNull();
    expect(parsed).toMatchObject({
      domain,
      address: ADDRESS,
      statement: WALLET_LOGIN_STATEMENT,
      uri,
      version: "1",
      nonce: CHALLENGE,
    });
    // The reference parser is a loose regex — it also accepts a scheme on line 1 — so
    // check the field grammar directly.
    expect(parsed!.domain).not.toContain("://");
    expect(parsed!.domain).toBe(new URL(parsed!.uri!).host);
    expect(parsed!.uri).not.toBe("null");
    expect(createSignInMessageText(parsed!)).toBe(m);
  });
});

describe("walletLoginMessage — line 1 is the bare authority, the URI line keeps the scheme", () => {
  it.each([
    ["http://localhost:3000", "localhost:3000", "http://localhost:3000"],
    ["https://x.example:443/", "x.example", "https://x.example"],
    ["http://x.example:80", "x.example", "http://x.example"],
    ["https://x.example:8443", "x.example:8443", "https://x.example:8443"],
    [" HTTPS://X.Example// ", "x.example", "https://x.example"],
    ["https://bücher.example", "xn--bcher-kva.example", "https://xn--bcher-kva.example"],
  ])("%j → %s", (origin, host, uri) => {
    const lines = walletLoginMessage({ challenge: CHALLENGE, origin, address: ADDRESS }).split("\n");
    expect(lines[0]).toBe(`${host} wants you to sign in with your Solana account:`);
    expect(lines[5]).toBe(`URI: ${uri}`);
  });
});

describe("walletLoginMessage — ASCII only (invariant 5)", () => {
  it.each([
    "https://www.tetrac.xyz",
    "http://localhost:3000",
    "https://x.example:8443",
    "http://[::1]:3000",
    "https://bücher.example",
  ])("every byte for %s is 0x20–0x7e or 0x0a", (origin) => {
    const bytes = encode(walletLoginMessage({ challenge: CHALLENGE, origin, address: ADDRESS }));
    expect([...bytes].filter((b) => b !== 0x0a && (b < 0x20 || b > 0x7e))).toEqual([]);
  });

  it("the statement is RFC 3986 reserved/unreserved characters plus space, with no line break", () => {
    expect(WALLET_LOGIN_STATEMENT).toMatch(/^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;= ]+$/);
    expect(WALLET_LOGIN_STATEMENT).not.toContain("\n");
  });
});

describe("walletLoginMessage — fits a Ledger off-chain message", () => {
  it("a 253-character host with a port and a 44-character address stays within 1212 bytes, RestrictedAscii", () => {
    const host = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)].join(".");
    expect(host).toHaveLength(253);
    const m = walletLoginMessage({ challenge: CHALLENGE, origin: `https://${host}:65535`, address: ADDRESS });
    expect(m.startsWith(`${host}:65535 wants you to sign in`)).toBe(true);
    const bytes = encode(m);
    expect(bytes.length).toBeLessThanOrEqual(1212);
    const [legacy, v0] = offchainMessageCandidates(bytes, new PublicKey(ADDRESS).toBytes());
    // Format byte 0 = RestrictedAscii: legacy header offset 17, v0 after the 32-byte application domain.
    expect(legacy![17]).toBe(0);
    expect(v0![49]).toBe(0);
  });
});

describe("generateChallenge — a valid SIWS nonce", () => {
  it("matches the nonce grammar and is accepted by the builder", () => {
    const challenge = generateChallenge();
    expect(challenge).toMatch(/^[A-Za-z0-9]{8,}$/);
    expect(walletLoginMessage({ challenge, origin: ORIGIN, address: ADDRESS })).toMatch(
      new RegExp(`\\nNonce: ${challenge}$`),
    );
  });
});

describe("walletLoginMessage — throws rather than emit a field outside the SIWS grammar", () => {
  it.each([
    ["undefined", undefined],
    ["empty", ""],
    ['the string "undefined"', "undefined"],
    ["31 base58 characters", ADDRESS.slice(0, 31)],
    ["45 base58 characters", ADDRESS + "1"],
    ['44 characters with a "0"', "0" + ADDRESS.slice(1)],
    ['44 characters with an "O"', "O" + ADDRESS.slice(1)],
    ['44 characters with an "I"', "I" + ADDRESS.slice(1)],
    ['44 characters with an "l"', "l" + ADDRESS.slice(1)],
  ])("rejects an address that is %s", (_label, address) => {
    expect(build({ address: address as string })).toThrow(/^\[tetrac\] .*address/);
  });

  it.each([
    ["7 characters", "abcdefg"],
    ["base64url", "ab-cd_efgh"],
    ["empty", ""],
  ])("rejects a challenge that is %s", (_label, challenge) => {
    expect(build({ challenge })).toThrow(/^\[tetrac\] .*challenge/);
  });

  // The quantifier edges. "1" × 32 is the base58 encoding of the all-zero 32-byte key, and
  // real keys with leading zero bytes encode to fewer than 43 characters.
  it.each([
    ["32", "1".repeat(32)],
    ["44", ADDRESS],
  ])("accepts a %s-character address", (_n, address) => {
    expect(build({ address })).not.toThrow();
  });

  it("accepts an 8-character challenge", () => {
    expect(build({ challenge: "abcdefgh" })).not.toThrow();
  });

  it.each(INVALID_ORIGINS)("rejects the origin %j", (origin) => {
    expect(build({ origin })).toThrow(/^\[tetrac\] Invalid origin/);
  });
});

describe("parseOrigin — a bare http(s) origin or throw", () => {
  it.each([
    ["https://myapp.example", "https://myapp.example"],
    ["https://myapp.example/", "https://myapp.example"],
    ["http://localhost:3000", "http://localhost:3000"],
    ["HTTPS://MyApp.Example:443/", "https://myapp.example"],
  ])("accepts %j", (origin, expected) => {
    const url = parseOrigin(origin);
    expect(url).toBeInstanceOf(URL);
    expect(url.origin).toBe(expected);
  });

  it.each([
    ...INVALID_ORIGINS,
    "https://myapp.example?",
    "https://myapp.example#",
    "https://u:p@myapp.example",
    "chrome-extension://abc",
    "ws://x.example",
    "file:///tmp/x",
  ])("rejects %j", (origin) => {
    expect(() => parseOrigin(origin)).toThrow(/^\[tetrac\] Invalid origin/);
  });
});
