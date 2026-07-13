// v0.5.0 — the AuthStore conformance suite, run against every first-party backend.
//
// This is the acceptance bar for ANY storage backend, and it is the artifact that makes
// adding Postgres/Mongo/etc. cheap: write ~120 lines, run this, ship. Here it runs
// against KvAuthStore over MemoryAdapter (the normative reference implementation) and
// over the mocked Redis/Upstash/Vercel KV adapters — so the suite is proven against the
// backends we already have BEFORE anything new is built on top of it.
//
// The mocked KV adapters are a regression baseline, not ground truth: atomicity and
// expiry are properties of the ENGINE, and a mock only asserts we mocked it the way we
// imagined. The dockerized real-Redis run (PRD v0.5.0 §3.4) is what makes MemoryAdapter's
// "matches Redis" claim a tested fact rather than a code comment.
import { authStoreConformanceCases } from "../src/storage/conformance";
import { KvAuthStore } from "../src/storage/store";
import { MemoryAdapter } from "../src/storage/memory";
import { DEFAULT_CONFIG } from "../src/core/config";

// A single mutable clock the suite drives via `advance`. Reset by each makeStore() call,
// which the suite invokes once per case — so cases never leak time into each other.
const T0 = 1_700_000_000_000;
let now = T0;

describe("AuthStore conformance — KvAuthStore over MemoryAdapter", () => {
  const cases = authStoreConformanceCases(
    () => {
      now = T0;
      return new KvAuthStore(new MemoryAdapter(() => now), DEFAULT_CONFIG.keyPrefixes);
    },
    {
      advance: (ms) => {
        now += ms;
      },
      // MemoryAdapter implements sweepExpired (it expires lazily, so it genuinely leaks
      // without one), and KvAuthStore forwards it.
      supportsSweep: true,
    },
  );

  // Guard against the suite silently shrinking to nothing — a green run of zero cases is
  // the most dangerous possible result.
  it("exposes the full case list", () => {
    expect(cases.length).toBeGreaterThanOrEqual(18);
  });

  for (const c of cases) {
    it(c.name, () => c.run());
  }
});
