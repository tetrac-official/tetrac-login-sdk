import { MemoryAdapter } from "../src/storage/memory";

describe("MemoryAdapter", () => {
  it("get/set/del round-trips", async () => {
    const s = new MemoryAdapter();
    await s.set("k", "v");
    expect(await s.get("k")).toBe("v");
    await s.del("k");
    expect(await s.get("k")).toBeNull();
  });

  it("incr counts and starts from zero", async () => {
    const s = new MemoryAdapter();
    expect(await s.incr("c")).toBe(1);
    expect(await s.incr("c")).toBe(2);
  });

  it("honors TTL via an injected clock", async () => {
    let now = 1_000_000;
    const s = new MemoryAdapter(() => now);
    await s.set("k", "v", { exSeconds: 5 });
    expect(await s.get("k")).toBe("v");
    now += 6_000; // advance 6s
    expect(await s.get("k")).toBeNull();
  });
});
