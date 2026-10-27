import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";

const CONTRACTS_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
);

function scan(code: string) {
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function scanContract(name: string) {
  return scan(fs.readFileSync(path.join(CONTRACTS_ROOT, name), "utf-8"));
}

describe("contracts/TtlStorageTiers.rs (unmanaged TTLs)", () => {
  const findings = scanContract("TtlStorageTiers.rs");

  it("flags storage that is never extended with AP-STORAGE-001", () => {
    const storage = findings.filter((f) => f.id === "AP-STORAGE-001");

    expect(storage).toHaveLength(1);
    expect(storage[0]?.severity).toBe("high");
    expect(storage[0]?.remediation).toContain("extend_ttl");
  });

  it("flags the unwrap on a possibly expired persistent read", () => {
    const unwraps = findings.filter((f) => f.id === "AP-ERROR-001");

    expect(unwraps.some((f) => f.location.function === "balance")).toBe(true);
  });

  it("does not count a commented-out extend_ttl as TTL management", () => {
    // `touch` only mentions extend_ttl inside a comment.
    expect(findings.map((f) => f.id)).toContain("AP-STORAGE-001");
  });
});

describe("contracts/TtlStorageTiersManaged.rs (managed TTLs)", () => {
  it("produces no findings", () => {
    expect(scanContract("TtlStorageTiersManaged.rs")).toEqual([]);
  });
});

describe("TTL edge cases", () => {
  const body = (extra: string) => `
    #[contractimpl]
    impl C {
        pub fn put(env: Env, owner: Address, v: i128) {
            owner.require_auth();
            env.storage().temporary().set(&owner, &v);
            ${extra}
        }
    }
  `;

  it("flags temporary storage with no extension", () => {
    expect(scan(body("")).map((f) => f.id)).toContain("AP-STORAGE-001");
  });

  it("accepts extend_ttl on temporary storage", () => {
    const ids = scan(body("env.storage().temporary().extend_ttl(&owner, 10, 20);")).map((f) => f.id);

    expect(ids).not.toContain("AP-STORAGE-001");
  });

  it("accepts extend_ttl_to_threshold on persistent storage", () => {
    const ids = scan(
      body("env.storage().persistent().extend_ttl_to_threshold(&owner, 10, 20);"),
    ).map((f) => f.id);

    expect(ids).not.toContain("AP-STORAGE-001");
  });

  it("still flags storage when extend_ttl only appears in comments", () => {
    const ids = scan(
      body("// env.storage().temporary().extend_ttl(&owner, 10, 20);\n/* extend_ttl(1, 2) */"),
    ).map((f) => f.id);

    expect(ids).toContain("AP-STORAGE-001");
  });

  it("stays silent when the contract touches no ledger storage", () => {
    expect(scan("pub fn add(a: u32, b: u32) -> u32 { a.saturating_add(b) }").map((f) => f.id)).not.toContain(
      "AP-STORAGE-001",
    );
  });
});
