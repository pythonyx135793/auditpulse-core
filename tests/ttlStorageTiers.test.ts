import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { loadConfig, scanTarget } from "../src/scanner";
import { renderSarif } from "../src/reporting/sarif";

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

  it("emits the TTL finding as a SARIF result with a region", () => {
    const engine = new AuditEngine(createDefaultRegistry());
    const target = path.join(CONTRACTS_ROOT, "TtlStorageTiers.rs");
    const { config } = loadConfig(target, engine.rules().map((r) => r.id));
    const log = JSON.parse(
      renderSarif(scanTarget(target, engine, config), {
        ruleDescriptions: new Map(engine.rules().map((r) => [r.id, r.description])),
      }),
    ) as any;

    const result = log.runs[0].results.find((r: any) => r.ruleId === "AP-STORAGE-001");
    expect(result).toBeDefined();
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toContain("TtlStorageTiers.rs");
    expect(result.locations[0].physicalLocation.region.startLine).toBeGreaterThan(0);
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
  const ids = (code: string) => scan(code).map((f) => f.id);

  it("flags temporary storage with no extension", () => {
    expect(ids(body(""))).toContain("AP-STORAGE-001");
  });

  it("accepts extend_ttl on temporary storage", () => {
    expect(ids(body("env.storage().temporary().extend_ttl(&owner, 10, 20);"))).not.toContain(
      "AP-STORAGE-001",
    );
  });

  it("accepts extend_ttl_to_threshold on persistent storage", () => {
    expect(
      ids(body("env.storage().persistent().extend_ttl_to_threshold(&owner, 10, 20);")),
    ).not.toContain("AP-STORAGE-001");
  });

  it("still flags storage when extend_ttl only appears in comments", () => {
    expect(
      ids(body("// env.storage().temporary().extend_ttl(&owner, 10, 20);\n/* extend_ttl(1, 2) */")),
    ).toContain("AP-STORAGE-001");
  });

  it("stays silent when the contract touches no ledger storage", () => {
    expect(ids("pub fn add(a: u32, b: u32) -> u32 { a.saturating_add(b) }")).not.toContain(
      "AP-STORAGE-001",
    );
  });
});
