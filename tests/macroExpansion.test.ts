import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { macrosContaining } from "../src/utils/rust";

const CONTRACT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
  "MacroExpandedVault.rs",
);

function scan(code: string) {
  return new AuditEngine(createDefaultRegistry()).run(code);
}

describe("contracts/MacroExpandedVault.rs", () => {
  const findings = scan(fs.readFileSync(CONTRACT, "utf-8"));

  it("treats a local require_auth macro as an auth check", () => {
    const auth = findings.filter((f) => f.id === "AP-AUTH-001");

    expect(auth.map((f) => f.location.function)).toEqual(["leak"]);
  });

  it("reports no storage finding for the sample (file-level extend_ttl text match)", () => {
    expect(findings.map((f) => f.id)).not.toContain("AP-STORAGE-001");
  });
});

describe("AP-STORAGE-001 temporary vs persistent TTL (file-level)", () => {
  const storageIds = (code: string) => scan(code).filter((f) => f.id === "AP-STORAGE-001");
  const wrap = (body: string, pre = "") => `
    ${pre}
    #[contractimpl]
    impl C {
        pub fn f(env: Env, k: u32) {
            ${body}
        }
    }
  `;
  const tmpMacro = "macro_rules! bump { ($e:expr, $k:expr) => { $e.storage().temporary().extend_ttl($k, 10, 20); }; }";

  it("temporary set with a temporary extend_ttl macro gives no finding", () => {
    expect(storageIds(wrap("env.storage().temporary().set(&k, &1); bump!(env, &k);", tmpMacro))).toEqual([]);
  });

  it("detects extend_ttl at file level only, regardless of storage kind", () => {
    expect(storageIds(wrap("env.storage().persistent().set(&k, &1); env.storage().temporary().extend_ttl(&k, 1, 2);"))).toEqual([]);
    expect(storageIds(wrap("env.storage().temporary().set(&k, &1); env.storage().persistent().extend_ttl(&k, 1, 2);"))).toEqual([]);
  });

  it("reports exactly one finding when no extend_ttl exists anywhere", () => {
    expect(storageIds(wrap("env.storage().temporary().set(&k, &1); env.storage().persistent().set(&k, &2);"))).toHaveLength(1);
  });

  it("a defined but never invoked TTL macro still suppresses the finding (text-match limitation)", () => {
    expect(storageIds(wrap("env.storage().temporary().set(&k, &1);", tmpMacro))).toEqual([]);
  });
});

describe("macro-expanded authorization", () => {
  const withMacro = (call: string) => `
    macro_rules! gate { ($a:expr) => { $a.require_auth(); }; }
    macro_rules! noop { ($a:expr) => { let _ = $a; }; }
    #[contractimpl]
    impl C {
        pub fn put(env: Env, owner: Address, v: i128) {
            ${call}
            env.storage().persistent().set(&owner, &v);
            env.storage().persistent().extend_ttl(&owner, 1, 2);
        }
    }
  `;
  const authIds = (code: string) => scan(code).filter((f) => f.id === "AP-AUTH-001");

  it("passes when the auth macro runs before the sensitive operation", () => {
    expect(authIds(withMacro("gate!(owner);"))).toEqual([]);
    expect(authIds(withMacro("gate![owner];"))).toEqual([]);
  });

  it("flags a macro that does not expand to require_auth", () => {
    expect(authIds(withMacro("noop!(owner);"))).toHaveLength(1);
  });

  it("flags an auth macro that runs after the sensitive operation", () => {
    const code = withMacro("").replace(
      "env.storage().persistent().extend_ttl(&owner, 1, 2);",
      "gate!(owner);",
    );

    expect(authIds(code)).toHaveLength(1);
  });

  it("does not trust an undefined macro of the same style", () => {
    expect(authIds("pub fn put(env: Env, o: Address) { gate!(o); env.storage().persistent().set(&o, &1); }")).toHaveLength(1);
  });

  it("macrosContaining ignores comments and strings", () => {
    const code = `macro_rules! a { () => { // x.require_auth();\n 1 }; }\nmacro_rules! b { () => { x.require_auth(); }; }`;

    expect(macrosContaining(code, /require_auth\s*\(/)).toEqual(["b"]);
  });
});
