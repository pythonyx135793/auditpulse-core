import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { FunctionRule } from "../engine.js";
import { extractRustFunctions, functionLocation, macrosContaining, sanitizeKeepLines } from "../utils/rust.js";

/**
 * Authorization-sensitive operations (token transfers, balance updates,
 * ledger entry writes) whose exposure matters for AP-AUTH-001.
 */
const SENSITIVE_OP =
  /client\.|\btransfer\b|\btransfer_from\b|\bburn\b|\bbump_arc\b|\bput_arc\b|\bdel_arc\b|\bget_arc\b|\.set\s*\(/;

/** An explicit authorization check inside the function body. */
const AUTH_CHECK = /require_auth(?:_for_args)?\s*\(/;

export class MissingRequireAuthPlugin implements Rule, FunctionRule {
  id = "AP-AUTH-001";
  name = "Missing Require Auth";
  description =
    "Detects authorization-sensitive operations (token transfers, balance updates, ledger entry writes) in functions that never call env.require_auth()";

  scan(code: string): Vulnerability[] {
    return extractRustFunctions(sanitizeKeepLines(code)).flatMap((fn) =>
      this.scanFunction(fn, code),
    );
  }

  /**
   * The engine passes functions extracted from raw source; comments and
   * string contents are blanked here so only executable text is judged.
   *
   * Ordering matters: an auth check only gates operations that execute
   * after it. When the first sensitive operation appears before the first
   * require_auth in the body, the operation runs unauthorized and the
   * finding survives. A trailing require_auth does not retroactively gate
   * it. This is a positional heuristic over the function body (AST-bounded
   * when available): it cannot tie an auth call to specific arguments, and
   * it does not reason about helper functions — a require_auth inside a
   * callee is invisible here, which is documented as a limitation rather
   * than guessed at.
   */
  scanFunction(fn: ScannedFunction, fileCode?: string): Vulnerability[] {
    const clean = sanitizeKeepLines(fn.body);
    const brace = clean.indexOf("{");
    const body = brace >= 0 ? clean.slice(brace) : clean;

    const sensitive = SENSITIVE_OP.exec(body);
    if (!sensitive) {
      return [];
    }

    // A local macro_rules! whose body calls require_auth is an auth check
    // wherever it is invoked.
    const macros = fileCode === undefined ? [] : macrosContaining(fileCode, AUTH_CHECK);
    const authPattern =
      macros.length === 0
        ? AUTH_CHECK
        : new RegExp(`${AUTH_CHECK.source}|\\b(?:${macros.join("|")})\\s*!\\s*[(\\[{]`);
    const auth = authPattern.exec(body);
    if (auth && auth.index < sensitive.index) {
      return [];
    }

    return [
      {
        id: "AP-AUTH-001",
        message: `Authorization-sensitive operations in function '${fn.name}' are not gated by require_auth before they execute. Add env.require_auth(&...) ahead of the sensitive operation so only the intended account can invoke it.`,
        severity: "critical",
        confidence: "high",
        location: functionLocation(fn),
        remediation:
          "Add env.require_auth(&account) before the sensitive operation, for the account authorized to perform it.",
      },
    ];
  }
}

export default new MissingRequireAuthPlugin();
