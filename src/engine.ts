import type { Rule, RuleId, ScannedFunction, Vulnerability } from "./types";
import type { RuleRegistry } from "./registry";
import { extractRustFunctionsAst } from "./parser/rust.js";

/**
 * Optional capability for rules that analyze functions: scanning one parsed
 * function at a time. Rules implementing this are handed the AST-extracted
 * functions (parser-unavailable or malformed input falls back to their own
 * source-text scan), so the tree is parsed once per file, not once per rule.
 */
export interface FunctionRule {
  /**
   * Scans one function; receives the boundaries and body of its declaration
   * and, when known, the whole file's source for file-level context such as
   * locally defined macros.
   */
  scanFunction(fn: ScannedFunction, fileCode?: string): Vulnerability[];
}

export function isFunctionRule(rule: Rule): rule is Rule & FunctionRule {
  return typeof (rule as Partial<FunctionRule>).scanFunction === "function";
}

/**
 * Optional capability for rules that scan whole files but want the shared
 * AST extraction to refine their locations. They receive the same
 * per-file extraction as function rules; null means the parser was
 * unavailable or the source was malformed, and the rule falls back to its
 * own source-text scan.
 */
export interface AstAwareRule {
  /** Scans the whole file with the shared extraction (or null) available. */
  scanCode(code: string, functions: ScannedFunction[] | null): Vulnerability[];
}

export function isAstAwareRule(rule: Rule): rule is Rule & AstAwareRule {
  return typeof (rule as Partial<AstAwareRule>).scanCode === "function";
}

/**
 * Runs registered rules over source code and aggregates their findings.
 * Holds no state beyond the registry, so one engine can scan many files.
 */
export class AuditEngine {
  constructor(private readonly registry: RuleRegistry) {}

  /** All rules the engine will execute, in registration order. */
  rules(): Rule[] {
    return this.registry.all();
  }

  /** Runs a single registered rule by id. */
  runRule(id: RuleId, code: string): Vulnerability[] {
    const rule = this.registry.get(id);
    if (!rule) {
      throw new Error(`Unknown rule id: ${id}`);
    }
    return rule.scan(code).map((finding) => stampRuleId(rule, finding));
  }

  /**
   * Runs every registered rule over `code`, in registration order. The file
   * is parsed once and the extraction (or the fallback on malformed input)
   * is shared by all function rules. Rules listed in `disabledRules` are not
   * executed at all.
   */
  run(
    code: string,
    options: { disabledRules?: readonly string[] } = {},
  ): Vulnerability[] {
    const disabled = new Set(options.disabledRules ?? []);
    const astFunctions = extractRustFunctionsAst(code);
    const findings: Vulnerability[] = [];
    for (const rule of this.rules()) {
      if (disabled.has(rule.id)) continue;
      if (isFunctionRule(rule)) {
        findings.push(...runFunctionRule(rule, code, astFunctions));
        continue;
      }
      if (isAstAwareRule(rule)) {
        findings.push(...rule.scanCode(code, astFunctions).map((f) => stampRuleId(rule, f)));
        continue;
      }
      findings.push(...this.runRule(rule.id, code));
    }
    return findings;
  }
}

/** Function rules run per-function when the AST is available, else fall back. */
function runFunctionRule(
  rule: Rule & FunctionRule,
  code: string,
  astFunctions: ScannedFunction[] | null,
): Vulnerability[] {
  if (astFunctions === null) {
    return rule.scan(code).map((finding) => stampRuleId(rule, finding));
  }
  const findings: Vulnerability[] = [];
  for (const fn of astFunctions) {
    findings.push(...rule.scanFunction(fn, code).map((finding) => stampRuleId(rule, finding)));
  }
  return findings;
}

/** Ensures every finding reports the id of the rule that produced it. */
function stampRuleId(rule: Rule, finding: Vulnerability): Vulnerability {
  return finding.id === rule.id ? finding : { ...finding, id: rule.id };
}
