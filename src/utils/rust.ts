/**
 * Shared text helpers for scanning Rust/Soroban source code.
 * Kept here so every rule strips comments in exactly the same way.
 *
 * This is plain source-text analysis, not a Rust AST analyzer. These helpers
 * exist so rules stay small and agree on how "clean" source is derived.
 */

/**
 * Removes `//` line comments and `/* ... *&#47;` block comments.
 *
 * Rules must compute findings on comment-free code so commented-out
 * examples never trigger them.
 */
export function removeComments(code: string): string {
  return code.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
}

/**
 * Removes `//` line comments and `/* ... *&#47;` block comments while keeping
 * line numbering: stripped text is replaced with spaces (newlines kept).
 *
 * Rules that report per-line locations should use this so the findings
 * point at the line that actually contained the suspicious code.
 */
export function removeCommentsKeepLines(code: string): string {
  return code
    .replace(/\/\/.*$/gm, (match) => " ".repeat(match.length))
    .replace(/\/\*[\s\S]*?\*\//g, (match) =>
      match.replace(/[^\n]/g, " "),
    );
}

import type { ScannedFunction, SourceLocation } from "../types";

/**
 * Blanks out the contents of string/char literals (keeping the quotes and
 * line count) so patterns inside string text, e.g. `"a.unwrap()"`, are not
 * matched. Call it on comment-free code.
 */
export function blankStringContents(code: string): string {
  return code.replace(
    /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g,
    (match) => match.replace(/[^"'\n]/g, " "),
  );
}

/** Both steps above, for rules that scan per line. */
export function sanitizeKeepLines(code: string): string {
  return blankStringContents(removeCommentsKeepLines(code));
}

/**
 * Best available location for a finding anchored to a whole function: the
 * `fn` keyword's line, plus its column when the AST provided one. Columns
 * are never invented for text-fallback extractions.
 */
export function functionLocation(fn: ScannedFunction): SourceLocation {
  return fn.column === undefined
    ? { line: fn.line, function: fn.name }
    : { line: fn.line, column: fn.column, function: fn.name };
}

/**
 * The scanned function whose body contains the 1-based `line`, or null.
 * Declarations cannot nest, so at most one function matches.
 */
function functionAtLine(
  fns: ScannedFunction[],
  line: number,
): ScannedFunction | null {
  for (const fn of fns) {
    if (fn.bodyLine <= line && line <= fn.endLine) {
      return fn;
    }
  }
  return null;
}

/**
 * Best location for a whole-file match on `line`: the line itself, plus the
 * enclosing function's name and `fn`-keyword column when the AST extraction
 * is available. Without it (null), only the line is reported.
 */
export function locateLine(
  functions: ScannedFunction[] | null,
  line: number,
): SourceLocation {
  const fn = functions === null ? null : functionAtLine(functions, line);
  if (fn === null) {
    return { line };
  }
  return fn.column === undefined
    ? { line, function: fn.name }
    : { line, column: fn.column, function: fn.name };
}

/**
 * Extracts top-level functions by brace counting, one nesting level per
 * function. `macro_rules!` blocks are skipped as a unit (brace-based, no
 * macro internals are parsed).
 */
export function extractRustFunctions(code: string): ScannedFunction[] {
  const lines = code.split("\n");
  const fns: ScannedFunction[] = [];
  let current: { line: number; name: string; body: string[]; depth: number } | null =
    null;

  const count = (line: string, ch: "{" | "}"): number =>
    line.split(ch).length - 1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";

    if (current === null) {
      // Skip macro_rules! bodies entirely.
      if (/macro_rules!/.test(line)) {
        let depth = count(line, "{") - count(line, "}");
        while (depth > 0 && i + 1 < lines.length) {
          i++;
          depth += count(lines[i] ?? "", "{") - count(lines[i] ?? "", "}");
        }
        continue;
      }

      const match = /\bfn\s+([A-Za-z_]\w*)\s*[(<]/.exec(line);
      if (!match) {
        continue;
      }
      current = {
        line: i + 1,
        name: match[1] ?? "<anonymous>",
        body: [line],
        depth: 0,
      };
    } else {
      current.body.push(line);
    }

    if (current === null) {
      continue;
    }
    current.depth += count(line, "{") - count(line, "}");
    if (current.depth <= 0) {
      const body = current.body.join("\n");
      const open = body.indexOf("{");
      fns.push({
        line: current.line,
        endLine: i + 1,
        name: current.name,
        body,
        bodyInner: open >= 0 ? body.slice(open + 1) : "",
        bodyLine: current.line + (open >= 0 ? body.slice(0, open).split("\n").length - 1 : 0),
      });
      current = null;
    }
  }

  return fns;
}

/**
 * Names of `macro_rules!` macros defined in `code` whose body calls
 * `pattern`. Invoking such a macro expands to that call, so rules treat
 * `name!(...)` as if the call were written inline. Brace matching only; the
 * macro internals are not parsed.
 */
export function macrosContaining(code: string, pattern: RegExp): string[] {
  const clean = sanitizeKeepLines(code);
  const names: string[] = [];
  const header = /macro_rules!\s*([A-Za-z_]\w*)\s*\{/g;
  for (let m = header.exec(clean); m; m = header.exec(clean)) {
    let depth = 1;
    let i = header.lastIndex;
    for (; i < clean.length && depth > 0; i++) {
      if (clean[i] === "{") depth++;
      else if (clean[i] === "}") depth--;
    }
    if (pattern.test(clean.slice(header.lastIndex, i))) {
      names.push(m[1] ?? "");
    }
  }
  return names;
}

/** Finds the 1-based line of the first regex match, or null when absent. */
export function findFirstMatchLine(
  lines: string[],
  pattern: RegExp,
): number | null {
  const index = lines.findIndex((line) => pattern.test(line));
  return index === -1 ? null : index + 1;
}
