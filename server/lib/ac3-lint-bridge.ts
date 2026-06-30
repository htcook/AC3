/**
 * ac3-lint-bridge.ts
 *
 * TypeScript bridge to invoke the Python ac3_lint quality linter on the
 * intermediate report dict. Spawns `python3 -m ac3_lint` as a subprocess
 * and returns the structured result.
 *
 * Usage:
 *   import { lintReport, LintResult } from './ac3-lint-bridge';
 *   const result = await lintReport(reportDict);
 *   if (!result.passed) { ... }
 */

import { spawn } from "child_process";
import { writeFile, unlink } from "fs/promises";
import { join } from "path";
import { randomUUID } from "crypto";
import { tmpdir } from "os";

export interface LintIssue {
  check_id: string;
  check_name: string;
  severity: "ERROR" | "WARNING" | "INFO";
  message: string;
  location: string;
  detail: string;
  suggestion: string;
  evidence: Record<string, unknown>;
}

export interface LintResult {
  passed: boolean;
  checks_run: number;
  checks_errored: number;
  summary: {
    errors: number;
    warnings: number;
    infos: number;
  };
  issues: LintIssue[];
}

/**
 * The path to the ac3_lint package relative to this file.
 * The package lives at server/lib/ac3_lint/ and the Python module
 * is importable from server/lib/ as `ac3_lint`.
 */
const AC3_LINT_DIR = join(__dirname, ".");

/**
 * Run the ac3_lint linter on a report dict.
 *
 * @param report - The intermediate report dict (same shape as the JSON files
 *                 in ac3_lint/examples/)
 * @param failOn - Severity threshold: "error" (default), "warning", or "info"
 * @returns LintResult with pass/fail status and all issues
 */
export async function lintReport(
  report: Record<string, unknown>,
  failOn: "error" | "warning" | "info" = "error"
): Promise<LintResult> {
  // Write the report dict to a temp file
  const tmpFile = join(tmpdir(), `ac3_lint_${randomUUID()}.json`);
  await writeFile(tmpFile, JSON.stringify(report), "utf-8");

  try {
    const result = await new Promise<LintResult>((resolve, reject) => {
      const proc = spawn("python3", [
        "-m", "ac3_lint",
        tmpFile,
        "--json",
        "--fail-on", failOn,
      ], {
        cwd: AC3_LINT_DIR,
        env: {
          ...process.env,
          PYTHONPATH: AC3_LINT_DIR,
        },
        timeout: 30000,
      });

      let stdout = "";
      let stderr = "";

      proc.stdout.on("data", (data) => { stdout += data.toString(); });
      proc.stderr.on("data", (data) => { stderr += data.toString(); });

      proc.on("close", (code) => {
        if (code === 2) {
          reject(new Error(`ac3_lint: bad input — ${stderr || stdout}`));
          return;
        }
        try {
          const parsed = JSON.parse(stdout);
          resolve(parsed as LintResult);
        } catch (e) {
          reject(new Error(
            `ac3_lint: failed to parse output (exit ${code}): ${stdout.slice(0, 500)}\nstderr: ${stderr.slice(0, 500)}`
          ));
        }
      });

      proc.on("error", (err) => {
        reject(new Error(`ac3_lint: spawn error — ${err.message}`));
      });
    });

    return result;
  } finally {
    // Clean up temp file
    await unlink(tmpFile).catch(() => {});
  }
}

/**
 * Format lint issues into a human-readable string for logging/notifications.
 */
export function formatLintIssues(result: LintResult): string {
  const lines: string[] = [];
  lines.push(`AC3 Lint: ${result.passed ? "PASS" : "FAIL"}`);
  lines.push(`  Checks: ${result.checks_run} | Errors: ${result.summary.errors} | Warnings: ${result.summary.warnings}`);

  if (result.issues.length > 0) {
    lines.push("");
    for (const issue of result.issues) {
      lines.push(`  [${issue.check_id}] ${issue.message}`);
      if (issue.location) lines.push(`    at: ${issue.location}`);
      if (issue.suggestion) lines.push(`    fix: ${issue.suggestion}`);
    }
  }

  return lines.join("\n");
}
