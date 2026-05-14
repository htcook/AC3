import "./chunk-KFQGP6VL.js";

// server/lib/ac3-lint-bridge.ts
import { spawn } from "child_process";
import { writeFile, unlink } from "fs/promises";
import { join } from "path";
import { randomUUID } from "crypto";
import { tmpdir } from "os";
var AC3_LINT_DIR = join(__dirname, ".");
async function lintReport(report, failOn = "error") {
  const tmpFile = join(tmpdir(), `ac3_lint_${randomUUID()}.json`);
  await writeFile(tmpFile, JSON.stringify(report), "utf-8");
  try {
    const result = await new Promise((resolve, reject) => {
      const proc = spawn("python3", [
        "-m",
        "ac3_lint",
        tmpFile,
        "--json",
        "--fail-on",
        failOn
      ], {
        cwd: AC3_LINT_DIR,
        env: {
          ...process.env,
          PYTHONPATH: AC3_LINT_DIR
        },
        timeout: 3e4
      });
      let stdout = "";
      let stderr = "";
      proc.stdout.on("data", (data) => {
        stdout += data.toString();
      });
      proc.stderr.on("data", (data) => {
        stderr += data.toString();
      });
      proc.on("close", (code) => {
        if (code === 2) {
          reject(new Error(`ac3_lint: bad input \u2014 ${stderr || stdout}`));
          return;
        }
        try {
          const parsed = JSON.parse(stdout);
          resolve(parsed);
        } catch (e) {
          reject(new Error(
            `ac3_lint: failed to parse output (exit ${code}): ${stdout.slice(0, 500)}
stderr: ${stderr.slice(0, 500)}`
          ));
        }
      });
      proc.on("error", (err) => {
        reject(new Error(`ac3_lint: spawn error \u2014 ${err.message}`));
      });
    });
    return result;
  } finally {
    await unlink(tmpFile).catch(() => {
    });
  }
}
function formatLintIssues(result) {
  const lines = [];
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
export {
  formatLintIssues,
  lintReport
};
