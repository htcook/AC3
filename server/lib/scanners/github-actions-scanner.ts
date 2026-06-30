/**
 * GitHub Actions Workflow Injection Scanner
 * ──────────────────────────────────────────
 * Security testing for GitHub Actions CI/CD pipelines:
 * - Expression injection in ${{ }} contexts (command injection via PR titles, branch names)
 * - pull_request_target misuse (code execution from untrusted forks)
 * - Unpinned third-party actions (supply chain attacks)
 * - Secret exposure in workflow logs
 * - Workflow_dispatch with unsafe inputs
 * - Self-hosted runner abuse
 * - GITHUB_TOKEN over-permissioning
 * - Artifact poisoning
 * - Cache poisoning
 *
 * @module github-actions-scanner
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type GHActionsVulnCategory =
  | "expression_injection"
  | "pull_request_target_abuse"
  | "unpinned_actions"
  | "secret_exposure"
  | "workflow_dispatch_injection"
  | "self_hosted_runner_abuse"
  | "token_over_permission"
  | "artifact_poisoning"
  | "cache_poisoning"
  | "pwn_request"
  | "configuration_weakness";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface GHActionsFinding {
  id: string;
  category: GHActionsVulnCategory;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cwe?: string;
  mitreTechnique?: string;
  file?: string;
  line?: number;
}

export interface GHActionsTarget {
  owner: string;
  repo: string;
  workflowFiles: WorkflowFile[];
}

export interface WorkflowFile {
  path: string;
  content: string;
}

export interface GHActionsScanResult {
  target: GHActionsTarget;
  findings: GHActionsFinding[];
  profile: GHActionsProfile;
  scanDuration: number;
  timestamp: string;
}

export interface GHActionsProfile {
  totalWorkflows: number;
  triggersUsed: string[];
  thirdPartyActions: ActionReference[];
  unpinnedActions: ActionReference[];
  usesSecrets: boolean;
  secretNames: string[];
  usesSelfHostedRunners: boolean;
  hasPermissionsBlock: boolean;
  defaultPermissions: string;
  usesEnvironments: boolean;
  hasCodeql: boolean;
  hasDependabot: boolean;
}

export interface ActionReference {
  action: string;
  version: string;
  isPinned: boolean;
  file: string;
  line: number;
}

// ─── Dangerous Expression Contexts ──────────────────────────────────────────

/**
 * GitHub Actions contexts that can be controlled by external users
 * and are dangerous when used in `run:` steps or `with:` inputs.
 */
export const INJECTABLE_CONTEXTS = [
  // PR-related (controllable by fork authors)
  "github.event.pull_request.title",
  "github.event.pull_request.body",
  "github.event.pull_request.head.ref",
  "github.event.pull_request.head.label",
  "github.event.pull_request.head.repo.default_branch",
  // Issue-related (controllable by any user)
  "github.event.issue.title",
  "github.event.issue.body",
  // Comment-related
  "github.event.comment.body",
  "github.event.review.body",
  "github.event.review_comment.body",
  // Discussion-related
  "github.event.discussion.title",
  "github.event.discussion.body",
  // Commit-related (controllable via commit messages)
  "github.event.commits[0].message",
  "github.event.head_commit.message",
  "github.event.head_commit.author.name",
  "github.event.head_commit.author.email",
  // Pages-related
  "github.event.pages[0].page_name",
  // Workflow dispatch inputs (user-controlled)
  "github.event.inputs.",
  // Branch/tag names
  "github.head_ref",
  "github.ref_name",
];

// ─── Known Dangerous Action Patterns ─────────────────────────────────────────

export const DANGEROUS_ACTION_PATTERNS: Array<{
  pattern: RegExp;
  severity: Severity;
  risk: string;
  remediation: string;
}> = [
  {
    pattern: /actions\/checkout@.*\n.*ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha/,
    severity: "critical",
    risk: "Checking out PR head in pull_request_target context executes untrusted code from forks",
    remediation: "Never checkout PR head SHA in pull_request_target. Use pull_request trigger instead, or checkout the base branch only.",
  },
  {
    pattern: /actions\/github-script@/,
    severity: "medium",
    risk: "github-script executes JavaScript with access to the GitHub API and GITHUB_TOKEN",
    remediation: "Ensure github-script inputs are not derived from user-controlled contexts. Pin to a specific SHA.",
  },
  {
    pattern: /peter-evans\/create-pull-request@/,
    severity: "medium",
    risk: "Can create PRs with arbitrary content, potentially bypassing branch protection",
    remediation: "Ensure the action is not triggered by untrusted events. Pin to a specific SHA.",
  },
];

// ─── Analysis Engine ─────────────────────────────────────────────────────────

/**
 * Analyze a set of GitHub Actions workflow files for security vulnerabilities.
 */
export function analyzeWorkflows(target: GHActionsTarget): GHActionsScanResult {
  const startTime = Date.now();
  const findings: GHActionsFinding[] = [];
  const allTriggers = new Set<string>();
  const allActions: ActionReference[] = [];
  const allSecrets = new Set<string>();
  let usesSelfHosted = false;
  let hasPermissions = false;
  let hasCodeql = false;
  let hasDependabot = false;
  let usesEnvironments = false;

  for (const workflow of target.workflowFiles) {
    const lines = workflow.content.split("\n");

    // Extract triggers
    const triggers = extractTriggers(workflow.content);
    triggers.forEach(t => allTriggers.add(t));

    // Extract actions
    const actions = extractActions(workflow.content, workflow.path);
    allActions.push(...actions);

    // Extract secrets
    const secrets = extractSecrets(workflow.content);
    secrets.forEach(s => allSecrets.add(s));

    // Check for self-hosted runners
    if (workflow.content.includes("self-hosted")) usesSelfHosted = true;

    // Check for permissions block
    if (/^\s*permissions:/m.test(workflow.content)) hasPermissions = true;

    // Check for environments
    if (/^\s*environment:/m.test(workflow.content)) usesEnvironments = true;

    // Check for CodeQL
    if (workflow.content.includes("codeql") || workflow.content.includes("CodeQL")) hasCodeql = true;

    // Check for Dependabot
    if (workflow.path.includes("dependabot")) hasDependabot = true;

    // ─── Vulnerability Checks ────────────────────────────────────────

    // Check 1: Expression injection
    checkExpressionInjection(workflow, lines, findings);

    // Check 2: pull_request_target abuse
    checkPullRequestTargetAbuse(workflow, lines, findings);

    // Check 3: Unpinned actions
    checkUnpinnedActions(actions, findings);

    // Check 4: Secret exposure in logs
    checkSecretExposure(workflow, lines, findings);

    // Check 5: workflow_dispatch injection
    checkWorkflowDispatchInjection(workflow, lines, findings);

    // Check 6: Self-hosted runner abuse
    checkSelfHostedRunnerAbuse(workflow, lines, findings, triggers);

    // Check 7: GITHUB_TOKEN permissions
    checkTokenPermissions(workflow, lines, findings);

    // Check 8: Artifact/cache poisoning
    checkArtifactPoisoning(workflow, lines, findings, triggers);
  }

  const unpinnedActions = allActions.filter(a => !a.isPinned);

  const profile: GHActionsProfile = {
    totalWorkflows: target.workflowFiles.length,
    triggersUsed: Array.from(allTriggers),
    thirdPartyActions: allActions.filter(a => !a.action.startsWith("actions/")),
    unpinnedActions,
    usesSecrets: allSecrets.size > 0,
    secretNames: Array.from(allSecrets),
    usesSelfHostedRunners: usesSelfHosted,
    hasPermissionsBlock: hasPermissions,
    defaultPermissions: hasPermissions ? "restricted" : "write-all (default)",
    usesEnvironments,
    hasCodeql,
    hasDependabot,
  };

  return {
    target,
    findings,
    profile,
    scanDuration: Date.now() - startTime,
    timestamp: new Date().toISOString(),
  };
}

// ─── Individual Checks ───────────────────────────────────────────────────────

function checkExpressionInjection(
  workflow: WorkflowFile,
  lines: string[],
  findings: GHActionsFinding[]
): void {
  let inRunBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Detect run: blocks — both "run:" and "- run:" YAML forms
    const isRunLine = trimmed.startsWith("run:") || trimmed.startsWith("- run:");
    if (isRunLine) {
      inRunBlock = true;
    } else if (inRunBlock && !trimmed.startsWith("-") && !trimmed.startsWith("#") && trimmed !== "" && !/^\s/.test(line) && !line.startsWith("\t")) {
      inRunBlock = false;
    }

    // Check for injectable expressions in run blocks
    const exprMatches = line.match(/\$\{\{[^}]+\}\}/g);
    if (exprMatches && (inRunBlock || isRunLine)) {
      for (const expr of exprMatches) {
        const exprContent = expr.replace(/\$\{\{\s*|\s*\}\}/g, "");

        for (const injectable of INJECTABLE_CONTEXTS) {
          if (exprContent.includes(injectable)) {
            findings.push({
              id: `GHA-EXPR-${i + 1}`,
              category: "expression_injection",
              severity: "critical",
              title: `Expression Injection via ${injectable}`,
              description: `The workflow uses user-controlled context "${injectable}" directly in a \`run:\` step. An attacker can inject arbitrary shell commands via PR titles, commit messages, branch names, or issue bodies.`,
              evidence: `File: ${workflow.path}, Line ${i + 1}: ${line.trim()}`,
              remediation: `Never use ${injectable} directly in run: steps. Instead:\n1. Pass it as an environment variable: env: TITLE: \${{ ${injectable} }}\n2. Reference the env var in the script: echo "$TITLE"\nThis prevents shell metacharacter injection.`,
              cwe: "CWE-78",
              mitreTechnique: "T1059",
              file: workflow.path,
              line: i + 1,
            });
            break;
          }
        }
      }
    }
  }
}

function checkPullRequestTargetAbuse(
  workflow: WorkflowFile,
  lines: string[],
  findings: GHActionsFinding[]
): void {
  const hasPRTarget = /on:\s*\n\s*pull_request_target/m.test(workflow.content) ||
                      /on:\s*\[.*pull_request_target.*\]/m.test(workflow.content) ||
                      /on:\s*pull_request_target/m.test(workflow.content);

  if (!hasPRTarget) return;

  // Check if it checks out the PR head
  const checkoutPRHead = /actions\/checkout@.*\n.*ref:\s*\$\{\{.*pull_request.*head/m.test(workflow.content) ||
                         /actions\/checkout@.*\n.*ref:\s*\$\{\{.*github\.head_ref/m.test(workflow.content);

  if (checkoutPRHead) {
    findings.push({
      id: "GHA-PRT-001",
      category: "pull_request_target_abuse",
      severity: "critical",
      title: "Pwn Request: pull_request_target Checks Out Untrusted PR Code",
      description: "This workflow uses pull_request_target trigger and checks out the PR head branch. This is a classic 'pwn request' vulnerability — the workflow runs with write permissions and access to secrets, but executes code from an untrusted fork.",
      evidence: `File: ${workflow.path}. Trigger: pull_request_target with checkout of PR head ref.`,
      remediation: "1. Use pull_request trigger instead (runs in fork context without secrets)\n2. If pull_request_target is needed, NEVER checkout the PR head\n3. Use a two-workflow pattern: first workflow runs in PR context, second workflow (triggered by workflow_run) processes the results with elevated permissions",
      cwe: "CWE-94",
      mitreTechnique: "T1195.002",
      file: workflow.path,
    });
  } else {
    // Still flag pull_request_target as it's risky
    findings.push({
      id: "GHA-PRT-002",
      category: "pull_request_target_abuse",
      severity: "medium",
      title: "pull_request_target Trigger Used",
      description: "This workflow uses the pull_request_target trigger which runs with write permissions and access to secrets. While it doesn't appear to checkout untrusted code, any future modifications could introduce a pwn request vulnerability.",
      evidence: `File: ${workflow.path}. Trigger: pull_request_target`,
      remediation: "Prefer pull_request trigger when possible. If pull_request_target is required, add a comment explaining why and never checkout the PR head branch.",
      cwe: "CWE-94",
      file: workflow.path,
    });
  }
}

function checkUnpinnedActions(
  actions: ActionReference[],
  findings: GHActionsFinding[]
): void {
  const thirdPartyUnpinned = actions.filter(a =>
    !a.isPinned && !a.action.startsWith("actions/") && !a.action.startsWith("./")
  );

  for (const action of thirdPartyUnpinned) {
    findings.push({
      id: `GHA-PIN-${action.line}`,
      category: "unpinned_actions",
      severity: "high",
      title: `Unpinned Third-Party Action: ${action.action}@${action.version}`,
      description: `The third-party action "${action.action}" is referenced by tag/branch (${action.version}) instead of a commit SHA. A compromised or hijacked action repository could inject malicious code into your CI/CD pipeline.`,
      evidence: `File: ${action.file}, Line ${action.line}: uses: ${action.action}@${action.version}`,
      remediation: `Pin to a specific commit SHA:\nuses: ${action.action}@<full-40-char-sha> # ${action.version}\n\nUse Dependabot or Renovate to automatically update pinned SHAs.`,
      cwe: "CWE-829",
      mitreTechnique: "T1195.002",
      file: action.file,
      line: action.line,
    });
  }

  // Also flag first-party actions on branches (not SHAs)
  const firstPartyUnpinned = actions.filter(a =>
    !a.isPinned && a.action.startsWith("actions/") && !a.action.startsWith("./")
  );

  if (firstPartyUnpinned.length > 5) {
    findings.push({
      id: "GHA-PIN-FIRST",
      category: "unpinned_actions",
      severity: "low",
      title: `${firstPartyUnpinned.length} First-Party Actions Not Pinned to SHA`,
      description: "Multiple GitHub-owned actions are referenced by tag instead of commit SHA. While lower risk than third-party actions, pinning to SHA provides defense-in-depth.",
      evidence: `Unpinned first-party actions: ${firstPartyUnpinned.slice(0, 5).map(a => `${a.action}@${a.version}`).join(", ")}`,
      remediation: "Pin all actions to commit SHAs for maximum supply chain security.",
      cwe: "CWE-829",
    });
  }
}

function checkSecretExposure(
  workflow: WorkflowFile,
  lines: string[],
  findings: GHActionsFinding[]
): void {
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check for secrets echoed to stdout
    if (/echo.*\$\{\{\s*secrets\./i.test(line) ||
        /printf.*\$\{\{\s*secrets\./i.test(line) ||
        /cat.*\$\{\{\s*secrets\./i.test(line)) {
      findings.push({
        id: `GHA-SEC-${i + 1}`,
        category: "secret_exposure",
        severity: "high",
        title: "Secret Potentially Exposed in Workflow Logs",
        description: "A secret value is being echoed or printed in a run step. While GitHub masks known secret values in logs, this can fail if the secret is transformed, split, or encoded.",
        evidence: `File: ${workflow.path}, Line ${i + 1}: ${line.trim()}`,
        remediation: "Never echo secrets to stdout. Use secrets only as environment variables or action inputs. If you need to verify a secret exists, check its length: echo ${#SECRET}",
        cwe: "CWE-532",
        mitreTechnique: "T1552.001",
        file: workflow.path,
        line: i + 1,
      });
    }

    // Check for secrets in URLs (can leak via HTTP logs)
    if (/https?:\/\/.*\$\{\{\s*secrets\./i.test(line)) {
      findings.push({
        id: `GHA-SEC-URL-${i + 1}`,
        category: "secret_exposure",
        severity: "high",
        title: "Secret Used in URL — Potential Log Exposure",
        description: "A secret is embedded in a URL string. This can expose the secret in HTTP access logs, proxy logs, browser history, or workflow output.",
        evidence: `File: ${workflow.path}, Line ${i + 1}: ${line.trim().substring(0, 100)}`,
        remediation: "Pass secrets via HTTP headers (Authorization: Bearer) or environment variables instead of URL parameters.",
        cwe: "CWE-598",
        file: workflow.path,
        line: i + 1,
      });
    }
  }
}

function checkWorkflowDispatchInjection(
  workflow: WorkflowFile,
  lines: string[],
  findings: GHActionsFinding[]
): void {
  const hasDispatch = /on:\s*\n\s*workflow_dispatch/m.test(workflow.content) ||
                      /on:\s*workflow_dispatch/m.test(workflow.content);

  if (!hasDispatch) return;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/run:.*\$\{\{\s*github\.event\.inputs\./i.test(line) ||
        (line.includes("run:") && lines.slice(i, i + 5).some(l => /\$\{\{\s*github\.event\.inputs\./.test(l)))) {
      findings.push({
        id: `GHA-DISP-${i + 1}`,
        category: "workflow_dispatch_injection",
        severity: "high",
        title: "workflow_dispatch Input Used in run: Step",
        description: "User-provided workflow_dispatch inputs are used directly in a run: step. If the input is not sanitized, an attacker with write access can inject shell commands.",
        evidence: `File: ${workflow.path}, Line ${i + 1}: ${line.trim()}`,
        remediation: "Pass dispatch inputs as environment variables:\nenv:\n  INPUT_VALUE: ${{ github.event.inputs.value }}\nThen reference as $INPUT_VALUE in the script.",
        cwe: "CWE-78",
        file: workflow.path,
        line: i + 1,
      });
      break;
    }
  }
}

function checkSelfHostedRunnerAbuse(
  workflow: WorkflowFile,
  lines: string[],
  findings: GHActionsFinding[],
  triggers: string[]
): void {
  const usesSelfHosted = workflow.content.includes("self-hosted");
  if (!usesSelfHosted) return;

  // Self-hosted + pull_request = dangerous (forks can run code on your runner)
  if (triggers.includes("pull_request") || triggers.includes("pull_request_target")) {
    findings.push({
      id: "GHA-RUNNER-001",
      category: "self_hosted_runner_abuse",
      severity: "critical",
      title: "Self-Hosted Runner Exposed to Pull Requests",
      description: "This workflow uses a self-hosted runner and is triggered by pull requests. Fork authors can submit PRs that execute arbitrary code on your self-hosted runner, potentially compromising the host machine and network.",
      evidence: `File: ${workflow.path}. Trigger: ${triggers.join(", ")}. Runner: self-hosted`,
      remediation: "1. Never use self-hosted runners for public repo PR workflows\n2. Use GitHub-hosted runners for untrusted code\n3. If self-hosted is required, use ephemeral runners in isolated containers\n4. Require approval for first-time contributors",
      cwe: "CWE-94",
      mitreTechnique: "T1059",
      file: workflow.path,
    });
  }
}

function checkTokenPermissions(
  workflow: WorkflowFile,
  _lines: string[],
  findings: GHActionsFinding[]
): void {
  const hasPermissions = /^\s*permissions:/m.test(workflow.content);

  if (!hasPermissions) {
    findings.push({
      id: "GHA-TOKEN-001",
      category: "token_over_permission",
      severity: "medium",
      title: "No Explicit Permissions Block — GITHUB_TOKEN Has Write Access",
      description: "This workflow does not define a permissions block. By default, GITHUB_TOKEN has write access to the repository contents, packages, and more. If the workflow is compromised, the token can be used to push malicious code.",
      evidence: `File: ${workflow.path}. No 'permissions:' block found.`,
      remediation: "Add a top-level permissions block with minimum required permissions:\npermissions:\n  contents: read\n  pull-requests: read\n\nOnly add write permissions for specific jobs that need them.",
      cwe: "CWE-250",
      mitreTechnique: "T1078",
      file: workflow.path,
    });
  }

  // Check for write-all
  if (/permissions:\s*write-all/m.test(workflow.content)) {
    findings.push({
      id: "GHA-TOKEN-002",
      category: "token_over_permission",
      severity: "high",
      title: "GITHUB_TOKEN Granted write-all Permissions",
      description: "The workflow explicitly grants write-all permissions to GITHUB_TOKEN. This gives the token maximum privileges including writing to repository contents, packages, and deployments.",
      evidence: `File: ${workflow.path}. permissions: write-all`,
      remediation: "Replace write-all with specific permissions needed for each job. Use the principle of least privilege.",
      cwe: "CWE-250",
      file: workflow.path,
    });
  }
}

function checkArtifactPoisoning(
  workflow: WorkflowFile,
  _lines: string[],
  findings: GHActionsFinding[],
  triggers: string[]
): void {
  const uploadsArtifact = workflow.content.includes("actions/upload-artifact");
  const downloadsArtifact = workflow.content.includes("actions/download-artifact");

  if (uploadsArtifact && (triggers.includes("pull_request") || triggers.includes("pull_request_target"))) {
    findings.push({
      id: "GHA-ART-001",
      category: "artifact_poisoning",
      severity: "medium",
      title: "Artifact Upload in PR Context — Potential Poisoning",
      description: "This workflow uploads artifacts from a PR context. If a downstream workflow downloads and executes these artifacts with elevated permissions, a fork author can inject malicious artifacts.",
      evidence: `File: ${workflow.path}. Uses upload-artifact with PR trigger.`,
      remediation: "Validate artifact contents before use in downstream workflows. Use artifact attestation. Never execute downloaded artifacts without verification.",
      cwe: "CWE-829",
      mitreTechnique: "T1195.002",
      file: workflow.path,
    });
  }

  // Check for cache poisoning
  if (workflow.content.includes("actions/cache") && triggers.includes("pull_request")) {
    findings.push({
      id: "GHA-CACHE-001",
      category: "cache_poisoning",
      severity: "medium",
      title: "Cache Used in PR Context — Potential Cache Poisoning",
      description: "This workflow uses actions/cache with pull_request trigger. A malicious PR can poison the cache with modified dependencies that persist for future workflow runs on the default branch.",
      evidence: `File: ${workflow.path}. Uses actions/cache with pull_request trigger.`,
      remediation: "Use cache scoping to isolate PR caches from default branch caches. Consider using cache-read-only for PR workflows.",
      cwe: "CWE-829",
      file: workflow.path,
    });
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function extractTriggers(content: string): string[] {
  const triggers: string[] = [];
  const onMatch = content.match(/^on:\s*\n((?:\s+\w+.*\n)*)/m);
  if (onMatch) {
    const triggerLines = onMatch[1].match(/^\s+(\w+)/gm);
    if (triggerLines) {
      triggers.push(...triggerLines.map(t => t.trim()));
    }
  }
  // Single-line on:
  const singleMatch = content.match(/^on:\s*\[([^\]]+)\]/m);
  if (singleMatch) {
    triggers.push(...singleMatch[1].split(",").map(t => t.trim()));
  }
  // Simple on: event
  const simpleMatch = content.match(/^on:\s+(\w+)\s*$/m);
  if (simpleMatch) {
    triggers.push(simpleMatch[1]);
  }
  return triggers;
}

function extractActions(content: string, filePath: string): ActionReference[] {
  const actions: ActionReference[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/uses:\s*([^@\s]+)@([^\s#]+)/);
    if (match) {
      const [, action, version] = match;
      if (action.startsWith("./")) continue; // Local action
      const isPinned = /^[a-f0-9]{40}$/.test(version);
      actions.push({ action, version, isPinned, file: filePath, line: i + 1 });
    }
  }

  return actions;
}

function extractSecrets(content: string): string[] {
  const secrets = new Set<string>();
  const matches = content.matchAll(/\$\{\{\s*secrets\.(\w+)\s*\}\}/g);
  for (const match of matches) {
    secrets.add(match[1]);
  }
  return Array.from(secrets);
}

/**
 * Generate a GitHub Actions-specific test plan for an engagement.
 */
export function generateGHActionsTestPlan(profile: GHActionsProfile): string[] {
  const tests: string[] = [
    "Audit all workflow files for expression injection in run: steps",
    "Check all third-party actions for SHA pinning",
    "Verify GITHUB_TOKEN permissions follow least-privilege principle",
    "Review workflow triggers for untrusted code execution risks",
  ];

  if (profile.triggersUsed.includes("pull_request_target")) {
    tests.push(
      "Test for pwn request vulnerability (PR target + checkout PR head)",
      "Verify pull_request_target workflows don't execute untrusted code",
      "Check for two-workflow pattern compliance"
    );
  }

  if (profile.usesSelfHostedRunners) {
    tests.push(
      "Verify self-hosted runners are not exposed to PR workflows from forks",
      "Check runner isolation (ephemeral containers vs persistent)",
      "Test for runner escape vectors (Docker socket, host network)"
    );
  }

  if (profile.usesSecrets) {
    tests.push(
      "Audit secret usage for potential log exposure",
      "Check for secrets in URL parameters",
      "Verify secrets are not passed to untrusted actions"
    );
  }

  if (profile.unpinnedActions.length > 0) {
    tests.push(
      `Pin ${profile.unpinnedActions.length} unpinned actions to commit SHAs`,
      "Enable Dependabot for automated action version updates",
      "Review third-party action source code for malicious behavior"
    );
  }

  if (!profile.hasCodeql) {
    tests.push("Enable CodeQL analysis for automated vulnerability scanning");
  }

  if (!profile.hasDependabot) {
    tests.push("Enable Dependabot for dependency and action version updates");
  }

  return tests;
}
