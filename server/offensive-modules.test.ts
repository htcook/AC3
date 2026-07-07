/**
 * Offensive Capability Modules — Comprehensive Tests
 *
 * Tests cover:
 *   1. SAML Offensive Engine: technique catalog, attack planning, evidence recording, SOC playbook
 *   2. K8s Post-Exploit Engine: technique catalog, attack planning, evidence recording, SOC playbook
 *   3. GitOps Offensive Engine: technique catalog, attack planning, evidence recording, SOC playbook
 *   4. Cloud Exploit Frameworks: tool catalog, module listing, evidence recording, SOC playbook
 *   5. Router wiring: all four routers export expected procedures
 *   6. Engagement workflow integration: new modules listed in phase definitions
 */
import { describe, it, expect } from "vitest";

// ═══════════════════════════════════════════════════════════════════════════════
// §1 — SAML OFFENSIVE ENGINE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe("SAML Offensive Engine", () => {
  it("exports SAML_OFFENSIVE_TECHNIQUES with at least 5 techniques", async () => {
    const mod = await import("./lib/saml-offensive-engine");
    expect(mod.SAML_OFFENSIVE_TECHNIQUES).toBeDefined();
    expect(Array.isArray(mod.SAML_OFFENSIVE_TECHNIQUES)).toBe(true);
    expect(mod.SAML_OFFENSIVE_TECHNIQUES.length).toBeGreaterThanOrEqual(5);
  });

  it("each technique has required fields for LLM training", async () => {
    const mod = await import("./lib/saml-offensive-engine");
    for (const technique of mod.SAML_OFFENSIVE_TECHNIQUES) {
      expect(technique.id).toBeDefined();
      expect(technique.name).toBeDefined();
      expect(technique.attackId).toBeDefined();
      expect(technique.category).toBeDefined();
      expect(technique.description).toBeDefined();
      expect(technique.difficulty).toBeDefined();
      expect(technique.opsecRisk).toBeGreaterThanOrEqual(1);
      expect(technique.opsecRisk).toBeLessThanOrEqual(10);
      expect(technique.noiseLevel).toBeDefined();
      expect(technique.prerequisites).toBeDefined();
      expect(Array.isArray(technique.prerequisites)).toBe(true);
    }
  });

  it("each technique has operator guidance steps", async () => {
    const mod = await import("./lib/saml-offensive-engine");
    for (const technique of mod.SAML_OFFENSIVE_TECHNIQUES) {
      expect(technique.operatorGuidance).toBeDefined();
      expect(Array.isArray(technique.operatorGuidance)).toBe(true);
      expect(technique.operatorGuidance.length).toBeGreaterThan(0);
      for (const step of technique.operatorGuidance) {
        expect(step.stepNumber).toBeDefined();
        expect(step.action).toBeDefined();
      }
    }
  });

  it("each technique has evasion techniques", async () => {
    const mod = await import("./lib/saml-offensive-engine");
    for (const technique of mod.SAML_OFFENSIVE_TECHNIQUES) {
      expect(technique.evasionTechniques).toBeDefined();
      expect(Array.isArray(technique.evasionTechniques)).toBe(true);
      expect(technique.evasionTechniques.length).toBeGreaterThan(0);
    }
  });

  it("each technique has detection signatures for SOC correlation", async () => {
    const mod = await import("./lib/saml-offensive-engine");
    for (const technique of mod.SAML_OFFENSIVE_TECHNIQUES) {
      expect(technique.detectionSignatures).toBeDefined();
      expect(Array.isArray(technique.detectionSignatures)).toBe(true);
      expect(technique.detectionSignatures.length).toBeGreaterThan(0);
      for (const sig of technique.detectionSignatures) {
        expect(sig.source).toBeDefined();
        expect(sig.eventName).toBeDefined();
        expect(sig.description).toBeDefined();
      }
    }
  });

  it("exports planSAMLAttack function", async () => {
    const mod = await import("./lib/saml-offensive-engine");
    expect(typeof mod.planSAMLAttack).toBe("function");
  });

  it("exports createSAMLEvidenceRecord function", async () => {
    const mod = await import("./lib/saml-offensive-engine");
    expect(typeof mod.createSAMLEvidenceRecord).toBe("function");
  });

  it("createSAMLEvidenceRecord produces valid evidence record", async () => {
    const mod = await import("./lib/saml-offensive-engine");
    const record = mod.createSAMLEvidenceRecord(
      "golden_saml",
      "Forged SAML assertion for AWS SSO",
      {
        success: true,
        sourceContext: "Google Workspace Admin",
        targetResource: "arn:aws-us-gov:iam::123456789:role/AdminRole",
        commandExecuted: "python3 golden_saml_forge.py --idp google --sp aws",
        rawOutput: "SAML assertion generated successfully",
        impactAchieved: "Assumed AdminRole in GovCloud account",
        operatorNotes: "Used offline signing key extracted from IdP",
      }
    );
    expect(record).toBeDefined();
    expect(record.techniqueId).toBe("golden_saml");
    expect(record.timestamp).toBeDefined();
    expect(record.success).toBe(true);
  });

  it("exports generateSOCDetectionPlaybook function", async () => {
    const mod = await import("./lib/saml-offensive-engine");
    expect(typeof mod.generateSOCDetectionPlaybook).toBe("function");
  });

  it("exports SAML_OFFENSIVE_SYSTEM_PROMPT for LLM training", async () => {
    const mod = await import("./lib/saml-offensive-engine");
    expect(mod.SAML_OFFENSIVE_SYSTEM_PROMPT).toBeDefined();
    expect(typeof mod.SAML_OFFENSIVE_SYSTEM_PROMPT).toBe("string");
    expect(mod.SAML_OFFENSIVE_SYSTEM_PROMPT.length).toBeGreaterThan(500);
    // Should contain key expertise areas
    expect(mod.SAML_OFFENSIVE_SYSTEM_PROMPT).toContain("SAML");
    expect(mod.SAML_OFFENSIVE_SYSTEM_PROMPT).toContain("Golden SAML");
  });

  it("includes T1606.002 (Forge Web Credentials: SAML Tokens) technique", async () => {
    const mod = await import("./lib/saml-offensive-engine");
    const goldenSaml = mod.SAML_OFFENSIVE_TECHNIQUES.find(
      (t) => t.attackId === "T1606.002" || t.id === "golden_saml"
    );
    expect(goldenSaml).toBeDefined();
    expect(goldenSaml!.name.toLowerCase()).toContain("saml");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// §2 — K8S POST-EXPLOIT ENGINE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe("K8s Post-Exploit Engine", () => {
  it("exports K8S_TECHNIQUES with at least 5 techniques", async () => {
    const mod = await import("./lib/k8s-post-exploit");
    expect(mod.K8S_TECHNIQUES).toBeDefined();
    expect(Array.isArray(mod.K8S_TECHNIQUES)).toBe(true);
    expect(mod.K8S_TECHNIQUES.length).toBeGreaterThanOrEqual(5);
  });

  it("each technique has required fields for LLM training", async () => {
    const mod = await import("./lib/k8s-post-exploit");
    for (const technique of mod.K8S_TECHNIQUES) {
      expect(technique.id).toBeDefined();
      expect(technique.name).toBeDefined();
      expect(technique.attackId).toBeDefined();
      expect(technique.category).toBeDefined();
      expect(technique.description).toBeDefined();
      expect(technique.difficulty).toBeDefined();
      expect(technique.opsecRisk).toBeGreaterThanOrEqual(1);
      expect(technique.opsecRisk).toBeLessThanOrEqual(10);
      expect(technique.noiseLevel).toBeDefined();
      expect(technique.prerequisites).toBeDefined();
    }
  });

  it("each technique has operator guidance steps with kubectl commands", async () => {
    const mod = await import("./lib/k8s-post-exploit");
    for (const technique of mod.K8S_TECHNIQUES) {
      expect(technique.operatorGuidance).toBeDefined();
      expect(Array.isArray(technique.operatorGuidance)).toBe(true);
      expect(technique.operatorGuidance.length).toBeGreaterThan(0);
      for (const step of technique.operatorGuidance) {
        expect(step.stepNumber).toBeDefined();
        expect(step.action).toBeDefined();
        expect(step.command).toBeDefined();
      }
    }
  });

  it("each technique has evasion techniques for FedRAMP/GovCloud", async () => {
    const mod = await import("./lib/k8s-post-exploit");
    for (const technique of mod.K8S_TECHNIQUES) {
      expect(technique.evasionTechniques).toBeDefined();
      expect(Array.isArray(technique.evasionTechniques)).toBe(true);
      expect(technique.evasionTechniques.length).toBeGreaterThan(0);
    }
  });

  it("each technique has detection signatures (Falco/GuardDuty/audit)", async () => {
    const mod = await import("./lib/k8s-post-exploit");
    for (const technique of mod.K8S_TECHNIQUES) {
      expect(technique.detectionSignatures).toBeDefined();
      expect(Array.isArray(technique.detectionSignatures)).toBe(true);
      expect(technique.detectionSignatures.length).toBeGreaterThan(0);
    }
  });

  it("exports planK8sAttack function", async () => {
    const mod = await import("./lib/k8s-post-exploit");
    expect(typeof mod.planK8sAttack).toBe("function");
  });

  it("exports createK8sEvidenceRecord function", async () => {
    const mod = await import("./lib/k8s-post-exploit");
    expect(typeof mod.createK8sEvidenceRecord).toBe("function");
  });

  it("createK8sEvidenceRecord produces valid evidence record", async () => {
    const mod = await import("./lib/k8s-post-exploit");
    const record = mod.createK8sEvidenceRecord(
      "secret_extraction",
      "Extracted secrets from kube-system namespace",
      {
        success: true,
        sourceContext: "compromised pod in default namespace",
        targetResource: "kube-system/aws-load-balancer-controller",
        namespace: "kube-system",
        commandExecuted: "kubectl get secrets -n kube-system -o json",
        rawOutput: "Found 12 secrets including AWS credentials",
        accessAchieved: "AWS IAM credentials for load balancer controller",
        operatorNotes: "Used service account token from compromised pod",
      }
    );
    expect(record).toBeDefined();
    expect(record.techniqueId).toBe("secret_extraction");
    expect(record.timestamp).toBeDefined();
    expect(record.success).toBe(true);
  });

  it("exports K8S_OFFENSIVE_SYSTEM_PROMPT for LLM training", async () => {
    const mod = await import("./lib/k8s-post-exploit");
    expect(mod.K8S_OFFENSIVE_SYSTEM_PROMPT).toBeDefined();
    expect(typeof mod.K8S_OFFENSIVE_SYSTEM_PROMPT).toBe("string");
    expect(mod.K8S_OFFENSIVE_SYSTEM_PROMPT.length).toBeGreaterThan(500);
    expect(mod.K8S_OFFENSIVE_SYSTEM_PROMPT).toContain("Kubernetes");
  });

  it("includes container escape technique", async () => {
    const mod = await import("./lib/k8s-post-exploit");
    const escape = mod.K8S_TECHNIQUES.find(
      (t) => t.id.includes("escape") || t.name.toLowerCase().includes("escape")
    );
    expect(escape).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// §3 — GITOPS OFFENSIVE ENGINE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe("GitOps Offensive Engine", () => {
  it("exports GITOPS_TECHNIQUES with at least 5 techniques", async () => {
    const mod = await import("./lib/gitops-offensive-engine");
    expect(mod.GITOPS_TECHNIQUES).toBeDefined();
    expect(Array.isArray(mod.GITOPS_TECHNIQUES)).toBe(true);
    expect(mod.GITOPS_TECHNIQUES.length).toBeGreaterThanOrEqual(5);
  });

  it("each technique has required fields for LLM training", async () => {
    const mod = await import("./lib/gitops-offensive-engine");
    for (const technique of mod.GITOPS_TECHNIQUES) {
      expect(technique.id).toBeDefined();
      expect(technique.name).toBeDefined();
      expect(technique.attackId).toBeDefined();
      expect(technique.category).toBeDefined();
      expect(technique.description).toBeDefined();
      expect(technique.difficulty).toBeDefined();
      expect(technique.opsecRisk).toBeGreaterThanOrEqual(1);
      expect(technique.opsecRisk).toBeLessThanOrEqual(10);
      expect(technique.noiseLevel).toBeDefined();
      expect(technique.prerequisites).toBeDefined();
    }
  });

  it("each technique has operator guidance steps", async () => {
    const mod = await import("./lib/gitops-offensive-engine");
    for (const technique of mod.GITOPS_TECHNIQUES) {
      expect(technique.operatorGuidance).toBeDefined();
      expect(Array.isArray(technique.operatorGuidance)).toBe(true);
      expect(technique.operatorGuidance.length).toBeGreaterThan(0);
    }
  });

  it("each technique has evasion techniques", async () => {
    const mod = await import("./lib/gitops-offensive-engine");
    for (const technique of mod.GITOPS_TECHNIQUES) {
      expect(technique.evasionTechniques).toBeDefined();
      expect(Array.isArray(technique.evasionTechniques)).toBe(true);
      expect(technique.evasionTechniques.length).toBeGreaterThan(0);
    }
  });

  it("each technique has detection signatures", async () => {
    const mod = await import("./lib/gitops-offensive-engine");
    for (const technique of mod.GITOPS_TECHNIQUES) {
      expect(technique.detectionSignatures).toBeDefined();
      expect(Array.isArray(technique.detectionSignatures)).toBe(true);
      expect(technique.detectionSignatures.length).toBeGreaterThan(0);
    }
  });

  it("exports planGitOpsAttack function", async () => {
    const mod = await import("./lib/gitops-offensive-engine");
    expect(typeof mod.planGitOpsAttack).toBe("function");
  });

  it("exports createGitOpsEvidenceRecord function", async () => {
    const mod = await import("./lib/gitops-offensive-engine");
    expect(typeof mod.createGitOpsEvidenceRecord).toBe("function");
  });

  it("createGitOpsEvidenceRecord produces valid evidence record", async () => {
    const mod = await import("./lib/gitops-offensive-engine");
    const record = mod.createGitOpsEvidenceRecord(
      "argocd_rbac_exploit",
      "Escalated ArgoCD privileges via RBAC misconfiguration",
      {
        success: true,
        sourceContext: "ArgoCD project-level admin",
        targetResource: "argocd/cluster-admin-role",
        repository: "github.com/stell-engineering/infra-deploy",
        commandExecuted: "argocd account update-password --current-password xxx",
        rawOutput: "Password updated successfully",
        impactAchieved: "Full cluster admin access via ArgoCD",
        operatorNotes: "RBAC policy allowed project admin to modify global roles",
      }
    );
    expect(record).toBeDefined();
    expect(record.techniqueId).toBe("argocd_rbac_exploit");
    expect(record.timestamp).toBeDefined();
    expect(record.success).toBe(true);
  });

  it("exports GITOPS_OFFENSIVE_SYSTEM_PROMPT for LLM training", async () => {
    const mod = await import("./lib/gitops-offensive-engine");
    expect(mod.GITOPS_OFFENSIVE_SYSTEM_PROMPT).toBeDefined();
    expect(typeof mod.GITOPS_OFFENSIVE_SYSTEM_PROMPT).toBe("string");
    expect(mod.GITOPS_OFFENSIVE_SYSTEM_PROMPT.length).toBeGreaterThan(500);
    expect(mod.GITOPS_OFFENSIVE_SYSTEM_PROMPT).toContain("ArgoCD");
  });

  it("includes T1195.002 (Compromise Software Supply Chain) technique", async () => {
    const mod = await import("./lib/gitops-offensive-engine");
    const supplyChain = mod.GITOPS_TECHNIQUES.find(
      (t) => t.attackId === "T1195.002" || t.attackId.includes("T1195")
    );
    expect(supplyChain).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// §4 — CLOUD EXPLOIT FRAMEWORKS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe("Cloud Exploit Frameworks", () => {
  it("exports CLOUD_TOOLS with at least 4 tools (Pacu, CloudFox, kube-hunter, Peirates)", async () => {
    const mod = await import("./lib/cloud-exploit-frameworks");
    expect(mod.CLOUD_TOOLS).toBeDefined();
    expect(Array.isArray(mod.CLOUD_TOOLS)).toBe(true);
    expect(mod.CLOUD_TOOLS.length).toBeGreaterThanOrEqual(4);
  });

  it("each tool has required metadata fields", async () => {
    const mod = await import("./lib/cloud-exploit-frameworks");
    for (const tool of mod.CLOUD_TOOLS) {
      expect(tool.id).toBeDefined();
      expect(tool.name).toBeDefined();
      expect(tool.category).toBeDefined();
      expect(tool.description).toBeDefined();
      expect(tool.govcloudSupport).toBeDefined();
      expect(typeof tool.govcloudSupport).toBe("boolean");
      expect(tool.modules).toBeDefined();
      expect(Array.isArray(tool.modules)).toBe(true);
      expect(tool.modules.length).toBeGreaterThan(0);
    }
  });

  it("each tool module has detection profile for OPSEC awareness", async () => {
    const mod = await import("./lib/cloud-exploit-frameworks");
    for (const tool of mod.CLOUD_TOOLS) {
      expect(tool.detectionProfile).toBeDefined();
      expect(tool.detectionProfile.rateLimitRisk).toBeDefined();
      expect(tool.detectionProfile.apiCallVolume).toBeDefined();
      expect(tool.detectionProfile.detectionAdvice).toBeDefined();
    }
  });

  it("each module has operator commands and OPSEC risk rating", async () => {
    const mod = await import("./lib/cloud-exploit-frameworks");
    for (const tool of mod.CLOUD_TOOLS) {
      for (const module of tool.modules) {
        expect(module.id).toBeDefined();
        expect(module.name).toBeDefined();
        expect(module.description).toBeDefined();
        expect(module.command).toBeDefined();
        expect(module.opsecRisk).toBeGreaterThanOrEqual(1);
        expect(module.opsecRisk).toBeLessThanOrEqual(10);
        expect(module.noiseLevel).toBeDefined();
      }
    }
  });

  it("includes Pacu with GovCloud support", async () => {
    const mod = await import("./lib/cloud-exploit-frameworks");
    const pacu = mod.CLOUD_TOOLS.find((t) => t.id === "pacu" || t.name.toLowerCase().includes("pacu"));
    expect(pacu).toBeDefined();
    expect(pacu!.govcloudSupport).toBe(true);
  });

  it("includes kube-hunter for K8s assessment", async () => {
    const mod = await import("./lib/cloud-exploit-frameworks");
    const kubeHunter = mod.CLOUD_TOOLS.find(
      (t) => t.id === "kube_hunter" || t.name.toLowerCase().includes("kube-hunter")
    );
    expect(kubeHunter).toBeDefined();
  });

  it("exports planCloudExploitation function", async () => {
    const mod = await import("./lib/cloud-exploit-frameworks");
    expect(typeof mod.planCloudExploitation).toBe("function");
  });

  it("exports createCloudToolEvidenceRecord function", async () => {
    const mod = await import("./lib/cloud-exploit-frameworks");
    expect(typeof mod.createCloudToolEvidenceRecord).toBe("function");
  });

  it("createCloudToolEvidenceRecord produces valid evidence record", async () => {
    const mod = await import("./lib/cloud-exploit-frameworks");
    const record = mod.createCloudToolEvidenceRecord(
      "pacu",
      "iam__enum_permissions",
      {
        success: true,
        commandExecuted: "pacu --exec iam__enum_permissions --region us-gov-west-1",
        findings: [
          {
            id: "finding-001",
            severity: "high" as const,
            title: "Overprivileged IAM Role",
            description: "Role has iam:* permissions",
            resource: "arn:aws-us-gov:iam::123456789:role/DeployRole",
            attackId: "T1078.004",
            exploitable: true,
            exploitPath: "AssumeRole → iam:CreateUser → persistence",
            evidence: "IAM policy JSON showing wildcard permissions",
          },
        ],
        rawOutput: "Enumerated 47 permissions for role DeployRole",
        operatorNotes: "Role is assumable from EKS service account",
      }
    );
    expect(record).toBeDefined();
    expect(record.toolName).toContain("Pacu");
    expect(record.moduleExecuted).toBe("iam__enum_permissions");
    expect(record.timestamp).toBeDefined();
    expect(record.findings.length).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// §5 — ROUTER WIRING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe("Offensive Module Routers", () => {
  it("samlOffensiveRouter exports expected procedures", async () => {
    const mod = await import("./routers/saml-offensive");
    expect(mod.samlOffensiveRouter).toBeDefined();
    const procedures = Object.keys(mod.samlOffensiveRouter);
    expect(procedures).toContain("listTechniques");
    expect(procedures).toContain("getTechnique");
    expect(procedures).toContain("planAttack");
    expect(procedures).toContain("recordEvidence");
    expect(procedures).toContain("generateSOCPlaybook");
  });

  it("k8sPostExploitRouter exports expected procedures", async () => {
    const mod = await import("./routers/k8s-post-exploit");
    expect(mod.k8sPostExploitRouter).toBeDefined();
    const procedures = Object.keys(mod.k8sPostExploitRouter);
    expect(procedures).toContain("listTechniques");
    expect(procedures).toContain("getTechnique");
    expect(procedures).toContain("planAttack");
    expect(procedures).toContain("recordEvidence");
    expect(procedures).toContain("generateSOCPlaybook");
  });

  it("gitopsOffensiveRouter exports expected procedures", async () => {
    const mod = await import("./routers/gitops-offensive");
    expect(mod.gitopsOffensiveRouter).toBeDefined();
    const procedures = Object.keys(mod.gitopsOffensiveRouter);
    expect(procedures).toContain("listTechniques");
    expect(procedures).toContain("getTechnique");
    expect(procedures).toContain("planAttack");
    expect(procedures).toContain("recordEvidence");
    expect(procedures).toContain("generateSOCPlaybook");
  });

  it("cloudExploitFrameworksRouter exports expected procedures", async () => {
    const mod = await import("./routers/cloud-exploit-frameworks");
    expect(mod.cloudExploitFrameworksRouter).toBeDefined();
    const procedures = Object.keys(mod.cloudExploitFrameworksRouter);
    expect(procedures).toContain("listTools");
    expect(procedures).toContain("getTool");
    expect(procedures).toContain("getModule");
    expect(procedures).toContain("planExploitation");
    expect(procedures).toContain("recordEvidence");
    expect(procedures).toContain("generateSOCPlaybook");
    expect(procedures).toContain("getInstallInstructions");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// §6 — ENGAGEMENT WORKFLOW INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe("Engagement Workflow Integration", () => {
  it("post_exploitation phase includes new offensive modules", async () => {
    const mod = await import("./lib/engagement-workflow-engine");
    const postExploit = mod.PHASE_DEFINITIONS.post_exploitation;
    expect(postExploit.requiredModules).toContain("saml-offensive-engine");
    expect(postExploit.requiredModules).toContain("k8s-post-exploit");
    expect(postExploit.requiredModules).toContain("cloud-exploit-frameworks");
  });

  it("lateral_movement phase includes cloud/k8s/gitops modules", async () => {
    const mod = await import("./lib/engagement-workflow-engine");
    const lateralMove = mod.PHASE_DEFINITIONS.lateral_movement;
    expect(lateralMove.requiredModules).toContain("k8s-post-exploit");
    expect(lateralMove.requiredModules).toContain("cloud-exploit-frameworks");
    expect(lateralMove.requiredModules).toContain("gitops-offensive-engine");
  });

  it("KILL_CHAIN_PHASES includes all standard phases", async () => {
    const mod = await import("./lib/engagement-workflow-engine");
    expect(mod.KILL_CHAIN_PHASES).toContain("post_exploitation");
    expect(mod.KILL_CHAIN_PHASES).toContain("lateral_movement");
    expect(mod.KILL_CHAIN_PHASES).toContain("exploitation");
  });
});
