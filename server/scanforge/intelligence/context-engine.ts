/**
 * ScanForge LLM Context Awareness Engine
 *
 * Uses the platform's built-in LLM to make ScanForge "context aware" —
 * understanding what it's scanning, why certain checks matter, and how
 * findings relate to each other. This is the brain that transforms
 * ScanForge from a dumb scanner into an intelligent security analyst.
 *
 * Capabilities:
 *   1. Asset Classification — Identify target environment (cloud/IoT/ICS/container/traditional)
 *   2. Adaptive Scan Planning — Select optimal scanners and templates based on context
 *   3. Finding Correlation — Chain findings into attack paths
 *   4. Enriched Narratives — Generate human-readable finding descriptions
 *   5. Compliance Mapping — Map findings to applicable frameworks
 *   6. Risk Contextualization — Adjust risk scores based on environment
 *
 * The engine uses structured JSON output from the LLM to ensure
 * deterministic, parseable results that integrate with the scan pipeline.
 */

import type {
  ScanTarget,
  ScanFinding,
  AssetClassification,
  AssetEnvironment,
  CloudProvider,
  ComplianceFramework,
  ComplianceMapping,
  ContextAnalysis,
  CorrelationResult,
  EnrichedNarrative,
  AttackPath,
  ScanType,
} from "../types";

// ─── LLM Integration ──────────────────────────────────────────────────────

let invokeLLM: any;
async function getLLM() {
  if (!invokeLLM) {
    const mod = await import("../../_core/llm");
    invokeLLM = mod.invokeLLM;
  }
  return invokeLLM;
}

// ─── Context Engine ───────────────────────────────────────────────────────

export class ContextEngine {
  private classificationCache: Map<string, AssetClassification> = new Map();
  private initialized = false;

  async initialize(): Promise<void> {
    // Pre-warm the LLM connection
    try {
      await getLLM();
      this.initialized = true;
      console.log("[ContextEngine] LLM context engine initialized");
    } catch (err: any) {
      console.warn(`[ContextEngine] LLM not available, falling back to heuristic mode: ${err.message}`);
      this.initialized = true; // Still mark as initialized — we'll use heuristics
    }
  }

  // ─── 1. Asset Classification ──────────────────────────────────────────

  /**
   * Classify a target's environment using LLM analysis of recon data.
   * Falls back to heuristic classification if LLM is unavailable.
   */
  async classifyTarget(
    target: ScanTarget,
    reconData?: {
      ports?: number[];
      services?: Record<number, string>;
      headers?: Record<string, string>;
      banners?: string[];
    }
  ): Promise<AssetClassification> {
    // Check cache first
    const cacheKey = `${target.value}:${target.type}`;
    const cached = this.classificationCache.get(cacheKey);
    if (cached) return cached;

    // Try LLM classification first
    try {
      const llm = await getLLM();
      const classification = await this.llmClassify(llm, target, reconData);
      this.classificationCache.set(cacheKey, classification);
      return classification;
    } catch {
      // Fall back to heuristic classification
      const classification = this.heuristicClassify(target, reconData);
      this.classificationCache.set(cacheKey, classification);
      return classification;
    }
  }

  private async llmClassify(
    llm: any,
    target: ScanTarget,
    reconData?: any
  ): Promise<AssetClassification> {
    const prompt = this.buildClassificationPrompt(target, reconData);

    const response = await llm({
      messages: [
        {
          role: "system",
          content: `You are an expert cybersecurity analyst specializing in asset classification and attack surface analysis. Analyze the provided target information and classify the asset environment. Be precise and evidence-based in your classification.`,
        },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "asset_classification",
          strict: true,
          schema: {
            type: "object",
            properties: {
              environment: {
                type: "string",
                enum: ["traditional", "cloud", "iot", "ics_ot", "container", "hybrid", "unknown"],
                description: "Primary environment type of the target",
              },
              cloudProvider: {
                type: "string",
                enum: ["aws", "azure", "gcp", "digitalocean", "unknown", "none"],
                description: "Cloud provider if applicable, 'none' if not cloud",
              },
              confidence: {
                type: "integer",
                description: "Confidence in classification (0-100)",
              },
              reasoning: {
                type: "string",
                description: "Detailed reasoning for the classification",
              },
              technologies: {
                type: "array",
                items: { type: "string" },
                description: "Detected technologies and frameworks",
              },
              inferredIndustry: {
                type: "string",
                description: "Inferred industry vertical",
              },
              inferredCriticality: {
                type: "string",
                enum: ["critical", "high", "medium", "low"],
                description: "Inferred asset criticality",
              },
              recommendedProfiles: {
                type: "array",
                items: { type: "string" },
                description: "Recommended scan profiles to run",
              },
              applicableCompliance: {
                type: "array",
                items: { type: "string" },
                description: "Applicable compliance frameworks",
              },
            },
            required: [
              "environment", "cloudProvider", "confidence", "reasoning",
              "technologies", "inferredIndustry", "inferredCriticality",
              "recommendedProfiles", "applicableCompliance",
            ],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");

    const parsed = JSON.parse(content);

    return {
      environment: parsed.environment as AssetEnvironment,
      cloudProvider: parsed.cloudProvider === "none" ? undefined : parsed.cloudProvider as CloudProvider,
      confidence: parsed.confidence,
      reasoning: parsed.reasoning,
      technologies: parsed.technologies,
      inferredIndustry: parsed.inferredIndustry,
      inferredCriticality: parsed.inferredCriticality,
      recommendedProfiles: parsed.recommendedProfiles,
      applicableCompliance: parsed.applicableCompliance as ComplianceFramework[],
    };
  }

  private buildClassificationPrompt(target: ScanTarget, reconData?: any): string {
    const parts: string[] = [
      `Classify the following target asset:`,
      ``,
      `Target: ${target.value}`,
      `Type: ${target.type}`,
    ];

    if (reconData?.ports?.length) {
      parts.push(`Open Ports: ${reconData.ports.join(", ")}`);
    }

    if (reconData?.services) {
      parts.push(`Services:`);
      for (const [port, service] of Object.entries(reconData.services)) {
        parts.push(`  Port ${port}: ${service}`);
      }
    }

    if (reconData?.headers) {
      parts.push(`HTTP Headers:`);
      for (const [key, value] of Object.entries(reconData.headers)) {
        parts.push(`  ${key}: ${value}`);
      }
    }

    if (reconData?.banners?.length) {
      parts.push(`Service Banners:`);
      for (const banner of reconData.banners) {
        parts.push(`  ${banner}`);
      }
    }

    if (target.cloudMeta) {
      parts.push(`Cloud Metadata: ${JSON.stringify(target.cloudMeta)}`);
    }

    if (target.iotMeta) {
      parts.push(`IoT Metadata: ${JSON.stringify(target.iotMeta)}`);
    }

    if (target.icsMeta) {
      parts.push(`ICS Metadata: ${JSON.stringify(target.icsMeta)}`);
    }

    if (target.containerMeta) {
      parts.push(`Container Metadata: ${JSON.stringify(target.containerMeta)}`);
    }

    parts.push(``);
    parts.push(`Based on the above information, classify this asset's environment type, identify the cloud provider (if any), list detected technologies, infer the industry vertical, assess criticality, recommend scan profiles, and identify applicable compliance frameworks.`);

    return parts.join("\n");
  }

  /**
   * Heuristic classification when LLM is unavailable.
   */
  private heuristicClassify(target: ScanTarget, reconData?: any): AssetClassification {
    const ports = reconData?.ports || target.ports || [];
    const services = reconData?.services || target.services || {};
    const serviceStr = Object.values(services).join(" ").toLowerCase();
    const host = target.value.toLowerCase();

    // Cloud indicators
    const cloudPorts = [6443, 8443, 2379, 10250, 10255];
    const cloudServices = ["kubernetes", "k8s", "docker", "etcd", "consul", "vault"];
    const awsIndicators = ["amazonaws.com", "aws", "ec2", "s3"];
    const azureIndicators = ["azure", "microsoft", "blob.core.windows.net"];
    const gcpIndicators = ["googleapis.com", "gcp", "google"];

    // IoT indicators
    const iotPorts = [1883, 8883, 5683, 5684, 1900];
    const iotServices = ["mqtt", "coap", "upnp", "ssdp", "zigbee"];

    // ICS/OT indicators
    const icsPorts = [502, 503, 20000, 47808, 44818, 4840, 2222, 4843];
    const icsServices = ["modbus", "dnp3", "bacnet", "ethernetip", "opcua", "opc", "scada", "plc"];

    // Container indicators
    const containerPorts = [2375, 2376, 4243, 5000, 6443, 10250];
    const containerServices = ["docker", "containerd", "registry", "kubelet"];

    let environment: AssetEnvironment = "traditional";
    let cloudProvider: CloudProvider | undefined;
    let confidence = 60;
    const technologies: string[] = [];
    const recommendedProfiles: string[] = [];
    const applicableCompliance: ComplianceFramework[] = [];

    // Check ICS first (most critical)
    const icsPortMatch = ports.some((p: number) => icsPorts.includes(p));
    const icsServiceMatch = icsServices.some(s => serviceStr.includes(s));
    if (icsPortMatch || icsServiceMatch || target.type === "ics_endpoint") {
      environment = "ics_ot";
      confidence = icsServiceMatch ? 90 : 75;
      recommendedProfiles.push("ics_ot", "network");
      applicableCompliance.push("iec_62443", "nerc_cip", "nist_800_53");
      if (icsServiceMatch) technologies.push(...icsServices.filter(s => serviceStr.includes(s)));
    }
    // Check IoT
    else if (ports.some((p: number) => iotPorts.includes(p)) || iotServices.some(s => serviceStr.includes(s)) || target.type === "iot_device") {
      environment = "iot";
      confidence = 80;
      recommendedProfiles.push("iot", "network");
      applicableCompliance.push("nist_csf");
      if (iotServices.some(s => serviceStr.includes(s))) technologies.push(...iotServices.filter(s => serviceStr.includes(s)));
    }
    // Check Cloud
    else if (awsIndicators.some(i => host.includes(i)) || azureIndicators.some(i => host.includes(i)) || gcpIndicators.some(i => host.includes(i)) || target.type === "cloud_resource") {
      environment = "cloud";
      confidence = 85;
      if (awsIndicators.some(i => host.includes(i))) cloudProvider = "aws";
      else if (azureIndicators.some(i => host.includes(i))) cloudProvider = "azure";
      else if (gcpIndicators.some(i => host.includes(i))) cloudProvider = "gcp";
      recommendedProfiles.push("cloud", "web");
      applicableCompliance.push("fedramp", "nist_800_53", "cis_benchmark");
    }
    // Check Container
    else if (ports.some((p: number) => containerPorts.includes(p)) || containerServices.some(s => serviceStr.includes(s)) || target.type === "container") {
      environment = "container";
      confidence = 80;
      recommendedProfiles.push("container", "cloud");
      applicableCompliance.push("cis_benchmark", "nist_800_53");
      if (containerServices.some(s => serviceStr.includes(s))) technologies.push(...containerServices.filter(s => serviceStr.includes(s)));
    }
    // Check for hybrid (multiple environment indicators)
    else if (
      (ports.some((p: number) => cloudPorts.includes(p)) || cloudServices.some(s => serviceStr.includes(s))) &&
      (ports.some((p: number) => [80, 443, 22, 3306].includes(p)))
    ) {
      environment = "hybrid";
      confidence = 65;
      recommendedProfiles.push("full");
      applicableCompliance.push("nist_800_53", "nist_csf");
    }
    // Default traditional
    else {
      environment = "traditional";
      confidence = 70;
      recommendedProfiles.push("network", "web");
      applicableCompliance.push("nist_800_53", "pci_dss");
    }

    return {
      environment,
      cloudProvider,
      confidence,
      reasoning: `Heuristic classification based on port analysis (${ports.length} ports), service fingerprinting, and hostname patterns.`,
      technologies,
      inferredCriticality: environment === "ics_ot" ? "critical" : environment === "cloud" ? "high" : "medium",
      recommendedProfiles,
      applicableCompliance,
    };
  }

  // ─── 2. Adaptive Scan Planning ────────────────────────────────────────

  /**
   * Generate an adaptive scan plan based on target classification.
   */
  async planScan(
    target: ScanTarget,
    classification: AssetClassification,
    availableScanners: string[],
    availableTemplateIds: string[]
  ): Promise<ContextAnalysis> {
    try {
      const llm = await getLLM();
      return await this.llmPlanScan(llm, target, classification, availableScanners, availableTemplateIds);
    } catch {
      return this.heuristicPlanScan(target, classification, availableScanners, availableTemplateIds);
    }
  }

  private async llmPlanScan(
    llm: any,
    target: ScanTarget,
    classification: AssetClassification,
    availableScanners: string[],
    availableTemplateIds: string[]
  ): Promise<ContextAnalysis> {
    const response = await llm({
      messages: [
        {
          role: "system",
          content: `You are an expert penetration tester planning a security assessment. Based on the target classification and available tools, create an optimal scan plan. Prioritize scanners and templates that are most relevant to the target environment. Consider safety constraints for ICS/OT environments.`,
        },
        {
          role: "user",
          content: [
            `Target: ${target.value} (${target.type})`,
            `Classification: ${JSON.stringify(classification, null, 2)}`,
            `Available Scanners: ${availableScanners.join(", ")}`,
            `Available Templates: ${availableTemplateIds.slice(0, 50).join(", ")}${availableTemplateIds.length > 50 ? ` ... and ${availableTemplateIds.length - 50} more` : ""}`,
            ``,
            `Create a scan plan selecting the most relevant scanners and templates. For ICS/OT targets, exclude aggressive scanners. For IoT targets, prefer gentle scanning. For cloud targets, include cloud-specific checks.`,
          ].join("\n"),
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "scan_plan",
          strict: true,
          schema: {
            type: "object",
            properties: {
              recommendedScanType: {
                type: "string",
                enum: ["full", "quick", "web", "network", "compliance", "cloud", "iot", "ics_ot", "container", "hybrid"],
              },
              recommendedScanners: {
                type: "array",
                items: { type: "string" },
              },
              recommendedTemplateIds: {
                type: "array",
                items: { type: "string" },
              },
              riskFactors: {
                type: "array",
                items: { type: "string" },
              },
              reasoning: {
                type: "string",
              },
            },
            required: ["recommendedScanType", "recommendedScanners", "recommendedTemplateIds", "riskFactors", "reasoning"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");

    const parsed = JSON.parse(content);

    return {
      target: target.value,
      classification,
      recommendedScanType: parsed.recommendedScanType as ScanType,
      recommendedScanners: parsed.recommendedScanners,
      recommendedTemplateIds: parsed.recommendedTemplateIds,
      riskFactors: parsed.riskFactors,
      reasoning: parsed.reasoning,
      analyzedAt: Date.now(),
    };
  }

  private heuristicPlanScan(
    target: ScanTarget,
    classification: AssetClassification,
    availableScanners: string[],
    availableTemplateIds: string[]
  ): ContextAnalysis {
    const env = classification.environment;
    let recommendedScanType: ScanType = "full";
    const recommendedScanners: string[] = [];
    const riskFactors: string[] = [];

    // Environment-specific scanner selection
    const scannerMap: Record<AssetEnvironment, string[]> = {
      traditional: ["http", "tls", "dns", "mysql", "postgresql", "redis", "mongodb", "smb", "ldap", "rdp", "vnc", "telnet", "amqp"],
      cloud: ["http", "tls", "dns", "aws-imds", "cloud-storage", "kubernetes", "docker", "etcd", "container-registry"],
      iot: ["http", "tls", "mqtt", "coap", "upnp", "dns"],
      ics_ot: ["modbus", "dnp3", "bacnet", "ethernetip", "opcua"],
      container: ["kubernetes", "docker", "etcd", "container-registry", "http", "tls"],
      hybrid: ["http", "tls", "dns", "aws-imds", "cloud-storage", "kubernetes", "docker", "mysql", "postgresql"],
      unknown: ["http", "tls", "dns"],
    };

    const envScanners = scannerMap[env] || scannerMap.unknown;
    for (const s of envScanners) {
      if (availableScanners.includes(s)) {
        recommendedScanners.push(s);
      }
    }

    // Scan type mapping
    const typeMap: Record<AssetEnvironment, ScanType> = {
      traditional: "full",
      cloud: "cloud",
      iot: "iot",
      ics_ot: "ics_ot",
      container: "container",
      hybrid: "hybrid",
      unknown: "full",
    };
    recommendedScanType = typeMap[env] || "full";

    // Risk factors
    if (env === "ics_ot") {
      riskFactors.push(
        "ICS/OT environment — physical safety implications",
        "Modbus/DNP3 protocols lack authentication by design",
        "Disruption could affect critical infrastructure",
      );
    }
    if (env === "cloud") {
      riskFactors.push(
        "Cloud misconfigurations are the #1 cause of data breaches",
        "IMDS credential theft enables lateral movement",
        "Public storage buckets expose sensitive data",
      );
    }
    if (env === "iot") {
      riskFactors.push(
        "IoT devices often lack security updates",
        "Default credentials are prevalent",
        "Constrained devices may crash under heavy scanning",
      );
    }
    if (env === "container") {
      riskFactors.push(
        "Exposed Docker/K8s APIs enable full cluster compromise",
        "Container escape vulnerabilities affect host security",
        "etcd exposure leaks all cluster secrets",
      );
    }

    return {
      target: target.value,
      classification,
      recommendedScanType,
      recommendedScanners,
      recommendedTemplateIds: availableTemplateIds.slice(0, 20),
      riskFactors,
      reasoning: `Heuristic scan plan for ${env} environment targeting ${target.value}. Selected ${recommendedScanners.length} scanners optimized for this environment type.`,
      analyzedAt: Date.now(),
    };
  }

  // ─── 3. Finding Correlation (Attack Path Analysis) ────────────────────

  /**
   * Correlate findings into attack paths using LLM reasoning.
   */
  async correlateFindings(
    findings: ScanFinding[],
    target: ScanTarget,
    classification: AssetClassification
  ): Promise<CorrelationResult> {
    if (findings.length < 2) {
      return {
        attackPaths: [],
        uncorrelatedFindings: findings.map(f => f.id),
        reasoning: "Insufficient findings for correlation (minimum 2 required).",
      };
    }

    try {
      const llm = await getLLM();
      return await this.llmCorrelate(llm, findings, target, classification);
    } catch {
      return this.heuristicCorrelate(findings, target, classification);
    }
  }

  private async llmCorrelate(
    llm: any,
    findings: ScanFinding[],
    target: ScanTarget,
    classification: AssetClassification
  ): Promise<CorrelationResult> {
    // Summarize findings for the LLM (avoid sending too much data)
    const findingSummaries = findings.slice(0, 30).map(f => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      port: f.port,
      protocol: f.protocol,
      cves: f.cves,
      cwes: f.cwes,
      techniqueIds: f.techniqueIds,
    }));

    const response = await llm({
      messages: [
        {
          role: "system",
          content: `You are an expert penetration tester analyzing scan findings to identify attack paths. An attack path is a chain of vulnerabilities that, when exploited in sequence, lead to a significant security impact (e.g., initial access → lateral movement → privilege escalation → data exfiltration). Identify realistic attack paths from the provided findings. Each path should have at least 2 findings in the chain.`,
        },
        {
          role: "user",
          content: [
            `Target: ${target.value} (${classification.environment})`,
            `Total Findings: ${findings.length}`,
            ``,
            `Findings:`,
            JSON.stringify(findingSummaries, null, 2),
            ``,
            `Identify attack paths by chaining related findings. Consider MITRE ATT&CK tactics progression.`,
          ].join("\n"),
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "correlation_result",
          strict: true,
          schema: {
            type: "object",
            properties: {
              attackPaths: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    description: { type: "string" },
                    findingChain: { type: "array", items: { type: "string" } },
                    tacticsTraversed: { type: "array", items: { type: "string" } },
                    riskScore: { type: "integer" },
                    exploitability: { type: "integer" },
                    businessImpact: { type: "string" },
                    narrative: { type: "string" },
                  },
                  required: ["name", "description", "findingChain", "tacticsTraversed", "riskScore", "exploitability", "businessImpact", "narrative"],
                  additionalProperties: false,
                },
              },
              uncorrelatedFindings: {
                type: "array",
                items: { type: "string" },
              },
              reasoning: { type: "string" },
            },
            required: ["attackPaths", "uncorrelatedFindings", "reasoning"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");

    const parsed = JSON.parse(content);

    return {
      attackPaths: parsed.attackPaths.map((ap: any) => ({
        id: `ap-${crypto.randomUUID().substring(0, 8)}`,
        ...ap,
      })),
      uncorrelatedFindings: parsed.uncorrelatedFindings,
      reasoning: parsed.reasoning,
    };
  }

  private heuristicCorrelate(
    findings: ScanFinding[],
    target: ScanTarget,
    classification: AssetClassification
  ): CorrelationResult {
    const attackPaths: AttackPath[] = [];
    const correlatedIds = new Set<string>();

    // Pattern 1: Initial Access → Credential Theft → Lateral Movement
    const initialAccess = findings.filter(f =>
      f.techniqueIds?.some(t => t.startsWith("T1190") || t.startsWith("T1133") || t.startsWith("T1078")) ||
      f.cwes?.includes("CWE-306") ||
      f.title.toLowerCase().includes("unauthenticated")
    );
    const credentialTheft = findings.filter(f =>
      f.techniqueIds?.some(t => t.startsWith("T1552") || t.startsWith("T1110")) ||
      f.title.toLowerCase().includes("credential") ||
      f.title.toLowerCase().includes("password")
    );
    const lateralMovement = findings.filter(f =>
      f.techniqueIds?.some(t => t.startsWith("T1021") || t.startsWith("T1570")) ||
      f.protocol === "smb" || f.protocol === "rdp" || f.protocol === "ssh"
    );

    if (initialAccess.length > 0 && credentialTheft.length > 0) {
      const chain = [initialAccess[0].id, credentialTheft[0].id];
      if (lateralMovement.length > 0) chain.push(lateralMovement[0].id);

      attackPaths.push({
        id: `ap-${crypto.randomUUID().substring(0, 8)}`,
        name: "Credential Theft via Exposed Service",
        description: `An attacker can gain initial access through ${initialAccess[0].title}, then steal credentials via ${credentialTheft[0].title}${lateralMovement.length > 0 ? `, and move laterally through ${lateralMovement[0].title}` : ""}.`,
        findingChain: chain,
        tacticsTraversed: ["Initial Access", "Credential Access", ...(lateralMovement.length > 0 ? ["Lateral Movement"] : [])],
        riskScore: 85,
        exploitability: 75,
        businessImpact: "Full network compromise through credential theft and lateral movement.",
      });
      chain.forEach(id => correlatedIds.add(id));
    }

    // Pattern 2: Cloud IMDS → Credential Theft → Data Exfiltration
    const imdsFindings = findings.filter(f => f.source.includes("aws-imds") || f.source.includes("cloud"));
    const storageFindings = findings.filter(f =>
      f.source.includes("s3") || f.source.includes("blob") || f.source.includes("gcs") ||
      f.techniqueIds?.includes("T1530")
    );

    if (imdsFindings.length > 0 && storageFindings.length > 0) {
      const chain = [imdsFindings[0].id, storageFindings[0].id];
      attackPaths.push({
        id: `ap-${crypto.randomUUID().substring(0, 8)}`,
        name: "Cloud Credential Theft to Data Exfiltration",
        description: `An attacker can exploit ${imdsFindings[0].title} to steal cloud credentials, then access ${storageFindings[0].title} to exfiltrate data.`,
        findingChain: chain,
        tacticsTraversed: ["Initial Access", "Credential Access", "Collection", "Exfiltration"],
        riskScore: 95,
        exploitability: 80,
        businessImpact: "Cloud credential compromise leading to data exfiltration from storage services.",
      });
      chain.forEach(id => correlatedIds.add(id));
    }

    // Pattern 3: Container Escape Path
    const dockerFindings = findings.filter(f => f.source.includes("docker") || f.source.includes("kubernetes"));
    const containerSecrets = findings.filter(f =>
      f.source.includes("etcd") || f.title.toLowerCase().includes("secret")
    );

    if (dockerFindings.length > 0 && containerSecrets.length > 0) {
      const chain = [dockerFindings[0].id, containerSecrets[0].id];
      attackPaths.push({
        id: `ap-${crypto.randomUUID().substring(0, 8)}`,
        name: "Container Escape to Secret Theft",
        description: `An attacker can exploit ${dockerFindings[0].title} to gain container access, then extract secrets via ${containerSecrets[0].title}.`,
        findingChain: chain,
        tacticsTraversed: ["Initial Access", "Privilege Escalation", "Credential Access"],
        riskScore: 90,
        exploitability: 70,
        businessImpact: "Full cluster compromise through container escape and secret extraction.",
      });
      chain.forEach(id => correlatedIds.add(id));
    }

    // Pattern 4: ICS/OT Attack Path
    const icsFindings = findings.filter(f =>
      f.environment === "ics_ot" ||
      ["modbus", "dnp3", "bacnet", "ethernetip", "opcua"].includes(f.protocol || "")
    );

    if (icsFindings.length >= 2) {
      const chain = icsFindings.slice(0, 3).map(f => f.id);
      attackPaths.push({
        id: `ap-${crypto.randomUUID().substring(0, 8)}`,
        name: "ICS/OT Process Manipulation",
        description: `Multiple ICS protocol exposures (${icsFindings.map(f => f.protocol).join(", ")}) allow an attacker to enumerate and manipulate industrial control processes.`,
        findingChain: chain,
        tacticsTraversed: ["Initial Access", "Discovery", "Impair Process Control"],
        riskScore: 98,
        exploitability: 60,
        businessImpact: "Physical process disruption with potential safety implications for critical infrastructure.",
      });
      chain.forEach(id => correlatedIds.add(id));
    }

    const uncorrelatedFindings = findings
      .filter(f => !correlatedIds.has(f.id))
      .map(f => f.id);

    return {
      attackPaths,
      uncorrelatedFindings,
      reasoning: `Heuristic correlation identified ${attackPaths.length} attack paths from ${findings.length} findings. ${uncorrelatedFindings.length} findings could not be correlated into attack chains.`,
    };
  }

  // ─── 4. Enriched Narratives ───────────────────────────────────────────

  /**
   * Generate enriched narratives for findings using LLM.
   */
  async enrichFinding(
    finding: ScanFinding,
    classification?: AssetClassification
  ): Promise<EnrichedNarrative> {
    try {
      const llm = await getLLM();
      return await this.llmEnrichFinding(llm, finding, classification);
    } catch {
      return this.heuristicEnrichFinding(finding, classification);
    }
  }

  private async llmEnrichFinding(
    llm: any,
    finding: ScanFinding,
    classification?: AssetClassification
  ): Promise<EnrichedNarrative> {
    const response = await llm({
      messages: [
        {
          role: "system",
          content: `You are an expert cybersecurity analyst writing finding narratives for a penetration test report. Write clear, actionable narratives that explain the technical impact and business risk. Tailor the language to the target environment (cloud/IoT/ICS/container/traditional).`,
        },
        {
          role: "user",
          content: [
            `Generate an enriched narrative for this finding:`,
            ``,
            `Title: ${finding.title}`,
            `Severity: ${finding.severity}`,
            `Description: ${finding.description}`,
            `Target: ${finding.target}`,
            `Protocol: ${finding.protocol || "N/A"}`,
            `CVEs: ${finding.cves?.join(", ") || "None"}`,
            `CWEs: ${finding.cwes?.join(", ") || "None"}`,
            `MITRE ATT&CK: ${finding.techniqueIds?.join(", ") || "None"}`,
            `Environment: ${classification?.environment || finding.environment || "unknown"}`,
            `Industry: ${classification?.inferredIndustry || "unknown"}`,
            ``,
            `Provide: technical narrative, executive summary, prioritized remediation steps, business impact assessment, and compliance implications.`,
          ].join("\n"),
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "enriched_narrative",
          strict: true,
          schema: {
            type: "object",
            properties: {
              technicalNarrative: { type: "string" },
              executiveSummary: { type: "string" },
              remediationSteps: { type: "array", items: { type: "string" } },
              businessImpact: { type: "string" },
              complianceImplications: { type: "array", items: { type: "string" } },
            },
            required: ["technicalNarrative", "executiveSummary", "remediationSteps", "businessImpact", "complianceImplications"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");

    const parsed = JSON.parse(content);

    return {
      findingId: finding.id,
      ...parsed,
    };
  }

  private heuristicEnrichFinding(
    finding: ScanFinding,
    classification?: AssetClassification
  ): EnrichedNarrative {
    const env = classification?.environment || finding.environment || "traditional";

    const envContext: Record<string, string> = {
      traditional: "standard IT infrastructure",
      cloud: "cloud-hosted infrastructure",
      iot: "IoT device ecosystem",
      ics_ot: "industrial control system environment",
      container: "containerized infrastructure",
      hybrid: "hybrid multi-environment infrastructure",
      unknown: "the target infrastructure",
    };

    return {
      findingId: finding.id,
      technicalNarrative: `${finding.description} This finding was detected in ${envContext[env] || envContext.unknown}. ${finding.cves?.length ? `The vulnerability is tracked as ${finding.cves.join(", ")}.` : ""} ${finding.cwes?.length ? `The underlying weakness is classified as ${finding.cwes.join(", ")}.` : ""}`,
      executiveSummary: `A ${finding.severity}-severity security issue was identified: ${finding.title}. This affects ${finding.target} and could impact the confidentiality, integrity, or availability of ${envContext[env] || envContext.unknown}.`,
      remediationSteps: finding.remediation
        ? finding.remediation.split(". ").filter(s => s.trim().length > 0).map(s => s.trim() + (s.endsWith(".") ? "" : "."))
        : ["Review the finding details and apply vendor-recommended patches.", "Implement compensating controls if immediate patching is not possible."],
      businessImpact: `This ${finding.severity}-severity finding in ${envContext[env] || envContext.unknown} could lead to ${finding.severity === "critical" || finding.severity === "high" ? "significant data breach, service disruption, or regulatory non-compliance" : "information disclosure or reduced security posture"}.`,
      complianceImplications: this.getComplianceImplications(finding, classification),
    };
  }

  private getComplianceImplications(
    finding: ScanFinding,
    classification?: AssetClassification
  ): string[] {
    const implications: string[] = [];
    const frameworks = classification?.applicableCompliance || [];

    if (frameworks.includes("nist_800_53") || frameworks.includes("fedramp")) {
      implications.push(`NIST 800-53: Potential violation of ${finding.cwes?.includes("CWE-306") ? "IA-2 (Identification and Authentication)" : "SC-7 (Boundary Protection)"}`);
    }
    if (frameworks.includes("pci_dss")) {
      implications.push(`PCI DSS: May violate Requirement ${finding.cwes?.includes("CWE-327") ? "4 (Encrypt transmission of cardholder data)" : "6 (Develop and maintain secure systems)"}`);
    }
    if (frameworks.includes("iec_62443")) {
      implications.push(`IEC 62443: Potential non-compliance with ${finding.severity === "critical" ? "SR 1.1 (Human user identification and authentication)" : "SR 3.1 (Communication integrity)"}`);
    }
    if (frameworks.includes("hipaa")) {
      implications.push("HIPAA: Potential violation of the Security Rule technical safeguards");
    }

    if (implications.length === 0) {
      implications.push("Review against applicable organizational security policies and regulatory requirements.");
    }

    return implications;
  }

  // ─── 5. Compliance Mapping ────────────────────────────────────────────

  /**
   * Map a finding to applicable compliance framework controls.
   */
  async mapToCompliance(
    finding: ScanFinding,
    frameworks: ComplianceFramework[]
  ): Promise<ComplianceMapping[]> {
    try {
      const llm = await getLLM();
      return await this.llmMapCompliance(llm, finding, frameworks);
    } catch {
      return this.heuristicMapCompliance(finding, frameworks);
    }
  }

  private async llmMapCompliance(
    llm: any,
    finding: ScanFinding,
    frameworks: ComplianceFramework[]
  ): Promise<ComplianceMapping[]> {
    const response = await llm({
      messages: [
        {
          role: "system",
          content: `You are a compliance expert mapping security findings to regulatory framework controls. Provide accurate control mappings with confidence levels.`,
        },
        {
          role: "user",
          content: [
            `Map this finding to the specified compliance frameworks:`,
            ``,
            `Finding: ${finding.title}`,
            `Severity: ${finding.severity}`,
            `CWEs: ${finding.cwes?.join(", ") || "None"}`,
            `CVEs: ${finding.cves?.join(", ") || "None"}`,
            `Protocol: ${finding.protocol || "N/A"}`,
            ``,
            `Frameworks: ${frameworks.join(", ")}`,
          ].join("\n"),
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "compliance_mappings",
          strict: true,
          schema: {
            type: "object",
            properties: {
              mappings: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    framework: { type: "string" },
                    controlId: { type: "string" },
                    controlTitle: { type: "string" },
                    status: { type: "string", enum: ["compliant", "non_compliant", "partially_compliant", "not_applicable"] },
                    confidence: { type: "integer" },
                  },
                  required: ["framework", "controlId", "controlTitle", "status", "confidence"],
                  additionalProperties: false,
                },
              },
            },
            required: ["mappings"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");

    const parsed = JSON.parse(content);
    return parsed.mappings as ComplianceMapping[];
  }

  private heuristicMapCompliance(
    finding: ScanFinding,
    frameworks: ComplianceFramework[]
  ): ComplianceMapping[] {
    const mappings: ComplianceMapping[] = [];

    // CWE to NIST 800-53 control mapping
    const cweToNist: Record<string, { controlId: string; controlTitle: string }> = {
      "CWE-306": { controlId: "IA-2", controlTitle: "Identification and Authentication (Organizational Users)" },
      "CWE-284": { controlId: "AC-3", controlTitle: "Access Enforcement" },
      "CWE-327": { controlId: "SC-13", controlTitle: "Cryptographic Protection" },
      "CWE-200": { controlId: "SC-28", controlTitle: "Protection of Information at Rest" },
      "CWE-79": { controlId: "SI-10", controlTitle: "Information Input Validation" },
      "CWE-89": { controlId: "SI-10", controlTitle: "Information Input Validation" },
      "CWE-918": { controlId: "SC-7", controlTitle: "Boundary Protection" },
      "CWE-732": { controlId: "AC-6", controlTitle: "Least Privilege" },
      "CWE-319": { controlId: "SC-8", controlTitle: "Transmission Confidentiality and Integrity" },
      "CWE-295": { controlId: "SC-12", controlTitle: "Cryptographic Key Establishment and Management" },
      "CWE-521": { controlId: "IA-5", controlTitle: "Authenticator Management" },
      "CWE-798": { controlId: "IA-5", controlTitle: "Authenticator Management" },
      "CWE-311": { controlId: "SC-8", controlTitle: "Transmission Confidentiality and Integrity" },
      "CWE-250": { controlId: "AC-6", controlTitle: "Least Privilege" },
    };

    for (const framework of frameworks) {
      if (framework === "nist_800_53" || framework === "fedramp") {
        for (const cwe of finding.cwes || []) {
          const mapping = cweToNist[cwe];
          if (mapping) {
            mappings.push({
              framework,
              controlId: mapping.controlId,
              controlTitle: mapping.controlTitle,
              status: "non_compliant",
              confidence: 80,
            });
          }
        }
      }

      if (framework === "pci_dss") {
        if (finding.cwes?.some(c => ["CWE-327", "CWE-319", "CWE-311"].includes(c))) {
          mappings.push({
            framework: "pci_dss",
            controlId: "4.1",
            controlTitle: "Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission",
            status: "non_compliant",
            confidence: 75,
          });
        }
        if (finding.cwes?.some(c => ["CWE-306", "CWE-521", "CWE-798"].includes(c))) {
          mappings.push({
            framework: "pci_dss",
            controlId: "8.2",
            controlTitle: "Employ at least one method to authenticate all users",
            status: "non_compliant",
            confidence: 75,
          });
        }
      }

      if (framework === "iec_62443") {
        if (finding.cwes?.some(c => ["CWE-306", "CWE-284"].includes(c))) {
          mappings.push({
            framework: "iec_62443",
            controlId: "SR 1.1",
            controlTitle: "Human user identification and authentication",
            status: "non_compliant",
            confidence: 70,
          });
        }
      }
    }

    return mappings;
  }

  // ─── 6. Risk Contextualization ────────────────────────────────────────

  /**
   * Adjust risk scores based on environmental context.
   */
  contextualizeRisk(
    finding: ScanFinding,
    classification: AssetClassification
  ): number {
    let modifier = 1.0;

    // Environment-based modifiers
    switch (classification.environment) {
      case "ics_ot":
        // ICS findings are inherently more critical due to safety implications
        modifier *= 1.3;
        if (finding.protocol && ["modbus", "dnp3", "bacnet", "ethernetip", "opcua"].includes(finding.protocol)) {
          modifier *= 1.2; // ICS protocol findings are even more critical
        }
        break;
      case "cloud":
        // Cloud misconfigs with credential exposure are critical
        if (finding.techniqueIds?.some(t => t.startsWith("T1552"))) {
          modifier *= 1.2;
        }
        break;
      case "iot":
        // IoT devices in critical infrastructure
        if (classification.inferredIndustry === "healthcare" || classification.inferredIndustry === "manufacturing") {
          modifier *= 1.15;
        }
        break;
      case "container":
        // Container escape paths
        if (finding.techniqueIds?.some(t => t === "T1611")) {
          modifier *= 1.25;
        }
        break;
    }

    // Criticality-based modifiers
    switch (classification.inferredCriticality) {
      case "critical": modifier *= 1.2; break;
      case "high": modifier *= 1.1; break;
      case "low": modifier *= 0.8; break;
    }

    const baseScore = finding.riskScore?.composite || 50;
    return Math.min(100, Math.round(baseScore * modifier));
  }
}

// ─── Singleton ─────────────────────────────────────────────────────────────

let _contextEngine: ContextEngine | null = null;

export function getContextEngine(): ContextEngine {
  if (!_contextEngine) {
    _contextEngine = new ContextEngine();
  }
  return _contextEngine;
}
