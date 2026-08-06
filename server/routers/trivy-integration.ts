/**
 * Trivy Container Image Vulnerability Scanning Router
 *
 * Triggers Trivy scans on the ScanForge server to scan:
 * - Docker images for CVEs
 * - Container registries (ECR, ACR, GCR, Docker Hub)
 * - Filesystem/IaC scanning (Terraform, CloudFormation, Dockerfiles)
 * - SBOM generation
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { executeRawCommand } from "../lib/scan-server-executor";

// ── Types ──────────────────────────────────────────────────────────────────

export interface TrivyVulnerability {
  vulnerabilityId: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  title: string;
  description: string;
  references: string[];
  cvss?: { score: number; vector: string };
  publishedDate?: string;
}

export interface TrivyMisconfiguration {
  id: string;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  resolution: string;
  type: string;       // e.g. "Dockerfile", "Terraform", "CloudFormation"
  message: string;
  causeMetadata?: { resource: string; provider: string; service: string };
}

export interface TrivyScanResult {
  target: string;
  scanType: string;
  vulnerabilities: TrivyVulnerability[];
  misconfigurations: TrivyMisconfiguration[];
  summary: {
    totalVulns: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    totalMisconfigs: number;
  };
  rawOutput: string;
  durationMs: number;
  errors: string[];
}

// ── Parsers ────────────────────────────────────────────────────────────────

function parseTrivyJsonOutput(stdout: string): {
  vulnerabilities: TrivyVulnerability[];
  misconfigurations: TrivyMisconfiguration[];
} {
  const vulnerabilities: TrivyVulnerability[] = [];
  const misconfigurations: TrivyMisconfiguration[] = [];

  try {
    const report = JSON.parse(stdout);
    const results = report.Results || [];

    for (const result of results) {
      // Parse vulnerabilities
      for (const vuln of result.Vulnerabilities || []) {
        vulnerabilities.push({
          vulnerabilityId: vuln.VulnerabilityID || "",
          pkgName: vuln.PkgName || "",
          installedVersion: vuln.InstalledVersion || "",
          fixedVersion: vuln.FixedVersion || "",
          severity: normalizeTrivySeverity(vuln.Severity || "UNKNOWN"),
          title: vuln.Title || "",
          description: vuln.Description || "",
          references: vuln.References || [],
          cvss: vuln.CVSS?.nvd ? {
            score: vuln.CVSS.nvd.V3Score || vuln.CVSS.nvd.V2Score || 0,
            vector: vuln.CVSS.nvd.V3Vector || vuln.CVSS.nvd.V2Vector || "",
          } : undefined,
          publishedDate: vuln.PublishedDate,
        });
      }

      // Parse misconfigurations
      for (const mc of result.Misconfigurations || []) {
        misconfigurations.push({
          id: mc.ID || "",
          title: mc.Title || "",
          description: mc.Description || "",
          severity: normalizeTrivySeverity(mc.Severity || "MEDIUM") as TrivyMisconfiguration["severity"],
          resolution: mc.Resolution || "",
          type: mc.Type || result.Type || "",
          message: mc.Message || "",
          causeMetadata: mc.CauseMetadata ? {
            resource: mc.CauseMetadata.Resource || "",
            provider: mc.CauseMetadata.Provider || "",
            service: mc.CauseMetadata.Service || "",
          } : undefined,
        });
      }
    }
  } catch {
    // If not valid JSON, return empty
  }

  return { vulnerabilities, misconfigurations };
}

function normalizeTrivySeverity(s: string): TrivyVulnerability["severity"] {
  const upper = s.toUpperCase();
  if (upper === "CRITICAL") return "CRITICAL";
  if (upper === "HIGH") return "HIGH";
  if (upper === "MEDIUM") return "MEDIUM";
  if (upper === "LOW") return "LOW";
  return "UNKNOWN";
}

// ── Router ─────────────────────────────────────────────────────────────────

export const trivyIntegrationRouter = router({

  // ── Check if Trivy is installed on scan server ──
  checkAvailability: protectedProcedure
    .query(async () => {
      try {
        const result = await executeRawCommand("trivy --version 2>&1 || echo 'NOT_INSTALLED'", 15);
        const output = (result.stdout || "").trim();
        if (output.includes("NOT_INSTALLED") || output.includes("not found")) {
          return { installed: false, version: "" };
        }
        const versionMatch = output.match(/Version:\s*(\S+)/);
        return {
          installed: true,
          version: versionMatch?.[1] || output.split("\n")[0].trim(),
        };
      } catch {
        return { installed: false, version: "" };
      }
    }),

  // ── Scan a Docker image for vulnerabilities ──
  scanImage: protectedProcedure
    .input(z.object({
      image: z.string().min(1),
      severity: z.array(z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])).optional(),
      ignoreUnfixed: z.boolean().default(false),
      timeoutSeconds: z.number().min(30).max(1800).default(300),
      registryCredentials: z.object({
        username: z.string(),
        password: z.string(),
        registry: z.string().optional(),
      }).optional(),
    }))
    .mutation(async ({ input }) => {
      const startTime = Date.now();
      const errors: string[] = [];

      let cmd = `trivy image --format json --quiet`;

      if (input.severity?.length) {
        cmd += ` --severity ${input.severity.join(",")}`;
      }
      if (input.ignoreUnfixed) {
        cmd += ` --ignore-unfixed`;
      }

      // Add registry credentials if provided
      let envPrefix = "";
      if (input.registryCredentials) {
        envPrefix = `TRIVY_USERNAME='${input.registryCredentials.username}' ` +
          `TRIVY_PASSWORD='${input.registryCredentials.password}' `;
        if (input.registryCredentials.registry) {
          envPrefix += `TRIVY_REGISTRY='${input.registryCredentials.registry}' `;
        }
      }

      cmd = `${envPrefix}${cmd} '${input.image}'`;

      try {
        const result = await executeRawCommand(cmd, input.timeoutSeconds);
        const stdout = result.stdout || "";
        const stderr = result.stderr || "";

        if (stderr && !stdout) {
          errors.push(stderr.substring(0, 500));
        }

        const { vulnerabilities, misconfigurations } = parseTrivyJsonOutput(stdout);

        const scanResult: TrivyScanResult = {
          target: input.image,
          scanType: "image",
          vulnerabilities,
          misconfigurations,
          summary: {
            totalVulns: vulnerabilities.length,
            critical: vulnerabilities.filter(v => v.severity === "CRITICAL").length,
            high: vulnerabilities.filter(v => v.severity === "HIGH").length,
            medium: vulnerabilities.filter(v => v.severity === "MEDIUM").length,
            low: vulnerabilities.filter(v => v.severity === "LOW").length,
            totalMisconfigs: misconfigurations.length,
          },
          rawOutput: stdout.substring(0, 50000),
          durationMs: Date.now() - startTime,
          errors,
        };

        return scanResult;
      } catch (e: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Trivy image scan failed: ${e.message}`,
        });
      }
    }),

  // ── Scan a filesystem/IaC for misconfigurations ──
  scanFilesystem: protectedProcedure
    .input(z.object({
      path: z.string().min(1),
      scanners: z.array(z.enum(["vuln", "misconfig", "secret", "license"])).default(["vuln", "misconfig", "secret"]),
      severity: z.array(z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"])).optional(),
      timeoutSeconds: z.number().min(30).max(1800).default(300),
    }))
    .mutation(async ({ input }) => {
      const startTime = Date.now();
      const errors: string[] = [];

      let cmd = `trivy fs --format json --quiet`;
      cmd += ` --scanners ${input.scanners.join(",")}`;

      if (input.severity?.length) {
        cmd += ` --severity ${input.severity.join(",")}`;
      }

      cmd += ` '${input.path}'`;

      try {
        const result = await executeRawCommand(cmd, input.timeoutSeconds);
        const stdout = result.stdout || "";
        const { vulnerabilities, misconfigurations } = parseTrivyJsonOutput(stdout);

        return {
          target: input.path,
          scanType: "filesystem",
          vulnerabilities,
          misconfigurations,
          summary: {
            totalVulns: vulnerabilities.length,
            critical: vulnerabilities.filter(v => v.severity === "CRITICAL").length,
            high: vulnerabilities.filter(v => v.severity === "HIGH").length,
            medium: vulnerabilities.filter(v => v.severity === "MEDIUM").length,
            low: vulnerabilities.filter(v => v.severity === "LOW").length,
            totalMisconfigs: misconfigurations.length,
          },
          rawOutput: stdout.substring(0, 50000),
          durationMs: Date.now() - startTime,
          errors,
        } as TrivyScanResult;
      } catch (e: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Trivy filesystem scan failed: ${e.message}`,
        });
      }
    }),

  // ── Generate SBOM for a Docker image ──
  generateSBOM: protectedProcedure
    .input(z.object({
      image: z.string().min(1),
      format: z.enum(["cyclonedx", "spdx", "spdx-json"]).default("cyclonedx"),
      timeoutSeconds: z.number().min(30).max(600).default(120),
    }))
    .mutation(async ({ input }) => {
      const startTime = Date.now();

      const cmd = `trivy image --format ${input.format} --quiet '${input.image}'`;

      try {
        const result = await executeRawCommand(cmd, input.timeoutSeconds);
        return {
          image: input.image,
          format: input.format,
          sbom: result.stdout || "",
          durationMs: Date.now() - startTime,
        };
      } catch (e: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `SBOM generation failed: ${e.message}`,
        });
      }
    }),

  // ── List Docker images on the scan server ──
  listLocalImages: protectedProcedure
    .query(async () => {
      try {
        const result = await executeRawCommand(
          "docker images --format '{{json .}}' 2>/dev/null || echo '[]'",
          15
        );
        const images: Array<{ repository: string; tag: string; id: string; size: string; created: string }> = [];
        const lines = (result.stdout || "").split("\n").filter(l => l.trim());
        for (const line of lines) {
          try {
            const img = JSON.parse(line);
            images.push({
              repository: img.Repository || "",
              tag: img.Tag || "",
              id: img.ID || "",
              size: img.Size || "",
              created: img.CreatedSince || img.CreatedAt || "",
            });
          } catch { /* skip */ }
        }
        return images;
      } catch {
        return [];
      }
    }),

  // ── Self-scan: scan all local Docker images on scan server ──
  selfScanAllImages: protectedProcedure
    .input(z.object({
      severity: z.array(z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])).default(["CRITICAL", "HIGH"]),
      ignoreUnfixed: z.boolean().default(true),
      maxImages: z.number().min(1).max(50).default(25),
      timeoutPerImage: z.number().min(30).max(600).default(120),
    }).optional())
    .mutation(async ({ input }) => {
      const opts = input || { severity: ["CRITICAL", "HIGH"], ignoreUnfixed: true, maxImages: 25, timeoutPerImage: 120 };
      const startTime = Date.now();
      const errors: string[] = [];

      // Step 1: List all local Docker images
      let images: Array<{ repository: string; tag: string; id: string }> = [];
      try {
        const listResult = await executeRawCommand(
          "docker images --format '{{json .}}' 2>/dev/null",
          15
        );
        const lines = (listResult.stdout || "").split("\n").filter(l => l.trim());
        for (const line of lines) {
          try {
            const img = JSON.parse(line);
            if (img.Repository && img.Repository !== "<none>") {
              images.push({
                repository: img.Repository,
                tag: img.Tag || "latest",
                id: img.ID || "",
              });
            }
          } catch { /* skip */ }
        }
      } catch (e: any) {
        errors.push(`Failed to list images: ${e.message}`);
      }

      // Limit to maxImages
      if (images.length > opts.maxImages) {
        images = images.slice(0, opts.maxImages);
      }

      // Step 2: Scan each image
      const imageResults: Array<{
        image: string;
        tag: string;
        id: string;
        vulnerabilities: TrivyVulnerability[];
        summary: { critical: number; high: number; medium: number; low: number; total: number };
        error?: string;
      }> = [];

      for (const img of images) {
        const imageRef = `${img.repository}:${img.tag}`;
        try {
          let cmd = `trivy image --format json --quiet`;
          if (opts.severity.length) cmd += ` --severity ${opts.severity.join(",")}`;
          if (opts.ignoreUnfixed) cmd += ` --ignore-unfixed`;
          cmd += ` '${imageRef}'`;

          const result = await executeRawCommand(cmd, opts.timeoutPerImage);
          const { vulnerabilities } = parseTrivyJsonOutput(result.stdout || "");

          imageResults.push({
            image: img.repository,
            tag: img.tag,
            id: img.id,
            vulnerabilities,
            summary: {
              critical: vulnerabilities.filter(v => v.severity === "CRITICAL").length,
              high: vulnerabilities.filter(v => v.severity === "HIGH").length,
              medium: vulnerabilities.filter(v => v.severity === "MEDIUM").length,
              low: vulnerabilities.filter(v => v.severity === "LOW").length,
              total: vulnerabilities.length,
            },
          });
        } catch (e: any) {
          imageResults.push({
            image: img.repository,
            tag: img.tag,
            id: img.id,
            vulnerabilities: [],
            summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
            error: e.message?.substring(0, 200),
          });
          errors.push(`${imageRef}: ${e.message?.substring(0, 100)}`);
        }
      }

      // Step 3: Aggregate results
      const totalVulns = imageResults.reduce((sum, r) => sum + r.summary.total, 0);
      const totalCritical = imageResults.reduce((sum, r) => sum + r.summary.critical, 0);
      const totalHigh = imageResults.reduce((sum, r) => sum + r.summary.high, 0);

      return {
        scannedImages: imageResults.length,
        totalImages: images.length,
        summary: {
          totalVulnerabilities: totalVulns,
          critical: totalCritical,
          high: totalHigh,
          medium: imageResults.reduce((sum, r) => sum + r.summary.medium, 0),
          low: imageResults.reduce((sum, r) => sum + r.summary.low, 0),
          imagesWithCritical: imageResults.filter(r => r.summary.critical > 0).length,
          imagesWithHigh: imageResults.filter(r => r.summary.high > 0).length,
          cleanImages: imageResults.filter(r => r.summary.total === 0).length,
        },
        imageResults,
        durationMs: Date.now() - startTime,
        errors,
      };
    }),

  // ── Self-scan: scan scan server filesystem for IaC misconfigs ──
  selfScanFilesystem: protectedProcedure
    .input(z.object({
      paths: z.array(z.string()).default(["/root", "/etc", "/opt"]),
      scanners: z.array(z.enum(["vuln", "misconfig", "secret"])).default(["misconfig", "secret"]),
      timeoutSeconds: z.number().min(30).max(1800).default(300),
    }).optional())
    .mutation(async ({ input }) => {
      const opts = input || { paths: ["/root", "/etc", "/opt"], scanners: ["misconfig", "secret"], timeoutSeconds: 300 };
      const startTime = Date.now();
      const allMisconfigs: TrivyMisconfiguration[] = [];
      const errors: string[] = [];

      for (const scanPath of opts.paths) {
        try {
          const cmd = `trivy fs --format json --quiet --scanners ${opts.scanners.join(",")} '${scanPath}'`;
          const result = await executeRawCommand(cmd, opts.timeoutSeconds);
          const { misconfigurations } = parseTrivyJsonOutput(result.stdout || "");
          allMisconfigs.push(...misconfigurations);
        } catch (e: any) {
          errors.push(`${scanPath}: ${e.message?.substring(0, 200)}`);
        }
      }

      return {
        scannedPaths: opts.paths,
        totalMisconfigurations: allMisconfigs.length,
        critical: allMisconfigs.filter(m => m.severity === "CRITICAL").length,
        high: allMisconfigs.filter(m => m.severity === "HIGH").length,
        medium: allMisconfigs.filter(m => m.severity === "MEDIUM").length,
        low: allMisconfigs.filter(m => m.severity === "LOW").length,
        misconfigurations: allMisconfigs,
        durationMs: Date.now() - startTime,
        errors,
      };
    }),
});
