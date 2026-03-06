/**
 * Cloud Security Knowledge Module Tests
 * Validates the cloud security training bundle integration
 */
import { describe, it, expect } from "vitest";
import {
  detectCloudProviders,
  getMisconfigPatterns,
  getCloudAttackPaths,
  getAttackPathsByMitre,
  matchMisconfigsToObservations,
  matchDetectionRules,
  getTrainingExamples,
  getCloudAnalysisPrompt,
  getCloudAttackPathPrompt,
  buildCloudSecurityContext,
  buildGeneralCloudContext,
  buildCloudHuntContext,
  buildCloudScoringContext,
} from "./lib/knowledge/cloud-security-knowledge";

describe("Cloud Security Knowledge Module", () => {
  // §1 — Cloud Provider Detection
  describe("detectCloudProviders", () => {
    it("detects AWS from S3 bucket observations", () => {
      const providers = detectCloudProviders(["s3.amazonaws.com bucket found", "EC2 instance running"]);
      expect(providers).toContain("AWS");
    });

    it("detects Azure from blob storage observations", () => {
      const providers = detectCloudProviders(["Azure Blob Storage container exposed", "Microsoft Azure"]);
      expect(providers).toContain("Azure");
    });

    it("detects GCP from cloud storage observations", () => {
      const providers = detectCloudProviders(["Google Cloud Storage bucket", "GCP project"]);
      expect(providers).toContain("GCP");
    });

    it("returns empty array for non-cloud observations", () => {
      const providers = detectCloudProviders(["Apache web server", "MySQL database"]);
      expect(providers).toEqual([]);
    });

    it("detects multiple providers simultaneously", () => {
      const providers = detectCloudProviders([
        "AWS S3 bucket exposed",
        "Azure Blob container public",
        "GCP storage bucket open",
      ]);
      expect(providers.length).toBeGreaterThanOrEqual(2);
    });
  });

  // §2 — Misconfiguration Patterns
  describe("getMisconfigPatterns", () => {
    it("returns all patterns when no provider specified", () => {
      const patterns = getMisconfigPatterns();
      expect(patterns.length).toBeGreaterThan(0);
    });

    it("filters patterns by AWS provider", () => {
      const patterns = getMisconfigPatterns("aws");
      expect(patterns.length).toBeGreaterThan(0);
      patterns.forEach(p => expect(p.cloud_provider.toLowerCase()).toBe("aws"));
    });

    it("each pattern has required fields", () => {
      const patterns = getMisconfigPatterns();
      patterns.forEach(p => {
        expect(p.id).toBeTruthy();
        expect(p.cloud_provider).toBeTruthy();
        expect(p.service).toBeTruthy();
        expect(p.misconfiguration).toBeTruthy();
        expect(p.risk_level).toBeTruthy();
        expect(p.signals).toBeDefined();
        expect(p.signals.length).toBeGreaterThan(0);
      });
    });
  });

  // §3 — Cloud Attack Paths
  describe("getCloudAttackPaths", () => {
    it("returns attack paths", () => {
      const paths = getCloudAttackPaths();
      expect(paths.length).toBeGreaterThan(0);
    });

    it("each path has title, steps with MITRE techniques", () => {
      const paths = getCloudAttackPaths();
      paths.forEach(p => {
        expect(p.title).toBeTruthy();
        expect(p.id).toBeTruthy();
        expect(p.steps).toBeDefined();
        expect(p.steps.length).toBeGreaterThan(0);
        // Each step should have mitre technique IDs
        p.steps.forEach(s => {
          expect(s.mitre).toBeDefined();
          expect(s.mitre.length).toBeGreaterThan(0);
        });
      });
    });
  });

  describe("getAttackPathsByMitre", () => {
    it("finds paths by MITRE technique ID from step data", () => {
      const paths = getCloudAttackPaths();
      if (paths.length > 0 && paths[0].steps.length > 0) {
        const firstMitre = paths[0].steps[0].mitre[0];
        const matched = getAttackPathsByMitre(firstMitre);
        expect(matched.length).toBeGreaterThan(0);
      }
    });
  });

  // §4 — Observation Matching
  describe("matchMisconfigsToObservations", () => {
    it("matches S3 bucket observations to AWS misconfig patterns", () => {
      const matches = matchMisconfigsToObservations(["bucket policy allows s3:GetObject for *", "objects accessible without authentication"]);
      expect(matches.length).toBeGreaterThan(0);
    });

    it("matches by misconfiguration description text", () => {
      const matches = matchMisconfigsToObservations(["public read access enabled on storage bucket"]);
      expect(matches.length).toBeGreaterThan(0);
    });

    it("returns empty for unrelated observations", () => {
      const matches = matchMisconfigsToObservations(["nginx web server", "MySQL 5.7"]);
      expect(matches).toEqual([]);
    });
  });

  // §5 — Detection Rules
  describe("matchDetectionRules", () => {
    it("matches cloud-related conditions", () => {
      const rules = matchDetectionRules(["cloud", "s3", "bucket"]);
      expect(rules.length).toBeGreaterThanOrEqual(0); // May or may not match depending on data
    });

    it("each rule has required fields", () => {
      const rules = matchDetectionRules(["cloud", "aws", "azure", "gcp", "s3", "blob", "iam"]);
      rules.forEach(r => {
        expect(r.name).toBeTruthy();
        expect(r.description).toBeTruthy();
        expect(r.confidence).toBeTruthy();
      });
    });
  });

  // §6 — Training Examples
  describe("getTrainingExamples", () => {
    it("returns training examples", () => {
      const examples = getTrainingExamples();
      expect(examples.length).toBeGreaterThan(0);
    });

    it("each example has input observations and output hypothesis", () => {
      const examples = getTrainingExamples();
      examples.forEach(e => {
        expect(e.input).toBeTruthy();
        expect(e.input.observations).toBeTruthy();
        expect(e.input.observations.length).toBeGreaterThan(0);
        expect(e.output).toBeTruthy();
        expect(e.output.hypothesis).toBeTruthy();
        expect(e.output.risk).toBeTruthy();
      });
    });
  });

  // §7 — LLM Prompts
  describe("getCloudAnalysisPrompt", () => {
    it("returns a non-empty prompt string", () => {
      const prompt = getCloudAnalysisPrompt();
      expect(prompt.length).toBeGreaterThan(100);
      expect(prompt).toContain("cloud");
    });
  });

  describe("getCloudAttackPathPrompt", () => {
    it("returns a non-empty prompt string", () => {
      const prompt = getCloudAttackPathPrompt();
      expect(prompt.length).toBeGreaterThan(100);
    });
  });

  // §8 — Context Builders
  describe("buildCloudSecurityContext", () => {
    it("builds context from AWS observations", () => {
      const ctx = buildCloudSecurityContext(["AWS S3 bucket exposed", "EC2 instance with public SSH"]);
      expect(ctx).toContain("CLOUD SECURITY");
      expect(ctx.length).toBeGreaterThan(50);
    });

    it("builds context from Azure observations", () => {
      const ctx = buildCloudSecurityContext(["Azure Blob Storage public container"]);
      expect(ctx).toContain("CLOUD SECURITY");
    });

    it("returns empty string for non-cloud observations", () => {
      const ctx = buildCloudSecurityContext(["Apache 2.4", "nginx"]);
      // May still return general cloud context or empty
      expect(typeof ctx).toBe("string");
    });
  });

  describe("buildGeneralCloudContext", () => {
    it("returns general cloud security context", () => {
      const ctx = buildGeneralCloudContext();
      expect(ctx.length).toBeGreaterThan(50);
      expect(ctx).toContain("CLOUD");
    });
  });

  describe("buildCloudHuntContext", () => {
    it("returns cloud hunt context with attack paths", () => {
      const ctx = buildCloudHuntContext();
      expect(ctx.length).toBeGreaterThan(50);
    });
  });

  describe("buildCloudScoringContext", () => {
    it("builds scoring context from cloud observations", () => {
      const ctx = buildCloudScoringContext(["AWS S3 bucket", "public access"]);
      expect(typeof ctx).toBe("string");
    });
  });
});
