/**
 * Tests for createFromScan stack profile generation and categorizeTechnologies
 * @author Harrison Cook — AceofCloud
 */
import { describe, it, expect } from "vitest";
import { categorizeTechnologies } from "./routers/stack-profile";

describe("categorizeTechnologies", () => {
  it("categorizes common web technologies correctly", () => {
    const techs = ["React", "Node.js", "PostgreSQL", "Docker", "AWS"];
    const result = categorizeTechnologies(techs);
    expect(result.webFrameworks).toContain("React");
    expect(result.databasesList).toContain("PostgreSQL");
    expect(result.devopsAndCi).toContain("Docker");
    expect(result.cloudServices).toContain("AWS");
  });

  it("categorizes AI/ML technologies into correct buckets", () => {
    const techs = ["LangChain", "FAISS", "Jupyter", "TensorFlow", "OpenAI"];
    const result = categorizeTechnologies(techs);
    expect(result.genaiAndLlm).toContain("LangChain");
    expect(result.genaiAndLlm).toContain("OpenAI");
    expect(result.dataAndMl).toContain("FAISS");
    expect(result.dataAndMl).toContain("Jupyter");
    expect(result.dataAndMl).toContain("TensorFlow");
  });

  it("categorizes programming languages correctly", () => {
    const techs = ["Python", "JavaScript", "Go", "Rust"];
    const result = categorizeTechnologies(techs);
    expect(result.languages).toContain("Python");
    expect(result.languages).toContain("JavaScript");
    expect(result.languages).toContain("Go");
    expect(result.languages).toContain("Rust");
  });

  it("categorizes infrastructure and DevOps tools", () => {
    const techs = ["Nginx", "Kubernetes", "Terraform", "GitHub Actions", "Linux"];
    const result = categorizeTechnologies(techs);
    expect(result.devopsAndCi).toContain("Nginx");
    expect(result.devopsAndCi).toContain("Kubernetes");
    expect(result.devopsAndCi).toContain("Terraform");
    expect(result.devopsAndCi).toContain("GitHub Actions");
    expect(result.infrastructure).toContain("Linux");
  });

  it("categorizes security tools correctly", () => {
    const techs = ["ModSecurity", "Vault", "Auth0", "Splunk"];
    const result = categorizeTechnologies(techs);
    expect(result.securityTools).toContain("ModSecurity");
    expect(result.securityTools).toContain("Vault");
    expect(result.securityTools).toContain("Auth0");
    expect(result.securityTools).toContain("Splunk");
  });

  it("Cloudflare WAF categorizes to cloudServices (cloudflare keyword matches first)", () => {
    const result = categorizeTechnologies(["Cloudflare WAF"]);
    expect(result.cloudServices).toContain("Cloudflare WAF");
  });

  it("puts unknown technologies in 'other' bucket", () => {
    const techs = ["CustomFramework", "ProprietaryTool", "InternalSDK"];
    const result = categorizeTechnologies(techs);
    expect(result.other).toContain("CustomFramework");
    expect(result.other).toContain("ProprietaryTool");
    expect(result.other).toContain("InternalSDK");
  });

  it("handles empty input gracefully", () => {
    const result = categorizeTechnologies([]);
    expect(result.languages).toHaveLength(0);
    expect(result.webFrameworks).toHaveLength(0);
    expect(result.other).toHaveLength(0);
  });

  it("handles case-insensitive matching", () => {
    const techs = ["REACT", "python", "DOCKER", "aws"];
    const result = categorizeTechnologies(techs);
    expect(result.webFrameworks).toContain("REACT");
    expect(result.languages).toContain("python");
    expect(result.devopsAndCi).toContain("DOCKER");
    expect(result.cloudServices).toContain("aws");
  });

  it("categorizes database technologies correctly", () => {
    const techs = ["MySQL", "Redis", "MongoDB", "Elasticsearch"];
    const result = categorizeTechnologies(techs);
    expect(result.databasesList).toContain("MySQL");
    expect(result.databasesList).toContain("Redis");
    expect(result.databasesList).toContain("MongoDB");
    expect(result.databasesList).toContain("Elasticsearch");
  });

  it("categorizes cloud services correctly", () => {
    const techs = ["Firebase", "Cloudflare", "Vercel", "Heroku", "DigitalOcean"];
    const result = categorizeTechnologies(techs);
    expect(result.cloudServices).toContain("Firebase");
    expect(result.cloudServices).toContain("Cloudflare");
    expect(result.cloudServices).toContain("Vercel");
    expect(result.cloudServices).toContain("Heroku");
    expect(result.cloudServices).toContain("DigitalOcean");
  });

  it("handles a realistic DI scan technology list", () => {
    const techs = [
      "Nginx", "React", "Node.js", "PostgreSQL", "Redis",
      "Docker", "AWS", "CloudFlare", "Python", "Streamlit",
      "LangChain", "FAISS", "GitHub Actions", "Grafana",
      "Ubuntu", "WordPress", "jQuery"
    ];
    const result = categorizeTechnologies(techs);
    // Should have items in multiple categories
    expect(result.webFrameworks.length).toBeGreaterThan(0);
    expect(result.devopsAndCi.length).toBeGreaterThan(0);
    expect(result.cloudServices.length).toBeGreaterThan(0);
    expect(result.dataAndMl.length).toBeGreaterThan(0);
    expect(result.genaiAndLlm.length).toBeGreaterThan(0);
    // Total categorized should equal input
    const totalCategorized = Object.values(result).flat().length;
    expect(totalCategorized).toBe(techs.length);
  });

  it("does not duplicate technologies across categories", () => {
    const techs = ["Firebase", "Cloudflare", "Docker", "Python", "React"];
    const result = categorizeTechnologies(techs);
    const allCategorized = Object.values(result).flat();
    const unique = new Set(allCategorized);
    expect(allCategorized.length).toBe(unique.size);
  });
});

describe("createFromScan integration", () => {
  it("categorizeTechnologies returns all required fields", () => {
    const result = categorizeTechnologies(["test"]);
    const requiredFields = [
      "languages", "webFrameworks", "dataAndMl", "genaiAndLlm",
      "cloudServices", "securityTools", "devopsAndCi", "databasesList",
      "infrastructure", "other"
    ];
    for (const field of requiredFields) {
      expect(result).toHaveProperty(field);
      expect(Array.isArray((result as any)[field])).toBe(true);
    }
  });

  it("handles Streamlit correctly (webFrameworks, not genaiAndLlm)", () => {
    const result = categorizeTechnologies(["Streamlit"]);
    expect(result.webFrameworks).toContain("Streamlit");
    expect(result.genaiAndLlm).not.toContain("Streamlit");
  });

  it("handles version-like strings in tech names gracefully", () => {
    const techs = ["nginx/1.21.0", "Apache/2.4.51", "PHP/8.1"];
    const result = categorizeTechnologies(techs);
    // nginx and apache should be categorized into devopsAndCi
    expect(result.devopsAndCi).toContain("nginx/1.21.0");
    expect(result.devopsAndCi).toContain("Apache/2.4.51");
    // PHP should be in languages
    expect(result.languages).toContain("PHP/8.1");
  });
});
