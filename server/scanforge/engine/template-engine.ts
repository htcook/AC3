/**
 * ScanForge Template Engine
 *
 * Loads and executes YAML-based scan templates. Each template defines:
 *   - Target protocol and request to send
 *   - Matchers to evaluate the response
 *   - Metadata (severity, CVEs, remediation, TI enrichment)
 *
 * Templates are loaded from the filesystem (server/scanforge/templates/*.yaml)
 * and can be hot-reloaded without restarting the service.
 *
 * This replaces hardcoded detection logic with a declarative, extensible
 * template system similar to Nuclei but tailored for the AC3 platform.
 */

import { readdir, readFile } from "fs/promises";
import { join, extname } from "path";
import { randomUUID } from "crypto";
import type {
  ScanTemplate,
  TemplateMatcher,
  TemplateRequest,
  ScanFinding,
  ScanTarget,
  ScanConfig,
  FindingEvidence,
  FindingSeverity,
} from "../types";

// ─── YAML Parser (lightweight, no external dependency) ─────────────────────
// We use a simple YAML subset parser to avoid adding js-yaml as a dependency.
// For production, swap this with the `yaml` npm package.

function parseYAML(content: string): any {
  // Use JSON-based YAML subset: templates can also be written as JSON
  // For full YAML support, install `yaml` package
  try {
    return JSON.parse(content);
  } catch {
    // Simple YAML parser for key: value pairs and arrays
    return parseSimpleYAML(content);
  }
}

function parseSimpleYAML(content: string): any {
  const lines = content.split("\n");
  const result: any = {};
  let currentKey = "";
  let currentArray: any[] | null = null;
  let currentObj: any = result;
  const stack: { obj: any; indent: number }[] = [{ obj: result, indent: -1 }];

  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, "");
    if (line.trim() === "" || line.trim().startsWith("#")) continue;

    const indent = line.search(/\S/);
    const trimmed = line.trim();

    // Array item
    if (trimmed.startsWith("- ")) {
      const value = trimmed.slice(2).trim();
      if (currentArray) {
        if (value.includes(": ")) {
          const obj: any = {};
          const [k, ...rest] = value.split(": ");
          obj[k.trim()] = rest.join(": ").trim().replace(/^["']|["']$/g, "");
          currentArray.push(obj);
        } else {
          currentArray.push(value.replace(/^["']|["']$/g, ""));
        }
      }
      continue;
    }

    // Key: value pair
    const colonIdx = trimmed.indexOf(":");
    if (colonIdx > 0) {
      const key = trimmed.slice(0, colonIdx).trim();
      const value = trimmed.slice(colonIdx + 1).trim();

      // Pop stack to correct level
      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
        stack.pop();
      }
      currentObj = stack[stack.length - 1].obj;

      if (value === "" || value === "|" || value === ">") {
        // Nested object or multiline string
        if (value === "" || value === "|" || value === ">") {
          currentObj[key] = {};
          stack.push({ obj: currentObj[key], indent });
          currentArray = null;
        }
      } else if (value === "[]") {
        currentObj[key] = [];
        currentArray = currentObj[key];
      } else {
        // Parse value
        let parsed: any = value.replace(/^["']|["']$/g, "");
        if (parsed === "true") parsed = true;
        else if (parsed === "false") parsed = false;
        else if (/^\d+$/.test(parsed)) parsed = parseInt(parsed, 10);
        else if (/^\d+\.\d+$/.test(parsed)) parsed = parseFloat(parsed);
        currentObj[key] = parsed;
        currentArray = null;
      }

      if (Array.isArray(currentObj[key])) {
        currentArray = currentObj[key];
      }
      currentKey = key;
    }
  }

  return result;
}

// ─── Template Store ────────────────────────────────────────────────────────

export class TemplateEngine {
  private templates: Map<string, ScanTemplate> = new Map();
  private templateDir: string;
  private loaded = false;

  constructor(templateDir?: string) {
    this.templateDir = templateDir || join(process.cwd(), "server", "scanforge", "templates", "definitions");
  }

  /**
   * Load all templates from the template directory.
   */
  async loadTemplates(): Promise<number> {
    try {
      const files = await readdir(this.templateDir);
      const yamlFiles = files.filter(f => [".yaml", ".yml", ".json"].includes(extname(f)));

      let loaded = 0;
      for (const file of yamlFiles) {
        try {
          const content = await readFile(join(this.templateDir, file), "utf-8");
          const raw = parseYAML(content);
          const template = this.validateTemplate(raw, file);
          if (template) {
            this.templates.set(template.id, template);
            loaded++;
          }
        } catch (err: any) {
          console.warn(`[TemplateEngine] Failed to load ${file}: ${err.message}`);
        }
      }

      this.loaded = true;
      console.log(`[TemplateEngine] Loaded ${loaded}/${yamlFiles.length} templates from ${this.templateDir}`);
      return loaded;
    } catch (err: any) {
      console.warn(`[TemplateEngine] Template directory not found: ${this.templateDir}`);
      this.loaded = true;
      return 0;
    }
  }

  /**
   * Register a template programmatically (for built-in templates).
   */
  register(template: ScanTemplate): void {
    this.templates.set(template.id, template);
  }

  /**
   * Get a template by ID.
   */
  get(id: string): ScanTemplate | undefined {
    return this.templates.get(id);
  }

  /**
   * Get all templates matching tags/protocol.
   */
  query(opts: {
    protocol?: string;
    tags?: string[];
    severity?: FindingSeverity[];
    ids?: string[];
  }): ScanTemplate[] {
    let results = Array.from(this.templates.values());

    if (opts.protocol) {
      results = results.filter(t => t.protocol === opts.protocol);
    }
    if (opts.tags?.length) {
      results = results.filter(t => opts.tags!.some(tag => t.tags.includes(tag)));
    }
    if (opts.severity?.length) {
      results = results.filter(t => opts.severity!.includes(t.severity));
    }
    if (opts.ids?.length) {
      results = results.filter(t => opts.ids!.includes(t.id));
    }

    return results;
  }

  /**
   * Get all loaded templates.
   */
  getAll(): ScanTemplate[] {
    return Array.from(this.templates.values());
  }

  /**
   * Get all loaded template IDs.
   */
  listIds(): string[] {
    return Array.from(this.templates.keys());
  }

  /**
   * Get template count.
   */
  get count(): number {
    return this.templates.size;
  }

  /**
   * Execute a template against a target and return findings.
   */
  async execute(
    template: ScanTemplate,
    target: ScanTarget,
    config?: ScanConfig
  ): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];

    try {
      const response = await this.sendRequest(template, target, config);
      if (!response) return findings;

      const matched = this.evaluateMatchers(template.matchers, response);

      if (matched) {
        findings.push({
          id: randomUUID(),
          source: `template:${template.id}`,
          title: template.name,
          description: template.description,
          severity: template.severity,
          confidence: this.calculateConfidence(template, response),
          target: target.value,
          port: this.getPort(template, target),
          protocol: template.protocol,
          cves: template.references?.cves,
          cwes: template.references?.cwes,
          techniqueIds: template.attack?.techniqueIds,
          evidence: this.buildEvidence(template, response),
          remediation: template.remediation,
          references: template.references?.urls,
          foundAt: Date.now(),
        });
      }
    } catch (err: any) {
      // Template execution errors are non-fatal
      console.debug(`[TemplateEngine] Template ${template.id} error on ${target.value}: ${err.message}`);
    }

    return findings;
  }

  // ─── Internal ──────────────────────────────────────────────────────────

  private validateTemplate(raw: any, filename: string): ScanTemplate | null {
    if (!raw.id || !raw.name || !raw.protocol) {
      console.warn(`[TemplateEngine] Invalid template ${filename}: missing id, name, or protocol`);
      return null;
    }

    return {
      id: raw.id,
      name: raw.name,
      description: raw.description || "",
      author: raw.author || "AC3",
      severity: raw.severity || "info",
      tags: Array.isArray(raw.tags) ? raw.tags : [],
      protocol: raw.protocol,
      matchers: Array.isArray(raw.matchers) ? raw.matchers : [],
      request: raw.request || undefined,
      references: raw.references || undefined,
      remediation: raw.remediation || undefined,
      attack: raw.attack || undefined,
      intelligence: raw.intelligence || undefined,
    };
  }

  private async sendRequest(
    template: ScanTemplate,
    target: ScanTarget,
    config?: ScanConfig
  ): Promise<TemplateResponse | null> {
    if (!template.request) {
      // No request defined — this is a passive check
      return null;
    }

    const req = template.request;
    const protocol = template.protocol;

    // HTTP/HTTPS requests
    if (protocol === "http" || protocol === "https") {
      return this.sendHTTPRequest(req, target, config);
    }

    // TCP raw requests
    if (protocol === "tcp" || req.rawPayload) {
      return this.sendTCPRequest(req, target);
    }

    return null;
  }

  private async sendHTTPRequest(
    req: TemplateRequest,
    target: ScanTarget,
    config?: ScanConfig
  ): Promise<TemplateResponse> {
    const baseUrl = target.type === "url"
      ? target.value
      : `https://${target.value}`;
    const url = `${baseUrl}${req.path || "/"}`;

    const headers: Record<string, string> = {
      "User-Agent": config?.userAgent || "AC3-ScanForge/1.0",
      ...req.headers,
    };

    const startTime = Date.now();
    try {
      const response = await fetch(url, {
        method: req.method || "GET",
        headers,
        body: req.body || undefined,
        redirect: req.followRedirects === false ? "manual" : "follow",
        signal: AbortSignal.timeout(config?.scannerTimeoutSeconds
          ? config.scannerTimeoutSeconds * 1000
          : 15000),
      });

      const body = await response.text();
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((v, k) => { responseHeaders[k] = v; });

      return {
        statusCode: response.status,
        headers: responseHeaders,
        body,
        responseTimeMs: Date.now() - startTime,
        size: body.length,
        raw: `HTTP/${response.status}\n${Object.entries(responseHeaders).map(([k, v]) => `${k}: ${v}`).join("\n")}\n\n${body}`,
      };
    } catch (err: any) {
      return {
        statusCode: 0,
        headers: {},
        body: "",
        responseTimeMs: Date.now() - startTime,
        size: 0,
        raw: "",
        error: err.message,
      };
    }
  }

  private async sendTCPRequest(
    req: TemplateRequest,
    target: ScanTarget
  ): Promise<TemplateResponse> {
    // TCP scanning requires net module — implemented in protocol scanners
    // This is a placeholder for template-driven TCP checks
    return {
      statusCode: 0,
      headers: {},
      body: "",
      responseTimeMs: 0,
      size: 0,
      raw: "",
      error: "TCP templates require protocol scanner execution",
    };
  }

  private evaluateMatchers(
    matchers: TemplateMatcher[],
    response: TemplateResponse
  ): boolean {
    if (matchers.length === 0) return false;

    // Default condition is AND (all must match)
    const firstCondition = matchers[0].condition || "and";
    let result = firstCondition === "and";

    for (const matcher of matchers) {
      const matched = this.evaluateSingleMatcher(matcher, response);
      const effective = matcher.negative ? !matched : matched;
      const condition = matcher.condition || firstCondition;

      if (condition === "or") {
        result = result || effective;
      } else {
        result = result && effective;
      }
    }

    return result;
  }

  private evaluateSingleMatcher(
    matcher: TemplateMatcher,
    response: TemplateResponse
  ): boolean {
    const part = this.getResponsePart(matcher.part || "all", response);

    switch (matcher.type) {
      case "status":
        return matcher.values.some(v => response.statusCode === parseInt(v, 10));

      case "word":
        return matcher.values.some(v => part.includes(v));

      case "regex":
        return matcher.values.some(v => {
          try {
            return new RegExp(v, "i").test(part);
          } catch {
            return false;
          }
        });

      case "header":
        return matcher.values.some(v => {
          const [key, ...rest] = v.split(":");
          const expected = rest.join(":").trim();
          const actual = response.headers[key.trim().toLowerCase()];
          return expected ? actual?.includes(expected) : !!actual;
        });

      case "body":
        return matcher.values.some(v => response.body.includes(v));

      case "size":
        return matcher.values.some(v => {
          const [op, size] = v.split(" ");
          const s = parseInt(size, 10);
          switch (op) {
            case ">": return response.size > s;
            case "<": return response.size < s;
            case "==": return response.size === s;
            default: return false;
          }
        });

      case "time":
        return matcher.values.some(v => {
          const [op, time] = v.split(" ");
          const t = parseInt(time, 10);
          switch (op) {
            case ">": return response.responseTimeMs > t;
            case "<": return response.responseTimeMs < t;
            default: return false;
          }
        });

      case "dsl":
        return this.evaluateDSL(matcher.values, response);

      case "version":
        return this.evaluateVersion(matcher.values, part);

      case "binary":
        return matcher.values.some(v => {
          const hex = Buffer.from(v, "hex").toString();
          return part.includes(hex);
        });

      default:
        return false;
    }
  }

  private getResponsePart(part: string, response: TemplateResponse): string {
    switch (part) {
      case "header":
        return Object.entries(response.headers).map(([k, v]) => `${k}: ${v}`).join("\n");
      case "body":
        return response.body;
      case "raw":
        return response.raw;
      case "all":
      default:
        return response.raw || `${Object.entries(response.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}\n\n${response.body}`;
    }
  }

  private evaluateDSL(expressions: string[], response: TemplateResponse): boolean {
    // Simple DSL evaluator for common patterns
    return expressions.some(expr => {
      try {
        // Replace variables
        let e = expr
          .replace(/status_code/g, String(response.statusCode))
          .replace(/content_length/g, String(response.size))
          .replace(/response_time/g, String(response.responseTimeMs));

        // contains(body, "text")
        const containsMatch = e.match(/contains\(body,\s*["'](.+?)["']\)/);
        if (containsMatch) {
          const has = response.body.includes(containsMatch[1]);
          e = e.replace(containsMatch[0], String(has));
        }

        // contains(header, "text")
        const headerContains = e.match(/contains\(header,\s*["'](.+?)["']\)/);
        if (headerContains) {
          const headerStr = Object.entries(response.headers).map(([k, v]) => `${k}: ${v}`).join("\n");
          const has = headerStr.includes(headerContains[1]);
          e = e.replace(headerContains[0], String(has));
        }

        // Simple boolean evaluation using indirect eval to avoid esbuild direct-eval warning
        // eslint-disable-next-line no-eval
        const indirectEval = (0, eval);
        return Boolean(indirectEval(e));
      } catch {
        return false;
      }
    });
  }

  private evaluateVersion(values: string[], text: string): boolean {
    // Extract version numbers from text and compare
    const versionRegex = /(\d+\.\d+(?:\.\d+)?)/g;
    const found = text.match(versionRegex);
    if (!found) return false;

    return values.some(v => {
      const [op, target] = v.split(" ");
      return found.some(f => this.compareVersions(f, op, target));
    });
  }

  private compareVersions(found: string, op: string, target: string): boolean {
    const a = found.split(".").map(Number);
    const b = target.split(".").map(Number);
    const len = Math.max(a.length, b.length);

    let cmp = 0;
    for (let i = 0; i < len; i++) {
      const av = a[i] || 0;
      const bv = b[i] || 0;
      if (av !== bv) { cmp = av > bv ? 1 : -1; break; }
    }

    switch (op) {
      case "<": return cmp < 0;
      case "<=": return cmp <= 0;
      case ">": return cmp > 0;
      case ">=": return cmp >= 0;
      case "==": return cmp === 0;
      default: return false;
    }
  }

  private calculateConfidence(template: ScanTemplate, response: TemplateResponse): number {
    let confidence = 70; // Base confidence for template match

    // Higher confidence for specific matchers
    if (template.matchers.some(m => m.type === "regex")) confidence += 10;
    if (template.matchers.some(m => m.type === "version")) confidence += 15;
    if (template.matchers.length > 2) confidence += 5;
    if (template.references?.cves?.length) confidence += 5;

    return Math.min(100, confidence);
  }

  private getPort(template: ScanTemplate, target: ScanTarget): number | undefined {
    if (template.protocol === "http") return 80;
    if (template.protocol === "https") return 443;
    if (target.ports?.length) return target.ports[0];
    return undefined;
  }

  private buildEvidence(template: ScanTemplate, response: TemplateResponse): FindingEvidence {
    return {
      request: template.request
        ? `${template.request.method || "GET"} ${template.request.path || "/"}`
        : undefined,
      response: response.body?.substring(0, 2000),
      matchedPattern: template.matchers.map(m => `${m.type}: ${m.values.join(", ")}`).join(" && "),
      data: {
        statusCode: response.statusCode,
        responseTimeMs: response.responseTimeMs,
        responseSize: response.size,
        headers: response.headers,
      },
    };
  }
}

// ─── Response Type ─────────────────────────────────────────────────────────

interface TemplateResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  responseTimeMs: number;
  size: number;
  raw: string;
  error?: string;
}

// ─── Singleton ─────────────────────────────────────────────────────────────

let _engine: TemplateEngine | null = null;

export function getTemplateEngine(templateDir?: string): TemplateEngine {
  if (!_engine) {
    _engine = new TemplateEngine(templateDir);
  }
  return _engine;
}
