import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/scanforge/engine/template-engine.ts
import { readdir, readFile } from "fs/promises";
import { existsSync } from "fs";
import { join, extname } from "path";
import { randomUUID } from "crypto";
import yaml from "js-yaml";
function parseYAML(content) {
  try {
    return JSON.parse(content);
  } catch {
    return yaml.load(content, { schema: yaml.DEFAULT_SCHEMA });
  }
}
function getTemplateEngine(templateDir) {
  if (!_engine) {
    _engine = new TemplateEngine(templateDir);
  }
  return _engine;
}
var TemplateEngine, _engine;
var init_template_engine = __esm({
  "server/scanforge/engine/template-engine.ts"() {
    "use strict";
    TemplateEngine = class {
      constructor(templateDir) {
        this.templates = /* @__PURE__ */ new Map();
        this.loaded = false;
        if (templateDir) {
          this.templateDir = templateDir;
        } else {
          const candidates = [
            join(process.cwd(), "server", "scanforge", "templates", "definitions"),
            join("/usr/src/app", "server", "scanforge", "templates", "definitions")
          ];
          this.templateDir = candidates.find((p) => existsSync(p)) || candidates[0];
        }
      }
      /**
       * Load all templates from the template directory.
       */
      async loadTemplates() {
        try {
          const files = await readdir(this.templateDir);
          const yamlFiles = files.filter((f) => [".yaml", ".yml", ".json"].includes(extname(f)));
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
            } catch (err) {
              console.warn(`[TemplateEngine] Failed to load ${file}: ${err.message}`);
            }
          }
          this.loaded = true;
          console.log(`[TemplateEngine] Loaded ${loaded}/${yamlFiles.length} templates from ${this.templateDir}`);
          return loaded;
        } catch (err) {
          console.warn(`[TemplateEngine] Template directory not found: ${this.templateDir}`);
          this.loaded = true;
          return 0;
        }
      }
      /**
       * Register a template programmatically (for built-in templates).
       */
      register(template) {
        this.templates.set(template.id, template);
      }
      /**
       * Get a template by ID.
       */
      get(id) {
        return this.templates.get(id);
      }
      /**
       * Get all templates matching tags/protocol.
       */
      query(opts) {
        let results = Array.from(this.templates.values());
        if (opts.protocol) {
          results = results.filter((t) => t.protocol === opts.protocol);
        }
        if (opts.tags?.length) {
          results = results.filter((t) => opts.tags.some((tag) => t.tags.includes(tag)));
        }
        if (opts.severity?.length) {
          results = results.filter((t) => opts.severity.includes(t.severity));
        }
        if (opts.ids?.length) {
          results = results.filter((t) => opts.ids.includes(t.id));
        }
        return results;
      }
      /**
       * Get all loaded templates.
       */
      getAll() {
        return Array.from(this.templates.values());
      }
      /**
       * Get all loaded template IDs.
       */
      listIds() {
        return Array.from(this.templates.keys());
      }
      /**
       * Get template count.
       */
      get count() {
        return this.templates.size;
      }
      /**
       * Execute a template against a target and return findings.
       */
      async execute(template, target, config) {
        const findings = [];
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
              foundAt: Date.now()
            });
          }
        } catch (err) {
          console.debug(`[TemplateEngine] Template ${template.id} error on ${target.value}: ${err.message}`);
        }
        return findings;
      }
      // ─── Internal ──────────────────────────────────────────────────────────
      validateTemplate(raw, filename) {
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
          request: raw.request || void 0,
          references: raw.references || void 0,
          remediation: raw.remediation || void 0,
          attack: raw.attack || void 0,
          intelligence: raw.intelligence || void 0
        };
      }
      async sendRequest(template, target, config) {
        if (!template.request) {
          return null;
        }
        const req = template.request;
        const protocol = template.protocol;
        if (protocol === "http" || protocol === "https") {
          return this.sendHTTPRequest(req, target, config);
        }
        if (protocol === "tcp" || req.rawPayload) {
          return this.sendTCPRequest(req, target);
        }
        return null;
      }
      async sendHTTPRequest(req, target, config) {
        const baseUrl = target.type === "url" ? target.value : `https://${target.value}`;
        const url = `${baseUrl}${req.path || "/"}`;
        const headers = {
          "User-Agent": config?.userAgent || "AC3-ScanForge/1.0",
          ...req.headers
        };
        const startTime = Date.now();
        try {
          const response = await fetch(url, {
            method: req.method || "GET",
            headers,
            body: req.body || void 0,
            redirect: req.followRedirects === false ? "manual" : "follow",
            signal: AbortSignal.timeout(config?.scannerTimeoutSeconds ? config.scannerTimeoutSeconds * 1e3 : 15e3)
          });
          const body = await response.text();
          const responseHeaders = {};
          response.headers.forEach((v, k) => {
            responseHeaders[k] = v;
          });
          return {
            statusCode: response.status,
            headers: responseHeaders,
            body,
            responseTimeMs: Date.now() - startTime,
            size: body.length,
            raw: `HTTP/${response.status}
${Object.entries(responseHeaders).map(([k, v]) => `${k}: ${v}`).join("\n")}

${body}`
          };
        } catch (err) {
          return {
            statusCode: 0,
            headers: {},
            body: "",
            responseTimeMs: Date.now() - startTime,
            size: 0,
            raw: "",
            error: err.message
          };
        }
      }
      async sendTCPRequest(req, target) {
        return {
          statusCode: 0,
          headers: {},
          body: "",
          responseTimeMs: 0,
          size: 0,
          raw: "",
          error: "TCP templates require protocol scanner execution"
        };
      }
      evaluateMatchers(matchers, response) {
        if (matchers.length === 0) return false;
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
      evaluateSingleMatcher(matcher, response) {
        const part = this.getResponsePart(matcher.part || "all", response);
        switch (matcher.type) {
          case "status":
            return matcher.values.some((v) => response.statusCode === parseInt(v, 10));
          case "word":
            return matcher.values.some((v) => part.includes(v));
          case "regex":
            return matcher.values.some((v) => {
              try {
                return new RegExp(v, "i").test(part);
              } catch {
                return false;
              }
            });
          case "header":
            return matcher.values.some((v) => {
              const [key, ...rest] = v.split(":");
              const expected = rest.join(":").trim();
              const actual = response.headers[key.trim().toLowerCase()];
              return expected ? actual?.includes(expected) : !!actual;
            });
          case "body":
            return matcher.values.some((v) => response.body.includes(v));
          case "size":
            return matcher.values.some((v) => {
              const [op, size] = v.split(" ");
              const s = parseInt(size, 10);
              switch (op) {
                case ">":
                  return response.size > s;
                case "<":
                  return response.size < s;
                case "==":
                  return response.size === s;
                default:
                  return false;
              }
            });
          case "time":
            return matcher.values.some((v) => {
              const [op, time] = v.split(" ");
              const t = parseInt(time, 10);
              switch (op) {
                case ">":
                  return response.responseTimeMs > t;
                case "<":
                  return response.responseTimeMs < t;
                default:
                  return false;
              }
            });
          case "dsl":
            return this.evaluateDSL(matcher.values, response);
          case "version":
            return this.evaluateVersion(matcher.values, part);
          case "binary":
            return matcher.values.some((v) => {
              const hex = Buffer.from(v, "hex").toString();
              return part.includes(hex);
            });
          default:
            return false;
        }
      }
      getResponsePart(part, response) {
        switch (part) {
          case "header":
            return Object.entries(response.headers).map(([k, v]) => `${k}: ${v}`).join("\n");
          case "body":
            return response.body;
          case "raw":
            return response.raw;
          case "all":
          default:
            return response.raw || `${Object.entries(response.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}

${response.body}`;
        }
      }
      evaluateDSL(expressions, response) {
        return expressions.some((expr) => {
          try {
            let e = expr.replace(/status_code/g, String(response.statusCode)).replace(/content_length/g, String(response.size)).replace(/response_time/g, String(response.responseTimeMs));
            const containsMatch = e.match(/contains\(body,\s*["'](.+?)["']\)/);
            if (containsMatch) {
              const has = response.body.includes(containsMatch[1]);
              e = e.replace(containsMatch[0], String(has));
            }
            const headerContains = e.match(/contains\(header,\s*["'](.+?)["']\)/);
            if (headerContains) {
              const headerStr = Object.entries(response.headers).map(([k, v]) => `${k}: ${v}`).join("\n");
              const has = headerStr.includes(headerContains[1]);
              e = e.replace(headerContains[0], String(has));
            }
            const indirectEval = (0, eval);
            return Boolean(indirectEval(e));
          } catch {
            return false;
          }
        });
      }
      evaluateVersion(values, text) {
        const versionRegex = /(\d+\.\d+(?:\.\d+)?)/g;
        const found = text.match(versionRegex);
        if (!found) return false;
        return values.some((v) => {
          const [op, target] = v.split(" ");
          return found.some((f) => this.compareVersions(f, op, target));
        });
      }
      compareVersions(found, op, target) {
        const a = found.split(".").map(Number);
        const b = target.split(".").map(Number);
        const len = Math.max(a.length, b.length);
        let cmp = 0;
        for (let i = 0; i < len; i++) {
          const av = a[i] || 0;
          const bv = b[i] || 0;
          if (av !== bv) {
            cmp = av > bv ? 1 : -1;
            break;
          }
        }
        switch (op) {
          case "<":
            return cmp < 0;
          case "<=":
            return cmp <= 0;
          case ">":
            return cmp > 0;
          case ">=":
            return cmp >= 0;
          case "==":
            return cmp === 0;
          default:
            return false;
        }
      }
      calculateConfidence(template, response) {
        let confidence = 70;
        if (template.matchers.some((m) => m.type === "regex")) confidence += 10;
        if (template.matchers.some((m) => m.type === "version")) confidence += 15;
        if (template.matchers.length > 2) confidence += 5;
        if (template.references?.cves?.length) confidence += 5;
        return Math.min(100, confidence);
      }
      getPort(template, target) {
        if (template.protocol === "http") return 80;
        if (template.protocol === "https") return 443;
        if (target.ports?.length) return target.ports[0];
        return void 0;
      }
      buildEvidence(template, response) {
        return {
          request: template.request ? `${template.request.method || "GET"} ${template.request.path || "/"}` : void 0,
          response: response.body?.substring(0, 2e3),
          matchedPattern: template.matchers.map((m) => `${m.type}: ${m.values.join(", ")}`).join(" && "),
          data: {
            statusCode: response.statusCode,
            responseTimeMs: response.responseTimeMs,
            responseSize: response.size,
            headers: response.headers
          }
        };
      }
    };
    _engine = null;
  }
});

export {
  TemplateEngine,
  getTemplateEngine,
  init_template_engine
};
