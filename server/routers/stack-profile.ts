/**
 * Customer Stack Profile Router
 * ==============================
 * tRPC procedures for managing customer technology stack profiles,
 * generating tailored test plans from scanner modules, and running
 * live HTTP probes against target infrastructure.
 *
 * @author Harrison Cook — AceofCloud
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb } from "../db";
import { customerStackProfiles } from "../../drizzle/schema";
import { eq, desc } from "drizzle-orm";
import { invokeLLM } from "../_core/llm";

// ─── Version-Specific CVE Database ─────────────────────────────────────────

export interface VersionCveRange {
  technology: string;
  cveId: string;
  affectedBelow: string;       // Versions below this are affected (semver)
  affectedAbove?: string;      // Optional: versions above this are affected (range)
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  scannerModule: string;
}

export const VERSION_CVE_DATABASE: VersionCveRange[] = [
  // ─── Streamlit ───
  { technology: 'streamlit', cveId: 'CVE-2024-0217', affectedBelow: '1.30.0', severity: 'high', title: 'Streamlit XSS via st.html', description: 'Stored XSS through st.html component in Streamlit < 1.30.0 allows arbitrary JavaScript execution in viewer browsers', scannerModule: 'streamlit-scanner' },
  { technology: 'streamlit', cveId: 'CVE-2023-44442', affectedBelow: '1.28.0', severity: 'medium', title: 'Streamlit SSRF via file upload', description: 'Server-side request forgery through file upload widget in Streamlit < 1.28.0', scannerModule: 'streamlit-scanner' },
  { technology: 'streamlit', cveId: 'CVE-2024-3568', affectedBelow: '1.33.0', severity: 'high', title: 'Streamlit session state manipulation', description: 'Session state injection allows cross-session data leakage in Streamlit < 1.33.0', scannerModule: 'streamlit-scanner' },
  // ─── Jupyter ───
  { technology: 'jupyter', cveId: 'CVE-2024-22421', affectedBelow: '7.0.7', severity: 'critical', title: 'Jupyter Server auth bypass', description: 'Authentication bypass in jupyter-server < 7.0.7 allows unauthenticated code execution', scannerModule: 'jupyter-scanner' },
  { technology: 'jupyterlab', cveId: 'CVE-2024-22420', affectedBelow: '4.0.11', severity: 'high', title: 'JupyterLab XSS via cell output', description: 'Cross-site scripting through notebook cell output rendering in JupyterLab < 4.0.11', scannerModule: 'jupyter-scanner' },
  { technology: 'jupyterhub', cveId: 'CVE-2024-28233', affectedBelow: '4.1.0', severity: 'high', title: 'JupyterHub CSRF token leak', description: 'CSRF token leakage via open redirect in JupyterHub < 4.1.0', scannerModule: 'jupyter-scanner' },
  // ─── LangChain ───
  { technology: 'langchain', cveId: 'CVE-2023-44467', affectedBelow: '0.0.312', severity: 'critical', title: 'LangChain arbitrary code execution', description: 'Arbitrary code execution via PALChain in LangChain < 0.0.312 through crafted Python expressions', scannerModule: 'langchain-agent-scanner' },
  { technology: 'langchain', cveId: 'CVE-2024-0243', affectedBelow: '0.1.0', severity: 'high', title: 'LangChain SSRF via document loaders', description: 'Server-side request forgery through WebBaseLoader and other document loaders in LangChain < 0.1.0', scannerModule: 'langchain-agent-scanner' },
  { technology: 'langchain', cveId: 'CVE-2024-3571', affectedBelow: '0.1.12', severity: 'high', title: 'LangChain SQL injection via SQLDatabaseChain', description: 'SQL injection through SQLDatabaseChain when user input is not sanitized in LangChain < 0.1.12', scannerModule: 'langchain-agent-scanner' },
  // ─── FAISS ───
  { technology: 'faiss', cveId: 'FAISS-2024-PICKLE', affectedBelow: '999.0.0', severity: 'critical', title: 'FAISS pickle deserialization RCE', description: 'All FAISS versions using pickle-based index serialization are vulnerable to arbitrary code execution via crafted index files', scannerModule: 'faiss-vector-scanner' },
  // ─── Firebase ───
  { technology: 'firebase', cveId: 'FIREBASE-RULES-OPEN', affectedBelow: '999.0.0', severity: 'high', title: 'Firebase Firestore open security rules', description: 'Default or misconfigured Firestore security rules allow unauthenticated read/write access', scannerModule: 'firebase-scanner' },
  { technology: 'firebase', cveId: 'CVE-2024-1527', affectedBelow: '10.8.0', severity: 'medium', title: 'Firebase JS SDK auth token leak', description: 'Authentication token exposure in Firebase JS SDK < 10.8.0 through error messages', scannerModule: 'firebase-scanner' },
  // ─── GitHub Actions ───
  { technology: 'github actions', cveId: 'GHA-EXPR-INJECTION', affectedBelow: '999.0.0', severity: 'critical', title: 'GitHub Actions expression injection', description: 'Workflow files using ${{ }} expressions with untrusted input (issue title, PR body) are vulnerable to arbitrary command injection', scannerModule: 'github-actions-scanner' },
];

// ─── Scanner Module Registry ────────────────────────────────────────────────

const SCANNER_REGISTRY: Record<string, {
  name: string;
  technologies: string[];
  description: string;
  importPath: string;
}> = {
  "streamlit-scanner": {
    name: "Streamlit Security Scanner",
    technologies: ["streamlit", "python", "flask"],
    description: "Fingerprinting, CVEs, HTML injection, widget manipulation, session poisoning",
    importPath: "../lib/scanners/streamlit-scanner",
  },
  "jupyter-scanner": {
    name: "Jupyter Notebook Scanner",
    technologies: ["jupyter", "jupyterlab", "jupyterhub", "ipython", "python"],
    description: "Kernel access, token brute-force, notebook exposure, path traversal, RCE",
    importPath: "../lib/scanners/jupyter-scanner",
  },
  "langchain-agent-scanner": {
    name: "LangChain Agent Scanner",
    technologies: ["langchain", "langserve", "langsmith", "openai", "anthropic", "llm", "rag"],
    description: "Tool injection, memory poisoning, guardrail bypass, RAG manipulation",
    importPath: "../lib/scanners/langchain-agent-scanner",
  },
  "faiss-vector-scanner": {
    name: "FAISS Vector DB Scanner",
    technologies: ["faiss", "vector", "embedding", "pinecone", "chroma", "weaviate", "qdrant"],
    description: "Index exposure, pickle RCE, embedding extraction, vector poisoning",
    importPath: "../lib/scanners/faiss-vector-scanner",
  },
  "firebase-scanner": {
    name: "Firebase Security Scanner",
    technologies: ["firebase", "firestore", "google cloud functions", "gcp"],
    description: "Config extraction, Firestore rules, auth bypass, Cloud Functions enumeration",
    importPath: "../lib/scanners/firebase-scanner",
  },
  "github-actions-scanner": {
    name: "GitHub Actions Scanner",
    technologies: ["github actions", "github", "ci/cd", "github workflows"],
    description: "Expression injection, pull_request_target abuse, unpinned actions, secret exposure",
    importPath: "../lib/scanners/github-actions-scanner",
  },
};

//// ─── Semver Comparison Utility ───────────────────────────────────────────

/** Returns true if versionA < versionB (simple semver comparison) */
export function semverLessThan(versionA: string, versionB: string): boolean {
  const partsA = versionA.split('.').map(Number);
  const partsB = versionB.split('.').map(Number);
  for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
    const a = partsA[i] || 0;
    const b = partsB[i] || 0;
    if (a < b) return true;
    if (a > b) return false;
  }
  return false; // equal
}

// ─── Version-Aware CVE Matching ─────────────────────────────────────────

export interface VersionCveMatch {
  technology: string;
  version: string;
  cveId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  scannerModule: string;
  affectedBelow: string;
}

/**
 * Match technology versions against the CVE database.
 * Returns CVEs that apply to the given technology+version combinations.
 */
export function matchVersionCves(
  technologyVersions: Record<string, string>
): VersionCveMatch[] {
  const matches: VersionCveMatch[] = [];
  for (const [tech, version] of Object.entries(technologyVersions)) {
    if (!version || !version.trim()) continue;
    const normalizedTech = tech.toLowerCase().trim();
    const cleanVersion = version.replace(/^v/i, '').trim();
    for (const cve of VERSION_CVE_DATABASE) {
      if (cve.technology !== normalizedTech) continue;
      if (semverLessThan(cleanVersion, cve.affectedBelow)) {
        matches.push({
          technology: tech,
          version: cleanVersion,
          cveId: cve.cveId,
          severity: cve.severity,
          title: cve.title,
          description: cve.description,
          scannerModule: cve.scannerModule,
          affectedBelow: cve.affectedBelow,
        });
      }
    }
  }
  // Sort by severity: critical > high > medium > low
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  matches.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  return matches;
}

// ─── Technology Matching ────────────────────────────────────────────────

function matchScannersToStack(stack: string[]): {
  matched: string[];
  coveragePercent: number;
  gaps: string[];
} {
  const normalizedStack = stack.map(t => t.toLowerCase().trim());
  const matched: string[] = [];
  const coveredTechs = new Set<string>();

  for (const [scannerKey, scanner] of Object.entries(SCANNER_REGISTRY)) {
    const hasMatch = scanner.technologies.some(scannerTech =>
      normalizedStack.some(stackTech =>
        stackTech.includes(scannerTech) || scannerTech.includes(stackTech)
      )
    );
    if (hasMatch) {
      matched.push(scannerKey);
      for (const tech of scanner.technologies) {
        for (const stackTech of normalizedStack) {
          if (stackTech.includes(tech) || tech.includes(stackTech)) {
            coveredTechs.add(stackTech);
          }
        }
      }
    }
  }

  const gaps = normalizedStack.filter(t => !coveredTechs.has(t));
  const coveragePercent = normalizedStack.length > 0
    ? Math.round((coveredTechs.size / normalizedStack.length) * 100)
    : 0;

  return { matched, coveragePercent, gaps };
}

function generateDiffRecommendation(
  newTechs: string[],
  removedTechs: string[],
  versionDrift: { technology: string; profileVersion: string; scanVersion: string }[],
  newCves: { technology: string; cveId: string; severity: string }[]
): string {
  const parts: string[] = [];
  if (newTechs.length > 0) {
    parts.push(`${newTechs.length} new technolog${newTechs.length === 1 ? 'y' : 'ies'} detected (${newTechs.slice(0, 5).join(', ')}${newTechs.length > 5 ? '...' : ''}). Consider updating the stack profile and adding scanner coverage.`);
  }
  if (removedTechs.length > 0) {
    parts.push(`${removedTechs.length} technolog${removedTechs.length === 1 ? 'y' : 'ies'} no longer detected (${removedTechs.slice(0, 5).join(', ')}${removedTechs.length > 5 ? '...' : ''}). May have been decommissioned or migrated.`);
  }
  if (versionDrift.length > 0) {
    parts.push(`${versionDrift.length} version change${versionDrift.length === 1 ? '' : 's'} detected. Review for security implications.`);
  }
  if (newCves.length > 0) {
    const critCount = newCves.filter(c => c.severity === 'critical' || c.severity === 'high').length;
    parts.push(`${newCves.length} new CVE exposure${newCves.length === 1 ? '' : 's'} from version drift${critCount > 0 ? ` (${critCount} critical/high)` : ''}. Immediate review recommended.`);
  }
  if (parts.length === 0) {
    return 'No significant drift detected. Stack profile is current with scan results.';
  }
  return parts.join(' ');
}

function flattenStack(profile: {
  languages?: string[] | null;
  webFrameworks?: string[] | null;
  dataAndMl?: string[] | null;
  genaiAndLlm?: string[] | null;
  cloudServices?: string[] | null;
  securityTools?: string[] | null;
  devopsAndCi?: string[] | null;
  databasesList?: string[] | null;
  infrastructure?: string[] | null;
  other?: string[] | null;
}): string[] {
  return [
    ...(profile.languages || []),
    ...(profile.webFrameworks || []),
    ...(profile.dataAndMl || []),
    ...(profile.genaiAndLlm || []),
    ...(profile.cloudServices || []),
    ...(profile.securityTools || []),
    ...(profile.devopsAndCi || []),
    ...(profile.databasesList || []),
    ...(profile.infrastructure || []),
    ...(profile.other || []),
  ].filter(Boolean);
}

// ─── Technology Categorization ─────────────────────────────────────────────

const CATEGORY_KEYWORDS: Record<string, string[]> = {
  languages: ['python', 'javascript', 'typescript', 'java', 'go', 'golang', 'ruby', 'php', 'c#', 'csharp', 'rust', 'swift', 'kotlin', 'scala', 'perl', 'r', 'lua', 'dart', 'elixir', 'haskell', 'c++', 'cpp', 'objective-c'],
  webFrameworks: ['react', 'angular', 'vue', 'svelte', 'next.js', 'nextjs', 'nuxt', 'express', 'node.js', 'node', 'django', 'flask', 'fastapi', 'rails', 'spring', 'laravel', 'asp.net', 'gatsby', 'remix', 'astro', 'streamlit', 'bootstrap', 'tailwind', 'jquery', 'ember', 'backbone', 'wordpress', 'drupal', 'joomla', 'shopify', 'wix', 'squarespace', 'deno', 'bun', 'koa', 'hapi', 'nest', 'nestjs'],
  dataAndMl: ['tensorflow', 'pytorch', 'scikit-learn', 'pandas', 'numpy', 'jupyter', 'jupyterlab', 'jupyterhub', 'notebook', 'faiss', 'mlflow', 'kubeflow', 'spark', 'hadoop', 'kafka', 'airflow', 'dbt', 'snowflake', 'databricks', 'sagemaker'],
  genaiAndLlm: ['langchain', 'langserve', 'openai', 'gpt', 'llama', 'anthropic', 'huggingface', 'transformers', 'ollama', 'chromadb', 'pinecone', 'weaviate', 'qdrant', 'milvus', 'vector', 'embedding', 'rag', 'chatgpt'],
  cloudServices: ['aws', 'amazon', 'azure', 'gcp', 'google cloud', 'firebase', 'cloudflare', 'vercel', 'netlify', 'heroku', 'digitalocean', 'linode', 'vultr', 'oracle cloud', 'ibm cloud', 'alibaba cloud', 's3', 'lambda', 'ec2', 'ecs', 'eks', 'fargate'],
  securityTools: ['waf', 'cloudflare waf', 'modsecurity', 'imperva', 'crowdstrike', 'sentinel', 'splunk', 'snort', 'suricata', 'ossec', 'fail2ban', 'vault', 'keycloak', 'auth0', 'okta', 'duo', 'fortinet', 'palo alto', 'checkpoint'],
  devopsAndCi: ['docker', 'kubernetes', 'k8s', 'jenkins', 'github actions', 'gitlab', 'circleci', 'travis', 'ansible', 'terraform', 'pulumi', 'helm', 'argocd', 'prometheus', 'grafana', 'datadog', 'new relic', 'nginx', 'apache', 'caddy', 'haproxy', 'envoy', 'istio'],
  databasesList: ['mysql', 'postgresql', 'postgres', 'mongodb', 'redis', 'elasticsearch', 'cassandra', 'dynamodb', 'cosmosdb', 'couchdb', 'neo4j', 'influxdb', 'timescaledb', 'cockroachdb', 'mariadb', 'sqlite', 'oracle', 'sql server', 'mssql', 'supabase', 'firebase realtime', 'firestore'],
  infrastructure: ['linux', 'ubuntu', 'centos', 'debian', 'windows server', 'vmware', 'proxmox', 'openstack', 'cloudformation', 'cdn', 'load balancer', 'dns', 'smtp', 'ftp', 'ssh', 'vpn', 'wireguard', 'openvpn', 'iis', 'litespeed', 'tomcat', 'weblogic'],
};

export function categorizeTechnologies(techs: string[]): {
  languages: string[];
  webFrameworks: string[];
  dataAndMl: string[];
  genaiAndLlm: string[];
  cloudServices: string[];
  securityTools: string[];
  devopsAndCi: string[];
  databasesList: string[];
  infrastructure: string[];
  other: string[];
} {
  const result: Record<string, string[]> = {
    languages: [], webFrameworks: [], dataAndMl: [], genaiAndLlm: [],
    cloudServices: [], securityTools: [], devopsAndCi: [], databasesList: [],
    infrastructure: [], other: [],
  };

  for (const tech of techs) {
    const techLower = tech.toLowerCase().trim();
    if (!techLower) continue;
    let categorized = false;
    for (const [category, keywords] of Object.entries(CATEGORY_KEYWORDS)) {
      if (keywords.some(kw => {
        // For short keywords (<=2 chars), require exact match or word boundary
        if (kw.length <= 2) {
          return techLower === kw || techLower.split(/[\s\/\-_.]+/).some(part => part === kw);
        }
        return techLower.includes(kw) || kw.includes(techLower);
      })) {
        result[category].push(tech);
        categorized = true;
        break;
      }
    }
    if (!categorized) result.other.push(tech);
  }

  return result as any;
}

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const stackProfileInput = z.object({
  customerName: z.string().min(1),
  engagementId: z.number().optional(),
  languages: z.array(z.string()).optional(),
  webFrameworks: z.array(z.string()).optional(),
  dataAndMl: z.array(z.string()).optional(),
  genaiAndLlm: z.array(z.string()).optional(),
  cloudServices: z.array(z.string()).optional(),
  securityTools: z.array(z.string()).optional(),
  devopsAndCi: z.array(z.string()).optional(),
  databasesList: z.array(z.string()).optional(),
  infrastructure: z.array(z.string()).optional(),
  other: z.array(z.string()).optional(),
  technologyVersions: z.record(z.string(), z.string()).optional(),
  notes: z.string().optional(),
});

// ─── Router ─────────────────────────────────────────────────────────────────

export const stackProfileRouter = router({
  /** List all stack profiles */
  list: protectedProcedure.query(async () => {
    const db = await getDb();
    const profiles = await db.select().from(customerStackProfiles).orderBy(desc(customerStackProfiles.updatedAt));
    return profiles;
  }),

  /** Get a single stack profile by ID */
  getById: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [profile] = await db.select().from(customerStackProfiles).where(eq(customerStackProfiles.id, input.id));
      if (!profile) throw new TRPCError({ code: "NOT_FOUND", message: "Stack profile not found" });
      return profile;
    }),

  /** Get stack profile by engagement ID */
  getByEngagement: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const profiles = await db.select().from(customerStackProfiles)
        .where(eq(customerStackProfiles.engagementId, input.engagementId))
        .orderBy(desc(customerStackProfiles.updatedAt));
      return profiles;
    }),

  /** Create a new stack profile */
  create: protectedProcedure
    .input(stackProfileInput)
    .mutation(async ({ input, ctx }) => {
      const allTechs = flattenStack(input);
      const { matched, coveragePercent, gaps } = matchScannersToStack(allTechs);

      // Version-aware CVE matching
      const versionCves = input.technologyVersions
        ? matchVersionCves(input.technologyVersions)
        : [];

      const db = await getDb();
      const [result] = await db.insert(customerStackProfiles).values({
        customerName: input.customerName,
        engagementId: input.engagementId || null,
        languages: input.languages || null,
        webFrameworks: input.webFrameworks || null,
        dataAndMl: input.dataAndMl || null,
        genaiAndLlm: input.genaiAndLlm || null,
        cloudServices: input.cloudServices || null,
        securityTools: input.securityTools || null,
        devopsAndCi: input.devopsAndCi || null,
        databasesList: input.databasesList || null,
        infrastructure: input.infrastructure || null,
        other: input.other || null,
        technologyVersions: input.technologyVersions || null,
        matchedScanners: matched,
        coveragePercent,
        gaps,
        notes: input.notes || null,
        createdBy: ctx.user?.id || null,
      });

      return { id: result.insertId, matchedScanners: matched, coveragePercent, gaps, versionCves };
    }),

  /** Update an existing stack profile */
  update: protectedProcedure
    .input(z.object({ id: z.number() }).merge(stackProfileInput.partial()))
    .mutation(async ({ input }) => {
      const { id, ...updates } = input;
      const allTechs = flattenStack(updates as any);
      let matchData: any = {};
      let versionCves: VersionCveMatch[] = [];
      if (allTechs.length > 0) {
        const { matched, coveragePercent, gaps } = matchScannersToStack(allTechs);
        matchData = { matchedScanners: matched, coveragePercent, gaps };
      }
      if (updates.technologyVersions) {
        versionCves = matchVersionCves(updates.technologyVersions);
        matchData.technologyVersions = updates.technologyVersions;
      }

      const db = await getDb();
      await db.update(customerStackProfiles)
        .set({ ...updates, ...matchData })
        .where(eq(customerStackProfiles.id, id));

      return { success: true, ...matchData, versionCves };
    }),

  /** Delete a stack profile */
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      await db.delete(customerStackProfiles).where(eq(customerStackProfiles.id, input.id));
      return { success: true };
    }),

  /** Get scanner registry (available modules) */
  getScannerRegistry: protectedProcedure.query(() => {
    return Object.entries(SCANNER_REGISTRY).map(([key, scanner]) => ({
      key,
      ...scanner,
    }));
  }),

  /** Match technologies to scanners (preview without saving) */
  matchScanners: protectedProcedure
    .input(z.object({ technologies: z.array(z.string()) }))
    .mutation(({ input }) => {
      return matchScannersToStack(input.technologies);
    }),

  /** Generate a tailored test plan from the stack profile using LLM + scanner modules */
  generateTestPlan: protectedProcedure
    .input(z.object({ profileId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const [profile] = await db.select().from(customerStackProfiles)
        .where(eq(customerStackProfiles.id, input.profileId));
      if (!profile) throw new TRPCError({ code: "NOT_FOUND", message: "Stack profile not found" });

      const allTechs = flattenStack(profile);
      const { matched } = matchScannersToStack(allTechs);

      // Gather test plan items from each matched scanner module
      const scannerTestPlans: Array<{ scanner: string; items: string[] }> = [];
      for (const scannerKey of matched) {
        try {
          const scanner = SCANNER_REGISTRY[scannerKey];
          if (!scanner) continue;
          const mod = require(scanner.importPath);
          // Each scanner has a generateXxxTestPlan function
          const genFn = Object.values(mod).find((v: any) => typeof v === 'function' && v.name?.includes('TestPlan'));
          if (typeof genFn === 'function') {
            const items = (genFn as Function)({});
            scannerTestPlans.push({ scanner: scanner.name, items: Array.isArray(items) ? items : [] });
          }
        } catch (e: any) {
          scannerTestPlans.push({ scanner: scannerKey, items: [`Error loading scanner: ${e.message}`] });
        }
      }

      // Use LLM to synthesize a comprehensive test plan
      const prompt = `You are a senior penetration tester creating a tailored security test plan for a customer.

Customer: ${profile.customerName}
Technology Stack:
${allTechs.map(t => `- ${t}`).join('\n')}

Matched Scanner Modules (${matched.length}):
${scannerTestPlans.map(sp => `\n### ${sp.scanner}\n${sp.items.map(i => `- ${i}`).join('\n')}`).join('\n')}

Coverage Gaps (technologies without dedicated scanners):
${(profile.gaps as string[] || []).map(g => `- ${g}`).join('\n') || 'None'}

Generate a comprehensive, prioritized test plan with 15-25 items. Each item should have:
- title: Short action title
- description: What to test and why
- scannerModule: Which scanner module handles this (or "manual" if no scanner)
- priority: "critical", "high", "medium", or "low"

Return ONLY a JSON array of objects with these fields.`;

      try {
        const response = await invokeLLM({
          messages: [
            { role: "system", content: "You are a security testing expert. Return only valid JSON arrays." },
            { role: "user", content: prompt },
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "test_plan",
              strict: true,
              schema: {
                type: "object",
                properties: {
                  items: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        title: { type: "string" },
                        description: { type: "string" },
                        scannerModule: { type: "string" },
                        priority: { type: "string" },
                      },
                      required: ["title", "description", "scannerModule", "priority"],
                      additionalProperties: false,
                    },
                  },
                },
                required: ["items"],
                additionalProperties: false,
              },
            },
          },
        });

        const content = response.choices?.[0]?.message?.content || '{"items":[]}';
        const parsed = JSON.parse(content);
        const testPlan = parsed.items || parsed;

        // Save the generated test plan back to the profile
        await db.update(customerStackProfiles)
          .set({ generatedTestPlan: testPlan })
          .where(eq(customerStackProfiles.id, input.profileId));

        return { testPlan, scannerTestPlans };
      } catch (e: any) {
        // Fallback: return scanner-generated test plans without LLM synthesis
        const fallbackPlan = scannerTestPlans.flatMap(sp =>
          sp.items.map(item => ({
            title: item.substring(0, 80),
            description: item,
            scannerModule: sp.scanner,
            priority: "medium",
          }))
        );
        await db.update(customerStackProfiles)
          .set({ generatedTestPlan: fallbackPlan })
          .where(eq(customerStackProfiles.id, input.profileId));
        return { testPlan: fallbackPlan, scannerTestPlans, llmError: e.message };
      }
    }),

  /** Run live HTTP probes against a target URL */
  runLiveProbes: protectedProcedure
    .input(z.object({
      targetUrl: z.string().url(),
      categories: z.array(z.enum(["faiss", "langchain", "rag", "firebase", "jupyter"])).optional(),
    }))
    .mutation(async ({ input }) => {
      const { buildProbeSpecs, analyzeProbeResponse, generateProbeReport } = require('../lib/scanners/live-probe-engine');
      const url = new URL(input.targetUrl);
      const target = {
        baseUrl: `${url.protocol}//${url.host}`,
        hostname: url.hostname,
        port: url.port ? parseInt(url.port) : undefined,
      };

      const allSpecs = buildProbeSpecs(target);
      // Filter by categories if specified
      const specs = input.categories
        ? allSpecs.filter((s: any) => input.categories!.includes(s.category))
        : allSpecs;

      const startTime = Date.now();
      const results: any[] = [];
      const axios = require('axios');

      // Run probes with concurrency limit
      const CONCURRENCY = 5;
      for (let i = 0; i < specs.length; i += CONCURRENCY) {
        const batch = specs.slice(i, i + CONCURRENCY);
        const batchResults = await Promise.allSettled(
          batch.map(async (spec: any) => {
            try {
              const response = await axios({
                method: spec.method,
                url: `${target.baseUrl}${spec.path}`,
                data: spec.body,
                headers: {
                  ...spec.headers,
                  'User-Agent': 'Mozilla/5.0 (compatible; AC3-SecurityScanner/1.0)',
                },
                timeout: 5000,
                maxRedirects: 3,
                validateStatus: () => true, // Accept all status codes
              });

              const result = analyzeProbeResponse(
                spec.category,
                spec.path,
                response.status,
                typeof response.data === 'string' ? response.data : JSON.stringify(response.data),
                response.headers || {},
                spec.expectedIndicators,
                spec.severity,
              );

              if (result) {
                result.target = target.baseUrl;
                results.push(result);
              }
            } catch (e: any) {
              // Network errors are expected for many probes — skip silently
            }
          })
        );
      }

      const report = generateProbeReport(target, results, Date.now() - startTime);
      return report;
    }),

  /** Run technology auto-detection against a target URL */
  detectTechnologies: protectedProcedure
    .input(z.object({ targetUrl: z.string().url() }))
    .mutation(async ({ input }) => {
      const { detectTechnologies } = require('../lib/scanners/tech-auto-detector');
      const axios = require('axios');
      const url = new URL(input.targetUrl);

      try {
        // Fetch the target to get headers and HTML
        const response = await axios.get(input.targetUrl, {
          timeout: 10000,
          maxRedirects: 5,
          validateStatus: () => true,
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; AC3-SecurityScanner/1.0)' },
        });

        const signals = [{
          hostname: url.hostname,
          headers: response.headers || {},
          html: typeof response.data === 'string' ? response.data.substring(0, 50000) : '',
          technologies: [],
          ports: [],
          responseSnippets: [typeof response.data === 'string' ? response.data.substring(0, 10000) : ''],
        }];

        const result = detectTechnologies(signals);
        return result;
      } catch (e: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Failed to detect technologies: ${e.message}`,
        });
      }
    }),

  /** Look up version-specific CVEs for a set of technology+version pairs (preview without saving) */
  lookupVersionCves: protectedProcedure
    .input(z.object({ technologyVersions: z.record(z.string(), z.string()) }))
    .mutation(({ input }) => {
      return {
        cves: matchVersionCves(input.technologyVersions),
        database: VERSION_CVE_DATABASE.map(c => ({ technology: c.technology, cveId: c.cveId, affectedBelow: c.affectedBelow, severity: c.severity, title: c.title })),
      };
    }),

  /** Get the full CVE database for reference (static + NVD dynamic) */
  getCveDatabase: protectedProcedure.query(async () => {
    const { getFullCveDatabase } = await import("../lib/nvd-cve-refresh");
    return getFullCveDatabase().map(c => ({
      technology: c.technology,
      cveId: c.cveId,
      affectedBelow: c.affectedBelow,
      severity: c.severity,
      title: c.title,
      description: c.description,
      scannerModule: c.scannerModule,
    }));
  }),

  /** Get CVE refresh stats for admin dashboard */
  cveRefreshStats: protectedProcedure.query(async () => {
    const { getCveRefreshStats } = await import("../lib/nvd-cve-refresh");
    return getCveRefreshStats();
  }),

  /** Manually trigger NVD CVE refresh */
  triggerCveRefresh: protectedProcedure
    .input(z.object({ technologies: z.array(z.string()).optional() }).optional())
    .mutation(async ({ input }) => {
      const { refreshCveDatabase } = await import("../lib/nvd-cve-refresh");
      return refreshCveDatabase(input?.technologies);
    }),

  /** Link a stack profile to an engagement */
  linkToEngagement: protectedProcedure
    .input(z.object({ profileId: z.number(), engagementId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const [profile] = await db.select().from(customerStackProfiles)
        .where(eq(customerStackProfiles.id, input.profileId));
      if (!profile) throw new TRPCError({ code: "NOT_FOUND", message: "Stack profile not found" });

      await db.update(customerStackProfiles)
        .set({ engagementId: input.engagementId })
        .where(eq(customerStackProfiles.id, input.profileId));

      return { success: true, profileId: input.profileId, engagementId: input.engagementId };
    }),

  /** Unlink a stack profile from its engagement */
  unlinkFromEngagement: protectedProcedure
    .input(z.object({ profileId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      await db.update(customerStackProfiles)
        .set({ engagementId: null })
        .where(eq(customerStackProfiles.id, input.profileId));
      return { success: true };
    }),

  /**
   * Get the stack profile for an engagement (used by the orchestrator at scan kickoff).
   * Returns the most recently updated profile linked to the engagement, or null.
   */
  getForOrchestrator: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const profiles = await db.select().from(customerStackProfiles)
        .where(eq(customerStackProfiles.engagementId, input.engagementId))
        .orderBy(desc(customerStackProfiles.updatedAt))
        .limit(1);
      if (!profiles.length) return null;
      const profile = profiles[0];
      const allTechs = flattenStack(profile);
      const { matched, coveragePercent, gaps } = matchScannersToStack(allTechs);
      const versionCves = profile.technologyVersions
        ? matchVersionCves(profile.technologyVersions as Record<string, string>)
        : [];
      return {
        ...profile,
        computedMatch: { matched, coveragePercent, gaps },
        versionCves,
      };
    }),

  /** Auto-create a stack profile from DI scan results */
  /** Compare a stack profile against the latest DI scan results to show drift */
  diffWithScan: protectedProcedure
    .input(z.object({
      profileId: z.number(),
      scanId: z.number(),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database not available");

      // Get the stack profile
      const profiles = await db.select().from(customerStackProfiles)
        .where(eq(customerStackProfiles.id, input.profileId))
        .limit(1);
      if (!profiles.length) throw new Error("Stack profile not found");
      const profile = profiles[0];

      // Get scan assets and their technologies
      const { discoveredAssets } = await import("../../drizzle/schema");
      const assets = await db.select().from(discoveredAssets)
        .where(eq(discoveredAssets.scanId, input.scanId));

      // Collect all technologies detected in the scan
      const scanTechs = new Set<string>();
      const scanVersions: Record<string, string> = {};
      for (const asset of assets) {
        const techs = (asset.technologies as string[] | null) || [];
        for (const t of techs) {
          // Parse "TechName/version" format
          const parts = t.split("/");
          const name = parts[0].trim();
          const version = parts.length > 1 ? parts.slice(1).join("/").trim() : undefined;
          scanTechs.add(name.toLowerCase());
          if (version) scanVersions[name.toLowerCase()] = version;
        }
      }

      // Get all profile technologies
      const profileTechs = flattenStack(profile).map(t => t.toLowerCase());
      const profileVersions = (profile.technologyVersions as Record<string, string> | null) || {};
      const profileVersionsLower: Record<string, string> = {};
      for (const [k, v] of Object.entries(profileVersions)) {
        profileVersionsLower[k.toLowerCase()] = v;
      }

      // Compute diff
      const profileTechSet = new Set(profileTechs);
      const newTechnologies: string[] = []; // In scan but not in profile
      const removedTechnologies: string[] = []; // In profile but not in scan
      const unchangedTechnologies: string[] = []; // In both
      const versionDrift: { technology: string; profileVersion: string; scanVersion: string }[] = [];

      // Find new technologies (in scan, not in profile)
      for (const tech of scanTechs) {
        if (!profileTechSet.has(tech)) {
          newTechnologies.push(tech);
        } else {
          unchangedTechnologies.push(tech);
        }
      }

      // Find removed technologies (in profile, not in scan)
      for (const tech of profileTechSet) {
        if (!scanTechs.has(tech)) {
          removedTechnologies.push(tech);
        }
      }

      // Find version drift
      for (const tech of unchangedTechnologies) {
        const profileVer = profileVersionsLower[tech];
        const scanVer = scanVersions[tech];
        if (profileVer && scanVer && profileVer !== scanVer) {
          versionDrift.push({
            technology: tech,
            profileVersion: profileVer,
            scanVersion: scanVer,
          });
        } else if (!profileVer && scanVer) {
          // Version newly detected
          versionDrift.push({
            technology: tech,
            profileVersion: "(unknown)",
            scanVersion: scanVer,
          });
        }
      }

      // Check for new CVE exposure from version drift
      const newCveExposure: { technology: string; version: string; cveId: string; severity: string }[] = [];
      if (versionDrift.length > 0) {
        const driftVersions: Record<string, string> = {};
        for (const d of versionDrift) {
          driftVersions[d.technology] = d.scanVersion;
        }
        const cves = matchVersionCves(driftVersions);
        for (const cve of cves) {
          newCveExposure.push({
            technology: cve.technology,
            version: driftVersions[cve.technology.toLowerCase()] || "",
            cveId: cve.cveId,
            severity: cve.severity,
          });
        }
      }

      return {
        profileId: input.profileId,
        scanId: input.scanId,
        profileName: profile.customerName,
        summary: {
          totalProfileTechs: profileTechs.length,
          totalScanTechs: scanTechs.size,
          newCount: newTechnologies.length,
          removedCount: removedTechnologies.length,
          unchangedCount: unchangedTechnologies.length,
          versionDriftCount: versionDrift.length,
          newCveCount: newCveExposure.length,
        },
        newTechnologies,
        removedTechnologies,
        unchangedTechnologies,
        versionDrift,
        newCveExposure,
        recommendation: generateDiffRecommendation(newTechnologies, removedTechnologies, versionDrift, newCveExposure),
      };
    }),

  createFromScan: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      customerName: z.string().min(1),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb: getDbCore } = await import("../db");
      const dbConn = await getDbCore();
      if (!dbConn) throw new Error("Database not available");

      // Import scan data helpers
      const { getDomainIntelScanById, getDiscoveredAssetsByScan } = await import("../db");
      const scan = await getDomainIntelScanById(input.scanId);
      if (!scan) throw new Error("Scan not found");

      const output = (scan as any).pipelineOutput as any;

      // Collect all technologies and versions from scan assets
      const allTechs = new Set<string>();
      const detectedVersions: Record<string, string> = {};

      // From pipeline output assets
      (output?.assets || []).forEach((a: any) => {
        const techList = a.technologies || a.asset?.technologies || [];
        (Array.isArray(techList) ? techList : []).forEach((t: string) => allTechs.add(t));
        // Extract versions
        const versions = a.detectedVersions || a.asset?.detectedVersions || a.asset?.technologyVersions || {};
        if (typeof versions === 'object') {
          Object.entries(versions).forEach(([k, v]) => {
            if (typeof v === 'string' && v.trim()) detectedVersions[k.toLowerCase()] = v;
          });
        }
      });

      // From DB discovered assets
      try {
        const dbAssets = await getDiscoveredAssetsByScan(input.scanId);
        dbAssets.forEach((a: any) => {
          const techList = a.technologies || [];
          (Array.isArray(techList) ? techList : []).forEach((t: string) => allTechs.add(t));
        });
      } catch { /* fallback if function not available */ }

      if (allTechs.size === 0) {
        throw new Error("No technologies detected in this scan. Cannot create stack profile.");
      }

      // Categorize technologies into stack profile fields
      const categorized = categorizeTechnologies(Array.from(allTechs));

      // Build the profile
      const allTechsFlat = flattenStack(categorized);
      const { matched, coveragePercent, gaps } = matchScannersToStack(allTechsFlat);
      const versionCves = Object.keys(detectedVersions).length > 0
        ? matchVersionCves(detectedVersions)
        : [];

      const db = await getDb();
      const [result] = await db.insert(customerStackProfiles).values({
        customerName: input.customerName,
        engagementId: input.engagementId || null,
        languages: categorized.languages.length > 0 ? categorized.languages : null,
        webFrameworks: categorized.webFrameworks.length > 0 ? categorized.webFrameworks : null,
        dataAndMl: categorized.dataAndMl.length > 0 ? categorized.dataAndMl : null,
        genaiAndLlm: categorized.genaiAndLlm.length > 0 ? categorized.genaiAndLlm : null,
        cloudServices: categorized.cloudServices.length > 0 ? categorized.cloudServices : null,
        securityTools: categorized.securityTools.length > 0 ? categorized.securityTools : null,
        devopsAndCi: categorized.devopsAndCi.length > 0 ? categorized.devopsAndCi : null,
        databasesList: categorized.databasesList.length > 0 ? categorized.databasesList : null,
        infrastructure: categorized.infrastructure.length > 0 ? categorized.infrastructure : null,
        other: categorized.other.length > 0 ? categorized.other : null,
        technologyVersions: Object.keys(detectedVersions).length > 0 ? detectedVersions : null,
        matchedScanners: matched,
        coveragePercent,
        gaps,
        notes: `Auto-generated from DI scan #${input.scanId} (${(scan as any).primaryDomain || 'unknown domain'})`,
        createdBy: ctx.user?.id || null,
      });

      return {
        id: result.insertId,
        technologiesDetected: allTechs.size,
        categorized,
        detectedVersions,
        matchedScanners: matched,
        coveragePercent,
        gaps,
        versionCves,
      };
    }),
});
