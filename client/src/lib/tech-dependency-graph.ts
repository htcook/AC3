/**
 * Tech Dependency Graph — defines technology relationships and renders them
 * as an interactive force-directed graph showing how detected technologies
 * relate to each other (e.g., jQuery depends on JavaScript, WordPress on PHP/MySQL).
 */

// ── Dependency Definitions ──────────────────────────────────────────

export interface TechDependency {
  /** Technology name (matches TECH_ICONS keys) */
  name: string;
  /** Technologies this depends on */
  dependsOn: string[];
  /** Category for grouping */
  category: TechCategory;
}

export type TechCategory =
  | "language"
  | "framework"
  | "cms"
  | "database"
  | "server"
  | "cdn"
  | "analytics"
  | "security"
  | "cloud"
  | "library"
  | "build_tool"
  | "other";

export const CATEGORY_COLORS: Record<TechCategory, string> = {
  language: "#F59E0B",    // amber
  framework: "#3B82F6",   // blue
  cms: "#10B981",         // emerald
  database: "#8B5CF6",    // purple
  server: "#EF4444",      // red
  cdn: "#06B6D4",         // cyan
  analytics: "#F97316",   // orange
  security: "#EC4899",    // pink
  cloud: "#6366F1",       // indigo
  library: "#14B8A6",     // teal
  build_tool: "#A855F7",  // violet
  other: "#6B7280",       // gray
};

export const CATEGORY_LABELS: Record<TechCategory, string> = {
  language: "Languages",
  framework: "Frameworks",
  cms: "CMS",
  database: "Databases",
  server: "Servers",
  cdn: "CDN / Delivery",
  analytics: "Analytics",
  security: "Security",
  cloud: "Cloud",
  library: "Libraries",
  build_tool: "Build Tools",
  other: "Other",
};

/**
 * Master dependency map — defines how technologies relate to each other.
 * This is intentionally comprehensive to cover common web stacks.
 */
export const TECH_DEPENDENCIES: TechDependency[] = [
  // ── Languages ──
  { name: "JavaScript", dependsOn: [], category: "language" },
  { name: "TypeScript", dependsOn: ["JavaScript"], category: "language" },
  { name: "PHP", dependsOn: [], category: "language" },
  { name: "Python", dependsOn: [], category: "language" },
  { name: "Ruby", dependsOn: [], category: "language" },
  { name: "Java", dependsOn: [], category: "language" },
  { name: "Go", dependsOn: [], category: "language" },
  { name: "Rust", dependsOn: [], category: "language" },
  { name: "C#", dependsOn: [], category: "language" },

  // ── Frontend Frameworks ──
  { name: "React", dependsOn: ["JavaScript"], category: "framework" },
  { name: "Vue.js", dependsOn: ["JavaScript"], category: "framework" },
  { name: "Angular", dependsOn: ["TypeScript"], category: "framework" },
  { name: "Svelte", dependsOn: ["JavaScript"], category: "framework" },
  { name: "Next.js", dependsOn: ["React"], category: "framework" },
  { name: "Nuxt.js", dependsOn: ["Vue.js"], category: "framework" },
  { name: "Gatsby", dependsOn: ["React"], category: "framework" },
  { name: "Astro", dependsOn: ["JavaScript"], category: "framework" },

  // ── Backend Frameworks ──
  { name: "Express", dependsOn: ["JavaScript"], category: "framework" },
  { name: "Django", dependsOn: ["Python"], category: "framework" },
  { name: "Flask", dependsOn: ["Python"], category: "framework" },
  { name: "FastAPI", dependsOn: ["Python"], category: "framework" },
  { name: "Rails", dependsOn: ["Ruby"], category: "framework" },
  { name: "Spring", dependsOn: ["Java"], category: "framework" },
  { name: "Laravel", dependsOn: ["PHP"], category: "framework" },
  { name: "ASP.NET", dependsOn: ["C#"], category: "framework" },

  // ── Libraries ──
  { name: "jQuery", dependsOn: ["JavaScript"], category: "library" },
  { name: "Bootstrap", dependsOn: ["JavaScript"], category: "library" },
  { name: "Tailwind CSS", dependsOn: [], category: "library" },
  { name: "Lodash", dependsOn: ["JavaScript"], category: "library" },
  { name: "Moment.js", dependsOn: ["JavaScript"], category: "library" },
  { name: "D3.js", dependsOn: ["JavaScript"], category: "library" },
  { name: "Three.js", dependsOn: ["JavaScript"], category: "library" },
  { name: "Socket.IO", dependsOn: ["JavaScript"], category: "library" },
  { name: "Axios", dependsOn: ["JavaScript"], category: "library" },

  // ── CMS ──
  { name: "WordPress", dependsOn: ["PHP", "MySQL"], category: "cms" },
  { name: "Drupal", dependsOn: ["PHP", "MySQL"], category: "cms" },
  { name: "Joomla", dependsOn: ["PHP", "MySQL"], category: "cms" },
  { name: "Ghost", dependsOn: ["JavaScript", "MySQL"], category: "cms" },
  { name: "Strapi", dependsOn: ["JavaScript"], category: "cms" },
  { name: "Contentful", dependsOn: [], category: "cms" },
  { name: "Shopify", dependsOn: [], category: "cms" },
  { name: "Magento", dependsOn: ["PHP", "MySQL"], category: "cms" },
  { name: "Squarespace", dependsOn: [], category: "cms" },
  { name: "Wix", dependsOn: [], category: "cms" },

  // ── Databases ──
  { name: "MySQL", dependsOn: [], category: "database" },
  { name: "PostgreSQL", dependsOn: [], category: "database" },
  { name: "MongoDB", dependsOn: [], category: "database" },
  { name: "Redis", dependsOn: [], category: "database" },
  { name: "SQLite", dependsOn: [], category: "database" },
  { name: "Elasticsearch", dependsOn: ["Java"], category: "database" },
  { name: "MariaDB", dependsOn: [], category: "database" },
  { name: "CouchDB", dependsOn: [], category: "database" },

  // ── Servers ──
  { name: "Nginx", dependsOn: [], category: "server" },
  { name: "Apache", dependsOn: [], category: "server" },
  { name: "Apache HTTP Server", dependsOn: [], category: "server" },
  { name: "IIS", dependsOn: [], category: "server" },
  { name: "Tomcat", dependsOn: ["Java"], category: "server" },
  { name: "Node.js", dependsOn: ["JavaScript"], category: "server" },
  { name: "Caddy", dependsOn: ["Go"], category: "server" },
  { name: "LiteSpeed", dependsOn: [], category: "server" },
  { name: "Gunicorn", dependsOn: ["Python"], category: "server" },
  { name: "Uvicorn", dependsOn: ["Python"], category: "server" },

  // ── CDN / Delivery ──
  { name: "Cloudflare", dependsOn: [], category: "cdn" },
  { name: "Akamai", dependsOn: [], category: "cdn" },
  { name: "Fastly", dependsOn: [], category: "cdn" },
  { name: "AWS CloudFront", dependsOn: [], category: "cdn" },
  { name: "jsDelivr", dependsOn: [], category: "cdn" },
  { name: "unpkg", dependsOn: [], category: "cdn" },
  { name: "cdnjs", dependsOn: [], category: "cdn" },
  { name: "Varnish", dependsOn: [], category: "cdn" },

  // ── Analytics ──
  { name: "Google Analytics", dependsOn: ["JavaScript"], category: "analytics" },
  { name: "Google Tag Manager", dependsOn: ["JavaScript"], category: "analytics" },
  { name: "Hotjar", dependsOn: ["JavaScript"], category: "analytics" },
  { name: "Mixpanel", dependsOn: ["JavaScript"], category: "analytics" },
  { name: "Segment", dependsOn: ["JavaScript"], category: "analytics" },
  { name: "Matomo", dependsOn: ["PHP", "MySQL"], category: "analytics" },
  { name: "Plausible", dependsOn: ["JavaScript"], category: "analytics" },

  // ── Security ──
  { name: "reCAPTCHA", dependsOn: ["JavaScript"], category: "security" },
  { name: "hCaptcha", dependsOn: ["JavaScript"], category: "security" },
  { name: "Let's Encrypt", dependsOn: [], category: "security" },
  { name: "ModSecurity", dependsOn: ["Apache"], category: "security" },
  { name: "Sucuri", dependsOn: [], category: "security" },
  { name: "Wordfence", dependsOn: ["WordPress"], category: "security" },

  // ── Cloud ──
  { name: "AWS", dependsOn: [], category: "cloud" },
  { name: "Azure", dependsOn: [], category: "cloud" },
  { name: "Google Cloud", dependsOn: [], category: "cloud" },
  { name: "DigitalOcean", dependsOn: [], category: "cloud" },
  { name: "Heroku", dependsOn: [], category: "cloud" },
  { name: "Vercel", dependsOn: ["JavaScript"], category: "cloud" },
  { name: "Netlify", dependsOn: ["JavaScript"], category: "cloud" },
  { name: "Docker", dependsOn: [], category: "cloud" },
  { name: "Kubernetes", dependsOn: ["Docker"], category: "cloud" },

  // ── Build Tools ──
  { name: "Webpack", dependsOn: ["JavaScript"], category: "build_tool" },
  { name: "Vite", dependsOn: ["JavaScript"], category: "build_tool" },
  { name: "Babel", dependsOn: ["JavaScript"], category: "build_tool" },
  { name: "ESLint", dependsOn: ["JavaScript"], category: "build_tool" },
  { name: "Prettier", dependsOn: ["JavaScript"], category: "build_tool" },
  { name: "Rollup", dependsOn: ["JavaScript"], category: "build_tool" },
  { name: "esbuild", dependsOn: ["Go"], category: "build_tool" },
  { name: "Parcel", dependsOn: ["JavaScript"], category: "build_tool" },
];

// ── Graph Building ──────────────────────────────────────────────────

export interface TechDepNode {
  id: string;
  name: string;
  category: TechCategory;
  /** Number of assets using this technology */
  assetCount: number;
  /** Whether this tech was detected in the scan */
  detected: boolean;
  /** Version if known */
  version?: string;
  /** Whether version is outdated */
  isOutdated?: boolean;
  // Force simulation fields
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
}

export interface TechDepEdge {
  source: string;
  target: string;
  type: "depends_on" | "implied";
}

export interface TechDepGraph {
  nodes: TechDepNode[];
  edges: TechDepEdge[];
  categories: { category: TechCategory; count: number }[];
}

/**
 * Build a tech dependency graph from detected technologies.
 * Only includes technologies that were detected OR are direct dependencies
 * of detected technologies (to show the dependency chain).
 */
export function buildTechDepGraph(
  detectedTechs: { name: string; count: number; version?: string; isOutdated?: boolean }[]
): TechDepGraph {
  const detectedSet = new Set(detectedTechs.map(t => t.name.toLowerCase()));
  const detectedMap = new Map(detectedTechs.map(t => [t.name.toLowerCase(), t]));

  // Find all relevant techs: detected + their dependencies (up to 2 levels deep)
  const relevantTechs = new Set<string>();
  const depLookup = new Map(TECH_DEPENDENCIES.map(d => [d.name.toLowerCase(), d]));

  // First pass: add all detected techs
  for (const t of detectedTechs) {
    const dep = depLookup.get(t.name.toLowerCase());
    if (dep) {
      relevantTechs.add(dep.name);
    } else {
      // Tech not in our dependency map — add as standalone
      relevantTechs.add(t.name);
    }
  }

  // Second pass: add dependencies of detected techs (2 levels deep)
  const addDeps = (techName: string, depth: number) => {
    if (depth > 2) return;
    const dep = depLookup.get(techName.toLowerCase());
    if (!dep) return;
    for (const parent of dep.dependsOn) {
      relevantTechs.add(parent);
      addDeps(parent, depth + 1);
    }
  };
  for (const tech of [...relevantTechs]) {
    addDeps(tech, 0);
  }

  // Build nodes
  const nodes: TechDepNode[] = [];
  const nodeIds = new Set<string>();

  for (const techName of relevantTechs) {
    const id = techName.toLowerCase().replace(/[^a-z0-9]/g, "-");
    if (nodeIds.has(id)) continue;
    nodeIds.add(id);

    const dep = depLookup.get(techName.toLowerCase());
    const detected = detectedMap.get(techName.toLowerCase());

    nodes.push({
      id,
      name: techName,
      category: dep?.category || "other",
      assetCount: detected?.count || 0,
      detected: detectedSet.has(techName.toLowerCase()),
      version: detected?.version,
      isOutdated: detected?.isOutdated,
    });
  }

  // Build edges
  const edges: TechDepEdge[] = [];
  for (const techName of relevantTechs) {
    const dep = depLookup.get(techName.toLowerCase());
    if (!dep) continue;
    const sourceId = techName.toLowerCase().replace(/[^a-z0-9]/g, "-");
    for (const parentName of dep.dependsOn) {
      const targetId = parentName.toLowerCase().replace(/[^a-z0-9]/g, "-");
      if (nodeIds.has(sourceId) && nodeIds.has(targetId)) {
        edges.push({
          source: sourceId,
          target: targetId,
          type: detectedSet.has(techName.toLowerCase()) ? "depends_on" : "implied",
        });
      }
    }
  }

  // Category counts
  const catCounts = new Map<TechCategory, number>();
  for (const n of nodes) {
    if (n.detected) {
      catCounts.set(n.category, (catCounts.get(n.category) || 0) + 1);
    }
  }
  const categories = [...catCounts.entries()]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count);

  return { nodes, edges, categories };
}
