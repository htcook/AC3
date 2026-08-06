/**
 * ZAP Technology Name Validator
 * 
 * Filters technology names to only include those recognized by ZAP's
 * includeTechnologyList / includeContextTechnologies API endpoints.
 * 
 * ZAP uses a hierarchical technology tree. Only exact matches (case-insensitive
 * matching against canonical names) are accepted. Invalid names cause "Bad Action"
 * errors from the ZAP API.
 * 
 * Reference: https://www.zaproxy.org/docs/desktop/start/features/techs/
 */

// Canonical ZAP technology names (from ZAP's built-in tech tree)
// These are the ONLY values ZAP accepts in includeTechnologyList/includeContextTechnologies
export const ZAP_VALID_TECHNOLOGIES: ReadonlySet<string> = new Set([
  // ─── Top-level categories ───
  "Db", "Language", "OS", "SCM", "WS",
  
  // ─── Databases (Db) ───
  "Db.CouchDB", "Db.Firebird", "Db.HypersonicSQL",
  "Db.IBM DB2", "Db.Microsoft Access", "Db.Microsoft SQL Server",
  "Db.MongoDB", "Db.MySQL", "Db.Oracle", "Db.PostgreSQL",
  "Db.SAP MaxDB", "Db.SQLite", "Db.Sybase",
  // Short forms also accepted by ZAP
  "CouchDB", "Firebird", "HypersonicSQL", "HSQLDB",
  "IBM DB2", "Microsoft Access", "Microsoft SQL Server", "MsSQL",
  "MongoDB", "MySQL", "MariaDB", "Oracle", "PostgreSQL",
  "SAP MaxDB", "SQLite", "Sybase",
  
  // ─── Languages (Language) ───
  "Language.ASP", "Language.C", "Language.Java", "Language.JavaScript",
  "Language.JSP/Servlet", "Language.PHP", "Language.Python",
  "Language.Ruby", "Language.XML",
  // Short forms
  "ASP", "ASP.NET", "C", "Java", "JavaScript", "JSP/Servlet", "JSP",
  "PHP", "Python", "Ruby", "XML",
  
  // ─── Operating Systems (OS) ───
  "OS.Linux", "OS.MacOS", "OS.Windows",
  // Short forms
  "Linux", "MacOS", "Windows",
  
  // ─── SCM ───
  "SCM.Git", "SCM.SVN",
  "Git", "SVN",
  
  // ─── Web Servers / Frameworks (WS) ───
  "WS.Apache", "WS.IIS", "WS.Tomcat",
  // Short forms and common web technologies ZAP recognizes
  "Apache", "IIS", "Tomcat", "Nginx",
  
  // ─── Frameworks & Libraries ───
  "Spring", "Spring Boot", "Spring Framework",
  "Django", "Flask",
  "Laravel", "Symfony", "CodeIgniter", "CakePHP",
  "Ruby on Rails", "Rails",
  "Express", "Node.js", "Next.js", "React", "Angular", "Vue.js",
  "jQuery", "Bootstrap",
  ".NET", ".NET Framework", ".NET Core",
  
  // ─── CMS ───
  "WordPress", "Drupal", "Joomla", "Magento", "Shopify",
  "Ghost", "Typo3", "Umbraco",
  
  // ─── Application Servers ───
  "JBoss", "WebLogic", "WebSphere", "GlassFish", "WildFly",
  "Jetty", "Undertow",
  
  // ─── Caching / Proxies ───
  "Varnish", "Squid", "HAProxy", "CloudFlare", "Cloudflare",
  "Akamai", "Fastly",
  
  // ─── Other recognized technologies ───
  "GraphQL", "REST", "SOAP", "gRPC",
  "Docker", "Kubernetes",
  "Redis", "Memcached", "Elasticsearch",
  "RabbitMQ", "Kafka",
  "AWS", "Azure", "GCP", "Google Cloud",
]);

// Lowercase lookup map for case-insensitive matching
const ZAP_TECH_LOWERCASE_MAP: Map<string, string> = new Map(
  Array.from(ZAP_VALID_TECHNOLOGIES).map(t => [t.toLowerCase(), t])
);

/**
 * Validate and filter a list of technology names, returning only those
 * recognized by ZAP's API.
 * 
 * @param technologies - Raw technology names (from LLM, asset fingerprinting, etc.)
 * @returns Filtered array of valid ZAP technology names
 */
export function filterValidZapTechnologies(technologies: string[]): string[] {
  if (!technologies?.length) return [];
  
  const valid: string[] = [];
  const invalid: string[] = [];
  
  for (const tech of technologies) {
    if (!tech || typeof tech !== 'string') continue;
    
    const trimmed = tech.trim();
    if (!trimmed || trimmed.toLowerCase() === 'unknown') continue;
    
    // Direct match (case-insensitive)
    const canonical = ZAP_TECH_LOWERCASE_MAP.get(trimmed.toLowerCase());
    if (canonical) {
      valid.push(canonical);
      continue;
    }
    
    // Try partial matching for common patterns
    // e.g., "Apache HTTP Server" → "Apache", "Microsoft SQL Server 2019" → "Microsoft SQL Server"
    let matched = false;
    for (const [lowerKey, canonicalName] of ZAP_TECH_LOWERCASE_MAP) {
      if (trimmed.toLowerCase().startsWith(lowerKey) || lowerKey.startsWith(trimmed.toLowerCase())) {
        valid.push(canonicalName);
        matched = true;
        break;
      }
    }
    
    if (!matched) {
      invalid.push(trimmed);
    }
  }
  
  if (invalid.length > 0) {
    console.warn(`[ZAP TechValidator] Filtered ${invalid.length} invalid technology name(s): ${invalid.join(", ")}`);
  }
  
  // Deduplicate
  return [...new Set(valid)];
}

/**
 * Check if a single technology name is valid for ZAP.
 */
export function isValidZapTechnology(tech: string): boolean {
  if (!tech || typeof tech !== 'string') return false;
  return ZAP_TECH_LOWERCASE_MAP.has(tech.trim().toLowerCase());
}
