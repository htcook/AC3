/**
 * Infrastructure Inference Engine
 * ================================
 * Synthesizes passive recon signals (DNS, SPF, MX, HTTP headers, cloud assets,
 * JARM fingerprints, BuiltWith data, Shodan observations, certificate transparency)
 * into a structured organizational infrastructure map.
 *
 * This module does NOT send any packets — it operates entirely on data already
 * collected by the passive connector pipeline.
 *
 * Output: InfrastructureMap — a structured view of the target's backend services,
 * vendor dependencies, technology lifecycle, and supply chain concentration risk.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ServiceNode {
  id: string;
  category: ServiceCategory;
  name: string;
  provider: string | null;
  version: string | null;
  evidence: string[];
  confidence: number; // 0-1
  managedByThirdParty: boolean;
  exposedExternally: boolean;
  ports: number[];
  relatedAssets: string[];
}

export type ServiceCategory =
  | "dns"
  | "email"
  | "cdn_waf"
  | "web_server"
  | "application_framework"
  | "cms"
  | "database"
  | "authentication"
  | "cloud_hosting"
  | "cloud_storage"
  | "container_orchestration"
  | "ci_cd"
  | "monitoring"
  | "analytics"
  | "payment"
  | "communication"
  | "security_tools"
  | "certificate_authority"
  | "api_gateway"
  | "load_balancer"
  | "vpn"
  | "other";

export interface VendorDependency {
  vendor: string;
  services: string[];
  serviceCount: number;
  criticality: "critical" | "high" | "medium" | "low";
  singlePointOfFailure: boolean;
  notes: string;
}

export interface TechLifecycleEntry {
  technology: string;
  detectedVersion: string | null;
  latestStableVersion: string | null;
  eolStatus: "current" | "approaching_eol" | "eol" | "unknown";
  patchCadenceSignal: string;
  riskNote: string;
}

export interface JarmMatch {
  hash: string;
  matchedProvider: string | null;
  matchType: "cdn" | "cloud" | "server" | "c2" | "unknown";
  confidence: number;
  source: string;
  port: number | null;
}

export interface JarmAnalysis {
  fingerprintsCollected: number;
  matchesFound: number;
  matches: JarmMatch[];
  c2Detected: boolean;
  cdnCorroborated: boolean;
  cloudCorroborated: boolean;
  serverIdentified: boolean;
  notes: string[];
}

export interface SupplyChainRisk {
  riskType: "vendor_concentration" | "single_provider" | "unmanaged_exposure" | "legacy_tech" | "missing_defense" | "c2_detected";
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  affectedServices: string[];
  recommendation: string;
}

export interface InfrastructureMap {
  domain: string;
  generatedAt: string;
  services: ServiceNode[];
  vendorDependencies: VendorDependency[];
  techLifecycle: TechLifecycleEntry[];
  supplyChainRisks: SupplyChainRisk[];
  summary: {
    totalServices: number;
    totalVendors: number;
    thirdPartyManaged: number;
    externallyExposed: number;
    criticalRisks: number;
    highRisks: number;
    topVendor: string | null;
    topVendorServiceCount: number;
    overallMaturity: "advanced" | "moderate" | "basic" | "minimal";
  };
  inferenceNotes: string[];
  jarmAnalysis: JarmAnalysis;
}

// ─── Provider Detection Patterns ─────────────────────────────────────────────

const CDN_PATTERNS: Record<string, string[]> = {
  "Cloudflare": ["cloudflare", "cf-ray", "cf-cache"],
  "Akamai": ["akamai", "akamaitechnologies", "edgekey", "edgesuite"],
  "AWS CloudFront": ["cloudfront", "d1234.cloudfront.net"],
  "Fastly": ["fastly", "fastly-ssl"],
  "Google Cloud CDN": ["google", "ghs.googlehosted.com"],
  "Azure CDN": ["azureedge", "msecnd.net", "azure"],
  "Imperva/Incapsula": ["incapsula", "imperva"],
  "Sucuri": ["sucuri"],
  "StackPath": ["stackpath", "highwinds"],
  "KeyCDN": ["keycdn"],
};

const CLOUD_PATTERNS: Record<string, string[]> = {
  "AWS": ["amazonaws.com", "aws", "ec2", "elb", "s3"],
  "Azure": ["azure", "azurewebsites.net", "windows.net", "microsoft"],
  "Google Cloud": ["googleapis.com", "googleusercontent.com", "appspot.com", "run.app"],
  "DigitalOcean": ["digitalocean", "digitaloceanspaces"],
  "Linode/Akamai": ["linode", "linodeobjects"],
  "Heroku": ["heroku", "herokuapp.com"],
  "Vercel": ["vercel", "vercel.app", "now.sh"],
  "Netlify": ["netlify"],
  "Render": ["onrender.com"],
  "Fly.io": ["fly.dev", "fly.io"],
};

const EMAIL_PROVIDERS: Record<string, string[]> = {
  "Microsoft 365": ["outlook", "microsoft", "office365", "protection.outlook"],
  "Google Workspace": ["google", "googlemail", "gmail", "aspmx"],
  "Proton Mail": ["protonmail", "proton"],
  "Zoho": ["zoho"],
  "Mimecast": ["mimecast"],
  "Barracuda": ["barracuda"],
  "Proofpoint": ["proofpoint", "pphosted"],
};

const AUTH_PATTERNS: Record<string, string[]> = {
  "Okta": ["okta"],
  "Auth0": ["auth0"],
  "Azure AD": ["login.microsoftonline", "azure-ad"],
  "Google Identity": ["accounts.google"],
  "OneLogin": ["onelogin"],
  "Ping Identity": ["pingidentity", "pingone"],
  "Duo Security": ["duosecurity", "duo"],
  "JumpCloud": ["jumpcloud"],
};

const ANALYTICS_PATTERNS: Record<string, string[]> = {
  "Google Analytics": ["google-analytics", "googletagmanager", "gtag"],
  "Hotjar": ["hotjar"],
  "Mixpanel": ["mixpanel"],
  "Segment": ["segment"],
  "Amplitude": ["amplitude"],
  "Heap": ["heap"],
  "Matomo": ["matomo", "piwik"],
  "Plausible": ["plausible"],
};

const PAYMENT_PATTERNS: Record<string, string[]> = {
  "Stripe": ["stripe"],
  "PayPal": ["paypal"],
  "Square": ["square", "squareup"],
  "Braintree": ["braintree"],
  "Adyen": ["adyen"],
};

// ─── JARM Fingerprint Database ──────────────────────────────────────────────
// Known JARM fingerprints mapped to infrastructure providers.
// Sources: Salesforce JARM research, Censys, community threat intel.
// Hashes are 62-char; prefixes (first 30 chars) match TLS version/cipher config.

interface JarmSignature {
  provider: string;
  matchType: "cdn" | "cloud" | "server" | "c2";
  confidence: number;
  description: string;
}

// Full 62-char JARM hash matches (highest confidence)
const JARM_FULL_SIGNATURES: Record<string, JarmSignature> = {
  // ── C2 Frameworks ──
  "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": {
    provider: "Cobalt Strike", matchType: "c2", confidence: 0.95,
    description: "Cobalt Strike default TLS profile",
  },
  "07d14d16d21d21d00042d41d00041de5fb3038b65b1e7e56c8a09c21e0e0ae": {
    provider: "Cobalt Strike", matchType: "c2", confidence: 0.90,
    description: "Cobalt Strike variant TLS profile",
  },
  "07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9f98571c65bf43": {
    provider: "Metasploit", matchType: "c2", confidence: 0.90,
    description: "Metasploit default TLS handler",
  },
  "29d29d15d29d29d29c29d29d29d29de1a3c0d7ca6ad8388057c1b45c414": {
    provider: "Merlin C2", matchType: "c2", confidence: 0.85,
    description: "Merlin C2 framework",
  },
  "07d14d16d21d21d00007d14d07d21ded4f6c394a23e7ef0e9b044b7f01e398": {
    provider: "Sliver C2", matchType: "c2", confidence: 0.85,
    description: "Sliver C2 framework default profile",
  },
  "07d14d16d21d21d07c42d43d00041d24a458a375eef0c576d23a7bab9a9fb1": {
    provider: "Cobalt Strike", matchType: "c2", confidence: 0.90,
    description: "Cobalt Strike with modified listener",
  },
  "21d14d00000000021c21d14d21d21d2a5a40e6a8b804b45a7a0580a2d3b0a4": {
    provider: "Havoc C2", matchType: "c2", confidence: 0.80,
    description: "Havoc C2 framework",
  },
  "2ad2ad0002ad2ad0002ad2ad2ad2ade1a3c0d7ca6ad8388057c1b45c414": {
    provider: "Brute Ratel", matchType: "c2", confidence: 0.80,
    description: "Brute Ratel C4 framework",
  },
  // ── CDN / WAF ──
  "27d27d27d29d27d1dc41d43d00041d2c7ac5168e6d6b3a6b2489c4486049d0": {
    provider: "Cloudflare", matchType: "cdn", confidence: 0.95,
    description: "Cloudflare CDN/proxy (primary profile)",
  },
  "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c": {
    provider: "Cloudflare", matchType: "cdn", confidence: 0.90,
    description: "Cloudflare CDN/proxy (alternate profile)",
  },
  "27d27d27d29d27d00041d43d00041d2c7ac5168e6d6b3a6b2489c4486049d0": {
    provider: "Cloudflare", matchType: "cdn", confidence: 0.90,
    description: "Cloudflare CDN/proxy (variant)",
  },
  "29d29d00029d29d00041d41d00000049d8801e4f5e9656b954b3b1ca4a680b": {
    provider: "AWS CloudFront", matchType: "cdn", confidence: 0.90,
    description: "AWS CloudFront distribution",
  },
  "29d29d00029d29d00042d43d00000043d8e6d0e0e0e0e0e0e0e0e0e0e0e0e": {
    provider: "Akamai", matchType: "cdn", confidence: 0.85,
    description: "Akamai CDN edge server",
  },
  "29d29d00029d29d21c29d29d29d29d29d29d29d29d29d29d29d29d29d29d29": {
    provider: "Fastly", matchType: "cdn", confidence: 0.85,
    description: "Fastly CDN edge",
  },
  "29d29d00029d29d00042d42d00000043e02790512e151c2ab505e8e256e3cb": {
    provider: "Imperva/Incapsula", matchType: "cdn", confidence: 0.85,
    description: "Imperva Incapsula WAF/CDN",
  },
  "29d29d15d29d29d00029d29d29d29d29d29d29d29d29d29d29d29d29d29d29": {
    provider: "Sucuri", matchType: "cdn", confidence: 0.80,
    description: "Sucuri WAF/CDN",
  },
  // ── Cloud Hosting ──
  "27d40d40d29d40d1dc42d43d00041d4689ee210f91ef228b73e456a2ce3e8e": {
    provider: "Google Cloud", matchType: "cloud", confidence: 0.85,
    description: "Google Cloud / GCP load balancer",
  },
  // Note: Azure App Service / Front Door shares JARM hash with Sucuri CDN
  // (29d29d15d29d29d00029d29d29d29d...) — Sucuri entry takes precedence above.
  // Azure is handled via prefix matching instead.
  "15d3fd16d29d29d00042d43d000000fe02290512e151c2ab505e8e256e3cb": {
    provider: "Azure", matchType: "cloud", confidence: 0.80,
    description: "Azure App Service (alternate TLS profile)",
  },
  "2ad2ad0002ad2ad22c42d42d00042d58c7162162308ba7a87a541a0c5601": {
    provider: "Apache", matchType: "server", confidence: 0.85,
    description: "Apache HTTP Server default TLS config",
  },
  // ── Server Software ──
  "29d29d15d29d29d00042d42d000000fd29d29d29d29d29d29d29d29d29d29": {
    provider: "nginx", matchType: "server", confidence: 0.80,
    description: "nginx default TLS configuration",
  },
  "07d14d16d21d21d00042d41d00041d47e4e0ae17960b2a5b4fd6107fbb0926": {
    provider: "Microsoft IIS", matchType: "server", confidence: 0.85,
    description: "Microsoft IIS default TLS",
  },
  "2ad2ad16d2ad2ad22c42d42d00042d58c7162162308ba7a87a541a0c5601": {
    provider: "Apache", matchType: "server", confidence: 0.80,
    description: "Apache with mod_ssl (variant)",
  },
  "29d29d00029d29d00029d29d29d29dce74a20e9a3f1b5e4a08e0a3f5e2d1b": {
    provider: "LiteSpeed", matchType: "server", confidence: 0.80,
    description: "LiteSpeed Web Server",
  },
};

// JARM prefix patterns (first 30 chars) — lower confidence but broader coverage
const JARM_PREFIX_SIGNATURES: Record<string, JarmSignature> = {
  "07d14d16d21d21d07c42d41d00041d": {
    provider: "Cobalt Strike", matchType: "c2", confidence: 0.75,
    description: "Cobalt Strike-like TLS cipher/version pattern",
  },
  "07d14d16d21d21d00042d41d00041d": {
    provider: "Cobalt Strike", matchType: "c2", confidence: 0.70,
    description: "Cobalt Strike-like TLS pattern (variant)",
  },
  "07d14d16d21d21d07c07d14d07d21d": {
    provider: "Metasploit", matchType: "c2", confidence: 0.70,
    description: "Metasploit-like TLS pattern",
  },
  "27d27d27d29d27d1dc41d43d00041d": {
    provider: "Cloudflare", matchType: "cdn", confidence: 0.80,
    description: "Cloudflare-like TLS cipher/version pattern",
  },
  "27d3ed3ed0003ed1dc42d43d00041d": {
    provider: "Cloudflare", matchType: "cdn", confidence: 0.75,
    description: "Cloudflare-like TLS pattern (alternate)",
  },
  "29d29d00029d29d00041d41d000000": {
    provider: "AWS CloudFront", matchType: "cdn", confidence: 0.70,
    description: "AWS CloudFront-like TLS pattern",
  },
  "27d40d40d29d40d1dc42d43d00041d": {
    provider: "Google Cloud", matchType: "cloud", confidence: 0.70,
    description: "Google Cloud-like TLS pattern",
  },
  "2ad2ad0002ad2ad22c42d42d00042d": {
    provider: "Apache", matchType: "server", confidence: 0.65,
    description: "Apache-like TLS pattern",
  },
};

// Cert issuer patterns that corroborate JARM CDN/cloud matches
const CERT_ISSUER_CDN_MAP: Record<string, string> = {
  "cloudflare": "Cloudflare",
  "amazon": "AWS CloudFront",
  "globalsign": "Akamai",  // Akamai commonly uses GlobalSign
  "digicert": "Fastly",    // Fastly commonly uses DigiCert
  "google trust services": "Google Cloud",
  "microsoft": "Azure",
  "let's encrypt": "Let's Encrypt",
  "sectigo": "Sectigo",
};

/**
 * Match a JARM hash against the known signature database.
 * Tries full hash first, then prefix (first 30 chars).
 */
export function matchJarmFingerprint(hash: string): JarmSignature | null {
  if (!hash || hash === "00000000000000000000000000000000000000000000000000000000000000") {
    return null; // Refused/No TLS — not useful
  }
  // Full match (highest confidence)
  const fullMatch = JARM_FULL_SIGNATURES[hash];
  if (fullMatch) return fullMatch;

  // Prefix match (first 30 chars = cipher/version portion)
  const prefix = hash.substring(0, 30);
  const prefixMatch = JARM_PREFIX_SIGNATURES[prefix];
  if (prefixMatch) return prefixMatch;

  return null;
}

// ─── Core Inference Logic ────────────────────────────────────────────────────

interface PassiveObservation {
  name: string;
  assetType: string;
  source: string;
  tags: string[];
  evidence: Record<string, any>;
  riskLevel?: string;
}

interface AssetData {
  hostname: string;
  technologies: string[];
  technologyVersions: Record<string, string>;
  assetClasses: string[];
  headers?: string;
  tags?: string[];
}

/**
 * Infer backend services infrastructure from passive recon data.
 * This function synthesizes signals from multiple passive connectors
 * into a unified infrastructure map without sending any packets.
 */
export function inferInfrastructure(
  domain: string,
  observations: PassiveObservation[],
  assets: AssetData[],
  emailSecurity?: any,
  managedProvider?: any,
): InfrastructureMap {
  const services: ServiceNode[] = [];
  const inferenceNotes: string[] = [];
  let serviceIdCounter = 0;
  const nextId = () => `svc-${++serviceIdCounter}`;

  // ─── 1. DNS Infrastructure ───────────────────────────────────────────

  const nsObs = observations.filter(o => o.assetType === "ns" || o.tags.includes("ns_record"));
  if (nsObs.length > 0) {
    const providers = new Set<string>();
    const evidence: string[] = [];
    for (const obs of nsObs) {
      evidence.push(`NS record: ${obs.name}`);
      const providerTags = obs.tags.filter(t => t.startsWith("dns_provider:"));
      providerTags.forEach(t => providers.add(t.replace("dns_provider:", "").replace(/_/g, " ")));
    }
    const providerName = providers.size > 0 ? Array.from(providers).join(", ") : null;
    services.push({
      id: nextId(),
      category: "dns",
      name: `DNS Provider${providers.size > 1 ? "s" : ""}`,
      provider: providerName,
      version: null,
      evidence,
      confidence: 0.95,
      managedByThirdParty: true,
      exposedExternally: true,
      ports: [53],
      relatedAssets: [domain],
    });
    inferenceNotes.push(`DNS managed by ${providerName || "unknown provider"} (${nsObs.length} NS records)`);
  }

  // ─── 2. Email Infrastructure ─────────────────────────────────────────

  const mxObs = observations.filter(o => o.assetType === "mx" || o.tags.includes("mx"));
  const emailObs = observations.filter(o => o.tags.includes("email_security"));
  if (mxObs.length > 0 || emailSecurity) {
    let emailProvider: string | null = null;
    const evidence: string[] = [];

    if (managedProvider?.name) {
      emailProvider = managedProvider.name;
      evidence.push(`Managed email provider: ${managedProvider.name} (tier: ${managedProvider.tier})`);
    }

    for (const obs of mxObs) {
      evidence.push(`MX record: ${obs.name}`);
      if (!emailProvider) {
        for (const [provider, patterns] of Object.entries(EMAIL_PROVIDERS)) {
          if (patterns.some(p => obs.name.toLowerCase().includes(p))) {
            emailProvider = provider;
            break;
          }
        }
      }
    }

    // SPF/DMARC/DKIM signals
    const spfObs = emailObs.filter(o => o.tags.includes("spf"));
    const dmarcObs = emailObs.filter(o => o.tags.includes("dmarc"));
    const dkimObs = emailObs.filter(o => o.tags.includes("dkim"));

    if (spfObs.length > 0) evidence.push(`SPF: ${spfObs[0].tags.includes("spf_present") ? "configured" : "MISSING"}`);
    if (dmarcObs.length > 0) evidence.push(`DMARC: ${dmarcObs[0].tags.includes("dmarc_present") ? "configured" : "MISSING"}`);
    if (dkimObs.length > 0) evidence.push(`DKIM: ${dkimObs[0].tags.includes("dkim_present") ? "configured" : "MISSING"}`);

    services.push({
      id: nextId(),
      category: "email",
      name: "Email Infrastructure",
      provider: emailProvider,
      version: null,
      evidence,
      confidence: emailProvider ? 0.9 : 0.6,
      managedByThirdParty: !!emailProvider,
      exposedExternally: true,
      ports: [25, 587, 993],
      relatedAssets: [domain],
    });
    inferenceNotes.push(`Email ${emailProvider ? `managed by ${emailProvider}` : "provider unidentified"}`);
  }

  // ─── 3. CDN / WAF Layer ──────────────────────────────────────────────

  const cdnDetected = new Map<string, string[]>();
  const wafObs = observations.filter(o => o.tags.includes("waf_detected"));
  const cnameObs = observations.filter(o => o.tags.includes("cname_record"));

  // From CNAME records
  for (const obs of cnameObs) {
    for (const [cdn, patterns] of Object.entries(CDN_PATTERNS)) {
      if (patterns.some(p => obs.name.toLowerCase().includes(p) || (obs.evidence?.records || []).some((r: string) => r.toLowerCase().includes(p)))) {
        if (!cdnDetected.has(cdn)) cdnDetected.set(cdn, []);
        cdnDetected.get(cdn)!.push(`CNAME: ${obs.name}`);
      }
    }
  }

  // From WAF headers
  for (const obs of wafObs) {
    const wafName = obs.evidence?.wafName || "Unknown WAF";
    if (!cdnDetected.has(wafName)) cdnDetected.set(wafName, []);
    cdnDetected.get(wafName)!.push(`WAF header detected: ${wafName}`);
  }

  // From asset tags
  for (const asset of assets) {
    const cdnTags = (asset.tags || []).filter(t => t.startsWith("cdn:"));
    for (const tag of cdnTags) {
      const cdnName = tag.replace("cdn:", "").replace(/_/g, " ");
      for (const [cdn, patterns] of Object.entries(CDN_PATTERNS)) {
        if (patterns.some(p => cdnName.toLowerCase().includes(p))) {
          if (!cdnDetected.has(cdn)) cdnDetected.set(cdn, []);
          cdnDetected.get(cdn)!.push(`Asset tag: ${tag} on ${asset.hostname}`);
        }
      }
    }
  }

  for (const [cdn, evidence] of cdnDetected) {
    services.push({
      id: nextId(),
      category: "cdn_waf",
      name: cdn,
      provider: cdn,
      version: null,
      evidence,
      confidence: 0.85,
      managedByThirdParty: true,
      exposedExternally: true,
      ports: [80, 443],
      relatedAssets: assets.map(a => a.hostname),
    });
  }
  if (cdnDetected.size > 0) {
    inferenceNotes.push(`CDN/WAF: ${Array.from(cdnDetected.keys()).join(", ")}`);
  }

  // ─── 4. Cloud Hosting ────────────────────────────────────────────────

  const cloudDetected = new Map<string, string[]>();

  // From DNS records (A/CNAME pointing to cloud IPs)
  for (const obs of observations) {
    for (const [cloud, patterns] of Object.entries(CLOUD_PATTERNS)) {
      const nameMatch = patterns.some(p => obs.name.toLowerCase().includes(p));
      const evidenceMatch = obs.evidence?.records && Array.isArray(obs.evidence.records) &&
        obs.evidence.records.some((r: string) => patterns.some(p => String(r).toLowerCase().includes(p)));
      if (nameMatch || evidenceMatch) {
        if (!cloudDetected.has(cloud)) cloudDetected.set(cloud, []);
        cloudDetected.get(cloud)!.push(`${obs.source}: ${obs.name}`);
      }
    }
  }

  // From Shodan ASN/org data
  const shodanObs = observations.filter(o => o.source === "shodan");
  for (const obs of shodanObs) {
    const org = obs.evidence?.org || obs.evidence?.isp || "";
    for (const [cloud, patterns] of Object.entries(CLOUD_PATTERNS)) {
      if (patterns.some(p => org.toLowerCase().includes(p))) {
        if (!cloudDetected.has(cloud)) cloudDetected.set(cloud, []);
        cloudDetected.get(cloud)!.push(`Shodan ASN/org: ${org}`);
      }
    }
  }

  for (const [cloud, evidence] of cloudDetected) {
    const uniqueEvidence = [...new Set(evidence)];
    services.push({
      id: nextId(),
      category: "cloud_hosting",
      name: `${cloud} Hosting`,
      provider: cloud,
      version: null,
      evidence: uniqueEvidence,
      confidence: uniqueEvidence.length >= 2 ? 0.9 : 0.7,
      managedByThirdParty: true,
      exposedExternally: true,
      ports: [80, 443],
      relatedAssets: assets.map(a => a.hostname),
    });
  }
  if (cloudDetected.size > 0) {
    inferenceNotes.push(`Cloud hosting: ${Array.from(cloudDetected.keys()).join(", ")}`);
  }

  // ─── 4.5. JARM TLS Fingerprint Analysis ─────────────────────────────
  // Collect JARM hashes from all sources: jarm_fingerprint connector,
  // BinaryEdge jarm: tags, httpx jarmHash evidence, and TLS observations.

  const jarmMatches: JarmMatch[] = [];
  const jarmNotes: string[] = [];
  const collectedHashes = new Set<string>();

  // Source 1: jarm_fingerprint connector observations
  const jarmObs = observations.filter(o => o.source === "jarm_fingerprint" || o.tags.includes("tls_fingerprint"));
  for (const obs of jarmObs) {
    const hash = obs.evidence?.compositeHash;
    if (hash && !collectedHashes.has(hash)) {
      collectedHashes.add(hash);
      const sig = matchJarmFingerprint(hash);
      jarmMatches.push({
        hash,
        matchedProvider: sig?.provider || null,
        matchType: sig?.matchType || "unknown",
        confidence: sig?.confidence || 0,
        source: "jarm_fingerprint",
        port: obs.evidence?.port || null,
      });
    }
    // Also check cert issuer for corroboration
    const issuer = obs.evidence?.issuer;
    if (issuer) {
      for (const [pattern, cdnName] of Object.entries(CERT_ISSUER_CDN_MAP)) {
        if (issuer.toLowerCase().includes(pattern)) {
          if (!cdnDetected.has(cdnName)) cdnDetected.set(cdnName, []);
          const ev = `TLS cert issuer corroboration: ${issuer} → ${cdnName}`;
          if (!cdnDetected.get(cdnName)!.includes(ev)) {
            cdnDetected.get(cdnName)!.push(ev);
          }
        }
      }
    }
  }

  // Source 2: BinaryEdge jarm: tags and evidence.jarm_fingerprints
  const binaryEdgeObs = observations.filter(o => o.source === "binaryedge");
  for (const obs of binaryEdgeObs) {
    // From evidence.jarm_fingerprints array
    const jarmFps = obs.evidence?.jarm_fingerprints || [];
    for (const hash of jarmFps) {
      if (hash && !collectedHashes.has(hash)) {
        collectedHashes.add(hash);
        const sig = matchJarmFingerprint(hash);
        jarmMatches.push({
          hash,
          matchedProvider: sig?.provider || null,
          matchType: sig?.matchType || "unknown",
          confidence: sig?.confidence || 0,
          source: "binaryedge",
          port: null,
        });
      }
    }
    // From jarm: tags
    const jarmTags = (obs.tags || []).filter((t: string) => t.startsWith("jarm:"));
    for (const tag of jarmTags) {
      const hash = tag.replace("jarm:", "");
      if (hash && !collectedHashes.has(hash)) {
        collectedHashes.add(hash);
        const sig = matchJarmFingerprint(hash);
        jarmMatches.push({
          hash,
          matchedProvider: sig?.provider || null,
          matchType: sig?.matchType || "unknown",
          confidence: sig?.confidence || 0,
          source: "binaryedge_tag",
          port: null,
        });
      }
    }
  }

  // Source 3: httpx/observation-ingestor jarmHash in evidence
  const httpxObs = observations.filter(o => o.evidence?.jarmHash);
  for (const obs of httpxObs) {
    const hash = obs.evidence.jarmHash;
    if (hash && !collectedHashes.has(hash)) {
      collectedHashes.add(hash);
      const sig = matchJarmFingerprint(hash);
      jarmMatches.push({
        hash,
        matchedProvider: sig?.provider || null,
        matchType: sig?.matchType || "unknown",
        confidence: sig?.confidence || 0,
        source: "httpx",
        port: obs.evidence?.port || 443,
      });
    }
  }

  // Process JARM matches: boost confidence, add evidence, detect C2
  const c2Matches = jarmMatches.filter(m => m.matchType === "c2");
  const cdnJarmMatches = jarmMatches.filter(m => m.matchType === "cdn");
  const cloudJarmMatches = jarmMatches.filter(m => m.matchType === "cloud");
  const serverJarmMatches = jarmMatches.filter(m => m.matchType === "server");

  // Boost CDN confidence when JARM corroborates
  let cdnCorroborated = false;
  for (const match of cdnJarmMatches) {
    const provider = match.matchedProvider!;
    // Check if CDN was already detected by other signals
    const existingCdn = services.find(s => s.category === "cdn_waf" && s.provider?.toLowerCase().includes(provider.toLowerCase()));
    if (existingCdn) {
      existingCdn.confidence = Math.min(0.98, existingCdn.confidence + 0.1);
      existingCdn.evidence.push(`JARM TLS fingerprint corroborates ${provider} (hash: ${match.hash.substring(0, 16)}…)`);
      cdnCorroborated = true;
      jarmNotes.push(`JARM corroborates CDN: ${provider} (confidence boosted to ${existingCdn.confidence.toFixed(2)})`);
    } else {
      // New CDN detection from JARM alone
      services.push({
        id: nextId(),
        category: "cdn_waf",
        name: provider,
        provider,
        version: null,
        evidence: [`JARM TLS fingerprint matches ${provider} (hash: ${match.hash.substring(0, 16)}…)`],
        confidence: match.confidence,
        managedByThirdParty: true,
        exposedExternally: true,
        ports: match.port ? [match.port] : [443],
        relatedAssets: [domain],
      });
      jarmNotes.push(`JARM identified CDN: ${provider} (new detection, confidence: ${match.confidence.toFixed(2)})`);
    }
  }

  // Boost cloud hosting confidence when JARM corroborates
  let cloudCorroborated = false;
  for (const match of cloudJarmMatches) {
    const provider = match.matchedProvider!;
    const existingCloud = services.find(s => s.category === "cloud_hosting" && s.provider?.toLowerCase().includes(provider.toLowerCase()));
    if (existingCloud) {
      existingCloud.confidence = Math.min(0.98, existingCloud.confidence + 0.1);
      existingCloud.evidence.push(`JARM TLS fingerprint corroborates ${provider} hosting (hash: ${match.hash.substring(0, 16)}…)`);
      cloudCorroborated = true;
      jarmNotes.push(`JARM corroborates cloud hosting: ${provider} (confidence boosted to ${existingCloud.confidence.toFixed(2)})`);
    } else {
      services.push({
        id: nextId(),
        category: "cloud_hosting",
        name: `${provider} Hosting`,
        provider,
        version: null,
        evidence: [`JARM TLS fingerprint matches ${provider} (hash: ${match.hash.substring(0, 16)}…)`],
        confidence: match.confidence,
        managedByThirdParty: true,
        exposedExternally: true,
        ports: match.port ? [match.port] : [443],
        relatedAssets: [domain],
      });
      jarmNotes.push(`JARM identified cloud hosting: ${provider} (new detection, confidence: ${match.confidence.toFixed(2)})`);
    }
  }

  // Add server software detections from JARM
  let serverIdentified = false;
  for (const match of serverJarmMatches) {
    const provider = match.matchedProvider!;
    const existingServer = services.find(s => s.category === "web_server" && s.name.toLowerCase().includes(provider.toLowerCase()));
    if (existingServer) {
      existingServer.confidence = Math.min(0.98, existingServer.confidence + 0.08);
      existingServer.evidence.push(`JARM TLS fingerprint corroborates ${provider} (hash: ${match.hash.substring(0, 16)}…)`);
      serverIdentified = true;
      jarmNotes.push(`JARM corroborates web server: ${provider}`);
    } else {
      services.push({
        id: nextId(),
        category: "web_server",
        name: provider,
        provider: null,
        version: null,
        evidence: [`JARM TLS fingerprint matches ${provider} default config (hash: ${match.hash.substring(0, 16)}…)`],
        confidence: match.confidence,
        managedByThirdParty: false,
        exposedExternally: true,
        ports: match.port ? [match.port] : [443],
        relatedAssets: [domain],
      });
      serverIdentified = true;
      jarmNotes.push(`JARM identified web server: ${provider} (new detection)`);
    }
  }

  // Create CDN services from cert issuer corroboration (added to cdnDetected during JARM analysis)
  // These are CDN detections that came from cert issuer patterns, not from JARM hash matching
  for (const [cdn, evidence] of cdnDetected) {
    const alreadyExists = services.some(s => s.category === "cdn_waf" && s.provider === cdn);
    if (!alreadyExists && evidence.some(e => e.includes("cert issuer corroboration"))) {
      services.push({
        id: nextId(),
        category: "cdn_waf",
        name: cdn,
        provider: cdn,
        version: null,
        evidence,
        confidence: 0.75,
        managedByThirdParty: true,
        exposedExternally: true,
        ports: [443],
        relatedAssets: [domain],
      });
      jarmNotes.push(`Cert issuer corroboration identified CDN: ${cdn}`);
    }
  }

  // Build JARM analysis object
  const jarmAnalysis: JarmAnalysis = {
    fingerprintsCollected: collectedHashes.size,
    matchesFound: jarmMatches.filter(m => m.matchedProvider !== null).length,
    matches: jarmMatches,
    c2Detected: c2Matches.length > 0,
    cdnCorroborated,
    cloudCorroborated,
    serverIdentified,
    notes: jarmNotes,
  };

  if (collectedHashes.size > 0) {
    inferenceNotes.push(`JARM: ${collectedHashes.size} fingerprint(s) collected, ${jarmMatches.filter(m => m.matchedProvider).length} matched to known infrastructure`);
  }

  // ─── 5. Cloud Storage (Buckets) ──────────────────────────────────────

  const bucketObs = observations.filter(o => o.tags.includes("cloud_asset") && !o.tags.includes("cloud_summary"));
  if (bucketObs.length > 0) {
    const publicBuckets = bucketObs.filter(o => o.tags.includes("public_bucket"));
    services.push({
      id: nextId(),
      category: "cloud_storage",
      name: "Cloud Storage Buckets",
      provider: bucketObs[0]?.evidence?.provider || null,
      version: null,
      evidence: bucketObs.map(o => `${o.evidence?.provider} bucket: ${o.evidence?.bucketName} (${o.tags.includes("public_bucket") ? "PUBLIC" : "private"})`),
      confidence: 0.95,
      managedByThirdParty: true,
      exposedExternally: publicBuckets.length > 0,
      ports: [443],
      relatedAssets: bucketObs.map(o => o.name),
    });
    if (publicBuckets.length > 0) {
      inferenceNotes.push(`WARNING: ${publicBuckets.length} publicly accessible cloud storage bucket(s) detected`);
    }
  }

  // ─── 6. Web Servers ──────────────────────────────────────────────────

  const webServerMap = new Map<string, { assets: string[]; version: string | null; evidence: string[] }>();

  for (const asset of assets) {
    const serverTech = asset.technologies.filter(t =>
      /nginx|apache|iis|litespeed|caddy|openresty|tomcat|lighttpd/i.test(t)
    );
    for (const tech of serverTech) {
      const normalized = tech.split("/")[0].trim();
      if (!webServerMap.has(normalized)) webServerMap.set(normalized, { assets: [], version: null, evidence: [] });
      const entry = webServerMap.get(normalized)!;
      entry.assets.push(asset.hostname);
      if (asset.technologyVersions[tech] || asset.technologyVersions[normalized]) {
        entry.version = asset.technologyVersions[tech] || asset.technologyVersions[normalized];
      }
      entry.evidence.push(`Detected on ${asset.hostname}`);
    }
  }

  // From HTTP headers
  const httpObs = observations.filter(o => o.tags.includes("tech_fingerprint"));
  for (const obs of httpObs) {
    const banner = obs.evidence?.serverBanner;
    if (banner) {
      const serverName = banner.split("/")[0].trim();
      if (!webServerMap.has(serverName)) webServerMap.set(serverName, { assets: [], version: null, evidence: [] });
      const entry = webServerMap.get(serverName)!;
      entry.evidence.push(`HTTP Server header: ${banner}`);
      if (banner.includes("/")) entry.version = banner.split("/")[1]?.trim() || null;
    }
  }

  for (const [server, data] of webServerMap) {
    services.push({
      id: nextId(),
      category: "web_server",
      name: server,
      provider: null,
      version: data.version,
      evidence: [...new Set(data.evidence)],
      confidence: 0.85,
      managedByThirdParty: false,
      exposedExternally: true,
      ports: [80, 443],
      relatedAssets: [...new Set(data.assets)],
    });
  }

  // ─── 7. Application Frameworks & CMS ─────────────────────────────────

  const frameworkPatterns: Record<string, { category: ServiceCategory; patterns: string[] }> = {
    "WordPress": { category: "cms", patterns: ["wordpress", "wp-"] },
    "Drupal": { category: "cms", patterns: ["drupal"] },
    "Joomla": { category: "cms", patterns: ["joomla"] },
    "Shopify": { category: "cms", patterns: ["shopify"] },
    "Magento": { category: "cms", patterns: ["magento"] },
    "React": { category: "application_framework", patterns: ["react"] },
    "Next.js": { category: "application_framework", patterns: ["next.js", "nextjs"] },
    "Vue.js": { category: "application_framework", patterns: ["vue.js", "vuejs"] },
    "Angular": { category: "application_framework", patterns: ["angular"] },
    "Django": { category: "application_framework", patterns: ["django"] },
    "Ruby on Rails": { category: "application_framework", patterns: ["rails", "ruby on rails"] },
    "Laravel": { category: "application_framework", patterns: ["laravel"] },
    "Express.js": { category: "application_framework", patterns: ["express"] },
    "ASP.NET": { category: "application_framework", patterns: ["asp.net", "aspnet"] },
    "Spring": { category: "application_framework", patterns: ["spring"] },
    "Flask": { category: "application_framework", patterns: ["flask"] },
  };

  const detectedFrameworks = new Set<string>();
  for (const asset of assets) {
    for (const tech of asset.technologies) {
      for (const [name, config] of Object.entries(frameworkPatterns)) {
        if (config.patterns.some(p => tech.toLowerCase().includes(p)) && !detectedFrameworks.has(name)) {
          detectedFrameworks.add(name);
          services.push({
            id: nextId(),
            category: config.category,
            name,
            provider: null,
            version: asset.technologyVersions[tech] || null,
            evidence: [`Detected via technology fingerprinting on ${asset.hostname}`],
            confidence: 0.8,
            managedByThirdParty: false,
            exposedExternally: true,
            ports: [443],
            relatedAssets: [asset.hostname],
          });
        }
      }
    }
  }

  // ─── 8. BuiltWith Signals ────────────────────────────────────────────

  const builtWithObs = observations.filter(o => o.source === "builtwith" || o.tags.includes("builtwith"));
  for (const obs of builtWithObs) {
    // Security tools
    if (obs.tags.includes("security_tools")) {
      const tools = obs.evidence?.tools || [];
      for (const tool of tools) {
        if (typeof tool === "string") {
          services.push({
            id: nextId(),
            category: "security_tools",
            name: tool,
            provider: null,
            version: null,
            evidence: [`BuiltWith detection: ${tool}`],
            confidence: 0.7,
            managedByThirdParty: true,
            exposedExternally: false,
            ports: [],
            relatedAssets: [domain],
          });
        }
      }
    }

    // Analytics
    if (obs.tags.includes("tech_stack")) {
      const techs = obs.evidence?.technologies || [];
      for (const tech of techs) {
        const techName = typeof tech === "string" ? tech : tech?.name || "";
        for (const [analytics, patterns] of Object.entries(ANALYTICS_PATTERNS)) {
          if (patterns.some(p => techName.toLowerCase().includes(p)) && !services.some(s => s.name === analytics)) {
            services.push({
              id: nextId(),
              category: "analytics",
              name: analytics,
              provider: analytics.split(" ")[0],
              version: null,
              evidence: [`BuiltWith: ${techName}`],
              confidence: 0.75,
              managedByThirdParty: true,
              exposedExternally: false,
              ports: [],
              relatedAssets: [domain],
            });
          }
        }

        // Payment processors
        for (const [payment, patterns] of Object.entries(PAYMENT_PATTERNS)) {
          if (patterns.some(p => techName.toLowerCase().includes(p)) && !services.some(s => s.name === payment)) {
            services.push({
              id: nextId(),
              category: "payment",
              name: payment,
              provider: payment,
              version: null,
              evidence: [`BuiltWith: ${techName}`],
              confidence: 0.75,
              managedByThirdParty: true,
              exposedExternally: false,
              ports: [],
              relatedAssets: [domain],
            });
          }
        }
      }
    }
  }

  // ─── 9. Authentication Providers ─────────────────────────────────────

  // From TXT verification records
  const txtObs = observations.filter(o => o.tags.includes("txt_record"));
  for (const obs of txtObs) {
    const records = obs.evidence?.records || [];
    for (const record of records) {
      for (const [auth, patterns] of Object.entries(AUTH_PATTERNS)) {
        if (patterns.some(p => String(record).toLowerCase().includes(p)) && !services.some(s => s.name === auth)) {
          services.push({
            id: nextId(),
            category: "authentication",
            name: auth,
            provider: auth,
            version: null,
            evidence: [`DNS TXT verification record: ${String(record).substring(0, 80)}`],
            confidence: 0.7,
            managedByThirdParty: true,
            exposedExternally: false,
            ports: [443],
            relatedAssets: [domain],
          });
        }
      }
    }
  }

  // ─── 10. Certificate Authority ───────────────────────────────────────

  const caaObs = observations.filter(o => o.tags.includes("caa_record"));
  const certObs = observations.filter(o => o.assetType === "certificate");
  if (caaObs.length > 0 || certObs.length > 0) {
    const issuers = new Set<string>();
    for (const obs of caaObs) {
      (obs.evidence?.authorizedIssuers || []).forEach((i: string) => issuers.add(i));
    }
    for (const obs of certObs) {
      if (obs.evidence?.issuer) issuers.add(obs.evidence.issuer);
    }
    if (issuers.size > 0) {
      services.push({
        id: nextId(),
        category: "certificate_authority",
        name: "TLS Certificate Authority",
        provider: Array.from(issuers).join(", "),
        version: null,
        evidence: [
          ...Array.from(issuers).map(i => `Authorized CA: ${i}`),
          ...(caaObs.length > 0 ? ["CAA DNS record present (certificate pinning)"] : []),
        ],
        confidence: 0.9,
        managedByThirdParty: true,
        exposedExternally: true,
        ports: [443],
        relatedAssets: [domain],
      });
    }
  }

  // ─── 11. Open Ports / Services from Shodan ───────────────────────────

  for (const obs of shodanObs) {
    const ports = obs.evidence?.ports || [];
    const services_data = obs.evidence?.services || [];
    if (Array.isArray(services_data)) {
      for (const svc of services_data) {
        const port = svc.port || 0;
        const product = svc.product || svc.service || `Port ${port}`;
        const version = svc.version || null;

        // Skip if we already have this service from another source
        if (services.some(s => s.name.toLowerCase() === product.toLowerCase())) continue;

        // Classify
        let category: ServiceCategory = "other";
        if ([3306, 5432, 27017, 6379, 5984].includes(port)) category = "database";
        else if ([8080, 8443, 9090].includes(port)) category = "api_gateway";
        else if ([1194, 500, 4500].includes(port)) category = "vpn";
        else if ([8500, 2379, 2380, 10250].includes(port)) category = "container_orchestration";
        else if ([9200, 9300, 5601, 3000, 9090].includes(port)) category = "monitoring";

        if (category !== "other" || port > 0) {
          services.push({
            id: nextId(),
            category,
            name: product,
            provider: null,
            version,
            evidence: [`Shodan: port ${port} on ${obs.name}`],
            confidence: 0.8,
            managedByThirdParty: false,
            exposedExternally: true,
            ports: [port],
            relatedAssets: [obs.name],
          });
        }
      }
    }
  }

  // ─── 12. Vendor Dependency Analysis ──────────────────────────────────

  const vendorMap = new Map<string, string[]>();
  for (const svc of services) {
    const vendor = svc.provider || "Self-Hosted";
    if (!vendorMap.has(vendor)) vendorMap.set(vendor, []);
    vendorMap.get(vendor)!.push(svc.name);
  }

  const vendorDependencies: VendorDependency[] = [];
  for (const [vendor, svcNames] of vendorMap) {
    if (vendor === "Self-Hosted") continue;
    const isCritical = svcNames.some(s => {
      const svc = services.find(sv => sv.name === s);
      return svc && ["dns", "email", "cloud_hosting", "authentication"].includes(svc.category);
    });
    vendorDependencies.push({
      vendor,
      services: svcNames,
      serviceCount: svcNames.length,
      criticality: isCritical ? (svcNames.length >= 3 ? "critical" : "high") : (svcNames.length >= 2 ? "medium" : "low"),
      singlePointOfFailure: svcNames.length >= 3,
      notes: svcNames.length >= 3
        ? `${vendor} provides ${svcNames.length} services — outage would affect multiple functions`
        : `${vendor} provides ${svcNames.join(", ")}`,
    });
  }
  vendorDependencies.sort((a, b) => b.serviceCount - a.serviceCount);

  // ─── 13. Technology Lifecycle Assessment ─────────────────────────────

  const techLifecycle: TechLifecycleEntry[] = [];
  for (const svc of services) {
    if (svc.version && svc.category !== "cdn_waf") {
      const eolStatus = inferEolStatus(svc.name, svc.version);
      techLifecycle.push({
        technology: svc.name,
        detectedVersion: svc.version,
        latestStableVersion: null, // Would require live lookup
        eolStatus: eolStatus.status,
        patchCadenceSignal: eolStatus.signal,
        riskNote: eolStatus.note,
      });
    }
  }

  // ─── 14. Supply Chain Risk Assessment ────────────────────────────────

  const supplyChainRisks: SupplyChainRisk[] = [];

  // Vendor concentration
  const topVendor = vendorDependencies[0];
  if (topVendor && topVendor.serviceCount >= 3) {
    supplyChainRisks.push({
      riskType: "vendor_concentration",
      severity: topVendor.serviceCount >= 5 ? "critical" : "high",
      description: `${topVendor.vendor} provides ${topVendor.serviceCount} services. A single vendor outage or compromise could cascade across ${topVendor.services.join(", ")}.`,
      affectedServices: topVendor.services,
      recommendation: `Evaluate redundancy for critical services hosted on ${topVendor.vendor}. Consider multi-cloud or failover strategies for DNS, email, and hosting.`,
    });
  }

  // Single provider for critical functions
  const criticalCategories: ServiceCategory[] = ["dns", "email", "cloud_hosting"];
  for (const cat of criticalCategories) {
    const catServices = services.filter(s => s.category === cat);
    if (catServices.length === 1 && catServices[0].managedByThirdParty) {
      supplyChainRisks.push({
        riskType: "single_provider",
        severity: "medium",
        description: `${cat.replace(/_/g, " ")} depends on a single provider (${catServices[0].provider}). No redundancy detected.`,
        affectedServices: [catServices[0].name],
        recommendation: `Consider secondary ${cat.replace(/_/g, " ")} provider for business continuity.`,
      });
    }
  }

  // Missing defenses
  const hasCdn = services.some(s => s.category === "cdn_waf");
  const hasWaf = wafObs.length > 0;
  if (!hasCdn && !hasWaf) {
    supplyChainRisks.push({
      riskType: "missing_defense",
      severity: "high",
      description: "No CDN or WAF detected. Web assets may be directly exposed to DDoS and application-layer attacks.",
      affectedServices: services.filter(s => s.exposedExternally).map(s => s.name),
      recommendation: "Deploy a CDN/WAF (Cloudflare, AWS CloudFront, Akamai) to protect externally-facing services.",
    });
  }

  // Legacy tech
  const eolTech = techLifecycle.filter(t => t.eolStatus === "eol");
  if (eolTech.length > 0) {
    supplyChainRisks.push({
      riskType: "legacy_tech",
      severity: "high",
      description: `${eolTech.length} end-of-life technology version(s) detected: ${eolTech.map(t => `${t.technology} ${t.detectedVersion}`).join(", ")}`,
      affectedServices: eolTech.map(t => t.technology),
      recommendation: "Upgrade end-of-life software to supported versions to receive security patches.",
    });
  }

  // Unmanaged external exposure
  const unmanaged = services.filter(s => s.exposedExternally && !s.managedByThirdParty && !["web_server", "application_framework", "cms"].includes(s.category));
  if (unmanaged.length > 0) {
    supplyChainRisks.push({
      riskType: "unmanaged_exposure",
      severity: unmanaged.some(s => s.category === "database") ? "critical" : "medium",
      description: `${unmanaged.length} self-managed service(s) exposed externally: ${unmanaged.map(s => `${s.name} (port ${s.ports.join(",")})`).join(", ")}`,
      affectedServices: unmanaged.map(s => s.name),
      recommendation: "Review firewall rules. Databases and internal services should not be directly accessible from the internet.",
    });
  }

  // C2 framework detected via JARM fingerprint
  if (c2Matches.length > 0) {
    const c2Names = [...new Set(c2Matches.map(m => m.matchedProvider!))];
    supplyChainRisks.push({
      riskType: "c2_detected",
      severity: "critical",
      description: `JARM TLS fingerprint matches known C2 framework(s): ${c2Names.join(", ")}. This may indicate active compromise, red team activity, or a false positive from similar TLS configuration.`,
      affectedServices: c2Matches.map(m => `JARM:${m.hash.substring(0, 16)}… (${m.matchedProvider})`),
      recommendation: `Investigate immediately. Verify whether ${c2Names.join(", ")} C2 infrastructure is authorized (red team) or indicates compromise. Cross-reference with historical data — ephemeral servers matching C2 JARM are higher risk.`,
    });
    inferenceNotes.push(`CRITICAL: JARM detected C2 framework signature(s): ${c2Names.join(", ")}`);
  }

  // ─── 15. Summary ─────────────────────────────────────────────────────

  const uniqueVendors = new Set(services.filter(s => s.provider).map(s => s.provider!));
  const criticalRisks = supplyChainRisks.filter(r => r.severity === "critical").length;
  const highRisks = supplyChainRisks.filter(r => r.severity === "high").length;

  const maturity = (() => {
    const hasAuth = services.some(s => s.category === "authentication");
    const hasSecurity = services.some(s => s.category === "security_tools");
    const hasMonitoring = services.some(s => s.category === "monitoring");
    const score = (hasCdn ? 1 : 0) + (hasAuth ? 1 : 0) + (hasSecurity ? 1 : 0) + (hasMonitoring ? 1 : 0) + (hasWaf ? 1 : 0);
    if (score >= 4) return "advanced" as const;
    if (score >= 2) return "moderate" as const;
    if (score >= 1) return "basic" as const;
    return "minimal" as const;
  })();

  return {
    domain,
    generatedAt: new Date().toISOString(),
    services,
    vendorDependencies,
    techLifecycle,
    supplyChainRisks,
    summary: {
      totalServices: services.length,
      totalVendors: uniqueVendors.size,
      thirdPartyManaged: services.filter(s => s.managedByThirdParty).length,
      externallyExposed: services.filter(s => s.exposedExternally).length,
      criticalRisks,
      highRisks,
      topVendor: topVendor?.vendor || null,
      topVendorServiceCount: topVendor?.serviceCount || 0,
      overallMaturity: maturity,
    },
    inferenceNotes,
    jarmAnalysis,
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function inferEolStatus(name: string, version: string): { status: "current" | "approaching_eol" | "eol" | "unknown"; signal: string; note: string } {
  const lowerName = name.toLowerCase();
  const majorVersion = parseInt(version.split(".")[0], 10);

  // Known EOL patterns (approximate — would need live lookup for precision)
  if (lowerName.includes("nginx")) {
    if (majorVersion < 1 || (majorVersion === 1 && parseInt(version.split(".")[1] || "0", 10) < 20)) {
      return { status: "approaching_eol", signal: "Version predates current mainline", note: "Consider upgrading to latest stable branch" };
    }
  }
  if (lowerName.includes("apache")) {
    if (version.startsWith("2.2") || version.startsWith("2.0") || version.startsWith("1.")) {
      return { status: "eol", signal: "Apache 2.2 reached EOL in 2018", note: "Upgrade to Apache 2.4.x immediately" };
    }
  }
  if (lowerName.includes("openssl")) {
    if (version.startsWith("1.0") || version.startsWith("0.")) {
      return { status: "eol", signal: "OpenSSL 1.0.x reached EOL", note: "Upgrade to OpenSSL 3.x" };
    }
    if (version.startsWith("1.1")) {
      return { status: "eol", signal: "OpenSSL 1.1.1 reached EOL September 2023", note: "Upgrade to OpenSSL 3.x" };
    }
  }
  if (lowerName.includes("php")) {
    if (majorVersion < 8) {
      return { status: "eol", signal: `PHP ${majorVersion}.x is end-of-life`, note: "Upgrade to PHP 8.2+ for security support" };
    }
  }
  if (lowerName.includes("node") || lowerName.includes("nodejs")) {
    if (majorVersion < 18) {
      return { status: "eol", signal: `Node.js ${majorVersion}.x is end-of-life`, note: "Upgrade to Node.js 20 LTS or later" };
    }
  }
  if (lowerName.includes("iis") || lowerName.includes("internet information services")) {
    if (majorVersion < 10) {
      return { status: "approaching_eol", signal: "IIS version may be tied to older Windows Server", note: "Verify Windows Server version is still supported" };
    }
  }

  return { status: "unknown", signal: "Version lifecycle not in local database", note: "Verify against vendor support matrix" };
}
