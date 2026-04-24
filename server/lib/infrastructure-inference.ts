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

export interface SupplyChainRisk {
  riskType: "vendor_concentration" | "single_provider" | "unmanaged_exposure" | "legacy_tech" | "missing_defense";
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
