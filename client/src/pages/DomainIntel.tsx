import { useState, useEffect, useRef, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  Globe, Search, Shield, Target, Plus, X,
  Loader2, CheckCircle2, AlertTriangle, Zap, Building2, Server, Cloud,
  Network, FileText, Brain, Crosshair, ChevronDown, ChevronUp,
  Eye, Fingerprint, Bug, Database, Radio, Radar, Scan, Info, Lock
} from "lucide-react";

const CLIENT_TYPES = [
  { value: "msp", label: "MSP / Managed Service Provider", icon: Server },
  { value: "enterprise", label: "Enterprise", icon: Building2 },
  { value: "saas", label: "SaaS Provider", icon: Cloud },
  { value: "paas", label: "PaaS Provider", icon: Network },
  { value: "iaas", label: "IaaS Provider", icon: Server },
  { value: "mixed_hosting", label: "Mixed Hosting", icon: Globe },
  { value: "other", label: "Other", icon: Shield },
];

const SECTORS = [
  "Technology", "Financial Services", "Healthcare", "Government", "Education",
  "Manufacturing", "Retail", "Energy", "Telecommunications", "Legal",
  "Media & Entertainment", "Non-Profit", "Defense", "Transportation", "Other"
];

const CRITICAL_FUNCTIONS = [
  "identity", "email", "payments", "customer_data", "intellectual_property",
  "supply_chain", "communications", "operations", "compliance", "hr",
  "development", "infrastructure", "sales", "marketing", "support"
];

const COMPLIANCE_FLAGS = [
  "SOC2", "HIPAA", "PCI-DSS", "GDPR", "NIST", "ISO27001", "FedRAMP",
  "CMMC", "SOX", "CCPA", "FERPA", "ITAR"
];

// ─── Scan Methods Metadata ──────────────────────────────────────────
// This describes every method the unified pipeline performs, for user transparency.
const SCAN_METHODS = [
  {
    id: "passive_asm_crtsh",
    name: "Certificate Transparency (crt.sh)",
    icon: Fingerprint,
    category: "Passive Data Collection",
    description: "Queries the crt.sh Certificate Transparency log database to discover subdomains from publicly issued SSL/TLS certificates. This is a free, no-API-key-required source that reveals real subdomains that have been issued certificates.",
    outputs: "Confirmed subdomains, certificate issuers, validity dates, SAN entries",
    attribution: "Data from crt.sh (Sectigo). Verify at: https://crt.sh/?q=%25.<domain>",
    falsePositiveRisk: "Low — certificates are real artifacts, but some subdomains may be expired or decommissioned.",
  },
  {
    id: "passive_asm_shodan",
    name: "Shodan Passive Port Discovery",
    icon: Radar,
    category: "Passive Data Collection",
    description: "Queries Shodan's database of internet-wide scan results to discover open ports, services, and technologies without sending any traffic to the target. Requires a Shodan API key for full results.",
    outputs: "Open ports, service banners, OS detection, technology fingerprints, CVE associations",
    attribution: "Data from Shodan (shodan.io). Verify at: https://www.shodan.io/host/<IP>",
    falsePositiveRisk: "Low — Shodan data is from real scans, but may be stale (days to weeks old).",
  },
  {
    id: "passive_asm_wayback",
    name: "Wayback Machine Historical Analysis",
    icon: Database,
    category: "Passive Data Collection",
    description: "Queries the Internet Archive's CDX API to discover historical URLs, forgotten admin panels, old API endpoints, and previously exposed paths. Reveals attack surface that may still be accessible.",
    outputs: "Historical URLs, MIME types, HTTP status codes, forgotten endpoints, old admin panels",
    attribution: "Data from Internet Archive (web.archive.org). Verify at: https://web.archive.org/web/*/<URL>",
    falsePositiveRisk: "Medium — historical URLs may no longer be accessible. Always verify current availability.",
  },
  {
    id: "passive_asm_rdap",
    name: "RDAP Domain Registration",
    icon: FileText,
    category: "Passive Data Collection",
    description: "Queries the Registration Data Access Protocol to retrieve domain registration details including registrar, nameservers, registration dates, and status codes. Free, no API key required.",
    outputs: "Registrar info, nameservers, registration/expiry dates, domain status, abuse contacts",
    attribution: "Data from RDAP (RFC 7483). Verify via: whois <domain> or rdap.org",
    falsePositiveRisk: "Very low — registration data is authoritative.",
  },
  {
    id: "passive_asm_ripestat",
    name: "RIPEstat Network Intelligence",
    icon: Network,
    category: "Passive Data Collection",
    description: "Queries RIPEstat's API for IP geolocation, ASN ownership, BGP prefix announcements, and network abuse contacts. Free, no API key required.",
    outputs: "IP geolocation, ASN info, BGP prefixes, network holder, abuse contacts",
    attribution: "Data from RIPE NCC (stat.ripe.net). Verify at: https://stat.ripe.net/<IP>",
    falsePositiveRisk: "Very low — network registration data is authoritative.",
  },
  {
    id: "passive_asm_censys",
    name: "Censys Host Discovery",
    icon: Search,
    category: "Passive Data Collection",
    description: "Queries Censys's internet-wide scan database for host details, certificates, and services. Requires Censys API credentials for access.",
    outputs: "Hosts, open ports, TLS certificates, autonomous systems, service protocols",
    attribution: "Data from Censys (censys.io). Verify at: https://search.censys.io/hosts/<IP>",
    falsePositiveRisk: "Low — based on real scan data, but may be slightly stale.",
  },
  {
    id: "passive_asm_urlscan",
    name: "urlscan.io Web Analysis",
    icon: Globe,
    category: "Passive Data Collection",
    description: "Searches urlscan.io's database of previously scanned pages to find technologies, linked domains, and page screenshots without visiting the target directly.",
    outputs: "Page technologies, linked domains, IP addresses, screenshots, HTTP transactions",
    attribution: "Data from urlscan.io. Verify at: https://urlscan.io/search/#domain:<domain>",
    falsePositiveRisk: "Low — based on real page scans by other users.",
  },
  {
    id: "passive_asm_securitytrails",
    name: "SecurityTrails DNS History",
    icon: Server,
    category: "Passive Data Collection",
    description: "Queries SecurityTrails for current and historical DNS records, subdomain enumeration, and associated domains. Requires SecurityTrails API key.",
    outputs: "Subdomains, DNS record history, associated domains, hosting changes",
    attribution: "Data from SecurityTrails (securitytrails.com). Verify at: https://securitytrails.com/domain/<domain>",
    falsePositiveRisk: "Low — DNS data is factual, but historical records may reference decommissioned infrastructure.",
  },
  {
    id: "passive_asm_dehashed",
    name: "Dehashed Breach Intelligence",
    icon: Lock,
    category: "Passive Data Collection",
    description: "Queries Dehashed's 15B+ breach record database to discover subdomains from email domains, credential exposures, IP associations, and breach database attribution. Excellent for domain and subdomain mapping through leaked email addresses. Requires Dehashed API key (credit-based).",
    outputs: "Breach-derived subdomains, credential exposure counts, IP associations, breach database names, email pattern analysis",
    attribution: "Data from Dehashed (dehashed.com). Breach records are aggregated from public and private data wells.",
    falsePositiveRisk: "Low — breach records are real artifacts. Subdomains derived from email domains are highly reliable for domain mapping.",
  },
  {
    id: "llm_passive_recon",
    name: "LLM-Powered Passive Reconnaissance",
    icon: Brain,
    category: "Discovery",
    description: "Uses a large language model to infer likely subdomains, services, and technology stacks based on the organization's sector, client type, and domain patterns. No active probing is performed — this is purely inference-based OSINT.",
    outputs: "Inferred subdomains, likely services (SSO, VPN, mail, API), estimated technology stack",
    attribution: "Findings labeled as \"Inferred\" — these are hypotheses, not confirmed assets. Verify by checking DNS records or visiting the URL.",
    falsePositiveRisk: "Medium — the LLM may suggest subdomains that don't exist. Always verify.",
  },
  {
    id: "dns_verification",
    name: "Active DNS Resolution",
    icon: Globe,
    category: "Discovery",
    description: "Resolves each inferred hostname via DNS (A, AAAA, CNAME, MX, TXT, NS records) to confirm whether the asset actually exists. Assets that resolve are upgraded from \"Inferred\" to \"DNS Verified\".",
    outputs: "DNS resolution status, IP addresses, CNAME chains, MX records, SPF/DMARC TXT records",
    attribution: "Findings labeled \"DNS Verified\" — the hostname resolved to an IP address. You can verify with: nslookup <hostname> or dig <hostname>",
    falsePositiveRisk: "Low — DNS resolution is deterministic. If it resolves, the record exists.",
  },
  {
    id: "banner_grabbing",
    name: "HTTP Banner & Header Analysis",
    icon: Fingerprint,
    category: "Discovery",
    description: "Sends an HTTP/HTTPS request to each resolved hostname and parses response headers (Server, X-Powered-By, X-Generator, Set-Cookie) to detect real technology names and version numbers.",
    outputs: "Server software versions (e.g., nginx/1.18.0), framework detection, cookie analysis",
    attribution: "Findings labeled \"Header Detected\" — version was extracted from HTTP response headers. Verify with: curl -I https://<hostname>",
    falsePositiveRisk: "Low — headers come directly from the server. However, servers can spoof headers.",
  },
  {
    id: "kev_enrichment",
    name: "CISA KEV (Known Exploited Vulnerabilities) Matching",
    icon: Shield,
    category: "Vulnerability Intelligence",
    description: "Cross-references detected technologies against the CISA Known Exploited Vulnerabilities catalog — a curated list of CVEs confirmed to be actively exploited in the wild. Matches are based on vendor/product name.",
    outputs: "KEV-listed CVEs, ransomware association flags, required remediation actions, due dates",
    attribution: "Findings labeled \"KEV\" with specific CVE IDs. Verify at: https://www.cisa.gov/known-exploited-vulnerabilities-catalog — search by CVE ID.",
    falsePositiveRisk: "Low for product match, Medium for version match — KEV entries are real CVEs, but the target may run a patched version.",
  },
  {
    id: "vuln_feed_enrichment",
    name: "Multi-Source Vulnerability Feed Matching",
    icon: Bug,
    category: "Vulnerability Intelligence",
    description: "Matches detected technologies against multiple vulnerability databases: NVD (National Vulnerability Database), Google Project Zero, CIRCL CVE database, and Exploit-DB. Provides CVSS scores and exploit availability.",
    outputs: "CVE IDs with CVSS scores, exploit availability, patch status, 0-day flags",
    attribution: "Each CVE links to its NVD page. Verify at: https://nvd.nist.gov/vuln/detail/<CVE-ID>. Sources listed per finding.",
    falsePositiveRisk: "Medium — product-family matches may not apply to the specific version running on the target.",
  },
  {
    id: "carver_shock_bia",
    name: "CARVER+SHOCK Business Impact Analysis",
    icon: Target,
    category: "Risk Scoring",
    description: "Applies the military-grade CARVER targeting methodology (Criticality, Accessibility, Recuperability, Vulnerability, Effect, Recognizability) combined with SHOCK factors (Scope, Handling, Operational Impact, Cascading Effects, Knowledge) to score each asset's mission importance.",
    outputs: "Per-asset CARVER scores (0-10 each), SHOCK scores (0-10 each), mission impact score, asset tier classification",
    attribution: "Scores are LLM-generated based on asset type, sector context, and critical functions. These are analytical estimates, not measured values.",
    falsePositiveRisk: "N/A — these are risk scores, not binary findings. Interpret as relative prioritization.",
  },
  {
    id: "hybrid_risk_scoring",
    name: "Hybrid Risk Score Computation",
    icon: Radar,
    category: "Risk Scoring",
    description: "Combines CVSS vulnerability scores with CARVER+SHOCK mission impact scores and contextual indicators (exposure level, recognizability, confidence) into a single 0-100 hybrid risk score per asset. Formula: 40% CVSS + 35% Mission Impact + 25% Context.",
    outputs: "Hybrid risk score (0-100), risk band (critical/high/medium/low), confidence percentage",
    attribution: "Computed algorithmically from the sub-scores above. The formula is deterministic — same inputs always produce the same score.",
    falsePositiveRisk: "N/A — this is a composite score. Accuracy depends on the quality of input scores.",
  },
  {
    id: "threat_actor_matching",
    name: "Threat Actor Profiling",
    icon: Crosshair,
    category: "Threat Intelligence",
    description: "Matches the organization's sector, technology stack, and risk profile against known threat actor groups (APTs, cybercrime groups) to identify which adversaries are most likely to target this organization.",
    outputs: "Matched threat actors with confidence scores, relevant TTPs, historical targeting patterns",
    attribution: "Based on public threat intelligence. Verify actor profiles at: https://attack.mitre.org/groups/",
    falsePositiveRisk: "Medium — threat actor targeting is probabilistic, not deterministic.",
  },
  {
    id: "campaign_design",
    name: "Automated Campaign Design",
    icon: Zap,
    category: "Offensive Planning",
    description: "Auto-generates red team, phishing, and purple team campaign recommendations based on discovered assets, vulnerabilities, and threat actor TTPs. Maps to specific MITRE ATT&CK techniques, Caldera abilities, and GoPhish templates.",
    outputs: "Campaign plans with attack chains, Caldera ability mappings, GoPhish email templates, MITRE technique IDs",
    attribution: "Campaign designs are AI-generated recommendations. Caldera abilities reference real ATT&CK technique IDs (e.g., T1566.001). Verify at: https://attack.mitre.org/techniques/<ID>",
    falsePositiveRisk: "N/A — these are recommendations, not findings.",
  },
];

// ─── Corroboration Tier Explanation ─────────────────────────────────
const CORROBORATION_TIERS = [
  {
    tier: "confirmed",
    label: "CONFIRMED",
    color: "text-emerald-400 bg-emerald-500/20 border-emerald-500/40",
    description: "Technology version was detected (via DNS/headers) AND matched to a specific CVE's affected version range. Severity is uncapped.",
    verification: "Check the CVE's affected version range against the detected version. Both are shown in the finding.",
  },
  {
    tier: "probable",
    label: "PROBABLE",
    color: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40",
    description: "The product/brand was detected but the specific version is unknown. A real CVE exists for this product family. Severity is capped at 6/10.",
    verification: "Confirm the actual version running on the target to determine if it falls within the CVE's affected range.",
  },
  {
    tier: "potential",
    label: "POTENTIAL",
    color: "text-purple-400 bg-purple-500/20 border-purple-500/40",
    description: "Risk was inferred by LLM analysis with no specific CVE backing. Severity is capped at 4/10. Shown as advisory only.",
    verification: "Perform manual assessment or active scanning to determine if this risk actually exists.",
  },
];

export default function DomainIntel() {
  const [, navigate] = useLocation();

  // Pre-fill domain from query parameter
  const urlParams = new URLSearchParams(window.location.search);
  const domainFromQuery = urlParams.get("domain") || "";

  // Form state — all in one view
  const [primaryDomain, setPrimaryDomain] = useState(domainFromQuery);
  const [additionalDomains, setAdditionalDomains] = useState<string[]>([]);
  const [newDomain, setNewDomain] = useState("");
  const [customerName, setCustomerName] = useState("");
  const [clientType, setClientType] = useState("enterprise");
  const [sector, setSector] = useState("");
  const [criticalFunctions, setCriticalFunctions] = useState<string[]>([]);
  const [complianceFlags, setComplianceFlags] = useState<string[]>([]);
  const [notes, setNotes] = useState("");

  // UI state
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showMethods, setShowMethods] = useState(false);
  const [showCorroboration, setShowCorroboration] = useState(false);
  const [scanMode, setScanMode] = useState<"passive_only" | "passive_plus_dns" | "full">("full");

  // Pipeline state
  const [isRunning, setIsRunning] = useState(false);
  const [isComplete, setIsComplete] = useState(false);
  const [scanId, setScanId] = useState<number | null>(null);
  const [pipelineStage, setPipelineStage] = useState(0);
  const [pipelineError, setPipelineError] = useState<string | null>(null);

  const startScan = trpc.domainIntel.startScan.useMutation({
    onSuccess: (data) => {
      setScanId(data.scanId);
      setIsRunning(true);
      setIsComplete(false);
      setPipelineStage(0);
      setPipelineError(null);
    },
    onError: (err) => {
      setIsRunning(false);
      setPipelineError(err.message);
    },
  });

  // Poll for scan status while running
  const scanStatusQuery = trpc.domainIntel.getScanStatus.useQuery(
    { scanId: scanId! },
    {
      enabled: isRunning && scanId !== null,
      refetchInterval: 3000,
    }
  );

  // React to scan status changes
  useEffect(() => {
    if (!scanStatusQuery.data || !isRunning) return;
    const { status } = scanStatusQuery.data;
    const stageMap: Record<string, number> = {
      passive_recon: 0.5,
      discovering: 1,
      analyzing: 2,
      scoring: 3,
      recommending: 4,
      completed: 5,
      failed: -1,
    };
    const stageNum = stageMap[status] ?? 0;
    if (stageNum > 0) setPipelineStage(stageNum);

    if (status === "completed") {
      setIsRunning(false);
      setIsComplete(true);
    } else if (status === "failed") {
      setPipelineError("Pipeline failed. Please try again.");
      setIsRunning(false);
    }
  }, [scanStatusQuery.data, isRunning]);

  // Past scans
  const scansQuery = trpc.domainIntel.listScans.useQuery();

  const addDomain = () => {
    const d = newDomain.trim().toLowerCase();
    if (d && !additionalDomains.includes(d) && d !== primaryDomain) {
      setAdditionalDomains([...additionalDomains, d]);
      setNewDomain("");
    }
  };

  const removeDomain = (d: string) => {
    setAdditionalDomains(additionalDomains.filter(x => x !== d));
  };

  const toggleFunction = (f: string) => {
    setCriticalFunctions(prev =>
      prev.includes(f) ? prev.filter(x => x !== f) : [...prev, f]
    );
  };

  const toggleCompliance = (f: string) => {
    setComplianceFlags(prev =>
      prev.includes(f) ? prev.filter(x => x !== f) : [...prev, f]
    );
  };

  const handleStartScan = () => {
    if (!primaryDomain || !customerName || !sector) return;
    setPipelineError(null);
    setPipelineStage(0);
    startScan.mutate({
      primaryDomain,
      additionalDomains,
      clientType: clientType as any,
      sector,
      customerName,
      criticalFunctions,
      complianceFlags,
      notes: notes || undefined,
    });
  };

  const canLaunch = !!primaryDomain && !!customerName && !!sector;

  const resetForm = () => {
    setPrimaryDomain("");
    setAdditionalDomains([]);
    setCustomerName("");
    setClientType("enterprise");
    setSector("");
    setCriticalFunctions([]);
    setComplianceFlags([]);
    setNotes("");
    setIsRunning(false);
    setIsComplete(false);
    setScanId(null);
    setPipelineStage(0);
    setPipelineError(null);
  };

  // Pipeline stages for progress display
  const PIPELINE_STAGES = [
    { label: "Passive Recon (crt.sh, Shodan, Wayback, RDAP, RIPEstat" + (scanMode === 'full' ? ', Censys, urlscan, SecurityTrails, Dehashed)' : ')'), stage: 0.5, method: "passive_asm" },
    { label: "LLM-Powered Discovery (enriched with passive data)", stage: 1, method: "llm_passive_recon" },
    { label: "DNS Verification & Banner Grabbing", stage: 2, method: "dns_verification" },
    { label: "CARVER+SHOCK BIA & Risk Scoring", stage: 3, method: "carver_shock_bia" },
    { label: "Vuln Feed & KEV Enrichment", stage: 3, method: "kev_enrichment" },
    { label: "Threat Actor Matching", stage: 4, method: "threat_actor_matching" },
    { label: "Campaign Design & Summaries", stage: 4, method: "campaign_design" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Brain className="h-7 w-7 text-purple-400" />
            Full-Scope Domain Intelligence
          </h1>
          <p className="text-muted-foreground mt-1 max-w-2xl">
            A single unified scan that performs passive reconnaissance, active DNS verification, vulnerability matching, risk scoring, threat actor profiling, and campaign design — all in one pipeline. Every finding includes clear attribution so you can verify it independently.
          </p>
        </div>
        {scansQuery.data && scansQuery.data.length > 0 && !isRunning && (
          <Button variant="outline" onClick={() => navigate("/domain-intel/history")}>
            <FileText className="h-4 w-4 mr-2" />
            Past Scans ({scansQuery.data.length})
          </Button>
        )}
      </div>

      {/* ─── Scan Methods Explainer ─────────────────────────────────── */}
      <Collapsible open={showMethods} onOpenChange={setShowMethods}>
        <CollapsibleTrigger asChild>
          <Card className="cursor-pointer hover:border-purple-500/30 transition-all">
            <CardContent className="p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-purple-500/10">
                  <Info className="h-5 w-5 text-purple-400" />
                </div>
                <div>
                  <p className="font-semibold text-sm">What does this scan perform? ({SCAN_METHODS.length} methods)</p>
                  <p className="text-xs text-muted-foreground">Click to see every search technique, data source, and how to verify findings</p>
                </div>
              </div>
              {showMethods ? <ChevronUp className="h-5 w-5 text-muted-foreground" /> : <ChevronDown className="h-5 w-5 text-muted-foreground" />}
            </CardContent>
          </Card>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="space-y-3 mt-3">
            {/* Group by category */}
            {["Discovery", "Vulnerability Intelligence", "Risk Scoring", "Threat Intelligence", "Offensive Planning"].map(category => {
              const methods = SCAN_METHODS.filter(m => m.category === category);
              if (methods.length === 0) return null;
              return (
                <div key={category}>
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 mt-3">{category}</p>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                    {methods.map(method => {
                      const Icon = method.icon;
                      return (
                        <Card key={method.id} className="border-border/60">
                          <CardContent className="p-4 space-y-2">
                            <div className="flex items-center gap-2">
                              <Icon className="h-4 w-4 text-purple-400 shrink-0" />
                              <p className="font-semibold text-sm">{method.name}</p>
                            </div>
                            <p className="text-xs text-muted-foreground leading-relaxed">{method.description}</p>
                            <div className="space-y-1 pt-1 border-t border-border/40">
                              <div className="flex gap-2 text-[11px]">
                                <span className="text-muted-foreground shrink-0 font-medium">Outputs:</span>
                                <span className="text-foreground/80">{method.outputs}</span>
                              </div>
                              <div className="flex gap-2 text-[11px]">
                                <span className="text-cyan-400 shrink-0 font-medium">How to verify:</span>
                                <span className="text-foreground/80">{method.attribution}</span>
                              </div>
                              <div className="flex gap-2 text-[11px]">
                                <span className="text-orange-400 shrink-0 font-medium">False positive risk:</span>
                                <span className="text-foreground/80">{method.falsePositiveRisk}</span>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      );
                    })}
                  </div>
                </div>
              );
            })}

            {/* Corroboration Tiers */}
            <div className="mt-4">
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Finding Corroboration Tiers</p>
              <p className="text-xs text-muted-foreground mb-3">
                Every finding is assigned a corroboration tier that indicates how much evidence supports it. Severity scores are capped based on the tier to prevent inflated risk from unverified findings.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {CORROBORATION_TIERS.map(t => (
                  <Card key={t.tier} className={`border ${t.color.split(" ").filter(c => c.startsWith("border-")).join(" ")}`}>
                    <CardContent className="p-3 space-y-1.5">
                      <Badge className={`text-[10px] ${t.color}`}>{t.label}</Badge>
                      <p className="text-xs text-muted-foreground">{t.description}</p>
                      <p className="text-[11px] text-cyan-400/80"><span className="font-medium">Verify:</span> {t.verification}</p>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          </div>
        </CollapsibleContent>
      </Collapsible>

      {/* ─── Running State ─────────────────────────────────────────── */}
      {isRunning && (
        <Card className="border-purple-500/30">
          <CardContent className="p-10 flex flex-col items-center justify-center text-center space-y-6">
            <div className="relative">
              <div className="absolute inset-0 animate-ping rounded-full bg-purple-500/20 w-20 h-20" />
              <div className="relative bg-purple-500/10 rounded-full p-5">
                <Brain className="h-10 w-10 text-purple-400 animate-pulse" />
              </div>
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold">Running Full-Scope Domain Intelligence</h2>
              <p className="text-muted-foreground max-w-md">
                Analyzing <span className="font-mono text-purple-400">{primaryDomain}</span> using {SCAN_METHODS.length} methods across {new Set(SCAN_METHODS.map(m => m.category)).size} categories.
                This typically takes 60-120 seconds.
              </p>
            </div>
            <div className="w-full max-w-sm space-y-2">
              <Progress value={Math.max(5, (pipelineStage / 5) * 100)} className="h-2" />
              <p className="text-xs text-muted-foreground text-center">
                {scanStatusQuery.data?.status === "passive_recon" ? "Stage 0.5: Passive reconnaissance — querying crt.sh, Shodan, Wayback, RDAP, Dehashed..." :
                 scanStatusQuery.data?.status === "discovering" ? "Stage 1: LLM discovery enriched with passive recon data..." :
                 scanStatusQuery.data?.status === "analyzing" ? "Stage 2: BIA scoring + asset classification..." :
                 scanStatusQuery.data?.status === "scoring" ? "Stage 3: Vuln feeds + KEV enrichment + risk computation..." :
                 scanStatusQuery.data?.status === "recommending" ? "Stage 4: Threat actors + campaign design + summaries..." :
                 "Initializing pipeline..."}
              </p>
            </div>
            <div className="space-y-2 w-full max-w-md text-left">
              {PIPELINE_STAGES.map((s, i) => (
                <div key={i} className="flex items-center gap-3">
                  {pipelineStage > s.stage ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                  ) : pipelineStage === s.stage ? (
                    <Loader2 className="h-4 w-4 animate-spin text-purple-400 shrink-0" />
                  ) : (
                    <div className="h-4 w-4 rounded-full border border-muted-foreground/30 shrink-0" />
                  )}
                  <span className={`text-sm ${pipelineStage >= s.stage ? "text-foreground" : "text-muted-foreground"}`}>{s.label}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ─── Complete State ─────────────────────────────────────────── */}
      {isComplete && scanId && (
        <Card className="border-emerald-500/30">
          <CardContent className="p-10 flex flex-col items-center justify-center text-center space-y-6">
            <div className="bg-emerald-500/10 rounded-full p-5">
              <CheckCircle2 className="h-10 w-10 text-emerald-400" />
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold">Full-Scope Scan Complete</h2>
              <p className="text-muted-foreground">
                All {SCAN_METHODS.length} methods completed for <span className="font-mono text-emerald-400">{primaryDomain}</span>.
                Every finding includes source attribution and verification instructions.
              </p>
            </div>
            <div className="flex gap-3">
              <Button onClick={() => navigate(`/domain-intel/${scanId}`)}>
                <Target className="h-4 w-4 mr-2" />
                View Results & Attribution
              </Button>
              <Button variant="outline" onClick={resetForm}>
                Start New Scan
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ─── Unified Search Form ───────────────────────────────────── */}
      {!isRunning && !isComplete && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Form */}
          <div className="lg:col-span-2 space-y-5">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Scan className="h-5 w-5 text-purple-400" />
                  Launch Domain Intelligence Scan
                </CardTitle>
                <CardDescription>
                  Enter a domain and organization details. One scan runs all {SCAN_METHODS.length} methods automatically.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                {/* Primary Domain — most prominent */}
                <div className="space-y-2">
                  <Label className="text-sm font-semibold">Target Domain *</Label>
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <Input
                        placeholder="example.com"
                        value={primaryDomain}
                        onChange={e => setPrimaryDomain(e.target.value.trim().toLowerCase())}
                        className="pl-10 text-lg h-12 font-mono"
                      />
                    </div>
                  </div>
                  <p className="text-[11px] text-muted-foreground">Subdomains will be discovered automatically via 9+ passive data sources (including breach intelligence) and DNS verification.</p>
                </div>

                {/* Additional Domains */}
                <div className="space-y-2">
                  <Label className="text-sm">Additional Domains (optional)</Label>
                  <div className="flex gap-2">
                    <Input
                      placeholder="subsidiary.com"
                      value={newDomain}
                      onChange={e => setNewDomain(e.target.value)}
                      onKeyDown={e => e.key === "Enter" && addDomain()}
                      className="font-mono"
                    />
                    <Button variant="outline" onClick={addDomain} disabled={!newDomain.trim()}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                  {additionalDomains.length > 0 && (
                    <div className="flex flex-wrap gap-2 mt-1">
                      {additionalDomains.map(d => (
                        <Badge key={d} variant="secondary" className="gap-1 font-mono">
                          {d}
                          <X className="h-3 w-3 cursor-pointer hover:text-destructive" onClick={() => removeDomain(d)} />
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>

                {/* Org Name + Sector + Client Type — single row */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <Label className="text-sm font-semibold">Organization Name *</Label>
                    <Input
                      placeholder="Acme Corporation"
                      value={customerName}
                      onChange={e => setCustomerName(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-sm font-semibold">Sector *</Label>
                    <Select value={sector} onValueChange={setSector}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select sector..." />
                      </SelectTrigger>
                      <SelectContent>
                        {SECTORS.map(s => (
                          <SelectItem key={s} value={s}>{s}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-sm">Client Type</Label>
                    <Select value={clientType} onValueChange={setClientType}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {CLIENT_TYPES.map(ct => (
                          <SelectItem key={ct.value} value={ct.value}>{ct.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                {/* Scan Mode Selector */}
                <div className="space-y-2">
                  <Label className="text-sm font-semibold flex items-center gap-2">
                    <Radar className="h-4 w-4 text-cyan-400" />
                    Scan Mode
                  </Label>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                    {[
                      { value: "passive_only" as const, label: "Passive Only", desc: "crt.sh, RDAP, RIPEstat, Wayback — no API keys needed", icon: Eye },
                      { value: "passive_plus_dns" as const, label: "Passive + DNS", desc: "Adds DNS resolution & banner grabbing to passive recon", icon: Globe },
                      { value: "full" as const, label: "Full Scope", desc: "All 9 connectors + LLM + DNS + vuln feeds + campaigns", icon: Radar },
                    ].map(mode => {
                      const Icon = mode.icon;
                      return (
                        <div
                          key={mode.value}
                          onClick={() => setScanMode(mode.value)}
                          className={`cursor-pointer rounded-lg border p-3 transition-all ${
                            scanMode === mode.value
                              ? "border-purple-500 bg-purple-500/10"
                              : "border-border hover:border-purple-500/30"
                          }`}
                        >
                          <div className="flex items-center gap-2 mb-1">
                            <Icon className={`h-4 w-4 ${scanMode === mode.value ? 'text-purple-400' : 'text-muted-foreground'}`} />
                            <span className={`text-sm font-medium ${scanMode === mode.value ? 'text-purple-400' : ''}`}>{mode.label}</span>
                          </div>
                          <p className="text-[10px] text-muted-foreground">{mode.desc}</p>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Advanced Options Toggle */}
                <Collapsible open={showAdvanced} onOpenChange={setShowAdvanced}>
                  <CollapsibleTrigger asChild>
                    <button className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors">
                      {showAdvanced ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      Advanced Options (critical functions, compliance, notes)
                    </button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="space-y-4 mt-3">
                    <div className="space-y-2">
                      <Label className="text-sm">Critical Business Functions</Label>
                      <p className="text-[11px] text-muted-foreground">Select functions critical to this organization. This drives BIA scoring.</p>
                      <div className="flex flex-wrap gap-2">
                        {CRITICAL_FUNCTIONS.map(f => (
                          <Badge
                            key={f}
                            variant={criticalFunctions.includes(f) ? "default" : "outline"}
                            className={`cursor-pointer transition-all ${
                              criticalFunctions.includes(f) ? "bg-purple-500 hover:bg-purple-600" : "hover:border-purple-500/50"
                            }`}
                            onClick={() => toggleFunction(f)}
                          >
                            {f.replace(/_/g, " ")}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label className="text-sm">Compliance Requirements</Label>
                      <div className="flex flex-wrap gap-2">
                        {COMPLIANCE_FLAGS.map(f => (
                          <Badge
                            key={f}
                            variant={complianceFlags.includes(f) ? "default" : "outline"}
                            className={`cursor-pointer transition-all ${
                              complianceFlags.includes(f) ? "bg-blue-500 hover:bg-blue-600" : "hover:border-blue-500/50"
                            }`}
                            onClick={() => toggleCompliance(f)}
                          >
                            {f}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label className="text-sm">Notes (optional)</Label>
                      <Textarea
                        placeholder="Any additional context about the organization, known infrastructure, or specific areas of concern..."
                        value={notes}
                        onChange={e => setNotes(e.target.value)}
                        rows={3}
                      />
                    </div>
                  </CollapsibleContent>
                </Collapsible>

                {/* Error */}
                {(startScan.error || pipelineError) && (
                  <Card className="border-destructive bg-destructive/10">
                    <CardContent className="p-3">
                      <p className="text-sm text-destructive flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4" />
                        {pipelineError || startScan.error?.message}
                      </p>
                    </CardContent>
                  </Card>
                )}

                {/* Launch Button */}
                <Button
                  onClick={handleStartScan}
                  disabled={!canLaunch || startScan.isPending}
                  className="w-full h-12 bg-purple-600 hover:bg-purple-700 text-base"
                >
                  {startScan.isPending ? (
                    <Loader2 className="h-5 w-5 mr-2 animate-spin" />
                  ) : (
                    <Zap className="h-5 w-5 mr-2" />
                  )}
                  Launch Full-Scope Domain Intelligence Scan
                </Button>

                {!canLaunch && (
                  <p className="text-xs text-muted-foreground text-center">
                    Fill in the target domain, organization name, and sector to launch.
                  </p>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Sidebar — What Will Run */}
          <div className="space-y-4">
            <Card className="border-purple-500/20 bg-purple-500/5">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Radar className="h-4 w-4 text-purple-400" />
                  Scan Coverage
                </CardTitle>
                <CardDescription className="text-[11px]">
                  All methods run automatically in a single pipeline
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {SCAN_METHODS.map(method => {
                  const Icon = method.icon;
                  return (
                    <div key={method.id} className="flex items-start gap-2 py-1">
                      <Icon className="h-3.5 w-3.5 text-purple-400 mt-0.5 shrink-0" />
                      <div>
                        <p className="text-xs font-medium">{method.name}</p>
                        <p className="text-[10px] text-muted-foreground">{method.category}</p>
                      </div>
                    </div>
                  );
                })}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Eye className="h-4 w-4 text-cyan-400" />
                  Attribution & Verification
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Every finding in the results includes:
                </p>
                <ul className="space-y-1.5 text-xs">
                  <li className="flex items-start gap-2">
                    <Badge className="text-[9px] bg-emerald-500/20 text-emerald-400 border-emerald-500/40 shrink-0 mt-0.5">SOURCE</Badge>
                    <span className="text-muted-foreground">Which method produced it</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Badge className="text-[9px] bg-cyan-500/20 text-cyan-400 border-cyan-500/40 shrink-0 mt-0.5">EVIDENCE</Badge>
                    <span className="text-muted-foreground">Step-by-step evidence chain</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Badge className="text-[9px] bg-yellow-500/20 text-yellow-400 border-yellow-500/40 shrink-0 mt-0.5">TIER</Badge>
                    <span className="text-muted-foreground">Confirmed / Probable / Potential</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Badge className="text-[9px] bg-purple-500/20 text-purple-400 border-purple-500/40 shrink-0 mt-0.5">VERIFY</Badge>
                    <span className="text-muted-foreground">How to independently confirm</span>
                  </li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      {/* ─── Recent Scans ──────────────────────────────────────────── */}
      {!isRunning && !isComplete && scansQuery.data && scansQuery.data.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-medium text-muted-foreground">Recent Scans</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {scansQuery.data.slice(0, 6).map((scan: any) => {
              const output = scan.pipelineOutput as any;
              const riskScore = output?.riskScore || scan.overallRiskScore || 0;
              const assetCount = output?.assets?.length || scan.totalAssets || 0;
              const findingCount = output?.postureFindings?.length || 0;
              const confirmedCount = output?.postureFindings?.filter((f: any) => f.corroborationTier === 'confirmed').length || 0;
              const probableCount = output?.postureFindings?.filter((f: any) => f.corroborationTier === 'probable').length || 0;
              const potentialCount = output?.postureFindings?.filter((f: any) => f.corroborationTier === 'potential').length || 0;
              return (
                <Card
                  key={scan.id}
                  className="cursor-pointer hover:border-purple-500/50 transition-all"
                  onClick={() => navigate(`/domain-intel/${scan.id}`)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-mono text-sm font-semibold">{scan.primaryDomain}</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          {scan.clientType?.toUpperCase() || 'SCAN'} &middot; Risk: <span className={riskScore >= 70 ? 'text-red-400 font-bold' : riskScore >= 40 ? 'text-orange-400 font-bold' : 'text-green-400 font-bold'}>{riskScore || 'N/A'}</span>
                        </p>
                      </div>
                      <Badge variant={
                        scan.status === "completed" ? "default" :
                        scan.status === "failed" ? "destructive" : "secondary"
                      } className={scan.status === "completed" ? "bg-emerald-500/20 text-emerald-400" : ""}>
                        {scan.status}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                      <span className="text-[10px] bg-muted px-1.5 py-0.5 rounded">{assetCount} assets</span>
                      {findingCount > 0 && <span className="text-[10px] bg-muted px-1.5 py-0.5 rounded">{findingCount} findings</span>}
                      {confirmedCount > 0 && <span className="text-[10px] bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">{confirmedCount} confirmed</span>}
                      {probableCount > 0 && <span className="text-[10px] bg-orange-500/20 text-orange-400 px-1.5 py-0.5 rounded">{probableCount} probable</span>}
                      {potentialCount > 0 && <span className="text-[10px] bg-muted/60 text-muted-foreground px-1.5 py-0.5 rounded">{potentialCount} potential</span>}
                    </div>
                    <div className="flex items-center justify-between mt-2 pt-2 border-t border-border">
                      <span className="text-[10px] text-muted-foreground">
                        {scan.createdAt ? new Date(scan.createdAt).toLocaleDateString() : ''}
                      </span>
                      <span className="text-[10px] text-purple-400 font-medium">View Results →</span>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
