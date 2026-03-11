// @ts-nocheck
import { useState, useEffect, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Streamdown } from "streamdown";
import { toast } from "sonner";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Slider } from "@/components/ui/slider";
import {
  ArrowLeft, Shield, Target, AlertTriangle, Brain, Globe, Server,
  ChevronDown, ChevronUp, Crosshair, Zap, FileText, ExternalLink,
  Activity, Lock, Eye, Network, Loader2, BarChart3, Bug, Skull, Database, Cpu,
  TrendingUp, Fingerprint, Radar, Info, Search, Radio, Scan, Flag, Undo2, MessageSquare,
  Download, FlaskConical, Mail, ShieldAlert, ShieldCheck, ShieldX, CheckCircle2, XCircle, RefreshCw,
  Layers, Play, Pause, Settings2, GitBranch, Link2, Users, Hash, Clock, Unplug, Wifi,
  Workflow, Lightbulb, Route, Telescope, ShieldQuestion, ArrowRightLeft, KeyRound,
  Box, ClipboardCheck, PackageSearch, GitCompareArrows
} from "lucide-react";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";

export default function ScanMethodsTab({ assets, scan }: { assets: any[]; scan: any }) {
  // Compute stats from the scan data
  const dnsVerifiedCount = assets.filter((a: any) => {
    const dm = a.discoveryMethod || (a.asset as any)?.discoveryMethod;
    return dm === 'dns_verified' || dm === 'header_detected';
  }).length;
  const inferredCount = assets.filter((a: any) => {
    const dm = a.discoveryMethod || (a.asset as any)?.discoveryMethod;
    return dm === 'inferred' || !dm;
  }).length;
  const headerDetectedCount = assets.filter((a: any) => {
    const dm = a.discoveryMethod || (a.asset as any)?.discoveryMethod;
    return dm === 'header_detected';
  }).length;
  const allFindings = assets.flatMap((a: any) => (a.postureFindings || []) as any[]);
  const confirmedFindings = allFindings.filter((f: any) => f.corroborationTier === 'confirmed');
  const probableFindings = allFindings.filter((f: any) => f.corroborationTier === 'probable');
  const potentialFindings = allFindings.filter((f: any) => !f.corroborationTier || f.corroborationTier === 'potential');
  const informationalFindings = allFindings.filter((f: any) => f.corroborationTier === 'informational');
  const kevFindings = allFindings.filter((f: any) => f.kevListed);

  const METHODS = [
    {
      id: "llm_passive_recon",
      name: "LLM-Powered Passive Reconnaissance",
      icon: Brain,
      category: "Discovery",
      status: "completed",
      description: "Used a large language model to infer likely subdomains, services, and technology stacks based on the organization's sector, client type, and domain patterns. No active probing was performed.",
      outputs: `Discovered ${assets.length} total assets (${inferredCount} inferred, ${dnsVerifiedCount} verified, ${subdomainAssets.length} subdomain)`,
      attribution: 'Findings labeled as "Inferred" are hypotheses. Verify by checking DNS records or visiting the URL.',
      fpRisk: "Low — all LLM-inferred subdomains are gated by DNS resolution. Non-existent subdomains are automatically filtered out before analysis.",
      verifyCmd: "nslookup <hostname> or dig <hostname>",
    },
    {
      id: "dns_verification",
      name: "Active DNS Resolution",
      icon: Globe,
      category: "Discovery",
      status: dnsVerifiedCount > 0 ? "completed" : "no_results",
      description: "Resolved each inferred hostname via DNS (A, AAAA, CNAME, MX, TXT, NS records) to confirm whether the asset actually exists.",
      outputs: `${dnsVerifiedCount} of ${assets.length} assets confirmed via DNS resolution`,
      attribution: 'Findings labeled "DNS Verified" resolved to an IP address.',
      fpRisk: "Low — DNS resolution is deterministic.",
      verifyCmd: "nslookup <hostname> or dig <hostname>",
    },
    {
      id: "banner_grabbing",
      name: "HTTP Banner & Header Analysis",
      icon: Fingerprint,
      category: "Discovery",
      status: headerDetectedCount > 0 ? "completed" : "no_results",
      description: "Sent HTTP/HTTPS requests to resolved hostnames and parsed response headers (Server, X-Powered-By, X-Generator, Set-Cookie) to detect technology names and versions.",
      outputs: `${headerDetectedCount} assets with header-detected technologies`,
      attribution: 'Findings labeled "Header Detected" — version extracted from HTTP response headers.',
      fpRisk: "Low — headers come directly from the server (but can be spoofed).",
      verifyCmd: "curl -I https://<hostname>",
    },
    {
      id: "internetdb_enrichment",
      name: "internet scan databases InternetDB Fast-Path",
      icon: Radar,
      category: "Passive Data Collection",
      status: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "no_results";
        const c = pr.connectorResults.find((r: any) => r.connector === "shodan_internetdb");
        return c && c.observations?.length > 0 ? "completed" : "no_results";
      })(),
      description: "Queried internet scan databases's free InternetDB API for instant IP enrichment — open ports, CVEs, CPEs, hostnames, and tags — without consuming API credits.",
      outputs: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "Not executed";
        const c = pr.connectorResults.find((r: any) => r.connector === "shodan_internetdb");
        if (!c) return "Not executed";
        return `${c.observations?.length || 0} observations from InternetDB`;
      })(),
      attribution: 'Data from Internet Scan Database (internetdb.shodan.io). Free, no API key required.',
      fpRisk: "Low — based on real internet scan databases scan data.",
      verifyCmd: "curl https://internetdb.shodan.io/<IP>",
    },
    {
      id: "binaryedge_enrichment",
      name: "BinaryEdge Host Intelligence",
      icon: Scan,
      category: "Passive Data Collection",
      status: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "no_results";
        const c = pr.connectorResults.find((r: any) => r.connector === "binaryedge");
        return c && c.observations?.length > 0 ? "completed" : "no_results";
      })(),
      description: "Queried BinaryEdge's internet-wide scanning database for independent validation of open ports, service banners, and CVEs. Provides multi-source corroboration with ~3,500 port coverage.",
      outputs: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "Not executed";
        const c = pr.connectorResults.find((r: any) => r.connector === "binaryedge");
        if (!c) return "Not executed";
        if (c.errors?.some((e: string) => e.includes("Skipped"))) return "Skipped — no API key configured";
        return `${c.observations?.length || 0} observations from BinaryEdge`;
      })(),
      attribution: 'Data from BinaryEdge (binaryedge.io). Independent scanning source.',
      fpRisk: "Low — based on real scan data from an independent source.",
      verifyCmd: "Visit https://app.binaryedge.io/services/query",
    },
    {
      id: "greynoise_enrichment",
      name: "GreyNoise Threat Pressure Context",
      icon: Radio,
      category: "Passive Data Collection",
      status: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "no_results";
        const c = pr.connectorResults.find((r: any) => r.connector === "greynoise");
        return c && c.observations?.length > 0 ? "completed" : "no_results";
      })(),
      description: "Queried GreyNoise to classify IPs as benign, malicious, or unknown. Identifies assets under active attack and IPs being mass-scanned. Provides unique threat pressure context.",
      outputs: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "Not executed";
        const c = pr.connectorResults.find((r: any) => r.connector === "greynoise");
        if (!c) return "Not executed";
        if (c.errors?.some((e: string) => e.includes("Skipped"))) return "Skipped — no API key or DNS resolution required";
        return `${c.observations?.length || 0} observations from GreyNoise`;
      })(),
      attribution: 'Data from GreyNoise (greynoise.io). Verify at: https://viz.greynoise.io/ip/<IP>',
      fpRisk: "Low — classifications based on observed internet traffic behavior.",
      verifyCmd: "Visit https://viz.greynoise.io/ip/<IP>",
    },
    {
      id: "github_recon",
      name: "Enhanced GitHub Reconnaissance",
      icon: Globe,
      category: "Passive Data Collection",
      status: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "no_results";
        const c = pr.connectorResults.find((r: any) => r.connector === "github_recon");
        return c && c.observations?.length > 0 ? "completed" : "no_results";
      })(),
      description: "Deep GitHub reconnaissance — discovers target organizations, enumerates public repositories, maps contributors and members, analyzes CI/CD workflows for secrets exposure, scans code with 30+ dork patterns, and detects leaked credentials using TruffleHog-style regex patterns.",
      outputs: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "Not executed";
        const c = pr.connectorResults.find((r: any) => r.connector === "github_recon");
        if (!c) return "Not executed";
        const orgs = c.observations?.filter((o: any) => o.tags?.includes('organization'))?.length || 0;
        const repos = c.observations?.filter((o: any) => o.tags?.includes('repository'))?.length || 0;
        const leaks = c.observations?.filter((o: any) => o.tags?.includes('code_leak'))?.length || 0;
        const secrets = c.observations?.filter((o: any) => o.tags?.includes('secrets_detected'))?.length || 0;
        return `${c.observations?.length || 0} observations: ${orgs} orgs, ${repos} repos, ${leaks} code leaks, ${secrets} secrets detected`;
      })(),
      attribution: 'Data from GitHub REST API and Code Search API. Verify at: https://github.com/<org>',
      fpRisk: "Low for org/repo discovery. Medium for code leak dorks (may match test/example files).",
      verifyCmd: "Visit the GitHub URLs in each finding to verify",
    },
    {
      id: "cloud_bucket_recon",
      name: "Enhanced Cloud Bucket Discovery",
      icon: Radar,
      category: "Passive Data Collection",
      status: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "no_results";
        const c = pr.connectorResults.find((r: any) => r.connector === "cloud_bucket_recon");
        return c && c.observations?.length > 0 ? "completed" : "no_results";
      })(),
      description: "Comprehensive cloud storage enumeration across 5 providers (AWS S3, Azure Blob, GCP Storage, DigitalOcean Spaces, Alibaba OSS). Uses intelligent wordlist generation with industry-specific patterns, permission depth analysis, public content listing, and sensitive file detection.",
      outputs: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "Not executed";
        const c = pr.connectorResults.find((r: any) => r.connector === "cloud_bucket_recon");
        if (!c) return "Not executed";
        const pub = c.observations?.filter((o: any) => o.tags?.includes('public_bucket'))?.length || 0;
        const priv = c.observations?.filter((o: any) => o.tags?.includes('private_bucket'))?.length || 0;
        const sensitive = c.observations?.filter((o: any) => o.tags?.includes('sensitive_files_exposed'))?.length || 0;
        return `${c.observations?.length || 0} observations: ${pub} public buckets, ${priv} private buckets${sensitive > 0 ? `, ${sensitive} with sensitive files` : ''}`;
      })(),
      attribution: 'Probed cloud storage endpoints directly. Verify by visiting the bucket URLs.',
      fpRisk: "Low — bucket existence is deterministic (HTTP 200/403 vs 404).",
      verifyCmd: "curl -I https://<bucket>.s3.amazonaws.com/",
    },
    {
      id: "dehashed_breach",
      name: "Dehashed Breach Intelligence",
      icon: Lock,
      category: "Passive Data Collection",
      status: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "no_results";
        const dh = pr.connectorResults.find((r: any) => r.connector === "dehashed");
        return dh && dh.observations?.length > 0 ? "completed" : "no_results";
      })(),
      description: "Queried Dehashed's 15B+ breach record database for domain and subdomain mapping through leaked email addresses, credential exposure detection, IP associations, and breach database attribution.",
      outputs: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "Not executed";
        const dh = pr.connectorResults.find((r: any) => r.connector === "dehashed");
        if (!dh) return "Not executed";
        const breachObs = dh.observations?.filter((o: any) => o.assetType === "breach") || [];
        const subdomainObs = dh.observations?.filter((o: any) => o.assetType === "subdomain") || [];
        const ipObs = dh.observations?.filter((o: any) => o.assetType === "ip") || [];
        return `${dh.observations?.length || 0} observations: ${subdomainObs.length} subdomains, ${ipObs.length} IPs, ${breachObs.length} breach records`;
      })(),
      attribution: 'Data from Dehashed (dehashed.com). Breach records aggregated from public and private data wells.',
      fpRisk: "Low — breach records are real artifacts. Subdomains from email domains are highly reliable.",
      verifyCmd: "Search dehashed.com for domain:<domain>",
    },
    {
      id: "kev_enrichment",
      name: "KEV Matching",
      icon: Shield,
      category: "Vulnerability Intelligence",
      status: kevFindings.length > 0 ? "completed" : "no_results",
      description: "Cross-referenced detected technologies against the CISA Known Exploited Vulnerabilities catalog — CVEs confirmed to be actively exploited in the wild.",
      outputs: `${kevFindings.length} KEV-listed findings matched`,
      attribution: 'Verify at: https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      fpRisk: "Low for product match, Medium for version match.",
      verifyCmd: "Search KEV by CVE ID",
    },
    {
      id: "vuln_feed",
      name: "Multi-Source Vulnerability Feed Matching",
      icon: Bug,
      category: "Vulnerability Intelligence",
      status: confirmedFindings.length + probableFindings.length > 0 ? "completed" : "no_results",
      description: "Matched technologies against NVD, zero-day research programs, vulnerability advisory feeds, and public exploit databases. Provides CVSS scores and exploit availability.",
      outputs: `${confirmedFindings.length} confirmed + ${probableFindings.length} probable CVE matches`,
      attribution: 'Each CVE links to NVD: https://nvd.nist.gov/vuln/detail/<CVE-ID>',
      fpRisk: "Medium — product-family matches may not apply to the specific version.",
      verifyCmd: "Visit NVD page for each CVE ID",
    },
    {
      id: "carver_shock",
      name: "Business Impact Analysis",
      icon: Target,
      category: "Risk Scoring",
      status: "completed",
      description: "Applied proprietary multi-dimensional targeting methodology to score each asset's mission importance and cascading risk.",
      outputs: `Scored ${assets.length} assets across 11 impact dimensions`,
      attribution: 'Scores are LLM-generated analytical estimates based on asset type and sector context.',
      fpRisk: "N/A — risk scores, not binary findings.",
      verifyCmd: "Review individual asset impact scores in Assets tab",
    },
    {
      id: "hybrid_risk",
      name: "Hybrid Risk Score Computation",
      icon: Radar,
      category: "Risk Scoring",
      status: "completed",
      description: "Combined vulnerability severity with mission impact analysis into a hybrid risk score. Also provides separated Asset Criticality (mission importance) and Vulnerability Risk (confirmed/probable scan findings only) scores.",
      outputs: `Overall risk: ${scan.overallRiskScore || 'N/A'} (${scan.overallRiskBand || 'N/A'}). Asset criticality and vuln risk are now separated — high criticality does NOT imply high vulnerability risk.`,
      attribution: 'Deterministic formula — same inputs always produce the same score. Vuln risk only counts confirmed/probable findings.',
      fpRisk: "N/A — composite score. Vuln risk requires scan evidence.",
      verifyCmd: "Compare CRIT vs VULN scores in the Assets tab",
    },
    {
      id: "threat_actors",
      name: "Threat Actor Profiling",
      icon: Crosshair,
      category: "Threat Intelligence",
      status: (scan.pipelineOutput as any)?.threatActorMatches ? "completed" : "no_results",
      description: "Matched the organization's sector, technology stack, and risk profile against known threat actor groups (APTs, cybercrime groups).",
      outputs: `${(scan.pipelineOutput as any)?.threatActorMatches?.topMatches?.length || 0} threat actors matched`,
      attribution: 'Verify actor profiles at: https://attack.mitre.org/groups/',
      fpRisk: "Medium — threat actor targeting is probabilistic.",
      verifyCmd: "Search MITRE ATT&CK Groups by name",
    },
    {
      id: "campaign_design",
      name: "Automated Campaign Design",
      icon: Zap,
      category: "Offensive Planning",
      status: ((scan.campaignRecommendations || []) as any[]).length > 0 ? "completed" : "no_results",
      description: "Auto-generated red team, phishing, and purple team campaign recommendations based on discovered assets, vulnerabilities, and threat actor TTPs.",
      outputs: `${((scan.campaignRecommendations || []) as any[]).length} campaigns designed`,
      attribution: 'emulation framework abilities reference real ATT&CK technique IDs. Verify at: https://attack.mitre.org/techniques/<ID>',
      fpRisk: "N/A — recommendations, not findings.",
      verifyCmd: "Review campaigns in the Campaigns tab",
    },
  ];

  const categories = ["Passive Data Collection", "Discovery", "Vulnerability Intelligence", "Risk Scoring", "Threat Intelligence", "Offensive Planning"];

  return (
    <>
      {/* Page description */}
      <Card className="bg-purple-500/5 border-purple-500/20">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-purple-400 mt-0.5 shrink-0" />
            <div>
              <p className="text-sm font-semibold">Scan Methods & Attribution</p>
              <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                This tab shows every method that was executed during this full-scope domain intelligence scan.
                Each method includes what it found, how to verify the results independently, and the false positive risk level.
                Use this information to validate findings before acting on them.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-purple-400">{METHODS.length}</p>
            <p className="text-[10px] text-muted-foreground">Methods Executed</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-emerald-400">{METHODS.filter(m => m.status === 'completed').length}</p>
            <p className="text-[10px] text-muted-foreground">Produced Results</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-cyan-400">{categories.length}</p>
            <p className="text-[10px] text-muted-foreground">Categories Covered</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-yellow-400">{allFindings.length}</p>
            <p className="text-[10px] text-muted-foreground">Total Findings</p>
          </CardContent>
        </Card>
      </div>

      {/* Methods by category */}
      {categories.map(category => {
        const methods = METHODS.filter(m => m.category === category);
        if (methods.length === 0) return null;
        return (
          <div key={category}>
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">{category}</p>
            <div className="space-y-2">
              {methods.map(method => {
                const Icon = method.icon;
                const isCompleted = method.status === 'completed';
                return (
                  <Card key={method.id} className={isCompleted ? "border-emerald-500/20" : "border-border/40 opacity-60"}>
                    <CardContent className="p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <div className={`p-1.5 rounded-lg ${isCompleted ? 'bg-emerald-500/10' : 'bg-muted'}`}>
                            <Icon className={`h-4 w-4 ${isCompleted ? 'text-emerald-400' : 'text-muted-foreground'}`} />
                          </div>
                          <div>
                            <p className="font-semibold text-sm">{method.name}</p>
                            <p className="text-[10px] text-muted-foreground">{method.category}</p>
                          </div>
                        </div>
                        <Badge className={isCompleted
                          ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40 text-[10px]"
                          : "bg-muted text-muted-foreground text-[10px]"
                        }>
                          {isCompleted ? "Results Found" : "No Results"}
                        </Badge>
                      </div>

                      <p className="text-xs text-muted-foreground leading-relaxed">{method.description}</p>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-border/40">
                        <div className="space-y-1.5">
                          <div className="flex items-start gap-2">
                            <Badge className="text-[8px] bg-emerald-500/20 text-emerald-400 border-emerald-500/40 shrink-0">OUTPUT</Badge>
                            <span className="text-[10px] text-foreground/80">{method.outputs}</span>
                          </div>
                          <div className="flex items-start gap-2">
                            <Badge className="text-[8px] bg-orange-500/20 text-orange-400 border-orange-500/40 shrink-0">FP RISK</Badge>
                            <span className="text-[10px] text-muted-foreground">{method.fpRisk}</span>
                          </div>
                        </div>
                        <div className="space-y-1.5">
                          <div className="flex items-start gap-2">
                            <Badge className="text-[8px] bg-cyan-500/20 text-cyan-400 border-cyan-500/40 shrink-0">VERIFY</Badge>
                            <span className="text-[10px] text-muted-foreground">{method.attribution}</span>
                          </div>
                          <div className="flex items-start gap-2">
                            <Badge className="text-[8px] bg-purple-500/20 text-purple-400 border-purple-500/40 shrink-0">CMD</Badge>
                            <code className="text-[10px] text-purple-400/80 font-mono bg-muted/30 px-1 rounded">{method.verifyCmd}</code>
                          </div>
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

      {/* Corroboration Tiers Explanation */}
      <div>
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Finding Corroboration Tiers</p>
        <p className="text-xs text-muted-foreground mb-3">
          Every finding is assigned a corroboration tier that indicates how much evidence supports it.
          Severity scores are capped based on the tier to prevent inflated risk from unverified findings.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {[
            { tier: "CONFIRMED", count: confirmedFindings.length, color: "text-emerald-400 bg-emerald-500/20 border-emerald-500/40", desc: "Technology version detected AND matched to CVE affected range. Severity uncapped.", verify: "Check CVE affected version range against detected version." },
            { tier: "PROBABLE", count: probableFindings.length, color: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40", desc: "Product detected but version unknown. CVE exists for product family. Severity capped at 6/10.", verify: "Confirm actual version to determine if it falls within CVE range." },
            { tier: "POTENTIAL", count: potentialFindings.length, color: "text-purple-400 bg-purple-500/20 border-purple-500/40", desc: "LLM-inferred risk with no CVE backing. Severity capped at 4/10. Advisory only.", verify: "Perform manual assessment or active scanning." },
            { tier: "INFORMATIONAL", count: informationalFindings.length, color: "text-slate-400 bg-slate-500/20 border-slate-500/40", desc: "Downgraded or out-of-scope findings. No exploitation expected.", verify: "Review analyst notes for context." },
          ].map(t => (
            <Card key={t.tier} className={`border ${t.color.split(' ').filter(c => c.startsWith('border-')).join(' ')}`}>
              <CardContent className="p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <Badge className={`text-[10px] ${t.color}`}>{t.tier}</Badge>
                  <span className="text-lg font-bold">{t.count}</span>
                </div>
                <p className="text-[10px] text-muted-foreground">{t.desc}</p>
                <p className="text-[10px] text-cyan-400/80"><span className="font-medium">Verify:</span> {t.verify}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </>
  );
}

// ─── Vulnerability Intelligence Section for Domain Intel ───

