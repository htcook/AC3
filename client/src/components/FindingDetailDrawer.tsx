import { useState } from "react";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription,
} from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Shield, AlertTriangle, ExternalLink, Bug, Copy, Check,
  Target, Fingerprint, Gauge, Flame, Globe2, GitBranch,
  FileWarning, Skull, TrendingUp, Info,
} from "lucide-react";

/* ── Types ── */
export interface VulnFinding {
  id: string;
  severity: string;
  title: string;
  cve?: string;
  corroborationTier?: string;
  detectedVersion?: string | null;
  affectedVersions?: string | null;
  versionMatchConfirmed?: boolean;
  evidenceDetail?: string | null;
  cvssScore?: number | null;
  tool?: string;
  essEnrichment?: {
    cessScore: number;
    cvssBase: number;
    cvssVector?: string;
    epssScore: number;
    exploitdbCount: number;
    metasploitCount: number;
    cisaKev: boolean;
    githubPocs: number;
    riskTier?: string;
    riskSummary?: string;
  };
}

export interface ZapFinding {
  alert: string;
  risk: string;
  url: string;
  cweId?: number;
  description?: string;
  solution?: string;
  reference?: string;
  evidence?: string;
  param?: string;
  attack?: string;
  otherInfo?: string;
}

/* ── Severity helpers ── */
const severityConfig: Record<string, { color: string; bg: string; border: string; label: string }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", label: "CRITICAL" },
  high:     { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", label: "HIGH" },
  medium:   { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", label: "MEDIUM" },
  low:      { color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", label: "LOW" },
  info:     { color: "text-gray-400", bg: "bg-gray-500/10", border: "border-gray-500/30", label: "INFO" },
};

function getSeverityConfig(severity: string) {
  return severityConfig[severity?.toLowerCase()] || severityConfig.info;
}

function cvssToSeverity(score: number): string {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}

/* ── CVSS Vector Breakdown ── */
function CvssVectorBreakdown({ vector }: { vector: string }) {
  const parts = vector.split("/").slice(1); // skip CVSS:3.1
  const labels: Record<string, string> = {
    AV: "Attack Vector", AC: "Attack Complexity", PR: "Privileges Required",
    UI: "User Interaction", S: "Scope", C: "Confidentiality", I: "Integrity", A: "Availability",
  };
  const values: Record<string, Record<string, { label: string; risk: string }>> = {
    AV: { N: { label: "Network", risk: "high" }, A: { label: "Adjacent", risk: "medium" }, L: { label: "Local", risk: "low" }, P: { label: "Physical", risk: "low" } },
    AC: { L: { label: "Low", risk: "high" }, H: { label: "High", risk: "low" } },
    PR: { N: { label: "None", risk: "high" }, L: { label: "Low", risk: "medium" }, H: { label: "High", risk: "low" } },
    UI: { N: { label: "None", risk: "high" }, R: { label: "Required", risk: "low" } },
    S:  { U: { label: "Unchanged", risk: "low" }, C: { label: "Changed", risk: "high" } },
    C:  { N: { label: "None", risk: "low" }, L: { label: "Low", risk: "medium" }, H: { label: "High", risk: "high" } },
    I:  { N: { label: "None", risk: "low" }, L: { label: "Low", risk: "medium" }, H: { label: "High", risk: "high" } },
    A:  { N: { label: "None", risk: "low" }, L: { label: "Low", risk: "medium" }, H: { label: "High", risk: "high" } },
  };
  const riskColors: Record<string, string> = { high: "text-red-400", medium: "text-yellow-400", low: "text-green-400" };

  return (
    <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
      {parts.map((part, i) => {
        const [key, val] = part.split(":");
        const label = labels[key] || key;
        const info = values[key]?.[val];
        return (
          <div key={i} className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">{label}</span>
            <span className={`font-mono font-medium ${info ? riskColors[info.risk] || "text-foreground" : "text-foreground"}`}>
              {info?.label || val}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/* ── Copy Button ── */
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="ghost" size="sm" className="h-6 w-6 p-0"
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
    >
      {copied ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3 text-muted-foreground" />}
    </Button>
  );
}

/* ── Section Component ── */
function Section({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
        {icon}{title}
      </h4>
      {children}
    </div>
  );
}

/* ── Vuln Detail Drawer ── */
export function VulnDetailDrawer({ vuln, open, onClose, assetHostname }: {
  vuln: VulnFinding | null;
  open: boolean;
  onClose: () => void;
  assetHostname?: string;
}) {
  if (!vuln) return null;
  const sev = getSeverityConfig(vuln.severity);
  const ess = vuln.essEnrichment;
  const effectiveCvss = ess?.cvssBase || vuln.cvssScore || 0;
  const effectiveVector = ess?.cvssVector || null;

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-[520px] sm:max-w-[520px] bg-card border-l border-border p-0">
        <SheetHeader className="px-6 pt-6 pb-4 border-b border-border">
          <div className="flex items-start gap-3">
            <div className={`p-2 rounded-lg ${sev.bg} ${sev.border} border`}>
              <Bug className={`h-5 w-5 ${sev.color}`} />
            </div>
            <div className="flex-1 min-w-0">
              <SheetTitle className="text-base font-semibold text-foreground leading-tight">
                {vuln.title}
              </SheetTitle>
              <SheetDescription className="mt-1 flex items-center gap-2 flex-wrap">
                <Badge variant="outline" className={`text-[10px] font-bold ${sev.color} ${sev.border}`}>
                  {sev.label}
                </Badge>
                {vuln.cve && (
                  <span className="flex items-center gap-1">
                    <span className="font-mono text-xs text-cyan-400">{vuln.cve}</span>
                    <CopyButton text={vuln.cve} />
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`}
                      target="_blank" rel="noopener noreferrer"
                      className="text-muted-foreground hover:text-foreground"
                    >
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </span>
                )}
                {assetHostname && (
                  <span className="text-[10px] text-muted-foreground">on {assetHostname}</span>
                )}
              </SheetDescription>
            </div>
          </div>
        </SheetHeader>

        <ScrollArea className="h-[calc(100vh-140px)]">
          <div className="px-6 py-4 space-y-5">

            {/* CVSS Score & Vector */}
            {effectiveCvss > 0 && (
              <Section title="CVSS Score" icon={<Gauge className="h-3.5 w-3.5" />}>
                <div className={`flex items-center gap-3 p-3 rounded-lg ${getSeverityConfig(cvssToSeverity(effectiveCvss)).bg} border ${getSeverityConfig(cvssToSeverity(effectiveCvss)).border}`}>
                  <div className={`text-3xl font-bold font-mono ${getSeverityConfig(cvssToSeverity(effectiveCvss)).color}`}>
                    {effectiveCvss.toFixed(1)}
                  </div>
                  <div>
                    <div className={`text-sm font-semibold ${getSeverityConfig(cvssToSeverity(effectiveCvss)).color}`}>
                      {getSeverityConfig(cvssToSeverity(effectiveCvss)).label}
                    </div>
                    {effectiveVector && (
                      <div className="text-[10px] font-mono text-muted-foreground mt-0.5 flex items-center gap-1">
                        {effectiveVector}
                        <CopyButton text={effectiveVector} />
                      </div>
                    )}
                  </div>
                </div>
                {effectiveVector && (
                  <div className="mt-3 p-3 rounded-lg bg-muted/20 border border-border/30">
                    <h5 className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-2">Vector Breakdown</h5>
                    <CvssVectorBreakdown vector={effectiveVector} />
                  </div>
                )}
              </Section>
            )}

            {/* Corroboration & Confidence */}
            {vuln.corroborationTier && (
              <Section title="Confidence Assessment" icon={<Fingerprint className="h-3.5 w-3.5" />}>
                <div className="p-3 rounded-lg bg-muted/20 border border-border/30 space-y-2">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={`text-[10px] font-bold ${
                      vuln.corroborationTier === 'confirmed' ? 'bg-green-500/20 text-green-300 border-green-500/40' :
                      vuln.corroborationTier === 'probable' ? 'bg-blue-500/20 text-blue-300 border-blue-500/40' :
                      'bg-zinc-500/20 text-zinc-400 border-zinc-500/40'
                    }`}>
                      {vuln.corroborationTier === 'confirmed' ? '\u2713 CONFIRMED' :
                       vuln.corroborationTier === 'probable' ? '\u223c PROBABLE' : '? POTENTIAL'}
                    </Badge>
                    {vuln.versionMatchConfirmed && (
                      <Badge variant="outline" className="text-[10px] bg-emerald-500/20 text-emerald-300 border-emerald-500/40">
                        VERSION MATCH
                      </Badge>
                    )}
                  </div>
                  {vuln.detectedVersion && (
                    <div className="text-xs">
                      <span className="text-muted-foreground">Detected Version: </span>
                      <span className="font-mono text-emerald-400">v{vuln.detectedVersion}</span>
                    </div>
                  )}
                  {vuln.affectedVersions && (
                    <div className="text-xs">
                      <span className="text-muted-foreground">Affected Versions: </span>
                      <span className="font-mono text-foreground">{vuln.affectedVersions}</span>
                    </div>
                  )}
                </div>
              </Section>
            )}

            {/* Evidence */}
            {vuln.evidenceDetail && (
              <Section title="Evidence" icon={<FileWarning className="h-3.5 w-3.5" />}>
                <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                  <p className="text-xs text-foreground leading-relaxed whitespace-pre-wrap">{vuln.evidenceDetail}</p>
                </div>
              </Section>
            )}

            {/* ESS Exploit Intelligence */}
            {ess && (
              <>
                <Separator />
                <Section title="Exploit Intelligence (ESS)" icon={<Skull className="h-3.5 w-3.5" />}>
                  <div className="space-y-3">
                    {/* Risk Summary */}
                    {ess.riskSummary && (
                      <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                        <p className="text-xs text-foreground leading-relaxed">{ess.riskSummary}</p>
                      </div>
                    )}

                    {/* Key Indicators Grid */}
                    <div className="grid grid-cols-2 gap-2">
                      {/* CESS Score */}
                      <div className={`p-2.5 rounded-lg border ${ess.cessScore >= 0.7 ? 'bg-red-500/10 border-red-500/30' : ess.cessScore >= 0.4 ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-green-500/10 border-green-500/30'}`}>
                        <div className="text-[10px] text-muted-foreground uppercase tracking-wider">CESS Exploit Prob.</div>
                        <div className={`text-lg font-bold font-mono ${ess.cessScore >= 0.7 ? 'text-red-400' : ess.cessScore >= 0.4 ? 'text-yellow-400' : 'text-green-400'}`}>
                          {(ess.cessScore * 100).toFixed(0)}%
                        </div>
                      </div>

                      {/* EPSS Score */}
                      <div className={`p-2.5 rounded-lg border ${ess.epssScore >= 0.5 ? 'bg-red-500/10 border-red-500/30' : ess.epssScore >= 0.1 ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-green-500/10 border-green-500/30'}`}>
                        <div className="text-[10px] text-muted-foreground uppercase tracking-wider">EPSS Score</div>
                        <div className={`text-lg font-bold font-mono ${ess.epssScore >= 0.5 ? 'text-red-400' : ess.epssScore >= 0.1 ? 'text-yellow-400' : 'text-green-400'}`}>
                          {(ess.epssScore * 100).toFixed(1)}%
                        </div>
                      </div>
                    </div>

                    {/* Exploit Availability */}
                    <div className="space-y-1.5">
                      <h5 className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Exploit Availability</h5>
                      <div className="flex flex-wrap gap-2">
                        {ess.cisaKev && (
                          <Badge className="bg-red-600/80 text-white border-red-500 text-[10px] font-bold">
                            <AlertTriangle className="h-3 w-3 mr-1" />CISA KEV
                          </Badge>
                        )}
                        {ess.metasploitCount > 0 && (
                          <Badge variant="outline" className="text-[10px] bg-purple-500/20 text-purple-300 border-purple-500/40">
                            <Flame className="h-3 w-3 mr-1" />Metasploit: {ess.metasploitCount} module{ess.metasploitCount > 1 ? 's' : ''}
                          </Badge>
                        )}
                        {ess.exploitdbCount > 0 && (
                          <Badge variant="outline" className="text-[10px] bg-orange-500/20 text-orange-300 border-orange-500/40">
                            <Target className="h-3 w-3 mr-1" />ExploitDB: {ess.exploitdbCount} exploit{ess.exploitdbCount > 1 ? 's' : ''}
                          </Badge>
                        )}
                        {ess.githubPocs > 0 && (
                          <Badge variant="outline" className="text-[10px] bg-green-500/20 text-green-300 border-green-500/40">
                            <GitBranch className="h-3 w-3 mr-1" />GitHub PoCs: {ess.githubPocs}
                          </Badge>
                        )}
                        {!ess.cisaKev && ess.metasploitCount === 0 && ess.exploitdbCount === 0 && ess.githubPocs === 0 && (
                          <span className="text-xs text-muted-foreground">No known public exploits</span>
                        )}
                      </div>
                    </div>

                    {/* Risk Tier */}
                    {ess.riskTier && (
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-muted-foreground uppercase tracking-wider">ESS Risk Tier:</span>
                        <Badge variant="outline" className={`text-[10px] font-bold ${
                          ess.riskTier === 'critical' ? 'text-red-400 border-red-500/30' :
                          ess.riskTier === 'high' ? 'text-orange-400 border-orange-500/30' :
                          ess.riskTier === 'medium' ? 'text-yellow-400 border-yellow-500/30' :
                          'text-green-400 border-green-500/30'
                        }`}>
                          {ess.riskTier.toUpperCase()}
                        </Badge>
                      </div>
                    )}
                  </div>
                </Section>
              </>
            )}

            {/* Why This CVSS Score */}
            <Separator />
            <Section title="Why This Severity Rating?" icon={<Info className="h-3.5 w-3.5" />}>
              <div className="p-3 rounded-lg bg-muted/20 border border-border/30 space-y-2 text-xs text-foreground leading-relaxed">
                {effectiveCvss > 0 ? (
                  <>
                    <p>
                      This finding is rated <strong className={sev.color}>{sev.label}</strong> based on
                      {ess ? " the Coalition ESS enrichment data" : " the CVSS base score"}
                      {effectiveCvss > 0 && ` of ${effectiveCvss.toFixed(1)}`}.
                    </p>
                    {ess && (
                      <p>
                        The CESS exploit probability is <strong>{(ess.cessScore * 100).toFixed(0)}%</strong>,
                        {ess.cisaKev && " this CVE is on the CISA Known Exploited Vulnerabilities catalog,"}
                        {ess.metasploitCount > 0 && ` ${ess.metasploitCount} Metasploit module(s) exist,`}
                        {ess.exploitdbCount > 0 && ` ${ess.exploitdbCount} ExploitDB entry(s) exist,`}
                        {ess.githubPocs > 0 && ` ${ess.githubPocs} GitHub PoC(s) found,`}
                        {" "}making this a {ess.cessScore >= 0.7 ? "high-priority" : ess.cessScore >= 0.4 ? "moderate-priority" : "lower-priority"} remediation target.
                      </p>
                    )}
                    {vuln.corroborationTier && (
                      <p>
                        Confidence: <strong>{vuln.corroborationTier === 'confirmed' ? 'Confirmed' : vuln.corroborationTier === 'probable' ? 'Probable' : 'Potential'}</strong>
                        {vuln.detectedVersion && ` — detected version ${vuln.detectedVersion}`}
                        {vuln.affectedVersions && ` falls within affected range ${vuln.affectedVersions}`}
                        {vuln.versionMatchConfirmed && " (version match confirmed)"}.
                      </p>
                    )}
                  </>
                ) : (
                  <p>
                    This finding is rated <strong className={sev.color}>{sev.label}</strong> based on
                    the tool's assessment. {vuln.corroborationTier === 'confirmed'
                      ? "It has been confirmed by active scanning."
                      : "Further validation may be needed to confirm exploitability."}
                  </p>
                )}
              </div>
            </Section>

            {/* External References */}
            {vuln.cve && (
              <>
                <Separator />
                <Section title="References" icon={<Globe2 className="h-3.5 w-3.5" />}>
                  <div className="space-y-1">
                    <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`} target="_blank" rel="noopener noreferrer"
                      className="flex items-center gap-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
                      <ExternalLink className="h-3 w-3" />NVD: {vuln.cve}
                    </a>
                    <a href={`https://www.cvedetails.com/cve/${vuln.cve}/`} target="_blank" rel="noopener noreferrer"
                      className="flex items-center gap-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
                      <ExternalLink className="h-3 w-3" />CVE Details
                    </a>
                    <a href={`https://vulners.com/cve/${vuln.cve}`} target="_blank" rel="noopener noreferrer"
                      className="flex items-center gap-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
                      <ExternalLink className="h-3 w-3" />Vulners
                    </a>
                    {ess?.metasploitCount && ess.metasploitCount > 0 && (
                      <a href={`https://www.rapid7.com/db/?q=${vuln.cve}&type=module`} target="_blank" rel="noopener noreferrer"
                        className="flex items-center gap-2 text-xs text-purple-400 hover:text-purple-300 transition-colors">
                        <ExternalLink className="h-3 w-3" />Rapid7 Metasploit Modules
                      </a>
                    )}
                    {ess?.exploitdbCount && ess.exploitdbCount > 0 && (
                      <a href={`https://www.exploit-db.com/search?cve=${vuln.cve.replace('CVE-', '')}`} target="_blank" rel="noopener noreferrer"
                        className="flex items-center gap-2 text-xs text-orange-400 hover:text-orange-300 transition-colors">
                        <ExternalLink className="h-3 w-3" />ExploitDB
                      </a>
                    )}
                  </div>
                </Section>
              </>
            )}
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}

/* ── ZAP Finding Detail Drawer ── */
export function ZapFindingDetailDrawer({ finding, open, onClose, assetHostname }: {
  finding: ZapFinding | null;
  open: boolean;
  onClose: () => void;
  assetHostname?: string;
}) {
  if (!finding) return null;
  const riskMap: Record<string, string> = { "High": "high", "Medium": "medium", "Low": "low", "Informational": "info" };
  const sev = getSeverityConfig(riskMap[finding.risk] || "info");

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-[520px] sm:max-w-[520px] bg-card border-l border-border p-0">
        <SheetHeader className="px-6 pt-6 pb-4 border-b border-border">
          <div className="flex items-start gap-3">
            <div className={`p-2 rounded-lg ${sev.bg} ${sev.border} border`}>
              <Shield className={`h-5 w-5 ${sev.color}`} />
            </div>
            <div className="flex-1 min-w-0">
              <SheetTitle className="text-base font-semibold text-foreground leading-tight">
                {finding.alert}
              </SheetTitle>
              <SheetDescription className="mt-1 flex items-center gap-2 flex-wrap">
                <Badge variant="outline" className={`text-[10px] font-bold ${sev.color} ${sev.border}`}>
                  {finding.risk.toUpperCase()}
                </Badge>
                {finding.cweId && (
                  <a href={`https://cwe.mitre.org/data/definitions/${finding.cweId}.html`} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-1 text-[10px] font-mono text-cyan-400 hover:text-cyan-300">
                    CWE-{finding.cweId}
                    <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                )}
                {assetHostname && (
                  <span className="text-[10px] text-muted-foreground">on {assetHostname}</span>
                )}
              </SheetDescription>
            </div>
          </div>
        </SheetHeader>

        <ScrollArea className="h-[calc(100vh-140px)]">
          <div className="px-6 py-4 space-y-5">
            {/* Affected URL */}
            <Section title="Affected URL" icon={<Globe2 className="h-3.5 w-3.5" />}>
              <div className="p-3 rounded-lg bg-muted/20 border border-border/30 flex items-center gap-2">
                <span className="text-xs font-mono text-foreground break-all flex-1">{finding.url}</span>
                <CopyButton text={finding.url} />
              </div>
            </Section>

            {/* Attack Details */}
            {(finding.param || finding.attack) && (
              <Section title="Attack Details" icon={<Target className="h-3.5 w-3.5" />}>
                <div className="p-3 rounded-lg bg-muted/20 border border-border/30 space-y-2">
                  {finding.param && (
                    <div className="text-xs">
                      <span className="text-muted-foreground">Parameter: </span>
                      <span className="font-mono text-foreground">{finding.param}</span>
                    </div>
                  )}
                  {finding.attack && (
                    <div className="text-xs">
                      <span className="text-muted-foreground">Attack: </span>
                      <span className="font-mono text-foreground break-all">{finding.attack}</span>
                    </div>
                  )}
                </div>
              </Section>
            )}

            {/* Evidence */}
            {finding.evidence && (
              <Section title="Evidence" icon={<FileWarning className="h-3.5 w-3.5" />}>
                <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                  <pre className="text-xs text-foreground whitespace-pre-wrap font-mono">{finding.evidence}</pre>
                </div>
              </Section>
            )}

            {/* Description */}
            {finding.description && (
              <Section title="Description" icon={<Info className="h-3.5 w-3.5" />}>
                <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                  <p className="text-xs text-foreground leading-relaxed">{finding.description}</p>
                </div>
              </Section>
            )}

            {/* Solution */}
            {finding.solution && (
              <Section title="Remediation" icon={<Shield className="h-3.5 w-3.5" />}>
                <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                  <p className="text-xs text-foreground leading-relaxed">{finding.solution}</p>
                </div>
              </Section>
            )}

            {/* References */}
            <Separator />
            <Section title="References" icon={<Globe2 className="h-3.5 w-3.5" />}>
              <div className="space-y-1">
                {finding.cweId && (
                  <a href={`https://cwe.mitre.org/data/definitions/${finding.cweId}.html`} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
                    <ExternalLink className="h-3 w-3" />CWE-{finding.cweId} Details
                  </a>
                )}
                {finding.reference && finding.reference.split('\n').filter(Boolean).map((ref, i) => (
                  <a key={i} href={ref.trim()} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors truncate">
                    <ExternalLink className="h-3 w-3 flex-none" />{ref.trim()}
                  </a>
                ))}
              </div>
            </Section>

            {/* Other Info */}
            {finding.otherInfo && (
              <Section title="Additional Information" icon={<TrendingUp className="h-3.5 w-3.5" />}>
                <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                  <p className="text-xs text-foreground leading-relaxed whitespace-pre-wrap">{finding.otherInfo}</p>
                </div>
              </Section>
            )}
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}
