import { useState } from "react";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription,
} from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Collapsible, CollapsibleContent, CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Shield, AlertTriangle, ExternalLink, Bug, Copy, Check,
  Target, Fingerprint, Gauge, Flame, Globe2, GitBranch,
  FileWarning, Skull, TrendingUp, Info, ChevronDown, ChevronRight,
  Terminal, Scan, ShieldCheck, FileText, Clock, Layers, BookOpen,
} from "lucide-react";
import { trpc } from "@/lib/trpc";

/* ── Common CWE Name Map (top 50 most common) ── */
const CWE_NAMES: Record<string, string> = {
  "CWE-20": "Improper Input Validation",
  "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
  "CWE-77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
  "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
  "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
  "CWE-98": "Improper Control of Filename for Include/Require Statement in PHP Program",
  "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
  "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
  "CWE-125": "Out-of-bounds Read",
  "CWE-190": "Integer Overflow or Wraparound",
  "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
  "CWE-264": "Permissions, Privileges, and Access Controls",
  "CWE-269": "Improper Privilege Management",
  "CWE-276": "Incorrect Default Permissions",
  "CWE-284": "Improper Access Control",
  "CWE-287": "Improper Authentication",
  "CWE-295": "Improper Certificate Validation",
  "CWE-306": "Missing Authentication for Critical Function",
  "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
  "CWE-311": "Missing Encryption of Sensitive Data",
  "CWE-319": "Cleartext Transmission of Sensitive Information",
  "CWE-326": "Inadequate Encryption Strength",
  "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
  "CWE-330": "Use of Insufficiently Random Values",
  "CWE-352": "Cross-Site Request Forgery (CSRF)",
  "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
  "CWE-400": "Uncontrolled Resource Consumption",
  "CWE-416": "Use After Free",
  "CWE-434": "Unrestricted Upload of File with Dangerous Type",
  "CWE-476": "NULL Pointer Dereference",
  "CWE-502": "Deserialization of Untrusted Data",
  "CWE-522": "Insufficiently Protected Credentials",
  "CWE-532": "Insertion of Sensitive Information into Log File",
  "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
  "CWE-611": "Improper Restriction of XML External Entity Reference",
  "CWE-613": "Insufficient Session Expiration",
  "CWE-639": "Authorization Bypass Through User-Controlled Key",
  "CWE-640": "Weak Password Recovery Mechanism for Forgotten Password",
  "CWE-668": "Exposure of Resource to Wrong Sphere",
  "CWE-732": "Incorrect Permission Assignment for Critical Resource",
  "CWE-787": "Out-of-bounds Write",
  "CWE-798": "Use of Hard-coded Credentials",
  "CWE-862": "Missing Authorization",
  "CWE-863": "Incorrect Authorization",
  "CWE-918": "Server-Side Request Forgery (SSRF)",
  "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
  "CWE-1236": "Improper Neutralization of Formula Elements in a CSV File",
};

function getCweName(cweId: string): string {
  return CWE_NAMES[cweId] || cweId;
}

/* ── Types ── */
export interface EvidenceStep {
  stage: string;
  tool: string;
  timestamp?: string;
  description: string;
  rawOutput?: string;
  httpRequest?: string;
  httpResponse?: string;
  command?: string;
  commandOutput?: string;
  confidence: string;
}

export interface ExploitEvidence {
  exploitName: string;
  exploitType: string;
  popsShell: boolean;
  shellType?: string;
  payload?: string;
  executionOutput?: string;
  shellSession?: string[];
  timestamp?: string;
  success: boolean;
}

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
  evidenceChain?: EvidenceStep[];
  exploitEvidence?: ExploitEvidence;
  validationResult?: {
    validated: boolean;
    method: string;
    proof: string;
    timestamp?: string;
  };
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
  const parts = vector.split("/").slice(1);
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

/* ── Collapsible Raw Output ── */
function CollapsibleOutput({ label, content }: { label: string; content: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger asChild>
        <button className="flex items-center gap-1.5 text-[10px] text-cyan-400 hover:text-cyan-300 transition-colors w-full text-left">
          {open ? <ChevronDown className="h-3 w-3 flex-none" /> : <ChevronRight className="h-3 w-3 flex-none" />}
          <span className="font-medium">{label}</span>
          <span className="text-muted-foreground ml-auto">{content.length > 500 ? `${(content.length / 1024).toFixed(1)}KB` : `${content.length} chars`}</span>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <pre className="mt-1.5 p-2.5 rounded bg-black/40 border border-border/20 text-[10px] font-mono text-green-300/80 overflow-x-auto max-h-[300px] overflow-y-auto whitespace-pre-wrap break-all">
          {content.slice(0, 10000)}
          {content.length > 10000 && "\n\n... [truncated]"}
        </pre>
      </CollapsibleContent>
    </Collapsible>
  );
}

/* ── Evidence Chain Step ── */
function EvidenceStepCard({ step, index }: { step: EvidenceStep; index: number }) {
  const confidenceColor = step.confidence === 'high' ? 'text-green-400 border-green-500/30 bg-green-500/10' :
    step.confidence === 'medium' ? 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10' :
    'text-zinc-400 border-zinc-500/30 bg-zinc-500/10';

  const stageIcon = step.stage === 'detection' ? <Scan className="h-3.5 w-3.5 text-blue-400" /> :
    step.stage === 'validation' ? <ShieldCheck className="h-3.5 w-3.5 text-green-400" /> :
    step.stage === 'exploitation' ? <Skull className="h-3.5 w-3.5 text-red-400" /> :
    <Layers className="h-3.5 w-3.5 text-muted-foreground" />;

  return (
    <div className="relative pl-6">
      {/* Timeline connector */}
      <div className="absolute left-[9px] top-0 bottom-0 w-px bg-border/40" />
      <div className="absolute left-0 top-2 h-5 w-5 rounded-full bg-card border border-border flex items-center justify-center z-10">
        <span className="text-[9px] font-bold text-muted-foreground">{index + 1}</span>
      </div>

      <div className="p-3 rounded-lg bg-muted/10 border border-border/30 space-y-2 ml-2">
        <div className="flex items-center gap-2 flex-wrap">
          {stageIcon}
          <span className="text-xs font-semibold text-foreground capitalize">{step.stage}</span>
          <Badge variant="outline" className="text-[9px]">{step.tool}</Badge>
          <Badge variant="outline" className={`text-[9px] ${confidenceColor}`}>
            {step.confidence} confidence
          </Badge>
          {step.timestamp && (
            <span className="text-[9px] text-muted-foreground flex items-center gap-0.5 ml-auto">
              <Clock className="h-2.5 w-2.5" />{step.timestamp}
            </span>
          )}
        </div>
        <p className="text-xs text-foreground/80 leading-relaxed">{step.description}</p>

        {/* Raw artifacts */}
        <div className="space-y-1.5">
          {step.rawOutput && <CollapsibleOutput label="Raw Scanner Output" content={step.rawOutput} />}
          {step.httpRequest && <CollapsibleOutput label="HTTP Request" content={step.httpRequest} />}
          {step.httpResponse && <CollapsibleOutput label="HTTP Response" content={step.httpResponse} />}
          {step.command && <CollapsibleOutput label="Command Executed" content={step.command} />}
          {step.commandOutput && <CollapsibleOutput label="Command Output" content={step.commandOutput} />}
        </div>
      </div>
    </div>
  );
}

/* ── Exploit Evidence Panel ── */
function ExploitEvidencePanel({ evidence }: { evidence: ExploitEvidence }) {
  return (
    <div className={`p-4 rounded-lg border space-y-3 ${
      evidence.success
        ? evidence.popsShell
          ? 'bg-red-500/5 border-red-500/30'
          : 'bg-orange-500/5 border-orange-500/30'
        : 'bg-zinc-500/5 border-zinc-500/30'
    }`}>
      {/* Header */}
      <div className="flex items-center gap-2 flex-wrap">
        {evidence.popsShell ? (
          <Badge className="bg-red-600/80 text-white border-red-500 text-[10px] font-bold">
            <Terminal className="h-3 w-3 mr-1" />SHELL OBTAINED
          </Badge>
        ) : evidence.success ? (
          <Badge className="bg-orange-600/80 text-white border-orange-500 text-[10px] font-bold">
            <Skull className="h-3 w-3 mr-1" />EXPLOIT SUCCESS
          </Badge>
        ) : (
          <Badge variant="outline" className="text-[10px] text-zinc-400 border-zinc-500/30">
            EXPLOIT ATTEMPTED
          </Badge>
        )}
        <span className="text-xs font-semibold text-foreground">{evidence.exploitName}</span>
        <Badge variant="outline" className="text-[9px]">{evidence.exploitType}</Badge>
        {evidence.shellType && (
          <Badge variant="outline" className="text-[9px] text-red-400 border-red-500/30">
            {evidence.shellType}
          </Badge>
        )}
      </div>

      {/* Payload */}
      {evidence.payload && (
        <CollapsibleOutput label="Exploit Payload" content={evidence.payload} />
      )}

      {/* Execution Output */}
      {evidence.executionOutput && (
        <CollapsibleOutput label="Execution Output" content={evidence.executionOutput} />
      )}

      {/* Shell Session */}
      {evidence.shellSession && evidence.shellSession.length > 0 && (
        <div className="space-y-1">
          <span className="text-[10px] font-medium text-red-400 flex items-center gap-1">
            <Terminal className="h-3 w-3" />Shell Session Transcript
          </span>
          <div className="p-2.5 rounded bg-black/60 border border-red-500/20 max-h-[250px] overflow-y-auto">
            {evidence.shellSession.map((line, i) => (
              <div key={i} className="text-[10px] font-mono leading-relaxed">
                {line.startsWith('$') || line.startsWith('#') || line.startsWith('root@') || line.startsWith('www-data@') ? (
                  <span className="text-green-400">{line}</span>
                ) : (
                  <span className="text-gray-300">{line}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {evidence.timestamp && (
        <span className="text-[9px] text-muted-foreground flex items-center gap-0.5">
          <Clock className="h-2.5 w-2.5" />Executed: {evidence.timestamp}
        </span>
      )}
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
  // NVD CVE lookup for description + CWE enrichment
  const [cveId] = useState(() => vuln?.cve || "");
  const nvdLookup = trpc.complianceExports.lookupCve.useQuery(
    { cveId: cveId },
    { enabled: !!vuln?.cve && /^CVE-\d{4}-\d{4,}$/i.test(vuln.cve || ""), staleTime: 24 * 60 * 60 * 1000, retry: 1 }
  );

  if (!vuln) return null;
  const sev = getSeverityConfig(vuln.severity);
  const ess = vuln.essEnrichment;
  const effectiveCvss = ess?.cvssBase || vuln.cvssScore || 0;
  const effectiveVector = ess?.cvssVector || null;
  const hasEvidenceChain = vuln.evidenceChain && vuln.evidenceChain.length > 0;
  const hasExploitEvidence = !!vuln.exploitEvidence;
  const hasValidation = !!vuln.validationResult;
  const nvdData = nvdLookup.data;
  const nvdCwes = nvdData?.cwes || [];
  const nvdDescription = nvdData?.description;

  // Determine if this is truly confirmed (has evidence)
  const hasAnyEvidence = hasEvidenceChain || hasExploitEvidence || hasValidation || !!vuln.evidenceDetail;
  const effectiveTier = vuln.corroborationTier === 'confirmed' && !hasAnyEvidence
    ? 'probable' // Downgrade if no evidence
    : vuln.corroborationTier;

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-[560px] sm:max-w-[560px] bg-card border-l border-border p-0">
        <SheetHeader className="px-6 pt-6 pb-4 border-b border-border">
          <div className="flex items-start gap-3">
            <div className={`p-2 rounded-lg ${sev.bg} ${sev.border} border`}>
              <Bug className={`h-5 w-5 ${sev.color}`} />
            </div>
            <div className="flex-1 min-w-0">
              <SheetTitle className="text-base font-semibold text-foreground leading-tight break-words">
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
                    <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`} target="_blank" rel="noopener noreferrer"
                      className="text-muted-foreground hover:text-foreground">
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

            {/* CVE Description & CWE Classification (from NVD) */}
            {vuln.cve && (
              <>
                {nvdLookup.isLoading && (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <div className="h-3 w-3 border-2 border-muted-foreground/30 border-t-cyan-400 rounded-full animate-spin" />
                    Loading CVE details from NVD...
                  </div>
                )}
                {nvdDescription && (
                  <Section title="CVE Description" icon={<BookOpen className="h-3.5 w-3.5" />}>
                    <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                      <p className="text-xs text-foreground leading-relaxed">{nvdDescription}</p>
                      {nvdData?.publishedDate && (
                        <p className="text-[10px] text-muted-foreground mt-2 flex items-center gap-1">
                          <Clock className="h-2.5 w-2.5" />
                          Published: {new Date(nvdData.publishedDate).toLocaleDateString()}
                          {nvdData.lastModifiedDate && ` \u2022 Modified: ${new Date(nvdData.lastModifiedDate).toLocaleDateString()}`}
                        </p>
                      )}
                    </div>
                  </Section>
                )}
                {nvdCwes.length > 0 && (
                  <Section title={`CWE Classification (${nvdCwes.length})`} icon={<Shield className="h-3.5 w-3.5" />}>
                    <div className="space-y-2">
                      {nvdCwes.map((cweId) => (
                        <div key={cweId} className="p-2.5 rounded-lg bg-muted/20 border border-border/30">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-[10px] font-mono text-amber-400 border-amber-500/30 bg-amber-500/10">
                              {cweId}
                            </Badge>
                            <a
                              href={`https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-muted-foreground hover:text-foreground"
                            >
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          </div>
                          <p className="text-[11px] text-foreground/80 mt-1 leading-relaxed">
                            {getCweName(cweId)}
                          </p>
                        </div>
                      ))}
                    </div>
                  </Section>
                )}
              </>
            )}

            {/* Corroboration & Confidence */}
            <Section title="Confidence Assessment" icon={<Fingerprint className="h-3.5 w-3.5" />}>
              <div className="p-3 rounded-lg bg-muted/20 border border-border/30 space-y-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant="outline" className={`text-[10px] font-bold ${
                    effectiveTier === 'confirmed' ? 'bg-green-500/20 text-green-300 border-green-500/40' :
                    effectiveTier === 'probable' ? 'bg-blue-500/20 text-blue-300 border-blue-500/40' :
                    'bg-zinc-500/20 text-zinc-400 border-zinc-500/40'
                  }`}>
                    {effectiveTier === 'confirmed' ? '\u2713 CONFIRMED' :
                     effectiveTier === 'probable' ? '\u223c PROBABLE' : '? POTENTIAL'}
                  </Badge>
                  {vuln.versionMatchConfirmed && (
                    <Badge variant="outline" className="text-[10px] bg-emerald-500/20 text-emerald-300 border-emerald-500/40">
                      VERSION MATCH
                    </Badge>
                  )}
                  {hasExploitEvidence && vuln.exploitEvidence?.success && (
                    <Badge variant="outline" className="text-[10px] bg-red-500/20 text-red-300 border-red-500/40">
                      EXPLOITED
                    </Badge>
                  )}
                  {hasValidation && vuln.validationResult?.validated && (
                    <Badge variant="outline" className="text-[10px] bg-green-500/20 text-green-300 border-green-500/40">
                      VALIDATED
                    </Badge>
                  )}
                  {!hasAnyEvidence && (
                    <Badge variant="outline" className="text-[10px] bg-amber-500/20 text-amber-300 border-amber-500/40">
                      NO EVIDENCE
                    </Badge>
                  )}
                </div>
                {vuln.corroborationTier === 'confirmed' && !hasAnyEvidence && (
                  <p className="text-[10px] text-amber-400 leading-relaxed">
                    This finding was marked as confirmed but has no supporting evidence. 
                    It has been downgraded to probable until evidence is collected through active validation or exploitation.
                  </p>
                )}
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

            {/* ── EVIDENCE CHAIN ── */}
            {hasEvidenceChain && (
              <>
                <Separator />
                <Section title={`Evidence Chain (${vuln.evidenceChain!.length} steps)`} icon={<Layers className="h-3.5 w-3.5" />}>
                  <div className="space-y-3">
                    {vuln.evidenceChain!.map((step, i) => (
                      <EvidenceStepCard key={i} step={step} index={i} />
                    ))}
                  </div>
                </Section>
              </>
            )}

            {/* ── VALIDATION RESULT ── */}
            {hasValidation && (
              <>
                <Separator />
                <Section title="Active Validation" icon={<ShieldCheck className="h-3.5 w-3.5" />}>
                  <div className={`p-3 rounded-lg border space-y-2 ${
                    vuln.validationResult!.validated
                      ? 'bg-green-500/5 border-green-500/30'
                      : 'bg-zinc-500/5 border-zinc-500/30'
                  }`}>
                    <div className="flex items-center gap-2">
                      {vuln.validationResult!.validated ? (
                        <Badge className="bg-green-600/80 text-white border-green-500 text-[10px] font-bold">
                          <ShieldCheck className="h-3 w-3 mr-1" />VALIDATED
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-[10px] text-zinc-400">NOT VALIDATED</Badge>
                      )}
                      <Badge variant="outline" className="text-[9px]">{vuln.validationResult!.method}</Badge>
                      {vuln.validationResult!.timestamp && (
                        <span className="text-[9px] text-muted-foreground flex items-center gap-0.5 ml-auto">
                          <Clock className="h-2.5 w-2.5" />{vuln.validationResult!.timestamp}
                        </span>
                      )}
                    </div>
                    <CollapsibleOutput label="Validation Proof" content={vuln.validationResult!.proof} />
                  </div>
                </Section>
              </>
            )}

            {/* ── EXPLOIT EVIDENCE ── */}
            {hasExploitEvidence && (
              <>
                <Separator />
                <Section title="Exploit Evidence" icon={<Skull className="h-3.5 w-3.5" />}>
                  <ExploitEvidencePanel evidence={vuln.exploitEvidence!} />
                </Section>
              </>
            )}

            {/* ── Legacy Evidence Detail (text) ── */}
            {vuln.evidenceDetail && !hasEvidenceChain && (
              <Section title="Evidence" icon={<FileWarning className="h-3.5 w-3.5" />}>
                <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                  <p className="text-xs text-foreground leading-relaxed whitespace-pre-wrap break-words">{vuln.evidenceDetail}</p>
                </div>
              </Section>
            )}

            {/* ESS Exploit Intelligence */}
            {ess && (
              <>
                <Separator />
                <Section title="Exploit Intelligence (ESS)" icon={<Skull className="h-3.5 w-3.5" />}>
                  <div className="space-y-3">
                    {ess.riskSummary && (
                      <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                        <p className="text-xs text-foreground leading-relaxed">{ess.riskSummary}</p>
                      </div>
                    )}
                    <div className="grid grid-cols-2 gap-2">
                      <div className={`p-2.5 rounded-lg border ${ess.cessScore >= 0.7 ? 'bg-red-500/10 border-red-500/30' : ess.cessScore >= 0.4 ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-green-500/10 border-green-500/30'}`}>
                        <div className="text-[10px] text-muted-foreground uppercase tracking-wider">CESS Exploit Prob.</div>
                        <div className={`text-lg font-bold font-mono ${ess.cessScore >= 0.7 ? 'text-red-400' : ess.cessScore >= 0.4 ? 'text-yellow-400' : 'text-green-400'}`}>
                          {(ess.cessScore * 100).toFixed(0)}%
                        </div>
                      </div>
                      <div className={`p-2.5 rounded-lg border ${ess.epssScore >= 0.5 ? 'bg-red-500/10 border-red-500/30' : ess.epssScore >= 0.1 ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-green-500/10 border-green-500/30'}`}>
                        <div className="text-[10px] text-muted-foreground uppercase tracking-wider">EPSS Score</div>
                        <div className={`text-lg font-bold font-mono ${ess.epssScore >= 0.5 ? 'text-red-400' : ess.epssScore >= 0.1 ? 'text-yellow-400' : 'text-green-400'}`}>
                          {(ess.epssScore * 100).toFixed(1)}%
                        </div>
                      </div>
                    </div>
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

            {/* Why This Severity Rating */}
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
                    {effectiveTier && (
                      <p>
                        Confidence: <strong>{effectiveTier === 'confirmed' ? 'Confirmed' : effectiveTier === 'probable' ? 'Probable' : 'Potential'}</strong>
                        {vuln.detectedVersion && ` — detected version ${vuln.detectedVersion}`}
                        {vuln.affectedVersions && ` falls within affected range ${vuln.affectedVersions}`}
                        {vuln.versionMatchConfirmed && " (version match confirmed)"}.
                        {hasExploitEvidence && vuln.exploitEvidence?.success && " This vulnerability has been successfully exploited."}
                        {hasValidation && vuln.validationResult?.validated && " Active validation has confirmed exploitability."}
                      </p>
                    )}
                  </>
                ) : (
                  <p>
                    This finding is rated <strong className={sev.color}>{sev.label}</strong> based on
                    the tool's assessment. {effectiveTier === 'confirmed'
                      ? "It has been confirmed by active scanning with supporting evidence."
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
              <SheetTitle className="text-base font-semibold text-foreground leading-tight break-words">
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
                  <pre className="text-xs text-foreground whitespace-pre-wrap font-mono break-words">{finding.evidence}</pre>
                </div>
              </Section>
            )}

            {/* Description */}
            {finding.description && (
              <Section title="Description" icon={<Info className="h-3.5 w-3.5" />}>
                <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                  <p className="text-xs text-foreground leading-relaxed break-words">{finding.description}</p>
                </div>
              </Section>
            )}

            {/* Solution */}
            {finding.solution && (
              <Section title="Remediation" icon={<Shield className="h-3.5 w-3.5" />}>
                <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                  <p className="text-xs text-foreground leading-relaxed break-words">{finding.solution}</p>
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
                    className="flex items-center gap-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
                    <ExternalLink className="h-3 w-3 flex-none" /><span className="truncate">{ref.trim()}</span>
                  </a>
                ))}
              </div>
            </Section>

            {/* Other Info */}
            {finding.otherInfo && (
              <Section title="Additional Information" icon={<TrendingUp className="h-3.5 w-3.5" />}>
                <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                  <p className="text-xs text-foreground leading-relaxed whitespace-pre-wrap break-words">{finding.otherInfo}</p>
                </div>
              </Section>
            )}
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}
