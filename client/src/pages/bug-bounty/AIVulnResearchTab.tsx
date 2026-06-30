/**
 * AI Vulnerability Research Tab
 * LLM-powered code auditing, 0-day discovery, and PoC generation.
 * Integrated into the Bug Bounty Hub as a new tab.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import {
  Brain, Crosshair, Shield, Code2, FileCode, GitBranch, Play, Loader2,
  AlertTriangle, Bug, CheckCircle2, XCircle, ChevronDown, ChevronRight,
  Copy, ExternalLink, Trash2, ShieldCheck, Upload, Zap, Target, Eye,
  ArrowRight, BarChart3, Clock, Cpu,
} from "lucide-react";

// ─── Severity colors ────────────────────────────────────────────────────────

const severityConfig: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30" },
  high: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  low: { color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30" },
  informational: { color: "text-zinc-400", bg: "bg-zinc-500/10", border: "border-zinc-500/30" },
};

const exploitabilityConfig: Record<string, { label: string; color: string }> = {
  trivial: { label: "Trivial", color: "text-red-400" },
  easy: { label: "Easy", color: "text-orange-400" },
  moderate: { label: "Moderate", color: "text-yellow-400" },
  difficult: { label: "Difficult", color: "text-blue-400" },
  theoretical: { label: "Theoretical", color: "text-zinc-400" },
};

// ─── New Research Dialog ────────────────────────────────────────────────────

function NewResearchDialog({
  open,
  onOpenChange,
  bugBountyPrograms,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  bugBountyPrograms?: Array<{ id: number; name: string; handle: string }>;
}) {
  const { toast } = useToast();
  const utils = trpc.useUtils();

  const [form, setForm] = useState({
    title: "",
    description: "",
    targetType: "source_code" as "source_code" | "github_repo" | "binary" | "config" | "protocol" | "firmware" | "custom",
    targetName: "",
    targetVersion: "",
    githubUrl: "",
    githubPath: "",
    language: "",
    researchPrompt: "Find all security vulnerabilities in this code. Focus on RCE, injection, authentication bypass, and memory corruption bugs. Generate working proof-of-concept exploits for each finding.",
    sourceCode: "",
    bugBountyProgramId: undefined as number | undefined,
    maxGithubFiles: 20,
  });

  const startResearch = trpc.aiVulnResearch.startResearch.useMutation({
    onSuccess: (data) => {
      toast({
        title: "Analysis Complete",
        description: `Found ${data.totalFindings} vulnerabilities (${data.criticalCount} critical, ${data.highCount} high) in ${(data.analysisTimeMs / 1000).toFixed(1)}s`,
      });
      utils.aiVulnResearch.listSessions.invalidate();
      utils.aiVulnResearch.stats.invalidate();
      onOpenChange(false);
      resetForm();
    },
    onError: (err) => {
      toast({ title: "Analysis Failed", description: err.message, variant: "destructive" });
    },
  });

  const fetchGithubTree = trpc.aiVulnResearch.fetchGithubTree.useQuery(
    { repoUrl: form.githubUrl, path: form.githubPath || undefined },
    { enabled: form.targetType === "github_repo" && form.githubUrl.includes("github.com/") },
  );

  function resetForm() {
    setForm({
      title: "", description: "", targetType: "source_code", targetName: "",
      targetVersion: "", githubUrl: "", githubPath: "", language: "",
      researchPrompt: "Find all security vulnerabilities in this code. Focus on RCE, injection, authentication bypass, and memory corruption bugs. Generate working proof-of-concept exploits for each finding.",
      sourceCode: "", bugBountyProgramId: undefined, maxGithubFiles: 20,
    });
  }

  function handleSubmit() {
    if (!form.title || !form.targetName || !form.researchPrompt) {
      toast({ title: "Missing fields", description: "Title, target name, and research prompt are required", variant: "destructive" });
      return;
    }
    if (form.targetType === "github_repo" && !form.githubUrl) {
      toast({ title: "Missing GitHub URL", description: "Provide a GitHub repository URL", variant: "destructive" });
      return;
    }
    if (form.targetType === "source_code" && !form.sourceCode) {
      toast({ title: "Missing source code", description: "Paste the source code to analyze", variant: "destructive" });
      return;
    }
    startResearch.mutate({
      title: form.title,
      description: form.description || undefined,
      targetType: form.targetType,
      targetName: form.targetName,
      targetVersion: form.targetVersion || undefined,
      githubUrl: form.githubUrl || undefined,
      githubPath: form.githubPath || undefined,
      language: form.language || undefined,
      researchPrompt: form.researchPrompt,
      sourceCode: form.sourceCode || undefined,
      bugBountyProgramId: form.bugBountyProgramId,
      maxGithubFiles: form.maxGithubFiles,
    });
  }

  const promptPresets = [
    { label: "General Vuln Hunt", prompt: "Find all security vulnerabilities in this code. Focus on RCE, injection, authentication bypass, and memory corruption bugs. Generate working proof-of-concept exploits for each finding." },
    { label: "0-Day RCE Focus", prompt: "Somebody told me there is an RCE 0-day when you open a file. Find it. Analyze every code path that handles external input, file parsing, or command execution. Generate a complete working exploit." },
    { label: "Memory Corruption", prompt: "Analyze this code for memory corruption vulnerabilities: buffer overflows, use-after-free, double-free, integer overflow/underflow, format string bugs, and heap corruption. Focus on exploitable conditions." },
    { label: "Web App Security", prompt: "Audit this web application code for OWASP Top 10 vulnerabilities: injection, broken auth, XSS, IDOR, security misconfiguration, SSRF, and deserialization flaws. Generate PoC for each finding." },
    { label: "Auth Bypass", prompt: "Focus exclusively on authentication and authorization vulnerabilities. Look for: JWT weaknesses, session fixation, privilege escalation, IDOR, broken access controls, and credential exposure." },
    { label: "Crypto Audit", prompt: "Audit all cryptographic implementations for weaknesses: weak algorithms, improper key management, predictable random values, timing attacks, padding oracle, and protocol-level flaws." },
  ];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-zinc-900 border-zinc-800 max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5 text-purple-400" />
            New AI Vulnerability Research Session
          </DialogTitle>
          <DialogDescription>
            Feed source code to the AI and let it autonomously discover vulnerabilities and generate working exploits.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Title & Description */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Session Title *</Label>
              <Input
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
                placeholder="Vim 9.2 RCE Hunt"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div>
              <Label>Target Name *</Label>
              <Input
                value={form.targetName}
                onChange={(e) => setForm({ ...form, targetName: e.target.value })}
                placeholder="vim, nginx, openssl..."
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <Label>Target Type</Label>
              <Select value={form.targetType} onValueChange={(v: any) => setForm({ ...form, targetType: v })}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="source_code">Source Code</SelectItem>
                  <SelectItem value="github_repo">GitHub Repo</SelectItem>
                  <SelectItem value="config">Configuration</SelectItem>
                  <SelectItem value="protocol">Protocol</SelectItem>
                  <SelectItem value="firmware">Firmware</SelectItem>
                  <SelectItem value="custom">Custom</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Language</Label>
              <Input
                value={form.language}
                onChange={(e) => setForm({ ...form, language: e.target.value })}
                placeholder="C, Python, Go..."
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div>
              <Label>Version</Label>
              <Input
                value={form.targetVersion}
                onChange={(e) => setForm({ ...form, targetVersion: e.target.value })}
                placeholder="9.2, 1.25.3..."
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
          </div>

          {/* Bug Bounty Program Link */}
          {bugBountyPrograms && bugBountyPrograms.length > 0 && (
            <div>
              <Label>Link to Bug Bounty Program (optional)</Label>
              <Select
                value={form.bugBountyProgramId ? String(form.bugBountyProgramId) : "none"}
                onValueChange={(v) => setForm({ ...form, bugBountyProgramId: v === "none" ? undefined : Number(v) })}
              >
                <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No program</SelectItem>
                  {bugBountyPrograms.map((p) => (
                    <SelectItem key={p.id} value={String(p.id)}>{p.name} ({p.handle})</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {/* GitHub URL (conditional) */}
          {form.targetType === "github_repo" && (
            <div className="space-y-3">
              <div>
                <Label>GitHub Repository URL *</Label>
                <Input
                  value={form.githubUrl}
                  onChange={(e) => setForm({ ...form, githubUrl: e.target.value })}
                  placeholder="https://github.com/vim/vim"
                  className="bg-zinc-800 border-zinc-700 mt-1"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Path Filter (optional)</Label>
                  <Input
                    value={form.githubPath}
                    onChange={(e) => setForm({ ...form, githubPath: e.target.value })}
                    placeholder="src/eval.c, lib/"
                    className="bg-zinc-800 border-zinc-700 mt-1"
                  />
                </div>
                <div>
                  <Label>Max Files to Analyze</Label>
                  <Input
                    type="number"
                    value={form.maxGithubFiles}
                    onChange={(e) => setForm({ ...form, maxGithubFiles: Number(e.target.value) || 20 })}
                    min={1}
                    max={50}
                    className="bg-zinc-800 border-zinc-700 mt-1"
                  />
                </div>
              </div>
              {fetchGithubTree.data && (
                <div className="p-3 bg-zinc-800/50 rounded-lg border border-zinc-700/50">
                  <p className="text-xs text-muted-foreground mb-1">
                    Repository contains <span className="text-emerald-400 font-medium">{fetchGithubTree.data.totalFiles}</span> source files
                    across <span className="text-blue-400 font-medium">{fetchGithubTree.data.dirs.length}</span> directories
                  </p>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {[...new Set(fetchGithubTree.data.files.map((f) => f.language))].slice(0, 10).map((lang) => (
                      <Badge key={lang} variant="outline" className="text-xs border-zinc-600">{lang}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Source Code Input (conditional) */}
          {form.targetType !== "github_repo" && (
            <div>
              <Label>Source Code *</Label>
              <Textarea
                value={form.sourceCode}
                onChange={(e) => setForm({ ...form, sourceCode: e.target.value })}
                placeholder="Paste the source code to analyze here..."
                className="bg-zinc-800 border-zinc-700 mt-1 font-mono text-xs min-h-[200px]"
                rows={12}
              />
              <p className="text-xs text-muted-foreground mt-1">
                {form.sourceCode.split("\n").length} lines, {form.sourceCode.length.toLocaleString()} chars
              </p>
            </div>
          )}

          {/* Research Prompt */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <Label>Research Prompt *</Label>
              <div className="flex gap-1 flex-wrap">
                {promptPresets.map((preset) => (
                  <Button
                    key={preset.label}
                    variant="outline"
                    size="sm"
                    className="text-[10px] h-6 px-2 border-zinc-700 hover:border-purple-500/50 hover:text-purple-400"
                    onClick={() => setForm({ ...form, researchPrompt: preset.prompt })}
                  >
                    {preset.label}
                  </Button>
                ))}
              </div>
            </div>
            <Textarea
              value={form.researchPrompt}
              onChange={(e) => setForm({ ...form, researchPrompt: e.target.value })}
              className="bg-zinc-800 border-zinc-700 mt-1 text-sm min-h-[80px]"
              rows={3}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} className="border-zinc-700">Cancel</Button>
          <Button
            onClick={handleSubmit}
            disabled={startResearch.isPending}
            className="bg-purple-600 hover:bg-purple-700"
          >
            {startResearch.isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Analyzing... (this may take 30-60s)
              </>
            ) : (
              <>
                <Brain className="h-4 w-4 mr-2" />
                Start AI Analysis
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Finding Detail View ────────────────────────────────────────────────────

function FindingDetail({ finding, onClose }: { finding: any; onClose: () => void }) {
  const { toast } = useToast();
  const utils = trpc.useUtils();
  const [showPoc, setShowPoc] = useState(false);

  const generatePoc = trpc.aiVulnResearch.generatePoc.useMutation({
    onSuccess: () => {
      toast({ title: "PoC Generated", description: "Proof-of-concept exploit has been generated" });
      utils.aiVulnResearch.getSession.invalidate();
    },
    onError: (err) => {
      toast({ title: "PoC Generation Failed", description: err.message, variant: "destructive" });
    },
  });

  const exportToBB = trpc.aiVulnResearch.exportToBugBounty.useMutation({
    onSuccess: () => {
      toast({ title: "Exported", description: "Finding exported to Bug Bounty Hub findings" });
      utils.aiVulnResearch.getSession.invalidate();
      utils.aiVulnResearch.stats.invalidate();
    },
    onError: (err) => {
      toast({ title: "Export Failed", description: err.message, variant: "destructive" });
    },
  });

  const toggleVerified = trpc.aiVulnResearch.toggleVerified.useMutation({
    onSuccess: () => {
      utils.aiVulnResearch.getSession.invalidate();
    },
  });

  const sev = severityConfig[finding.severity] || severityConfig.informational;
  const exploit = exploitabilityConfig[finding.exploitability] || { label: "Unknown", color: "text-zinc-400" };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <Badge className={`${sev.bg} ${sev.color} ${sev.border} border`}>
              {finding.severity.toUpperCase()}
            </Badge>
            {finding.cvssScore && (
              <Badge variant="outline" className="border-zinc-600 font-mono text-xs">
                CVSS {finding.cvssScore.toFixed(1)}
              </Badge>
            )}
            {finding.cweId && (
              <Badge variant="outline" className="border-zinc-600 text-xs">{finding.cweId}</Badge>
            )}
            {finding.verified === 1 && (
              <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 border">
                <CheckCircle2 className="h-3 w-3 mr-1" /> Verified
              </Badge>
            )}
          </div>
          <h3 className="text-lg font-semibold">{finding.title}</h3>
          <p className="text-sm text-muted-foreground">{finding.vulnType}</p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            className="border-zinc-700"
            onClick={() => toggleVerified.mutate({ findingId: finding.id })}
          >
            {finding.verified === 1 ? <XCircle className="h-4 w-4 mr-1" /> : <CheckCircle2 className="h-4 w-4 mr-1" />}
            {finding.verified === 1 ? "Unverify" : "Verify"}
          </Button>
          {!finding.exportedToBugBounty && (
            <Button
              variant="outline"
              size="sm"
              className="border-zinc-700 hover:border-emerald-500/50 hover:text-emerald-400"
              onClick={() => exportToBB.mutate({ findingId: finding.id })}
              disabled={exportToBB.isPending}
            >
              <Upload className="h-4 w-4 mr-1" />
              {exportToBB.isPending ? "Exporting..." : "Export to BB"}
            </Button>
          )}
          {finding.exportedToBugBounty === 1 && (
            <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 border">
              Exported
            </Badge>
          )}
        </div>
      </div>

      {/* Details Grid */}
      <div className="grid grid-cols-2 gap-4">
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-4 space-y-2">
            <h4 className="text-sm font-medium text-muted-foreground">Description</h4>
            <p className="text-sm whitespace-pre-wrap">{finding.description}</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-4 space-y-3">
            <div>
              <h4 className="text-sm font-medium text-muted-foreground">Exploitability</h4>
              <p className={`text-sm font-medium ${exploit.color}`}>{exploit.label}</p>
            </div>
            <div>
              <h4 className="text-sm font-medium text-muted-foreground">Attack Vector</h4>
              <p className="text-sm">{finding.attackVector || "N/A"}</p>
            </div>
            {finding.filePath && (
              <div>
                <h4 className="text-sm font-medium text-muted-foreground">Location</h4>
                <p className="text-sm font-mono text-blue-400">
                  {finding.filePath}
                  {finding.lineStart && `:${finding.lineStart}`}
                  {finding.lineEnd && `-${finding.lineEnd}`}
                </p>
              </div>
            )}
            <div>
              <h4 className="text-sm font-medium text-muted-foreground">Confidence</h4>
              <p className="text-sm">{finding.confidenceScore ? `${(finding.confidenceScore * 100).toFixed(0)}%` : "N/A"}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Root Cause & Impact */}
      {(finding.rootCause || finding.impact) && (
        <div className="grid grid-cols-2 gap-4">
          {finding.rootCause && (
            <Card className="bg-zinc-800/50 border-zinc-700/50">
              <CardContent className="p-4">
                <h4 className="text-sm font-medium text-muted-foreground mb-2">Root Cause</h4>
                <p className="text-sm whitespace-pre-wrap">{finding.rootCause}</p>
              </CardContent>
            </Card>
          )}
          {finding.impact && (
            <Card className="bg-zinc-800/50 border-zinc-700/50">
              <CardContent className="p-4">
                <h4 className="text-sm font-medium text-muted-foreground mb-2">Impact</h4>
                <p className="text-sm whitespace-pre-wrap">{finding.impact}</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Affected Code */}
      {finding.affectedCode && (
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-sm font-medium text-muted-foreground">Affected Code</h4>
              <Button
                variant="ghost"
                size="sm"
                className="h-7"
                onClick={() => { navigator.clipboard.writeText(finding.affectedCode); toast({ title: "Copied" }); }}
              >
                <Copy className="h-3 w-3 mr-1" /> Copy
              </Button>
            </div>
            <pre className="bg-zinc-900 p-3 rounded-lg text-xs font-mono overflow-x-auto border border-zinc-700/50 max-h-[300px] overflow-y-auto">
              <code>{finding.affectedCode}</code>
            </pre>
          </CardContent>
        </Card>
      )}

      {/* PoC Section */}
      <Card className="bg-zinc-800/50 border-zinc-700/50">
        <CardContent className="p-4">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-medium flex items-center gap-2">
              <Zap className="h-4 w-4 text-amber-400" />
              Proof-of-Concept Exploit
            </h4>
            <div className="flex gap-2">
              {finding.pocCode && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7"
                  onClick={() => setShowPoc(!showPoc)}
                >
                  <Eye className="h-3 w-3 mr-1" /> {showPoc ? "Hide" : "Show"}
                </Button>
              )}
              {(!finding.pocCode || finding.pocStatus === "not_generated" || finding.pocStatus === "failed") && (
                <Button
                  variant="outline"
                  size="sm"
                  className="border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
                  onClick={() => generatePoc.mutate({ findingId: finding.id })}
                  disabled={generatePoc.isPending}
                >
                  {generatePoc.isPending ? (
                    <><Loader2 className="h-3 w-3 mr-1 animate-spin" /> Generating...</>
                  ) : (
                    <><Zap className="h-3 w-3 mr-1" /> Generate PoC</>
                  )}
                </Button>
              )}
            </div>
          </div>
          {finding.pocCode && showPoc && (
            <div className="relative">
              <Button
                variant="ghost"
                size="sm"
                className="absolute top-2 right-2 h-7 z-10"
                onClick={() => { navigator.clipboard.writeText(finding.pocCode); toast({ title: "PoC copied to clipboard" }); }}
              >
                <Copy className="h-3 w-3" />
              </Button>
              <pre className="bg-zinc-900 p-3 rounded-lg text-xs font-mono overflow-x-auto border border-amber-500/20 max-h-[400px] overflow-y-auto">
                <code>{finding.pocCode}</code>
              </pre>
              {finding.pocLanguage && (
                <Badge variant="outline" className="mt-2 text-xs border-zinc-600">{finding.pocLanguage}</Badge>
              )}
            </div>
          )}
          {!finding.pocCode && finding.pocStatus !== "generating" && (
            <p className="text-xs text-muted-foreground">No PoC generated yet. Click "Generate PoC" to create a working exploit.</p>
          )}
        </CardContent>
      </Card>

      {/* Remediation */}
      {finding.remediation && (
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-4">
            <h4 className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-emerald-400" /> Remediation
            </h4>
            <p className="text-sm whitespace-pre-wrap">{finding.remediation}</p>
          </CardContent>
        </Card>
      )}

      {/* LLM Reasoning */}
      {finding.llmReasoning && (
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-4">
            <h4 className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
              <Brain className="h-4 w-4 text-purple-400" /> AI Reasoning
            </h4>
            <p className="text-sm whitespace-pre-wrap text-muted-foreground">{finding.llmReasoning}</p>
          </CardContent>
        </Card>
      )}

      {/* MITRE ATT&CK */}
      {finding.mitreTechniques && Array.isArray(finding.mitreTechniques) && finding.mitreTechniques.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-muted-foreground">MITRE ATT&CK:</span>
          {finding.mitreTechniques.map((t: string) => (
            <Badge key={t} variant="outline" className="text-xs border-zinc-600 font-mono">{t}</Badge>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Session Detail View ────────────────────────────────────────────────────

function SessionDetail({ sessionId, onBack }: { sessionId: number; onBack: () => void }) {
  const { toast } = useToast();
  const [selectedFinding, setSelectedFinding] = useState<any>(null);

  const { data, isLoading } = trpc.aiVulnResearch.getSession.useQuery(
    { sessionId },
    { staleTime: 30000 },
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-purple-400" />
        <span className="ml-2 text-muted-foreground">Loading session...</span>
      </div>
    );
  }

  if (!data) return <p className="text-muted-foreground text-center py-8">Session not found</p>;

  const { session, findings, snippets } = data;
  const metadata = session.metadata as any;

  if (selectedFinding) {
    return (
      <div>
        <Button variant="ghost" size="sm" onClick={() => setSelectedFinding(null)} className="mb-4">
          <ChevronRight className="h-4 w-4 mr-1 rotate-180" /> Back to Findings
        </Button>
        <FindingDetail finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Back button + Session header */}
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" onClick={onBack}>
          <ChevronRight className="h-4 w-4 mr-1 rotate-180" /> Back to Sessions
        </Button>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className={`border-zinc-600 ${session.status === "completed" ? "text-emerald-400" : session.status === "analyzing" ? "text-amber-400" : session.status === "failed" ? "text-red-400" : "text-zinc-400"}`}>
            {session.status}
          </Badge>
        </div>
      </div>

      <div>
        <h2 className="text-xl font-bold">{session.title}</h2>
        <p className="text-sm text-muted-foreground mt-1">
          {session.targetName}{session.targetVersion ? ` v${session.targetVersion}` : ""} — {session.targetType.replace("_", " ")}
          {session.language ? ` (${session.language})` : ""}
        </p>
        {session.description && <p className="text-sm mt-2">{session.description}</p>}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-6 gap-3">
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold">{session.totalFindings}</p>
            <p className="text-xs text-muted-foreground">Total</p>
          </CardContent>
        </Card>
        <Card className="bg-red-500/5 border-red-500/20">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-red-400">{session.criticalCount}</p>
            <p className="text-xs text-red-400/70">Critical</p>
          </CardContent>
        </Card>
        <Card className="bg-orange-500/5 border-orange-500/20">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-orange-400">{session.highCount}</p>
            <p className="text-xs text-orange-400/70">High</p>
          </CardContent>
        </Card>
        <Card className="bg-yellow-500/5 border-yellow-500/20">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-yellow-400">{session.mediumCount}</p>
            <p className="text-xs text-yellow-400/70">Medium</p>
          </CardContent>
        </Card>
        <Card className="bg-blue-500/5 border-blue-500/20">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-blue-400">{session.lowCount}</p>
            <p className="text-xs text-blue-400/70">Low</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-purple-400">{session.tokensUsed?.toLocaleString() || 0}</p>
            <p className="text-xs text-muted-foreground">Tokens</p>
          </CardContent>
        </Card>
      </div>

      {/* Metadata */}
      {metadata && (
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          {metadata.filesAnalyzed && <span><FileCode className="h-3 w-3 inline mr-1" />{metadata.filesAnalyzed} files analyzed</span>}
          {metadata.totalLines && <span><Code2 className="h-3 w-3 inline mr-1" />{metadata.totalLines.toLocaleString()} lines</span>}
          {session.analysisTimeMs && <span><Clock className="h-3 w-3 inline mr-1" />{(session.analysisTimeMs / 1000).toFixed(1)}s</span>}
          {session.llmModel && <span><Cpu className="h-3 w-3 inline mr-1" />{session.llmModel}</span>}
        </div>
      )}

      {/* Summary */}
      {metadata?.summary && (
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-4">
            <h4 className="text-sm font-medium text-muted-foreground mb-2">Analysis Summary</h4>
            <p className="text-sm whitespace-pre-wrap">{metadata.summary}</p>
          </CardContent>
        </Card>
      )}

      {/* Findings List */}
      <div>
        <h3 className="text-sm font-medium mb-3">Findings ({findings.length})</h3>
        <div className="space-y-2">
          {findings.map((f: any) => {
            const sev = severityConfig[f.severity] || severityConfig.informational;
            return (
              <div
                key={f.id}
                className={`p-3 rounded-lg border cursor-pointer hover:bg-zinc-800/80 transition-colors ${sev.border} ${sev.bg}`}
                onClick={() => setSelectedFinding(f)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 flex-1 min-w-0">
                    <Badge className={`${sev.bg} ${sev.color} ${sev.border} border text-[10px] shrink-0`}>
                      {f.severity.toUpperCase()}
                    </Badge>
                    <span className="text-sm font-medium truncate">{f.title}</span>
                  </div>
                  <div className="flex items-center gap-2 ml-3 shrink-0">
                    {f.cvssScore && (
                      <span className="text-xs font-mono text-muted-foreground">CVSS {f.cvssScore.toFixed(1)}</span>
                    )}
                    {f.cweId && (
                      <Badge variant="outline" className="text-[10px] border-zinc-600">{f.cweId}</Badge>
                    )}
                    {f.pocStatus === "generated" && (
                      <Zap className="h-3 w-3 text-amber-400" title="PoC available" />
                    )}
                    {f.verified === 1 && (
                      <CheckCircle2 className="h-3 w-3 text-emerald-400" title="Verified" />
                    )}
                    {f.exportedToBugBounty === 1 && (
                      <Upload className="h-3 w-3 text-blue-400" title="Exported to Bug Bounty" />
                    )}
                    <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  </div>
                </div>
                <p className="text-xs text-muted-foreground mt-1 truncate">{f.vulnType} — {f.filePath || "N/A"}</p>
              </div>
            );
          })}
          {findings.length === 0 && (
            <p className="text-sm text-muted-foreground text-center py-6">No findings in this session.</p>
          )}
        </div>
      </div>

      {/* Code Snippets */}
      {snippets.length > 0 && (
        <div>
          <h3 className="text-sm font-medium mb-3">Analyzed Files ({snippets.length})</h3>
          <div className="grid grid-cols-2 gap-2">
            {snippets.map((s: any) => (
              <div key={s.id} className="p-2 bg-zinc-800/50 rounded-lg border border-zinc-700/50 flex items-center gap-2">
                <FileCode className="h-4 w-4 text-blue-400 shrink-0" />
                <span className="text-xs font-mono truncate">{s.filename}</span>
                <Badge variant="outline" className="text-[10px] border-zinc-600 shrink-0">{s.language}</Badge>
                <span className="text-[10px] text-muted-foreground shrink-0">{s.lineCount} lines</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Tab Component ─────────────────────────────────────────────────────

export function AIVulnResearchTab() {
  const { toast } = useToast();
  const utils = trpc.useUtils();
  const [showNewDialog, setShowNewDialog] = useState(false);
  const [selectedSessionId, setSelectedSessionId] = useState<number | null>(null);

  const stats = trpc.aiVulnResearch.stats.useQuery(undefined, { staleTime: 60000 });
  const sessions = trpc.aiVulnResearch.listSessions.useQuery({ limit: 50 }, { staleTime: 30000 });

  const deleteSession = trpc.aiVulnResearch.deleteSession.useMutation({
    onSuccess: () => {
      toast({ title: "Session deleted" });
      utils.aiVulnResearch.listSessions.invalidate();
      utils.aiVulnResearch.stats.invalidate();
    },
  });

  // If viewing a session detail
  if (selectedSessionId) {
    return (
      <SessionDetail
        sessionId={selectedSessionId}
        onBack={() => setSelectedSessionId(null)}
      />
    );
  }

  const s = stats.data;

  return (
    <div className="space-y-4">
      {/* Description */}
      <p className="text-sm text-muted-foreground">
        AI-powered vulnerability research engine. Feed source code or point at a GitHub repository and let the AI autonomously discover security vulnerabilities, generate working proof-of-concept exploits, and export findings to the Bug Bounty pipeline.
      </p>

      {/* Stats Overview */}
      <div className="grid grid-cols-5 gap-3">
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-3 text-center">
            <Brain className="h-5 w-5 mx-auto mb-1 text-purple-400" />
            <p className="text-xl font-bold">{s?.totalSessions ?? 0}</p>
            <p className="text-[10px] text-muted-foreground">Sessions</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-3 text-center">
            <Bug className="h-5 w-5 mx-auto mb-1 text-red-400" />
            <p className="text-xl font-bold">{s?.totalFindings ?? 0}</p>
            <p className="text-[10px] text-muted-foreground">Findings</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-3 text-center">
            <AlertTriangle className="h-5 w-5 mx-auto mb-1 text-red-400" />
            <p className="text-xl font-bold text-red-400">{(s?.criticalFindings ?? 0) + (s?.highFindings ?? 0)}</p>
            <p className="text-[10px] text-muted-foreground">Critical+High</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-3 text-center">
            <Zap className="h-5 w-5 mx-auto mb-1 text-amber-400" />
            <p className="text-xl font-bold text-amber-400">{s?.pocGenerated ?? 0}</p>
            <p className="text-[10px] text-muted-foreground">PoCs Generated</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-800/50 border-zinc-700/50">
          <CardContent className="p-3 text-center">
            <Upload className="h-5 w-5 mx-auto mb-1 text-emerald-400" />
            <p className="text-xl font-bold text-emerald-400">{s?.exportedToBugBounty ?? 0}</p>
            <p className="text-[10px] text-muted-foreground">Exported to BB</p>
          </CardContent>
        </Card>
      </div>

      {/* Action Bar */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">Research Sessions</h3>
        <Button
          onClick={() => setShowNewDialog(true)}
          className="bg-purple-600 hover:bg-purple-700"
          size="sm"
        >
          <Brain className="h-4 w-4 mr-2" />
          New Research Session
        </Button>
      </div>

      {/* Sessions List */}
      <div className="space-y-2">
        {sessions.data?.sessions.map((session: any) => {
          const metadata = session.metadata as any;
          return (
            <div
              key={session.id}
              className="p-4 bg-zinc-800/50 rounded-lg border border-zinc-700/50 hover:border-zinc-600 transition-colors cursor-pointer"
              onClick={() => setSelectedSessionId(session.id)}
            >
              <div className="flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h4 className="text-sm font-medium truncate">{session.title}</h4>
                    <Badge variant="outline" className={`text-[10px] border-zinc-600 ${
                      session.status === "completed" ? "text-emerald-400 border-emerald-500/30" :
                      session.status === "analyzing" ? "text-amber-400 border-amber-500/30" :
                      session.status === "failed" ? "text-red-400 border-red-500/30" :
                      "text-zinc-400"
                    }`}>
                      {session.status === "analyzing" && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                      {session.status}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Target className="h-3 w-3" />
                      {session.targetName}{session.targetVersion ? ` v${session.targetVersion}` : ""}
                    </span>
                    <span>{session.targetType.replace("_", " ")}</span>
                    {session.language && <span className="font-mono">{session.language}</span>}
                    <span>{new Date(session.createdAt).toLocaleString()}</span>
                  </div>
                </div>
                <div className="flex items-center gap-3 ml-4">
                  {session.status === "completed" && (
                    <div className="flex items-center gap-2 text-xs">
                      {session.criticalCount > 0 && <Badge className="bg-red-500/10 text-red-400 border-red-500/30 border text-[10px]">{session.criticalCount} CRIT</Badge>}
                      {session.highCount > 0 && <Badge className="bg-orange-500/10 text-orange-400 border-orange-500/30 border text-[10px]">{session.highCount} HIGH</Badge>}
                      {session.mediumCount > 0 && <Badge className="bg-yellow-500/10 text-yellow-400 border-yellow-500/30 border text-[10px]">{session.mediumCount} MED</Badge>}
                      {session.lowCount > 0 && <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/30 border text-[10px]">{session.lowCount} LOW</Badge>}
                      <span className="text-muted-foreground">{session.totalFindings} total</span>
                    </div>
                  )}
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400"
                    onClick={(e) => {
                      e.stopPropagation();
                      if (confirm("Delete this research session and all its findings?")) {
                        deleteSession.mutate({ sessionId: session.id });
                      }
                    }}
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                </div>
              </div>
            </div>
          );
        })}
        {sessions.isLoading && (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-5 w-5 animate-spin text-purple-400" />
          </div>
        )}
        {!sessions.isLoading && (!sessions.data?.sessions || sessions.data.sessions.length === 0) && (
          <div className="text-center py-12">
            <Brain className="h-12 w-12 mx-auto mb-3 text-purple-400/30" />
            <p className="text-sm text-muted-foreground mb-1">No research sessions yet</p>
            <p className="text-xs text-muted-foreground mb-4">
              Start your first AI vulnerability research session to discover 0-days
            </p>
            <Button onClick={() => setShowNewDialog(true)} className="bg-purple-600 hover:bg-purple-700" size="sm">
              <Brain className="h-4 w-4 mr-2" /> Start First Session
            </Button>
          </div>
        )}
      </div>

      <NewResearchDialog
        open={showNewDialog}
        onOpenChange={setShowNewDialog}
      />
    </div>
  );
}
