import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import {
  Shield, Plus, Search, Eye, EyeOff, AlertTriangle,
  CheckCircle, XCircle, BarChart3, Target, Trash2,
  Clock, ShieldAlert, ShieldCheck, ShieldX, ShieldQuestion,
  Activity, Timer, Zap, FileCode, Copy, Download, Loader2
} from "lucide-react";

const TACTICS = [
  "reconnaissance", "resource-development", "initial-access",
  "execution", "persistence", "privilege-escalation",
  "defense-evasion", "credential-access", "discovery",
  "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact"
];

const DETECTION_METHODS = [
  "SIEM", "EDR", "NDR", "IDS/IPS", "Firewall", "WAF",
  "Honeypot", "Manual Review", "Log Analysis", "Threat Hunting",
  "Email Gateway", "DLP", "UEBA", "SOAR", "Other"
];

const RESPONSE_ACTIONS = [
  "Isolated Host", "Blocked IP", "Contained User", "Escalated to IR",
  "Quarantined File", "Disabled Account", "Network Segmented",
  "Alert Only", "Ignored", "No Action", "Other"
];

const OUTCOME_CONFIG = {
  detected: { label: "Detected", icon: ShieldCheck, color: "text-emerald-400", bg: "bg-emerald-500/20", border: "border-emerald-500/30" },
  blocked: { label: "Blocked", icon: Shield, color: "text-blue-400", bg: "bg-blue-500/20", border: "border-blue-500/30" },
  missed: { label: "Missed", icon: ShieldX, color: "text-red-400", bg: "bg-red-500/20", border: "border-red-500/30" },
  partial: { label: "Partial", icon: ShieldAlert, color: "text-yellow-400", bg: "bg-yellow-500/20", border: "border-yellow-500/30" },
  not_tested: { label: "Not Tested", icon: ShieldQuestion, color: "text-zinc-400", bg: "bg-zinc-500/20", border: "border-zinc-500/30" },
};

function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${Math.round(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}m`;
}

export default function PurpleTeam() {
  const [search, setSearch] = useState("");
  const [tacticFilter, setTacticFilter] = useState("");
  const [gapFilter, setGapFilter] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [activeTab, setActiveTab] = useState<"tests" | "matrix" | "gaps" | "scores">("tests");
  const [outcomeDialogTest, setOutcomeDialogTest] = useState<any>(null);
  const [ruleDialogTest, setRuleDialogTest] = useState<any>(null);
  const [ruleFormat, setRuleFormat] = useState<"sigma" | "splunk_spl" | "kql">("sigma");
  const [generatedRules, setGeneratedRules] = useState<Record<string, string>>({});
  const [showBulkRulesDialog, setShowBulkRulesDialog] = useState(false);
  const [bulkRules, setBulkRules] = useState<any[]>([]);
  const [bulkFormat, setBulkFormat] = useState<"sigma" | "splunk_spl" | "kql">("sigma");

  // Blue team outcome form state
  const [btOutcome, setBtOutcome] = useState<string>("not_tested");
  const [btMethod, setBtMethod] = useState("");
  const [btAction, setBtAction] = useState("");
  const [btTTD, setBtTTD] = useState("");
  const [btTTR, setBtTTR] = useState("");
  const [btNotes, setBtNotes] = useState("");

  // Create form state
  const [newTechniqueId, setNewTechniqueId] = useState("");
  const [newTechniqueName, setNewTechniqueName] = useState("");
  const [newTactic, setNewTactic] = useState("execution");
  const [newDetected, setNewDetected] = useState(false);
  const [newNotes, setNewNotes] = useState("");

  const searchInput = useMemo(() => ({
    search: search || undefined,
    tactic: tacticFilter || undefined,
    isGap: gapFilter === "gaps" ? true : gapFilter === "detected" ? false : undefined,
  }), [search, tacticFilter, gapFilter]);

  const { data: tests, isLoading, refetch } = trpc.purpleTeam.listTests.useQuery(searchInput);
  const { data: stats } = trpc.purpleTeam.stats.useQuery();
  const { data: matrix } = trpc.purpleTeam.coverageMatrix.useQuery(undefined, { enabled: activeTab === "matrix" });
  const { data: scores } = trpc.purpleTeam.listScores.useQuery(undefined, { enabled: activeTab === "scores" });
  const { data: gapSummary } = trpc.purpleTeam.detectionGapSummary.useQuery(undefined, { enabled: activeTab === "gaps" });

  const createMutation = trpc.purpleTeam.createTest.useMutation({
    onSuccess: () => {
      toast.success("Detection test created");
      setShowCreateDialog(false);
      setNewTechniqueId("");
      setNewTechniqueName("");
      setNewNotes("");
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const updateMutation = trpc.purpleTeam.updateTest.useMutation({
    onSuccess: () => {
      toast.success("Test updated");
      refetch();
    },
  });

  const deleteMutation = trpc.purpleTeam.deleteTest.useMutation({
    onSuccess: () => {
      toast.success("Test deleted");
      refetch();
    },
  });

  const generateRuleMutation = trpc.detectionRules.generateForTest.useMutation({
    onSuccess: (data) => {
      setGeneratedRules(data.rules);
      toast.success("Detection rules generated");
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const generateBulkRulesMutation = trpc.detectionRules.generateForGaps.useMutation({
    onSuccess: (data) => {
      setBulkRules(data.rules);
      toast.success(`Generated ${data.rules.length} detection rules`);
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const { data: gapCount } = trpc.detectionRules.gapCount.useQuery();

  const outcomeMutation = trpc.purpleTeam.updateBlueTeamOutcome.useMutation({
    onSuccess: () => {
      toast.success("Blue team outcome recorded");
      setOutcomeDialogTest(null);
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const openOutcomeDialog = (test: any) => {
    setOutcomeDialogTest(test);
    setBtOutcome(test.blueTeamOutcome || "not_tested");
    setBtMethod(test.detectionMethod || "");
    setBtAction(test.responseAction || "");
    setBtTTD(test.timeToDetect != null ? String(test.timeToDetect) : "");
    setBtTTR(test.timeToRespond != null ? String(test.timeToRespond) : "");
    setBtNotes(test.blueTeamNotes || "");
  };

  const getCoverageColor = (pct: number) => {
    if (pct >= 80) return "bg-emerald-500";
    if (pct >= 60) return "bg-green-500";
    if (pct >= 40) return "bg-yellow-500";
    if (pct >= 20) return "bg-orange-500";
    return "bg-red-500";
  };

  const getGapColor = (pct: number) => {
    if (pct >= 60) return "text-red-400";
    if (pct >= 40) return "text-orange-400";
    if (pct >= 20) return "text-yellow-400";
    return "text-emerald-400";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6 text-violet-400" />
            Purple Team &amp; Detection Tests
          </h1>
          <p className="text-muted-foreground mt-1">
            Track red vs blue team results, record outcomes, and identify detection gaps
          </p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              New Detection Test
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Detection Test</DialogTitle>
              <DialogDescription>Log a detection test result</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Technique ID</Label>
                  <Input value={newTechniqueId} onChange={(e) => setNewTechniqueId(e.target.value)} placeholder="T1059.001" />
                </div>
                <div>
                  <Label>Technique Name</Label>
                  <Input value={newTechniqueName} onChange={(e) => setNewTechniqueName(e.target.value)} placeholder="PowerShell" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Tactic</Label>
                  <Select value={newTactic} onValueChange={setNewTactic}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {TACTICS.map(t => (
                        <SelectItem key={t} value={t}>
                          {t.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Detected?</Label>
                  <Select value={newDetected ? "yes" : "no"} onValueChange={(v) => setNewDetected(v === "yes")}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="yes">Yes - Detected</SelectItem>
                      <SelectItem value="no">No - Gap</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div>
                <Label>Notes</Label>
                <Textarea value={newNotes} onChange={(e) => setNewNotes(e.target.value)} placeholder="Test details..." />
              </div>
            </div>
            <DialogFooter>
              <Button
                onClick={() => createMutation.mutate({
                  techniqueId: newTechniqueId,
                  techniqueName: newTechniqueName,
                  tactic: newTactic,
                  detected: newDetected,
                  isGap: !newDetected,
                  executionResult: "success",
                  notes: newNotes,
                })}
                disabled={!newTechniqueId || createMutation.isPending}
              >
                Create Test
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold">{stats?.totalTests ?? 0}</div>
            <div className="text-xs text-muted-foreground">Total Tests</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-emerald-400">{stats?.totalDetected ?? 0}</div>
            <div className="text-xs text-muted-foreground">Detected</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-red-400">{stats?.totalGaps ?? 0}</div>
            <div className="text-xs text-muted-foreground">Gaps</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-blue-400">{stats?.coverageRate ?? 0}%</div>
            <div className="text-xs text-muted-foreground">Coverage Rate</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-purple-400">{stats?.totalScores ?? 0}</div>
            <div className="text-xs text-muted-foreground">Defense Scores</div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b pb-2">
        {[
          { key: "tests", label: "Detection Tests", icon: Eye },
          { key: "gaps", label: "Gap Summary", icon: ShieldAlert },
          { key: "matrix", label: "Coverage Matrix", icon: BarChart3 },
          { key: "scores", label: "Defense Scores", icon: Shield },
        ].map(tab => (
          <Button
            key={tab.key}
            variant={activeTab === tab.key ? "default" : "ghost"}
            size="sm"
            className="gap-2"
            onClick={() => setActiveTab(tab.key as any)}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </Button>
        ))}
      </div>

      {/* Blue Team Outcome Dialog */}
      <Dialog open={!!outcomeDialogTest} onOpenChange={(open) => !open && setOutcomeDialogTest(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-violet-400" />
              Record Blue Team Outcome
            </DialogTitle>
            <DialogDescription>
              {outcomeDialogTest && (
                <span>
                  <code className="text-violet-400">{outcomeDialogTest.techniqueId}</code> — {outcomeDialogTest.techniqueName}
                </span>
              )}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            {/* Outcome Selection */}
            <div>
              <Label className="mb-2 block">Outcome</Label>
              <div className="grid grid-cols-5 gap-2">
                {(Object.entries(OUTCOME_CONFIG) as [string, typeof OUTCOME_CONFIG.detected][]).map(([key, cfg]) => (
                  <button
                    key={key}
                    onClick={() => setBtOutcome(key)}
                    className={`flex flex-col items-center gap-1 p-2 rounded-lg border-2 transition-all text-xs ${
                      btOutcome === key
                        ? `${cfg.border} ${cfg.bg} ${cfg.color}`
                        : "border-zinc-700 text-zinc-500 hover:border-zinc-500"
                    }`}
                  >
                    <cfg.icon className="h-5 w-5" />
                    {cfg.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Detection Method</Label>
                <Select value={btMethod || "placeholder"} onValueChange={(v) => setBtMethod(v === "placeholder" ? "" : v)}>
                  <SelectTrigger><SelectValue placeholder="Select method..." /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="placeholder" disabled>Select method...</SelectItem>
                    {DETECTION_METHODS.map(m => (
                      <SelectItem key={m} value={m}>{m}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Response Action</Label>
                <Select value={btAction || "placeholder"} onValueChange={(v) => setBtAction(v === "placeholder" ? "" : v)}>
                  <SelectTrigger><SelectValue placeholder="Select action..." /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="placeholder" disabled>Select action...</SelectItem>
                    {RESPONSE_ACTIONS.map(a => (
                      <SelectItem key={a} value={a}>{a}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="flex items-center gap-1">
                  <Timer className="h-3 w-3" /> Time to Detect (seconds)
                </Label>
                <Input
                  type="number"
                  value={btTTD}
                  onChange={(e) => setBtTTD(e.target.value)}
                  placeholder="e.g. 120"
                  min="0"
                />
              </div>
              <div>
                <Label className="flex items-center gap-1">
                  <Zap className="h-3 w-3" /> Time to Respond (seconds)
                </Label>
                <Input
                  type="number"
                  value={btTTR}
                  onChange={(e) => setBtTTR(e.target.value)}
                  placeholder="e.g. 300"
                  min="0"
                />
              </div>
            </div>

            <div>
              <Label>Blue Team Notes</Label>
              <Textarea
                value={btNotes}
                onChange={(e) => setBtNotes(e.target.value)}
                placeholder="Describe what the blue team observed, how the alert was triaged, and any follow-up actions..."
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOutcomeDialogTest(null)}>Cancel</Button>
            <Button
              onClick={() => {
                if (!outcomeDialogTest) return;
                outcomeMutation.mutate({
                  testId: outcomeDialogTest.testId,
                  blueTeamOutcome: btOutcome as any,
                  detectionMethod: btMethod || undefined,
                  responseAction: btAction || undefined,
                  timeToDetect: btTTD ? parseInt(btTTD) : undefined,
                  timeToRespond: btTTR ? parseInt(btTTR) : undefined,
                  blueTeamNotes: btNotes || undefined,
                });
              }}
              disabled={outcomeMutation.isPending}
              className="gap-2"
            >
              <ShieldCheck className="h-4 w-4" />
              {outcomeMutation.isPending ? "Saving..." : "Save Outcome"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rule Generation Dialog */}
      <Dialog open={!!ruleDialogTest} onOpenChange={(open) => !open && setRuleDialogTest(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileCode className="h-5 w-5 text-amber-400" />
              Detection Rule Generator
            </DialogTitle>
            <DialogDescription>
              {ruleDialogTest && (
                <span>
                  <code className="text-violet-400">{ruleDialogTest.techniqueId}</code> — {ruleDialogTest.techniqueName}
                </span>
              )}
            </DialogDescription>
          </DialogHeader>
          {generateRuleMutation.isPending ? (
            <div className="flex items-center justify-center py-12 gap-3">
              <Loader2 className="h-6 w-6 animate-spin text-amber-400" />
              <span className="text-muted-foreground">Generating detection rules with AI...</span>
            </div>
          ) : Object.keys(generatedRules).length > 0 ? (
            <div className="space-y-4">
              <div className="flex gap-2">
                {(["sigma", "splunk_spl", "kql"] as const).map(fmt => (
                  <Button
                    key={fmt}
                    size="sm"
                    variant={ruleFormat === fmt ? "default" : "outline"}
                    onClick={() => setRuleFormat(fmt)}
                    className="text-xs"
                  >
                    {fmt === "sigma" ? "Sigma" : fmt === "splunk_spl" ? "Splunk SPL" : "KQL"}
                  </Button>
                ))}
              </div>
              <div className="relative">
                <pre className="bg-zinc-900 border border-zinc-700 rounded-lg p-4 text-xs overflow-x-auto max-h-[400px] overflow-y-auto">
                  <code>{generatedRules[ruleFormat] || "No rule generated for this format"}</code>
                </pre>
                <Button
                  size="icon"
                  variant="ghost"
                  className="absolute top-2 right-2 h-7 w-7"
                  onClick={() => {
                    navigator.clipboard.writeText(generatedRules[ruleFormat] || "");
                    toast.success("Rule copied to clipboard");
                  }}
                >
                  <Copy className="h-3 w-3" />
                </Button>
              </div>
            </div>
          ) : null}
          <DialogFooter>
            <Button variant="outline" onClick={() => setRuleDialogTest(null)}>Close</Button>
            {Object.keys(generatedRules).length > 0 && (
              <Button
                className="gap-2"
                onClick={() => {
                  const content = Object.entries(generatedRules)
                    .map(([fmt, rule]) => `# ${fmt.toUpperCase()}\n\n${rule}`)
                    .join("\n\n---\n\n");
                  const blob = new Blob([content], { type: "text/plain" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `detection-rule-${ruleDialogTest?.techniqueId || "unknown"}.txt`;
                  a.click();
                  URL.revokeObjectURL(url);
                  toast.success("Rules downloaded");
                }}
              >
                <Download className="h-4 w-4" />
                Download All Formats
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Rules Dialog */}
      <Dialog open={showBulkRulesDialog} onOpenChange={setShowBulkRulesDialog}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileCode className="h-5 w-5 text-amber-400" />
              Bulk Detection Rules — {bulkFormat === "sigma" ? "Sigma" : bulkFormat === "splunk_spl" ? "Splunk SPL" : "KQL"}
            </DialogTitle>
            <DialogDescription>{bulkRules.length} rules generated for detection gaps</DialogDescription>
          </DialogHeader>
          {generateBulkRulesMutation.isPending ? (
            <div className="flex items-center justify-center py-12 gap-3">
              <Loader2 className="h-6 w-6 animate-spin text-amber-400" />
              <span className="text-muted-foreground">Generating bulk detection rules...</span>
            </div>
          ) : bulkRules.length > 0 ? (
            <div className="space-y-4">
              {bulkRules.map((r, i) => (
                <Card key={i} className="border-amber-500/20">
                  <CardContent className="p-3">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <code className="text-xs text-violet-400">{r.techniqueId}</code>
                        <span className="text-sm">{r.techniqueName}</span>
                      </div>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7"
                        onClick={() => {
                          navigator.clipboard.writeText(r.rule);
                          toast.success(`Rule for ${r.techniqueId} copied`);
                        }}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                    <pre className="bg-zinc-900 border border-zinc-700 rounded p-2 text-[10px] overflow-x-auto max-h-32 overflow-y-auto">
                      <code>{r.rule}</code>
                    </pre>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : null}
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowBulkRulesDialog(false)}>Close</Button>
            {bulkRules.length > 0 && (
              <Button
                className="gap-2"
                onClick={() => {
                  const content = bulkRules.map(r => `# ${r.techniqueId} - ${r.techniqueName}\n\n${r.rule}`).join("\n\n---\n\n");
                  const blob = new Blob([content], { type: "text/plain" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `bulk-detection-rules-${bulkFormat}.txt`;
                  a.click();
                  URL.revokeObjectURL(url);
                  toast.success("All rules downloaded");
                }}
              >
                <Download className="h-4 w-4" />
                Download All
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Tab Content: Detection Tests */}
      {activeTab === "tests" && (
        <>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Search techniques..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" />
            </div>
            <Select value={tacticFilter} onValueChange={setTacticFilter}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="All Tactics" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tactics</SelectItem>
                {TACTICS.map(t => (
                  <SelectItem key={t} value={t}>
                    {t.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={gapFilter} onValueChange={setGapFilter}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="All Results" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Results</SelectItem>
                <SelectItem value="detected">Detected</SelectItem>
                <SelectItem value="gaps">Gaps Only</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-3">
            {isLoading ? (
              <div className="text-center py-8 text-muted-foreground">Loading...</div>
            ) : !tests?.items?.length ? (
              <Card>
                <CardContent className="py-8 text-center text-muted-foreground">
                  <Eye className="h-10 w-10 mx-auto mb-3 opacity-40" />
                  <p>No detection tests yet</p>
                </CardContent>
              </Card>
            ) : (
              tests.items.map((test: any) => {
                const outcome = test.blueTeamOutcome || "not_tested";
                const ocfg = OUTCOME_CONFIG[outcome as keyof typeof OUTCOME_CONFIG] || OUTCOME_CONFIG.not_tested;
                return (
                  <Card key={test.testId} className={`${test.isGap ? "border-red-500/30" : "border-emerald-500/30"}`}>
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          {test.detected ? (
                            <CheckCircle className="h-5 w-5 text-emerald-400 shrink-0" />
                          ) : (
                            <XCircle className="h-5 w-5 text-red-400 shrink-0" />
                          )}
                          <div>
                            <div className="flex items-center gap-2 flex-wrap">
                              <code className="text-sm text-violet-400">{test.techniqueId}</code>
                              <span className="text-sm font-medium">{test.techniqueName}</span>
                            </div>
                            <div className="flex items-center gap-2 mt-1 flex-wrap">
                              <Badge variant="outline" className="text-[10px] capitalize">
                                {test.tactic?.replace(/-/g, " ")}
                              </Badge>
                              {test.isGap && (
                                <Badge className="text-[10px] bg-red-500/20 text-red-400 border-red-500/30">
                                  GAP
                                </Badge>
                              )}
                              <Badge className={`text-[10px] ${ocfg.bg} ${ocfg.color} ${ocfg.border}`}>
                                <ocfg.icon className="h-3 w-3 mr-1" />
                                {ocfg.label}
                              </Badge>
                              {test.detectionMethod && (
                                <Badge variant="outline" className="text-[10px]">
                                  {test.detectionMethod}
                                </Badge>
                              )}
                              {test.timeToDetect != null && (
                                <Badge variant="outline" className="text-[10px] text-blue-400">
                                  <Timer className="h-3 w-3 mr-1" />
                                  TTD: {formatDuration(test.timeToDetect)}
                                </Badge>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <Button
                            size="sm"
                            variant="outline"
                            className="text-xs gap-1"
                            onClick={() => openOutcomeDialog(test)}
                          >
                            <ShieldCheck className="h-3 w-3" />
                            Blue Team
                          </Button>
                          {test.isGap && (
                            <Button
                              size="sm"
                              variant="outline"
                              className="text-xs gap-1 text-amber-400 border-amber-500/30"
                              onClick={() => {
                                setRuleDialogTest(test);
                                setGeneratedRules({});
                                generateRuleMutation.mutate({ testId: test.testId, formats: ["sigma", "splunk_spl", "kql"], useLLM: true });
                              }}
                            >
                              <FileCode className="h-3 w-3" />
                              Gen Rule
                            </Button>
                          )}
                          {test.isGap && test.mitigationStatus !== "resolved" && (
                            <Button
                              size="sm"
                              variant="outline"
                              className="text-xs"
                              onClick={() => updateMutation.mutate({
                                testId: test.testId,
                                mitigationStatus: "resolved",
                                detected: true,
                                isGap: false,
                              })}
                            >
                              Mark Resolved
                            </Button>
                          )}
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-8 w-8"
                            onClick={() => deleteMutation.mutate({ testId: test.testId })}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                      {(test.notes || test.blueTeamNotes) && (
                        <div className="mt-2 pl-8 space-y-1">
                          {test.notes && (
                            <p className="text-xs text-muted-foreground">{test.notes}</p>
                          )}
                          {test.blueTeamNotes && (
                            <p className="text-xs text-blue-400/80">
                              <span className="font-medium">Blue Team:</span> {test.blueTeamNotes}
                            </p>
                          )}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })
            )}
          </div>
        </>
      )}

      {/* Tab Content: Gap Summary Dashboard */}
      {activeTab === "gaps" && (
        <div className="space-y-6">
          {!gapSummary ? (
            <div className="text-center py-8 text-muted-foreground">Loading gap summary...</div>
          ) : (
            <>
              {/* Bulk Rule Generation */}
              <Card className="border-amber-500/20 bg-amber-500/5">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <FileCode className="h-8 w-8 text-amber-400" />
                      <div>
                        <h3 className="font-semibold">Auto-Generate Detection Rules</h3>
                        <p className="text-xs text-muted-foreground">
                          Generate Sigma, Splunk SPL, or KQL rules for {gapCount?.count ?? 0} undetected techniques using AI
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Select value={bulkFormat} onValueChange={(v) => setBulkFormat(v as any)}>
                        <SelectTrigger className="w-[130px]">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="sigma">Sigma</SelectItem>
                          <SelectItem value="splunk_spl">Splunk SPL</SelectItem>
                          <SelectItem value="kql">KQL</SelectItem>
                        </SelectContent>
                      </Select>
                      <Button
                        className="gap-2"
                        disabled={generateBulkRulesMutation.isPending || !gapCount?.count}
                        onClick={() => {
                          setShowBulkRulesDialog(true);
                          setBulkRules([]);
                          generateBulkRulesMutation.mutate({ format: bulkFormat });
                        }}
                      >
                        {generateBulkRulesMutation.isPending ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <FileCode className="h-4 w-4" />
                        )}
                        Generate Rules
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Outcome Distribution */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
                {(Object.entries(OUTCOME_CONFIG) as [string, typeof OUTCOME_CONFIG.detected][]).map(([key, cfg]) => {
                  const count = gapSummary.outcomes[key as keyof typeof gapSummary.outcomes] || 0;
                  return (
                    <Card key={key} className={`${cfg.border}`}>
                      <CardContent className="pt-4 pb-4 text-center">
                        <cfg.icon className={`h-6 w-6 mx-auto mb-1 ${cfg.color}`} />
                        <div className={`text-2xl font-bold ${cfg.color}`}>{count}</div>
                        <div className="text-xs text-muted-foreground">{cfg.label}</div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>

              {/* Assessment Progress */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Activity className="h-4 w-4 text-violet-400" />
                    Assessment Progress
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-4">
                    <div className="flex-1">
                      <div className="h-4 bg-zinc-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-violet-500 transition-all rounded-full"
                          style={{ width: `${gapSummary.totalTests > 0 ? Math.round((gapSummary.totalAssessed / gapSummary.totalTests) * 100) : 0}%` }}
                        />
                      </div>
                    </div>
                    <span className="text-sm font-medium">
                      {gapSummary.totalAssessed}/{gapSummary.totalTests} assessed
                      ({gapSummary.totalTests > 0 ? Math.round((gapSummary.totalAssessed / gapSummary.totalTests) * 100) : 0}%)
                    </span>
                  </div>
                </CardContent>
              </Card>

              {/* Response Metrics */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <Card>
                  <CardContent className="pt-4 pb-4">
                    <div className="flex items-center gap-3">
                      <Timer className="h-8 w-8 text-blue-400" />
                      <div>
                        <div className="text-2xl font-bold text-blue-400">
                          {formatDuration(gapSummary.avgTimeToDetect)}
                        </div>
                        <div className="text-xs text-muted-foreground">Avg Time to Detect (MTTD)</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4 pb-4">
                    <div className="flex items-center gap-3">
                      <Zap className="h-8 w-8 text-orange-400" />
                      <div>
                        <div className="text-2xl font-bold text-orange-400">
                          {formatDuration(gapSummary.avgTimeToRespond)}
                        </div>
                        <div className="text-xs text-muted-foreground">Avg Time to Respond (MTTR)</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Detection Methods */}
              {gapSummary.detectionMethods.length > 0 && (
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base">Detection Method Breakdown</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {gapSummary.detectionMethods.map((m: any) => (
                        <div key={m.method} className="flex items-center gap-3">
                          <div className="w-32 text-sm truncate">{m.method}</div>
                          <div className="flex-1">
                            <div className="h-5 bg-zinc-800 rounded-full overflow-hidden relative">
                              <div
                                className="h-full bg-blue-500/60 rounded-full"
                                style={{ width: `${Math.max((m.count / Math.max(...gapSummary.detectionMethods.map((d: any) => d.count))) * 100, 5)}%` }}
                              />
                              <span className="absolute inset-0 flex items-center justify-center text-xs font-medium">
                                {m.count}
                              </span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Gaps by Tactic */}
              {gapSummary.gapsByTactic.length > 0 && (
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base">Detection Gaps by Tactic</CardTitle>
                    <CardDescription>Tactics with the highest gap rates need immediate attention</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {gapSummary.gapsByTactic
                        .sort((a: any, b: any) => b.gapRate - a.gapRate)
                        .map((row: any) => (
                          <div key={row.tactic} className="flex items-center gap-3">
                            <div className="w-40 text-sm capitalize truncate">
                              {row.tactic.replace(/-/g, " ")}
                            </div>
                            <div className="flex-1">
                              <div className="h-5 bg-zinc-800 rounded-full overflow-hidden relative">
                                <div
                                  className="h-full bg-red-500/50 rounded-full"
                                  style={{ width: `${Math.max(row.gapRate, 3)}%` }}
                                />
                                <span className="absolute inset-0 flex items-center justify-center text-xs font-medium">
                                  {row.gapRate}% gap rate
                                </span>
                              </div>
                            </div>
                            <div className="w-28 text-xs text-right text-muted-foreground">
                              <span className="text-red-400">{row.missed}</span> missed,{" "}
                              <span className="text-yellow-400">{row.partial}</span> partial
                            </div>
                          </div>
                        ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Top Undetected Techniques */}
              {gapSummary.missedTests.length > 0 && (
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-red-400" />
                      Top Undetected Techniques
                    </CardTitle>
                    <CardDescription>These techniques were executed successfully but not detected by the blue team</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {gapSummary.missedTests.map((t: any) => (
                        <div key={t.testId} className="flex items-center justify-between p-2 rounded-lg bg-red-500/5 border border-red-500/20">
                          <div className="flex items-center gap-2">
                            <XCircle className="h-4 w-4 text-red-400 shrink-0" />
                            <code className="text-xs text-violet-400">{t.techniqueId}</code>
                            <span className="text-sm">{t.techniqueName}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-[10px] capitalize">
                              {t.tactic?.replace(/-/g, " ")}
                            </Badge>
                            {t.gapSeverity && (
                              <Badge className={`text-[10px] ${
                                t.gapSeverity === "critical" ? "bg-red-500/20 text-red-400" :
                                t.gapSeverity === "high" ? "bg-orange-500/20 text-orange-400" :
                                "bg-yellow-500/20 text-yellow-400"
                              }`}>
                                {t.gapSeverity}
                              </Badge>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </>
          )}
        </div>
      )}

      {/* Tab Content: Coverage Matrix */}
      {activeTab === "matrix" && matrix && (
        <Card>
          <CardHeader>
            <CardTitle>MITRE ATT&CK Detection Coverage Matrix</CardTitle>
            <CardDescription>
              Overall coverage: {matrix.summary.overallCoverage}% ({matrix.summary.totalDetected}/{matrix.summary.totalTests} detected)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {matrix.matrix.map((row: any) => (
                <div key={row.tactic} className="flex items-center gap-3">
                  <div className="w-40 text-sm capitalize truncate">
                    {row.tactic.replace(/-/g, " ")}
                  </div>
                  <div className="flex-1">
                    <div className="h-6 bg-zinc-800 rounded-full overflow-hidden relative">
                      <div
                        className={`h-full ${getCoverageColor(row.coverage)} transition-all rounded-full`}
                        style={{ width: `${Math.max(row.coverage, 2)}%` }}
                      />
                      <span className="absolute inset-0 flex items-center justify-center text-xs font-medium">
                        {row.coverage}%
                      </span>
                    </div>
                  </div>
                  <div className="w-24 text-xs text-right text-muted-foreground">
                    {row.detected}/{row.totalTests} detected
                  </div>
                  {row.gaps > 0 && (
                    <Badge className="text-[10px] bg-red-500/20 text-red-400">
                      {row.gaps} gaps
                    </Badge>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tab Content: Defense Scores */}
      {activeTab === "scores" && (
        <div className="space-y-4">
          {!scores?.items?.length ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                <Shield className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p>No defense scores yet</p>
              </CardContent>
            </Card>
          ) : (
            scores.items.map((score: any) => (
              <Card key={score.scoreId}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="font-semibold">{score.organizationName}</h3>
                    <Badge className={`${
                      score.overallScore >= 70 ? "bg-emerald-500/20 text-emerald-400" :
                      score.overallScore >= 40 ? "bg-yellow-500/20 text-yellow-400" :
                      "bg-red-500/20 text-red-400"
                    }`}>
                      Score: {score.overallScore}
                    </Badge>
                  </div>
                  <div className="grid grid-cols-4 gap-4">
                    {[
                      { label: "Detection", value: score.detectionScore, color: "text-blue-400" },
                      { label: "Vulnerability", value: score.vulnerabilityScore, color: "text-orange-400" },
                      { label: "Surface", value: score.surfaceScore, color: "text-purple-400" },
                      { label: "Response", value: score.responseScore, color: "text-emerald-400" },
                    ].map(item => (
                      <div key={item.label} className="text-center">
                        <div className={`text-lg font-bold ${item.color}`}>{item.value}</div>
                        <div className="text-xs text-muted-foreground">{item.label}</div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      )}
    </div>
  );
}
