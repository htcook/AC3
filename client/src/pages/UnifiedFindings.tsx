/**
 * Unified Findings Dashboard
 *
 * Shows all web application security findings from ZAP, SQLMap, and XSStrike/Dalfox
 * in a single view. Findings are grouped by severity, tool, and MITRE ATT&CK technique
 * with filtering, search, and drill-down capabilities.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Loader2, Search, Shield, Bug, AlertTriangle, Target, Crosshair,
  ExternalLink, ChevronRight, ChevronDown, Zap, Database,
  Code, Eye, ShieldAlert, BarChart3, Layers, Filter,
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── Constants ──────────────────────────────────────────────────────────────

const SEVERITY_CONFIG: Record<string, { label: string; color: string; dotColor: string; order: number }> = {
  high: { label: "High", color: "bg-red-500/15 text-red-400 border-red-500/30", dotColor: "bg-red-400", order: 0 },
  medium: { label: "Medium", color: "bg-amber-500/15 text-amber-400 border-amber-500/30", dotColor: "bg-amber-400", order: 1 },
  low: { label: "Low", color: "bg-blue-500/15 text-blue-400 border-blue-500/30", dotColor: "bg-blue-400", order: 2 },
  info: { label: "Info", color: "bg-gray-500/15 text-gray-400 border-gray-500/30", dotColor: "bg-gray-400", order: 3 },
};

const TOOL_CONFIG: Record<string, { label: string; icon: React.ReactNode; color: string; description: string }> = {
  zap: { label: "ZAP", icon: <Zap className="w-4 h-4" />, color: "text-orange-400", description: "OWASP ZAP DAST Scanner" },
  sqlmap: { label: "SQLMap", icon: <Database className="w-4 h-4" />, color: "text-cyan-400", description: "Blind SQL Injection Scanner" },
  xsstrike: { label: "XSStrike", icon: <Code className="w-4 h-4" />, color: "text-emerald-400", description: "Advanced XSS Scanner" },
  dalfox: { label: "Dalfox", icon: <Code className="w-4 h-4" />, color: "text-lime-400", description: "Parameter-based XSS Scanner" },
  other: { label: "Other", icon: <Bug className="w-4 h-4" />, color: "text-gray-400", description: "Other scanners" },
};

const TACTIC_COLORS: Record<string, string> = {
  "initial-access": "text-red-400",
  "execution": "text-orange-400",
  "persistence": "text-amber-400",
  "privilege-escalation": "text-yellow-400",
  "defense-evasion": "text-lime-400",
  "credential-access": "text-emerald-400",
  "discovery": "text-teal-400",
  "lateral-movement": "text-cyan-400",
  "collection": "text-sky-400",
  "exfiltration": "text-blue-400",
  "impact": "text-violet-400",
  "command-and-control": "text-purple-400",
  "reconnaissance": "text-pink-400",
  "resource-development": "text-rose-400",
};

// ─── Helpers ────────────────────────────────────────────────────────────────

function inferTool(zapPluginId: string | null): string {
  if (!zapPluginId) return "other";
  if (zapPluginId.startsWith("sqlmap-")) return "sqlmap";
  if (zapPluginId.startsWith("xsstrike-")) return "xsstrike";
  if (zapPluginId.startsWith("dalfox-")) return "dalfox";
  if (/^\d+$/.test(zapPluginId)) return "zap";
  return "other";
}

function formatConfidence(confidence: number | null): string {
  if (confidence === null || confidence === undefined) return "—";
  return `${Math.round(confidence * 100)}%`;
}

// ─── Summary Cards ──────────────────────────────────────────────────────────

function StatsCards({ stats, isLoading }: { stats: any; isLoading: boolean }) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {[...Array(6)].map((_, i) => (
          <Card key={i} className="bg-card/50 border-border/50 animate-pulse">
            <CardContent className="p-4"><div className="h-8 bg-muted rounded" /></CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (!stats) return null;

  const cards = [
    { label: "Total Findings", value: stats.total, icon: <Layers className="w-4 h-4 text-blue-400" />, color: "text-blue-400" },
    { label: "High Severity", value: stats.bySeverity?.high || 0, icon: <AlertTriangle className="w-4 h-4 text-red-400" />, color: "text-red-400" },
    { label: "Medium", value: stats.bySeverity?.medium || 0, icon: <Shield className="w-4 h-4 text-amber-400" />, color: "text-amber-400" },
    { label: "Low / Info", value: (stats.bySeverity?.low || 0) + (stats.bySeverity?.info || 0), icon: <Eye className="w-4 h-4 text-gray-400" />, color: "text-gray-400" },
    { label: "Exploitable", value: stats.exploitable, icon: <ShieldAlert className="w-4 h-4 text-purple-400" />, color: "text-purple-400" },
    { label: "MITRE Techniques", value: stats.byMitreTechnique?.length || 0, icon: <Target className="w-4 h-4 text-emerald-400" />, color: "text-emerald-400" },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((card) => (
        <Card key={card.label} className="bg-card/50 border-border/50 hover:border-border transition-colors">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-1">
              {card.icon}
              <span className="text-xs text-muted-foreground">{card.label}</span>
            </div>
            <span className={`text-2xl font-bold font-mono ${card.color}`}>{card.value}</span>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Tool Distribution Bar ──────────────────────────────────────────────────

function ToolDistribution({ stats }: { stats: any }) {
  if (!stats?.byTool) return null;
  const total = Object.values(stats.byTool as Record<string, number>).reduce((a: number, b: number) => a + b, 0);
  if (total === 0) return null;

  const toolColors: Record<string, string> = {
    zap: "bg-orange-500",
    sqlmap: "bg-cyan-500",
    xsstrike: "bg-emerald-500",
    dalfox: "bg-lime-500",
    other: "bg-gray-500",
  };

  return (
    <Card className="bg-card/50 border-border/50">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
          <BarChart3 className="w-4 h-4" /> Findings by Tool
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-4">
        <div className="flex h-3 rounded-full overflow-hidden bg-muted/30 mb-3">
          {Object.entries(stats.byTool as Record<string, number>).map(([tool, count]) => (
            <TooltipProvider key={tool}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div
                    className={`${toolColors[tool] || "bg-gray-500"} transition-all`}
                    style={{ width: `${(count / total) * 100}%` }}
                  />
                </TooltipTrigger>
                <TooltipContent>
                  <span className="font-mono">{TOOL_CONFIG[tool]?.label || tool}: {count} ({Math.round((count / total) * 100)}%)</span>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          ))}
        </div>
        <div className="flex flex-wrap gap-3">
          {Object.entries(stats.byTool as Record<string, number>).map(([tool, count]) => (
            <div key={tool} className="flex items-center gap-1.5 text-xs">
              <div className={`w-2.5 h-2.5 rounded-full ${toolColors[tool] || "bg-gray-500"}`} />
              <span className="text-muted-foreground">{TOOL_CONFIG[tool]?.label || tool}</span>
              <span className="font-mono font-medium">{count}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── MITRE ATT&CK Heatmap ──────────────────────────────────────────────────

function MitreHeatmap({ stats }: { stats: any }) {
  if (!stats?.byMitreTechnique?.length) return null;

  return (
    <Card className="bg-card/50 border-border/50">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
          <Target className="w-4 h-4" /> Top MITRE ATT&CK Techniques
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-4">
        <div className="space-y-2">
          {stats.byMitreTechnique.map((t: any) => {
            const maxCount = stats.byMitreTechnique[0]?.count || 1;
            const pct = (t.count / maxCount) * 100;
            const tacticColor = TACTIC_COLORS[t.tactic?.toLowerCase().replace(/\s+/g, '-')] || "text-gray-400";
            return (
              <div key={t.techniqueId} className="group">
                <div className="flex items-center justify-between mb-0.5">
                  <div className="flex items-center gap-2 text-xs min-w-0">
                    <span className="font-mono text-muted-foreground shrink-0">{t.techniqueId}</span>
                    <span className="truncate">{t.techniqueName}</span>
                    {t.tactic && (
                      <Badge variant="outline" className={`text-[9px] px-1 py-0 ${tacticColor} border-current/20 shrink-0`}>
                        {t.tactic}
                      </Badge>
                    )}
                  </div>
                  <span className="font-mono text-xs font-medium ml-2 shrink-0">{t.count}</span>
                </div>
                <div className="h-1.5 rounded-full bg-muted/30 overflow-hidden">
                  <div className="h-full rounded-full bg-emerald-500/60 transition-all" style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Tactic Distribution ────────────────────────────────────────────────────

function TacticDistribution({ stats, onTacticClick }: { stats: any; onTacticClick: (tactic: string) => void }) {
  if (!stats?.byMitreTactic || Object.keys(stats.byMitreTactic).length === 0) return null;

  const sorted = Object.entries(stats.byMitreTactic as Record<string, number>)
    .sort(([, a], [, b]) => b - a);

  return (
    <Card className="bg-card/50 border-border/50">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
          <Crosshair className="w-4 h-4" /> Findings by MITRE Tactic
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-4">
        <div className="flex flex-wrap gap-2">
          {sorted.map(([tactic, count]) => {
            const color = TACTIC_COLORS[tactic.toLowerCase().replace(/\s+/g, '-')] || "text-gray-400";
            return (
              <button
                key={tactic}
                onClick={() => onTacticClick(tactic)}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-border/50 hover:border-border bg-card/30 hover:bg-card/60 transition-colors text-xs cursor-pointer`}
              >
                <span className={`${color} font-medium`}>{tactic}</span>
                <span className="font-mono text-muted-foreground">{count}</span>
              </button>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Finding Detail Dialog ──────────────────────────────────────────────────

function FindingDetail({ finding, open, onClose }: { finding: any; open: boolean; onClose: () => void }) {
  if (!finding) return null;
  const tool = inferTool(finding.zapPluginId);
  const toolConfig = TOOL_CONFIG[tool];
  const sevConfig = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.info;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base">
            <Badge variant="outline" className={sevConfig.color}>{sevConfig.label}</Badge>
            <span className="truncate">{finding.alertName}</span>
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 text-sm">
          {/* Meta row */}
          <div className="flex flex-wrap gap-2">
            <Badge variant="outline" className={`${toolConfig?.color || "text-gray-400"} border-current/20`}>
              {toolConfig?.icon} <span className="ml-1">{toolConfig?.label || tool}</span>
            </Badge>
            {finding.mitreAttackId && (
              <Badge variant="outline" className="text-emerald-400 border-emerald-500/20">
                <Target className="w-3 h-3 mr-1" /> {finding.mitreAttackId} {finding.mitreAttackName}
              </Badge>
            )}
            {finding.mitreTactic && (
              <Badge variant="outline" className="text-purple-400 border-purple-500/20">
                {finding.mitreTactic}
              </Badge>
            )}
            {finding.exploitAvailable === 1 && (
              <Badge variant="outline" className="text-red-400 border-red-500/20">
                <ShieldAlert className="w-3 h-3 mr-1" /> Exploit Available
              </Badge>
            )}
            {finding.cweId && (
              <Badge variant="outline" className="text-sky-400 border-sky-500/20">CWE-{finding.cweId}</Badge>
            )}
            {finding.wascId && (
              <Badge variant="outline" className="text-indigo-400 border-indigo-500/20">WASC-{finding.wascId}</Badge>
            )}
            <Badge variant="outline" className="text-muted-foreground">
              Confidence: {formatConfidence(finding.confidence)}
            </Badge>
          </div>

          <Separator />

          {/* URL & Parameter */}
          {finding.url && (
            <div>
              <span className="text-muted-foreground text-xs font-medium">URL</span>
              <p className="font-mono text-xs break-all mt-0.5">{finding.url}</p>
            </div>
          )}
          {finding.param && (
            <div className="flex gap-4">
              {finding.method && (
                <div>
                  <span className="text-muted-foreground text-xs font-medium">Method</span>
                  <p className="font-mono text-xs mt-0.5">{finding.method}</p>
                </div>
              )}
              <div>
                <span className="text-muted-foreground text-xs font-medium">Parameter</span>
                <p className="font-mono text-xs mt-0.5">{finding.param}</p>
              </div>
            </div>
          )}

          {/* Description */}
          {finding.description && (
            <div>
              <span className="text-muted-foreground text-xs font-medium">Description</span>
              <p className="text-xs mt-0.5 whitespace-pre-wrap">{finding.description}</p>
            </div>
          )}

          {/* Attack / Evidence */}
          {finding.attack && (
            <div>
              <span className="text-muted-foreground text-xs font-medium">Attack Payload</span>
              <pre className="text-xs mt-0.5 p-2 rounded bg-muted/30 overflow-x-auto font-mono">{finding.attack}</pre>
            </div>
          )}
          {finding.evidence && (
            <div>
              <span className="text-muted-foreground text-xs font-medium">Evidence</span>
              <pre className="text-xs mt-0.5 p-2 rounded bg-muted/30 overflow-x-auto font-mono">{finding.evidence}</pre>
            </div>
          )}

          {/* Solution */}
          {finding.solution && (
            <div>
              <span className="text-muted-foreground text-xs font-medium">Solution</span>
              <p className="text-xs mt-0.5 whitespace-pre-wrap">{finding.solution}</p>
            </div>
          )}

          {/* Exploit Module */}
          {finding.exploitModulePath && (
            <div>
              <span className="text-muted-foreground text-xs font-medium">Metasploit Module</span>
              <p className="font-mono text-xs mt-0.5 text-red-400">{finding.exploitModulePath}</p>
            </div>
          )}

          {/* AI Triage */}
          {finding.aiTriageVerdict && (
            <div>
              <span className="text-muted-foreground text-xs font-medium">AI Triage</span>
              <div className="flex items-center gap-2 mt-0.5">
                <Badge variant="outline" className="text-xs">{finding.aiTriageVerdict}</Badge>
                {finding.falsePositiveScore != null && (
                  <span className="text-xs text-muted-foreground">FP Score: {Math.round(finding.falsePositiveScore * 100)}%</span>
                )}
              </div>
              {finding.aiTriageReason && <p className="text-xs mt-1 text-muted-foreground">{finding.aiTriageReason}</p>}
            </div>
          )}

          {/* References */}
          {finding.referenceLinks && (
            <div>
              <span className="text-muted-foreground text-xs font-medium">References</span>
              <div className="flex flex-col gap-0.5 mt-0.5">
                {finding.referenceLinks.split("\n").filter(Boolean).map((ref: string, i: number) => (
                  <a key={i} href={ref.trim()} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:underline flex items-center gap-1">
                    <ExternalLink className="w-3 h-3" /> {ref.trim()}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Scan Info */}
          <Separator />
          <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
            {finding.scanName && <span>Scan: <span className="text-foreground">{finding.scanName}</span></span>}
            {finding.scanType && <span>Type: <span className="text-foreground">{finding.scanType}</span></span>}
            {finding.createdAt && <span>Found: <span className="text-foreground">{new Date(finding.createdAt).toLocaleString()}</span></span>}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Finding Row ────────────────────────────────────────────────────────────

function FindingRow({ finding, onClick }: { finding: any; onClick: () => void }) {
  const tool = inferTool(finding.zapPluginId);
  const toolConfig = TOOL_CONFIG[tool];
  const sevConfig = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.info;

  return (
    <button
      onClick={onClick}
      className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg border border-border/30 hover:border-border/60 bg-card/30 hover:bg-card/50 transition-colors text-left cursor-pointer group"
    >
      {/* Severity dot */}
      <div className={`w-2 h-2 rounded-full shrink-0 ${sevConfig.dotColor}`} />

      {/* Tool icon */}
      <div className={`shrink-0 ${toolConfig?.color || "text-gray-400"}`}>
        {toolConfig?.icon || <Bug className="w-4 h-4" />}
      </div>

      {/* Alert name */}
      <div className="min-w-0 flex-1">
        <p className="text-sm truncate group-hover:text-foreground transition-colors">{finding.alertName || "Unnamed Finding"}</p>
        <div className="flex items-center gap-2 mt-0.5">
          {finding.url && <span className="text-[10px] text-muted-foreground font-mono truncate max-w-[300px]">{finding.url}</span>}
          {finding.param && <span className="text-[10px] text-muted-foreground">param: {finding.param}</span>}
        </div>
      </div>

      {/* MITRE badge */}
      {finding.mitreAttackId && (
        <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-emerald-400 border-emerald-500/20 shrink-0 hidden lg:flex">
          {finding.mitreAttackId}
        </Badge>
      )}

      {/* Confidence */}
      <span className="text-[10px] text-muted-foreground font-mono shrink-0 hidden md:block w-10 text-right">
        {formatConfidence(finding.confidence)}
      </span>

      {/* Exploit indicator */}
      {finding.exploitAvailable === 1 && (
        <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
      )}

      <ChevronRight className="w-4 h-4 text-muted-foreground/50 group-hover:text-muted-foreground shrink-0" />
    </button>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────

export default function UnifiedFindings() {
  const [severity, setSeverity] = useState<string>("");
  const [tool, setTool] = useState<string>("");
  const [mitreTactic, setMitreTactic] = useState<string>("");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [offset, setOffset] = useState(0);
  const limit = 100;

  // Debounce search
  const [searchTimer, setSearchTimer] = useState<ReturnType<typeof setTimeout> | null>(null);
  const handleSearch = (val: string) => {
    setSearch(val);
    if (searchTimer) clearTimeout(searchTimer);
    setSearchTimer(setTimeout(() => {
      setDebouncedSearch(val);
      setOffset(0);
    }, 400));
  };

  // Queries
  const statsQuery = trpc.webAppScanning.unifiedFindingsStats.useQuery();
  const findingsQuery = trpc.webAppScanning.unifiedFindings.useQuery({
    severity: severity || undefined,
    tool: tool || undefined,
    mitreTactic: mitreTactic || undefined,
    search: debouncedSearch || undefined,
    limit,
    offset,
  });

  const stats = statsQuery.data;
  const findings = findingsQuery.data?.findings || [];
  const total = findingsQuery.data?.total || 0;
  const hasMore = offset + limit < total;
  const hasPrev = offset > 0;

  const activeFilters = [severity, tool, mitreTactic, debouncedSearch].filter(Boolean).length;

  const clearFilters = () => {
    setSeverity("");
    setTool("");
    setMitreTactic("");
    setSearch("");
    setDebouncedSearch("");
    setOffset(0);
  };

  return (
    <AppShell>
      <div className="p-4 md:p-6 space-y-5 max-w-[1400px] mx-auto">
        {/* Header */}
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <Shield className="w-5 h-5 text-emerald-400" />
            Unified Findings
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            All web application security findings from ZAP, SQLMap, and XSStrike/Dalfox in one view. Filter by severity, tool, or MITRE ATT&CK technique to focus your analysis.
          </p>
        </div>

        {/* Summary Stats */}
        <StatsCards stats={stats} isLoading={statsQuery.isLoading} />

        {/* Analytics Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <ToolDistribution stats={stats} />
          <MitreHeatmap stats={stats} />
          <TacticDistribution stats={stats} onTacticClick={(tactic) => { setMitreTactic(tactic); setOffset(0); }} />
        </div>

        {/* Filters */}
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Filter className="w-4 h-4 text-muted-foreground shrink-0" />

              <div className="relative flex-1 min-w-[180px] max-w-[300px]">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search findings..."
                  value={search}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="pl-8 h-8 text-xs"
                />
              </div>

              <Select value={severity} onValueChange={(v) => { setSeverity(v === "all" ? "" : v); setOffset(0); }}>
                <SelectTrigger className="h-8 w-[120px] text-xs">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                </SelectContent>
              </Select>

              <Select value={tool} onValueChange={(v) => { setTool(v === "all" ? "" : v); setOffset(0); }}>
                <SelectTrigger className="h-8 w-[120px] text-xs">
                  <SelectValue placeholder="Tool" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Tools</SelectItem>
                  <SelectItem value="zap">ZAP</SelectItem>
                  <SelectItem value="sqlmap">SQLMap</SelectItem>
                  <SelectItem value="xsstrike">XSStrike/Dalfox</SelectItem>
                </SelectContent>
              </Select>

              <Select value={mitreTactic} onValueChange={(v) => { setMitreTactic(v === "all" ? "" : v); setOffset(0); }}>
                <SelectTrigger className="h-8 w-[160px] text-xs">
                  <SelectValue placeholder="MITRE Tactic" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Tactics</SelectItem>
                  {stats?.byMitreTactic && Object.keys(stats.byMitreTactic).map((tactic) => (
                    <SelectItem key={tactic} value={tactic}>{tactic}</SelectItem>
                  ))}
                </SelectContent>
              </Select>

              {activeFilters > 0 && (
                <Button variant="ghost" size="sm" onClick={clearFilters} className="h-8 text-xs text-muted-foreground">
                  Clear ({activeFilters})
                </Button>
              )}

              <div className="ml-auto text-xs text-muted-foreground">
                {findingsQuery.isLoading ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <span className="font-mono">{total} findings</span>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Findings List */}
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-2">
            {findingsQuery.isLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                <span className="ml-2 text-sm text-muted-foreground">Loading findings...</span>
              </div>
            ) : findings.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <Shield className="w-10 h-10 mb-3 opacity-30" />
                <p className="text-sm font-medium">No findings found</p>
                <p className="text-xs mt-1">
                  {activeFilters > 0 ? "Try adjusting your filters" : "Run a web application scan to populate findings"}
                </p>
              </div>
            ) : (
              <ScrollArea className="max-h-[600px]">
                <div className="space-y-1">
                  {findings.map((finding: any) => (
                    <FindingRow
                      key={finding.id}
                      finding={finding}
                      onClick={() => setSelectedFinding(finding)}
                    />
                  ))}
                </div>
              </ScrollArea>
            )}

            {/* Pagination */}
            {total > limit && (
              <div className="flex items-center justify-between pt-3 px-2 border-t border-border/30 mt-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!hasPrev}
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  className="h-7 text-xs"
                >
                  Previous
                </Button>
                <span className="text-xs text-muted-foreground">
                  {offset + 1}–{Math.min(offset + limit, total)} of {total}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!hasMore}
                  onClick={() => setOffset(offset + limit)}
                  className="h-7 text-xs"
                >
                  Next
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Finding Detail Dialog */}
        <FindingDetail
          finding={selectedFinding}
          open={!!selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      </div>
    </AppShell>
  );
}
