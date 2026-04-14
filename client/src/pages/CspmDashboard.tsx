import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  ChartContainer, ChartTooltip, ChartTooltipContent, ChartLegend, ChartLegendContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, BarChart, Bar, ResponsiveContainer, Area, AreaChart } from "recharts";
import {
  Shield, ShieldAlert, ShieldCheck, Activity, AlertTriangle, Bug,
  Clock, RefreshCw, Search, Filter, ChevronDown, ChevronRight,
  Container, Cloud, Server, FileCode, CheckCircle, XCircle,
  TrendingUp, BarChart3, Loader2, Info, Play, Zap, Rocket,
} from "lucide-react";
import { toast } from "sonner";

// ── Severity badge helper ─────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-500 text-white",
    medium: "bg-yellow-500 text-black",
    low: "bg-blue-500 text-white",
    info: "bg-gray-500 text-white",
    informational: "bg-gray-500 text-white",
    unknown: "bg-gray-400 text-white",
  };
  return (
    <Badge className={`${colors[severity?.toLowerCase()] || colors.unknown} text-xs font-medium`}>
      {severity?.toUpperCase()}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    completed: "bg-emerald-600 text-white",
    running: "bg-blue-500 text-white animate-pulse",
    pending: "bg-gray-500 text-white",
    error: "bg-red-600 text-white",
    cancelled: "bg-gray-400 text-white",
  };
  return (
    <Badge className={`${colors[status?.toLowerCase()] || "bg-gray-400 text-white"} text-xs`}>
      {status?.toUpperCase()}
    </Badge>
  );
}

function ToolBadge({ tool }: { tool: string }) {
  const colors: Record<string, string> = {
    prowler: "bg-purple-600/20 text-purple-300 border-purple-600/30",
    scoutsuite: "bg-cyan-600/20 text-cyan-300 border-cyan-600/30",
    trivy: "bg-emerald-600/20 text-emerald-300 border-emerald-600/30",
  };
  return (
    <Badge variant="outline" className={`${colors[tool?.toLowerCase()] || ""} text-xs`}>
      {tool}
    </Badge>
  );
}

// ── Stats Cards ───────────────────────────────────────────────────────────

function StatsOverview() {
  const { data: stats, isLoading } = trpc.cspmDashboard.getStats.useQuery();

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {[...Array(6)].map((_, i) => (
          <Card key={i} className="animate-pulse">
            <CardContent className="p-4">
              <div className="h-4 bg-muted rounded w-20 mb-2" />
              <div className="h-8 bg-muted rounded w-16" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  const items = [
    { label: "Total Scans", value: stats?.totalRuns ?? 0, icon: Activity, color: "text-blue-400" },
    { label: "Completed", value: stats?.completedRuns ?? 0, icon: CheckCircle, color: "text-emerald-400" },
    { label: "Total Findings", value: stats?.totalFindings ?? 0, icon: ShieldAlert, color: "text-amber-400" },
    { label: "Critical", value: stats?.totalCritical ?? 0, icon: AlertTriangle, color: "text-red-400" },
    { label: "High", value: stats?.totalHigh ?? 0, icon: Shield, color: "text-orange-400" },
    { label: "Avg Score", value: stats?.avgComplianceScore ? `${Math.round(stats.avgComplianceScore)}%` : "N/A", icon: TrendingUp, color: "text-cyan-400" },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {items.map((item) => (
        <Card key={item.label} className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-1">
              <item.icon className={`h-4 w-4 ${item.color}`} />
              <span className="text-xs text-muted-foreground">{item.label}</span>
            </div>
            <p className="text-2xl font-bold tabular-nums">{item.value}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ── Compliance Trend Chart ────────────────────────────────────────────────

const trendChartConfig: ChartConfig = {
  complianceScore: { label: "Compliance Score", color: "oklch(0.72 0.17 162)" },
  criticalCount: { label: "Critical", color: "oklch(0.63 0.24 25)" },
  highCount: { label: "High", color: "oklch(0.70 0.17 55)" },
};

function ComplianceTrendChart() {
  const [trendTool, setTrendTool] = useState<string>("all");
  const { data: trendData, isLoading } = trpc.cspmDashboard.getComplianceTrend.useQuery({
    tool: trendTool !== "all" ? trendTool as any : undefined,
    days: 90,
  });

  const chartData = useMemo(() => {
    if (!trendData?.length) return [];
    return trendData.map((d: any) => ({
      date: new Date(d.createdAt).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
      complianceScore: d.complianceScore ?? 0,
      criticalCount: d.criticalCount ?? 0,
      highCount: d.highCount ?? 0,
      tool: d.scanTool,
      provider: d.scanProvider,
    }));
  }, [trendData]);

  return (
    <Card className="bg-card/50 border-border/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <CardTitle className="text-lg flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-cyan-400" />
              Compliance Trend
            </CardTitle>
            <CardDescription>Score and critical findings over time (last 90 days)</CardDescription>
          </div>
          <Select value={trendTool} onValueChange={setTrendTool}>
            <SelectTrigger className="w-[130px] h-8 text-xs">
              <SelectValue placeholder="All Tools" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Tools</SelectItem>
              <SelectItem value="prowler">Prowler</SelectItem>
              <SelectItem value="scoutsuite">ScoutSuite</SelectItem>
              <SelectItem value="trivy">Trivy</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : chartData.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <BarChart3 className="h-10 w-10 mb-3 opacity-40" />
            <p className="text-sm">No completed scans yet</p>
            <p className="text-xs mt-1">Run a scan to start tracking compliance trends</p>
          </div>
        ) : (
          <ChartContainer config={trendChartConfig} className="h-[280px] w-full">
            <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 10, bottom: 0 }}>
              <defs>
                <linearGradient id="complianceGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="oklch(0.72 0.17 162)" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="oklch(0.72 0.17 162)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0 0)" />
              <XAxis dataKey="date" tick={{ fontSize: 11 }} stroke="oklch(0.5 0 0)" />
              <YAxis yAxisId="score" domain={[0, 100]} tick={{ fontSize: 11 }} stroke="oklch(0.5 0 0)" />
              <YAxis yAxisId="count" orientation="right" tick={{ fontSize: 11 }} stroke="oklch(0.5 0 0)" />
              <ChartTooltip content={<ChartTooltipContent />} />
              <ChartLegend content={<ChartLegendContent />} />
              <Area
                yAxisId="score"
                type="monotone"
                dataKey="complianceScore"
                stroke="oklch(0.72 0.17 162)"
                fill="url(#complianceGradient)"
                strokeWidth={2}
                name="Compliance Score"
              />
              <Line
                yAxisId="count"
                type="monotone"
                dataKey="criticalCount"
                stroke="oklch(0.63 0.24 25)"
                strokeWidth={2}
                dot={{ r: 3 }}
                name="Critical"
              />
              <Line
                yAxisId="count"
                type="monotone"
                dataKey="highCount"
                stroke="oklch(0.70 0.17 55)"
                strokeWidth={2}
                dot={{ r: 3 }}
                name="High"
              />
            </AreaChart>
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  );
}

// ── Scan History Table ────────────────────────────────────────────────────

function ScanHistoryTable({ onSelectRun }: { onSelectRun: (id: number) => void }) {
  const [toolFilter, setToolFilter] = useState<string>("all");
  const [providerFilter, setProviderFilter] = useState<string>("all");

  const { data: scans, isLoading, refetch } = trpc.cspmDashboard.getScanHistory.useQuery({
    tool: toolFilter !== "all" ? toolFilter as any : undefined,
    provider: providerFilter !== "all" ? providerFilter : undefined,
    limit: 100,
  });

  return (
    <Card className="bg-card/50 border-border/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <CardTitle className="text-lg flex items-center gap-2">
              <Clock className="h-5 w-5 text-blue-400" />
              Scan History
            </CardTitle>
            <CardDescription>Recent CSPM scan runs across all tools</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Select value={toolFilter} onValueChange={setToolFilter}>
              <SelectTrigger className="w-[130px] h-8 text-xs">
                <SelectValue placeholder="All Tools" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tools</SelectItem>
                <SelectItem value="prowler">Prowler</SelectItem>
                <SelectItem value="scoutsuite">ScoutSuite</SelectItem>
                <SelectItem value="trivy">Trivy</SelectItem>
              </SelectContent>
            </Select>
            <Select value={providerFilter} onValueChange={setProviderFilter}>
              <SelectTrigger className="w-[140px] h-8 text-xs">
                <SelectValue placeholder="All Providers" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Providers</SelectItem>
                <SelectItem value="aws">AWS</SelectItem>
                <SelectItem value="azure">Azure</SelectItem>
                <SelectItem value="gcp">GCP</SelectItem>
                <SelectItem value="digitalocean">DigitalOcean</SelectItem>
                <SelectItem value="docker">Docker</SelectItem>
                <SelectItem value="filesystem">Filesystem</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="ghost" size="sm" onClick={() => refetch()}>
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : !scans?.length ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Shield className="h-10 w-10 mb-3 opacity-40" />
            <p className="text-sm">No scan runs recorded yet</p>
            <p className="text-xs mt-1">Run a Prowler, ScoutSuite, or Trivy scan to see results here</p>
          </div>
        ) : (
          <ScrollArea className="max-h-[500px]">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-card/95 backdrop-blur">
                <tr className="border-b border-border/50">
                  <th className="text-left p-3 font-medium text-muted-foreground">Tool</th>
                  <th className="text-left p-3 font-medium text-muted-foreground">Provider</th>
                  <th className="text-left p-3 font-medium text-muted-foreground">Status</th>
                  <th className="text-right p-3 font-medium text-muted-foreground">Findings</th>
                  <th className="text-right p-3 font-medium text-muted-foreground">Critical</th>
                  <th className="text-right p-3 font-medium text-muted-foreground">High</th>
                  <th className="text-right p-3 font-medium text-muted-foreground">Score</th>
                  <th className="text-right p-3 font-medium text-muted-foreground">Duration</th>
                  <th className="text-right p-3 font-medium text-muted-foreground">Date</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan: any) => (
                  <tr
                    key={scan.id}
                    className="border-b border-border/30 hover:bg-muted/30 cursor-pointer transition-colors"
                    onClick={() => onSelectRun(scan.id)}
                  >
                    <td className="p-3"><ToolBadge tool={scan.scanTool} /></td>
                    <td className="p-3 text-xs">{scan.scanProvider}</td>
                    <td className="p-3"><StatusBadge status={scan.scanStatus} /></td>
                    <td className="p-3 text-right tabular-nums">{scan.totalFindings ?? 0}</td>
                    <td className="p-3 text-right tabular-nums">
                      <span className={scan.criticalCount > 0 ? "text-red-400 font-medium" : "text-muted-foreground"}>
                        {scan.criticalCount ?? 0}
                      </span>
                    </td>
                    <td className="p-3 text-right tabular-nums">
                      <span className={scan.highCount > 0 ? "text-orange-400 font-medium" : "text-muted-foreground"}>
                        {scan.highCount ?? 0}
                      </span>
                    </td>
                    <td className="p-3 text-right tabular-nums">
                      {scan.complianceScore != null ? (
                        <span className={scan.complianceScore >= 80 ? "text-emerald-400" : scan.complianceScore >= 50 ? "text-amber-400" : "text-red-400"}>
                          {scan.complianceScore}%
                        </span>
                      ) : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="p-3 text-right text-xs text-muted-foreground tabular-nums">
                      {scan.scanDurationMs ? `${(scan.scanDurationMs / 1000).toFixed(1)}s` : "—"}
                    </td>
                    <td className="p-3 text-right text-xs text-muted-foreground">
                      {scan.createdAt ? new Date(scan.createdAt).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}

// ── Findings Detail View ──────────────────────────────────────────────────

function FindingsDetail({ scanRunId, onBack }: { scanRunId: number; onBack: () => void }) {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState("");

  const { data: run, isLoading: runLoading } = trpc.cspmDashboard.getScanRun.useQuery({ id: scanRunId });
  const { data: findings, isLoading: findingsLoading } = trpc.cspmDashboard.getFindings.useQuery({
    scanRunId,
    severity: severityFilter !== "all" ? severityFilter : undefined,
    status: statusFilter !== "all" ? statusFilter : undefined,
    limit: 500,
  });
  const { data: containerVulns } = trpc.cspmDashboard.getContainerVulns.useQuery({
    scanRunId,
    severity: severityFilter !== "all" ? severityFilter : undefined,
    limit: 500,
  });

  const isTrivy = run?.scanTool === "trivy";
  const displayItems = isTrivy ? containerVulns : findings;

  const filteredItems = useMemo(() => {
    if (!displayItems) return [];
    if (!searchTerm) return displayItems;
    const lower = searchTerm.toLowerCase();
    return displayItems.filter((item: any) => {
      const searchable = [
        item.checkId || item.vulnId || "",
        item.checkTitle || item.title || "",
        item.description || "",
        item.service || item.pkgName || "",
        item.resourceName || item.imageName || "",
      ].join(" ").toLowerCase();
      return searchable.includes(lower);
    });
  }, [displayItems, searchTerm]);

  if (runLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3 flex-wrap">
        <Button variant="ghost" size="sm" onClick={onBack} className="gap-1">
          <ChevronRight className="h-4 w-4 rotate-180" /> Back
        </Button>
        <Separator orientation="vertical" className="h-6" />
        <ToolBadge tool={run?.scanTool || ""} />
        <StatusBadge status={run?.scanStatus || ""} />
        <span className="text-sm text-muted-foreground">{run?.scanProvider}</span>
        {run?.complianceFramework && (
          <Badge variant="outline" className="text-xs">{run.complianceFramework}</Badge>
        )}
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-3">
            <p className="text-xs text-muted-foreground">Total</p>
            <p className="text-xl font-bold">{run?.totalFindings ?? 0}</p>
          </CardContent>
        </Card>
        <Card className="bg-red-950/20 border-red-900/30">
          <CardContent className="p-3">
            <p className="text-xs text-red-400">Critical</p>
            <p className="text-xl font-bold text-red-400">{run?.criticalCount ?? 0}</p>
          </CardContent>
        </Card>
        <Card className="bg-orange-950/20 border-orange-900/30">
          <CardContent className="p-3">
            <p className="text-xs text-orange-400">High</p>
            <p className="text-xl font-bold text-orange-400">{run?.highCount ?? 0}</p>
          </CardContent>
        </Card>
        <Card className="bg-yellow-950/20 border-yellow-900/30">
          <CardContent className="p-3">
            <p className="text-xs text-yellow-400">Medium</p>
            <p className="text-xl font-bold text-yellow-400">{run?.mediumCount ?? 0}</p>
          </CardContent>
        </Card>
        <Card className="bg-blue-950/20 border-blue-900/30">
          <CardContent className="p-3">
            <p className="text-xs text-blue-400">Low</p>
            <p className="text-xl font-bold text-blue-400">{run?.lowCount ?? 0}</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search findings..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-9 h-9 text-sm"
          />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[120px] h-9 text-xs">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        {!isTrivy && (
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[120px] h-9 text-xs">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="fail">Fail</SelectItem>
              <SelectItem value="pass">Pass</SelectItem>
              <SelectItem value="warning">Warning</SelectItem>
            </SelectContent>
          </Select>
        )}
        <span className="text-xs text-muted-foreground ml-auto">
          {filteredItems.length} {isTrivy ? "vulnerabilities" : "findings"}
        </span>
      </div>

      {/* Findings List */}
      {findingsLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <ScrollArea className="max-h-[600px]">
          <div className="space-y-2">
            {filteredItems.map((item: any, idx: number) => (
              <FindingCard key={item.id || idx} item={item} isTrivy={isTrivy} />
            ))}
            {filteredItems.length === 0 && (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <ShieldCheck className="h-10 w-10 mb-3 opacity-40" />
                <p className="text-sm">No findings match your filters</p>
              </div>
            )}
          </div>
        </ScrollArea>
      )}
    </div>
  );
}

// ── Individual Finding Card ───────────────────────────────────────────────

function FindingCard({ item, isTrivy }: { item: any; isTrivy: boolean }) {
  const [expanded, setExpanded] = useState(false);

  if (isTrivy) {
    return (
      <Card className="bg-card/50 border-border/30 hover:border-border/60 transition-colors">
        <CardContent className="p-3">
          <div className="flex items-start gap-3">
            <div className="shrink-0 mt-0.5">
              <SeverityBadge severity={item.severity} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-sm font-medium text-blue-400">{item.vulnId}</span>
                <span className="text-xs text-muted-foreground">in</span>
                <span className="text-sm font-medium">{item.pkgName}</span>
              </div>
              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{item.title || item.description}</p>
              <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground flex-wrap">
                <span>Image: <span className="text-foreground">{item.imageName}</span></span>
                {item.installedVersion && <span>Installed: <span className="font-mono">{item.installedVersion}</span></span>}
                {item.fixedVersion && <span>Fix: <span className="font-mono text-emerald-400">{item.fixedVersion}</span></span>}
                {item.cvssScore && <span>CVSS: <span className="font-medium">{item.cvssScore}</span></span>}
              </div>
            </div>
            {item.primaryUrl && (
              <a href={item.primaryUrl} target="_blank" rel="noopener noreferrer" className="shrink-0">
                <Button variant="ghost" size="sm" className="h-7 text-xs">Details</Button>
              </a>
            )}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-card/50 border-border/30 hover:border-border/60 transition-colors">
      <CardContent className="p-3">
        <div
          className="flex items-start gap-3 cursor-pointer"
          onClick={() => setExpanded(!expanded)}
        >
          <div className="shrink-0 mt-0.5">
            <SeverityBadge severity={item.severity} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              {item.checkId && <span className="font-mono text-xs text-muted-foreground">{item.checkId}</span>}
              <Badge variant="outline" className="text-xs">{item.status}</Badge>
            </div>
            <p className="text-sm font-medium mt-1">{item.checkTitle}</p>
            <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground flex-wrap">
              {item.service && <span>Service: <span className="text-foreground">{item.service}</span></span>}
              {item.region && <span>Region: {item.region}</span>}
              {item.resourceName && <span>Resource: <span className="text-foreground">{item.resourceName}</span></span>}
            </div>
          </div>
          <ChevronDown className={`h-4 w-4 shrink-0 text-muted-foreground transition-transform ${expanded ? "rotate-180" : ""}`} />
        </div>

        {expanded && (
          <div className="mt-3 pt-3 border-t border-border/30 space-y-2 text-sm">
            {item.description && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-1">Description</p>
                <p className="text-sm">{item.description}</p>
              </div>
            )}
            {item.riskDetails && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-1">Risk</p>
                <p className="text-sm">{item.riskDetails}</p>
              </div>
            )}
            {item.remediation && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-1">Remediation</p>
                <p className="text-sm text-emerald-400">{item.remediation}</p>
              </div>
            )}
            {item.resourceArn && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-1">Resource ARN</p>
                <p className="text-xs font-mono break-all">{item.resourceArn}</p>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── Launch Scan Dialog ────────────────────────────────────────────────────

function LaunchScanButton() {
  const [open, setOpen] = useState(false);
  const [selectedTool, setSelectedTool] = useState<string>("prowler");
  const [selectedCredId, setSelectedCredId] = useState<string>("");
  const [trivyImage, setTrivyImage] = useState("");
  const [trivyTag, setTrivyTag] = useState("latest");
  const [compliance, setCompliance] = useState("");
  const [services, setServices] = useState("");

  const utils = trpc.useUtils();
  const { data: creds } = trpc.cloudCredentials.listCredentials.useQuery(undefined, { enabled: open });

  const launchFromCred = trpc.cspmDashboard.launchScanFromCredential.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.tool} scan completed`, {
        description: `${data.totalFindings} findings in ${(data.durationMs / 1000).toFixed(1)}s`,
      });
      utils.cspmDashboard.getStats.invalidate();
      utils.cspmDashboard.getScanHistory.invalidate();
      utils.cspmDashboard.getComplianceTrend.invalidate();
      setOpen(false);
    },
    onError: (err) => {
      toast.error("Scan failed", { description: err.message });
    },
  });

  const launchTrivy = trpc.cspmDashboard.runTrivyScan.useMutation({
    onSuccess: (data) => {
      toast.success("Trivy scan completed", {
        description: `${data.totalVulns} vulnerabilities found in ${(data.durationMs / 1000).toFixed(1)}s`,
      });
      utils.cspmDashboard.getStats.invalidate();
      utils.cspmDashboard.getScanHistory.invalidate();
      utils.cspmDashboard.getComplianceTrend.invalidate();
      setOpen(false);
    },
    onError: (err) => {
      toast.error("Trivy scan failed", { description: err.message });
    },
  });

  const isRunning = launchFromCred.isPending || launchTrivy.isPending;

  const handleLaunch = () => {
    if (selectedTool === "trivy") {
      if (!trivyImage) {
        toast.error("Please enter a Docker image name");
        return;
      }
      launchTrivy.mutate({
        image: trivyImage,
        imageTag: trivyTag || "latest",
      });
    } else {
      if (!selectedCredId) {
        toast.error("Please select a credential");
        return;
      }
      launchFromCred.mutate({
        credentialId: Number(selectedCredId),
        tool: selectedTool as "prowler" | "scoutsuite",
        services: services ? services.split(",").map(s => s.trim()).filter(Boolean) : undefined,
        compliance: compliance || undefined,
        timeoutSeconds: 600,
      });
    }
  };

  return (
    <>
      <Button onClick={() => setOpen(true)} className="gap-2 bg-purple-600 hover:bg-purple-700">
        <Rocket className="h-4 w-4" />
        Launch Scan
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Zap className="h-5 w-5 text-purple-400" />
              Launch CSPM Scan
            </DialogTitle>
            <DialogDescription>
              Select a tool and credential to run a cloud security scan. Results will be persisted automatically.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            {/* Tool Selection */}
            <div className="space-y-2">
              <Label>Scan Tool</Label>
              <Select value={selectedTool} onValueChange={setSelectedTool}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="prowler">
                    <span className="flex items-center gap-2">
                      <Shield className="h-4 w-4 text-purple-400" /> Prowler (CIS Benchmarks)
                    </span>
                  </SelectItem>
                  <SelectItem value="scoutsuite">
                    <span className="flex items-center gap-2">
                      <Cloud className="h-4 w-4 text-cyan-400" /> ScoutSuite (Multi-Cloud Audit)
                    </span>
                  </SelectItem>
                  <SelectItem value="trivy">
                    <span className="flex items-center gap-2">
                      <Container className="h-4 w-4 text-emerald-400" /> Trivy (Container Scan)
                    </span>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Credential or Image selection */}
            {selectedTool === "trivy" ? (
              <div className="space-y-3">
                <div className="space-y-2">
                  <Label>Docker Image</Label>
                  <Input
                    placeholder="e.g. nginx, ubuntu, myregistry/myapp"
                    value={trivyImage}
                    onChange={(e) => setTrivyImage(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Tag</Label>
                  <Input
                    placeholder="latest"
                    value={trivyTag}
                    onChange={(e) => setTrivyTag(e.target.value)}
                  />
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="space-y-2">
                  <Label>Cloud Credential</Label>
                  <Select value={selectedCredId} onValueChange={setSelectedCredId}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select a stored credential..." />
                    </SelectTrigger>
                    <SelectContent>
                      {creds?.map((c: any) => (
                        <SelectItem key={c.id} value={String(c.id)}>
                          <span className="flex items-center gap-2">
                            <Badge variant="outline" className="text-xs">{c.provider?.toUpperCase()}</Badge>
                            {c.credentialName}
                          </span>
                        </SelectItem>
                      ))}
                      {(!creds || creds.length === 0) && (
                        <div className="p-3 text-xs text-muted-foreground text-center">
                          No credentials stored. Add one in Cloud Credentials first.
                        </div>
                      )}
                    </SelectContent>
                  </Select>
                </div>

                {selectedTool === "prowler" && (
                  <div className="space-y-2">
                    <Label>Compliance Framework (optional)</Label>
                    <Select value={compliance} onValueChange={setCompliance}>
                      <SelectTrigger>
                        <SelectValue placeholder="None (all checks)" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">None (all checks)</SelectItem>
                        <SelectItem value="cis_1.5_aws">CIS 1.5 AWS</SelectItem>
                        <SelectItem value="cis_2.0_aws">CIS 2.0 AWS</SelectItem>
                        <SelectItem value="cis_3.0_aws">CIS 3.0 AWS</SelectItem>
                        <SelectItem value="cis_2.0_azure">CIS 2.0 Azure</SelectItem>
                        <SelectItem value="cis_2.0_gcp">CIS 2.0 GCP</SelectItem>
                        <SelectItem value="pci_3.2.1_aws">PCI DSS 3.2.1</SelectItem>
                        <SelectItem value="hipaa_aws">HIPAA</SelectItem>
                        <SelectItem value="soc2_aws">SOC2</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                )}

                <div className="space-y-2">
                  <Label>Services (optional, comma-separated)</Label>
                  <Input
                    placeholder="e.g. s3, ec2, iam"
                    value={services}
                    onChange={(e) => setServices(e.target.value)}
                  />
                </div>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="ghost" onClick={() => setOpen(false)} disabled={isRunning}>
              Cancel
            </Button>
            <Button
              onClick={handleLaunch}
              disabled={isRunning}
              className="gap-2 bg-purple-600 hover:bg-purple-700"
            >
              {isRunning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" />
                  Launch Scan
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────

export default function CspmDashboard() {
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);

  return (
    <div className="space-y-6 p-1">
      {/* Page Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-purple-400" />
            CSPM Dashboard
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Cloud Security Posture Management — Prowler, ScoutSuite, and Trivy scan results with historical tracking
          </p>
        </div>
        <LaunchScanButton />
      </div>

      {selectedRunId ? (
        <FindingsDetail scanRunId={selectedRunId} onBack={() => setSelectedRunId(null)} />
      ) : (
        <>
          {/* Stats */}
          <StatsOverview />

          {/* Compliance Trend Chart */}
          <ComplianceTrendChart />

          {/* Scan History */}
          <ScanHistoryTable onSelectRun={setSelectedRunId} />
        </>
      )}
    </div>
  );
}
