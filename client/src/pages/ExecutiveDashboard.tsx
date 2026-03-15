import { trpc } from "@/lib/trpc";
import { useState, useMemo } from "react";
import { useLocation } from "wouter";
import {
  Shield, TrendingUp, TrendingDown, AlertTriangle, CheckCircle2,
  BarChart3, PieChart, Activity, Building2, Target, Clock,
  ChevronRight, ArrowUpRight, ArrowDownRight, Minus,
  ShieldCheck, ShieldAlert, FileText, Layers, Globe,
  Briefcase, Lock, Eye, Zap, Users, Download, Crosshair, Cpu
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";

// ─── Risk Score Gauge ──────────────────────────────────────────────────────
function RiskGauge({ score, level }: { score: number; level: string }) {
  const color = level === "critical" ? "text-red-500" :
                level === "high" ? "text-orange-500" :
                level === "medium" ? "text-yellow-500" :
                level === "low" ? "text-emerald-500" : "text-cyan-500";
  const bgColor = level === "critical" ? "from-red-500/20 to-red-500/5" :
                  level === "high" ? "from-orange-500/20 to-orange-500/5" :
                  level === "medium" ? "from-yellow-500/20 to-yellow-500/5" :
                  level === "low" ? "from-emerald-500/20 to-emerald-500/5" : "from-cyan-500/20 to-cyan-500/5";
  const ringColor = level === "critical" ? "stroke-red-500" :
                    level === "high" ? "stroke-orange-500" :
                    level === "medium" ? "stroke-yellow-500" :
                    level === "low" ? "stroke-emerald-500" : "stroke-cyan-500";

  const circumference = 2 * Math.PI * 80;
  const dashOffset = circumference - (score / 100) * circumference;

  return (
    <div className={`relative flex flex-col items-center justify-center p-8 rounded-2xl bg-gradient-to-b ${bgColor}`}>
      <svg width="200" height="200" viewBox="0 0 200 200" className="transform -rotate-90">
        <circle cx="100" cy="100" r="80" fill="none" stroke="currentColor" strokeWidth="12"
          className="text-muted/20" />
        <circle cx="100" cy="100" r="80" fill="none" strokeWidth="12"
          className={`${ringColor} transition-all duration-1000 ease-out`}
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          strokeLinecap="round" />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`text-5xl font-bold tabular-nums ${color}`}>{score}</span>
        <span className="text-sm text-muted-foreground mt-1 uppercase tracking-wider font-medium">{level} risk</span>
      </div>
    </div>
  );
}

// ─── Stat Card ─────────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, trend, trendLabel, variant = "default" }: {
  icon: any; label: string; value: string | number; trend?: "up" | "down" | "flat";
  trendLabel?: string; variant?: "default" | "danger" | "warning" | "success";
}) {
  const borderColor = variant === "danger" ? "border-red-500/30" :
                      variant === "warning" ? "border-yellow-500/30" :
                      variant === "success" ? "border-emerald-500/30" : "border-border";
  const iconColor = variant === "danger" ? "text-red-500" :
                    variant === "warning" ? "text-yellow-500" :
                    variant === "success" ? "text-emerald-500" : "text-primary";

  return (
    <Card className={`${borderColor}`}>
      <CardContent className="p-5">
        <div className="flex items-start justify-between">
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground uppercase tracking-wider">{label}</span>
            <span className="text-2xl font-bold tabular-nums">{value}</span>
          </div>
          <div className={`p-2 rounded-lg bg-muted/50 ${iconColor}`}>
            <Icon className="w-5 h-5" />
          </div>
        </div>
        {trend && trendLabel && (
          <div className="flex items-center gap-1 mt-2 text-xs">
            {trend === "up" ? <ArrowUpRight className="w-3 h-3 text-red-500" /> :
             trend === "down" ? <ArrowDownRight className="w-3 h-3 text-emerald-500" /> :
             <Minus className="w-3 h-3 text-muted-foreground" />}
            <span className={trend === "up" ? "text-red-500" : trend === "down" ? "text-emerald-500" : "text-muted-foreground"}>
              {trendLabel}
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Compliance Framework Card ─────────────────────────────────────────────
function ComplianceCard({ framework, version, percent, passed, total, status }: {
  framework: string; version: string; percent: number; passed: number; total: number; status: string;
}) {
  const statusColor = status === "compliant" ? "text-emerald-500" :
                      status === "partial" ? "text-yellow-500" : "text-red-500";
  const statusBg = status === "compliant" ? "bg-emerald-500/10" :
                   status === "partial" ? "bg-yellow-500/10" : "bg-red-500/10";
  const progressColor = status === "compliant" ? "[&>div]:bg-emerald-500" :
                        status === "partial" ? "[&>div]:bg-yellow-500" : "[&>div]:bg-red-500";

  // Clean up framework name for display
  const displayName = framework
    .replace(/_/g, " ")
    .replace("NIST AI RMF", "NIST AI RMF 1.0")
    .replace("NIST AI 600 1", "NIST AI 600-1 (GenAI)")
    .replace("OMB M 24 10", "OMB M-24-10")
    .replace("DOD RAI", "DoD RAI")
    .replace("EO 14110", "EO 14110")
    .replace("MITRE ATLAS", "MITRE ATLAS")
    .replace("CMMC AI", "CMMC 2.0 AI")
    .replace("FEDRAMP AI", "FedRAMP AI");

  return (
    <Card className="hover:border-primary/30 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-3">
          <div>
            <h4 className="font-semibold text-sm">{displayName}</h4>
            <span className="text-xs text-muted-foreground">v{version}</span>
          </div>
          <Badge variant="outline" className={`${statusColor} ${statusBg} border-0 text-xs`}>
            {status === "compliant" ? "Compliant" : status === "partial" ? "Partial" : "Non-Compliant"}
          </Badge>
        </div>
        <Progress value={percent} className={`h-2 mb-2 ${progressColor}`} />
        <div className="flex justify-between text-xs text-muted-foreground">
          <span>{passed}/{total} controls</span>
          <span className="font-medium">{percent}%</span>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Business Impact Indicator ─────────────────────────────────────────────
function ImpactIndicator({ label, value, status, unit }: {
  label: string; value: number; status: string; unit?: string;
}) {
  const color = status === "critical" ? "text-red-500" :
                status === "warning" ? "text-yellow-500" : "text-emerald-500";
  const bgColor = status === "critical" ? "bg-red-500" :
                  status === "warning" ? "bg-yellow-500" : "bg-emerald-500";
  const progressColor = status === "critical" ? "[&>div]:bg-red-500" :
                        status === "warning" ? "[&>div]:bg-yellow-500" : "[&>div]:bg-emerald-500";

  return (
    <div className="flex flex-col gap-2 p-4 rounded-lg bg-muted/30 border">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">{label}</span>
        <span className={`text-lg font-bold tabular-nums ${color}`}>
          {value}{unit ? ` ${unit}` : unit === undefined ? "%" : ""}
        </span>
      </div>
      <Progress value={Math.min(100, value)} className={`h-1.5 ${progressColor}`} />
    </div>
  );
}

// ─── Severity Bar Chart ────────────────────────────────────────────────────
function SeverityBars({ critical, high, medium, low, info }: {
  critical: number; high: number; medium: number; low: number; info: number;
}) {
  const max = Math.max(critical, high, medium, low, info, 1);
  const bars = [
    { label: "Critical", value: critical, color: "bg-red-500", textColor: "text-red-500" },
    { label: "High", value: high, color: "bg-orange-500", textColor: "text-orange-500" },
    { label: "Medium", value: medium, color: "bg-yellow-500", textColor: "text-yellow-500" },
    { label: "Low", value: low, color: "bg-emerald-500", textColor: "text-emerald-500" },
    { label: "Info", value: info, color: "bg-cyan-500", textColor: "text-cyan-500" },
  ];

  return (
    <div className="flex flex-col gap-3">
      {bars.map(b => (
        <div key={b.label} className="flex items-center gap-3">
          <span className={`text-xs font-medium w-16 ${b.textColor}`}>{b.label}</span>
          <div className="flex-1 h-6 bg-muted/30 rounded overflow-hidden">
            <div className={`h-full ${b.color} rounded transition-all duration-700 ease-out flex items-center justify-end pr-2`}
              style={{ width: `${Math.max(2, (b.value / max) * 100)}%` }}>
              {b.value > 0 && <span className="text-xs font-bold text-white">{b.value}</span>}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Top Risks Table ───────────────────────────────────────────────────────
function TopRisksTable({ categories }: { categories: Array<{
  category: string; total: number; critical: number; high: number; riskWeight: number;
}> }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border/50">
            <th className="text-left py-2 px-3 text-xs text-muted-foreground font-medium">Category</th>
            <th className="text-center py-2 px-3 text-xs text-muted-foreground font-medium">Total</th>
            <th className="text-center py-2 px-3 text-xs text-muted-foreground font-medium">Critical</th>
            <th className="text-center py-2 px-3 text-xs text-muted-foreground font-medium">High</th>
            <th className="text-right py-2 px-3 text-xs text-muted-foreground font-medium">Risk Weight</th>
          </tr>
        </thead>
        <tbody>
          {categories.map((c, i) => (
            <tr key={i} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
              <td className="py-2.5 px-3 font-medium">{c.category}</td>
              <td className="py-2.5 px-3 text-center tabular-nums">{c.total}</td>
              <td className="py-2.5 px-3 text-center">
                {c.critical > 0 ? <Badge variant="destructive" className="text-xs">{c.critical}</Badge> : <span className="text-muted-foreground">0</span>}
              </td>
              <td className="py-2.5 px-3 text-center">
                {c.high > 0 ? <Badge variant="outline" className="text-orange-500 border-orange-500/30 text-xs">{c.high}</Badge> : <span className="text-muted-foreground">0</span>}
              </td>
              <td className="py-2.5 px-3 text-right">
                <div className="flex items-center justify-end gap-2">
                  <div className="w-16 h-1.5 bg-muted/30 rounded overflow-hidden">
                    <div className="h-full bg-red-500 rounded" style={{ width: `${Math.min(100, c.riskWeight)}%` }} />
                  </div>
                  <span className="text-xs tabular-nums text-muted-foreground w-6">{c.riskWeight}</span>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Main Executive Dashboard ──────────────────────────────────────────────
export default function ExecutiveDashboard() {
  const [, navigate] = useLocation();
  const [selectedEngagementId, setSelectedEngagementId] = useState<number | null>(null);
  const [exportingPdf, setExportingPdf] = useState(false);

  const { data: riskPosture, isLoading: riskLoading } = trpc.executiveDashboard.riskPosture.useQuery();
  const { data: compliance, isLoading: compLoading } = trpc.executiveDashboard.complianceOverview.useQuery();
  const { data: impact, isLoading: impactLoading } = trpc.executiveDashboard.businessImpact.useQuery();
  const { data: topRisks, isLoading: risksLoading } = trpc.executiveDashboard.topRisks.useQuery();
  const { data: engagements, isLoading: engLoading } = trpc.executiveDashboard.engagementSummary.useQuery();
  const { data: threatSummary } = trpc.threatIntelMatching.summary.useQuery();

  // Threat group matching for selected engagement
  const matchInput = useMemo(() => selectedEngagementId ? { engagementId: selectedEngagementId } : null, [selectedEngagementId]);
  const { data: threatMatches, isLoading: threatLoading } = trpc.threatIntelMatching.matchGroups.useQuery(
    matchInput as { engagementId: number },
    { enabled: !!selectedEngagementId }
  );

  // PDF export handler
  const handleExportPdf = async () => {
    setExportingPdf(true);
    try {
      // Trigger browser print dialog for PDF generation
      window.print();
      toast.success("PDF export initiated — use your browser's print dialog to save.");
    } catch {
      toast.error("PDF export failed");
    } finally {
      setExportingPdf(false);
    }
  };

  return (
    <div className="flex flex-col gap-6 p-6 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="w-7 h-7 text-primary" />
            Executive Security Overview
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Risk posture, compliance status, and business impact at a glance
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant="outline" className="text-xs">
            <Clock className="w-3 h-3 mr-1" />
            Last updated: {new Date().toLocaleDateString()}
          </Badge>
          <Button variant="outline" size="sm" onClick={handleExportPdf} disabled={exportingPdf}>
            <Download className="w-4 h-4 mr-1" />
            {exportingPdf ? "Exporting..." : "Export PDF"}
          </Button>
        </div>
      </div>

      {/* Risk Posture + Key Stats Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Risk Gauge */}
        <div className="lg:col-span-4">
          <Card className="h-full">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <ShieldAlert className="w-4 h-4" />
                Organization Risk Score
              </CardTitle>
            </CardHeader>
            <CardContent className="flex justify-center">
              {riskLoading ? (
                <Skeleton className="w-[200px] h-[200px] rounded-full" />
              ) : (
                <RiskGauge score={riskPosture?.riskScore || 0} level={riskPosture?.riskLevel || "minimal"} />
              )}
            </CardContent>
          </Card>
        </div>

        {/* Key Metrics */}
        <div className="lg:col-span-8 grid grid-cols-2 md:grid-cols-4 gap-4">
          {riskLoading ? (
            Array(4).fill(0).map((_, i) => <Skeleton key={i} className="h-[120px]" />)
          ) : (
            <>
              <StatCard
                icon={AlertTriangle}
                label="Critical Vulns"
                value={riskPosture?.vulnerabilities.critical || 0}
                variant={riskPosture?.vulnerabilities.critical ? "danger" : "default"}
                trend="flat"
                trendLabel="Requires attention"
              />
              <StatCard
                icon={Target}
                label="Total Findings"
                value={riskPosture?.vulnerabilities.total || 0}
                variant="default"
                trend="flat"
                trendLabel="Across all engagements"
              />
              <StatCard
                icon={Briefcase}
                label="Active Engagements"
                value={riskPosture?.engagements.active || 0}
                variant="default"
                trend="flat"
                trendLabel={`${riskPosture?.engagements.completed || 0} completed`}
              />
              <StatCard
                icon={ShieldCheck}
                label="AI Compliance"
                value={`${compliance?.overallCompliance || 0}%`}
                variant={
                  (compliance?.overallCompliance || 0) >= 80 ? "success" :
                  (compliance?.overallCompliance || 0) >= 50 ? "warning" : "danger"
                }
                trend="flat"
                trendLabel="8 frameworks assessed"
              />
            </>
          )}
        </div>
      </div>

      {/* Tabbed Content */}
      <Tabs defaultValue="risk" className="w-full">
        <TabsList className="w-full justify-start bg-muted/30 p-1">
          <TabsTrigger value="risk" className="gap-1.5">
            <ShieldAlert className="w-4 h-4" /> Risk Analysis
          </TabsTrigger>
          <TabsTrigger value="compliance" className="gap-1.5">
            <CheckCircle2 className="w-4 h-4" /> Compliance
          </TabsTrigger>
          <TabsTrigger value="impact" className="gap-1.5">
            <BarChart3 className="w-4 h-4" /> Business Impact
          </TabsTrigger>
          <TabsTrigger value="engagements" className="gap-1.5">
            <Layers className="w-4 h-4" /> Engagements
          </TabsTrigger>
          <TabsTrigger value="threats" className="gap-1.5">
            <Crosshair className="w-4 h-4" /> Threat Groups
          </TabsTrigger>
        </TabsList>

        {/* Risk Analysis Tab */}
        <TabsContent value="risk" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-primary" />
                  Vulnerability Severity Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                {riskLoading ? (
                  <Skeleton className="h-[200px]" />
                ) : (
                  <SeverityBars
                    critical={riskPosture?.vulnerabilities.critical || 0}
                    high={riskPosture?.vulnerabilities.high || 0}
                    medium={riskPosture?.vulnerabilities.medium || 0}
                    low={riskPosture?.vulnerabilities.low || 0}
                    info={riskPosture?.vulnerabilities.info || 0}
                  />
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-orange-500" />
                  Top Risk Categories
                </CardTitle>
              </CardHeader>
              <CardContent>
                {risksLoading ? (
                  <Skeleton className="h-[200px]" />
                ) : (
                  <TopRisksTable categories={topRisks?.categories || []} />
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Compliance Tab */}
        <TabsContent value="compliance" className="mt-4">
          <div className="flex flex-col gap-6">
            {/* Overall Compliance Score */}
            <Card className="border-primary/20">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-semibold">Overall AI Compliance Score</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      Aggregate compliance across {compliance?.frameworks.length || 8} U.S. government frameworks
                    </p>
                  </div>
                  <div className="text-right">
                    <span className={`text-4xl font-bold tabular-nums ${
                      (compliance?.overallCompliance || 0) >= 80 ? "text-emerald-500" :
                      (compliance?.overallCompliance || 0) >= 50 ? "text-yellow-500" : "text-red-500"
                    }`}>
                      {compliance?.overallCompliance || 0}%
                    </span>
                    <p className="text-xs text-muted-foreground mt-1">
                      Last assessed: {new Date(compliance?.lastAssessed || Date.now()).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                <Progress
                  value={compliance?.overallCompliance || 0}
                  className={`h-3 mt-4 ${
                    (compliance?.overallCompliance || 0) >= 80 ? "[&>div]:bg-emerald-500" :
                    (compliance?.overallCompliance || 0) >= 50 ? "[&>div]:bg-yellow-500" : "[&>div]:bg-red-500"
                  }`}
                />
              </CardContent>
            </Card>

            {/* Framework Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {compLoading ? (
                Array(8).fill(0).map((_, i) => <Skeleton key={i} className="h-[140px]" />)
              ) : (
                compliance?.frameworks.map((fw, i) => (
                  <ComplianceCard
                    key={i}
                    framework={fw.framework}
                    version={fw.version}
                    percent={fw.compliancePercent}
                    passed={fw.controlsPassed}
                    total={fw.controlsTotal}
                    status={fw.overallStatus}
                  />
                ))
              )}
            </div>
          </div>
        </TabsContent>

        {/* Business Impact Tab */}
        <TabsContent value="impact" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Zap className="w-4 h-4 text-yellow-500" />
                  Business Risk Indicators
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-3">
                {impactLoading ? (
                  Array(4).fill(0).map((_, i) => <Skeleton key={i} className="h-[70px]" />)
                ) : (
                  impact?.indicators.map((ind, i) => (
                    <ImpactIndicator
                      key={i}
                      label={ind.label}
                      value={ind.value}
                      status={ind.status}
                      unit={ind.unit}
                    />
                  ))
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Target className="w-4 h-4 text-primary" />
                  Exploit & Coverage Metrics
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                {impactLoading ? (
                  <Skeleton className="h-[200px]" />
                ) : (
                  <>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-center">
                        <span className="text-3xl font-bold text-red-500 tabular-nums">{impact?.exploitableVulns || 0}</span>
                        <p className="text-xs text-muted-foreground mt-1">Exploitable Vulns</p>
                      </div>
                      <div className="p-4 rounded-lg bg-primary/10 border border-primary/20 text-center">
                        <span className="text-3xl font-bold text-primary tabular-nums">{impact?.pipelineCoverage || 0}%</span>
                        <p className="text-xs text-muted-foreground mt-1">Pipeline Coverage</p>
                      </div>
                    </div>

                    <div className="p-4 rounded-lg bg-muted/30 border">
                      <h4 className="text-sm font-medium mb-3">Pipeline Status Breakdown</h4>
                      <div className="flex flex-col gap-2">
                        {Object.entries(impact?.pipelineBreakdown || {}).map(([status, count]) => (
                          <div key={status} className="flex items-center justify-between text-sm">
                            <span className="capitalize text-muted-foreground">{status}</span>
                            <Badge variant="outline" className="text-xs tabular-nums">{count as number}</Badge>
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Engagements Tab */}
        <TabsContent value="engagements" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Layers className="w-4 h-4 text-primary" />
                Recent Engagements
              </CardTitle>
            </CardHeader>
            <CardContent>
              {engLoading ? (
                <Skeleton className="h-[300px]" />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border/50">
                        <th className="text-left py-2 px-3 text-xs text-muted-foreground font-medium">Engagement</th>
                        <th className="text-left py-2 px-3 text-xs text-muted-foreground font-medium">Client</th>
                        <th className="text-left py-2 px-3 text-xs text-muted-foreground font-medium">Sector</th>
                        <th className="text-left py-2 px-3 text-xs text-muted-foreground font-medium">Target</th>
                        <th className="text-center py-2 px-3 text-xs text-muted-foreground font-medium">Mode</th>
                        <th className="text-center py-2 px-3 text-xs text-muted-foreground font-medium">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(engagements?.engagements || []).map((eng) => (
                        <tr key={eng.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                          <td className="py-2.5 px-3 font-medium">{eng.name}</td>
                          <td className="py-2.5 px-3 text-muted-foreground">{eng.clientName || "—"}</td>
                          <td className="py-2.5 px-3">
                            {eng.sector ? <Badge variant="outline" className="text-xs">{eng.sector}</Badge> : "—"}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-xs">{eng.targetDomain || "—"}</td>
                          <td className="py-2.5 px-3 text-center">
                            <Badge variant={eng.scanMode === "active" ? "destructive" : "outline"} className="text-xs">
                              {eng.scanMode || "passive"}
                            </Badge>
                          </td>
                          <td className="py-2.5 px-3 text-center">
                            <Badge variant={eng.status === "active" ? "default" : "secondary"} className="text-xs">
                              {eng.status || "unknown"}
                            </Badge>
                          </td>
                        </tr>
                      ))}
                      {(!engagements?.engagements || engagements.engagements.length === 0) && (
                        <tr>
                          <td colSpan={6} className="py-8 text-center text-muted-foreground">
                            No engagements found
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        {/* Threat Groups Tab */}
        <TabsContent value="threats" className="mt-4">
          <div className="flex flex-col gap-6">
            {/* Threat Intel Summary */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Card>
                <CardContent className="p-4 text-center">
                  <Crosshair className="w-5 h-5 mx-auto mb-1 text-red-500" />
                  <div className="text-2xl font-bold tabular-nums">{threatSummary?.totalGroups || 0}</div>
                  <div className="text-xs text-muted-foreground">Threat Groups Tracked</div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <Cpu className="w-5 h-5 mx-auto mb-1 text-primary" />
                  <div className="text-2xl font-bold tabular-nums">{threatSummary?.totalTechniques || 0}</div>
                  <div className="text-xs text-muted-foreground">Unique TTPs</div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <Building2 className="w-5 h-5 mx-auto mb-1 text-blue-500" />
                  <div className="text-2xl font-bold tabular-nums">{threatSummary?.fedrampProviderCount || 0}</div>
                  <div className="text-xs text-muted-foreground">FedRAMP Providers</div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <AlertTriangle className="w-5 h-5 mx-auto mb-1 text-orange-500" />
                  <div className="text-2xl font-bold tabular-nums">{threatSummary?.activeGroups || 0}</div>
                  <div className="text-xs text-muted-foreground">Active Groups</div>
                </CardContent>
              </Card>
            </div>

            {/* Engagement Selector for Threat Matching */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <Target className="w-4 h-4 text-primary" />
                    Threat Group Matching
                  </span>
                  <div className="w-[300px]">
                    <Select
                      value={selectedEngagementId?.toString() || ""}
                      onValueChange={(v) => setSelectedEngagementId(v ? Number(v) : null)}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select an engagement to match..." />
                      </SelectTrigger>
                      <SelectContent>
                        {(engagements?.engagements || []).map((eng) => (
                          <SelectItem key={eng.id} value={eng.id.toString()}>
                            {eng.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!selectedEngagementId ? (
                  <div className="py-12 text-center text-muted-foreground">
                    <Crosshair className="w-8 h-8 mx-auto mb-3 opacity-30" />
                    <p>Select an engagement above to match against known threat groups.</p>
                    <p className="text-xs mt-1">The matching engine correlates TTPs, CVEs, tools, and sector targeting.</p>
                  </div>
                ) : threatLoading ? (
                  <div className="flex flex-col gap-3">
                    {Array(3).fill(0).map((_, i) => <Skeleton key={i} className="h-[100px]" />)}
                  </div>
                ) : !threatMatches?.matches.length ? (
                  <div className="py-12 text-center text-muted-foreground">
                    <ShieldCheck className="w-8 h-8 mx-auto mb-3 opacity-30" />
                    <p>No threat group matches found for this engagement.</p>
                    <p className="text-xs mt-1">This may indicate the engagement has limited findings or uses novel TTPs.</p>
                  </div>
                ) : (
                  <div className="flex flex-col gap-3">
                    <p className="text-xs text-muted-foreground">
                      Analyzed {threatMatches.totalGroupsAnalyzed} groups — {threatMatches.matches.length} matches found
                    </p>
                    {threatMatches.matches.map((match) => {
                      const riskColor = match.riskLevel === "critical" ? "text-red-500" :
                                        match.riskLevel === "high" ? "text-orange-500" :
                                        match.riskLevel === "medium" ? "text-yellow-500" : "text-emerald-500";
                      const riskBg = match.riskLevel === "critical" ? "bg-red-500/10 border-red-500/30" :
                                     match.riskLevel === "high" ? "bg-orange-500/10 border-orange-500/30" :
                                     match.riskLevel === "medium" ? "bg-yellow-500/10 border-yellow-500/30" : "bg-emerald-500/10 border-emerald-500/30";
                      return (
                        <div
                          key={match.groupId}
                          className={`p-4 rounded-lg border ${riskBg} hover:border-primary/50 cursor-pointer transition-colors`}
                          onClick={() => navigate(`/threat-group/${match.groupId}`)}
                        >
                          <div className="flex items-start justify-between mb-2">
                            <div>
                              <div className="flex items-center gap-2">
                                <h4 className="font-semibold text-sm">{match.groupName}</h4>
                                <Badge variant="outline" className="text-xs uppercase">{match.groupType}</Badge>
                                {match.active && <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 text-xs">Active</Badge>}
                              </div>
                              <p className="text-xs text-muted-foreground mt-1">
                                Origin: {match.origin} — {match.aliases.join(", ")}
                              </p>
                            </div>
                            <div className="text-right">
                              <span className={`text-2xl font-bold tabular-nums ${riskColor}`}>{match.matchScore}%</span>
                              <p className={`text-xs font-medium uppercase ${riskColor}`}>{match.riskLevel} risk</p>
                            </div>
                          </div>
                          <p className="text-xs text-muted-foreground mb-3">{match.matchSummary}</p>
                          <div className="flex flex-wrap gap-4 text-xs">
                            <span className="flex items-center gap-1">
                              <Crosshair className="w-3 h-3" /> {match.matchedTechniqueCount} TTPs
                            </span>
                            <span className="flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3" /> {match.matchedCVECount} CVEs
                            </span>
                            <span className="flex items-center gap-1">
                              <Cpu className="w-3 h-3" /> {match.matchedToolCount} Tools
                            </span>
                            <span className="flex items-center gap-1">
                              <Building2 className="w-3 h-3" /> {match.fedrampExposureCount} FedRAMP
                            </span>
                            {match.sectorRelevance > 0 && (
                              <Badge variant="outline" className="text-xs">
                                Sector match: {match.sectorRelevance}%
                              </Badge>
                            )}
                          </div>
                          <div className="flex items-center gap-1 mt-2 text-xs text-primary">
                            View full profile <ChevronRight className="w-3 h-3" />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Threat Group Type Breakdown */}
            {threatSummary?.byType && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Users className="w-4 h-4" /> Groups by Type
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {Object.entries(threatSummary.byType).map(([type, count]) => (
                      <div key={type} className="p-3 rounded-lg bg-muted/30 border text-center">
                        <span className="text-lg font-bold tabular-nums">{count as number}</span>
                        <p className="text-xs text-muted-foreground capitalize mt-1">{type.replace(/_/g, " ")}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
