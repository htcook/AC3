import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import {
  Brain, RefreshCw, Play, Database, FileText, Shield, Zap,
  Clock, CheckCircle2, AlertTriangle, Loader2, ChevronDown, ChevronUp,
  BookOpen, Target, Crosshair, Bug, Globe, Radio, Newspaper,
  FlaskConical, TrendingUp, BarChart3, Eye, Download
} from "lucide-react";
import { useState, useMemo } from "react";

// ── Category icons & colors ──────────────────────────────────────────
const CATEGORY_META: Record<string, { icon: any; color: string; label: string }> = {
  incident_reports: { icon: FileText, color: "text-red-400", label: "Incident Reports" },
  government_advisories: { icon: Shield, color: "text-blue-400", label: "Government Advisories" },
  vendor_research: { icon: Target, color: "text-purple-400", label: "Vendor Research" },
  news: { icon: Newspaper, color: "text-yellow-400", label: "News & Analysis" },
  threat_sharing: { icon: Radio, color: "text-green-400", label: "Threat Sharing" },
  exploit_intel: { icon: Bug, color: "text-orange-400", label: "Exploit Intelligence" },
};

// ── Severity colors ──────────────────────────────────────────────────
function severityColor(s: string) {
  switch (s?.toLowerCase()) {
    case "critical": return "bg-red-500/20 text-red-400 border-red-500/30";
    case "high": return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "low": return "bg-green-500/20 text-green-400 border-green-500/30";
    default: return "bg-gray-500/20 text-gray-400 border-gray-500/30";
  }
}

export default function TrainingDashboard() {
  const [activeTab, setActiveTab] = useState<"overview" | "reports" | "templates" | "exploits">("overview");
  const [expandedSource, setExpandedSource] = useState<string | null>(null);
  const [reportPage, setReportPage] = useState(0);
  const [templatePage, setTemplatePage] = useState(0);
  const [exploitPage, setExploitPage] = useState(0);
  const [templateStatusFilter, setTemplateStatusFilter] = useState<string>("all");

  // ── Queries ──────────────────────────────────────────────────────────
  const { data: sources } = trpc.threatIntelTraining.listSources.useQuery();
  const { data: ingestStats } = trpc.threatIntelTraining.ingestStats.useQuery();
  const { data: dashStats } = trpc.threatIntelTraining.dashboardStats.useQuery();
  const { data: learnerStats } = trpc.threatIntelTraining.learnerStats.useQuery();
  const { data: reports } = trpc.threatIntelTraining.listReports.useQuery({
    limit: 20,
    offset: reportPage * 20,
  });
  const { data: templates } = trpc.threatIntelTraining.listTemplates.useQuery({
    limit: 20,
    offset: templatePage * 20,
    status: templateStatusFilter === "all" ? undefined : templateStatusFilter,
  });
  const { data: exploits } = trpc.threatIntelTraining.listExploits.useQuery({
    limit: 20,
    offset: exploitPage * 20,
  });

  // ── Mutations ────────────────────────────────────────────────────────
  const ingestAll = trpc.threatIntelTraining.ingestAll.useMutation({
    onSuccess: (data) => {
      const totalNew = data.totalNewRecords || 0;
      toast.success(`Ingestion complete: ${totalNew} new reports from ${data.successfulSources || 0} sources`);
    },
    onError: (e) => toast.error(`Ingestion failed: ${e.message}`),
  });
  const ingestSource = trpc.threatIntelTraining.ingestSource.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Source ingested: ${data.newRecords || 0} new records`);
    },
    onError: (e) => toast.error(`Source ingestion failed: ${e.message}`),
  });
  const processBatch = trpc.threatIntelTraining.processBatch.useMutation({
    onSuccess: (data: any) => {
      const count = Array.isArray(data) ? data.length : 0;
      toast.success(`Processed ${count} reports into attack sequences`);
    },
    onError: (e) => toast.error(`Processing failed: ${e.message}`),
  });

  const isAnyLoading = ingestAll.isPending || ingestSource.isPending || processBatch.isPending;

  // ── Derived stats from dashboardStats (which has { ingestion, learning }) ──
  const ingestion = dashStats?.ingestion;
  const learning = dashStats?.learning;
  const totalReports = ingestion?.totalReports || 0;
  const totalTemplates = learning?.totalTemplates || 0;
  const totalExploits = ingestion?.totalExploits || 0;
  const processedReports = learning?.byStatus?.["processed"] || 0;

  const TABS = [
    { id: "overview" as const, label: "OVERVIEW", icon: BarChart3 },
    { id: "reports" as const, label: "REPORTS", icon: FileText, count: totalReports },
    { id: "templates" as const, label: "ATTACK TEMPLATES", icon: Crosshair, count: totalTemplates },
    { id: "exploits" as const, label: "EXPLOIT INTEL", icon: Bug, count: totalExploits },
  ];

  return (
    <AppShell>
      {/* ── Header ────────────────────────────────────────────────────── */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-2">
          <h1 className="font-display text-4xl tracking-wider flex items-center gap-3">
            <Brain className="w-8 h-8 text-primary" />
            TRAINING DASHBOARD
          </h1>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              className="font-display tracking-wider"
              onClick={() => processBatch.mutate({ limit: 10 })}
              disabled={isAnyLoading}
            >
              {processBatch.isPending ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <FlaskConical className="w-4 h-4 mr-2" />
              )}
              PROCESS BATCH
            </Button>
            <Button
              className="font-display tracking-wider bg-primary hover:bg-primary/90"
              size="sm"
              onClick={() => ingestAll.mutate()}
              disabled={isAnyLoading}
            >
              {ingestAll.isPending ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Download className="w-4 h-4 mr-2" />
              )}
              RUN INGESTION NOW
            </Button>
          </div>
        </div>
        <p className="text-muted-foreground text-sm max-w-3xl">
          This dashboard manages the platform's threat intelligence training pipeline. It ingests real-world incident
          reports, breach analyses, and exploit data from 11+ public sources, then uses LLM-powered extraction to
          build reusable attack sequence templates for campaign design and adversary emulation.
        </p>
      </div>

      {/* ── Quick Stats ───────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
        <div className="bg-card border border-border p-4">
          <div className="text-xs text-muted-foreground font-display tracking-wider">SOURCES</div>
          <div className="text-2xl font-display text-primary">{sources?.length || 0}</div>
          <div className="text-xs text-muted-foreground">active feeds</div>
        </div>
        <div className="bg-card border border-border p-4">
          <div className="text-xs text-muted-foreground font-display tracking-wider">REPORTS</div>
          <div className="text-2xl font-display">{totalReports}</div>
          <div className="text-xs text-muted-foreground">ingested</div>
        </div>
        <div className="bg-card border border-border p-4">
          <div className="text-xs text-muted-foreground font-display tracking-wider">PROCESSED</div>
          <div className="text-2xl font-display text-green-400">{processedReports}</div>
          <div className="text-xs text-muted-foreground">LLM extracted</div>
        </div>
        <div className="bg-card border border-border p-4">
          <div className="text-xs text-muted-foreground font-display tracking-wider">TEMPLATES</div>
          <div className="text-2xl font-display text-purple-400">{totalTemplates}</div>
          <div className="text-xs text-muted-foreground">attack sequences</div>
        </div>
        <div className="bg-card border border-border p-4">
          <div className="text-xs text-muted-foreground font-display tracking-wider">EXPLOITS</div>
          <div className="text-2xl font-display text-orange-400">{totalExploits}</div>
          <div className="text-xs text-muted-foreground">CVEs tracked</div>
        </div>
        <div className="bg-card border border-border p-4">
          <div className="text-xs text-muted-foreground font-display tracking-wider">PENDING</div>
          <div className="text-2xl font-display text-yellow-400">{Math.max(0, totalReports - processedReports)}</div>
          <div className="text-xs text-muted-foreground">awaiting extraction</div>
        </div>
      </div>

      {/* ── Tab Navigation ────────────────────────────────────────────── */}
      <div className="flex gap-1 border-b border-border mb-6">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3 font-display text-sm tracking-wider border-b-2 transition-colors ${
                activeTab === tab.id
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
              {tab.count !== undefined && (
                <span className="text-xs bg-secondary px-1.5 py-0.5 rounded">{tab.count}</span>
              )}
            </button>
          );
        })}
      </div>

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* OVERVIEW TAB                                                   */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {/* Feed Source Cards */}
          <div>
            <h2 className="font-display text-xl tracking-wider mb-4 flex items-center gap-2">
              <Globe className="w-5 h-5 text-primary" />
              FEED SOURCES ({sources?.length || 0})
            </h2>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
              {sources?.map((source) => {
                const meta = CATEGORY_META[source.category] || { icon: Globe, color: "text-gray-400", label: source.category };
                const Icon = meta.icon;
                const isExpanded = expandedSource === source.name;
                return (
                  <div key={source.name} className="bg-card border border-border overflow-hidden">
                    <button
                      onClick={() => setExpandedSource(isExpanded ? null : source.name)}
                      className="w-full p-4 text-left flex items-start gap-3 hover:bg-secondary/30 transition-colors"
                    >
                      <div className={`w-10 h-10 flex items-center justify-center rounded bg-secondary ${meta.color}`}>
                        <Icon className="w-5 h-5" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <p className="font-display text-sm tracking-wider truncate">{source.name.replace(/_/g, " ").toUpperCase()}</p>
                          {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                        </div>
                        <p className="text-xs text-muted-foreground">{meta.label}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="outline" className="text-[10px]">Priority {source.priority}</Badge>
                        </div>
                      </div>
                    </button>
                    {isExpanded && (
                      <div className="px-4 pb-4 border-t border-border pt-3">
                        <div className="flex gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            className="font-display text-xs"
                            onClick={() => ingestSource.mutate({ source: source.name })}
                            disabled={isAnyLoading}
                          >
                            {ingestSource.isPending ? (
                              <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                            ) : (
                              <Play className="w-3 h-3 mr-1" />
                            )}
                            INGEST NOW
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Learner Stats */}
          {learnerStats && (
            <div>
              <h2 className="font-display text-xl tracking-wider mb-4 flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-primary" />
                LEARNER PIPELINE STATUS
              </h2>
              <div className="grid md:grid-cols-3 gap-4">
                <div className="bg-card border border-border p-5">
                  <div className="text-xs text-muted-foreground font-display tracking-wider mb-2">EXTRACTION RATE</div>
                  <div className="text-3xl font-display text-green-400">
                    {learnerStats.totalReports > 0
                      ? Math.round(((learnerStats.byStatus?.["processed"] || 0) / learnerStats.totalReports) * 100)
                      : 0}%
                  </div>
                  <div className="w-full bg-secondary h-2 mt-2 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-green-500 transition-all"
                      style={{
                        width: `${learnerStats.totalReports > 0
                          ? ((learnerStats.byStatus?.["processed"] || 0) / learnerStats.totalReports) * 100
                          : 0}%`,
                      }}
                    />
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">
                    {learnerStats.byStatus?.["processed"] || 0} of {learnerStats.totalReports} reports processed
                  </p>
                </div>
                <div className="bg-card border border-border p-5">
                  <div className="text-xs text-muted-foreground font-display tracking-wider mb-2">TEMPLATE QUALITY</div>
                  <div className="text-3xl font-display text-purple-400">
                    {learnerStats.avgPhasesPerTemplate
                      ? `${Math.round(learnerStats.avgPhasesPerTemplate)} phases`
                      : "—"}
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">Average phases per template</p>
                  <div className="flex gap-2 mt-2">
                    <Badge variant="outline" className="text-[10px]">
                      {learnerStats.byStatus?.["validated"] || learnerStats.byStatus?.["production"] || 0} validated
                    </Badge>
                    <Badge variant="outline" className="text-[10px]">
                      {learnerStats.byStatus?.["draft"] || 0} drafts
                    </Badge>
                  </div>
                </div>
                <div className="bg-card border border-border p-5">
                  <div className="text-xs text-muted-foreground font-display tracking-wider mb-2">COVERAGE</div>
                  <div className="text-3xl font-display text-blue-400">
                    {learnerStats.topTechniques?.length || 0}
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">Unique MITRE techniques learned</p>
                  <div className="flex gap-2 mt-2">
                    <Badge variant="outline" className="text-[10px]">
                      {learnerStats.topActors?.length || 0} actors
                    </Badge>
                    <Badge variant="outline" className="text-[10px]">
                      {Object.keys(learnerStats.templatesByType || {}).length} attack types
                    </Badge>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Ingestion Source Breakdown */}
          {ingestion && ingestion.bySource && ingestion.bySource.length > 0 && (
            <div>
              <h2 className="font-display text-xl tracking-wider mb-4 flex items-center gap-2">
                <Clock className="w-5 h-5 text-primary" />
                INGESTION BREAKDOWN BY SOURCE
              </h2>
              <div className="bg-card border border-border overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-secondary/30">
                      <th className="text-left px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">SOURCE</th>
                      <th className="text-right px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">RECORDS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ingestion.bySource.map((stat, i: number) => (
                      <tr key={i} className="border-b border-border/50 hover:bg-secondary/20">
                        <td className="px-4 py-3 font-mono text-xs">{stat.source}</td>
                        <td className="px-4 py-3 text-right font-mono text-xs">{stat.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Template Type Breakdown */}
          {learning && learning.templatesByType && Object.keys(learning.templatesByType).length > 0 && (
            <div>
              <h2 className="font-display text-xl tracking-wider mb-4 flex items-center gap-2">
                <Crosshair className="w-5 h-5 text-primary" />
                TEMPLATES BY ATTACK TYPE
              </h2>
              <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-3">
                {Object.entries(learning.templatesByType).map(([type, count]) => (
                  <div key={type} className="bg-card border border-border p-4">
                    <div className="text-xs text-muted-foreground font-display tracking-wider">
                      {type.replace(/_/g, " ").toUpperCase()}
                    </div>
                    <div className="text-2xl font-display text-purple-400">{count as number}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* REPORTS TAB                                                    */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {activeTab === "reports" && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display text-xl tracking-wider">
              INGESTED REPORTS ({reports?.total || 0})
            </h2>
          </div>
          <div className="bg-card border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-secondary/30">
                  <th className="text-left px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">TITLE</th>
                  <th className="text-left px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">SOURCE</th>
                  <th className="text-left px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">SEVERITY</th>
                  <th className="text-left px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">STATUS</th>
                  <th className="text-right px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">DATE</th>
                </tr>
              </thead>
              <tbody>
                {reports?.reports?.map((report: any) => (
                  <tr key={report.id} className="border-b border-border/50 hover:bg-secondary/20">
                    <td className="px-4 py-3">
                      <div className="max-w-md">
                        <p className="font-medium text-sm truncate">{report.title}</p>
                        {report.url && (
                          <a href={report.url} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline truncate block">
                            {report.url}
                          </a>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="outline" className="text-[10px] font-mono">{report.source}</Badge>
                    </td>
                    <td className="px-4 py-3">
                      <Badge className={`text-[10px] ${severityColor(report.severity)}`}>
                        {(report.severity || "unknown").toUpperCase()}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      {report.status === "processed" ? (
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-[10px]">
                          <CheckCircle2 className="w-3 h-3 mr-1" /> PROCESSED
                        </Badge>
                      ) : (
                        <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30 text-[10px]">
                          <Clock className="w-3 h-3 mr-1" /> {(report.status || "pending").toUpperCase()}
                        </Badge>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right text-xs text-muted-foreground">
                      {report.publishedAt ? new Date(report.publishedAt).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
                {(!reports?.reports || reports.reports.length === 0) && (
                  <tr>
                    <td colSpan={5} className="px-4 py-16 text-center text-muted-foreground">
                      <FileText className="w-12 h-12 mx-auto mb-3 opacity-50" />
                      <p className="font-display">No reports ingested yet</p>
                      <p className="text-sm mt-1">Click "Run Ingestion Now" to fetch reports from all sources</p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {/* Pagination */}
          <div className="flex items-center justify-between mt-4">
            <Button
              variant="outline"
              size="sm"
              disabled={reportPage === 0}
              onClick={() => setReportPage(p => Math.max(0, p - 1))}
              className="font-display"
            >
              PREVIOUS
            </Button>
            <span className="text-xs text-muted-foreground font-display">
              Page {reportPage + 1}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={!reports?.reports || reports.reports.length < 20}
              onClick={() => setReportPage(p => p + 1)}
              className="font-display"
            >
              NEXT
            </Button>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* ATTACK TEMPLATES TAB                                           */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {activeTab === "templates" && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display text-xl tracking-wider">
              ATTACK SEQUENCE TEMPLATES ({templates?.total || 0})
            </h2>
            <div className="flex gap-2">
              {["all", "draft", "validated", "production"].map((status) => (
                <Button
                  key={status}
                  variant={templateStatusFilter === status ? "default" : "outline"}
                  size="sm"
                  className="font-display text-xs"
                  onClick={() => { setTemplateStatusFilter(status); setTemplatePage(0); }}
                >
                  {status.toUpperCase()}
                </Button>
              ))}
            </div>
          </div>
          <div className="space-y-3">
            {templates?.templates?.map((template: any) => (
              <TemplateCard key={template.id} template={template} />
            ))}
            {(!templates?.templates || templates.templates.length === 0) && (
              <div className="text-center py-16 text-muted-foreground">
                <Crosshair className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p className="font-display">No attack templates yet</p>
                <p className="text-sm mt-1">Run "Process Batch" to extract attack sequences from ingested reports</p>
              </div>
            )}
          </div>
          {/* Pagination */}
          <div className="flex items-center justify-between mt-4">
            <Button
              variant="outline"
              size="sm"
              disabled={templatePage === 0}
              onClick={() => setTemplatePage(p => Math.max(0, p - 1))}
              className="font-display"
            >
              PREVIOUS
            </Button>
            <span className="text-xs text-muted-foreground font-display">
              Page {templatePage + 1}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={!templates?.templates || templates.templates.length < 20}
              onClick={() => setTemplatePage(p => p + 1)}
              className="font-display"
            >
              NEXT
            </Button>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* EXPLOIT INTEL TAB                                              */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {activeTab === "exploits" && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display text-xl tracking-wider">
              EXPLOIT INTELLIGENCE ({exploits?.total || 0})
            </h2>
          </div>
          <div className="bg-card border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-secondary/30">
                  <th className="text-left px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">CVE</th>
                  <th className="text-left px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">DESCRIPTION</th>
                  <th className="text-left px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">SEVERITY</th>
                  <th className="text-center px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">CVSS</th>
                  <th className="text-center px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">KEV</th>
                  <th className="text-center px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">MSF</th>
                  <th className="text-right px-4 py-3 font-display text-xs tracking-wider text-muted-foreground">FIRST SEEN</th>
                </tr>
              </thead>
              <tbody>
                {exploits?.exploits?.map((exploit: any) => (
                  <tr key={exploit.id} className="border-b border-border/50 hover:bg-secondary/20">
                    <td className="px-4 py-3 font-mono text-xs text-primary">{exploit.cveId}</td>
                    <td className="px-4 py-3">
                      <p className="text-sm truncate max-w-sm">{exploit.description || "—"}</p>
                    </td>
                    <td className="px-4 py-3">
                      <Badge className={`text-[10px] ${severityColor(exploit.severity)}`}>
                        {(exploit.severity || "unknown").toUpperCase()}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-center font-mono text-xs">
                      {exploit.cvssScore ? Number(exploit.cvssScore).toFixed(1) : "—"}
                    </td>
                    <td className="px-4 py-3 text-center">
                      {exploit.cisaKev ? (
                        <Badge className="bg-red-500/20 text-red-400 border-red-500/30 text-[10px]">KEV</Badge>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-center">
                      {exploit.hasMetasploitModule ? (
                        <Badge className="bg-purple-500/20 text-purple-400 border-purple-500/30 text-[10px]">EXP</Badge>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right text-xs text-muted-foreground">
                      {exploit.createdAt ? new Date(exploit.createdAt).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
                {(!exploits?.exploits || exploits.exploits.length === 0) && (
                  <tr>
                    <td colSpan={7} className="px-4 py-16 text-center text-muted-foreground">
                      <Bug className="w-12 h-12 mx-auto mb-3 opacity-50" />
                      <p className="font-display">No exploit intelligence yet</p>
                      <p className="text-sm mt-1">Exploit data is ingested from CVE feeds and CISA KEV</p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {/* Pagination */}
          <div className="flex items-center justify-between mt-4">
            <Button
              variant="outline"
              size="sm"
              disabled={exploitPage === 0}
              onClick={() => setExploitPage(p => Math.max(0, p - 1))}
              className="font-display"
            >
              PREVIOUS
            </Button>
            <span className="text-xs text-muted-foreground font-display">
              Page {exploitPage + 1}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={!exploits?.exploits || exploits.exploits.length < 20}
              onClick={() => setExploitPage(p => p + 1)}
              className="font-display"
            >
              NEXT
            </Button>
          </div>
        </div>
      )}
    </AppShell>
  );
}

// ── Template Card Component ──────────────────────────────────────────
function TemplateCard({ template }: { template: any }) {
  const [expanded, setExpanded] = useState(false);

  const phases = (() => {
    try {
      return typeof template.phases === "string" ? JSON.parse(template.phases) : template.phases;
    } catch { return []; }
  })();

  const techniques = (() => {
    try {
      return typeof template.techniques === "string" ? JSON.parse(template.techniques) : template.techniques;
    } catch { return []; }
  })();

  const statusColor = template.status === "production"
    ? "bg-green-500/20 text-green-400 border-green-500/30"
    : template.status === "validated"
    ? "bg-blue-500/20 text-blue-400 border-blue-500/30"
    : "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";

  return (
    <div className="bg-card border border-border overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-4 text-left flex items-start gap-4 hover:bg-secondary/20 transition-colors"
      >
        <div className="w-10 h-10 flex items-center justify-center rounded bg-purple-500/20 text-purple-400">
          <Crosshair className="w-5 h-5" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <p className="font-display text-sm tracking-wider truncate">{template.name}</p>
            <Badge className={`text-[10px] ${statusColor}`}>{template.status?.toUpperCase()}</Badge>
            {template.confidence && (
              <Badge variant="outline" className="text-[10px]">
                {Math.round(Number(template.confidence) * 100)}% confidence
              </Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground truncate">{template.description}</p>
          <div className="flex flex-wrap gap-1 mt-2">
            {template.targetSector && (
              <Badge variant="outline" className="text-[10px]">{template.targetSector}</Badge>
            )}
            {template.threatActor && (
              <Badge variant="outline" className="text-[10px] text-red-400 border-red-500/30">{template.threatActor}</Badge>
            )}
            <Badge variant="outline" className="text-[10px]">{phases?.length || 0} phases</Badge>
            <Badge variant="outline" className="text-[10px]">{techniques?.length || 0} techniques</Badge>
          </div>
        </div>
        {expanded ? <ChevronUp className="w-4 h-4 text-muted-foreground mt-1" /> : <ChevronDown className="w-4 h-4 text-muted-foreground mt-1" />}
      </button>
      {expanded && phases && phases.length > 0 && (
        <div className="px-4 pb-4 border-t border-border pt-3">
          <h4 className="font-display text-xs tracking-wider text-muted-foreground mb-3">ATTACK PHASES</h4>
          <div className="space-y-2">
            {phases.map((phase: any, i: number) => (
              <div key={i} className="flex items-start gap-3 bg-secondary/30 p-3">
                <div className="w-6 h-6 flex items-center justify-center rounded-full bg-primary/20 text-primary text-xs font-display shrink-0">
                  {i + 1}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="font-display text-xs tracking-wider">{phase.tactic?.toUpperCase() || `PHASE ${i + 1}`}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{phase.description || phase.technique || "—"}</p>
                  {phase.technique && (
                    <Badge variant="outline" className="text-[10px] mt-1 font-mono">{phase.technique}</Badge>
                  )}
                </div>
              </div>
            ))}
          </div>
          {techniques && techniques.length > 0 && (
            <div className="mt-3">
              <h4 className="font-display text-xs tracking-wider text-muted-foreground mb-2">MITRE TECHNIQUES</h4>
              <div className="flex flex-wrap gap-1">
                {techniques.map((t: string, i: number) => (
                  <Badge key={i} variant="outline" className="text-[10px] font-mono">{t}</Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
