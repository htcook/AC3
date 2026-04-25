import { useState, useMemo } from "react";
import { useRoute } from "wouter";
import { trpc } from "@/lib/trpc";
import {
  Shield, AlertTriangle, CheckCircle, Lock, Eye, FileText,
  ChevronDown, ChevronUp, ExternalLink, Bug, Server, Globe,
  BarChart3, Target, Lightbulb, BookOpen, Clock, Pen, Download,
  Calendar, MapPin, Users, Scale, Database, Radio, Hash
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import { CorroborationTierBadge } from "@/components/CorroborationTierBadge";

// ─── Severity helpers ──────────────────────────────────────────────
function severityColor(sev: number): string {
  if (sev >= 9) return "text-red-400";
  if (sev >= 7) return "text-orange-400";
  if (sev >= 4) return "text-yellow-400";
  return "text-green-400";
}

function severityBadge(sev: number): string {
  if (sev >= 9) return "Critical";
  if (sev >= 7) return "High";
  if (sev >= 4) return "Medium";
  return "Low";
}

function severityBadgeColor(sev: number): string {
  if (sev >= 9) return "bg-red-500/20 text-red-300 border-red-500/30";
  if (sev >= 7) return "bg-orange-500/20 text-orange-300 border-orange-500/30";
  if (sev >= 4) return "bg-yellow-500/20 text-yellow-300 border-yellow-500/30";
  return "bg-green-500/20 text-green-300 border-green-500/30";
}

function riskBandColor(band: string): string {
  switch (band?.toLowerCase()) {
    case "critical": return "text-red-400";
    case "high": return "text-orange-400";
    case "medium": return "text-yellow-400";
    case "low": return "text-green-400";
    default: return "text-gray-400";
  }
}

// ─── Password Gate ─────────────────────────────────────────────────
function PasswordGate({ onSubmit }: { onSubmit: (pw: string) => void }) {
  const [password, setPassword] = useState("");
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center p-4">
      <Card className="w-full max-w-md bg-slate-900/80 border-slate-700/50 backdrop-blur-sm">
        <CardHeader className="text-center">
          <div className="mx-auto w-16 h-16 rounded-full bg-teal-500/10 flex items-center justify-center mb-4">
            <Lock className="w-8 h-8 text-teal-400" />
          </div>
          <CardTitle className="text-xl text-white">Protected Report</CardTitle>
          <p className="text-sm text-slate-400 mt-2">This report is password protected. Enter the password to continue.</p>
        </CardHeader>
        <CardContent>
          <form onSubmit={(e) => { e.preventDefault(); onSubmit(password); }} className="space-y-4">
            <Input
              type="password"
              placeholder="Enter access password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="bg-slate-800 border-slate-600 text-white"
            />
            <Button type="submit" className="w-full bg-teal-600 hover:bg-teal-700 text-white" disabled={!password}>
              <Lock className="w-4 h-4 mr-2" /> Unlock Report
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────
export default function ClientPortal() {
  const [, params] = useRoute("/portal/:token");
  const token = params?.token || "";
  const [password, setPassword] = useState<string | undefined>(undefined);
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());
  const [findingFilter, setFindingFilter] = useState<string>("all");
  const [showSignDialog, setShowSignDialog] = useState(false);
  const [signForm, setSignForm] = useState({ name: "", title: "", organization: "", email: "", signatureType: "typed" as "typed" | "drawn" });
  // toast imported from sonner at top level
  const signRoeMutation = trpc.clientPortal.signRoe.useMutation({
    onSuccess: () => {
      toast.success("Your digital signature has been recorded successfully.");
      setShowSignDialog(false);
      refetch();
    },
    onError: (err) => {
      toast.error(err.message);
    },
  });

  const { data, isLoading, error, refetch } = trpc.clientPortal.accessReport.useQuery(
    { token, password },
    { enabled: !!token, retry: false }
  );

  // Handle password requirement
  if (data && "requiresPassword" in data && data.requiresPassword === true) {
    return <PasswordGate onSubmit={(pw) => { setPassword(pw); setTimeout(() => refetch(), 100); }} />;
  }

  // Loading state
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-2 border-teal-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-slate-400">Loading engagement report...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center p-4">
        <Card className="w-full max-w-md bg-slate-900/80 border-slate-700/50">
          <CardContent className="pt-8 text-center">
            <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
            <h2 className="text-xl font-bold text-white mb-2">Access Denied</h2>
            <p className="text-slate-400">Unable to access this resource. Please verify your permissions.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!data || !("engagement" in data)) return null;

  const report = data as any;
  const brandColor = report.branding?.brandingColor || "#14b8a6";
  const clientName = report.branding?.clientName || report.engagement?.customerName || "Client";

  // Filter findings
  const filteredFindings = useMemo(() => {
    if (!report.findings) return [];
    if (findingFilter === "all") return report.findings;
    return report.findings.filter((f: any) => {
      const band = severityBadge(f.severity).toLowerCase();
      return band === findingFilter;
    });
  }, [report.findings, findingFilter]);

  const toggleFinding = (idx: number) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  return (
      <AppShell activePath="/portal">
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Header */}
      <header className="border-b border-slate-800/50 bg-slate-950/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            {report.branding?.clientLogo ? (
              <img src={report.branding.clientLogo} alt="Logo" className="h-8 w-auto" />
            ) : (
              <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ backgroundColor: brandColor + "20" }}>
                <Shield className="w-5 h-5" style={{ color: brandColor }} />
              </div>
            )}
            <div>
              <h1 className="text-lg font-bold text-white">{clientName}</h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Manage client-facing deliverables and engagement visibility. This portal lets you share findings, reports, and progress updates with clients in a controlled, professional format. Configure what each client can see, upload deliverables, and track client acknowledgments. Use this page to maintain transparent communication with stakeholders throughout the engagement lifecycle.</p>
              <p className="text-xs text-slate-500">Security Assessment Report</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Eye className="w-3.5 h-3.5" />
            <span>Read-only</span>
          </div>
        </div>
      </header>

      {/* Custom message banner */}
      {report.branding?.customMessage && (
        <div className="border-b border-slate-800/30 bg-slate-900/50">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3">
            <p className="text-sm text-slate-300">{report.branding.customMessage}</p>
          </div>
        </div>
      )}

      <main className="max-w-6xl mx-auto px-4 sm:px-6 py-8 space-y-8">
        {/* Engagement Overview */}
        <section>
          <h2 className="text-2xl font-bold text-white mb-1">{report.engagement?.name}</h2>
          <div className="flex flex-wrap gap-3 text-sm text-slate-400 mt-2">
            <span className="flex items-center gap-1.5">
              <Target className="w-4 h-4" style={{ color: brandColor }} />
              {report.engagement?.engagementType?.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}
            </span>
            {report.engagement?.targetDomain && (
              <span className="flex items-center gap-1.5">
                <Globe className="w-4 h-4" style={{ color: brandColor }} />
                {report.engagement.targetDomain}
              </span>
            )}
            {report.engagement?.startDate && (
              <span className="flex items-center gap-1.5">
                <Clock className="w-4 h-4" style={{ color: brandColor }} />
                {new Date(report.engagement.startDate).toLocaleDateString()} 
                {report.engagement?.endDate && ` — ${new Date(report.engagement.endDate).toLocaleDateString()}`}
              </span>
            )}
            <Badge variant="outline" className="border-slate-600 text-slate-300 capitalize">
              {report.engagement?.status}
            </Badge>
          </div>
        </section>

        {/* Risk Score Banner */}
        {report.sections?.includeRiskScores && report.riskScore != null && (
          <Card className="bg-slate-900/60 border-slate-700/50">
            <CardContent className="p-6">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-6">
                <div className="text-center">
                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Overall Risk</p>
                  <p className={`text-4xl font-black ${riskBandColor(report.riskBand || "")}`}>{report.riskScore}</p>
                  <Badge variant="outline" className={`mt-1 capitalize ${riskBandColor(report.riskBand || "")}`}>
                    {report.riskBand || "N/A"}
                  </Badge>
                </div>
                <div className="text-center">
                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Assets Scanned</p>
                  <p className="text-4xl font-black text-white">{report.assetCount || 0}</p>
                </div>
                <div className="text-center">
                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Findings</p>
                  <p className="text-4xl font-black text-white">{report.findingCount || 0}</p>
                </div>
                <div className="text-center">
                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Risk Distribution</p>
                  {report.riskDistribution && (
                    <div className="flex gap-1 justify-center mt-2">
                      {report.riskDistribution.critical > 0 && (
                        <Badge className="bg-red-500/20 text-red-300 text-xs">{report.riskDistribution.critical} Crit</Badge>
                      )}
                      {report.riskDistribution.high > 0 && (
                        <Badge className="bg-orange-500/20 text-orange-300 text-xs">{report.riskDistribution.high} High</Badge>
                      )}
                      {report.riskDistribution.medium > 0 && (
                        <Badge className="bg-yellow-500/20 text-yellow-300 text-xs">{report.riskDistribution.medium} Med</Badge>
                      )}
                      {report.riskDistribution.low > 0 && (
                        <Badge className="bg-green-500/20 text-green-300 text-xs">{report.riskDistribution.low} Low</Badge>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Tabs for content sections */}
        <Tabs defaultValue="summary" className="space-y-6">
          <TabsList className="bg-slate-900/60 border border-slate-700/50">
            {report.sections?.includeExecutiveSummary && (
              <TabsTrigger value="summary" className="data-[state=active]:bg-slate-700">
                <BookOpen className="w-4 h-4 mr-1.5" /> Summary
              </TabsTrigger>
            )}
            {report.sections?.includeFindings && report.findings?.length > 0 && (
              <TabsTrigger value="findings" className="data-[state=active]:bg-slate-700">
                <Bug className="w-4 h-4 mr-1.5" /> Findings
              </TabsTrigger>
            )}
            {report.sections?.includeAssets && report.assets?.length > 0 && (
              <TabsTrigger value="assets" className="data-[state=active]:bg-slate-700">
                <Server className="w-4 h-4 mr-1.5" /> Assets
              </TabsTrigger>
            )}
            {report.sections?.includeRecommendations && report.recommendations?.length > 0 && (
              <TabsTrigger value="recommendations" className="data-[state=active]:bg-slate-700">
                <Lightbulb className="w-4 h-4 mr-1.5" /> Recommendations
              </TabsTrigger>
            )}
            {report.reports?.length > 0 && (
              <TabsTrigger value="reports" className="data-[state=active]:bg-slate-700">
                <FileText className="w-4 h-4 mr-1.5" /> Reports
              </TabsTrigger>
            )}
            {report.roe && (
              <TabsTrigger value="roe" className="data-[state=active]:bg-slate-700">
                <Scale className="w-4 h-4 mr-1.5" /> Rules of Engagement
              </TabsTrigger>
            )}
          </TabsList>

          {/* Executive Summary */}
          {report.sections?.includeExecutiveSummary && (
            <TabsContent value="summary" className="space-y-6">
              {report.executiveSummary && (
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-lg text-white flex items-center gap-2">
                      <BookOpen className="w-5 h-5" style={{ color: brandColor }} />
                      Executive Summary
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="prose prose-invert prose-sm max-w-none">
                      {report.executiveSummary.split("\n").map((line: string, i: number) => (
                        <p key={i} className="text-slate-300 leading-relaxed">{line}</p>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
              {report.threatModelSummary && (
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-lg text-white flex items-center gap-2">
                      <Shield className="w-5 h-5" style={{ color: brandColor }} />
                      Threat Model
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="prose prose-invert prose-sm max-w-none">
                      {report.threatModelSummary.split("\n").map((line: string, i: number) => (
                        <p key={i} className="text-slate-300 leading-relaxed">{line}</p>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
              {report.campaigns && report.campaigns.length > 0 && (
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-lg text-white flex items-center gap-2">
                      <Target className="w-5 h-5" style={{ color: brandColor }} />
                      Identified Attack Campaigns
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {report.campaigns.map((c: any, i: number) => (
                      <div key={i} className="p-4 rounded-lg bg-slate-800/50 border border-slate-700/30">
                        <h4 className="font-semibold text-white mb-1">{c.name}</h4>
                        <p className="text-sm text-slate-400 mb-2">{c.objective}</p>
                        <div className="flex flex-wrap gap-2">
                          {c.attackVector && (
                            <Badge variant="outline" className="text-xs border-slate-600 text-slate-300">
                              {c.attackVector}
                            </Badge>
                          )}
                          {c.mitreTechniques?.map((t: string, j: number) => (
                            <Badge key={j} variant="outline" className="text-xs border-slate-600 text-slate-300">
                              {t}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}
            </TabsContent>
          )}

          {/* Findings */}
          {report.sections?.includeFindings && (
            <TabsContent value="findings" className="space-y-4">
              {/* Filter bar */}
              <div className="flex flex-wrap gap-2">
                {["all", "critical", "high", "medium", "low"].map((f) => (
                  <Button
                    key={f}
                    size="sm"
                    variant={findingFilter === f ? "default" : "outline"}
                    onClick={() => setFindingFilter(f)}
                    className={findingFilter === f ? "bg-slate-700" : "border-slate-700 text-slate-400"}
                  >
                    {f === "all" ? `All (${report.findings?.length || 0})` : 
                      `${f.charAt(0).toUpperCase() + f.slice(1)} (${report.findings?.filter((x: any) => severityBadge(x.severity).toLowerCase() === f).length || 0})`}
                  </Button>
                ))}
              </div>

              {/* Findings list */}
              {filteredFindings.map((f: any, idx: number) => (
                <Card key={idx} className="bg-slate-900/60 border-slate-700/50 overflow-hidden">
                  <div
                    className="p-4 cursor-pointer hover:bg-slate-800/30 transition-colors"
                    onClick={() => toggleFinding(idx)}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <Badge className={`text-xs border ${severityBadgeColor(f.severity)}`}>
                            {severityBadge(f.severity)} ({f.severity?.toFixed(1)})
                          </Badge>
                          {f.kevListed && (
                            <Badge className="bg-red-600/30 text-red-300 text-xs border border-red-500/40">KEV</Badge>
                          )}
                          {f.exploitAvailable && (
                            <Badge className="bg-orange-600/30 text-orange-300 text-xs border border-orange-500/40">Exploit</Badge>
                          )}
                          {f.corroborationTier && (
                            <CorroborationTierBadge tier={f.corroborationTier} size="sm" showTooltip={true} />
                          )}
                        </div>
                        <h4 className="font-medium text-white text-sm">{f.title}</h4>
                        <p className="text-xs text-slate-500 mt-0.5">
                          {f.assetHostname} {f.category ? `• ${f.category}` : ""}
                        </p>
                      </div>
                      {expandedFindings.has(idx) ? (
                        <ChevronUp className="w-4 h-4 text-slate-500 shrink-0" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />
                      )}
                    </div>
                  </div>
                  {expandedFindings.has(idx) && (
                    <div className="px-4 pb-4 border-t border-slate-800/50 pt-3 space-y-3">
                      {f.evidenceDetail && (
                        <div>
                          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Evidence</p>
                          <p className="text-sm text-slate-300">{f.evidenceDetail}</p>
                        </div>
                      )}
                      {f.cveIds && f.cveIds.length > 0 && (
                        <div>
                          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">CVEs</p>
                          <div className="flex flex-wrap gap-1">
                            {f.cveIds.map((cve: string, j: number) => (
                              <Badge key={j} variant="outline" className="text-xs border-slate-600 text-slate-300">
                                {cve}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                        <div>
                          <p className="text-slate-500">Likelihood</p>
                          <p className="text-slate-300">{f.likelihood?.toFixed(2) || "N/A"}</p>
                        </div>
                        <div>
                          <p className="text-slate-500">Confidence</p>
                          <p className="text-slate-300">{f.confidence?.toFixed(2) || "N/A"}</p>
                        </div>
                        <div>
                          <p className="text-slate-500">Category</p>
                          <p className="text-slate-300 capitalize">{f.category || "N/A"}</p>
                        </div>
                      </div>
                    </div>
                  )}
                </Card>
              ))}
              {filteredFindings.length === 0 && (
                <div className="text-center py-12 text-slate-500">
                  <CheckCircle className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No findings match the selected filter.</p>
                </div>
              )}
            </TabsContent>
          )}

          {/* Assets */}
          {report.sections?.includeAssets && (
            <TabsContent value="assets" className="space-y-4">
              <div className="grid gap-3">
                {report.assets?.map((a: any, idx: number) => (
                  <Card key={idx} className="bg-slate-900/60 border-slate-700/50">
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center">
                            <Server className="w-5 h-5 text-slate-400" />
                          </div>
                          <div>
                            <p className="font-medium text-white text-sm">{a.hostname}</p>
                            <p className="text-xs text-slate-500 capitalize">{a.assetType}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-3 text-sm">
                          <div className="text-center">
                            <p className="text-xs text-slate-500">Risk</p>
                            <p className={`font-bold ${riskBandColor(a.riskBand || "")}`}>
                              {a.riskScore?.toFixed(0) || "N/A"}
                            </p>
                          </div>
                          <Badge variant="outline" className={`capitalize text-xs ${riskBandColor(a.riskBand || "")}`}>
                            {a.riskBand || "N/A"}
                          </Badge>
                          <div className="text-center">
                            <p className="text-xs text-slate-500">Findings</p>
                            <p className="font-bold text-white">{a.findingCount}</p>
                          </div>
                        </div>
                      </div>
                      {a.technologies && a.technologies.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-1">
                          {a.technologies.map((t: string, j: number) => (
                            <Badge key={j} variant="outline" className="text-xs border-slate-700 text-slate-400">
                              {t}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>
          )}

          {/* Recommendations */}
          {report.sections?.includeRecommendations && (
            <TabsContent value="recommendations" className="space-y-4">
              <Card className="bg-slate-900/60 border-slate-700/50">
                <CardHeader>
                  <CardTitle className="text-lg text-white flex items-center gap-2">
                    <Lightbulb className="w-5 h-5" style={{ color: brandColor }} />
                    Security Recommendations
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {report.recommendations?.map((r: string, idx: number) => (
                      <div key={idx} className="flex items-start gap-3 p-3 rounded-lg bg-slate-800/30 border border-slate-700/20">
                        <div className="w-6 h-6 rounded-full flex items-center justify-center shrink-0 text-xs font-bold" style={{ backgroundColor: brandColor + "20", color: brandColor }}>
                          {idx + 1}
                        </div>
                        <p className="text-sm text-slate-300">{r}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          )}

          {/* Reports */}
          {report.reports?.length > 0 && (
            <TabsContent value="reports" className="space-y-4">
              {report.reports.map((r: any, idx: number) => (
                <Card key={idx} className="bg-slate-900/60 border-slate-700/50">
                  <CardContent className="p-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <FileText className="w-8 h-8 text-slate-400" />
                      <div>
                        <p className="font-medium text-white text-sm">{r.title}</p>
                        <p className="text-xs text-slate-500">
                          {r.reportType?.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}
                          {r.generatedAt && ` • ${new Date(r.generatedAt).toLocaleDateString()}`}
                        </p>
                      </div>
                    </div>
                    {r.reportUrl && (
                      <Button size="sm" variant="outline" className="border-slate-700 text-slate-300" asChild>
                        <a href={r.reportUrl} target="_blank" rel="noopener noreferrer">
                          <ExternalLink className="w-4 h-4 mr-1.5" /> Download
                        </a>
                      </Button>
                    )}
                  </CardContent>
                </Card>
              ))}
            </TabsContent>
          )}
          {/* Rules of Engagement */}
          {report.roe && (
            <TabsContent value="roe" className="space-y-6">
              {/* RoE Header */}
              <Card className="bg-slate-900/60 border-slate-700/50">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-lg text-white flex items-center gap-2">
                        <Scale className="w-5 h-5" style={{ color: brandColor }} />
                        {report.roe.title}
                      </CardTitle>
                      <p className="text-sm text-slate-400 mt-1">Version {report.roe.version} • Status: <Badge variant="outline" className="capitalize border-slate-600 text-slate-300">{report.roe.status?.replace(/_/g, " ")}</Badge></p>
                    </div>
                    <div className="flex gap-2">
                      {(report.roe.status === "pending_review" || report.roe.status === "approved") && (
                        <Button size="sm" onClick={() => setShowSignDialog(true)} className="bg-teal-600 hover:bg-teal-700 text-white">
                          <Pen className="w-4 h-4 mr-1.5" /> Sign Document
                        </Button>
                      )}
                    </div>
                  </div>
                </CardHeader>
              </Card>

              {/* Purpose & Authorization */}
              {report.roe.purpose && (
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-base text-white">Purpose & Authorization</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <p className="text-sm text-slate-300 leading-relaxed">{report.roe.purpose}</p>
                    {report.roe.assumptions && (
                      <div>
                        <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">Assumptions</p>
                        <p className="text-sm text-slate-400">{report.roe.assumptions}</p>
                      </div>
                    )}
                    {report.roe.limitations && (
                      <div>
                        <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">Limitations</p>
                        <p className="text-sm text-slate-400">{report.roe.limitations}</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Scope */}
              <Card className="bg-slate-900/60 border-slate-700/50">
                <CardHeader>
                  <CardTitle className="text-base text-white flex items-center gap-2">
                    <Target className="w-4 h-4" style={{ color: brandColor }} /> Scope
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {report.roe.scopeInclusions && (
                    <div>
                      <p className="text-xs font-medium text-green-400 uppercase tracking-wider mb-2">In-Scope Assets</p>
                      <div className="space-y-1">
                        {(Array.isArray(report.roe.scopeInclusions) ? report.roe.scopeInclusions : []).map((item: any, i: number) => (
                          <div key={i} className="flex items-center gap-2 text-sm text-slate-300 p-2 rounded bg-slate-800/30">
                            <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />
                            <span>{typeof item === 'string' ? item : `${item.type || ''}: ${item.value || item.description || JSON.stringify(item)}`}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {report.roe.scopeExclusions && (
                    <div>
                      <p className="text-xs font-medium text-red-400 uppercase tracking-wider mb-2">Out-of-Scope / Exclusions</p>
                      <div className="space-y-1">
                        {(Array.isArray(report.roe.scopeExclusions) ? report.roe.scopeExclusions : []).map((item: any, i: number) => (
                          <div key={i} className="flex items-center gap-2 text-sm text-slate-300 p-2 rounded bg-slate-800/30">
                            <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                            <span>{typeof item === 'string' ? item : `${item.type || ''}: ${item.value || item.description || JSON.stringify(item)}`}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Testing Types & Attack Vectors */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {report.roe.testingTypes && (report.roe.testingTypes as any[]).length > 0 && (
                  <Card className="bg-slate-900/60 border-slate-700/50">
                    <CardHeader>
                      <CardTitle className="text-base text-white">Authorized Testing Types</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-2">
                        {(report.roe.testingTypes as string[]).map((t: string, i: number) => (
                          <Badge key={i} variant="outline" className="border-teal-500/30 text-teal-300 capitalize">
                            {t.replace(/_/g, " ")}
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
                {report.roe.attackVectors && (report.roe.attackVectors as any[]).length > 0 && (
                  <Card className="bg-slate-900/60 border-slate-700/50">
                    <CardHeader>
                      <CardTitle className="text-base text-white">Authorized Attack Vectors</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-2">
                        {(report.roe.attackVectors as string[]).map((v: string, i: number) => (
                          <Badge key={i} variant="outline" className="border-orange-500/30 text-orange-300 capitalize">
                            {v.replace(/_/g, " ")}
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>

              {/* Schedule */}
              {(report.roe.scheduleStart || report.roe.scheduleEnd) && (
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-base text-white flex items-center gap-2">
                      <Calendar className="w-4 h-4" style={{ color: brandColor }} /> Testing Schedule
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      {report.roe.scheduleStart && (
                        <div>
                          <p className="text-xs text-slate-500 uppercase">Start Date</p>
                          <p className="text-slate-300">{new Date(report.roe.scheduleStart).toLocaleDateString()}</p>
                        </div>
                      )}
                      {report.roe.scheduleEnd && (
                        <div>
                          <p className="text-xs text-slate-500 uppercase">End Date</p>
                          <p className="text-slate-300">{new Date(report.roe.scheduleEnd).toLocaleDateString()}</p>
                        </div>
                      )}
                      {report.roe.scheduleTimezone && (
                        <div>
                          <p className="text-xs text-slate-500 uppercase">Timezone</p>
                          <p className="text-slate-300">{report.roe.scheduleTimezone}</p>
                        </div>
                      )}
                      {report.roe.scheduleWindow && (
                        <div>
                          <p className="text-xs text-slate-500 uppercase">Testing Window</p>
                          <p className="text-slate-300">{report.roe.scheduleWindow}</p>
                        </div>
                      )}
                    </div>
                    {report.roe.scheduleDays && (report.roe.scheduleDays as any[]).length > 0 && (
                      <div className="mt-3">
                        <p className="text-xs text-slate-500 uppercase mb-1">Testing Days</p>
                        <div className="flex gap-2">
                          {(report.roe.scheduleDays as string[]).map((d: string) => (
                            <Badge key={d} variant="outline" className="border-slate-600 text-slate-300 capitalize">{d}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Communications */}
              {(report.roe.commFrequency || report.roe.commMethod || report.roe.incidentResponse) && (
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-base text-white flex items-center gap-2">
                      <Radio className="w-4 h-4" style={{ color: brandColor }} /> Communications & Escalation
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm">
                    {report.roe.commFrequency && (
                      <div><span className="text-slate-500">Frequency:</span> <span className="text-slate-300 capitalize">{report.roe.commFrequency.replace(/_/g, " ")}</span></div>
                    )}
                    {report.roe.commMethod && (
                      <div><span className="text-slate-500">Method:</span> <span className="text-slate-300 capitalize">{report.roe.commMethod.replace(/_/g, " ")}</span></div>
                    )}
                    {report.roe.incidentResponse && (
                      <div>
                        <p className="text-slate-500 mb-1">Incident Response Plan:</p>
                        <p className="text-slate-300 bg-slate-800/30 p-3 rounded">{report.roe.incidentResponse}</p>
                      </div>
                    )}
                    {report.roe.haltConditions && (
                      <div>
                        <p className="text-slate-500 mb-1">Halt Conditions:</p>
                        <p className="text-slate-300 bg-slate-800/30 p-3 rounded">{report.roe.haltConditions}</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Data Handling */}
              {(report.roe.dataHandling || report.roe.evidenceRetention) && (
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-base text-white flex items-center gap-2">
                      <Database className="w-4 h-4" style={{ color: brandColor }} /> Data Handling & Evidence
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm">
                    {report.roe.dataHandling && (<div><span className="text-slate-500">Data Handling:</span> <span className="text-slate-300">{report.roe.dataHandling}</span></div>)}
                    {report.roe.evidenceRetention && (<div><span className="text-slate-500">Evidence Retention:</span> <span className="text-slate-300">{report.roe.evidenceRetention}</span></div>)}
                    {report.roe.piiHandling && (<div><span className="text-slate-500">PII Handling:</span> <span className="text-slate-300">{report.roe.piiHandling}</span></div>)}
                    {report.roe.encryptionRequired !== undefined && (<div><span className="text-slate-500">Encryption Required:</span> <span className="text-slate-300">{report.roe.encryptionRequired ? "Yes" : "No"}</span></div>)}
                    {report.roe.destructionMethod && (<div><span className="text-slate-500">Destruction Method:</span> <span className="text-slate-300 capitalize">{report.roe.destructionMethod.replace(/_/g, " ")}</span></div>)}
                  </CardContent>
                </Card>
              )}

              {/* Legal & Compliance */}
              {(report.roe.legalJurisdiction || report.roe.complianceFrameworks) && (
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-base text-white flex items-center gap-2">
                      <Scale className="w-4 h-4" style={{ color: brandColor }} /> Legal & Compliance
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm">
                    {report.roe.legalJurisdiction && (<div><span className="text-slate-500">Jurisdiction:</span> <span className="text-slate-300">{report.roe.legalJurisdiction}</span></div>)}
                    {report.roe.ndaRequired !== undefined && (<div><span className="text-slate-500">NDA Required:</span> <span className="text-slate-300">{report.roe.ndaRequired ? "Yes" : "No"}</span></div>)}
                    {report.roe.liabilityClause && (<div><span className="text-slate-500">Liability:</span> <span className="text-slate-300">{report.roe.liabilityClause}</span></div>)}
                    {report.roe.complianceFrameworks && (report.roe.complianceFrameworks as any[]).length > 0 && (
                      <div>
                        <p className="text-slate-500 mb-2">Compliance Frameworks:</p>
                        <div className="flex flex-wrap gap-2">
                          {(report.roe.complianceFrameworks as string[]).map((f: string, i: number) => (
                            <Badge key={i} variant="outline" className="border-blue-500/30 text-blue-300 uppercase text-xs">{f}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Personnel */}
              {report.roe.personnel && report.roe.personnel.length > 0 && (
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-base text-white flex items-center gap-2">
                      <Users className="w-4 h-4" style={{ color: brandColor }} /> Key Personnel
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {report.roe.personnel.map((p: any, i: number) => (
                        <div key={i} className="p-3 rounded-lg bg-slate-800/30 border border-slate-700/20">
                          <div className="flex items-center justify-between mb-1">
                            <p className="font-medium text-white text-sm">{p.name}</p>
                            {p.isPrimary && <Badge className="bg-teal-500/20 text-teal-300 text-xs">Primary</Badge>}
                          </div>
                          <p className="text-xs text-slate-400 capitalize">{p.role?.replace(/_/g, " ")}</p>
                          {p.organization && <p className="text-xs text-slate-500">{p.organization}</p>}
                          {p.email && <p className="text-xs text-slate-500">{p.email}</p>}
                          {p.phone && <p className="text-xs text-slate-500">{p.phone}</p>}
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Signatures */}
              <Card className="bg-slate-900/60 border-slate-700/50">
                <CardHeader>
                  <CardTitle className="text-base text-white flex items-center gap-2">
                    <Pen className="w-4 h-4" style={{ color: brandColor }} /> Signatures
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {report.roe.signatures && report.roe.signatures.length > 0 ? (
                    <div className="space-y-3">
                      {report.roe.signatures.map((sig: any, i: number) => (
                        <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-slate-800/30 border border-slate-700/20">
                          <div>
                            <p className="font-medium text-white text-sm">{sig.signerName}</p>
                            <p className="text-xs text-slate-400">{sig.signerTitle} — {sig.signerOrganization}</p>
                            <p className="text-xs text-slate-500">{sig.signerEmail}</p>
                          </div>
                          <div className="text-right">
                            <Badge className="bg-green-500/20 text-green-300 text-xs">Signed</Badge>
                            {sig.signedAt && <p className="text-xs text-slate-500 mt-1">{new Date(sig.signedAt).toLocaleString()}</p>}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-6">
                      <Pen className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                      <p className="text-sm text-slate-400">No signatures yet</p>
                      {(report.roe.status === "pending_review" || report.roe.status === "approved") && (
                        <Button size="sm" onClick={() => setShowSignDialog(true)} className="mt-3 bg-teal-600 hover:bg-teal-700 text-white">
                          <Pen className="w-4 h-4 mr-1.5" /> Be the first to sign
                        </Button>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          )}
        </Tabs>

        {/* RoE Signature Dialog */}
        <Dialog open={showSignDialog} onOpenChange={setShowSignDialog}>
          <DialogContent className="bg-slate-900 border-slate-700 text-white max-w-lg">
            <DialogHeader>
              <DialogTitle>Sign Rules of Engagement</DialogTitle>
              <DialogDescription className="text-slate-400">
                By signing this document, you acknowledge and agree to the terms, scope, and conditions outlined in the Rules of Engagement.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label className="text-slate-300">Full Name *</Label>
                  <Input value={signForm.name} onChange={(e) => setSignForm({ ...signForm, name: e.target.value })} placeholder="John Smith" className="bg-slate-800 border-slate-600 text-white" />
                </div>
                <div className="space-y-2">
                  <Label className="text-slate-300">Title *</Label>
                  <Input value={signForm.title} onChange={(e) => setSignForm({ ...signForm, title: e.target.value })} placeholder="CISO" className="bg-slate-800 border-slate-600 text-white" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label className="text-slate-300">Organization *</Label>
                  <Input value={signForm.organization} onChange={(e) => setSignForm({ ...signForm, organization: e.target.value })} placeholder="Acme Corp" className="bg-slate-800 border-slate-600 text-white" />
                </div>
                <div className="space-y-2">
                  <Label className="text-slate-300">Email *</Label>
                  <Input type="email" value={signForm.email} onChange={(e) => setSignForm({ ...signForm, email: e.target.value })} placeholder="john@acme.com" className="bg-slate-800 border-slate-600 text-white" />
                </div>
              </div>
              <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700/50">
                <p className="text-xs text-slate-500 mb-2">Digital Signature (Typed)</p>
                <div className="h-16 flex items-center justify-center border border-dashed border-slate-600 rounded bg-slate-900/50">
                  {signForm.name ? (
                    <p className="text-2xl italic text-teal-400" style={{ fontFamily: "'Georgia', serif" }}>{signForm.name}</p>
                  ) : (
                    <p className="text-sm text-slate-600">Your typed signature will appear here</p>
                  )}
                </div>
              </div>
              <div className="flex items-start gap-2 p-3 rounded bg-amber-500/10 border border-amber-500/20">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <p className="text-xs text-amber-300">By clicking "Sign Document" below, you are providing your legally binding electronic signature under the Electronic Signatures in Global and National Commerce Act (E-SIGN Act).</p>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowSignDialog(false)} className="border-slate-600 text-slate-300">Cancel</Button>
              <Button
                onClick={() => {
                  if (!signForm.name || !signForm.title || !signForm.organization || !signForm.email) {
                    toast.error("Please fill in all required fields.");
                    return;
                  }
                  signRoeMutation.mutate({
                    token,
                    password,
                    roeId: report.roe.id,
                    signerName: signForm.name,
                    signerTitle: signForm.title,
                    signerOrganization: signForm.organization,
                    signerEmail: signForm.email,
                    signatureData: signForm.name, // typed signature
                    signatureType: "typed",
                  });
                }}
                disabled={signRoeMutation.isPending}
                className="bg-teal-600 hover:bg-teal-700 text-white"
              >
                {signRoeMutation.isPending ? "Signing..." : "Sign Document"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Footer */}
        <footer className="border-t border-slate-800/50 pt-6 pb-8 text-center text-xs text-slate-600">
          <p>This report was prepared by <strong className="text-slate-500">Harrison Cook</strong> at <strong className="text-slate-500">AceofCloud</strong></p>
          <p className="mt-1">Confidential — For authorized recipients only</p>
        </footer>
      </main>
    </div>
      </AppShell>
  );
}
