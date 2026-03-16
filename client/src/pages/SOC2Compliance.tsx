import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { Shield, CheckCircle2, AlertTriangle, XCircle, FileText, BarChart3, GitBranch, Clock, Target, Layers, Building2, TrendingUp, Eye, Zap, ArrowRight, Lock, ShieldCheck, Flag, Award, Gauge } from "lucide-react";

export default function SOC2Compliance() {
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedFramework, setSelectedFramework] = useState("SOC2");
  const [selectedCategory, setSelectedCategory] = useState<string | undefined>(undefined);
  const [selectedStatus, setSelectedStatus] = useState<string | undefined>(undefined);
  const [fedRAMPFamily, setFedRAMPFamily] = useState<string | undefined>(undefined);
  const [cmmcDomain, setCMMCDomain] = useState<string | undefined>(undefined);
  const [cmmcLevel, setCMMCLevel] = useState(2);

  const frameworks = trpc.soc2Compliance.getFrameworks.useQuery();
  const controls = trpc.soc2Compliance.getControls.useQuery({ framework: selectedFramework, category: selectedCategory, status: selectedStatus });
  const categories = trpc.soc2Compliance.getCategories.useQuery({ framework: selectedFramework });
  const findings = trpc.soc2Compliance.getFindings.useQuery({});
  const stats = trpc.soc2Compliance.dashboardStats.useQuery();
  const timeline = trpc.soc2Compliance.getPostureTimeline.useQuery({ framework: selectedFramework, days: 90 });

  // FedRAMP queries
  const fedRAMPControls = trpc.soc2Compliance.getFedRAMPControls.useQuery(
    { family: fedRAMPFamily, baseline: "moderate" },
    { enabled: activeTab === "fedramp" }
  );
  const fedRAMPPOAM = trpc.soc2Compliance.getFedRAMPPOAM.useQuery(undefined, { enabled: activeTab === "fedramp" });
  const atoStatus = trpc.soc2Compliance.getATOPackageStatus.useQuery(undefined, { enabled: activeTab === "fedramp" });

  // CMMC queries
  const cmmcPractices = trpc.soc2Compliance.getCMMCPractices.useQuery(
    { domain: cmmcDomain, level: cmmcLevel },
    { enabled: activeTab === "cmmc" }
  );
  const sprsScore = trpc.soc2Compliance.getSPRSScore.useQuery(undefined, { enabled: activeTab === "cmmc" });
  const cmmcAssessment = trpc.soc2Compliance.getCMMCAssessment.useQuery(
    { level: cmmcLevel },
    { enabled: activeTab === "cmmc" }
  );

  const updateFinding = trpc.soc2Compliance.updateFinding.useMutation({
    onSuccess: () => { toast.success("Finding status updated"); findings.refetch(); },
  });

  const statusIcon = (status: string) => {
    switch (status) {
      case "compliant": case "implemented": case "met": return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
      case "partial": case "partially_implemented": case "partially_met": return <AlertTriangle className="h-4 w-4 text-amber-400" />;
      case "non_compliant": case "not_implemented": case "not_met": return <XCircle className="h-4 w-4 text-red-400" />;
      case "inherited": return <ShieldCheck className="h-4 w-4 text-blue-400" />;
      case "planned": return <Clock className="h-4 w-4 text-purple-400" />;
      default: return <Clock className="h-4 w-4 text-zinc-400" />;
    }
  };

  const statusColor = (status: string) => {
    switch (status) {
      case "compliant": case "implemented": case "met": return "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";
      case "partial": case "partially_implemented": case "partially_met": return "text-amber-400 border-amber-500/30 bg-amber-500/10";
      case "non_compliant": case "not_implemented": case "not_met": return "text-red-400 border-red-500/30 bg-red-500/10";
      case "inherited": return "text-blue-400 border-blue-500/30 bg-blue-500/10";
      case "planned": return "text-purple-400 border-purple-500/30 bg-purple-500/10";
      default: return "text-zinc-400 border-zinc-500/30 bg-zinc-500/10";
    }
  };

  const severityColor = (sev: string) => {
    switch (sev) {
      case "critical": return "bg-red-500/20 text-red-300 border-red-500/30";
      case "high": return "bg-orange-500/20 text-orange-300 border-orange-500/30";
      case "medium": return "bg-amber-500/20 text-amber-300 border-amber-500/30";
      case "low": return "bg-blue-500/20 text-blue-300 border-blue-500/30";
      default: return "bg-zinc-500/20 text-zinc-300 border-zinc-500/30";
    }
  };

  const certColor = (status: string) => {
    switch (status) {
      case "certified": return "text-emerald-400 border-emerald-500/30";
      case "in_progress": return "text-amber-400 border-amber-500/30";
      case "expired": return "text-red-400 border-red-500/30";
      default: return "text-zinc-400 border-zinc-500/30";
    }
  };

  const sprsGaugeColor = (score: number) => {
    if (score >= 80) return "text-emerald-400";
    if (score >= 40) return "text-amber-400";
    if (score >= 0) return "text-orange-400";
    return "text-red-400";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-7 w-7 text-emerald-400" />
            Enterprise Compliance
          </h1>
          <p className="text-muted-foreground mt-1">SOC 2, ISO 27001, NIST 800-53, PCI DSS, HIPAA, FedRAMP, and CMMC compliance with automated evidence collection</p>
        </div>
        <Select value={selectedFramework} onValueChange={setSelectedFramework}>
          <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="SOC2">SOC 2 Type II</SelectItem>
            <SelectItem value="ISO27001">ISO 27001</SelectItem>
            <SelectItem value="NIST800-53">NIST 800-53</SelectItem>
            <SelectItem value="PCI-DSS">PCI DSS</SelectItem>
            <SelectItem value="HIPAA">HIPAA</SelectItem>
            <SelectItem value="FedRAMP">FedRAMP</SelectItem>
            <SelectItem value="CMMC">CMMC 2.0</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: "Overall Score", value: `${stats.data?.overallScore ?? 0}%`, icon: Target, color: (stats.data?.overallScore ?? 0) >= 80 ? "text-emerald-400" : "text-amber-400" },
          { label: "Compliant", value: stats.data?.compliantControls ?? 0, icon: CheckCircle2, color: "text-emerald-400" },
          { label: "Partial", value: stats.data?.partialControls ?? 0, icon: AlertTriangle, color: "text-amber-400" },
          { label: "Open Findings", value: stats.data?.openFindings ?? 0, icon: FileText, color: "text-red-400" },
          { label: "Frameworks", value: stats.data?.frameworkCount ?? 0, icon: Layers, color: "text-cyan-400" },
        ].map((kpi) => (
          <Card key={kpi.label} className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-4 flex items-center gap-4">
              <kpi.icon className={`h-8 w-8 ${kpi.color}`} />
              <div>
                <div className="text-2xl font-bold">{kpi.value}</div>
                <div className="text-xs text-muted-foreground">{kpi.label}</div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="flex-wrap">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="controls">Controls</TabsTrigger>
          <TabsTrigger value="findings">Audit Findings</TabsTrigger>
          <TabsTrigger value="frameworks">Frameworks</TabsTrigger>
          <TabsTrigger value="fedramp" className="flex items-center gap-1"><Flag className="h-3 w-3" /> FedRAMP</TabsTrigger>
          <TabsTrigger value="cmmc" className="flex items-center gap-1"><Award className="h-3 w-3" /> CMMC</TabsTrigger>
          <TabsTrigger value="evidence">Evidence</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4 mt-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-lg">Control Categories</CardTitle>
              <CardDescription>Compliance posture by SOC 2 TSC category</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {categories.data?.map(cat => (
                  <div key={cat.name} className="space-y-1 cursor-pointer hover:bg-zinc-800/30 p-2 rounded transition-colors" onClick={() => { setSelectedCategory(cat.name); setActiveTab("controls"); }}>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">{cat.name}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">{cat.compliant}/{cat.totalControls} compliant</span>
                        <Badge variant="outline" className={cat.score >= 80 ? "text-emerald-400 border-emerald-500/30" : cat.score >= 60 ? "text-amber-400 border-amber-500/30" : "text-red-400 border-red-500/30"}>
                          {cat.score}%
                        </Badge>
                      </div>
                    </div>
                    <div className="flex gap-0.5 h-2 rounded overflow-hidden">
                      <div className="bg-emerald-500/60 transition-all" style={{ width: `${(cat.compliant / cat.totalControls) * 100}%` }} />
                      <div className="bg-amber-500/60 transition-all" style={{ width: `${(cat.partial / cat.totalControls) * 100}%` }} />
                      <div className="bg-red-500/60 transition-all" style={{ width: `${(cat.nonCompliant / cat.totalControls) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2"><TrendingUp className="h-5 w-5 text-emerald-400" /> Compliance Posture Trend</CardTitle>
              <CardDescription>90-day compliance score trajectory</CardDescription>
            </CardHeader>
            <CardContent>
              {timeline.data && timeline.data.length > 0 ? (
                <div className="space-y-3">
                  <div className="flex items-end gap-1 h-32">
                    {timeline.data.map((point, i) => (
                      <div key={i} className="flex-1 flex flex-col items-center justify-end h-full">
                        <div
                          className={`w-full rounded-t transition-all ${point.score >= 90 ? "bg-emerald-500/50" : point.score >= 80 ? "bg-emerald-500/30" : point.score >= 70 ? "bg-amber-500/30" : "bg-red-500/30"}`}
                          style={{ height: `${point.score}%` }}
                        />
                      </div>
                    ))}
                  </div>
                  <div className="flex justify-between text-xs text-muted-foreground">
                    <span>{timeline.data[0]?.date}</span>
                    <span>{timeline.data[timeline.data.length - 1]?.date}</span>
                  </div>
                </div>
              ) : (
                <div className="text-center text-muted-foreground p-8">No timeline data available</div>
              )}
            </CardContent>
          </Card>

          {findings.data && findings.data.filter(f => f.severity === "critical" || f.severity === "high").length > 0 && (
            <Card className="bg-gradient-to-r from-red-950/20 to-orange-950/20 border-red-800/30">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2"><AlertTriangle className="h-4 w-4 text-red-400" /> Critical & High Findings</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {findings.data.filter(f => f.severity === "critical" || f.severity === "high").map(f => (
                  <div key={f.id} className="flex items-center justify-between p-2 rounded bg-zinc-900/50">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className={severityColor(f.severity)}>{f.severity}</Badge>
                      <span className="text-sm">{f.title}</span>
                      <Badge variant="outline" className="text-xs">{f.controlId}</Badge>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">Due: {new Date(f.dueDate).toLocaleDateString()}</span>
                      <Badge variant="outline" className="text-xs">{f.status}</Badge>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Controls Tab */}
        <TabsContent value="controls" className="space-y-3 mt-4">
          <div className="flex gap-2 mb-3">
            <Select value={selectedCategory || "all"} onValueChange={v => setSelectedCategory(v === "all" ? undefined : v)}>
              <SelectTrigger className="w-48"><SelectValue placeholder="All Categories" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                {categories.data?.map(c => <SelectItem key={c.name} value={c.name}>{c.name}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={selectedStatus || "all"} onValueChange={v => setSelectedStatus(v === "all" ? undefined : v)}>
              <SelectTrigger className="w-48"><SelectValue placeholder="All Statuses" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="compliant">Compliant</SelectItem>
                <SelectItem value="partial">Partial</SelectItem>
                <SelectItem value="non_compliant">Non-Compliant</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {controls.data?.map(control => (
            <Card key={control.id} className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {statusIcon(control.status)}
                    <span className="font-mono text-sm text-muted-foreground">{control.id}</span>
                    <span className="font-medium">{control.title}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={`text-xs ${control.automationLevel === "full" ? "text-cyan-400 border-cyan-500/30" : control.automationLevel === "partial" ? "text-amber-400 border-amber-500/30" : "text-zinc-400 border-zinc-500/30"}`}>
                      {control.automationLevel === "full" ? "Automated" : control.automationLevel === "partial" ? "Semi-Auto" : "Manual"}
                    </Badge>
                    <Badge variant="outline" className={statusColor(control.status)}>{control.status.replace("_", " ")}</Badge>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-2">{control.description}</p>
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <span>Owner: {control.owner}</span>
                  <span>Priority: <Badge variant="outline" className="text-xs">{control.priority}</Badge></span>
                  {control.evidence.length > 0 && <span className="flex items-center gap-1"><FileText className="h-3 w-3" /> {control.evidence.length} evidence items</span>}
                  {control.mappings.length > 0 && (
                    <span className="flex items-center gap-1">
                      <GitBranch className="h-3 w-3" />
                      Maps to: {control.mappings.map(m => `${m.framework} ${m.controlId}`).join(", ")}
                    </span>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        {/* Findings Tab */}
        <TabsContent value="findings" className="space-y-3 mt-4">
          {findings.data?.map(finding => (
            <Card key={finding.id} className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={severityColor(finding.severity)}>{finding.severity}</Badge>
                    <span className="font-medium">{finding.title}</span>
                    <Badge variant="outline" className="text-xs">{finding.controlId}</Badge>
                  </div>
                  <Select value={finding.status} onValueChange={v => updateFinding.mutate({ findingId: finding.id, status: v as any })}>
                    <SelectTrigger className="w-36 h-8"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="open">Open</SelectItem>
                      <SelectItem value="in_progress">In Progress</SelectItem>
                      <SelectItem value="remediated">Remediated</SelectItem>
                      <SelectItem value="accepted_risk">Accepted Risk</SelectItem>
                      <SelectItem value="false_positive">False Positive</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <p className="text-sm text-muted-foreground mb-2">{finding.description}</p>
                <div className="p-2 rounded bg-zinc-800/50 text-sm">
                  <span className="text-xs text-muted-foreground">Recommendation:</span>
                  <p className="mt-1">{finding.recommendation}</p>
                </div>
                <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                  <span>Assignee: {finding.assignee}</span>
                  <span>Due: {new Date(finding.dueDate).toLocaleDateString()}</span>
                  <span>Discovered: {new Date(finding.discoveredAt).toLocaleDateString()}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        {/* Frameworks Tab */}
        <TabsContent value="frameworks" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {frameworks.data?.map(fw => (
              <Card key={fw.id} className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors cursor-pointer" onClick={() => {
                if (fw.id === "fedramp") { setActiveTab("fedramp"); }
                else if (fw.id === "cmmc") { setActiveTab("cmmc"); }
                else { setSelectedFramework(fw.id.toUpperCase().replace("-", "")); setActiveTab("controls"); }
              }}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <h3 className="font-medium">{fw.name}</h3>
                      <span className="text-xs text-muted-foreground">v{fw.version}</span>
                    </div>
                    <Badge variant="outline" className={certColor(fw.certificationStatus)}>
                      {fw.certificationStatus.replace("_", " ")}
                    </Badge>
                  </div>
                  <div className="text-center mb-3">
                    <div className={`text-3xl font-bold ${fw.overallScore >= 80 ? "text-emerald-400" : fw.overallScore >= 60 ? "text-amber-400" : "text-red-400"}`}>
                      {fw.overallScore}%
                    </div>
                    <div className="text-xs text-muted-foreground">Compliance Score</div>
                  </div>
                  <div className="space-y-1 text-sm">
                    <div className="flex justify-between"><span className="text-muted-foreground">Total Controls</span><span>{fw.totalControls}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Assessed</span><span>{fw.assessedControls}</span></div>
                    <div className="flex justify-between"><span className="text-emerald-400">Compliant</span><span>{fw.compliantControls}</span></div>
                    <div className="flex justify-between"><span className="text-amber-400">Partial</span><span>{fw.partialControls}</span></div>
                    <div className="flex justify-between"><span className="text-red-400">Non-Compliant</span><span>{fw.nonCompliantControls}</span></div>
                  </div>
                  <div className="mt-3 flex gap-0.5 h-2 rounded overflow-hidden">
                    <div className="bg-emerald-500/60" style={{ width: `${(fw.compliantControls / fw.totalControls) * 100}%` }} />
                    <div className="bg-amber-500/60" style={{ width: `${(fw.partialControls / fw.totalControls) * 100}%` }} />
                    <div className="bg-red-500/60" style={{ width: `${(fw.nonCompliantControls / fw.totalControls) * 100}%` }} />
                    <div className="bg-zinc-700/60 flex-1" />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* ═══════════════════ FedRAMP Tab ═══════════════════ */}
        <TabsContent value="fedramp" className="space-y-4 mt-4">
          {/* ATO Package Status */}
          {atoStatus.data && (
            <Card className="bg-gradient-to-r from-blue-950/20 to-indigo-950/20 border-blue-800/30">
              <CardHeader className="pb-3">
                <CardTitle className="text-lg flex items-center gap-2">
                  <Flag className="h-5 w-5 text-blue-400" /> ATO Package Status
                </CardTitle>
                <CardDescription>Authorization to Operate package progress for FedRAMP Moderate</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div className="p-3 rounded bg-zinc-900/50">
                    <div className="text-xs text-muted-foreground">ATO Status</div>
                    <Badge variant="outline" className={atoStatus.data.atoStatus === "authorized" ? "text-emerald-400 border-emerald-500/30" : "text-amber-400 border-amber-500/30"}>
                      {atoStatus.data.atoStatus.replace("_", " ")}
                    </Badge>
                  </div>
                  <div className="p-3 rounded bg-zinc-900/50">
                    <div className="text-xs text-muted-foreground">Impact Level</div>
                    <div className="font-bold text-blue-400">{atoStatus.data.impactLevel}</div>
                  </div>
                  <div className="p-3 rounded bg-zinc-900/50">
                    <div className="text-xs text-muted-foreground">3PAO</div>
                    <div className="text-sm">{atoStatus.data.thirdPartyAssessor}</div>
                  </div>
                  <div className="p-3 rounded bg-zinc-900/50">
                    <div className="text-xs text-muted-foreground">Sponsoring Agency</div>
                    <div className="text-sm">{atoStatus.data.sponsoringAgency}</div>
                  </div>
                </div>
                <div className="space-y-2">
                  <div className="text-sm font-medium">Package Documents</div>
                  {atoStatus.data.documents.map((doc: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-2 rounded bg-zinc-800/50">
                      <div className="flex items-center gap-2">
                        <FileText className="h-4 w-4 text-blue-400" />
                        <span className="text-sm">{doc.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Progress value={doc.completionPct} className="w-24 h-2" />
                        <span className="text-xs text-muted-foreground">{doc.completionPct}%</span>
                        <Badge variant="outline" className={doc.status === "complete" ? "text-emerald-400 border-emerald-500/30" : doc.status === "in_progress" ? "text-amber-400 border-amber-500/30" : "text-zinc-400 border-zinc-500/30"}>
                          {doc.status.replace("_", " ")}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* FedRAMP Control Families */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg">FedRAMP Moderate Controls</CardTitle>
                  <CardDescription>
                    {fedRAMPControls.data?.totalControls ?? 0} controls |{" "}
                    <span className="text-emerald-400">{fedRAMPControls.data?.implemented ?? 0} implemented</span> |{" "}
                    <span className="text-amber-400">{fedRAMPControls.data?.partiallyImplemented ?? 0} partial</span> |{" "}
                    <span className="text-purple-400">{fedRAMPControls.data?.planned ?? 0} planned</span> |{" "}
                    <span className="text-blue-400">{fedRAMPControls.data?.inherited ?? 0} inherited</span>
                  </CardDescription>
                </div>
                <Select value={fedRAMPFamily || "all"} onValueChange={v => setFedRAMPFamily(v === "all" ? undefined : v)}>
                  <SelectTrigger className="w-64"><SelectValue placeholder="All Families" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Families</SelectItem>
                    {fedRAMPControls.data?.familySummary?.map((f: any) => (
                      <SelectItem key={f.family} value={f.family}>{f.family} - {f.familyName} ({f.total})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent>
              {!fedRAMPFamily ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {fedRAMPControls.data?.familySummary?.map((fam: any) => (
                    <div key={fam.family} className="p-3 rounded bg-zinc-800/50 cursor-pointer hover:bg-zinc-800 transition-colors" onClick={() => setFedRAMPFamily(fam.family)}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-mono text-sm font-medium">{fam.family}</span>
                        <span className="text-xs text-muted-foreground">{fam.total} controls</span>
                      </div>
                      <div className="text-xs text-muted-foreground mb-2">{fam.familyName}</div>
                      <div className="flex gap-0.5 h-2 rounded overflow-hidden">
                        <div className="bg-emerald-500/60" style={{ width: `${(fam.implemented / fam.total) * 100}%` }} />
                        <div className="bg-amber-500/60" style={{ width: `${(fam.partiallyImplemented / fam.total) * 100}%` }} />
                        <div className="bg-blue-500/60" style={{ width: `${(fam.inherited / fam.total) * 100}%` }} />
                        <div className="bg-purple-500/60" style={{ width: `${(fam.planned / fam.total) * 100}%` }} />
                        <div className="bg-red-500/60" style={{ width: `${(fam.notImplemented / fam.total) * 100}%` }} />
                      </div>
                      <div className="flex gap-3 mt-1 text-xs">
                        <span className="text-emerald-400">{fam.implemented}</span>
                        <span className="text-amber-400">{fam.partiallyImplemented}</span>
                        <span className="text-blue-400">{fam.inherited}</span>
                        <span className="text-purple-400">{fam.planned}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="space-y-2">
                  <Button variant="ghost" size="sm" onClick={() => setFedRAMPFamily(undefined)} className="mb-2">
                    <ArrowRight className="h-3 w-3 rotate-180 mr-1" /> All Families
                  </Button>
                  {fedRAMPControls.data?.controls.map((ctrl: any) => (
                    <div key={ctrl.controlId} className="p-3 rounded bg-zinc-800/50">
                      <div className="flex items-start justify-between mb-1">
                        <div className="flex items-center gap-2">
                          {statusIcon(ctrl.status === "implemented" ? "implemented" : ctrl.status === "partially_implemented" ? "partially_implemented" : ctrl.status === "inherited" ? "inherited" : ctrl.status === "planned" ? "planned" : "not_implemented")}
                          <span className="font-mono text-sm text-muted-foreground">{ctrl.controlId}</span>
                          <span className="text-sm font-medium">{ctrl.title}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={statusColor(ctrl.status)}>{ctrl.status.replace(/_/g, " ")}</Badge>
                          <Badge variant="outline" className="text-xs">{ctrl.baseline}</Badge>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground mb-1">{ctrl.description}</p>
                      {ctrl.nistMapping.length > 0 && (
                        <div className="text-xs text-muted-foreground flex items-center gap-1">
                          <GitBranch className="h-3 w-3" /> NIST: {ctrl.nistMapping.join(", ")}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* POA&M */}
          {fedRAMPPOAM.data && fedRAMPPOAM.data.length > 0 && (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2"><AlertTriangle className="h-5 w-5 text-amber-400" /> Plan of Action & Milestones (POA&M)</CardTitle>
                <CardDescription>{fedRAMPPOAM.data.length} open items requiring remediation</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {fedRAMPPOAM.data.map((item: any) => (
                  <div key={item.id} className="p-3 rounded bg-zinc-800/50">
                    <div className="flex items-start justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={severityColor(item.risk)}>{item.risk}</Badge>
                        <span className="font-mono text-xs">{item.controlId}</span>
                        <span className="text-sm">{item.weakness}</span>
                      </div>
                      <Badge variant="outline" className={item.status === "completed" ? "text-emerald-400 border-emerald-500/30" : item.status === "in_progress" ? "text-amber-400 border-amber-500/30" : "text-zinc-400 border-zinc-500/30"}>
                        {item.status.replace("_", " ")}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">{item.mitigationPlan}</p>
                    <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                      <span>Due: {new Date(item.scheduledCompletion).toLocaleDateString()}</span>
                      <span>Milestone: {item.milestone}</span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ═══════════════════ CMMC Tab ═══════════════════ */}
        <TabsContent value="cmmc" className="space-y-4 mt-4">
          {/* SPRS Score */}
          {sprsScore.data && (
            <Card className="bg-gradient-to-r from-indigo-950/20 to-purple-950/20 border-indigo-800/30">
              <CardHeader className="pb-3">
                <CardTitle className="text-lg flex items-center gap-2">
                  <Gauge className="h-5 w-5 text-indigo-400" /> SPRS Score
                </CardTitle>
                <CardDescription>Supplier Performance Risk System score for CMMC Level 2 assessment readiness</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div className="text-center p-4 rounded bg-zinc-900/50">
                    <div className={`text-4xl font-bold ${sprsGaugeColor(sprsScore.data.totalScore)}`}>
                      {sprsScore.data.totalScore}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">SPRS Score (max 110)</div>
                    <Progress value={(sprsScore.data.totalScore / 110) * 100} className="mt-2 h-2" />
                  </div>
                  <div className="p-4 rounded bg-zinc-900/50">
                    <div className="text-2xl font-bold text-emerald-400">{sprsScore.data.practicesMet}</div>
                    <div className="text-xs text-muted-foreground">Practices Met</div>
                  </div>
                  <div className="p-4 rounded bg-zinc-900/50">
                    <div className="text-2xl font-bold text-amber-400">{sprsScore.data.practicesPartial}</div>
                    <div className="text-xs text-muted-foreground">Partially Met</div>
                  </div>
                  <div className="p-4 rounded bg-zinc-900/50">
                    <div className="text-2xl font-bold text-red-400">{sprsScore.data.practicesNotMet}</div>
                    <div className="text-xs text-muted-foreground">Not Met</div>
                  </div>
                </div>
                {sprsScore.data.domainScores && (
                  <div className="space-y-2">
                    <div className="text-sm font-medium">Domain Breakdown</div>
                    {sprsScore.data.domainScores.map((ds: any) => (
                      <div key={ds.domain} className="flex items-center gap-3 p-2 rounded bg-zinc-800/50">
                        <span className="font-mono text-xs w-8">{ds.domain}</span>
                        <span className="text-xs text-muted-foreground w-48 truncate">{ds.domainName}</span>
                        <div className="flex-1">
                          <Progress value={(ds.met / ds.total) * 100} className="h-2" />
                        </div>
                        <span className="text-xs w-16 text-right">{ds.met}/{ds.total}</span>
                        <span className="text-xs w-12 text-right font-mono">{ds.score}/{ds.maxScore}</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* CMMC Assessment Readiness */}
          {cmmcAssessment.data && (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-lg flex items-center gap-2"><Award className="h-5 w-5 text-purple-400" /> Assessment Readiness</CardTitle>
                    <CardDescription>CMMC Level {cmmcLevel} certification readiness analysis</CardDescription>
                  </div>
                  <Select value={String(cmmcLevel)} onValueChange={v => setCMMCLevel(Number(v))}>
                    <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">Level 1 (FCI)</SelectItem>
                      <SelectItem value="2">Level 2 (CUI)</SelectItem>
                      <SelectItem value="3">Level 3 (Expert)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                  <div className="p-3 rounded bg-zinc-800/50 text-center">
                    <div className={`text-2xl font-bold ${cmmcAssessment.data.readinessScore >= 80 ? "text-emerald-400" : cmmcAssessment.data.readinessScore >= 60 ? "text-amber-400" : "text-red-400"}`}>
                      {cmmcAssessment.data.readinessScore}%
                    </div>
                    <div className="text-xs text-muted-foreground">Readiness</div>
                  </div>
                  <div className="p-3 rounded bg-zinc-800/50 text-center">
                    <div className="text-2xl font-bold">{cmmcAssessment.data.totalPractices}</div>
                    <div className="text-xs text-muted-foreground">Total Practices</div>
                  </div>
                  <div className="p-3 rounded bg-zinc-800/50 text-center">
                    <div className="text-2xl font-bold text-emerald-400">{cmmcAssessment.data.met}</div>
                    <div className="text-xs text-muted-foreground">Met</div>
                  </div>
                  <div className="p-3 rounded bg-zinc-800/50 text-center">
                    <div className="text-2xl font-bold text-red-400">{cmmcAssessment.data.gaps}</div>
                    <div className="text-xs text-muted-foreground">Gaps</div>
                  </div>
                </div>
                {cmmcAssessment.data.gapDetails && cmmcAssessment.data.gapDetails.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-sm font-medium">Gap Analysis</div>
                    {cmmcAssessment.data.gapDetails.slice(0, 15).map((gap: any, i: number) => (
                      <div key={i} className="flex items-center justify-between p-2 rounded bg-zinc-800/50">
                        <div className="flex items-center gap-2">
                          <XCircle className="h-3 w-3 text-red-400" />
                          <span className="font-mono text-xs">{gap.practiceId}</span>
                          <span className="text-sm">{gap.title}</span>
                        </div>
                        <Badge variant="outline" className={statusColor(gap.status)}>{gap.status.replace(/_/g, " ")}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* CMMC Practices by Domain */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg">CMMC Practices</CardTitle>
                  <CardDescription>
                    {cmmcPractices.data?.totalPractices ?? 0} practices |{" "}
                    <span className="text-emerald-400">{cmmcPractices.data?.met ?? 0} met</span> |{" "}
                    <span className="text-amber-400">{cmmcPractices.data?.partiallyMet ?? 0} partial</span> |{" "}
                    <span className="text-red-400">{cmmcPractices.data?.notMet ?? 0} not met</span>
                  </CardDescription>
                </div>
                <Select value={cmmcDomain || "all"} onValueChange={v => setCMMCDomain(v === "all" ? undefined : v)}>
                  <SelectTrigger className="w-64"><SelectValue placeholder="All Domains" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Domains</SelectItem>
                    {cmmcPractices.data?.domainSummary?.map((d: any) => (
                      <SelectItem key={d.domain} value={d.domain}>{d.domain} - {d.domainName} ({d.total})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent>
              {!cmmcDomain ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {cmmcPractices.data?.domainSummary?.map((dom: any) => (
                    <div key={dom.domain} className="p-3 rounded bg-zinc-800/50 cursor-pointer hover:bg-zinc-800 transition-colors" onClick={() => setCMMCDomain(dom.domain)}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-mono text-sm font-medium">{dom.domain}</span>
                        <span className="text-xs text-muted-foreground">{dom.total} practices</span>
                      </div>
                      <div className="text-xs text-muted-foreground mb-2">{dom.domainName}</div>
                      <div className="flex gap-0.5 h-2 rounded overflow-hidden">
                        <div className="bg-emerald-500/60" style={{ width: `${(dom.met / dom.total) * 100}%` }} />
                        <div className="bg-amber-500/60" style={{ width: `${(dom.partiallyMet / dom.total) * 100}%` }} />
                        <div className="bg-red-500/60" style={{ width: `${(dom.notMet / dom.total) * 100}%` }} />
                      </div>
                      <div className="flex gap-3 mt-1 text-xs">
                        <span className="text-emerald-400">{dom.met} met</span>
                        <span className="text-amber-400">{dom.partiallyMet} partial</span>
                        <span className="text-red-400">{dom.notMet} not met</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="space-y-2">
                  <Button variant="ghost" size="sm" onClick={() => setCMMCDomain(undefined)} className="mb-2">
                    <ArrowRight className="h-3 w-3 rotate-180 mr-1" /> All Domains
                  </Button>
                  {cmmcPractices.data?.practices.map((p: any) => (
                    <div key={p.practiceId} className="p-3 rounded bg-zinc-800/50">
                      <div className="flex items-start justify-between mb-1">
                        <div className="flex items-center gap-2">
                          {statusIcon(p.status)}
                          <span className="font-mono text-sm text-muted-foreground">{p.practiceId}</span>
                          <span className="text-sm font-medium">{p.title}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs">L{p.level}</Badge>
                          <Badge variant="outline" className={`text-xs ${p.weight >= 5 ? "text-red-400 border-red-500/30" : p.weight >= 3 ? "text-amber-400 border-amber-500/30" : "text-zinc-400 border-zinc-500/30"}`}>
                            Weight: {p.weight}
                          </Badge>
                          <Badge variant="outline" className={statusColor(p.status)}>{p.status.replace(/_/g, " ")}</Badge>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground mb-1">{p.description}</p>
                      {p.nistMapping.length > 0 && (
                        <div className="text-xs text-muted-foreground flex items-center gap-1">
                          <GitBranch className="h-3 w-3" /> NIST 800-171: {p.nistMapping.join(", ")}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Evidence Tab */}
        <TabsContent value="evidence" className="mt-4">
          {/* Auto-Collected Evidence from Engagements */}
          <Card className="bg-zinc-900/50 border-zinc-800 mb-4">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2"><Zap className="h-5 w-5 text-emerald-400" /> Auto-Collected Evidence from Engagements</CardTitle>
              <CardDescription>Real evidence automatically mapped from pentest engagements, vulnerability scans, and tool outputs to compliance controls across all 7 frameworks.</CardDescription>
            </CardHeader>
            <CardContent>
              <AutoEvidencePanel />
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2"><FileText className="h-5 w-5 text-cyan-400" /> Static Evidence Collection</CardTitle>
              <CardDescription>Framework-defined evidence mapped to compliance controls. {stats.data?.evidenceItems ?? 0} evidence items across {stats.data?.totalControls ?? 0} controls.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {controls.data?.filter(c => c.evidence.length > 0).slice(0, 10).map(control => (
                  <div key={control.id} className="p-3 rounded bg-zinc-800/50">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="font-mono text-xs text-muted-foreground">{control.id}</span>
                      <span className="text-sm font-medium">{control.title}</span>
                    </div>
                    <div className="space-y-1">
                      {control.evidence.map(ev => (
                        <div key={ev.id} className="flex items-center gap-2 text-sm p-1.5 rounded bg-zinc-900/50">
                          {ev.automated ? <Zap className="h-3 w-3 text-cyan-400" /> : <Eye className="h-3 w-3 text-zinc-400" />}
                          <Badge variant="outline" className="text-xs">{ev.type.replace("_", " ")}</Badge>
                          <span className="truncate">{ev.title}</span>
                          <span className="text-xs text-muted-foreground ml-auto">{ev.source}</span>
                          <span className="text-xs text-muted-foreground">{new Date(ev.collectedAt).toLocaleDateString()}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function AutoEvidencePanel() {
  const [engagementId, setEngagementId] = useState("");
  const posture = trpc.soc2Compliance.getCompliancePosture.useQuery(undefined, { retry: false });
  const engagementEvidence = trpc.soc2Compliance.getEngagementEvidence.useQuery(
    { engagementId },
    { enabled: !!engagementId, retry: false }
  );
  const mappingRules = trpc.soc2Compliance.getMappingRules.useQuery(undefined, { retry: false });

  const frameworkColors: Record<string, string> = {
    SOC2: "text-blue-400", FedRAMP: "text-red-400", CMMC: "text-amber-400",
    ISO27001: "text-green-400", HIPAA: "text-purple-400", "PCI DSS": "text-orange-400", "NIST CSF": "text-cyan-400"
  };

  return (
    <div className="space-y-4">
      {/* Compliance Posture Summary */}
      {posture.data && (
        <div>
          <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-emerald-400" /> Compliance Posture Across Frameworks
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {posture.data.frameworkPosture?.map((fp: any) => (
              <div key={fp.framework} className="p-2 rounded bg-zinc-800/50 text-center">
                <span className={`text-xs font-medium ${frameworkColors[fp.framework] || 'text-zinc-400'}`}>{fp.framework}</span>
                <div className="text-lg font-bold mt-1">{fp.controlsCovered}/{fp.totalControls}</div>
                <Progress value={(fp.controlsCovered / Math.max(fp.totalControls, 1)) * 100} className="h-1 mt-1" />
                <span className="text-xs text-muted-foreground">{fp.coveragePercent}% covered</span>
              </div>
            ))}
          </div>
          {posture.data.totalFindings !== undefined && (
            <div className="flex gap-4 mt-3 text-xs text-muted-foreground">
              <span>Total findings mapped: <strong className="text-foreground">{posture.data.totalFindings}</strong></span>
              <span>Engagements analyzed: <strong className="text-foreground">{posture.data.engagementsAnalyzed}</strong></span>
              <span>Overall score: <strong className="text-emerald-400">{posture.data.overallScore}/100</strong></span>
            </div>
          )}
        </div>
      )}

      {/* Mapping Rules Summary */}
      {mappingRules.data && (
        <div>
          <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
            <GitBranch className="h-4 w-4 text-cyan-400" /> Evidence Mapping Rules
          </h4>
          <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
            {Object.entries(mappingRules.data.rulesByCategory || {}).map(([cat, count]: [string, any]) => (
              <div key={cat} className="p-2 rounded bg-zinc-800/50 text-center">
                <span className="text-xs text-muted-foreground">{cat}</span>
                <div className="text-sm font-bold mt-1">{count}</div>
              </div>
            ))}
          </div>
          <p className="text-xs text-muted-foreground mt-1">{mappingRules.data.totalRules} mapping rules across {mappingRules.data.frameworksCovered} frameworks</p>
        </div>
      )}

      {/* Per-Engagement Evidence Lookup */}
      <div>
        <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
          <Target className="h-4 w-4 text-amber-400" /> Engagement Evidence Lookup
        </h4>
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Enter engagement ID to view mapped evidence..."
            value={engagementId}
            onChange={e => setEngagementId(e.target.value)}
            className="flex-1 px-3 py-1.5 rounded bg-zinc-800 border border-zinc-700 text-sm focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
          <Button size="sm" variant="outline" onClick={() => setEngagementId(engagementId)} disabled={!engagementId}>
            <ArrowRight className="h-4 w-4" />
          </Button>
        </div>
        {engagementEvidence.data && (
          <div className="mt-3 space-y-2">
            <div className="flex gap-4 text-xs text-muted-foreground mb-2">
              <span>Controls mapped: <strong className="text-foreground">{engagementEvidence.data.controlsMapped}</strong></span>
              <span>Evidence items: <strong className="text-foreground">{engagementEvidence.data.evidenceCount}</strong></span>
              <span>Frameworks: <strong className="text-foreground">{engagementEvidence.data.frameworksCovered}</strong></span>
            </div>
            {engagementEvidence.data.evidence?.slice(0, 15).map((ev: any, i: number) => (
              <div key={i} className="flex items-center gap-2 text-sm p-2 rounded bg-zinc-800/50">
                <Zap className="h-3 w-3 text-emerald-400 shrink-0" />
                <Badge variant="outline" className={`text-xs ${frameworkColors[ev.framework] || ''}`}>{ev.framework}</Badge>
                <span className="font-mono text-xs text-muted-foreground">{ev.controlId}</span>
                <span className="truncate">{ev.description}</span>
                <Badge variant="outline" className="text-xs ml-auto">{ev.toolSource}</Badge>
              </div>
            ))}
          </div>
        )}
        {engagementEvidence.isError && engagementId && (
          <p className="text-xs text-muted-foreground mt-2">No evidence found for this engagement. Run an engagement first to auto-collect compliance evidence.</p>
        )}
      </div>

      {!posture.data && !posture.isLoading && (
        <div className="text-center py-6 text-muted-foreground">
          <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No compliance evidence collected yet. Run engagements to auto-map findings to compliance controls.</p>
        </div>
      )}
    </div>
  );
}
