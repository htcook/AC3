import React, { useState, useMemo, useCallback } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  Shield,
  Plus,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Sparkles,
  Eye,
  Trash2,
  ChevronRight,
  ArrowLeft,
  Download,
  RefreshCw,
  ShieldCheck,
  Loader2,
  AlertCircle,
  Edit3,
  Save,
  XCircle,
  Upload,
  Zap,
  FileDown,
  Server,
  Target,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

// ─── Severity Config ────────────────────────────────────────────────────────

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; border: string; label: string }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", label: "Critical" },
  high: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", label: "High" },
  moderate: { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", label: "Moderate" },
  low: { color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", label: "Low" },
  informational: { color: "text-gray-400", bg: "bg-gray-500/10", border: "border-gray-500/30", label: "Info" },
};

const STATUS_CONFIG: Record<string, { color: string; bg: string; icon: React.ReactNode; label: string }> = {
  draft: { color: "text-gray-400", bg: "bg-gray-500/10", icon: <Edit3 className="h-3 w-3" />, label: "Draft" },
  generating: { color: "text-blue-400", bg: "bg-blue-500/10", icon: <Loader2 className="h-3 w-3 animate-spin" />, label: "Generating" },
  review: { color: "text-yellow-400", bg: "bg-yellow-500/10", icon: <Eye className="h-3 w-3" />, label: "In Review" },
  approved: { color: "text-green-400", bg: "bg-green-500/10", icon: <CheckCircle2 className="h-3 w-3" />, label: "Approved" },
  final: { color: "text-emerald-400", bg: "bg-emerald-500/10", icon: <ShieldCheck className="h-3 w-3" />, label: "Final" },
};

const QA_STATUS_CONFIG: Record<string, { color: string; label: string }> = {
  pending: { color: "text-gray-400", label: "Pending" },
  pass: { color: "text-green-400", label: "Pass" },
  revise: { color: "text-red-400", label: "Revise" },
};

// ─── Main Component ─────────────────────────────────────────────────────────

export default function Ac3Reports() {
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  return (
    <AppShell activePath="/ac3-reports">
      <div className="w-full space-y-6">
        {selectedReportId ? (
          <ReportDetail
            reportId={selectedReportId}
            onBack={() => setSelectedReportId(null)}
          />
        ) : (
          <ReportList
            onSelect={setSelectedReportId}
            onCreateNew={() => setShowCreateDialog(true)}
          />
        )}
        <CreateReportDialog
          open={showCreateDialog}
          onClose={() => setShowCreateDialog(false)}
          onCreated={(id) => {
            setShowCreateDialog(false);
            setSelectedReportId(id);
          }}
        />
      </div>
    </AppShell>
  );
}

// ─── Report List ────────────────────────────────────────────────────────────

function ReportList({ onSelect, onCreateNew }: { onSelect: (id: string) => void; onCreateNew: () => void }) {
  const { data: reports, isLoading } = trpc.ac3Reports.listReports.useQuery();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-red-500/20 to-orange-500/20 border border-red-500/30 flex items-center justify-center">
            <Shield className="h-5 w-5 text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">AC3 FedRAMP Reports</h1>
            <p className="text-sm text-muted-foreground">
              FedRAMP-compliant penetration test and red team assessment reports
            </p>
          </div>
        </div>
        <Button onClick={onCreateNew} className="gap-2">
          <Plus className="h-4 w-4" />
          New Report
        </Button>
      </div>

      {/* Info Banner */}
      <Card className="border-blue-500/20 bg-blue-500/5">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <ShieldCheck className="h-5 w-5 text-blue-400 mt-0.5 shrink-0" />
            <div className="text-sm text-blue-300/80">
              <p className="font-medium text-blue-300 mb-1">FedRAMP Assessment Report Generator</p>
              <p>
                Platform-controlled severity, evidence, ATT&CK IDs, and NIST 800-53 control mappings serve as the
                source of truth. The LLM drafts only bounded narrative fields (title, summary, business impact,
                technical details, remediation) which require human review before approval.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Report Cards */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : !reports?.length ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FileText className="h-12 w-12 text-muted-foreground/30 mb-4" />
            <p className="text-muted-foreground text-sm">No reports yet</p>
            <Button variant="outline" className="mt-4 gap-2" onClick={onCreateNew}>
              <Plus className="h-4 w-4" />
              Create Your First Report
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4">
          {reports.map((report: any) => {
            const status = STATUS_CONFIG[report.status] || STATUS_CONFIG.draft;
            const qa = QA_STATUS_CONFIG[report.qaStatus] || QA_STATUS_CONFIG.pending;
            return (
              <Card
                key={report.reportId}
                className="cursor-pointer hover:border-primary/30 transition-colors"
                onClick={() => onSelect(report.reportId)}
              >
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-1">
                        <h3 className="font-semibold truncate">{report.name}</h3>
                        <Badge variant="outline" className={`${status.bg} ${status.color} border-0 gap-1 text-xs`}>
                          {status.icon}
                          {status.label}
                        </Badge>
                        {report.qaStatus !== "pending" && (
                          <Badge variant="outline" className={`${qa.color} border-0 text-xs`}>
                            QA: {qa.label}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        <span>{report.clientName || "No client"}</span>
                        <span>{report.assessmentType?.replace(/_/g, " ") || "Pentest"}</span>
                        {report.fedrampImpactLevel && (
                          <Badge variant="outline" className="text-xs border-amber-500/30 text-amber-400">
                            FedRAMP {report.fedrampImpactLevel.toUpperCase()}
                          </Badge>
                        )}
                        <span className="ml-auto">{report.reportId}</span>
                      </div>
                    </div>
                    <ChevronRight className="h-5 w-5 text-muted-foreground ml-4 shrink-0" />
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Create Report Dialog ───────────────────────────────────────────────────

function CreateReportDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (id: string) => void }) {
  const { toast } = useToast();
  const utils = trpc.useUtils();
  const createMutation = trpc.ac3Reports.createReport.useMutation({
    onSuccess: (data) => {
      utils.ac3Reports.listReports.invalidate();
      onCreated(data.reportId);
      toast({ title: "Report created", description: `Report ${data.reportId} created successfully.` });
    },
    onError: (err) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const [form, setForm] = useState({
    name: "",
    clientName: "",
    systemName: "",
    assessmentType: "penetration_test" as const,
    fedrampImpactLevel: "moderate" as const,
    cloudProvider: "",
    serviceModel: "",
  });

  const handleCreate = () => {
    if (!form.name.trim()) {
      toast({ title: "Name required", variant: "destructive" });
      return;
    }
    createMutation.mutate({
      name: form.name,
      clientName: form.clientName || undefined,
      systemName: form.systemName || undefined,
      assessmentType: form.assessmentType,
      fedrampImpactLevel: form.fedrampImpactLevel,
      cloudProvider: form.cloudProvider || undefined,
      serviceModel: form.serviceModel || undefined,
    });
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Create New Assessment Report</DialogTitle>
          <DialogDescription>
            Configure the report metadata. These fields are platform-controlled and serve as the source of truth.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Report Name *</Label>
            <Input
              value={form.name}
              onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="Q1 2026 External Penetration Test"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Client Name</Label>
              <Input
                value={form.clientName}
                onChange={(e) => setForm(f => ({ ...f, clientName: e.target.value }))}
                placeholder="Acme Corp"
              />
            </div>
            <div>
              <Label>System Name</Label>
              <Input
                value={form.systemName}
                onChange={(e) => setForm(f => ({ ...f, systemName: e.target.value }))}
                placeholder="CloudGov Production"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Assessment Type</Label>
              <Select
                value={form.assessmentType}
                onValueChange={(v) => setForm(f => ({ ...f, assessmentType: v as any }))}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="penetration_test">Penetration Test</SelectItem>
                  <SelectItem value="red_team">Red Team</SelectItem>
                  <SelectItem value="purple_team">Purple Team</SelectItem>
                  <SelectItem value="vulnerability_assessment">Vulnerability Assessment</SelectItem>
                  <SelectItem value="hybrid">Hybrid</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>FedRAMP Impact Level</Label>
              <Select
                value={form.fedrampImpactLevel}
                onValueChange={(v) => setForm(f => ({ ...f, fedrampImpactLevel: v as any }))}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="moderate">Moderate</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="li-saas">LI-SaaS</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Cloud Provider</Label>
              <Input
                value={form.cloudProvider}
                onChange={(e) => setForm(f => ({ ...f, cloudProvider: e.target.value }))}
                placeholder="AWS GovCloud"
              />
            </div>
            <div>
              <Label>Service Model</Label>
              <Input
                value={form.serviceModel}
                onChange={(e) => setForm(f => ({ ...f, serviceModel: e.target.value }))}
                placeholder="SaaS / IaaS / PaaS"
              />
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleCreate} disabled={createMutation.isPending}>
            {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
            Create Report
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Report Detail ──────────────────────────────────────────────────────────

function ReportDetail({ reportId, onBack }: { reportId: string; onBack: () => void }) {
  const { toast } = useToast();
  const utils = trpc.useUtils();
  const { data: reportData, isLoading } = trpc.ac3Reports.getReport.useQuery({ reportId });
  const [activeTab, setActiveTab] = useState("findings");
  const [showAddFinding, setShowAddFinding] = useState(false);
  const [editingMetadata, setEditingMetadata] = useState(false);
  const [showEngagementImport, setShowEngagementImport] = useState(false);
  const [showCalderaImport, setShowCalderaImport] = useState(false);

  const generateAllMutation = trpc.ac3Reports.generateAllNarratives.useMutation({
    onSuccess: (data) => {
      utils.ac3Reports.getReport.invalidate({ reportId });
      toast({ title: "Narratives generated", description: `Processed ${data.totalProcessed} findings.` });
    },
    onError: (err) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const generateExecMutation = trpc.ac3Reports.generateExecSummary.useMutation({
    onSuccess: () => {
      utils.ac3Reports.getReport.invalidate({ reportId });
      toast({ title: "Executive summary generated" });
    },
    onError: (err) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const qaReviewMutation = trpc.ac3Reports.runQaReview.useMutation({
    onSuccess: (data) => {
      utils.ac3Reports.getReport.invalidate({ reportId });
      toast({
        title: `QA Review: ${data.qaStatus.toUpperCase()}`,
        description: data.review.issues.length > 0
          ? `${data.review.issues.length} issue(s) found`
          : "No issues found",
      });
    },
    onError: (err) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const updateStatusMutation = trpc.ac3Reports.updateReport.useMutation({
    onSuccess: () => {
      utils.ac3Reports.getReport.invalidate({ reportId });
      toast({ title: "Status updated" });
    },
  });

  const deleteReportMutation = trpc.ac3Reports.deleteReport.useMutation({
    onSuccess: () => {
      utils.ac3Reports.listReports.invalidate();
      onBack();
      toast({ title: "Report deleted" });
    },
  });

  if (isLoading || !reportData) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const report = reportData;
  const findings = (report as any).findings || [];
  const status = STATUS_CONFIG[report.status] || STATUS_CONFIG.draft;
  const pendingNarratives = findings.filter((f: any) => f.narrativeStatus === "pending").length;

  const severityCounts = findings.reduce((acc: any, f: any) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={onBack}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold tracking-tight">{report.name}</h1>
              <Badge variant="outline" className={`${status.bg} ${status.color} border-0 gap-1`}>
                {status.icon}
                {status.label}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              {report.reportId} · {report.clientName || "No client"} · {report.assessmentType?.replace(/_/g, " ")}
              {report.fedrampImpactLevel && ` · FedRAMP ${report.fedrampImpactLevel.toUpperCase()}`}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            onClick={() => deleteReportMutation.mutate({ reportId })}
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete
          </Button>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {["critical", "high", "moderate", "low", "informational"].map((sev) => {
          const cfg = SEVERITY_CONFIG[sev];
          return (
            <Card key={sev} className={`${cfg.bg} border ${cfg.border}`}>
              <CardContent className="p-3 text-center">
                <div className={`text-2xl font-bold ${cfg.color}`}>
                  {severityCounts[sev] || 0}
                </div>
                <div className={`text-xs ${cfg.color} opacity-80`}>{cfg.label}</div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Action Bar */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center gap-3">
            <Button
              size="sm"
              className="gap-2"
              onClick={() => setShowAddFinding(true)}
            >
              <Plus className="h-3.5 w-3.5" />
              Add Finding
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              onClick={() => setShowEngagementImport(true)}
            >
              <Upload className="h-3.5 w-3.5" />
              Import Engagement
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              onClick={() => setShowCalderaImport(true)}
            >
              <Zap className="h-3.5 w-3.5" />
              Import Caldera Op
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              onClick={() => generateAllMutation.mutate({ reportId })}
              disabled={generateAllMutation.isPending || pendingNarratives === 0}
            >
              {generateAllMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Sparkles className="h-3.5 w-3.5" />
              )}
              Generate Narratives ({pendingNarratives} pending)
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              onClick={() => generateExecMutation.mutate({ reportId })}
              disabled={generateExecMutation.isPending || findings.length === 0}
            >
              {generateExecMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <FileText className="h-3.5 w-3.5" />
              )}
              Generate Exec Summary
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              onClick={() => qaReviewMutation.mutate({ reportId })}
              disabled={qaReviewMutation.isPending}
            >
              {qaReviewMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <ShieldCheck className="h-3.5 w-3.5" />
              )}
              Run QA Review
            </Button>
            <div className="ml-auto flex items-center gap-2">
              <Select
                value={report.status}
                onValueChange={(v) => updateStatusMutation.mutate({ reportId, status: v as any })}
              >
                <SelectTrigger className="w-[140px] h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="draft">Draft</SelectItem>
                  <SelectItem value="review">In Review</SelectItem>
                  <SelectItem value="approved">Approved</SelectItem>
                  <SelectItem value="final">Final</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="findings" className="gap-2">
            <AlertTriangle className="h-3.5 w-3.5" />
            Findings ({findings.length})
          </TabsTrigger>
          <TabsTrigger value="executive" className="gap-2">
            <FileText className="h-3.5 w-3.5" />
            Executive Summary
          </TabsTrigger>
          <TabsTrigger value="qa" className="gap-2">
            <ShieldCheck className="h-3.5 w-3.5" />
            QA Review
          </TabsTrigger>
          <TabsTrigger value="metadata" className="gap-2">
            <Shield className="h-3.5 w-3.5" />
            Metadata & Scope
          </TabsTrigger>
          <TabsTrigger value="export" className="gap-2">
            <Download className="h-3.5 w-3.5" />
            Export
          </TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-4 mt-4">
          <FindingsTab reportId={reportId} findings={findings} />
        </TabsContent>

        <TabsContent value="executive" className="space-y-4 mt-4">
          <ExecSummaryTab report={report} />
        </TabsContent>

        <TabsContent value="qa" className="space-y-4 mt-4">
          <QaReviewTab report={report} />
        </TabsContent>

        <TabsContent value="metadata" className="space-y-4 mt-4">
          <MetadataTab report={report} reportId={reportId} />
        </TabsContent>

        <TabsContent value="export" className="space-y-4 mt-4">
          <ExportTab reportId={reportId} />
        </TabsContent>
      </Tabs>

      {/* Add Finding Dialog */}
      <AddFindingDialog
        open={showAddFinding}
        onClose={() => setShowAddFinding(false)}
        reportId={reportId}
      />

      {/* Engagement Import Dialog */}
      <EngagementImportDialog
        open={showEngagementImport}
        onClose={() => setShowEngagementImport(false)}
        reportId={reportId}
      />

      {/* Caldera Import Dialog */}
      <CalderaImportDialog
        open={showCalderaImport}
        onClose={() => setShowCalderaImport(false)}
        reportId={reportId}
      />
    </div>
  );
}

// ─── Findings Tab ───────────────────────────────────────────────────────────

function FindingsTab({ reportId, findings }: { reportId: string; findings: any[] }) {
  const { toast } = useToast();
  const utils = trpc.useUtils();
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const generateNarrative = trpc.ac3Reports.generateFindingNarrative.useMutation({
    onSuccess: () => {
      utils.ac3Reports.getReport.invalidate({ reportId });
      toast({ title: "Narrative generated" });
    },
    onError: (err) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const deleteFinding = trpc.ac3Reports.deleteFinding.useMutation({
    onSuccess: () => {
      utils.ac3Reports.getReport.invalidate({ reportId });
      toast({ title: "Finding deleted" });
    },
  });

  const updateFinding = trpc.ac3Reports.updateFinding.useMutation({
    onSuccess: () => {
      utils.ac3Reports.getReport.invalidate({ reportId });
      toast({ title: "Finding updated" });
    },
  });

  if (!findings.length) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <AlertTriangle className="h-12 w-12 text-muted-foreground/30 mb-4" />
          <p className="text-muted-foreground text-sm">No findings yet. Add findings to begin report generation.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-3">
      {findings.map((finding: any) => {
        const sev = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.informational;
        const isExpanded = expandedId === finding.findingId;
        const techniques = (finding.attackTechniques as any[] || []);
        const controls = (finding.controls as any[] || []);

        return (
          <Card key={finding.findingId} className={`${sev.bg} border ${sev.border}`}>
            <CardContent className="p-4">
              {/* Finding Header */}
              <div
                className="flex items-center justify-between cursor-pointer"
                onClick={() => setExpandedId(isExpanded ? null : finding.findingId)}
              >
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <Badge variant="outline" className={`${sev.color} ${sev.bg} border-0 text-xs shrink-0`}>
                    {sev.label}
                  </Badge>
                  <span className="font-medium truncate">{finding.title}</span>
                  {finding.cvssScore && (
                    <Badge variant="outline" className="text-xs shrink-0">
                      CVSS {finding.cvssScore}
                    </Badge>
                  )}
                  <Badge variant="outline" className={`text-xs shrink-0 ${
                    finding.narrativeStatus === "approved" ? "text-green-400" :
                    finding.narrativeStatus === "drafted" ? "text-blue-400" :
                    finding.narrativeStatus === "reviewed" ? "text-yellow-400" :
                    "text-gray-400"
                  }`}>
                    {finding.narrativeStatus}
                  </Badge>
                </div>
                <ChevronRight className={`h-4 w-4 text-muted-foreground transition-transform ${isExpanded ? "rotate-90" : ""}`} />
              </div>

              {/* Expanded Detail */}
              {isExpanded && (
                <div className="mt-4 space-y-4 border-t border-border/50 pt-4">
                  {/* Platform-Controlled Fields (Source of Truth) */}
                  <div className="space-y-3">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                      <Shield className="h-3.5 w-3.5" />
                      Platform Source of Truth
                    </h4>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                      <div>
                        <Label className="text-xs text-muted-foreground">Severity</Label>
                        <p className={`text-sm font-medium ${sev.color}`}>{sev.label}</p>
                      </div>
                      {finding.cvssScore && (
                        <div>
                          <Label className="text-xs text-muted-foreground">CVSS</Label>
                          <p className="text-sm">{finding.cvssScore} {finding.cvssVector && `(${finding.cvssVector})`}</p>
                        </div>
                      )}
                      <div>
                        <Label className="text-xs text-muted-foreground">Finding ID</Label>
                        <p className="text-sm font-mono">{finding.findingId}</p>
                      </div>
                    </div>

                    {/* ATT&CK Techniques */}
                    {techniques.length > 0 && (
                      <div>
                        <Label className="text-xs text-muted-foreground">ATT&CK Techniques</Label>
                        <div className="flex flex-wrap gap-1.5 mt-1">
                          {techniques.map((t: any, i: number) => (
                            <Badge key={i} variant="outline" className="text-xs bg-purple-500/10 text-purple-400 border-purple-500/30">
                              {t.id}{t.name ? `: ${t.name}` : ""}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* NIST Controls */}
                    {controls.length > 0 && (
                      <div>
                        <Label className="text-xs text-muted-foreground">NIST 800-53 Controls</Label>
                        <div className="flex flex-wrap gap-1.5 mt-1">
                          {controls.map((c: any, i: number) => (
                            <Badge key={i} variant="outline" className="text-xs bg-cyan-500/10 text-cyan-400 border-cyan-500/30">
                              {c.id}{c.family ? ` (${c.family})` : ""}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Evidence */}
                    {(finding.evidence as any[] || []).length > 0 && (
                      <div>
                        <Label className="text-xs text-muted-foreground">Evidence</Label>
                        <div className="space-y-1 mt-1">
                          {(finding.evidence as any[]).map((e: any, i: number) => (
                            <div key={i} className="text-xs bg-background/50 rounded px-2 py-1 flex items-center gap-2">
                              <Badge variant="outline" className="text-[10px]">{e.type}</Badge>
                              <span>{e.description}</span>
                              {e.url && <a href={e.url} target="_blank" rel="noopener" className="text-blue-400 hover:underline ml-auto">View</a>}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Assets */}
                    {(finding.assets as any[] || []).length > 0 && (
                      <div>
                        <Label className="text-xs text-muted-foreground">Affected Assets</Label>
                        <div className="flex flex-wrap gap-1.5 mt-1">
                          {(finding.assets as string[]).map((a, i) => (
                            <Badge key={i} variant="outline" className="text-xs">{a}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* LLM-Drafted Narrative Fields */}
                  <div className="space-y-3">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                      <Sparkles className="h-3.5 w-3.5" />
                      LLM-Drafted Narratives
                      <Badge variant="outline" className="text-[10px] ml-2">
                        {finding.narrativeStatus === "pending" ? "Not yet generated" : finding.narrativeStatus}
                      </Badge>
                    </h4>

                    {finding.narrativeStatus === "pending" ? (
                      <div className="text-center py-4">
                        <p className="text-sm text-muted-foreground mb-3">
                          Narrative fields have not been generated yet.
                        </p>
                        <Button
                          size="sm"
                          variant="outline"
                          className="gap-2"
                          onClick={() => generateNarrative.mutate({ findingId: finding.findingId })}
                          disabled={generateNarrative.isPending}
                        >
                          {generateNarrative.isPending ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Sparkles className="h-3.5 w-3.5" />
                          )}
                          Generate Narrative
                        </Button>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {finding.summary && (
                          <div>
                            <Label className="text-xs text-muted-foreground">Summary</Label>
                            <p className="text-sm mt-1">{finding.summary}</p>
                          </div>
                        )}
                        {finding.businessImpact && (
                          <div>
                            <Label className="text-xs text-muted-foreground">Business Impact</Label>
                            <p className="text-sm mt-1">{finding.businessImpact}</p>
                          </div>
                        )}
                        {finding.technicalDetails && (
                          <div>
                            <Label className="text-xs text-muted-foreground">Technical Details</Label>
                            <p className="text-sm mt-1 whitespace-pre-wrap">{finding.technicalDetails}</p>
                          </div>
                        )}
                        {finding.remediation && (
                          <div>
                            <Label className="text-xs text-muted-foreground">Remediation</Label>
                            <p className="text-sm mt-1 whitespace-pre-wrap">{finding.remediation}</p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 pt-2 border-t border-border/50">
                    {finding.narrativeStatus !== "pending" && (
                      <>
                        <Button
                          size="sm"
                          variant="outline"
                          className="gap-1 text-xs"
                          onClick={() => generateNarrative.mutate({ findingId: finding.findingId })}
                          disabled={generateNarrative.isPending}
                        >
                          <RefreshCw className="h-3 w-3" />
                          Regenerate
                        </Button>
                        {finding.narrativeStatus === "drafted" && (
                          <Button
                            size="sm"
                            variant="outline"
                            className="gap-1 text-xs text-green-400"
                            onClick={() => updateFinding.mutate({ findingId: finding.findingId, narrativeStatus: "approved" })}
                          >
                            <CheckCircle2 className="h-3 w-3" />
                            Approve
                          </Button>
                        )}
                      </>
                    )}
                    <Button
                      size="sm"
                      variant="ghost"
                      className="gap-1 text-xs text-red-400 ml-auto"
                      onClick={() => deleteFinding.mutate({ findingId: finding.findingId })}
                    >
                      <Trash2 className="h-3 w-3" />
                      Delete
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

// ─── Add Finding Dialog ─────────────────────────────────────────────────────

function AddFindingDialog({ open, onClose, reportId }: { open: boolean; onClose: () => void; reportId: string }) {
  const { toast } = useToast();
  const utils = trpc.useUtils();

  const addMutation = trpc.ac3Reports.addFinding.useMutation({
    onSuccess: () => {
      utils.ac3Reports.getReport.invalidate({ reportId });
      onClose();
      toast({ title: "Finding added" });
      setForm(defaultForm);
    },
    onError: (err) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const defaultForm = {
    title: "",
    severity: "high" as const,
    cvssScore: "",
    cvssVector: "",
    attackTechniques: "",
    controls: "",
    assets: "",
    evidenceDesc: "",
    evidenceType: "screenshot",
    evidenceRef: "",
  };

  const [form, setForm] = useState(defaultForm);

  const handleAdd = () => {
    if (!form.title.trim()) {
      toast({ title: "Title required", variant: "destructive" });
      return;
    }

    const attackTechniques = form.attackTechniques
      .split(",")
      .map(s => s.trim())
      .filter(Boolean)
      .map(id => ({ id }));

    const controls = form.controls
      .split(",")
      .map(s => s.trim())
      .filter(Boolean)
      .map(id => ({ id }));

    const assets = form.assets
      .split(",")
      .map(s => s.trim())
      .filter(Boolean);

    const evidence = form.evidenceDesc ? [{
      type: form.evidenceType,
      reference: form.evidenceRef || form.evidenceDesc,
      description: form.evidenceDesc,
    }] : [];

    addMutation.mutate({
      reportId,
      title: form.title,
      severity: form.severity,
      cvssScore: form.cvssScore || undefined,
      cvssVector: form.cvssVector || undefined,
      attackTechniques: attackTechniques.length > 0 ? attackTechniques : undefined,
      controls: controls.length > 0 ? controls : undefined,
      assets: assets.length > 0 ? assets : undefined,
      evidence: evidence.length > 0 ? evidence : undefined,
    });
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add Finding</DialogTitle>
          <DialogDescription>
            Define platform-controlled fields. Severity, evidence, ATT&CK IDs, and controls are the source of truth.
            The LLM will draft narrative fields separately.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Finding Title *</Label>
            <Input
              value={form.title}
              onChange={(e) => setForm(f => ({ ...f, title: e.target.value }))}
              placeholder="Unauthenticated API Endpoint Exposes PII"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Severity *</Label>
              <Select value={form.severity} onValueChange={(v) => setForm(f => ({ ...f, severity: v as any }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="moderate">Moderate</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="informational">Informational</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>CVSS Score</Label>
              <Input
                value={form.cvssScore}
                onChange={(e) => setForm(f => ({ ...f, cvssScore: e.target.value }))}
                placeholder="9.1"
              />
            </div>
          </div>
          <div>
            <Label>CVSS Vector</Label>
            <Input
              value={form.cvssVector}
              onChange={(e) => setForm(f => ({ ...f, cvssVector: e.target.value }))}
              placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
            />
          </div>
          <div>
            <Label>ATT&CK Techniques (comma-separated)</Label>
            <Input
              value={form.attackTechniques}
              onChange={(e) => setForm(f => ({ ...f, attackTechniques: e.target.value }))}
              placeholder="T1190, T1078, T1530"
            />
          </div>
          <div>
            <Label>NIST 800-53 Controls (comma-separated)</Label>
            <Input
              value={form.controls}
              onChange={(e) => setForm(f => ({ ...f, controls: e.target.value }))}
              placeholder="AC-3, SC-8, IA-2"
            />
          </div>
          <div>
            <Label>Affected Assets (comma-separated)</Label>
            <Input
              value={form.assets}
              onChange={(e) => setForm(f => ({ ...f, assets: e.target.value }))}
              placeholder="api.example.com, 10.0.1.50"
            />
          </div>
          <div className="space-y-2">
            <Label>Evidence</Label>
            <div className="grid grid-cols-3 gap-2">
              <Select value={form.evidenceType} onValueChange={(v) => setForm(f => ({ ...f, evidenceType: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="screenshot">Screenshot</SelectItem>
                  <SelectItem value="log">Log</SelectItem>
                  <SelectItem value="network_capture">Network Capture</SelectItem>
                  <SelectItem value="command_output">Command Output</SelectItem>
                  <SelectItem value="configuration">Configuration</SelectItem>
                </SelectContent>
              </Select>
              <Input
                className="col-span-2"
                value={form.evidenceRef}
                onChange={(e) => setForm(f => ({ ...f, evidenceRef: e.target.value }))}
                placeholder="Evidence reference/URL"
              />
            </div>
            <Textarea
              value={form.evidenceDesc}
              onChange={(e) => setForm(f => ({ ...f, evidenceDesc: e.target.value }))}
              placeholder="Evidence description..."
              rows={2}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleAdd} disabled={addMutation.isPending}>
            {addMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
            Add Finding
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Executive Summary Tab ──────────────────────────────────────────────────

function ExecSummaryTab({ report }: { report: any }) {
  if (!report.execNarrative) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <FileText className="h-12 w-12 text-muted-foreground/30 mb-4" />
          <p className="text-muted-foreground text-sm">
            Executive summary has not been generated yet. Add findings first, then click "Generate Exec Summary".
          </p>
        </CardContent>
      </Card>
    );
  }

  const rating = SEVERITY_CONFIG[report.execOverallRating] || SEVERITY_CONFIG.moderate;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Overall Risk Rating
            <Badge className={`${rating.bg} ${rating.color} border-0 ml-2`}>
              {rating.label}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm">{report.execRiskStatement}</p>
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-green-400" />
              Key Strengths
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {(report.execKeyStrengths as string[] || []).map((s: string, i: number) => (
                <li key={i} className="text-sm flex items-start gap-2">
                  <CheckCircle2 className="h-3.5 w-3.5 text-green-400 mt-0.5 shrink-0" />
                  {s}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-red-400" />
              Key Gaps
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {(report.execKeyGaps as string[] || []).map((g: string, i: number) => (
                <li key={i} className="text-sm flex items-start gap-2">
                  <AlertCircle className="h-3.5 w-3.5 text-red-400 mt-0.5 shrink-0" />
                  {g}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Executive Narrative</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="prose prose-sm prose-invert max-w-none whitespace-pre-wrap">
            {report.execNarrative}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── QA Review Tab ──────────────────────────────────────────────────────────

function QaReviewTab({ report }: { report: any }) {
  const qaIssues = (report.qaIssues as any[] || []);
  const qaStatus = QA_STATUS_CONFIG[report.qaStatus] || QA_STATUS_CONFIG.pending;

  if (report.qaStatus === "pending") {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <ShieldCheck className="h-12 w-12 text-muted-foreground/30 mb-4" />
          <p className="text-muted-foreground text-sm">
            QA review has not been run yet. Click "Run QA Review" to check the report for audit readiness.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card className={report.qaStatus === "pass" ? "border-green-500/30 bg-green-500/5" : "border-red-500/30 bg-red-500/5"}>
        <CardContent className="p-4 flex items-center gap-3">
          {report.qaStatus === "pass" ? (
            <CheckCircle2 className="h-5 w-5 text-green-400" />
          ) : (
            <XCircle className="h-5 w-5 text-red-400" />
          )}
          <div>
            <p className={`font-medium ${qaStatus.color}`}>QA Status: {qaStatus.label}</p>
            {report.qaReviewedAt && (
              <p className="text-xs text-muted-foreground">
                Reviewed: {new Date(report.qaReviewedAt).toLocaleString()}
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      {qaIssues.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Issues Found ({qaIssues.length})</h3>
          {qaIssues.map((issue: any, i: number) => (
            <Card key={i} className={
              issue.severity === "high" ? "border-red-500/30" :
              issue.severity === "medium" ? "border-yellow-500/30" :
              "border-blue-500/30"
            }>
              <CardContent className="p-3">
                <div className="flex items-start gap-2">
                  <Badge variant="outline" className={`text-xs shrink-0 ${
                    issue.severity === "high" ? "text-red-400" :
                    issue.severity === "medium" ? "text-yellow-400" :
                    "text-blue-400"
                  }`}>
                    {issue.severity}
                  </Badge>
                  <div>
                    <p className="text-sm font-medium">{issue.section}</p>
                    <p className="text-sm text-muted-foreground">{issue.issue}</p>
                    <p className="text-xs text-primary mt-1">Fix: {issue.recommended_fix}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Metadata Tab ───────────────────────────────────────────────────────────

function MetadataTab({ report, reportId }: { report: any; reportId: string }) {
  const { toast } = useToast();
  const utils = trpc.useUtils();
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({
    scopeDomains: (report.scopeDomains as string[] || []).join(", "),
    scopeAssets: (report.scopeAssets as string[] || []).join(", "),
    approvedVectors: (report.approvedVectors as string[] || []).join(", "),
    outOfScope: (report.outOfScope as string[] || []).join(", "),
    assessmentWindowStart: report.assessmentWindowStart ? new Date(report.assessmentWindowStart).toISOString().split("T")[0] : "",
    assessmentWindowEnd: report.assessmentWindowEnd ? new Date(report.assessmentWindowEnd).toISOString().split("T")[0] : "",
  });

  const updateMutation = trpc.ac3Reports.updateReport.useMutation({
    onSuccess: () => {
      utils.ac3Reports.getReport.invalidate({ reportId });
      setEditing(false);
      toast({ title: "Metadata updated" });
    },
  });

  const handleSave = () => {
    updateMutation.mutate({
      reportId,
      scopeDomains: form.scopeDomains.split(",").map(s => s.trim()).filter(Boolean),
      scopeAssets: form.scopeAssets.split(",").map(s => s.trim()).filter(Boolean),
      approvedVectors: form.approvedVectors.split(",").map(s => s.trim()).filter(Boolean),
      outOfScope: form.outOfScope.split(",").map(s => s.trim()).filter(Boolean),
      assessmentWindowStart: form.assessmentWindowStart ? new Date(form.assessmentWindowStart).getTime() : undefined,
      assessmentWindowEnd: form.assessmentWindowEnd ? new Date(form.assessmentWindowEnd).getTime() : undefined,
    });
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">Report Metadata</CardTitle>
            <Button variant="outline" size="sm" onClick={() => setEditing(!editing)}>
              {editing ? "Cancel" : "Edit"}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs text-muted-foreground">Client</Label>
              <p className="text-sm">{report.clientName || "—"}</p>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground">System</Label>
              <p className="text-sm">{report.systemName || "—"}</p>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground">Assessment Type</Label>
              <p className="text-sm">{report.assessmentType?.replace(/_/g, " ") || "—"}</p>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground">FedRAMP Level</Label>
              <p className="text-sm">{report.fedrampImpactLevel?.toUpperCase() || "—"}</p>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground">Cloud Provider</Label>
              <p className="text-sm">{report.cloudProvider || "—"}</p>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground">Service Model</Label>
              <p className="text-sm">{report.serviceModel || "—"}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Scope & Rules of Engagement</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {editing ? (
            <>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Assessment Window Start</Label>
                  <Input
                    type="date"
                    value={form.assessmentWindowStart}
                    onChange={(e) => setForm(f => ({ ...f, assessmentWindowStart: e.target.value }))}
                  />
                </div>
                <div>
                  <Label>Assessment Window End</Label>
                  <Input
                    type="date"
                    value={form.assessmentWindowEnd}
                    onChange={(e) => setForm(f => ({ ...f, assessmentWindowEnd: e.target.value }))}
                  />
                </div>
              </div>
              <div>
                <Label>In-Scope Domains (comma-separated)</Label>
                <Textarea
                  value={form.scopeDomains}
                  onChange={(e) => setForm(f => ({ ...f, scopeDomains: e.target.value }))}
                  rows={2}
                />
              </div>
              <div>
                <Label>In-Scope Assets (comma-separated)</Label>
                <Textarea
                  value={form.scopeAssets}
                  onChange={(e) => setForm(f => ({ ...f, scopeAssets: e.target.value }))}
                  rows={2}
                />
              </div>
              <div>
                <Label>Approved Attack Vectors (comma-separated)</Label>
                <Textarea
                  value={form.approvedVectors}
                  onChange={(e) => setForm(f => ({ ...f, approvedVectors: e.target.value }))}
                  rows={2}
                />
              </div>
              <div>
                <Label>Out of Scope (comma-separated)</Label>
                <Textarea
                  value={form.outOfScope}
                  onChange={(e) => setForm(f => ({ ...f, outOfScope: e.target.value }))}
                  rows={2}
                />
              </div>
              <Button onClick={handleSave} disabled={updateMutation.isPending} className="gap-2">
                {updateMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                Save Changes
              </Button>
            </>
          ) : (
            <div className="space-y-3">
              <div>
                <Label className="text-xs text-muted-foreground">Assessment Window</Label>
                <p className="text-sm">
                  {report.assessmentWindowStart ? new Date(report.assessmentWindowStart).toLocaleDateString() : "—"}
                  {" to "}
                  {report.assessmentWindowEnd ? new Date(report.assessmentWindowEnd).toLocaleDateString() : "—"}
                </p>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">In-Scope Domains</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {(report.scopeDomains as string[] || []).length > 0
                    ? (report.scopeDomains as string[]).map((d, i) => <Badge key={i} variant="outline" className="text-xs">{d}</Badge>)
                    : <span className="text-sm text-muted-foreground">None specified</span>}
                </div>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">In-Scope Assets</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {(report.scopeAssets as string[] || []).length > 0
                    ? (report.scopeAssets as string[]).map((a, i) => <Badge key={i} variant="outline" className="text-xs">{a}</Badge>)
                    : <span className="text-sm text-muted-foreground">None specified</span>}
                </div>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Approved Attack Vectors</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {(report.approvedVectors as string[] || []).length > 0
                    ? (report.approvedVectors as string[]).map((v, i) => <Badge key={i} variant="outline" className="text-xs">{v}</Badge>)
                    : <span className="text-sm text-muted-foreground">None specified</span>}
                </div>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Out of Scope</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {(report.outOfScope as string[] || []).length > 0
                    ? (report.outOfScope as string[]).map((o, i) => <Badge key={i} variant="outline" className="text-xs">{o}</Badge>)
                    : <span className="text-sm text-muted-foreground">None specified</span>}
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Export Tab ──────────────────────────────────────────────────────────────

function ExportTab({ reportId }: { reportId: string }) {
  const { toast } = useToast();
  const { data: exportData, isLoading } = trpc.ac3Reports.exportReportJson.useQuery({ reportId });
  const { data: reportData } = trpc.ac3Reports.getReport.useQuery({ reportId });
  const [copied, setCopied] = useState(false);

  const exportDocxMutation = trpc.ac3Reports.exportDocx.useMutation({
    onSuccess: (data) => {
      toast({ title: "DOCX Generated", description: "Your report document is ready for download." });
      window.open(data.url, "_blank");
    },
    onError: (err) => {
      toast({ title: "DOCX Export Failed", description: err.message, variant: "destructive" });
    },
  });

  const handleCopy = () => {
    if (exportData) {
      navigator.clipboard.writeText(JSON.stringify(exportData, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    if (exportData) {
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${reportId}-report.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  return (
    <div className="space-y-4">
      {/* DOCX Export */}
      <Card className="border-blue-500/20">
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <FileDown className="h-4 w-4 text-blue-400" />
            DOCX Report Export
          </CardTitle>
          <CardDescription>
            Generate a professional FedRAMP-compliant Word document with title page, executive summary,
            scope, findings summary table, and detailed findings with ATT&CK mappings and NIST controls.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3">
            <Button
              onClick={() => exportDocxMutation.mutate({ reportId })}
              disabled={exportDocxMutation.isPending}
              className="gap-2"
            >
              {exportDocxMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <FileDown className="h-4 w-4" />
              )}
              {exportDocxMutation.isPending ? "Generating DOCX..." : "Generate & Download DOCX"}
            </Button>
            {(reportData as any)?.docxUrl && (
              <Button variant="outline" size="sm" className="gap-2" onClick={() => window.open((reportData as any).docxUrl, "_blank")}>
                <Download className="h-3.5 w-3.5" />
                Download Previous DOCX
              </Button>
            )}
          </div>
          <div className="mt-3 text-xs text-muted-foreground">
            <p>The DOCX includes: Title Page, Executive Summary, Scope & Methodology, Findings Summary Table, and Detailed Findings.</p>
            <p className="mt-1">Author: Harrison Cook — AceofCloud</p>
          </div>
        </CardContent>
      </Card>

      {/* JSON Export */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <Download className="h-4 w-4" />
            JSON Export
          </CardTitle>
          <CardDescription>
            Export the report as structured JSON compatible with the AC3 report_input.schema.json format.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 mb-4">
            <Button variant="outline" size="sm" onClick={handleCopy} className="gap-2">
              {copied ? <CheckCircle2 className="h-3.5 w-3.5 text-green-400" /> : <FileText className="h-3.5 w-3.5" />}
              {copied ? "Copied!" : "Copy JSON"}
            </Button>
            <Button variant="outline" size="sm" onClick={handleDownload} className="gap-2">
              <Download className="h-3.5 w-3.5" />
              Download JSON
            </Button>
          </div>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <pre className="bg-background/50 rounded-lg p-4 text-xs overflow-auto max-h-[500px] border">
              {JSON.stringify(exportData, null, 2)}
            </pre>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Engagement Import Dialog ────────────────────────────────────────────────

function EngagementImportDialog({ open, onClose, reportId }: { open: boolean; onClose: () => void; reportId: string }) {
  const { toast } = useToast();
  const utils = trpc.useUtils();
  const { data: engagements, isLoading } = trpc.ac3Reports.listEngagements.useQuery(undefined, { enabled: open });
  const [selectedEngId, setSelectedEngId] = useState<number | null>(null);

  const importMutation = trpc.ac3Reports.importEngagementFindings.useMutation({
    onSuccess: (data: any) => {
      utils.ac3Reports.getReport.invalidate({ reportId });
      const parts = [`${data.imported} new`];
      if (data.merged) parts.push(`${data.merged} merged`);
      if (data.skipped) parts.push(`${data.skipped} filtered`);
      toast({
        title: "Engagement Imported",
        description: `${parts.join(", ")} findings from "${data.engagementName}" (${data.total} events processed).`,
      });
      onClose();
      setSelectedEngId(null);
    },
    onError: (err) => {
      toast({ title: "Import Failed", description: err.message, variant: "destructive" });
    },
  });

  const handleImport = () => {
    if (!selectedEngId) return;
    importMutation.mutate({ reportId, engagementId: selectedEngId });
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Import from Engagement
          </DialogTitle>
          <DialogDescription>
            Select an engagement to auto-populate findings from its timeline events.
            Security events (exploits, shells, credentials, pivots, exfiltration) will be mapped
            to findings with ATT&CK IDs and NIST 800-53 controls.
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : !engagements?.length ? (
          <div className="text-center py-8 text-muted-foreground">
            <Target className="h-8 w-8 mx-auto mb-2 opacity-40" />
            <p className="text-sm">No engagements found.</p>
          </div>
        ) : (
          <div className="max-h-[400px] overflow-y-auto space-y-2">
            {engagements.map((eng: any) => (
              <Card
                key={eng.id}
                className={`cursor-pointer transition-colors ${
                  selectedEngId === eng.id
                    ? "border-primary bg-primary/5"
                    : "hover:border-primary/30"
                }`}
                onClick={() => setSelectedEngId(eng.id)}
              >
                <CardContent className="p-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium text-sm">{eng.name}</div>
                      <div className="text-xs text-muted-foreground flex items-center gap-2 mt-0.5">
                        <span>{eng.customerName}</span>
                        <Badge variant="outline" className="text-xs">
                          {eng.engagementType?.replace(/_/g, " ")}
                        </Badge>
                        <Badge variant="outline" className={`text-xs ${
                          eng.status === "completed" ? "text-green-400" :
                          eng.status === "active" ? "text-blue-400" : "text-gray-400"
                        }`}>
                          {eng.status}
                        </Badge>
                      </div>
                    </div>
                    {eng.calderaOperationId && (
                      <Badge variant="outline" className="text-xs text-amber-400">
                        <Zap className="h-3 w-3 mr-1" />
                        Caldera Linked
                      </Badge>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={handleImport}
            disabled={!selectedEngId || importMutation.isPending}
            className="gap-2"
          >
            {importMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
            Import Findings
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Caldera Import Dialog ───────────────────────────────────────────────────

function CalderaImportDialog({ open, onClose, reportId }: { open: boolean; onClose: () => void; reportId: string }) {
  const { toast } = useToast();
  const utils = trpc.useUtils();
  const { data: operations, isLoading } = trpc.ac3Reports.listCalderaOperations.useQuery(undefined, { enabled: open });
  const [selectedOpId, setSelectedOpId] = useState<string | null>(null);
  const [includeFailedLinks, setIncludeFailedLinks] = useState(false);

  const importMutation = trpc.ac3Reports.importCalderaOperation.useMutation({
    onSuccess: (data: any) => {
      utils.ac3Reports.getReport.invalidate({ reportId });
      const parts = [`${data.imported} new`];
      if (data.merged) parts.push(`${data.merged} merged into existing`);
      toast({
        title: "Caldera Operation Imported",
        description: `${parts.join(", ")} findings from "${data.operationName}" (${data.totalLinks} links, adversary: ${data.adversaryName}).`,
      });
      onClose();
      setSelectedOpId(null);
    },
    onError: (err) => {
      toast({ title: "Import Failed", description: err.message, variant: "destructive" });
    },
  });

  const handleImport = () => {
    if (!selectedOpId) return;
    importMutation.mutate({ reportId, operationId: selectedOpId, includeFailedLinks });
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-amber-400" />
            Import from Caldera Operation
          </DialogTitle>
          <DialogDescription>
            Select a Caldera operation to bulk-import findings. Each ability executed in the operation
            chain will be mapped to a finding with pre-filled ATT&CK technique IDs, NIST controls,
            severity ratings, and evidence from command outputs.
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : !operations?.length ? (
          <div className="text-center py-8 text-muted-foreground">
            <Server className="h-8 w-8 mx-auto mb-2 opacity-40" />
            <p className="text-sm">No Caldera operations found.</p>
            <p className="text-xs mt-1">Ensure Caldera is configured and has completed operations.</p>
          </div>
        ) : (
          <div className="max-h-[400px] overflow-y-auto space-y-2">
            {operations.map((op: any) => (
              <Card
                key={op.id}
                className={`cursor-pointer transition-colors ${
                  selectedOpId === String(op.id)
                    ? "border-amber-500 bg-amber-500/5"
                    : "hover:border-amber-500/30"
                }`}
                onClick={() => setSelectedOpId(String(op.id))}
              >
                <CardContent className="p-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium text-sm">{op.name}</div>
                      <div className="text-xs text-muted-foreground flex items-center gap-2 mt-0.5">
                        <span>Adversary: {op.adversaryName}</span>
                        <Badge variant="outline" className={`text-xs ${
                          op.state === "finished" ? "text-green-400" :
                          op.state === "running" ? "text-blue-400" : "text-gray-400"
                        }`}>
                          {op.state}
                        </Badge>
                      </div>
                    </div>
                    <div className="text-right text-xs text-muted-foreground">
                      <div>{op.linkCount} links</div>
                      <div>{op.agentCount} agents</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        <div className="flex items-center gap-2 px-1">
          <input
            type="checkbox"
            id="includeFailedLinks"
            checked={includeFailedLinks}
            onChange={(e) => setIncludeFailedLinks(e.target.checked)}
            className="rounded border-gray-600"
          />
          <Label htmlFor="includeFailedLinks" className="text-sm cursor-pointer">
            Include failed/blocked links as findings
          </Label>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={handleImport}
            disabled={!selectedOpId || importMutation.isPending}
            className="gap-2"
          >
            {importMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
            Import Operation
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
