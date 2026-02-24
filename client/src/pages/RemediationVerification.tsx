"use client";

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import {
  Loader2, AlertTriangle, Trash2, PlusCircle, Clock,
  CheckCircle2, XCircle, Play, AlertCircle, ShieldCheck, FileDown, Database
} from "lucide-react";
import { exportToPdf } from "@/lib/export-pdf";

const SEVERITY_CONFIG: Record<string, { color: string; bgColor: string; label: string }> = {
  critical: { color: "text-red-400", bgColor: "bg-red-500/20 border-red-500/30", label: "Critical" },
  high: { color: "text-orange-400", bgColor: "bg-orange-500/20 border-orange-500/30", label: "High" },
  medium: { color: "text-yellow-400", bgColor: "bg-yellow-500/20 border-yellow-500/30", label: "Medium" },
  low: { color: "text-blue-400", bgColor: "bg-blue-500/20 border-blue-500/30", label: "Low" },
  info: { color: "text-zinc-400", bgColor: "bg-zinc-500/20 border-zinc-500/30", label: "Info" },
};

const STATUS_CONFIG: Record<string, { color: string; icon: typeof CheckCircle2; label: string }> = {
  pending: { color: "bg-zinc-500/20 text-zinc-400", icon: Clock, label: "Pending" },
  running: { color: "bg-blue-500/20 text-blue-400", icon: Loader2, label: "Running" },
  verified_fixed: { color: "bg-green-500/20 text-green-400", icon: CheckCircle2, label: "Fixed" },
  still_vulnerable: { color: "bg-red-500/20 text-red-400", icon: XCircle, label: "Vulnerable" },
  error: { color: "bg-orange-500/20 text-orange-400", icon: AlertTriangle, label: "Error" },
};

const METHOD_LABELS: Record<string, string> = {
  re_exploit: "Re-Exploit",
  scan_recheck: "Scan Recheck",
  config_audit: "Config Audit",
  manual: "Manual",
};

const RemediationVerificationPage = () => {
  const [isCreateDialogOpen, setCreateDialogOpen] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const utils = trpc.useUtils();
  const statsQuery = trpc.remediationVerification.dashboardStats.useQuery();
  const listQuery = trpc.remediationVerification.list.useQuery(
    statusFilter === "all" ? {} : { status: statusFilter as any }
  );
  const overdueQuery = trpc.remediationVerification.overdue.useQuery();
  const timelineQuery = trpc.remediationVerification.timeline.useQuery({ days: 30 });

  const createMutation = trpc.remediationVerification.create.useMutation({
    onSuccess: () => {
      toast.success("Remediation verification created");
      utils.remediationVerification.list.invalidate();
      utils.remediationVerification.dashboardStats.invalidate();
      setCreateDialogOpen(false);
    },
    onError: (err: any) => toast.error("Failed to create", { description: err.message }),
  });

  const executeMutation = trpc.remediationVerification.execute.useMutation({
    onSuccess: (data) => {
      if (data.status === "verified_fixed") {
        toast.success("Vulnerability confirmed remediated!", { description: data.output });
      } else {
        toast.error("Vulnerability still present", { description: data.output });
      }
      utils.remediationVerification.list.invalidate();
      utils.remediationVerification.dashboardStats.invalidate();
      utils.remediationVerification.overdue.invalidate();
    },
    onError: (err: any) => toast.error("Verification failed", { description: err.message }),
  });

  const deleteMutation = trpc.remediationVerification.delete.useMutation({
    onSuccess: () => {
      toast.success("Deleted");
      utils.remediationVerification.list.invalidate();
      utils.remediationVerification.dashboardStats.invalidate();
    },
  });

  const handleCreateSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    createMutation.mutate({
      originalFindingId: parseInt(fd.get("findingId") as string) || 1,
      originalFindingType: fd.get("findingType") as string,
      verificationMethod: fd.get("method") as any,
      severity: fd.get("severity") as any,
      assetName: (fd.get("assetName") as string) || undefined,
      findingTitle: (fd.get("findingTitle") as string) || undefined,
      techniqueId: (fd.get("techniqueId") as string) || undefined,
    });
  };

  const stats = statsQuery.data;
  const items = listQuery.data ?? [];
  const overdueItems = overdueQuery.data ?? [];
  const timeline = timelineQuery.data ?? [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-emerald-500" />
            Remediation Dashboard
          </h1>
          <p className="text-muted-foreground mt-1">
            Track vulnerability remediation progress with SLA enforcement, automated re-verification, and regression detection. Every fix is verified through re-exploitation or scan recheck.
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <ExportRemediationButton />
          <SeedDemoButton onSuccess={() => listQuery.refetch()} />
          <ClearDemoButton onSuccess={() => listQuery.refetch()} />
          <Dialog open={isCreateDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button size="lg" className="gap-2">
                <PlusCircle className="h-4 w-4" /> New Verification
              </Button>
            </DialogTrigger>
          <DialogContent className="sm:max-w-[600px]">
            <form onSubmit={handleCreateSubmit}>
              <DialogHeader>
                <DialogTitle>Create Remediation Verification</DialogTitle>
                <DialogDescription>
                  Schedule a re-verification for a remediated finding. The system will re-exploit or rescan to confirm the fix.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="findingTitle">Finding Title</Label>
                    <Input id="findingTitle" name="findingTitle" placeholder="e.g., CVE-2024-1234 RCE" className="mt-1" required />
                  </div>
                  <div>
                    <Label htmlFor="assetName">Asset</Label>
                    <Input id="assetName" name="assetName" placeholder="e.g., web-server-01" className="mt-1" />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Severity</Label>
                    <Select name="severity" defaultValue="high">
                      <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="critical">Critical</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                        <SelectItem value="info">Info</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Verification Method</Label>
                    <Select name="method" defaultValue="re_exploit">
                      <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="re_exploit">Re-Exploit</SelectItem>
                        <SelectItem value="scan_recheck">Scan Recheck</SelectItem>
                        <SelectItem value="config_audit">Config Audit</SelectItem>
                        <SelectItem value="manual">Manual</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="findingType">Finding Type</Label>
                    <Input id="findingType" name="findingType" placeholder="e.g., exploit, vuln_scan" className="mt-1" defaultValue="exploit" required />
                  </div>
                  <div>
                    <Label htmlFor="techniqueId">MITRE Technique (Optional)</Label>
                    <Input id="techniqueId" name="techniqueId" placeholder="e.g., T1059.001" className="mt-1" />
                  </div>
                </div>
                <input type="hidden" name="findingId" value="1" />
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
                <Button type="submit" disabled={createMutation.isPending} className="gap-2">
                  {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                  Create
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Total</p>
            <p className="text-2xl font-bold mt-1">{stats?.total ?? 0}</p>
          </CardContent>
        </Card>
        <Card className={stats?.slaCompliant != null && stats.slaCompliant < 80 ? "border-red-500/50" : ""}>
          <CardContent className="pt-4 pb-3">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">SLA Compliance</p>
            <p className={`text-2xl font-bold mt-1 ${stats?.slaCompliant != null && stats.slaCompliant < 80 ? "text-red-400" : stats?.slaCompliant != null && stats.slaCompliant < 95 ? "text-yellow-400" : "text-green-400"}`}>
              {stats?.slaCompliant ?? 100}%
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Verified Fixed</p>
            <p className="text-2xl font-bold text-green-400 mt-1">{stats?.verifiedFixed ?? 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Still Vulnerable</p>
            <p className="text-2xl font-bold text-red-400 mt-1">{stats?.stillVulnerable ?? 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Overdue</p>
            <p className={`text-2xl font-bold mt-1 ${(stats?.overdue ?? 0) > 0 ? "text-red-400" : "text-muted-foreground"}`}>
              {stats?.overdue ?? 0}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Avg MTTR</p>
            <p className="text-2xl font-bold mt-1">{stats?.avgRemediationHours ?? 0}h</p>
          </CardContent>
        </Card>
      </div>

      {/* Overdue Alert */}
      {overdueItems.length > 0 && (
        <Alert variant="destructive" className="border-red-500/50 bg-red-500/5">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle className="font-semibold">
            {overdueItems.length} Overdue Remediation{overdueItems.length > 1 ? "s" : ""}
          </AlertTitle>
          <AlertDescription>
            <div className="mt-2 space-y-1">
              {overdueItems.slice(0, 5).map((item: any) => (
                <div key={item.id} className="flex items-center justify-between text-sm">
                  <span>{item.findingTitle || `Finding #${item.originalFindingId}`} — {item.assetName || "Unknown asset"}</span>
                  <Badge variant="destructive" className="text-xs">{item.hoursOverdue}h overdue</Badge>
                </div>
              ))}
              {overdueItems.length > 5 && (
                <p className="text-xs text-muted-foreground mt-1">...and {overdueItems.length - 5} more</p>
              )}
            </div>
          </AlertDescription>
        </Alert>
      )}

      {/* Severity & Method Breakdown */}
      {stats && stats.total > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold">Severity Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {Object.entries(stats.severityBreakdown).map(([sev, count]) => {
                  const cfg = SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.info;
                  const pct = stats.total > 0 ? (count / stats.total) * 100 : 0;
                  return (
                    <div key={sev} className="space-y-1">
                      <div className="flex items-center justify-between text-sm">
                        <span className={`font-medium ${cfg.color}`}>{cfg.label}</span>
                        <span className="text-muted-foreground">{count} ({Math.round(pct)}%)</span>
                      </div>
                      <Progress value={pct} className="h-2" />
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold">Verification Methods</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {Object.entries(stats.methodBreakdown).map(([method, count]) => {
                  const pct = stats.total > 0 ? (count / stats.total) * 100 : 0;
                  return (
                    <div key={method} className="space-y-1">
                      <div className="flex items-center justify-between text-sm">
                        <span className="font-medium">{METHOD_LABELS[method] || method}</span>
                        <span className="text-muted-foreground">{count} ({Math.round(pct)}%)</span>
                      </div>
                      <Progress value={pct} className="h-2" />
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Timeline Chart */}
      {timeline.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">30-Day Remediation Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-1 h-32">
              {timeline.slice(-30).map((day) => {
                const maxVal = Math.max(...timeline.map(d => d.created + d.fixed + d.stillVuln), 1);
                const total = day.created + day.fixed + day.stillVuln;
                const height = (total / maxVal) * 100;
                return (
                  <div key={day.date} className="flex-1 flex flex-col items-center gap-0.5" title={`${day.date}: ${day.created} created, ${day.fixed} fixed, ${day.stillVuln} still vuln`}>
                    <div className="w-full flex flex-col-reverse gap-px" style={{ height: `${Math.max(height, 2)}%` }}>
                      {day.fixed > 0 && <div className="bg-green-500 rounded-t-sm" style={{ flex: day.fixed }} />}
                      {day.stillVuln > 0 && <div className="bg-red-500 rounded-t-sm" style={{ flex: day.stillVuln }} />}
                      {day.created > 0 && <div className="bg-blue-500 rounded-t-sm" style={{ flex: day.created }} />}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="flex items-center justify-center gap-6 mt-3 text-xs text-muted-foreground">
              <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-blue-500" /> Created</span>
              <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-green-500" /> Fixed</span>
              <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-red-500" /> Still Vulnerable</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Verification Items */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold">Remediation Items</CardTitle>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[160px] h-8 text-xs">
                <SelectValue placeholder="Filter by status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="running">Running</SelectItem>
                <SelectItem value="verified_fixed">Verified Fixed</SelectItem>
                <SelectItem value="still_vulnerable">Still Vulnerable</SelectItem>
                <SelectItem value="error">Error</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {listQuery.isLoading && (
            <div className="flex items-center justify-center py-10">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          )}
          {items.length === 0 && !listQuery.isLoading && (
            <div className="text-center py-10">
              <ShieldCheck className="h-12 w-12 text-muted-foreground/20 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">No remediation items found.</p>
              <p className="text-xs text-muted-foreground mt-1">Create a new verification to track a remediated finding.</p>
            </div>
          )}
          {items.length > 0 && (
            <div className="space-y-2">
              {items.map((item: any) => {
                const statusCfg = STATUS_CONFIG[item.status] || STATUS_CONFIG.pending;
                const StatusIcon = statusCfg.icon;
                const sevCfg = SEVERITY_CONFIG[item.severity || "medium"] || SEVERITY_CONFIG.medium;
                const isOverdue = item.slaDeadline && new Date(item.slaDeadline) < new Date() && item.status !== "verified_fixed";
                return (
                  <div
                    key={item.id}
                    className={`flex items-center gap-4 p-3 rounded-lg border transition-colors hover:bg-accent/30 ${isOverdue ? "border-red-500/30 bg-red-500/5" : ""}`}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-sm">{item.findingTitle || `Finding #${item.originalFindingId}`}</span>
                        <Badge className={`${sevCfg.bgColor} border text-xs`}>{sevCfg.label}</Badge>
                        <Badge className={`${statusCfg.color} text-xs`}>
                          <StatusIcon className={`h-3 w-3 mr-1 ${item.status === "running" ? "animate-spin" : ""}`} />
                          {statusCfg.label}
                        </Badge>
                        {isOverdue && (
                          <Badge variant="destructive" className="text-xs gap-1">
                            <AlertCircle className="h-3 w-3" /> SLA Overdue
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                        {item.assetName && <span>Asset: {item.assetName}</span>}
                        <span>Method: {METHOD_LABELS[item.verificationMethod] || item.verificationMethod}</span>
                        {item.techniqueId && <span>Technique: {item.techniqueId}</span>}
                        {item.slaDeadline && (
                          <span className={isOverdue ? "text-red-400 font-medium" : ""}>
                            SLA: {new Date(item.slaDeadline).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                      {item.verificationOutput && (
                        <p className="text-xs text-muted-foreground mt-1 italic">{item.verificationOutput}</p>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {(item.status === "pending" || item.status === "still_vulnerable") && (
                        <Button
                          size="sm"
                          variant="outline"
                          className="gap-1"
                          onClick={() => executeMutation.mutate({ id: item.id })}
                          disabled={executeMutation.isPending}
                        >
                          {executeMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                          Verify
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-destructive hover:text-destructive"
                        onClick={() => {
                          if (window.confirm("Delete this item?")) deleteMutation.mutate({ id: item.id });
                        }}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

// ─── Export Remediation Report Button ────────────────────────────────────────
function ExportRemediationButton() {
  const [isExporting, setIsExporting] = useState(false);
  const exportQuery = trpc.remediationVerification.exportReport.useQuery(undefined, { enabled: false });

  const handleExport = async () => {
    setIsExporting(true);
    try {
      const result = await exportQuery.refetch();
      if (result.data) {
        exportToPdf(result.data.html, result.data.filename);
        toast.success("Report opened for PDF export");
      }
    } catch (err) {
      toast.error("Failed to generate report");
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <Button variant="outline" onClick={handleExport} disabled={isExporting} className="gap-2">
      {isExporting ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileDown className="h-4 w-4" />}
      Export PDF
    </Button>
  );
}

// ─── Seed Demo Data Button ──────────────────────────────────────────────────
function SeedDemoButton({ onSuccess }: { onSuccess: () => void }) {
  const seedMutation = trpc.remediationVerification.seedDemoData.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      onSuccess();
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <Button variant="outline" onClick={() => seedMutation.mutate()} disabled={seedMutation.isPending} className="gap-2">
      {seedMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Database className="h-4 w-4" />}
      Seed Demo Data
    </Button>
  );
}

function ClearDemoButton({ onSuccess }: { onSuccess: () => void }) {
  const clearMutation = trpc.remediationVerification.clearDemoData.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      onSuccess();
    },
    onError: (err: any) => toast.error(err.message),
  });

  return (
    <Button variant="outline" onClick={() => clearMutation.mutate()} disabled={clearMutation.isPending} className="gap-2 text-destructive border-destructive/30 hover:bg-destructive/10">
      {clearMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
      Clear Demo Data
    </Button>
  );
}

export default RemediationVerificationPage;
