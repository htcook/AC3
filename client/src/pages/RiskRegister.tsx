import { useState, useMemo, useCallback } from "react";
import { useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import {
  ClipboardCheck, Plus, Search, Filter, Download, Trash2,
  ChevronLeft, ChevronRight, AlertTriangle, CheckCircle2,
  ShieldAlert, Clock, ArrowUpDown, MoreHorizontal, FileText,
  Upload, Eye, XCircle, ShieldCheck, Loader2, RefreshCw,
} from "lucide-react";

// ─── Severity badge colors ───
function SeverityBadge({ severity }: { severity: string | null }) {
  const s = severity?.toLowerCase() || "unknown";
  const colors: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    moderate: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    informational: "bg-gray-500/15 text-gray-400 border-gray-500/30",
  };
  return (
    <Badge variant="outline" className={`text-xs font-medium ${colors[s] || colors.informational}`}>
      {severity || "Unknown"}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    open: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    closed: "bg-gray-500/15 text-gray-400 border-gray-500/30",
    risk_accepted: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    false_positive: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
    operationally_required: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    vendor_dependent: "bg-pink-500/15 text-pink-400 border-pink-500/30",
    deferred: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };
  const labels: Record<string, string> = {
    open: "Open",
    closed: "Closed",
    risk_accepted: "Risk Accepted",
    false_positive: "False Positive",
    operationally_required: "Op. Required",
    vendor_dependent: "Vendor Dep.",
    deferred: "Deferred",
  };
  return (
    <Badge variant="outline" className={`text-xs font-medium ${colors[status] || ""}`}>
      {labels[status] || status}
    </Badge>
  );
}

export default function RiskRegister() {
  const [, navigate] = useLocation();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [sortBy, setSortBy] = useState<"createdAt" | "severity" | "scheduledCompletion" | "poamId">("createdAt");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(0);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [bulkAction, setBulkAction] = useState<string>("");
  const [bulkJustification, setBulkJustification] = useState("");
  const [showBulkDialog, setShowBulkDialog] = useState(false);
  const [showImportDialog, setShowImportDialog] = useState(false);
  const pageSize = 50;

  const utils = trpc.useUtils();

  const queryInput = useMemo(() => ({
    status: statusFilter !== "all" ? statusFilter as any : undefined,
    severity: severityFilter !== "all" ? severityFilter as any : undefined,
    sourceType: sourceFilter !== "all" ? sourceFilter as any : undefined,
    search: search || undefined,
    overdue: overdueOnly || undefined,
    sortBy,
    sortOrder,
    limit: pageSize,
    offset: page * pageSize,
  }), [statusFilter, severityFilter, sourceFilter, search, overdueOnly, sortBy, sortOrder, page]);

  const { data, isLoading, error } = trpc.riskRegister.list.useQuery(queryInput);
  const metricsQuery = trpc.riskRegister.executiveMetrics.useQuery({ days: 90 });
  const reportsQuery = trpc.riskRegister.availableReports.useQuery();

  const bulkMutation = trpc.riskRegister.bulkUpdateStatus.useMutation({
    onSuccess: (result) => {
      toast.success(`Updated ${result.updated} entries`);
      setSelectedIds(new Set());
      setShowBulkDialog(false);
      setBulkJustification("");
      utils.riskRegister.list.invalidate();
      utils.riskRegister.executiveMetrics.invalidate();
    },
    onError: (err) => toast.error("Bulk update failed", { description: err.message }),
  });

  const autoPopulateMutation = trpc.riskRegister.autoPopulateFromEngagement.useMutation({
    onSuccess: (result) => {
      toast.success(`Imported: ${result.created} created, ${result.updated} updated (${result.total} total findings)`);
      setShowImportDialog(false);
      utils.riskRegister.list.invalidate();
      utils.riskRegister.executiveMetrics.invalidate();
    },
    onError: (err) => toast.error("Import failed", { description: err.message }),
  });

  const toggleSort = useCallback((col: typeof sortBy) => {
    if (sortBy === col) setSortOrder(o => o === "asc" ? "desc" : "asc");
    else { setSortBy(col); setSortOrder("desc"); }
  }, [sortBy]);

  const toggleSelect = useCallback((id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const toggleSelectAll = useCallback(() => {
    if (!data?.items) return;
    if (selectedIds.size === data.items.length) setSelectedIds(new Set());
    else setSelectedIds(new Set(data.items.map(i => i.id)));
  }, [data, selectedIds.size]);

  const handleBulkAction = () => {
    if (selectedIds.size === 0 || !bulkAction) return;
    bulkMutation.mutate({
      ids: Array.from(selectedIds),
      status: bulkAction as any,
      justification: bulkJustification || undefined,
    });
  };

  const exportPoam = () => {
    // Open export in new tab (uses query endpoint)
    toast.info("POA&M export data is available via the Export POA&M button on the detail page");
  };

  const metrics = metricsQuery.data?.summary;
  const totalPages = data ? Math.ceil(data.total / pageSize) : 0;

  return (
    <div className="space-y-6 p-1">
      {/* Page Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-blue-500/10 border border-blue-500/20">
            <ClipboardCheck className="h-8 w-8 text-blue-400" />
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Risk Register</h1>
            <p className="text-muted-foreground mt-1">
              FedRAMP POA&M-aligned risk tracking. Every pentest, red team engagement, and CTEM scan feeds into this
              centralized register for compliance reporting, risk acceptance workflows, and executive visibility.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Dialog open={showImportDialog} onOpenChange={setShowImportDialog}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <Upload className="h-4 w-4 mr-2" /> Import from Engagement
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Import Findings to Risk Register</DialogTitle>
                <DialogDescription>
                  Select a finalized engagement report to auto-populate the Risk Register with its findings.
                  Duplicate findings will be marked as re-observed rather than duplicated.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                {reportsQuery.isLoading ? (
                  <div className="flex items-center gap-2 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading reports...</div>
                ) : reportsQuery.data && reportsQuery.data.length > 0 ? (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {reportsQuery.data.map(r => (
                      <button
                        key={r.reportId}
                        onClick={() => autoPopulateMutation.mutate({ reportId: r.reportId })}
                        disabled={autoPopulateMutation.isPending}
                        className="w-full text-left p-3 rounded-lg border border-border hover:border-primary/50 hover:bg-accent/50 transition-colors"
                      >
                        <div className="font-medium text-sm">{r.title || r.reportId}</div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {r.assessmentType} &middot; {r.createdAt ? new Date(r.createdAt).toLocaleDateString() : ""}
                        </div>
                      </button>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No finalized reports available for import.</p>
                )}
              </div>
            </DialogContent>
          </Dialog>
          <Button variant="outline" size="sm" onClick={exportPoam}>
            <Download className="h-4 w-4 mr-2" /> Export POA&M
          </Button>
          <Button size="sm" onClick={() => navigate("/risk-register/new")}>
            <Plus className="h-4 w-4 mr-2" /> New Entry
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {[
          { label: "Total Open", value: metrics?.totalOpen ?? "—", icon: ShieldAlert, color: "text-red-400", onClick: () => { setStatusFilter("open"); setPage(0); } },
          { label: "Overdue", value: metrics?.overdue ?? "—", icon: Clock, color: "text-orange-400", onClick: () => { setOverdueOnly(true); setPage(0); } },
          { label: "Closed (90d)", value: metrics?.totalClosedInPeriod ?? "—", icon: CheckCircle2, color: "text-emerald-400", onClick: () => { setStatusFilter("closed"); setPage(0); } },
          { label: "Risk Accepted", value: metrics?.riskAccepted ?? "—", icon: ShieldCheck, color: "text-purple-400", onClick: () => { setStatusFilter("risk_accepted"); setPage(0); } },
          { label: "Vendor Dep.", value: metrics?.vendorDependent ?? "—", icon: AlertTriangle, color: "text-pink-400", onClick: () => { setStatusFilter("vendor_dependent"); setPage(0); } },
          { label: "New (90d)", value: metrics?.newInPeriod ?? "—", icon: FileText, color: "text-blue-400", onClick: () => {} },
        ].map((card, i) => (
          <Card key={i} className="cursor-pointer hover:border-primary/40 transition-colors" onClick={card.onClick}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <card.icon className={`h-5 w-5 ${card.color}`} />
                <span className="text-2xl font-bold tabular-nums">{card.value}</span>
              </div>
              <p className="text-xs text-muted-foreground mt-1">{card.label}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search POA&M ID, weakness, asset, CVE..."
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0); }}
            className="pl-9"
          />
        </div>
        <Select value={statusFilter} onValueChange={v => { setStatusFilter(v); setPage(0); }}>
          <SelectTrigger className="w-[150px]"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="closed">Closed</SelectItem>
            <SelectItem value="risk_accepted">Risk Accepted</SelectItem>
            <SelectItem value="false_positive">False Positive</SelectItem>
            <SelectItem value="vendor_dependent">Vendor Dep.</SelectItem>
            <SelectItem value="deferred">Deferred</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={v => { setSeverityFilter(v); setPage(0); }}>
          <SelectTrigger className="w-[140px]"><SelectValue placeholder="Severity" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="moderate">Moderate</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="informational">Informational</SelectItem>
          </SelectContent>
        </Select>
        <Select value={sourceFilter} onValueChange={v => { setSourceFilter(v); setPage(0); }}>
          <SelectTrigger className="w-[150px]"><SelectValue placeholder="Source" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Sources</SelectItem>
            <SelectItem value="pentest">Pentest</SelectItem>
            <SelectItem value="red_team">Red Team</SelectItem>
            <SelectItem value="vulnerability_scan">Vuln Scan</SelectItem>
            <SelectItem value="ctem">CTEM</SelectItem>
            <SelectItem value="manual">Manual</SelectItem>
            <SelectItem value="cicd">CI/CD</SelectItem>
          </SelectContent>
        </Select>
        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <Checkbox checked={overdueOnly} onCheckedChange={(c) => { setOverdueOnly(!!c); setPage(0); }} />
          <span className="text-muted-foreground">Overdue only</span>
        </label>
        {(statusFilter !== "all" || severityFilter !== "all" || sourceFilter !== "all" || overdueOnly || search) && (
          <Button variant="ghost" size="sm" onClick={() => { setStatusFilter("all"); setSeverityFilter("all"); setSourceFilter("all"); setOverdueOnly(false); setSearch(""); setPage(0); }}>
            <XCircle className="h-4 w-4 mr-1" /> Clear
          </Button>
        )}
      </div>

      {/* Bulk Actions */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 p-3 rounded-lg bg-accent/50 border border-accent">
          <span className="text-sm font-medium">{selectedIds.size} selected</span>
          <Select value={bulkAction} onValueChange={setBulkAction}>
            <SelectTrigger className="w-[160px] h-8"><SelectValue placeholder="Bulk action..." /></SelectTrigger>
            <SelectContent>
              <SelectItem value="closed">Mark Closed</SelectItem>
              <SelectItem value="risk_accepted">Accept Risk</SelectItem>
              <SelectItem value="false_positive">False Positive</SelectItem>
              <SelectItem value="deferred">Defer</SelectItem>
            </SelectContent>
          </Select>
          {bulkAction && (
            <Dialog open={showBulkDialog} onOpenChange={setShowBulkDialog}>
              <DialogTrigger asChild>
                <Button size="sm" variant="default">Apply</Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Confirm Bulk Action</DialogTitle>
                  <DialogDescription>
                    This will update {selectedIds.size} entries to "{bulkAction.replace(/_/g, " ")}".
                  </DialogDescription>
                </DialogHeader>
                <Textarea
                  placeholder="Justification (optional for close, required for risk acceptance)"
                  value={bulkJustification}
                  onChange={e => setBulkJustification(e.target.value)}
                />
                <DialogFooter>
                  <Button variant="outline" onClick={() => setShowBulkDialog(false)}>Cancel</Button>
                  <Button onClick={handleBulkAction} disabled={bulkMutation.isPending}>
                    {bulkMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    Confirm
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          )}
          <Button variant="ghost" size="sm" onClick={() => setSelectedIds(new Set())}>
            <XCircle className="h-4 w-4" />
          </Button>
        </div>
      )}

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-6 space-y-3">
              {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
            </div>
          ) : error ? (
            <div className="p-6 text-center text-destructive">
              <AlertTriangle className="h-8 w-8 mx-auto mb-2" />
              <p>Failed to load risk register: {error.message}</p>
            </div>
          ) : data && data.items.length === 0 ? (
            <div className="p-12 text-center">
              <ClipboardCheck className="h-12 w-12 mx-auto text-muted-foreground/40 mb-4" />
              <h3 className="text-lg font-medium">No entries found</h3>
              <p className="text-sm text-muted-foreground mt-1">
                {search || statusFilter !== "all" || severityFilter !== "all"
                  ? "Try adjusting your filters."
                  : "Create a manual entry or import findings from an engagement."}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="w-10">
                      <Checkbox
                        checked={data && selectedIds.size === data.items.length && data.items.length > 0}
                        onCheckedChange={toggleSelectAll}
                      />
                    </TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("poamId")}>
                      <div className="flex items-center gap-1">POA&M ID <ArrowUpDown className="h-3 w-3" /></div>
                    </TableHead>
                    <TableHead>Weakness</TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("severity")}>
                      <div className="flex items-center gap-1">Severity <ArrowUpDown className="h-3 w-3" /></div>
                    </TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Asset</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>CVE</TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("scheduledCompletion")}>
                      <div className="flex items-center gap-1">Due Date <ArrowUpDown className="h-3 w-3" /></div>
                    </TableHead>
                    <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("createdAt")}>
                      <div className="flex items-center gap-1">Created <ArrowUpDown className="h-3 w-3" /></div>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data?.items.map(entry => {
                    const isOverdue = entry.status === "open" && entry.scheduledCompletionDate && new Date(entry.scheduledCompletionDate) < new Date();
                    return (
                      <TableRow
                        key={entry.id}
                        className={`cursor-pointer transition-colors ${isOverdue ? "bg-red-500/5" : ""}`}
                        onClick={() => navigate(`/risk-register/${entry.id}`)}
                      >
                        <TableCell onClick={e => e.stopPropagation()}>
                          <Checkbox
                            checked={selectedIds.has(entry.id)}
                            onCheckedChange={() => toggleSelect(entry.id)}
                          />
                        </TableCell>
                        <TableCell className="font-mono text-xs whitespace-nowrap">{entry.poamId}</TableCell>
                        <TableCell>
                          <div className="max-w-[250px]">
                            <div className="font-medium text-sm truncate">{entry.weaknessName}</div>
                            {entry.controls && (
                              <div className="text-xs text-muted-foreground truncate mt-0.5">{entry.controls}</div>
                            )}
                          </div>
                        </TableCell>
                        <TableCell><SeverityBadge severity={entry.severity} /></TableCell>
                        <TableCell><StatusBadge status={entry.status} /></TableCell>
                        <TableCell className="text-xs text-muted-foreground max-w-[150px] truncate">{entry.assetIdentifier || "—"}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">{entry.sourceType || "—"}</Badge>
                        </TableCell>
                        <TableCell className="text-xs font-mono text-muted-foreground">{entry.cve || "—"}</TableCell>
                        <TableCell className="text-xs whitespace-nowrap">
                          {entry.scheduledCompletionDate ? (
                            <span className={isOverdue ? "text-red-400 font-medium" : ""}>
                              {new Date(entry.scheduledCompletionDate).toLocaleDateString()}
                              {isOverdue && <AlertTriangle className="inline h-3 w-3 ml-1" />}
                            </span>
                          ) : "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {entry.createdAt ? new Date(entry.createdAt).toLocaleDateString() : "—"}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      {data && data.total > pageSize && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, data.total)} of {data.total} entries
          </p>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(p => p - 1)}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <span className="text-sm text-muted-foreground">Page {page + 1} of {totalPages}</span>
            <Button variant="outline" size="sm" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
