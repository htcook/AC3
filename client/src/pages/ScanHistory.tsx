import AppShell from "@/components/AppShell";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Globe, Search, ArrowLeft, Target, Loader2, RotateCcw, Trash2,
  ChevronUp, ChevronDown, Filter, Calendar, Shield, AlertTriangle,
  CheckCircle2, Clock, XCircle, Zap, FileText
} from "lucide-react";
import { toast } from "sonner";
import { exportDiReport } from "@/lib/export-di-report";

type SortField = "updatedAt" | "createdAt" | "primaryDomain" | "status" | "overallRiskScore" | "totalAssets";
type SortDir = "asc" | "desc";

const STATUS_OPTIONS = [
  { value: "all", label: "All Statuses" },
  { value: "completed", label: "Completed" },
  { value: "scan_complete", label: "Scan Complete" },
  { value: "pending", label: "Pending" },
  { value: "failed", label: "Failed" },
  { value: "in_progress", label: "In Progress" },
];

function statusIcon(status: string) {
  switch (status) {
    case "completed": return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />;
    case "scan_complete": return <Zap className="h-3.5 w-3.5 text-cyan-400" />;
    case "failed": return <XCircle className="h-3.5 w-3.5 text-red-400" />;
    case "pending": return <Clock className="h-3.5 w-3.5 text-muted-foreground" />;
    default: return <Loader2 className="h-3.5 w-3.5 text-yellow-400 animate-spin" />;
  }
}

function statusBadge(status: string) {
  const label = status === "scan_complete" ? "scan complete" : status;
  const cls =
    status === "completed" ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" :
    status === "scan_complete" ? "bg-cyan-500/20 text-cyan-400 border-cyan-500/30" :
    status === "failed" ? "bg-red-500/20 text-red-400 border-red-500/30" :
    status === "pending" ? "bg-muted text-muted-foreground" :
    "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
  return (
    <Badge variant="outline" className={`text-[10px] ${cls}`}>
      <span className="flex items-center gap-1">{statusIcon(status)} {label}</span>
    </Badge>
  );
}

function riskColor(score: number | null | undefined) {
  if (!score) return "text-muted-foreground";
  if (score >= 70) return "text-red-400 font-bold";
  if (score >= 40) return "text-orange-400 font-bold";
  return "text-green-400 font-bold";
}

export default function ScanHistory() {
  const [, navigate] = useLocation();
  const scansQuery = trpc.domainIntel.listScans.useQuery();
  const retryScan = trpc.domainIntel.retryScan.useMutation({
    onSuccess: () => { toast.success("Scan retried"); scansQuery.refetch(); },
    onError: (e: any) => toast.error("Retry failed: " + e.message),
  });
  const deleteScan = trpc.domainIntel.deleteScan.useMutation({
    onSuccess: () => { toast.success("Scan deleted"); scansQuery.refetch(); },
    onError: (e: any) => toast.error("Delete failed: " + e.message),
  });

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [sortField, setSortField] = useState<SortField>("updatedAt");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 25;

  const STUCK_THRESHOLD_MS = 15 * 60 * 1000;
  const isScanStuck = (scan: any) => {
    const inProgressStatuses = ['pending', 'passive_recon', 'discovering', 'analyzing', 'scoring', 'recommending'];
    return inProgressStatuses.includes(scan.status)
      && scan.updatedAt
      && (Date.now() - new Date(scan.updatedAt).getTime() > STUCK_THRESHOLD_MS);
  };

  const filtered = useMemo(() => {
    if (!scansQuery.data) return [];
    let list = [...scansQuery.data];

    // Search filter
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter((s: any) =>
        s.primaryDomain?.toLowerCase().includes(q) ||
        s.customerName?.toLowerCase().includes(q) ||
        s.sector?.toLowerCase().includes(q)
      );
    }

    // Status filter
    if (statusFilter !== "all") {
      if (statusFilter === "in_progress") {
        list = list.filter((s: any) =>
          !["completed", "scan_complete", "failed", "pending"].includes(s.status)
        );
      } else {
        list = list.filter((s: any) => s.status === statusFilter);
      }
    }

    // Sort
    list.sort((a: any, b: any) => {
      let av: any, bv: any;
      switch (sortField) {
        case "updatedAt":
          av = new Date(a.updatedAt || a.createdAt || 0).getTime();
          bv = new Date(b.updatedAt || b.createdAt || 0).getTime();
          break;
        case "createdAt":
          av = new Date(a.createdAt || 0).getTime();
          bv = new Date(b.createdAt || 0).getTime();
          break;
        case "primaryDomain":
          av = (a.primaryDomain || "").toLowerCase();
          bv = (b.primaryDomain || "").toLowerCase();
          break;
        case "status":
          av = a.status || "";
          bv = b.status || "";
          break;
        case "overallRiskScore":
          av = a.overallRiskScore || 0;
          bv = b.overallRiskScore || 0;
          break;
        case "totalAssets":
          av = a.totalAssets || 0;
          bv = b.totalAssets || 0;
          break;
        default:
          av = 0; bv = 0;
      }
      if (av < bv) return sortDir === "asc" ? -1 : 1;
      if (av > bv) return sortDir === "asc" ? 1 : -1;
      return 0;
    });

    return list;
  }, [scansQuery.data, search, statusFilter, sortField, sortDir]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const pageData = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir(d => d === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDir("desc");
    }
    setPage(0);
  };

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <ChevronDown className="h-3 w-3 text-muted-foreground/40" />;
    return sortDir === "asc"
      ? <ChevronUp className="h-3 w-3 text-purple-400" />
      : <ChevronDown className="h-3 w-3 text-purple-400" />;
  };

  // Stats
  const stats = useMemo(() => {
    if (!scansQuery.data) return { total: 0, completed: 0, scanComplete: 0, failed: 0, pending: 0 };
    const d = scansQuery.data;
    return {
      total: d.length,
      completed: d.filter((s: any) => s.status === "completed").length,
      scanComplete: d.filter((s: any) => s.status === "scan_complete").length,
      failed: d.filter((s: any) => s.status === "failed").length,
      pending: d.filter((s: any) => s.status === "pending").length,
    };
  }, [scansQuery.data]);

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="sm" onClick={() => navigate("/domain-intel")}>
              <ArrowLeft className="h-4 w-4 mr-1" /> Back
            </Button>
            <div>
              <h1 className="text-2xl font-bold flex items-center gap-2">
                <Globe className="h-6 w-6 text-purple-400" />
                Scan History
              </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Review the complete history of all domain intelligence scans, vulnerability scans, and reconnaissance operations. Filter by date, domain, status, or scan type to find specific results. Click any scan to view its full findings, asset inventory, and risk scores. Use the comparison feature to track how a target's security posture has changed between scans. The cleanup tool lets admins remove empty or test scans.</p>
              <p className="text-muted-foreground text-sm mt-0.5">
                Browse, filter, and manage all domain intelligence scans. Click any completed scan to view full results.
              </p>
            </div>
          </div>
          <Button onClick={() => navigate("/domain-intel")} className="bg-purple-600 hover:bg-purple-700">
            <Target className="h-4 w-4 mr-2" /> New Scan
          </Button>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: "Total Scans", value: stats.total, color: "text-foreground" },
            { label: "Completed", value: stats.completed, color: "text-emerald-400" },
            { label: "Scan Complete", value: stats.scanComplete, color: "text-cyan-400" },
            { label: "Failed", value: stats.failed, color: "text-red-400" },
            { label: "Pending", value: stats.pending, color: "text-muted-foreground" },
          ].map(s => (
            <Card key={s.label}>
              <CardContent className="p-3 text-center">
                <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{s.label}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search domain, customer, sector..."
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(0); }}
              className="pl-9"
            />
          </div>
          <Select value={statusFilter} onValueChange={v => { setStatusFilter(v); setPage(0); }}>
            <SelectTrigger className="w-[180px]">
              <Filter className="h-3.5 w-3.5 mr-2 text-muted-foreground" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUS_OPTIONS.map(o => (
                <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <span className="text-xs text-muted-foreground">
            {filtered.length} scan{filtered.length !== 1 ? "s" : ""} found
          </span>
        </div>

        {/* Table */}
        <Card>
          <CardContent className="p-0">
            {scansQuery.isLoading ? (
              <div className="p-6 space-y-3">
                {Array.from({ length: 8 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-muted/30">
                      {([
                        { field: "primaryDomain" as SortField, label: "Domain" },
                        { field: "status" as SortField, label: "Status" },
                        { field: "overallRiskScore" as SortField, label: "Risk" },
                        { field: "totalAssets" as SortField, label: "Assets" },
                        { field: "updatedAt" as SortField, label: "Last Activity" },
                      ]).map(col => (
                        <th
                          key={col.field}
                          className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider cursor-pointer hover:text-foreground transition-colors select-none"
                          onClick={() => toggleSort(col.field)}
                        >
                          <span className="flex items-center gap-1">
                            {col.label} <SortIcon field={col.field} />
                          </span>
                        </th>
                      ))}
                      <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {pageData.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="px-4 py-12 text-center text-muted-foreground">
                          No scans match your filters.
                        </td>
                      </tr>
                    ) : pageData.map((scan: any) => {
                      const stuck = isScanStuck(scan);
                      const canRetry = stuck || scan.status === 'failed' || scan.status === 'pending';
                      const canView = scan.status === 'completed' || scan.status === 'scan_complete';
                      const risk = scan.overallRiskScore;
                      return (
                        <tr
                          key={scan.id}
                          className={`border-b border-border/50 hover:bg-muted/20 transition-colors ${canView ? 'cursor-pointer' : ''}`}
                          onClick={() => canView && navigate(`/domain-intel/${scan.id}`)}
                        >
                          <td className="px-4 py-3">
                            <div>
                              <p className="font-mono text-sm font-semibold">{scan.primaryDomain}</p>
                              {scan.customerName && (
                                <p className="text-[10px] text-muted-foreground mt-0.5">{scan.customerName} · {scan.sector || 'N/A'}</p>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            {stuck ? (
                              <Badge variant="outline" className="text-[10px] bg-orange-500/20 text-orange-400 border-orange-500/30">
                                <span className="flex items-center gap-1"><AlertTriangle className="h-3 w-3" /> stuck</span>
                              </Badge>
                            ) : statusBadge(scan.status)}
                          </td>
                          <td className="px-4 py-3">
                            <span className={`font-mono text-sm ${riskColor(risk)}`}>
                              {risk ?? '—'}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <span className="text-sm">{scan.totalAssets || 0}</span>
                          </td>
                          <td className="px-4 py-3">
                            <span className="text-xs text-muted-foreground">
                              {(scan.updatedAt || scan.createdAt) ? new Date(scan.updatedAt || scan.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : '—'}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-right">
                            <div className="flex items-center justify-end gap-1" onClick={e => e.stopPropagation()}>
                              {canView && (
                                <>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-7 px-2 text-purple-400 hover:text-purple-300"
                                  onClick={() => navigate(`/domain-intel/${scan.id}`)}
                                >
                                  <Target className="h-3.5 w-3.5 mr-1" /> View
                                </Button>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-7 px-2 text-cyan-400 hover:text-cyan-300"
                                  onClick={async () => {
                                    try {
                                      toast.info('Generating DI report...');
                                      const response = await fetch(`/api/trpc/domainIntel.getScan?input=${encodeURIComponent(JSON.stringify({ id: scan.id }))}`);
                                      const result = await response.json();
                                      const fullData = result?.result?.data;
                                      if (!fullData?.scan) { toast.error('Failed to load scan data'); return; }
                                      const fullScan = fullData.scan;
                                      const pipeline = fullScan.pipelineOutput || {};
                                      const assets = fullData.assets || [];
                                      const fullScanData = { ...fullScan, ...pipeline, assets, observations: pipeline?.observations || [] };
                                      let evidenceData;
                                      try {
                                        const evResp = await fetch(`/api/trpc/domainIntel.getReportEvidence?input=${encodeURIComponent(JSON.stringify({ scanId: scan.id }))}`);
                                        const evResult = await evResp.json();
                                        evidenceData = evResult?.result?.data;
                                      } catch { /* optional */ }
                                      let infraMapData = null;
                                      try {
                                        const infraResp = await fetch(`/api/trpc/calderaProxy.inferInfrastructure?input=${encodeURIComponent(JSON.stringify({ scanId: scan.id }))}`);
                                        const infraRes = await infraResp.json();
                                        infraMapData = infraRes?.result?.data || null;
                                      } catch { /* optional */ }
                                      let vrHistory = null;
                                      try {
                                        const vrResp = await fetch(`/api/trpc/calderaProxy.getVendorRiskHistory?input=${encodeURIComponent(JSON.stringify({ scanId: scan.id }))}`);
                                        const vrRes = await vrResp.json();
                                        vrHistory = vrRes?.result?.data?.history || null;
                                      } catch { /* optional */ }
                                      await exportDiReport(fullScan.primaryDomain, fullScanData, undefined, evidenceData, infraMapData, vrHistory);
                                      toast.success('DI report generated');
                                    } catch (err: any) {
                                      toast.error('Report failed: ' + (err.message || 'Unknown error'));
                                    }
                                  }}
                                >
                                  <FileText className="h-3.5 w-3.5 mr-1" /> Report
                                </Button>
                                </>
                              )}
                              {canRetry && (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-7 px-2 text-orange-400 hover:text-orange-300"
                                  onClick={() => retryScan.mutate({ scanId: scan.id })}
                                  disabled={retryScan.isPending}
                                >
                                  {retryScan.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCcw className="h-3 w-3" />}
                                </Button>
                              )}
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 px-2 text-red-400/60 hover:text-red-400"
                                onClick={() => { if (confirm('Delete this scan?')) deleteScan.mutate({ scanId: scan.id }); }}
                                disabled={deleteScan.isPending}
                              >
                                <Trash2 className="h-3 w-3" />
                              </Button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">
              Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length}
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page === 0}
                onClick={() => setPage(p => p - 1)}
              >
                Previous
              </Button>
              <span className="text-xs text-muted-foreground">
                Page {page + 1} of {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages - 1}
                onClick={() => setPage(p => p + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
