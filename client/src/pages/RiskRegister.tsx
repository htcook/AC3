import React, { useState, useMemo, useCallback } from "react";
import { Link, useLocation } from "wouter";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Checkbox } from "@/components/ui/checkbox";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { toast } from "sonner";
import {
  ClipboardCheck, Plus, Search, Download, ChevronLeft, ChevronRight,
  AlertTriangle, MoreHorizontal, Trash2, ArrowUpDown, FileSpreadsheet,
} from "lucide-react";

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  moderate: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  informational: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};
const STATUS_COLORS: Record<string, string> = {
  open: "bg-red-500/20 text-red-400 border-red-500/30",
  in_progress: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  closed: "bg-green-500/20 text-green-400 border-green-500/30",
  risk_accepted: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  deferred: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  vendor_dependent: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
};
const STATUS_LABELS: Record<string, string> = {
  open: "Open", in_progress: "In Progress", closed: "Closed",
  risk_accepted: "Risk Accepted", deferred: "Deferred", vendor_dependent: "Vendor Dependent",
};

export default function RiskRegister() {
  const [, navigate] = useLocation();
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [sourceFilter, setSourceFilter] = useState<string>("");
  const [sortBy, setSortBy] = useState<"createdAt" | "severity" | "status" | "scheduledCompletionDate" | "originalDetectionDate">("createdAt");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [selected, setSelected] = useState<number[]>([]);

  const queryInput = useMemo(() => ({
    page, pageSize,
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
    source: sourceFilter || undefined,
    search: search || undefined,
    sortBy, sortDir,
  }), [page, pageSize, statusFilter, severityFilter, sourceFilter, search, sortBy, sortDir]);

  const { data, isLoading, refetch } = trpc.riskRegister.list.useQuery(queryInput);
  const metrics = trpc.riskRegister.executiveMetrics.useQuery({ days: 90 });
  const bulkUpdate = trpc.riskRegister.bulkUpdateStatus.useMutation({
    onSuccess: () => { refetch(); setSelected([]); toast.success("Status updated"); },
    onError: (e: any) => toast.error(e.message),
  });
  const deleteMut = trpc.riskRegister.delete.useMutation({
    onSuccess: () => { refetch(); toast.success("Entry deleted"); },
    onError: (e: any) => toast.error(e.message),
  });
  const exportExcel = trpc.riskRegister.exportPoamExcel.useMutation({
    onSuccess: (d: any) => {
      const bytes = Uint8Array.from(atob(d.base64), c => c.charCodeAt(0));
      const blob = new Blob([bytes], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = d.filename; a.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported ${d.count} entries to Excel`);
    },
    onError: (e: any) => toast.error(e.message),
  });

  const toggleSelect = useCallback((id: number) => {
    setSelected(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  }, []);
  const toggleAll = useCallback(() => {
    if (!data) return;
    setSelected(prev => prev.length === data.items.length ? [] : data.items.map((i: any) => i.id));
  }, [data]);

  const handleSort = (col: typeof sortBy) => {
    if (sortBy === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortBy(col); setSortDir("desc"); }
  };

  const handleExport = () => {
    if (!data) return;
    const headers = ["POA&M ID", "Weakness Name", "Severity", "Status", "Asset", "Controls", "Detection Date", "Scheduled Completion", "Source"];
    const rows = data.items.map((i: any) => [
      i.poamId, i.weaknessName, i.severity, i.status, i.assetIdentifier || "", i.controls || "",
      i.originalDetectionDate || "", i.scheduledCompletionDate || "", i.source,
    ]);
    const csv = [headers, ...rows].map(r => r.map((c: any) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `risk-register-${new Date().toISOString().split("T")[0]}.csv`; a.click();
    URL.revokeObjectURL(url);
    toast.success("CSV exported");
  };

  const m = metrics.data?.summary;

  return (
    <AppShell activePath="/risk-register">
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ClipboardCheck className="h-8 w-8 text-primary" />
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Risk Register</h1>
              <p className="text-muted-foreground">FedRAMP POA&M management and risk lifecycle tracking</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExport} disabled={!data?.items.length}>
              <Download className="h-4 w-4 mr-1" /> CSV
            </Button>
            <Button variant="outline" size="sm" onClick={() => exportExcel.mutate({ status: statusFilter || undefined, severity: severityFilter || undefined })} disabled={exportExcel.isPending}>
              <FileSpreadsheet className="h-4 w-4 mr-1" /> {exportExcel.isPending ? "Generating..." : "FedRAMP POA&M"}
            </Button>
            <Link href="/risk-register/new">
              <Button size="sm"><Plus className="h-4 w-4 mr-1" /> New Entry</Button>
            </Link>
          </div>
        </div>

        {m && (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {[
              { label: "Open Items", value: m.totalOpen, color: "text-red-400" },
              { label: "Overdue", value: m.overdue, color: "text-orange-400" },
              { label: "Closed (90d)", value: m.totalClosedInPeriod, color: "text-green-400" },
              { label: "Risk Accepted", value: m.riskAccepted, color: "text-purple-400" },
              { label: "Vendor Dep.", value: m.vendorDependent, color: "text-cyan-400" },
              { label: "New (90d)", value: m.newInPeriod, color: "text-yellow-400" },
            ].map(c => (
              <Card key={c.label} className="bg-card border-border">
                <CardContent className="p-4 text-center">
                  <div className={`text-2xl font-bold ${c.color}`}>{c.value}</div>
                  <div className="text-xs text-muted-foreground">{c.label}</div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search POA&M ID, weakness, asset..." className="pl-9 bg-card border-border"
              value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} />
          </div>
          <Select value={statusFilter || "all"} onValueChange={v => { setStatusFilter(v === "all" ? "" : v); setPage(1); }}>
            <SelectTrigger className="w-[160px] bg-card border-border"><SelectValue placeholder="All Statuses" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Statuses</SelectItem>
              {Object.entries(STATUS_LABELS).map(([k, v]) => <SelectItem key={k} value={k}>{v}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={severityFilter || "all"} onValueChange={v => { setSeverityFilter(v === "all" ? "" : v); setPage(1); }}>
            <SelectTrigger className="w-[140px] bg-card border-border"><SelectValue placeholder="All Severities" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              {["critical", "high", "moderate", "low", "informational"].map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={sourceFilter || "all"} onValueChange={v => { setSourceFilter(v === "all" ? "" : v); setPage(1); }}>
            <SelectTrigger className="w-[160px] bg-card border-border"><SelectValue placeholder="All Sources" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Sources</SelectItem>
              {["manual", "engagement", "ctem_scan", "vulnerability_scan", "pentest", "red_team", "bug_bounty"].map(s =>
                <SelectItem key={s} value={s}>{s.replace(/_/g, " ")}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>

        {selected.length > 0 && (
          <div className="flex items-center gap-3 p-3 bg-primary/10 border border-primary/30 rounded-lg">
            <span className="text-sm font-medium">{selected.length} selected</span>
            <DropdownMenu>
              <DropdownMenuTrigger asChild><Button size="sm" variant="outline">Bulk Status Change</Button></DropdownMenuTrigger>
              <DropdownMenuContent>
                {Object.entries(STATUS_LABELS).map(([k, v]) => (
                  <DropdownMenuItem key={k} onClick={() => bulkUpdate.mutate({ ids: selected, status: k as any })}>{v}</DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            <Button size="sm" variant="ghost" onClick={() => setSelected([])}>Clear</Button>
          </div>
        )}

        <Card className="bg-card border-border">
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="w-10"><Checkbox checked={data && selected.length === data.items.length && data.items.length > 0} onCheckedChange={toggleAll} /></TableHead>
                <TableHead className="cursor-pointer" onClick={() => handleSort("createdAt")}><span className="flex items-center gap-1">POA&M ID <ArrowUpDown className="h-3 w-3" /></span></TableHead>
                <TableHead>Weakness</TableHead>
                <TableHead className="cursor-pointer" onClick={() => handleSort("severity")}><span className="flex items-center gap-1">Severity <ArrowUpDown className="h-3 w-3" /></span></TableHead>
                <TableHead className="cursor-pointer" onClick={() => handleSort("status")}><span className="flex items-center gap-1">Status <ArrowUpDown className="h-3 w-3" /></span></TableHead>
                <TableHead>Asset</TableHead>
                <TableHead className="cursor-pointer" onClick={() => handleSort("scheduledCompletionDate")}><span className="flex items-center gap-1">Due Date <ArrowUpDown className="h-3 w-3" /></span></TableHead>
                <TableHead>Source</TableHead>
                <TableHead className="w-10"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? Array.from({ length: 5 }).map((_, i) => (
                <TableRow key={i} className="border-border">{Array.from({ length: 9 }).map((_, j) => (<TableCell key={j}><div className="h-4 bg-muted rounded animate-pulse" /></TableCell>))}</TableRow>
              )) : !data?.items.length ? (
                <TableRow className="border-border"><TableCell colSpan={9} className="text-center py-12 text-muted-foreground">
                  <ClipboardCheck className="h-12 w-12 mx-auto mb-3 opacity-30" />
                  <p className="font-medium">No risk register entries found</p>
                  <p className="text-sm mt-1">Create a new entry or sync from engagements</p>
                </TableCell></TableRow>
              ) : data.items.map((item: any) => {
                const isOverdue = item.scheduledCompletionDate && new Date(item.scheduledCompletionDate) < new Date() && !["closed", "risk_accepted"].includes(item.status);
                return (
                  <TableRow key={item.id} className="border-border cursor-pointer hover:bg-muted/30" onClick={() => navigate(`/risk-register/${item.id}`)}>
                    <TableCell onClick={e => e.stopPropagation()}><Checkbox checked={selected.includes(item.id)} onCheckedChange={() => toggleSelect(item.id)} /></TableCell>
                    <TableCell className="font-mono text-xs text-primary">{item.poamId}</TableCell>
                    <TableCell className="max-w-[250px] truncate font-medium">{item.weaknessName}</TableCell>
                    <TableCell><Badge variant="outline" className={SEV_COLORS[item.severity] || ""}>{item.severity}</Badge></TableCell>
                    <TableCell><Badge variant="outline" className={STATUS_COLORS[item.status] || ""}>{STATUS_LABELS[item.status] || item.status}</Badge></TableCell>
                    <TableCell className="max-w-[150px] truncate text-muted-foreground text-sm">{item.assetIdentifier || "\u2014"}</TableCell>
                    <TableCell className="text-sm">
                      {item.scheduledCompletionDate ? (
                        <span className={isOverdue ? "text-red-400 font-medium" : "text-muted-foreground"}>
                          {isOverdue && <AlertTriangle className="h-3 w-3 inline mr-1" />}
                          {new Date(item.scheduledCompletionDate).toLocaleDateString()}
                        </span>
                      ) : "\u2014"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground capitalize">{item.source.replace(/_/g, " ")}</TableCell>
                    <TableCell onClick={e => e.stopPropagation()}>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild><Button variant="ghost" size="icon" className="h-7 w-7"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => navigate(`/risk-register/${item.id}`)}>View Details</DropdownMenuItem>
                          <DropdownMenuItem className="text-red-400" onClick={() => { if (confirm("Delete this entry?")) deleteMut.mutate({ id: item.id }); }}><Trash2 className="h-4 w-4 mr-2" />Delete</DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Card>

        {data && data.totalPages > 1 && (
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Showing {(page - 1) * pageSize + 1}\u2013{Math.min(page * pageSize, data.total)} of {data.total}</span>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}><ChevronLeft className="h-4 w-4" /></Button>
              <span className="text-sm">Page {page} of {data.totalPages}</span>
              <Button variant="outline" size="sm" disabled={page >= data.totalPages} onClick={() => setPage(p => p + 1)}><ChevronRight className="h-4 w-4" /></Button>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
