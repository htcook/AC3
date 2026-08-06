/**
 * Bug Report Admin Dashboard
 *
 * Triage, assign, and track all bug reports filed by testers through AI chatbots.
 * Provides filtering by status, severity, and category with bulk actions and
 * detailed view with admin notes.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
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
  Bug,
  CheckCircle2,
  Clock,
  AlertTriangle,
  XCircle,
  Search,
  RefreshCw,
  Eye,
  MessageSquare,
  Trash2,
  ChevronLeft,
  ChevronRight,
  Filter,
  ArrowUpDown,
  Ban,
  Loader2,
} from "lucide-react";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import { Checkbox } from "@/components/ui/checkbox";

const STATUS_CONFIG: Record<string, { label: string; icon: any; color: string; bg: string }> = {
  open: { label: "Open", icon: Bug, color: "text-red-400", bg: "bg-red-500/10" },
  in_progress: { label: "In Progress", icon: Clock, color: "text-yellow-400", bg: "bg-yellow-500/10" },
  resolved: { label: "Resolved", icon: CheckCircle2, color: "text-green-400", bg: "bg-green-500/10" },
  closed: { label: "Closed", icon: XCircle, color: "text-zinc-400", bg: "bg-zinc-500/10" },
  wont_fix: { label: "Won't Fix", icon: Ban, color: "text-orange-400", bg: "bg-orange-500/10" },
};

const SEVERITY_CONFIG: Record<string, { color: string; bg: string }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/20" },
  high: { color: "text-orange-400", bg: "bg-orange-500/20" },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/20" },
  low: { color: "text-blue-400", bg: "bg-blue-500/20" },
};

export default function BugReportDashboard() {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [page, setPage] = useState(0);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [detailId, setDetailId] = useState<number | null>(null);
  const [noteText, setNoteText] = useState("");
  const [bulkStatus, setBulkStatus] = useState<string>("");
  const pageSize = 25;

  const utils = trpc.useUtils();

  const { data: stats } = trpc.bugReports.stats.useQuery();
  const { data: listData, isLoading } = trpc.bugReports.list.useQuery({
    status: statusFilter as any,
    severity: severityFilter as any,
    category: categoryFilter as any,
    search: searchQuery || undefined,
    limit: pageSize,
    offset: page * pageSize,
  });

  const { data: detail } = trpc.bugReports.getById.useQuery(
    { id: detailId! },
    { enabled: !!detailId }
  );

  const updateStatus = trpc.bugReports.updateStatus.useMutation({
    onSuccess: () => {
      toast.success("Status updated");
      utils.bugReports.list.invalidate();
      utils.bugReports.stats.invalidate();
      if (detailId) utils.bugReports.getById.invalidate({ id: detailId });
    },
  });

  const addNotes = trpc.bugReports.addNotes.useMutation({
    onSuccess: () => {
      toast.success("Note added");
      setNoteText("");
      if (detailId) utils.bugReports.getById.invalidate({ id: detailId });
    },
  });

  const bulkUpdate = trpc.bugReports.bulkUpdateStatus.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.updated} reports updated`);
      setSelectedIds(new Set());
      setBulkStatus("");
      utils.bugReports.list.invalidate();
      utils.bugReports.stats.invalidate();
    },
  });

  const deleteMut = trpc.bugReports.delete.useMutation({
    onSuccess: () => {
      toast.success("Bug report deleted");
      setDetailId(null);
      utils.bugReports.list.invalidate();
      utils.bugReports.stats.invalidate();
    },
  });

  const reports = listData?.reports ?? [];
  const total = listData?.total ?? 0;
  const totalPages = Math.ceil(total / pageSize);

  const toggleSelect = (id: number) => {
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelectedIds(next);
  };

  const toggleAll = () => {
    if (selectedIds.size === reports.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(reports.map((r: any) => r.id)));
    }
  };

  return (
    <AppShell title="Bug Report Dashboard" subtitle="Triage, assign, and track all bug reports filed by testers through AI chatbots. Use filters to prioritize critical issues and bulk actions to manage reports efficiently.">
      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-foreground">{stats?.total ?? 0}</p>
            <p className="text-xs text-muted-foreground">Total</p>
          </CardContent>
        </Card>
        <Card className="bg-red-500/5 border-red-500/20">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-red-400">{stats?.byStatus.open ?? 0}</p>
            <p className="text-xs text-muted-foreground">Open</p>
          </CardContent>
        </Card>
        <Card className="bg-yellow-500/5 border-yellow-500/20">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-yellow-400">{stats?.byStatus.inProgress ?? 0}</p>
            <p className="text-xs text-muted-foreground">In Progress</p>
          </CardContent>
        </Card>
        <Card className="bg-green-500/5 border-green-500/20">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-green-400">{stats?.byStatus.resolved ?? 0}</p>
            <p className="text-xs text-muted-foreground">Resolved</p>
          </CardContent>
        </Card>
        <Card className="bg-red-500/5 border-red-500/20">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-red-400">{stats?.bySeverity.critical ?? 0}</p>
            <p className="text-xs text-muted-foreground">Critical</p>
          </CardContent>
        </Card>
        <Card className="bg-orange-500/5 border-orange-500/20">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-orange-400">{stats?.bySeverity.high ?? 0}</p>
            <p className="text-xs text-muted-foreground">High</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-4 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search bug reports..."
            value={searchQuery}
            onChange={(e) => { setSearchQuery(e.target.value); setPage(0); }}
            className="pl-10 bg-card/50 border-border/50"
          />
        </div>
        <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v); setPage(0); }}>
          <SelectTrigger className="w-[140px] bg-card/50 border-border/50">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="in_progress">In Progress</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
            <SelectItem value="closed">Closed</SelectItem>
            <SelectItem value="wont_fix">Won't Fix</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={(v) => { setSeverityFilter(v); setPage(0); }}>
          <SelectTrigger className="w-[140px] bg-card/50 border-border/50">
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
        <Select value={categoryFilter} onValueChange={(v) => { setCategoryFilter(v); setPage(0); }}>
          <SelectTrigger className="w-[140px] bg-card/50 border-border/50">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            <SelectItem value="bug">Bug</SelectItem>
            <SelectItem value="ui">UI</SelectItem>
            <SelectItem value="performance">Performance</SelectItem>
            <SelectItem value="security">Security</SelectItem>
            <SelectItem value="feature_request">Feature Request</SelectItem>
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          size="sm"
          onClick={() => { utils.bugReports.list.invalidate(); utils.bugReports.stats.invalidate(); }}
        >
          <RefreshCw className="w-4 h-4 mr-1" /> Refresh
        </Button>
      </div>

      {/* Bulk Actions */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 mb-4 p-3 bg-primary/5 border border-primary/20 rounded-lg">
          <span className="text-sm text-foreground font-medium">{selectedIds.size} selected</span>
          <Select value={bulkStatus} onValueChange={setBulkStatus}>
            <SelectTrigger className="w-[160px] bg-card/50 border-border/50">
              <SelectValue placeholder="Set status..." />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="in_progress">In Progress</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
              <SelectItem value="closed">Closed</SelectItem>
              <SelectItem value="wont_fix">Won't Fix</SelectItem>
            </SelectContent>
          </Select>
          {bulkStatus && (
            <Button
              size="sm"
              onClick={() => bulkUpdate.mutate({ ids: Array.from(selectedIds), status: bulkStatus as any })}
              disabled={bulkUpdate.isPending}
            >
              {bulkUpdate.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : null}
              Apply
            </Button>
          )}
          <Button variant="ghost" size="sm" onClick={() => setSelectedIds(new Set())}>
            Clear
          </Button>
        </div>
      )}

      {/* Report List */}
      <Card className="bg-card/50 border-border/50">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/50">
                  <th className="p-3 text-left w-10">
                    <Checkbox
                      checked={reports.length > 0 && selectedIds.size === reports.length}
                      onCheckedChange={toggleAll}
                    />
                  </th>
                  <th className="p-3 text-left text-muted-foreground font-medium">Title</th>
                  <th className="p-3 text-left text-muted-foreground font-medium w-24">Severity</th>
                  <th className="p-3 text-left text-muted-foreground font-medium w-28">Status</th>
                  <th className="p-3 text-left text-muted-foreground font-medium w-24">Category</th>
                  <th className="p-3 text-left text-muted-foreground font-medium w-32">Reporter</th>
                  <th className="p-3 text-left text-muted-foreground font-medium w-28">Page</th>
                  <th className="p-3 text-left text-muted-foreground font-medium w-36">Filed</th>
                  <th className="p-3 text-left text-muted-foreground font-medium w-20">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={9} className="p-8 text-center text-muted-foreground">
                      <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />
                      Loading bug reports...
                    </td>
                  </tr>
                ) : reports.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="p-8 text-center text-muted-foreground">
                      <Bug className="w-8 h-8 mx-auto mb-2 opacity-50" />
                      No bug reports found
                    </td>
                  </tr>
                ) : (
                  reports.map((report: any) => {
                    const sev = SEVERITY_CONFIG[report.severity] || SEVERITY_CONFIG.medium;
                    const stat = STATUS_CONFIG[report.status] || STATUS_CONFIG.open;
                    const StatIcon = stat.icon;
                    return (
                      <tr
                        key={report.id}
                        className="border-b border-border/30 hover:bg-muted/30 cursor-pointer transition-colors"
                        onClick={() => setDetailId(report.id)}
                      >
                        <td className="p-3" onClick={(e) => e.stopPropagation()}>
                          <Checkbox
                            checked={selectedIds.has(report.id)}
                            onCheckedChange={() => toggleSelect(report.id)}
                          />
                        </td>
                        <td className="p-3">
                          <div className="font-medium text-foreground truncate max-w-[300px]">{report.title}</div>
                          <div className="text-xs text-muted-foreground truncate max-w-[300px] mt-0.5">{report.description?.slice(0, 80)}</div>
                        </td>
                        <td className="p-3">
                          <Badge variant="outline" className={`${sev.bg} ${sev.color} border-0 text-xs`}>
                            {report.severity}
                          </Badge>
                        </td>
                        <td className="p-3">
                          <div className={`flex items-center gap-1.5 ${stat.color}`}>
                            <StatIcon className="w-3.5 h-3.5" />
                            <span className="text-xs">{stat.label}</span>
                          </div>
                        </td>
                        <td className="p-3">
                          <span className="text-xs text-muted-foreground">{report.category}</span>
                        </td>
                        <td className="p-3">
                          <span className="text-xs text-muted-foreground">{report.userName || `User #${report.userId}`}</span>
                        </td>
                        <td className="p-3">
                          <span className="text-xs text-muted-foreground truncate max-w-[100px] block">{report.page || "—"}</span>
                        </td>
                        <td className="p-3">
                          <span className="text-xs text-muted-foreground">
                            {report.createdAt ? new Date(report.createdAt).toLocaleDateString() : "—"}
                          </span>
                        </td>
                        <td className="p-3" onClick={(e) => e.stopPropagation()}>
                          <Button variant="ghost" size="sm" onClick={() => setDetailId(report.id)}>
                            <Eye className="w-4 h-4" />
                          </Button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between p-3 border-t border-border/50">
              <span className="text-xs text-muted-foreground">
                Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, total)} of {total}
              </span>
              <div className="flex gap-1">
                <Button variant="ghost" size="sm" disabled={page === 0} onClick={() => setPage(p => p - 1)}>
                  <ChevronLeft className="w-4 h-4" />
                </Button>
                <Button variant="ghost" size="sm" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>
                  <ChevronRight className="w-4 h-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Detail Dialog */}
      <Dialog open={!!detailId} onOpenChange={(open) => { if (!open) setDetailId(null); }}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          {detail && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Bug className="w-5 h-5 text-primary" />
                  {detail.title}
                </DialogTitle>
                <DialogDescription>
                  Filed by {detail.userName || `User #${detail.userId}`} on{" "}
                  {detail.createdAt ? new Date(detail.createdAt).toLocaleString() : "Unknown"}
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4">
                {/* Meta */}
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline" className={`${SEVERITY_CONFIG[detail.severity]?.bg} ${SEVERITY_CONFIG[detail.severity]?.color} border-0`}>
                    {detail.severity}
                  </Badge>
                  <Badge variant="outline" className={`${STATUS_CONFIG[detail.status]?.bg} ${STATUS_CONFIG[detail.status]?.color} border-0`}>
                    {STATUS_CONFIG[detail.status]?.label || detail.status}
                  </Badge>
                  <Badge variant="outline">{detail.category}</Badge>
                  {detail.page && <Badge variant="outline" className="text-xs">Page: {detail.page}</Badge>}
                </div>

                {/* Description */}
                <div>
                  <h4 className="text-sm font-medium text-foreground mb-1">Description</h4>
                  <p className="text-sm text-muted-foreground whitespace-pre-wrap">{detail.description}</p>
                </div>

                {/* Steps to Reproduce */}
                {detail.stepsToReproduce && (
                  <div>
                    <h4 className="text-sm font-medium text-foreground mb-1">Steps to Reproduce</h4>
                    <p className="text-sm text-muted-foreground whitespace-pre-wrap">{detail.stepsToReproduce}</p>
                  </div>
                )}

                {/* Expected vs Actual */}
                <div className="grid grid-cols-2 gap-4">
                  {detail.expectedBehavior && (
                    <div>
                      <h4 className="text-sm font-medium text-green-400 mb-1">Expected Behavior</h4>
                      <p className="text-sm text-muted-foreground">{detail.expectedBehavior}</p>
                    </div>
                  )}
                  {detail.actualBehavior && (
                    <div>
                      <h4 className="text-sm font-medium text-red-400 mb-1">Actual Behavior</h4>
                      <p className="text-sm text-muted-foreground">{detail.actualBehavior}</p>
                    </div>
                  )}
                </div>

                {/* Browser Info */}
                {detail.browserInfo && (
                  <div>
                    <h4 className="text-sm font-medium text-foreground mb-1">Browser Info</h4>
                    <p className="text-xs text-muted-foreground font-mono">{detail.browserInfo}</p>
                  </div>
                )}

                {/* Status Update */}
                <div>
                  <h4 className="text-sm font-medium text-foreground mb-2">Update Status</h4>
                  <div className="flex gap-2 flex-wrap">
                    {Object.entries(STATUS_CONFIG).map(([key, cfg]) => {
                      const Icon = cfg.icon;
                      return (
                        <Button
                          key={key}
                          variant={detail.status === key ? "default" : "outline"}
                          size="sm"
                          className={detail.status === key ? "" : `${cfg.color}`}
                          onClick={() => updateStatus.mutate({ id: detail.id, status: key as any })}
                          disabled={updateStatus.isPending}
                        >
                          <Icon className="w-3.5 h-3.5 mr-1" />
                          {cfg.label}
                        </Button>
                      );
                    })}
                  </div>
                </div>

                {/* Admin Notes */}
                <div>
                  <h4 className="text-sm font-medium text-foreground mb-2">Admin Notes</h4>
                  {detail.adminNotes && (
                    <pre className="text-xs text-muted-foreground bg-muted/30 p-3 rounded-lg mb-3 whitespace-pre-wrap font-mono">
                      {detail.adminNotes}
                    </pre>
                  )}
                  <div className="flex gap-2">
                    <Textarea
                      placeholder="Add a note..."
                      value={noteText}
                      onChange={(e) => setNoteText(e.target.value)}
                      className="bg-card/50 border-border/50 text-sm min-h-[60px]"
                    />
                  </div>
                  <div className="flex justify-between mt-2">
                    <Button
                      size="sm"
                      onClick={() => addNotes.mutate({ id: detail.id, notes: noteText })}
                      disabled={!noteText.trim() || addNotes.isPending}
                    >
                      <MessageSquare className="w-4 h-4 mr-1" />
                      Add Note
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => {
                        if (confirm("Delete this bug report permanently?")) {
                          deleteMut.mutate({ id: detail.id });
                        }
                      }}
                      disabled={deleteMut.isPending}
                    >
                      <Trash2 className="w-4 h-4 mr-1" />
                      Delete
                    </Button>
                  </div>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
