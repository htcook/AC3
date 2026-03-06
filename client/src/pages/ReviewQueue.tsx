/**
 * Review Queue — Tier 2 LLM-Assisted Approval Workflow
 *
 * Operators review and approve/reject LLM-generated scan plans,
 * vulnerability triage, detection rules, exploit plans, and more.
 */
import { useState, useMemo, useEffect } from "react";
import { useReviewQueueEvents } from "@/hooks/useWebSocket";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  ClipboardCheck,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  Shield,
  Brain,
  Target,
  Search,
  FileText,
  Zap,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Eye,
} from "lucide-react";
import AppShell from "@/components/AppShell";
import { toast } from "sonner";

// ─── Helpers ────────────────────────────────────────────────────────────────

const CATEGORY_LABELS: Record<string, { label: string; icon: any; color: string }> = {
  scan_plan: { label: "Scan Plan", icon: Target, color: "bg-blue-500/10 text-blue-400 border-blue-500/30" },
  vuln_triage: { label: "Vuln Triage", icon: Shield, color: "bg-orange-500/10 text-orange-400 border-orange-500/30" },
  detection_rule: { label: "Detection Rule", icon: Search, color: "bg-green-500/10 text-green-400 border-green-500/30" },
  exploit_plan: { label: "Exploit Plan", icon: Zap, color: "bg-red-500/10 text-red-400 border-red-500/30" },
  hunt_hypothesis: { label: "Hunt Hypothesis", icon: Brain, color: "bg-purple-500/10 text-purple-400 border-purple-500/30" },
  risk_score: { label: "Risk Score", icon: AlertTriangle, color: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30" },
  report_draft: { label: "Report Draft", icon: FileText, color: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30" },
  c2_action: { label: "C2 Action", icon: Target, color: "bg-red-500/10 text-red-400 border-red-500/30" },
};

const RISK_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  low: "bg-green-500/20 text-green-300 border-green-500/40",
  info: "bg-blue-500/20 text-blue-300 border-blue-500/40",
};

const STATUS_COLORS: Record<string, string> = {
  pending: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  approved: "bg-green-500/20 text-green-300 border-green-500/40",
  rejected: "bg-red-500/20 text-red-300 border-red-500/40",
  deferred: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  auto_approved: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  expired: "bg-zinc-500/20 text-zinc-400 border-zinc-500/40",
};

function timeAgo(dateStr: string | null | undefined): string {
  if (!dateStr) return "—";
  const ms = Date.now() - new Date(dateStr).getTime();
  if (ms < 60_000) return "just now";
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return `${Math.floor(ms / 86_400_000)}d ago`;
}

// ─── Main Component ─────────────────────────────────────────────────────────

export default function ReviewQueue() {

  const [statusFilter, setStatusFilter] = useState<string>("pending");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [detailItem, setDetailItem] = useState<any | null>(null);
  const [reviewNotes, setReviewNotes] = useState("");
  const [rejectDialogId, setRejectDialogId] = useState<number | null>(null);
  const [rejectReason, setRejectReason] = useState("");

  const utils = trpc.useUtils();

  // Real-time WebSocket events — auto-refresh on new review items
  const { events: wsEvents, lastEvent } = useReviewQueueEvents();
  useEffect(() => {
    if (lastEvent) {
      utils.reviewQueue.list.invalidate();
      utils.reviewQueue.stats.invalidate();
    }
  }, [lastEvent]);

  const { data: items, isLoading } = trpc.reviewQueue.list.useQuery({
    status: statusFilter as any,
    category: categoryFilter as any,
    limit: 100,
  });

  const { data: stats } = trpc.reviewQueue.stats.useQuery();

  const approveMut = trpc.reviewQueue.approve.useMutation({
    onSuccess: () => {
      toast.success("Item approved and queued for execution.");
      utils.reviewQueue.list.invalidate();
      utils.reviewQueue.stats.invalidate();
    },
  });

  const rejectMut = trpc.reviewQueue.reject.useMutation({
    onSuccess: () => {
      toast.success("Item rejected with notes.");
      utils.reviewQueue.list.invalidate();
      utils.reviewQueue.stats.invalidate();
      setRejectDialogId(null);
      setRejectReason("");
    },
  });

  const deferMut = trpc.reviewQueue.defer.useMutation({
    onSuccess: () => {
      toast.success("Item deferred for later review.");
      utils.reviewQueue.list.invalidate();
      utils.reviewQueue.stats.invalidate();
    },
  });

  const bulkApproveMut = trpc.reviewQueue.bulkApprove.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.approvedCount} items approved.`);
      setSelectedIds([]);
      utils.reviewQueue.list.invalidate();
      utils.reviewQueue.stats.invalidate();
    },
  });

  const toggleSelect = (id: number) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  const selectAll = () => {
    if (!items?.items) return;
    const allIds = items.items.map((i: any) => i.id);
    setSelectedIds((prev) => (prev.length === allIds.length ? [] : allIds));
  };

  return (
    <AppShell activePath="/review-queue">
      <div className="space-y-6 p-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <ClipboardCheck className="w-6 h-6 text-amber-400" />
              Review Queue
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Tier 2 LLM-Assisted Approval Workflow — Review and approve AI-generated plans before execution
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              utils.reviewQueue.list.invalidate();
              utils.reviewQueue.stats.invalidate();
            }}
          >
            <RefreshCw className="w-4 h-4 mr-1" /> Refresh
          </Button>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            { label: "Pending", value: stats?.pending ?? 0, color: "text-amber-400", icon: Clock },
            { label: "Approved", value: stats?.approved ?? 0, color: "text-green-400", icon: CheckCircle2 },
            { label: "Rejected", value: stats?.rejected ?? 0, color: "text-red-400", icon: XCircle },
            { label: "Deferred", value: stats?.deferred ?? 0, color: "text-blue-400", icon: Clock },
            { label: "Auto-Approved", value: stats?.auto_approved ?? 0, color: "text-emerald-400", icon: Zap },
            { label: "Expired", value: stats?.expired ?? 0, color: "text-zinc-400", icon: AlertTriangle },
          ].map((s) => (
            <Card key={s.label} className="bg-card/50 border-border/50">
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <s.icon className={`w-4 h-4 ${s.color}`} />
                  <span className="text-xs text-muted-foreground uppercase tracking-wider">{s.label}</span>
                </div>
                <p className={`text-2xl font-bold mt-1 ${s.color}`}>{s.value}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Filters & Bulk Actions */}
        <div className="flex items-center gap-3 flex-wrap">
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Statuses</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="approved">Approved</SelectItem>
              <SelectItem value="rejected">Rejected</SelectItem>
              <SelectItem value="deferred">Deferred</SelectItem>
              <SelectItem value="auto_approved">Auto-Approved</SelectItem>
              <SelectItem value="expired">Expired</SelectItem>
            </SelectContent>
          </Select>

          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Category" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Categories</SelectItem>
              {Object.entries(CATEGORY_LABELS).map(([key, val]) => (
                <SelectItem key={key} value={key}>{val.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>

          {selectedIds.length > 0 && statusFilter === "pending" && (
            <Button
              variant="default"
              size="sm"
              className="bg-green-600 hover:bg-green-700"
              onClick={() => bulkApproveMut.mutate({ ids: selectedIds })}
              disabled={bulkApproveMut.isPending}
            >
              <CheckCircle2 className="w-4 h-4 mr-1" />
              Approve {selectedIds.length} Selected
            </Button>
          )}

          <span className="text-sm text-muted-foreground ml-auto">
            {items?.total ?? 0} items total
          </span>
        </div>

        {/* Queue Table */}
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="border-border/50">
                  {statusFilter === "pending" && (
                    <TableHead className="w-10">
                      <input
                        type="checkbox"
                        checked={selectedIds.length === (items?.items?.length ?? 0) && selectedIds.length > 0}
                        onChange={selectAll}
                        className="rounded border-border"
                      />
                    </TableHead>
                  )}
                  <TableHead>Category</TableHead>
                  <TableHead className="min-w-[300px]">Title</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-12 text-muted-foreground">
                      Loading review queue...
                    </TableCell>
                  </TableRow>
                ) : !items?.items?.length ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-12">
                      <div className="space-y-2">
                        <ClipboardCheck className="w-10 h-10 text-muted-foreground/40 mx-auto" />
                        <p className="text-muted-foreground">No items in queue</p>
                        <p className="text-xs text-muted-foreground/60">
                          LLM-generated plans will appear here for review
                        </p>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  items.items.map((item: any) => {
                    const cat = CATEGORY_LABELS[item.category] || { label: item.category, icon: FileText, color: "bg-zinc-500/10 text-zinc-400" };
                    const CatIcon = cat.icon;
                    return (
                      <TableRow key={item.id} className="border-border/30 hover:bg-muted/30">
                        {statusFilter === "pending" && (
                          <TableCell>
                            <input
                              type="checkbox"
                              checked={selectedIds.includes(item.id)}
                              onChange={() => toggleSelect(item.id)}
                              className="rounded border-border"
                            />
                          </TableCell>
                        )}
                        <TableCell>
                          <Badge variant="outline" className={cat.color}>
                            <CatIcon className="w-3 h-3 mr-1" />
                            {cat.label}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <button
                            onClick={() => setDetailItem(item)}
                            className="text-left hover:text-foreground transition-colors"
                          >
                            <p className="font-medium text-sm line-clamp-1">{item.title}</p>
                            <p className="text-xs text-muted-foreground line-clamp-1 mt-0.5">{item.summary}</p>
                          </button>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={RISK_COLORS[item.riskLevel] || ""}>
                            {item.riskLevel?.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {item.llmConfidence ? (
                            <span className={`text-sm font-mono ${
                              Number(item.llmConfidence) >= 90 ? "text-green-400" :
                              Number(item.llmConfidence) >= 70 ? "text-yellow-400" : "text-red-400"
                            }`}>
                              {Number(item.llmConfidence).toFixed(0)}%
                            </span>
                          ) : (
                            <span className="text-muted-foreground text-xs">—</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={STATUS_COLORS[item.rqStatus] || ""}>
                            {item.rqStatus?.replace("_", " ")}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {timeAgo(item.createdAt)}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setDetailItem(item)}
                              className="h-7 px-2"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </Button>
                            {(item.rqStatus === "pending" || item.rqStatus === "deferred") && (
                              <>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-7 px-2 text-green-400 hover:text-green-300 hover:bg-green-500/10"
                                  onClick={() => approveMut.mutate({ id: item.id })}
                                  disabled={approveMut.isPending}
                                >
                                  <CheckCircle2 className="w-3.5 h-3.5" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-7 px-2 text-red-400 hover:text-red-300 hover:bg-red-500/10"
                                  onClick={() => { setRejectDialogId(item.id); setRejectReason(""); }}
                                >
                                  <XCircle className="w-3.5 h-3.5" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-7 px-2 text-blue-400 hover:text-blue-300 hover:bg-blue-500/10"
                                  onClick={() => deferMut.mutate({ id: item.id })}
                                  disabled={deferMut.isPending}
                                >
                                  <Clock className="w-3.5 h-3.5" />
                                </Button>
                              </>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Detail Dialog */}
        <Dialog open={!!detailItem} onOpenChange={() => setDetailItem(null)}>
          <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                {detailItem && CATEGORY_LABELS[detailItem.category] && (
                  <Badge variant="outline" className={CATEGORY_LABELS[detailItem.category].color}>
                    {CATEGORY_LABELS[detailItem.category].label}
                  </Badge>
                )}
                {detailItem?.title}
              </DialogTitle>
            </DialogHeader>
            {detailItem && (
              <div className="space-y-4">
                <div className="flex gap-2">
                  <Badge variant="outline" className={RISK_COLORS[detailItem.riskLevel] || ""}>
                    Risk: {detailItem.riskLevel?.toUpperCase()}
                  </Badge>
                  <Badge variant="outline" className={STATUS_COLORS[detailItem.rqStatus] || ""}>
                    {detailItem.rqStatus?.replace("_", " ")}
                  </Badge>
                  {detailItem.llmConfidence && (
                    <Badge variant="outline">
                      Confidence: {Number(detailItem.llmConfidence).toFixed(0)}%
                    </Badge>
                  )}
                  {detailItem.autoApproveEligible === 1 && (
                    <Badge variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                      Auto-Approve Eligible
                    </Badge>
                  )}
                </div>

                <div>
                  <h4 className="text-sm font-semibold text-muted-foreground mb-1">Summary</h4>
                  <p className="text-sm">{detailItem.summary}</p>
                </div>

                {detailItem.llmRationale && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-1">LLM Rationale</h4>
                    <div className="bg-muted/30 rounded-lg p-3 text-sm whitespace-pre-wrap">
                      {detailItem.llmRationale}
                    </div>
                  </div>
                )}

                <div>
                  <h4 className="text-sm font-semibold text-muted-foreground mb-1">Payload</h4>
                  <pre className="bg-muted/30 rounded-lg p-3 text-xs overflow-x-auto max-h-60">
                    {JSON.stringify(detailItem.payloadJson, null, 2)}
                  </pre>
                </div>

                {detailItem.reviewNotes && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-1">Review Notes</h4>
                    <p className="text-sm">{detailItem.reviewNotes}</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Reviewed by {detailItem.reviewedBy} — {detailItem.reviewedAt ? new Date(detailItem.reviewedAt).toLocaleString() : ""}
                    </p>
                  </div>
                )}

                {(detailItem.rqStatus === "pending" || detailItem.rqStatus === "deferred") && (
                  <div className="space-y-3">
                    <Textarea
                      placeholder="Optional review notes..."
                      value={reviewNotes}
                      onChange={(e) => setReviewNotes(e.target.value)}
                      rows={2}
                    />
                    <div className="flex gap-2">
                      <Button
                        className="bg-green-600 hover:bg-green-700"
                        onClick={() => {
                          approveMut.mutate({ id: detailItem.id, notes: reviewNotes || undefined });
                          setDetailItem(null);
                          setReviewNotes("");
                        }}
                        disabled={approveMut.isPending}
                      >
                        <CheckCircle2 className="w-4 h-4 mr-1" /> Approve
                      </Button>
                      <Button
                        variant="destructive"
                        onClick={() => {
                          if (!reviewNotes.trim()) {
                            toast.error("Please provide a rejection reason.");
                            return;
                          }
                          rejectMut.mutate({ id: detailItem.id, notes: reviewNotes });
                          setDetailItem(null);
                          setReviewNotes("");
                        }}
                        disabled={rejectMut.isPending}
                      >
                        <XCircle className="w-4 h-4 mr-1" /> Reject
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => {
                          deferMut.mutate({ id: detailItem.id, notes: reviewNotes || undefined });
                          setDetailItem(null);
                          setReviewNotes("");
                        }}
                        disabled={deferMut.isPending}
                      >
                        <Clock className="w-4 h-4 mr-1" /> Defer
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* Reject Dialog */}
        <Dialog open={rejectDialogId !== null} onOpenChange={() => setRejectDialogId(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Reject Review Item</DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Provide a reason for rejecting this item. This will be recorded in the audit trail.
              </p>
              <Textarea
                placeholder="Rejection reason (required)..."
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                rows={3}
              />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setRejectDialogId(null)}>Cancel</Button>
              <Button
                variant="destructive"
                onClick={() => {
                  if (!rejectReason.trim()) {
                    toast.error("Rejection reason is required.");
                    return;
                  }
                  rejectMut.mutate({ id: rejectDialogId!, notes: rejectReason });
                }}
                disabled={rejectMut.isPending}
              >
                <XCircle className="w-4 h-4 mr-1" /> Reject
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </AppShell>
  );
}
