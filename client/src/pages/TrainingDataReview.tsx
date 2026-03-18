import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
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
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import {
  CheckCircle2,
  XCircle,
  Flag,
  RotateCcw,
  Download,
  FileJson,
  Eye,
  ChevronLeft,
  ChevronRight,
  Sparkles,
  Filter,
  CheckCheck,
  BarChart3,
  Loader2,
} from "lucide-react";

// ─── Review Status Badge ────────────────────────────────────────────────────
function ReviewBadge({ status }: { status: string }) {
  const config: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "outline" }> = {
    pending_review: { label: "Pending", variant: "outline" },
    approved: { label: "Approved", variant: "default" },
    rejected: { label: "Rejected", variant: "destructive" },
    flagged: { label: "Flagged", variant: "secondary" },
  };
  const c = config[status] || config.pending_review;
  return <Badge variant={c.variant}>{c.label}</Badge>;
}

function QualityBadge({ quality, score }: { quality: string; score: number }) {
  const colors: Record<string, string> = {
    high: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    low: "bg-red-500/15 text-red-400 border-red-500/30",
    rejected: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  };
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border ${colors[quality] || colors.low}`}>
      {quality} ({(score * 100).toFixed(0)}%)
    </span>
  );
}

// ─── Message Preview ────────────────────────────────────────────────────────
function MessagePreview({ messages }: { messages: any[] }) {
  if (!messages || !Array.isArray(messages)) return <span className="text-muted-foreground text-xs">No messages</span>;
  return (
    <div className="space-y-2 max-h-80 overflow-y-auto">
      {messages.map((msg: any, i: number) => (
        <div key={i} className={`rounded-lg p-3 text-sm ${
          msg.role === "system" ? "bg-purple-500/10 border border-purple-500/20" :
          msg.role === "assistant" ? "bg-blue-500/10 border border-blue-500/20" :
          "bg-zinc-500/10 border border-zinc-500/20"
        }`}>
          <div className="text-xs font-semibold mb-1 uppercase tracking-wider opacity-60">{msg.role}</div>
          <div className="whitespace-pre-wrap text-xs leading-relaxed font-mono">{
            typeof msg.content === "string" ? msg.content.slice(0, 500) + (msg.content.length > 500 ? "..." : "") : JSON.stringify(msg.content).slice(0, 500)
          }</div>
        </div>
      ))}
    </div>
  );
}

// ─── Stats Cards ────────────────────────────────────────────────────────────
function StatsCards({ data }: { data: any }) {
  if (!data) return null;
  const s = data.summary;
  const cards = [
    { label: "Total Examples", value: s.total, icon: BarChart3, color: "text-blue-400" },
    { label: "Pending Review", value: s.pendingReview, icon: Eye, color: "text-amber-400" },
    { label: "Approved", value: s.approved, icon: CheckCircle2, color: "text-emerald-400" },
    { label: "Rejected", value: s.rejected, icon: XCircle, color: "text-red-400" },
    { label: "Flagged", value: s.flagged, icon: Flag, color: "text-orange-400" },
    { label: "Review Progress", value: `${s.reviewProgress}%`, icon: Sparkles, color: "text-purple-400" },
  ];
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((c) => (
        <Card key={c.label} className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-1">
              <c.icon className={`h-4 w-4 ${c.color}`} />
              <span className="text-xs text-muted-foreground">{c.label}</span>
            </div>
            <div className="text-2xl font-bold">{c.value}</div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Model Progress Table ───────────────────────────────────────────────────
function ModelProgressTable({ data }: { data: any[] }) {
  if (!data?.length) return null;
  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm">Review Progress by Model</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 text-xs text-muted-foreground">
                <th className="text-left py-2 pr-4">Model</th>
                <th className="text-right py-2 px-2">Total</th>
                <th className="text-right py-2 px-2">Approved</th>
                <th className="text-right py-2 px-2">Rejected</th>
                <th className="text-right py-2 px-2">Pending</th>
                <th className="text-right py-2 px-2">Avg Score</th>
                <th className="text-right py-2 pl-2">Progress</th>
              </tr>
            </thead>
            <tbody>
              {data.map((m) => (
                <tr key={m.model} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                  <td className="py-2 pr-4 font-mono text-xs">{m.model}</td>
                  <td className="text-right py-2 px-2">{m.total}</td>
                  <td className="text-right py-2 px-2 text-emerald-400">{m.approved}</td>
                  <td className="text-right py-2 px-2 text-red-400">{m.rejected}</td>
                  <td className="text-right py-2 px-2 text-amber-400">{m.pending}</td>
                  <td className="text-right py-2 px-2">{m.avgScore}</td>
                  <td className="text-right py-2 pl-2">
                    <div className="flex items-center justify-end gap-2">
                      <div className="w-16 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                        <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${m.reviewProgress}%` }} />
                      </div>
                      <span className="text-xs text-muted-foreground w-10 text-right">{m.reviewProgress}%</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Export Panel ────────────────────────────────────────────────────────────
function ExportPanel() {
  const { toast } = useToast();
  const [format, setFormat] = useState<"openai_chat" | "anthropic" | "raw">("openai_chat");
  const [reviewFilter, setReviewFilter] = useState<"approved" | "pending_review" | "all">("approved");
  const [qualityFilter, setQualityFilter] = useState<"high" | "medium" | "low" | "all">("all");
  const [sourceFilter, setSourceFilter] = useState<"lab_scenario" | "live_engagement" | "manual" | "synthetic" | "all">("all");
  const [minScore, setMinScore] = useState<string>("");
  const [modelFilter, setModelFilter] = useState("");

  const previewInput = useMemo(() => ({
    reviewStatus: reviewFilter,
    quality: qualityFilter,
    source: sourceFilter,
    minScore: minScore ? parseFloat(minScore) : undefined,
    model: modelFilter || undefined,
  }), [reviewFilter, qualityFilter, sourceFilter, minScore, modelFilter]);

  const preview = trpc.trainingReview.getExportPreview.useQuery(previewInput);

  const exportQuery = trpc.trainingReview.exportJsonl.useQuery(
    {
      format,
      reviewStatus: reviewFilter,
      quality: qualityFilter,
      source: sourceFilter,
      minScore: minScore ? parseFloat(minScore) : undefined,
      model: modelFilter || undefined,
      limit: 5000,
    },
    { enabled: false }
  );

  const handleExport = useCallback(async () => {
    try {
      const result = await exportQuery.refetch();
      if (result.data) {
        const blob = new Blob([result.data.jsonl], { type: "application/jsonl" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = result.data.filename;
        a.click();
        URL.revokeObjectURL(url);
        toast({
          title: "Export Complete",
          description: `Downloaded ${result.data.metadata.exampleCount} examples as ${format} JSONL`,
        });
      }
    } catch (err) {
      toast({ title: "Export Failed", description: String(err), variant: "destructive" });
    }
  }, [exportQuery, format, toast]);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Format</label>
          <Select value={format} onValueChange={(v: any) => setFormat(v)}>
            <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="openai_chat">OpenAI Chat</SelectItem>
              <SelectItem value="anthropic">Anthropic</SelectItem>
              <SelectItem value="raw">Raw JSONL</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Review Status</label>
          <Select value={reviewFilter} onValueChange={(v: any) => setReviewFilter(v)}>
            <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="approved">Approved Only</SelectItem>
              <SelectItem value="pending_review">Pending Review</SelectItem>
              <SelectItem value="all">All</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Quality</label>
          <Select value={qualityFilter} onValueChange={(v: any) => setQualityFilter(v)}>
            <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Quality</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Source</label>
          <Select value={sourceFilter} onValueChange={(v: any) => setSourceFilter(v)}>
            <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Sources</SelectItem>
              <SelectItem value="lab_scenario">Lab Scenario</SelectItem>
              <SelectItem value="live_engagement">Live Engagement</SelectItem>
              <SelectItem value="manual">Manual</SelectItem>
              <SelectItem value="synthetic">Synthetic</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Min Score</label>
          <Input
            type="number"
            min={0}
            max={1}
            step={0.05}
            placeholder="0.00"
            value={minScore}
            onChange={(e) => setMinScore(e.target.value)}
            className="h-9"
          />
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Model Filter</label>
          <Input
            placeholder="e.g. recon-v2"
            value={modelFilter}
            onChange={(e) => setModelFilter(e.target.value)}
            className="h-9"
          />
        </div>
      </div>

      {preview.data && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-6">
                <div>
                  <div className="text-xs text-muted-foreground">Examples to Export</div>
                  <div className="text-2xl font-bold">{preview.data.totalExamples}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">Avg Quality</div>
                  <div className="text-2xl font-bold">{preview.data.avgQualityScore}</div>
                </div>
                <div className="flex gap-2">
                  <span className="text-xs px-2 py-1 rounded bg-emerald-500/15 text-emerald-400">{preview.data.qualityBreakdown.high} high</span>
                  <span className="text-xs px-2 py-1 rounded bg-amber-500/15 text-amber-400">{preview.data.qualityBreakdown.medium} med</span>
                  <span className="text-xs px-2 py-1 rounded bg-red-500/15 text-red-400">{preview.data.qualityBreakdown.low} low</span>
                </div>
              </div>
              <Button onClick={handleExport} disabled={exportQuery.isFetching || !preview.data.totalExamples} className="gap-2">
                {exportQuery.isFetching ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                Export JSONL
              </Button>
            </div>
            {preview.data.modelBreakdown.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-2">
                {preview.data.modelBreakdown.map((m: any) => (
                  <span key={m.model} className="text-xs px-2 py-1 rounded bg-zinc-800 text-zinc-300 font-mono">
                    {m.model}: {m.count}
                  </span>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────
export default function TrainingDataReview() {
  const { toast } = useToast();
  const utils = trpc.useUtils();

  // Filters
  const [reviewFilter, setReviewFilter] = useState<"pending_review" | "approved" | "rejected" | "flagged" | "all">("pending_review");
  const [qualityFilter, setQualityFilter] = useState<"high" | "medium" | "low" | "rejected" | "all">("all");
  const [sourceFilter, setSourceFilter] = useState<"lab_scenario" | "live_engagement" | "manual" | "synthetic" | "all">("all");
  const [modelFilter, setModelFilter] = useState("");
  const [page, setPage] = useState(1);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [detailExample, setDetailExample] = useState<any>(null);
  const [reviewNotes, setReviewNotes] = useState("");
  const [autoApproveOpen, setAutoApproveOpen] = useState(false);
  const [autoThreshold, setAutoThreshold] = useState("0.85");

  // Queries
  const overview = trpc.trainingReview.getReviewOverview.useQuery();
  const listInput = useMemo(() => ({
    page,
    pageSize: 25,
    reviewStatus: reviewFilter,
    quality: qualityFilter,
    source: sourceFilter,
    model: modelFilter || undefined,
  }), [page, reviewFilter, qualityFilter, sourceFilter, modelFilter]);
  const list = trpc.trainingReview.listForReview.useQuery(listInput);

  // Mutations
  const reviewMut = trpc.trainingReview.reviewExample.useMutation({
    onSuccess: () => {
      utils.trainingReview.listForReview.invalidate();
      utils.trainingReview.getReviewOverview.invalidate();
      toast({ title: "Review saved" });
    },
  });
  const bulkMut = trpc.trainingReview.bulkReview.useMutation({
    onSuccess: (data) => {
      setSelectedIds(new Set());
      utils.trainingReview.listForReview.invalidate();
      utils.trainingReview.getReviewOverview.invalidate();
      toast({ title: `Bulk action complete`, description: `${data.processed} examples updated to ${data.newStatus}` });
    },
  });
  const autoApproveMut = trpc.trainingReview.autoApproveByThreshold.useMutation({
    onSuccess: (data) => {
      setAutoApproveOpen(false);
      utils.trainingReview.listForReview.invalidate();
      utils.trainingReview.getReviewOverview.invalidate();
      toast({ title: "Auto-approve complete", description: `${data.approvedCount} examples approved` });
    },
  });

  const handleReview = useCallback((exampleId: string, action: "approve" | "reject" | "flag" | "reset") => {
    reviewMut.mutate({ exampleId, action, notes: reviewNotes || undefined });
    setReviewNotes("");
    setDetailExample(null);
  }, [reviewMut, reviewNotes]);

  const handleBulk = useCallback((action: "approve" | "reject" | "flag" | "reset") => {
    if (selectedIds.size === 0) return;
    bulkMut.mutate({ exampleIds: Array.from(selectedIds), action });
  }, [bulkMut, selectedIds]);

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const toggleSelectAll = useCallback(() => {
    if (!list.data?.rows) return;
    const allIds = list.data.rows.map((r: any) => r.exampleId);
    const allSelected = allIds.every((id: string) => selectedIds.has(id));
    if (allSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(allIds));
    }
  }, [list.data, selectedIds]);

  return (
    <div className="space-y-6 p-1">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Training Data Review</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Review, approve, and export curated training examples for LLM fine-tuning
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setAutoApproveOpen(true)} className="gap-2">
            <Sparkles className="h-4 w-4" /> Auto-Approve
          </Button>
        </div>
      </div>

      {/* Stats */}
      <StatsCards data={overview.data} />

      <Tabs defaultValue="review" className="space-y-4">
        <TabsList className="bg-zinc-900 border border-zinc-800">
          <TabsTrigger value="review" className="gap-2"><Eye className="h-4 w-4" /> Review Queue</TabsTrigger>
          <TabsTrigger value="progress" className="gap-2"><BarChart3 className="h-4 w-4" /> Progress</TabsTrigger>
          <TabsTrigger value="export" className="gap-2"><FileJson className="h-4 w-4" /> JSONL Export</TabsTrigger>
        </TabsList>

        {/* ─── Review Queue Tab ─────────────────────────────────────────── */}
        <TabsContent value="review" className="space-y-4">
          {/* Filters */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-4">
              <div className="flex flex-wrap items-end gap-3">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Status</label>
                  <Select value={reviewFilter} onValueChange={(v: any) => { setReviewFilter(v); setPage(1); }}>
                    <SelectTrigger className="h-9 w-36"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="pending_review">Pending</SelectItem>
                      <SelectItem value="approved">Approved</SelectItem>
                      <SelectItem value="rejected">Rejected</SelectItem>
                      <SelectItem value="flagged">Flagged</SelectItem>
                      <SelectItem value="all">All</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Quality</label>
                  <Select value={qualityFilter} onValueChange={(v: any) => { setQualityFilter(v); setPage(1); }}>
                    <SelectTrigger className="h-9 w-28"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Source</label>
                  <Select value={sourceFilter} onValueChange={(v: any) => { setSourceFilter(v); setPage(1); }}>
                    <SelectTrigger className="h-9 w-36"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Sources</SelectItem>
                      <SelectItem value="lab_scenario">Lab Scenario</SelectItem>
                      <SelectItem value="live_engagement">Live Engagement</SelectItem>
                      <SelectItem value="manual">Manual</SelectItem>
                      <SelectItem value="synthetic">Synthetic</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Model</label>
                  <Input placeholder="Filter model..." value={modelFilter} onChange={(e) => { setModelFilter(e.target.value); setPage(1); }} className="h-9 w-40" />
                </div>
                {selectedIds.size > 0 && (
                  <div className="flex items-center gap-2 ml-auto">
                    <span className="text-xs text-muted-foreground">{selectedIds.size} selected</span>
                    <Button size="sm" variant="outline" onClick={() => handleBulk("approve")} className="h-8 gap-1 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/10">
                      <CheckCircle2 className="h-3.5 w-3.5" /> Approve
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => handleBulk("reject")} className="h-8 gap-1 text-red-400 border-red-500/30 hover:bg-red-500/10">
                      <XCircle className="h-3.5 w-3.5" /> Reject
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => handleBulk("flag")} className="h-8 gap-1 text-orange-400 border-orange-500/30 hover:bg-orange-500/10">
                      <Flag className="h-3.5 w-3.5" /> Flag
                    </Button>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Table */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-zinc-800 text-xs text-muted-foreground">
                      <th className="text-left p-3 w-8">
                        <input type="checkbox" className="rounded" onChange={toggleSelectAll} checked={list.data?.rows?.length ? list.data.rows.every((r: any) => selectedIds.has(r.exampleId)) : false} />
                      </th>
                      <th className="text-left p-3">Model</th>
                      <th className="text-left p-3">Source</th>
                      <th className="text-left p-3">Quality</th>
                      <th className="text-left p-3">Status</th>
                      <th className="text-left p-3">Preview</th>
                      <th className="text-left p-3">Reviewer</th>
                      <th className="text-right p-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.isLoading ? (
                      <tr><td colSpan={8} className="p-8 text-center text-muted-foreground"><Loader2 className="h-5 w-5 animate-spin mx-auto" /></td></tr>
                    ) : !list.data?.rows?.length ? (
                      <tr><td colSpan={8} className="p-8 text-center text-muted-foreground">No examples match filters</td></tr>
                    ) : (
                      list.data.rows.map((row: any) => {
                        const msgs = Array.isArray(row.messages) ? row.messages : [];
                        const firstUser = msgs.find((m: any) => m.role === "user");
                        const preview = firstUser?.content?.slice(0, 80) || "—";
                        return (
                          <tr key={row.exampleId} className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors">
                            <td className="p-3">
                              <input type="checkbox" className="rounded" checked={selectedIds.has(row.exampleId)} onChange={() => toggleSelect(row.exampleId)} />
                            </td>
                            <td className="p-3 font-mono text-xs">{row.model}</td>
                            <td className="p-3">
                              <Badge variant="outline" className="text-xs">{row.source}</Badge>
                            </td>
                            <td className="p-3"><QualityBadge quality={row.quality} score={row.qualityScore} /></td>
                            <td className="p-3"><ReviewBadge status={row.reviewStatus} /></td>
                            <td className="p-3 max-w-xs truncate text-xs text-muted-foreground cursor-pointer hover:text-foreground" onClick={() => setDetailExample(row)}>
                              {preview}
                            </td>
                            <td className="p-3 text-xs text-muted-foreground">{row.reviewedBy || "—"}</td>
                            <td className="p-3">
                              <div className="flex items-center justify-end gap-1">
                                <Button size="icon" variant="ghost" className="h-7 w-7 text-emerald-400 hover:bg-emerald-500/10" onClick={() => handleReview(row.exampleId, "approve")} title="Approve">
                                  <CheckCircle2 className="h-4 w-4" />
                                </Button>
                                <Button size="icon" variant="ghost" className="h-7 w-7 text-red-400 hover:bg-red-500/10" onClick={() => handleReview(row.exampleId, "reject")} title="Reject">
                                  <XCircle className="h-4 w-4" />
                                </Button>
                                <Button size="icon" variant="ghost" className="h-7 w-7 text-orange-400 hover:bg-orange-500/10" onClick={() => handleReview(row.exampleId, "flag")} title="Flag">
                                  <Flag className="h-4 w-4" />
                                </Button>
                                <Button size="icon" variant="ghost" className="h-7 w-7 text-blue-400 hover:bg-blue-500/10" onClick={() => setDetailExample(row)} title="View">
                                  <Eye className="h-4 w-4" />
                                </Button>
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
              {/* Pagination */}
              {list.data && list.data.totalPages > 1 && (
                <div className="flex items-center justify-between p-3 border-t border-zinc-800">
                  <span className="text-xs text-muted-foreground">
                    Page {list.data.page} of {list.data.totalPages} ({list.data.total} total)
                  </span>
                  <div className="flex gap-1">
                    <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage(p => p - 1)} className="h-8">
                      <ChevronLeft className="h-4 w-4" />
                    </Button>
                    <Button size="sm" variant="outline" disabled={page >= list.data.totalPages} onClick={() => setPage(p => p + 1)} className="h-8">
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─── Progress Tab ─────────────────────────────────────────────── */}
        <TabsContent value="progress" className="space-y-4">
          <ModelProgressTable data={overview.data?.modelProgress || []} />
          {overview.data?.sourceProgress && (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Review Progress by Source</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {overview.data.sourceProgress.map((s: any) => (
                    <div key={s.source} className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/50">
                      <div className="text-xs text-muted-foreground mb-1">{s.source.replace(/_/g, " ")}</div>
                      <div className="text-lg font-bold">{s.total}</div>
                      <div className="flex gap-2 mt-1 text-xs">
                        <span className="text-emerald-400">{s.approved} approved</span>
                        <span className="text-red-400">{s.rejected} rejected</span>
                      </div>
                      <div className="w-full h-1.5 bg-zinc-700 rounded-full mt-2 overflow-hidden">
                        <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${s.total ? ((s.approved / s.total) * 100) : 0}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ─── Export Tab ───────────────────────────────────────────────── */}
        <TabsContent value="export" className="space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><FileJson className="h-5 w-5 text-blue-400" /> JSONL Export for Fine-Tuning</CardTitle>
              <CardDescription>Export curated training examples in OpenAI, Anthropic, or raw JSONL format for fine-tuning pipelines</CardDescription>
            </CardHeader>
            <CardContent>
              <ExportPanel />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* ─── Detail Dialog ───────────────────────────────────────────────── */}
      <Dialog open={!!detailExample} onOpenChange={() => { setDetailExample(null); setReviewNotes(""); }}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          {detailExample && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-3">
                  <span className="font-mono text-sm">{detailExample.model}</span>
                  <QualityBadge quality={detailExample.quality} score={detailExample.qualityScore} />
                  <ReviewBadge status={detailExample.reviewStatus} />
                </DialogTitle>
                <DialogDescription>
                  Example ID: {detailExample.exampleId} | Source: {detailExample.source} | Created: {detailExample.createdAt}
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <MessagePreview messages={detailExample.messages as any[]} />
                {detailExample.metadata && (
                  <div className="rounded-lg bg-zinc-800/50 p-3">
                    <div className="text-xs font-semibold mb-1 text-muted-foreground">Metadata</div>
                    <pre className="text-xs font-mono whitespace-pre-wrap max-h-32 overflow-y-auto">
                      {JSON.stringify(detailExample.metadata, null, 2)}
                    </pre>
                  </div>
                )}
                {detailExample.reviewNotes && (
                  <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-3">
                    <div className="text-xs font-semibold mb-1 text-amber-400">Previous Review Notes</div>
                    <p className="text-sm">{detailExample.reviewNotes}</p>
                  </div>
                )}
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Review Notes (optional)</label>
                  <Textarea
                    placeholder="Add notes about this example..."
                    value={reviewNotes}
                    onChange={(e) => setReviewNotes(e.target.value)}
                    rows={2}
                  />
                </div>
              </div>
              <DialogFooter className="flex gap-2">
                <Button variant="outline" onClick={() => handleReview(detailExample.exampleId, "reset")} className="gap-1">
                  <RotateCcw className="h-4 w-4" /> Reset
                </Button>
                <Button variant="outline" onClick={() => handleReview(detailExample.exampleId, "flag")} className="gap-1 text-orange-400 border-orange-500/30 hover:bg-orange-500/10">
                  <Flag className="h-4 w-4" /> Flag
                </Button>
                <Button variant="outline" onClick={() => handleReview(detailExample.exampleId, "reject")} className="gap-1 text-red-400 border-red-500/30 hover:bg-red-500/10">
                  <XCircle className="h-4 w-4" /> Reject
                </Button>
                <Button onClick={() => handleReview(detailExample.exampleId, "approve")} className="gap-1 bg-emerald-600 hover:bg-emerald-700">
                  <CheckCircle2 className="h-4 w-4" /> Approve
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* ─── Auto-Approve Dialog ─────────────────────────────────────────── */}
      <Dialog open={autoApproveOpen} onOpenChange={setAutoApproveOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><Sparkles className="h-5 w-5 text-purple-400" /> Auto-Approve by Threshold</DialogTitle>
            <DialogDescription>
              Automatically approve all pending examples that meet the quality threshold. This cannot be undone easily.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Minimum Quality Score</label>
              <Input
                type="number"
                min={0}
                max={1}
                step={0.05}
                value={autoThreshold}
                onChange={(e) => setAutoThreshold(e.target.value)}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Examples with quality score &ge; {autoThreshold} and status "pending_review" will be auto-approved.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAutoApproveOpen(false)}>Cancel</Button>
            <Button
              onClick={() => autoApproveMut.mutate({ minQualityScore: parseFloat(autoThreshold) || 0.85 })}
              disabled={autoApproveMut.isPending}
              className="gap-2 bg-purple-600 hover:bg-purple-700"
            >
              {autoApproveMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCheck className="h-4 w-4" />}
              Auto-Approve
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
