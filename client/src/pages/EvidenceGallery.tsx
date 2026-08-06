import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Camera, Download, RefreshCw, Eye, Shield, Server,
  Activity, Crosshair, Filter, Image, FileText, Clock,
  ChevronLeft, ChevronRight, Loader2, AlertTriangle,
  Layers, Network, Cpu, Zap,
} from "lucide-react";

// ─── Panel type config ─────────────────────────────────────────────────
const PANEL_ICONS: Record<string, typeof Camera> = {
  agentTable: Server,
  operationTimeline: Activity,
  adversaryProfile: Crosshair,
  attackChainSummary: Zap,
};

const PANEL_COLORS: Record<string, string> = {
  agentTable: "bg-red-500/10 text-red-400 border-red-500/30",
  operationTimeline: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  adversaryProfile: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  attackChainSummary: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
};

const PANEL_LABELS: Record<string, string> = {
  agentTable: "C2 Agent Check-Ins",
  operationTimeline: "Operation Timeline",
  adversaryProfile: "Adversary Profile",
  attackChainSummary: "Attack Chain Summary",
};

const PHASE_OPTIONS = [
  { value: "all", label: "All Phases" },
  { value: "exploitation", label: "Exploitation" },
  { value: "post-exploitation", label: "Post-Exploitation" },
];

const PANEL_OPTIONS = [
  { value: "all", label: "All Types" },
  { value: "agentTable", label: "Agent Check-Ins" },
  { value: "operationTimeline", label: "Operation Timeline" },
  { value: "adversaryProfile", label: "Adversary Profile" },
  { value: "attackChainSummary", label: "Attack Chain" },
];

export default function EvidenceGallery() {
  // ─── Filters ───
  const [selectedEngagement, setSelectedEngagement] = useState<string>("all");
  const [selectedPhase, setSelectedPhase] = useState<string>("all");
  const [selectedPanel, setSelectedPanel] = useState<string>("all");
  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 12;

  // ─── Dialogs ───
  const [previewItem, setPreviewItem] = useState<any>(null);
  const [captureEngId, setCaptureEngId] = useState<number | null>(null);
  const [captureDialogOpen, setCaptureDialogOpen] = useState(false);

  // ─── Queries ───
  const engagementsQuery = trpc.evidenceGallery.engagementsWithEvidence.useQuery();
  const statsQuery = trpc.evidenceGallery.galleryStats.useQuery(
    selectedEngagement !== "all" ? { engagementId: selectedEngagement } : undefined
  );
  const galleryQuery = trpc.evidenceGallery.gallery.useQuery({
    engagementId: selectedEngagement !== "all" ? selectedEngagement : undefined,
    phase: selectedPhase as any,
    panelType: selectedPanel as any,
    agentPaw: selectedAgent || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  // ─── Mutations ───
  const captureMutation = trpc.evidenceGallery.captureEvidence.useMutation({
    onSuccess: (data) => {
      toast.success(`Captured ${data.itemsCreated} evidence panels (${data.snapshot.agentCount} agents)`);
      galleryQuery.refetch();
      statsQuery.refetch();
      engagementsQuery.refetch();
      setCaptureDialogOpen(false);
    },
    onError: (err) => toast.error(`Capture failed: ${err.message}`),
  });

  const exportMutation = trpc.evidenceGallery.exportPng.useMutation({
    onSuccess: (data) => {
      toast.success(`Exported as ${data.format.toUpperCase()} (${(data.size / 1024).toFixed(1)} KB)`);
      window.open(data.url, "_blank");
    },
    onError: (err) => toast.error(`Export failed: ${err.message}`),
  });

  // ─── Derived data ───
  const items = galleryQuery.data?.items ?? [];
  const total = galleryQuery.data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  // Extract unique agent PAWs from tags for the agent filter
  const agentPaws = useMemo(() => {
    const paws = new Set<string>();
    for (const item of items) {
      const tags = item.parsedTags || [];
      for (const tag of tags) {
        if (typeof tag === "string" && tag.startsWith("agent:")) {
          paws.add(tag.replace("agent:", ""));
        }
      }
    }
    return Array.from(paws);
  }, [items]);

  // ─── Engagement list for capture dialog ───
  const allEngagementsQuery = trpc.engagements.list.useQuery(
    { limit: 50, offset: 0 },
    { enabled: captureDialogOpen }
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Camera className="h-6 w-6 text-cyan-400" />
            Evidence Gallery
          </h1>
          <p className="text-muted-foreground mt-1">
            Auto-captured Caldera C2 evidence snapshots with source/destination IPs and timestamps
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => { galleryQuery.refetch(); statsQuery.refetch(); }}
          >
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </Button>
          <Button
            size="sm"
            className="bg-cyan-600 hover:bg-cyan-700"
            onClick={() => setCaptureDialogOpen(true)}
          >
            <Camera className="h-4 w-4 mr-1" />
            Capture Evidence
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-cyan-400">{statsQuery.data?.total ?? 0}</div>
            <div className="text-xs text-muted-foreground">Total Evidence</div>
          </CardContent>
        </Card>
        {(statsQuery.data?.byCategory ?? []).map((cat) => {
          const Icon = PANEL_ICONS[cat.category || ""] || FileText;
          return (
            <Card key={cat.category} className="bg-card/50 border-border/50">
              <CardContent className="p-4 text-center">
                <Icon className="h-4 w-4 mx-auto mb-1 text-muted-foreground" />
                <div className="text-xl font-bold">{cat.count}</div>
                <div className="text-xs text-muted-foreground truncate">{cat.label}</div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Filters */}
      <Card className="bg-card/50 border-border/50">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium">Filters</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {/* Engagement filter */}
            <Select value={selectedEngagement} onValueChange={(v) => { setSelectedEngagement(v); setPage(0); }}>
              <SelectTrigger className="h-9">
                <SelectValue placeholder="All Engagements" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Engagements</SelectItem>
                {(engagementsQuery.data ?? []).map((eng) => (
                  <SelectItem key={eng.engagementId} value={eng.engagementId || ""}>
                    {eng.engagementName} ({eng.evidenceCount})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Phase filter */}
            <Select value={selectedPhase} onValueChange={(v) => { setSelectedPhase(v); setPage(0); }}>
              <SelectTrigger className="h-9">
                <SelectValue placeholder="All Phases" />
              </SelectTrigger>
              <SelectContent>
                {PHASE_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Panel type filter */}
            <Select value={selectedPanel} onValueChange={(v) => { setSelectedPanel(v); setPage(0); }}>
              <SelectTrigger className="h-9">
                <SelectValue placeholder="All Types" />
              </SelectTrigger>
              <SelectContent>
                {PANEL_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Agent filter */}
            <Select value={selectedAgent || "all"} onValueChange={(v) => { setSelectedAgent(v === "all" ? "" : v); setPage(0); }}>
              <SelectTrigger className="h-9">
                <SelectValue placeholder="All Agents" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Agents</SelectItem>
                {agentPaws.map((paw) => (
                  <SelectItem key={paw} value={paw}>{paw}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Gallery Grid */}
      {galleryQuery.isLoading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      ) : items.length === 0 ? (
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-12 text-center">
            <Camera className="h-12 w-12 mx-auto mb-4 text-muted-foreground/50" />
            <h3 className="text-lg font-medium mb-2">No Evidence Captured Yet</h3>
            <p className="text-muted-foreground text-sm mb-4">
              Capture Caldera C2 evidence from an active engagement to populate the gallery.
            </p>
            <Button
              className="bg-cyan-600 hover:bg-cyan-700"
              onClick={() => setCaptureDialogOpen(true)}
            >
              <Camera className="h-4 w-4 mr-1" />
              Capture Evidence Now
            </Button>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {items.map((item) => {
              const meta = item.parsedMetadata || {};
              const panelType = meta.panelType || item.category || "unknown";
              const Icon = PANEL_ICONS[panelType] || FileText;
              const colorClass = PANEL_COLORS[panelType] || "bg-gray-500/10 text-gray-400 border-gray-500/30";
              const label = PANEL_LABELS[panelType] || panelType;

              return (
                <Card
                  key={item.evidenceId}
                  className="bg-card/50 border-border/50 hover:border-cyan-500/30 transition-colors cursor-pointer group"
                  onClick={() => setPreviewItem(item)}
                >
                  <CardHeader className="p-4 pb-2">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2">
                        <div className={`p-2 rounded-lg border ${colorClass}`}>
                          <Icon className="h-4 w-4" />
                        </div>
                        <div>
                          <CardTitle className="text-sm font-medium leading-tight">{label}</CardTitle>
                          <p className="text-xs text-muted-foreground mt-0.5 truncate max-w-[200px]">
                            {item.title}
                          </p>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-[10px] shrink-0">
                        {meta.phase || "N/A"}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="p-4 pt-2 space-y-2">
                    {/* Network context */}
                    <div className="space-y-1 text-xs">
                      <div className="flex items-center gap-1.5">
                        <Network className="h-3 w-3 text-red-400" />
                        <span className="text-muted-foreground">C2:</span>
                        <span className="text-red-400 font-mono truncate">{meta.calderaServerUrl || "N/A"}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <Cpu className="h-3 w-3 text-emerald-400" />
                        <span className="text-muted-foreground">Agents:</span>
                        <span className="text-emerald-400 font-bold">{meta.agentCount ?? 0}</span>
                        <span className="text-muted-foreground ml-2">Ops:</span>
                        <span className="text-amber-400 font-bold">{meta.operationCount ?? 0}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <Clock className="h-3 w-3 text-muted-foreground" />
                        <span className="text-muted-foreground">
                          {meta.capturedAt ? new Date(meta.capturedAt).toLocaleString() : "N/A"}
                        </span>
                      </div>
                    </div>

                    {/* Tags */}
                    <div className="flex flex-wrap gap-1">
                      {(item.parsedTags || []).filter((t: string) => t.startsWith("agent:")).slice(0, 3).map((tag: string) => (
                        <Badge key={tag} variant="secondary" className="text-[10px] px-1.5 py-0">
                          {tag}
                        </Badge>
                      ))}
                    </div>

                    {/* Actions */}
                    <div className="flex gap-2 pt-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7 text-xs flex-1"
                        onClick={(e) => { e.stopPropagation(); setPreviewItem(item); }}
                      >
                        <Eye className="h-3 w-3 mr-1" />
                        Preview
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7 text-xs flex-1"
                        onClick={(e) => {
                          e.stopPropagation();
                          exportMutation.mutate({ evidenceId: item.evidenceId });
                        }}
                        disabled={exportMutation.isPending}
                      >
                        {exportMutation.isPending ? (
                          <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                        ) : (
                          <Download className="h-3 w-3 mr-1" />
                        )}
                        Export
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page === 0}
                onClick={() => setPage(p => Math.max(0, p - 1))}
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-sm text-muted-foreground">
                Page {page + 1} of {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages - 1}
                onClick={() => setPage(p => p + 1)}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          )}
        </>
      )}

      {/* Preview Dialog */}
      <Dialog open={!!previewItem} onOpenChange={(open) => { if (!open) setPreviewItem(null); }}>
        <DialogContent className="max-w-4xl max-h-[85vh] overflow-auto">
          {previewItem && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  {(() => {
                    const pt = previewItem.parsedMetadata?.panelType || previewItem.category;
                    const Icon = PANEL_ICONS[pt] || FileText;
                    return <Icon className="h-5 w-5 text-cyan-400" />;
                  })()}
                  {previewItem.title}
                </DialogTitle>
                <DialogDescription>
                  Evidence ID: {previewItem.evidenceId} | Captured: {previewItem.parsedMetadata?.capturedAt ? new Date(previewItem.parsedMetadata.capturedAt).toLocaleString() : "N/A"}
                </DialogDescription>
              </DialogHeader>

              {/* Metadata */}
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground">C2 Server:</span>
                    <span className="text-red-400 font-mono">{previewItem.parsedMetadata?.calderaServerUrl || "N/A"}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground">C2 IP:</span>
                    <span className="text-red-400 font-mono">{previewItem.parsedMetadata?.calderaServerIp || "N/A"}</span>
                  </div>
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground">Agents:</span>
                    <Badge variant="outline">{previewItem.parsedMetadata?.agentCount ?? 0}</Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground">Operations:</span>
                    <Badge variant="outline">{previewItem.parsedMetadata?.operationCount ?? 0}</Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground">Phase:</span>
                    <Badge variant="secondary">{previewItem.parsedMetadata?.phase || "N/A"}</Badge>
                  </div>
                </div>
              </div>

              {/* HTML Preview */}
              {previewItem.fileUrl && (
                <div className="border border-border rounded-lg overflow-hidden bg-[#0d1117]">
                  <iframe
                    src={previewItem.fileUrl}
                    className="w-full h-[400px] border-0"
                    title="Evidence Preview"
                    sandbox="allow-same-origin"
                  />
                </div>
              )}

              {/* Actions */}
              <div className="flex gap-2 justify-end">
                {previewItem.fileUrl && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => window.open(previewItem.fileUrl, "_blank")}
                  >
                    <Eye className="h-4 w-4 mr-1" />
                    Open Full Size
                  </Button>
                )}
                <Button
                  size="sm"
                  className="bg-cyan-600 hover:bg-cyan-700"
                  onClick={() => exportMutation.mutate({ evidenceId: previewItem.evidenceId })}
                  disabled={exportMutation.isPending}
                >
                  {exportMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                  ) : (
                    <Download className="h-4 w-4 mr-1" />
                  )}
                  Export as PNG
                </Button>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Capture Evidence Dialog */}
      <Dialog open={captureDialogOpen} onOpenChange={setCaptureDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Camera className="h-5 w-5 text-cyan-400" />
              Capture Caldera Evidence
            </DialogTitle>
            <DialogDescription>
              Capture a live evidence snapshot from the Caldera C2 framework for an engagement.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium mb-1 block">Engagement</label>
              <Select
                value={captureEngId ? String(captureEngId) : ""}
                onValueChange={(v) => setCaptureEngId(Number(v))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select engagement..." />
                </SelectTrigger>
                <SelectContent>
                  {(allEngagementsQuery.data?.engagements ?? []).map((eng: any) => (
                    <SelectItem key={eng.id} value={String(eng.id)}>
                      {eng.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-sm">
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
                <div>
                  <p className="text-amber-400 font-medium">Live Capture</p>
                  <p className="text-muted-foreground text-xs mt-1">
                    This will connect to the Caldera C2 server and capture current agent check-ins,
                    operation data, and adversary profiles. Evidence will include source/destination
                    IPs and precise timestamps.
                  </p>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setCaptureDialogOpen(false)}>Cancel</Button>
              <Button
                className="bg-cyan-600 hover:bg-cyan-700"
                disabled={!captureEngId || captureMutation.isPending}
                onClick={() => {
                  if (captureEngId) {
                    captureMutation.mutate({ engagementId: captureEngId });
                  }
                }}
              >
                {captureMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                ) : (
                  <Camera className="h-4 w-4 mr-1" />
                )}
                Capture
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
