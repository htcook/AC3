import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  AlertTriangle,
  Ban,
  Clock,
  Lock,
  Database,
  GraduationCap,
  Globe,
  Wrench,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Plus,
  Filter,
  BarChart3,
  FileText,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────

type GapCategory =
  | "scope_exclusion"
  | "tool_limitation"
  | "time_constraint"
  | "access_denied"
  | "data_unavailable"
  | "expertise_gap"
  | "environmental_constraint";

type GapStatus = "open" | "acknowledged" | "mitigated" | "resolved" | "accepted";
type PotentialImpact = "critical" | "high" | "medium" | "low" | "unknown";

interface IntelligenceGapsProps {
  engagementId?: number;
  scanId?: number;
  customerId?: string;
  compact?: boolean;
}

// ── Category Metadata ──────────────────────────────────────────────────────

const CATEGORY_META: Record<
  GapCategory,
  { label: string; icon: typeof AlertTriangle; color: string }
> = {
  scope_exclusion: { label: "Scope Exclusion", icon: Ban, color: "text-orange-400" },
  tool_limitation: { label: "Tool Limitation", icon: Wrench, color: "text-yellow-400" },
  time_constraint: { label: "Time Constraint", icon: Clock, color: "text-red-400" },
  access_denied: { label: "Access Denied", icon: Lock, color: "text-red-500" },
  data_unavailable: { label: "Data Unavailable", icon: Database, color: "text-zinc-400" },
  expertise_gap: { label: "Expertise Gap", icon: GraduationCap, color: "text-purple-400" },
  environmental_constraint: {
    label: "Environmental",
    icon: Globe,
    color: "text-blue-400",
  },
};

const IMPACT_COLORS: Record<PotentialImpact, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/30",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  low: "bg-green-500/20 text-green-300 border-green-500/30",
  unknown: "bg-zinc-500/20 text-zinc-300 border-zinc-500/30",
};

const STATUS_COLORS: Record<GapStatus, string> = {
  open: "bg-red-500/20 text-red-300 border-red-500/30",
  acknowledged: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  mitigated: "bg-blue-500/20 text-blue-300 border-blue-500/30",
  resolved: "bg-green-500/20 text-green-300 border-green-500/30",
  accepted: "bg-zinc-500/20 text-zinc-300 border-zinc-500/30",
};

// ── Main Component ─────────────────────────────────────────────────────────

export function IntelligenceGapsPanel({
  engagementId,
  scanId,
  customerId,
  compact = false,
}: IntelligenceGapsProps) {
  const [filterCategory, setFilterCategory] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [expandedGaps, setExpandedGaps] = useState<Set<number>>(new Set());
  const [resolveDialogGap, setResolveDialogGap] = useState<number | null>(null);
  const [resolutionNote, setResolutionNote] = useState("");
  const [resolutionStatus, setResolutionStatus] = useState<"resolved" | "mitigated" | "accepted">(
    "resolved"
  );
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  // ── Data Queries ───────────────────────────────────────────────────────

  const gapsQuery = trpc.intelligenceGaps.list.useQuery(
    {
      engagementId,
      scanId,
      customerId,
      ...(filterCategory !== "all" ? { category: filterCategory as GapCategory } : {}),
      ...(filterStatus !== "all" ? { status: filterStatus as GapStatus } : {}),
    },
    { enabled: !!(engagementId || scanId || customerId) }
  );

  const summaryQuery = trpc.intelligenceGaps.summary.useQuery(
    { engagementId, scanId, customerId },
    { enabled: !!(engagementId || scanId || customerId) }
  );

  const resolveMutation = trpc.intelligenceGaps.resolve.useMutation({
    onSuccess: () => {
      gapsQuery.refetch();
      summaryQuery.refetch();
      setResolveDialogGap(null);
      setResolutionNote("");
    },
  });

  const utils = trpc.useUtils();

  // ── Helpers ────────────────────────────────────────────────────────────

  const toggleExpanded = (id: number) => {
    setExpandedGaps((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const gaps = gapsQuery.data || [];
  const summary = summaryQuery.data;

  // ── Compact Summary Mode ───────────────────────────────────────────────

  if (compact) {
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-sm font-medium text-zinc-300">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          Intelligence Gaps
          {summary && (
            <Badge variant="outline" className="ml-auto text-xs border-amber-500/30 text-amber-300">
              {summary.openCount} open
            </Badge>
          )}
        </div>
        {gapsQuery.isLoading ? (
          <div className="text-xs text-zinc-500">Loading gaps...</div>
        ) : gaps.length === 0 ? (
          <div className="text-xs text-zinc-500">No intelligence gaps identified</div>
        ) : (
          <div className="space-y-1">
            {gaps.slice(0, 5).map((gap) => {
              const meta = CATEGORY_META[gap.category as GapCategory];
              const Icon = meta?.icon || AlertTriangle;
              return (
                <div
                  key={gap.id}
                  className="flex items-start gap-2 text-xs p-1.5 rounded bg-zinc-800/50"
                >
                  <Icon className={`h-3 w-3 mt-0.5 shrink-0 ${meta?.color || "text-zinc-400"}`} />
                  <div className="min-w-0">
                    <div className="text-zinc-200 truncate">{gap.title}</div>
                    <div className="text-zinc-500 truncate">{gap.reason}</div>
                  </div>
                  <Badge
                    variant="outline"
                    className={`shrink-0 text-[10px] px-1 py-0 ${
                      IMPACT_COLORS[(gap.potentialImpact as PotentialImpact) || "unknown"]
                    }`}
                  >
                    {gap.potentialImpact || "?"}
                  </Badge>
                </div>
              );
            })}
            {gaps.length > 5 && (
              <div className="text-xs text-zinc-500 text-center">
                +{gaps.length - 5} more gaps
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  // ── Full Panel Mode ────────────────────────────────────────────────────

  return (
    <div className="space-y-4">
      {/* Summary Stats */}
      {summary && summary.total > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <SummaryCard
            label="Total Gaps"
            value={summary.total}
            icon={BarChart3}
            color="text-zinc-300"
          />
          <SummaryCard
            label="Open"
            value={summary.openCount}
            icon={AlertTriangle}
            color="text-red-400"
          />
          <SummaryCard
            label="Resolved"
            value={summary.resolvedCount}
            icon={CheckCircle2}
            color="text-green-400"
          />
          <SummaryCard
            label="Categories"
            value={Object.keys(summary.byCategory).length}
            icon={Filter}
            color="text-blue-400"
          />
        </div>
      )}

      {/* Category Breakdown */}
      {summary && summary.total > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(summary.byCategory).map(([cat, cnt]) => {
            const meta = CATEGORY_META[cat as GapCategory];
            const Icon = meta?.icon || AlertTriangle;
            return (
              <TooltipProvider key={cat}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button
                      onClick={() =>
                        setFilterCategory(filterCategory === cat ? "all" : cat)
                      }
                      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs border transition-colors ${
                        filterCategory === cat
                          ? "bg-zinc-700 border-zinc-500 text-zinc-100"
                          : "bg-zinc-800/50 border-zinc-700/50 text-zinc-400 hover:border-zinc-600"
                      }`}
                    >
                      <Icon className={`h-3 w-3 ${meta?.color || ""}`} />
                      {meta?.label || cat}
                      <span className="text-zinc-500 ml-0.5">{cnt as number}</span>
                    </button>
                  </TooltipTrigger>
                  <TooltipContent side="bottom" className="text-xs">
                    Click to filter by {meta?.label || cat}
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            );
          })}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="w-[140px] h-8 text-xs bg-zinc-800 border-zinc-700">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="acknowledged">Acknowledged</SelectItem>
            <SelectItem value="mitigated">Mitigated</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
            <SelectItem value="accepted">Accepted</SelectItem>
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          size="sm"
          className="h-8 text-xs"
          onClick={() => setShowCreateDialog(true)}
        >
          <Plus className="h-3 w-3 mr-1" />
          Add Gap
        </Button>
      </div>

      {/* Gaps List */}
      {gapsQuery.isLoading ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-16 bg-zinc-800/50 rounded-lg animate-pulse" />
          ))}
        </div>
      ) : gaps.length === 0 ? (
        <Card className="bg-zinc-800/30 border-zinc-700/50">
          <CardContent className="py-8 text-center">
            <CheckCircle2 className="h-8 w-8 text-green-400 mx-auto mb-2" />
            <p className="text-sm text-zinc-400">
              {filterCategory !== "all" || filterStatus !== "all"
                ? "No gaps match the current filters"
                : "No intelligence gaps identified for this assessment"}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {gaps.map((gap) => {
            const meta = CATEGORY_META[gap.category as GapCategory];
            const Icon = meta?.icon || AlertTriangle;
            const isExpanded = expandedGaps.has(gap.id);
            const assets = (gap.affectedAssets as string[]) || [];

            return (
              <div
                key={gap.id}
                className="bg-zinc-800/40 border border-zinc-700/50 rounded-lg overflow-hidden"
              >
                {/* Gap Header */}
                <button
                  onClick={() => toggleExpanded(gap.id)}
                  className="w-full flex items-start gap-3 p-3 text-left hover:bg-zinc-700/20 transition-colors"
                >
                  <div className="mt-0.5">
                    {isExpanded ? (
                      <ChevronDown className="h-4 w-4 text-zinc-500" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-zinc-500" />
                    )}
                  </div>
                  <Icon
                    className={`h-4 w-4 mt-0.5 shrink-0 ${meta?.color || "text-zinc-400"}`}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium text-zinc-200">{gap.title}</span>
                      <Badge
                        variant="outline"
                        className={`text-[10px] px-1.5 py-0 ${
                          IMPACT_COLORS[
                            (gap.potentialImpact as PotentialImpact) || "unknown"
                          ]
                        }`}
                      >
                        {gap.potentialImpact || "unknown"}
                      </Badge>
                      <Badge
                        variant="outline"
                        className={`text-[10px] px-1.5 py-0 ${
                          STATUS_COLORS[(gap.status as GapStatus) || "open"]
                        }`}
                      >
                        {gap.status}
                      </Badge>
                    </div>
                    <div className="text-xs text-zinc-500 mt-0.5 line-clamp-1">
                      {gap.reason}
                    </div>
                  </div>
                </button>

                {/* Expanded Detail */}
                {isExpanded && (
                  <div className="px-3 pb-3 pt-0 ml-11 space-y-3 border-t border-zinc-700/30">
                    <div className="pt-2 space-y-2">
                      {gap.description && (
                        <div>
                          <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-0.5">
                            Description
                          </div>
                          <div className="text-xs text-zinc-300">{gap.description}</div>
                        </div>
                      )}
                      <div>
                        <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-0.5">
                          Reason
                        </div>
                        <div className="text-xs text-zinc-300">{gap.reason}</div>
                      </div>
                      {gap.riskImplication && (
                        <div>
                          <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-0.5">
                            Risk Implication
                          </div>
                          <div className="text-xs text-amber-300/80">{gap.riskImplication}</div>
                        </div>
                      )}
                      {gap.recommendation && (
                        <div>
                          <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-0.5">
                            Recommendation
                          </div>
                          <div className="text-xs text-blue-300/80">{gap.recommendation}</div>
                        </div>
                      )}
                      {assets.length > 0 && (
                        <div>
                          <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-0.5">
                            Affected Assets
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {assets.map((a, i) => (
                              <Badge
                                key={i}
                                variant="outline"
                                className="text-[10px] bg-zinc-900/50 border-zinc-600/50 text-zinc-300"
                              >
                                {a}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="flex items-center gap-3 text-[10px] text-zinc-500 pt-1">
                        <span>Detected by: {gap.detectedBy || "system"}</span>
                        {gap.estimatedEffort && <span>Effort: {gap.estimatedEffort}</span>}
                        <span>
                          Created:{" "}
                          {gap.createdAt
                            ? new Date(gap.createdAt).toLocaleDateString()
                            : "—"}
                        </span>
                      </div>
                    </div>

                    {/* Actions */}
                    {gap.status === "open" || gap.status === "acknowledged" ? (
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => setResolveDialogGap(gap.id)}
                        >
                          <CheckCircle2 className="h-3 w-3 mr-1" />
                          Resolve
                        </Button>
                        {gap.status === "open" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs text-zinc-400"
                            onClick={async () => {
                              await trpc.intelligenceGaps.updateStatus.mutate({
                                gapId: gap.id,
                                status: "acknowledged",
                              } as any).catch(() => {});
                              gapsQuery.refetch();
                            }}
                          >
                            Acknowledge
                          </Button>
                        )}
                      </div>
                    ) : gap.resolutionNote ? (
                      <div className="text-xs text-zinc-500 italic">
                        Resolution: {gap.resolutionNote}
                      </div>
                    ) : null}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Resolve Dialog */}
      <Dialog
        open={resolveDialogGap !== null}
        onOpenChange={(open) => {
          if (!open) {
            setResolveDialogGap(null);
            setResolutionNote("");
          }
        }}
      >
        <DialogContent className="bg-zinc-900 border-zinc-700">
          <DialogHeader>
            <DialogTitle className="text-zinc-100">Resolve Intelligence Gap</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-zinc-400 mb-1 block">Resolution Type</label>
              <Select
                value={resolutionStatus}
                onValueChange={(v) =>
                  setResolutionStatus(v as "resolved" | "mitigated" | "accepted")
                }
              >
                <SelectTrigger className="bg-zinc-800 border-zinc-700">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="resolved">Resolved — Gap has been fully addressed</SelectItem>
                  <SelectItem value="mitigated">
                    Mitigated — Compensating controls in place
                  </SelectItem>
                  <SelectItem value="accepted">
                    Accepted — Risk acknowledged and accepted
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-zinc-400 mb-1 block">Resolution Note</label>
              <Textarea
                value={resolutionNote}
                onChange={(e) => setResolutionNote(e.target.value)}
                placeholder="Describe how this gap was addressed..."
                className="bg-zinc-800 border-zinc-700 text-zinc-200 min-h-[80px]"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="ghost"
              onClick={() => {
                setResolveDialogGap(null);
                setResolutionNote("");
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (resolveDialogGap && resolutionNote.trim()) {
                  resolveMutation.mutate({
                    gapId: resolveDialogGap,
                    resolutionNote: resolutionNote.trim(),
                    status: resolutionStatus,
                  });
                }
              }}
              disabled={!resolutionNote.trim() || resolveMutation.isPending}
            >
              {resolveMutation.isPending ? "Saving..." : "Save Resolution"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create Gap Dialog */}
      <CreateGapDialog
        open={showCreateDialog}
        onOpenChange={setShowCreateDialog}
        engagementId={engagementId}
        scanId={scanId}
        customerId={customerId}
        onCreated={() => {
          gapsQuery.refetch();
          summaryQuery.refetch();
        }}
      />
    </div>
  );
}

// ── Summary Card ───────────────────────────────────────────────────────────

function SummaryCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number;
  icon: typeof AlertTriangle;
  color: string;
}) {
  return (
    <div className="bg-zinc-800/40 border border-zinc-700/50 rounded-lg p-3">
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${color}`} />
        <span className="text-[10px] uppercase tracking-wider text-zinc-500">{label}</span>
      </div>
      <div className="text-xl font-semibold text-zinc-100 mt-1">{value}</div>
    </div>
  );
}

// ── Create Gap Dialog ──────────────────────────────────────────────────────

function CreateGapDialog({
  open,
  onOpenChange,
  engagementId,
  scanId,
  customerId,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  engagementId?: number;
  scanId?: number;
  customerId?: string;
  onCreated: () => void;
}) {
  const [category, setCategory] = useState<GapCategory>("tool_limitation");
  const [title, setTitle] = useState("");
  const [reason, setReason] = useState("");
  const [recommendation, setRecommendation] = useState("");
  const [impact, setImpact] = useState<PotentialImpact>("medium");

  const createMutation = trpc.intelligenceGaps.create.useMutation({
    onSuccess: () => {
      onCreated();
      onOpenChange(false);
      setTitle("");
      setReason("");
      setRecommendation("");
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-zinc-900 border-zinc-700 max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-zinc-100">Add Intelligence Gap</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">Category</label>
            <Select value={category} onValueChange={(v) => setCategory(v as GapCategory)}>
              <SelectTrigger className="bg-zinc-800 border-zinc-700">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(CATEGORY_META).map(([key, meta]) => {
                  const Icon = meta.icon;
                  return (
                    <SelectItem key={key} value={key}>
                      <span className="flex items-center gap-2">
                        <Icon className={`h-3 w-3 ${meta.color}`} />
                        {meta.label}
                      </span>
                    </SelectItem>
                  );
                })}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">Title</label>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Brief description of what wasn't assessed"
              className="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-md text-zinc-200 placeholder:text-zinc-600"
            />
          </div>
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">Reason (why it wasn't assessed)</label>
            <Textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Explain why this area was not assessed..."
              className="bg-zinc-800 border-zinc-700 text-zinc-200 min-h-[60px]"
            />
          </div>
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">Potential Impact</label>
            <Select value={impact} onValueChange={(v) => setImpact(v as PotentialImpact)}>
              <SelectTrigger className="bg-zinc-800 border-zinc-700">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">Recommendation (optional)</label>
            <Textarea
              value={recommendation}
              onChange={(e) => setRecommendation(e.target.value)}
              placeholder="Suggested next steps to address this gap..."
              className="bg-zinc-800 border-zinc-700 text-zinc-200 min-h-[60px]"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => {
              if (title.trim() && reason.trim()) {
                createMutation.mutate({
                  engagementId,
                  scanId,
                  customerId,
                  category,
                  title: title.trim(),
                  reason: reason.trim(),
                  potentialImpact: impact,
                  recommendation: recommendation.trim() || undefined,
                });
              }
            }}
            disabled={!title.trim() || !reason.trim() || createMutation.isPending}
          >
            {createMutation.isPending ? "Creating..." : "Create Gap"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
