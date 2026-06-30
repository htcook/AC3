// @ts-nocheck
/**
 * DiscoveryContextComparisonView — Side-by-side diff of discovery context snapshots.
 *
 * Shows current vs historical snapshot with per-specialist change highlighting:
 * - Attribution shifts (org name, confidence delta)
 * - Lifecycle stage transitions
 * - New/removed threat actors
 * - Role changes (exposure, environment, criticality)
 * - Business context changes (function, revenue impact)
 *
 * Props: assetDbId, hostname, currentContext, onClose
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogClose
} from "@/components/ui/dialog";
import {
  ArrowRight, ArrowUp, ArrowDown, Minus, Fingerprint, Server,
  Clock, Building2, Skull, TrendingUp, TrendingDown, Equal,
  History, X, ChevronRight, AlertTriangle, CheckCircle2
} from "lucide-react";

interface ComparisonViewProps {
  assetDbId: number;
  hostname: string;
  currentContext: any;
  open: boolean;
  onClose: () => void;
}

// ─── Change Detection Helpers ─────────────────────────────────────

interface FieldChange {
  field: string;
  label: string;
  oldValue: any;
  newValue: any;
  changeType: "added" | "removed" | "modified" | "unchanged";
  delta?: number; // For numeric confidence changes
}

function detectChanges(oldCtx: any, newCtx: any): {
  attribution: FieldChange[];
  role: FieldChange[];
  lifecycle: FieldChange[];
  businessContext: FieldChange[];
  threatRelevance: FieldChange[];
  summary: { total: number; added: number; removed: number; modified: number };
} {
  const changes = {
    attribution: detectAttributionChanges(oldCtx?.attribution, newCtx?.attribution),
    role: detectRoleChanges(oldCtx?.role, newCtx?.role),
    lifecycle: detectLifecycleChanges(oldCtx?.lifecycle, newCtx?.lifecycle),
    businessContext: detectBusinessContextChanges(oldCtx?.businessContext, newCtx?.businessContext),
    threatRelevance: detectThreatRelevanceChanges(oldCtx?.threatRelevance, newCtx?.threatRelevance),
    summary: { total: 0, added: 0, removed: 0, modified: 0 },
  };

  const allChanges = [
    ...changes.attribution, ...changes.role, ...changes.lifecycle,
    ...changes.businessContext, ...changes.threatRelevance,
  ].filter(c => c.changeType !== "unchanged");

  changes.summary = {
    total: allChanges.length,
    added: allChanges.filter(c => c.changeType === "added").length,
    removed: allChanges.filter(c => c.changeType === "removed").length,
    modified: allChanges.filter(c => c.changeType === "modified").length,
  };

  return changes;
}

function detectAttributionChanges(oldAttr: any, newAttr: any): FieldChange[] {
  const changes: FieldChange[] = [];
  const oldPrimary = oldAttr?.primaryClaim;
  const newPrimary = newAttr?.primaryClaim;

  const oldOrg = oldPrimary?.attributedTo?.organization || null;
  const newOrg = newPrimary?.attributedTo?.organization || null;
  changes.push({
    field: "attribution.organization",
    label: "Primary Organization",
    oldValue: oldOrg,
    newValue: newOrg,
    changeType: oldOrg === newOrg ? "unchanged" : (!oldOrg ? "added" : !newOrg ? "removed" : "modified"),
  });

  const oldConf = oldPrimary?.confidenceScore ?? null;
  const newConf = newPrimary?.confidenceScore ?? null;
  changes.push({
    field: "attribution.confidence",
    label: "Attribution Confidence",
    oldValue: oldConf,
    newValue: newConf,
    changeType: oldConf === newConf ? "unchanged" : (oldConf == null ? "added" : newConf == null ? "removed" : "modified"),
    delta: (oldConf != null && newConf != null) ? newConf - oldConf : undefined,
  });

  const oldType = oldPrimary?.claimType || null;
  const newType = newPrimary?.claimType || null;
  changes.push({
    field: "attribution.claimType",
    label: "Claim Type",
    oldValue: oldType,
    newValue: newType,
    changeType: oldType === newType ? "unchanged" : (!oldType ? "added" : !newType ? "removed" : "modified"),
  });

  const oldCount = oldAttr?.claims?.length ?? 0;
  const newCount = newAttr?.claims?.length ?? 0;
  if (oldCount !== newCount) {
    changes.push({
      field: "attribution.claimCount",
      label: "Total Claims",
      oldValue: oldCount,
      newValue: newCount,
      changeType: "modified",
      delta: newCount - oldCount,
    });
  }

  return changes;
}

function detectRoleChanges(oldRole: any, newRole: any): FieldChange[] {
  const changes: FieldChange[] = [];
  const oldR = oldRole?.role || {};
  const newR = newRole?.role || {};

  for (const [key, label] of [
    ["exposure", "Exposure Level"],
    ["environment", "Environment"],
    ["criticality", "Criticality"],
    ["primaryFunction", "Primary Function"],
  ] as const) {
    const oldVal = oldR[key] || null;
    const newVal = newR[key] || null;
    changes.push({
      field: `role.${key}`,
      label,
      oldValue: oldVal,
      newValue: newVal,
      changeType: oldVal === newVal ? "unchanged" : (!oldVal ? "added" : !newVal ? "removed" : "modified"),
    });
  }

  const oldConf = oldRole?.metadata?.confidenceScore ?? oldRole?.role?.confidenceScore ?? null;
  const newConf = newRole?.metadata?.confidenceScore ?? newRole?.role?.confidenceScore ?? null;
  if (oldConf !== newConf) {
    changes.push({
      field: "role.confidence",
      label: "Role Confidence",
      oldValue: oldConf,
      newValue: newConf,
      changeType: oldConf == null ? "added" : newConf == null ? "removed" : "modified",
      delta: (oldConf != null && newConf != null) ? newConf - oldConf : undefined,
    });
  }

  return changes;
}

function detectLifecycleChanges(oldLc: any, newLc: any): FieldChange[] {
  const changes: FieldChange[] = [];

  const oldStage = oldLc?.stage || null;
  const newStage = newLc?.stage || null;
  changes.push({
    field: "lifecycle.stage",
    label: "Lifecycle Stage",
    oldValue: oldStage,
    newValue: newStage,
    changeType: oldStage === newStage ? "unchanged" : (!oldStage ? "added" : !newStage ? "removed" : "modified"),
  });

  const oldDir = oldLc?.direction || null;
  const newDir = newLc?.direction || null;
  changes.push({
    field: "lifecycle.direction",
    label: "Trajectory Direction",
    oldValue: oldDir,
    newValue: newDir,
    changeType: oldDir === newDir ? "unchanged" : (!oldDir ? "added" : !newDir ? "removed" : "modified"),
  });

  const oldConf = oldLc?.confidenceScore ?? null;
  const newConf = newLc?.confidenceScore ?? null;
  if (oldConf !== newConf) {
    changes.push({
      field: "lifecycle.confidence",
      label: "Lifecycle Confidence",
      oldValue: oldConf,
      newValue: newConf,
      changeType: oldConf == null ? "added" : newConf == null ? "removed" : "modified",
      delta: (oldConf != null && newConf != null) ? newConf - oldConf : undefined,
    });
  }

  return changes;
}

function detectBusinessContextChanges(oldBc: any, newBc: any): FieldChange[] {
  const changes: FieldChange[] = [];

  for (const [key, label] of [
    ["businessFunction", "Business Function"],
    ["revenueImpact", "Revenue Impact"],
    ["regulatoryScope", "Regulatory Scope"],
    ["dataClassification", "Data Classification"],
  ] as const) {
    const oldVal = oldBc?.[key] || null;
    const newVal = newBc?.[key] || null;
    changes.push({
      field: `businessContext.${key}`,
      label,
      oldValue: oldVal,
      newValue: newVal,
      changeType: oldVal === newVal ? "unchanged" : (!oldVal ? "added" : !newVal ? "removed" : "modified"),
    });
  }

  return changes;
}

function detectThreatRelevanceChanges(oldTr: any, newTr: any): FieldChange[] {
  const changes: FieldChange[] = [];

  const oldScore = oldTr?.overallThreatScore ?? null;
  const newScore = newTr?.overallThreatScore ?? null;
  changes.push({
    field: "threatRelevance.overallScore",
    label: "Overall Threat Score",
    oldValue: oldScore,
    newValue: newScore,
    changeType: oldScore === newScore ? "unchanged" : (oldScore == null ? "added" : newScore == null ? "removed" : "modified"),
    delta: (oldScore != null && newScore != null) ? newScore - oldScore : undefined,
  });

  const oldBand = oldTr?.threatBand || null;
  const newBand = newTr?.threatBand || null;
  changes.push({
    field: "threatRelevance.threatBand",
    label: "Threat Band",
    oldValue: oldBand,
    newValue: newBand,
    changeType: oldBand === newBand ? "unchanged" : (!oldBand ? "added" : !newBand ? "removed" : "modified"),
  });

  // Detect actor type changes
  const oldActors = (oldTr?.relevantActorTypes || []).sort().join(",");
  const newActors = (newTr?.relevantActorTypes || []).sort().join(",");
  if (oldActors !== newActors) {
    changes.push({
      field: "threatRelevance.actorTypes",
      label: "Relevant Actor Types",
      oldValue: oldTr?.relevantActorTypes || [],
      newValue: newTr?.relevantActorTypes || [],
      changeType: "modified",
    });
  }

  // Detect campaign correlation changes
  const oldCampaigns = (oldTr?.campaignCorrelations || []).map((c: any) => c.campaignId || c.campaignName).sort().join(",");
  const newCampaigns = (newTr?.campaignCorrelations || []).map((c: any) => c.campaignId || c.campaignName).sort().join(",");
  if (oldCampaigns !== newCampaigns) {
    changes.push({
      field: "threatRelevance.campaigns",
      label: "Campaign Correlations",
      oldValue: oldTr?.campaignCorrelations?.length || 0,
      newValue: newTr?.campaignCorrelations?.length || 0,
      changeType: "modified",
      delta: (newTr?.campaignCorrelations?.length || 0) - (oldTr?.campaignCorrelations?.length || 0),
    });
  }

  return changes;
}

// ─── Change Display Components ────────────────────────────────────

function ChangeIcon({ type }: { type: FieldChange["changeType"] }) {
  switch (type) {
    case "added": return <ArrowRight className="h-3 w-3 text-emerald-400" />;
    case "removed": return <X className="h-3 w-3 text-red-400" />;
    case "modified": return <ChevronRight className="h-3 w-3 text-amber-400" />;
    default: return <Equal className="h-3 w-3 text-zinc-500" />;
  }
}

function DeltaBadge({ delta }: { delta: number | undefined }) {
  if (delta == null || delta === 0) return null;
  const isPositive = delta > 0;
  return (
    <Badge className={`text-[8px] px-1 py-0 h-3.5 gap-0.5 ${
      isPositive ? "bg-emerald-600/80 text-white border-emerald-500/60" : "bg-red-600/80 text-white border-red-500/60"
    }`}>
      {isPositive ? <TrendingUp className="h-2.5 w-2.5" /> : <TrendingDown className="h-2.5 w-2.5" />}
      {isPositive ? "+" : ""}{delta}
    </Badge>
  );
}

function formatValue(val: any): string {
  if (val == null) return "—";
  if (Array.isArray(val)) return val.length === 0 ? "None" : val.join(", ");
  if (typeof val === "number") return String(val);
  return String(val).replace(/_/g, " ");
}

function ChangeRow({ change }: { change: FieldChange }) {
  if (change.changeType === "unchanged") return null;
  const bgColor = change.changeType === "added" ? "bg-emerald-500/5 border-emerald-500/20"
    : change.changeType === "removed" ? "bg-red-500/5 border-red-500/20"
    : "bg-amber-500/5 border-amber-500/20";

  return (
    <div className={`flex items-center gap-3 p-2.5 rounded-lg border ${bgColor} transition-all`}>
      <ChangeIcon type={change.changeType} />
      <div className="flex-1 min-w-0">
        <p className="text-[10px] text-muted-foreground font-medium">{change.label}</p>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="text-xs text-zinc-400 line-through truncate max-w-[140px]">
            {formatValue(change.oldValue)}
          </span>
          <ArrowRight className="h-2.5 w-2.5 text-muted-foreground shrink-0" />
          <span className="text-xs font-medium truncate max-w-[140px]">
            {formatValue(change.newValue)}
          </span>
        </div>
      </div>
      <DeltaBadge delta={change.delta} />
    </div>
  );
}

// ─── Specialist Change Section ────────────────────────────────────

function SpecialistChangeSection({ title, icon, changes, color }: {
  title: string;
  icon: React.ReactNode;
  changes: FieldChange[];
  color: string;
}) {
  const significantChanges = changes.filter(c => c.changeType !== "unchanged");
  if (significantChanges.length === 0) {
    return (
      <div className={`p-3 rounded-lg border ${color} opacity-50`}>
        <div className="flex items-center gap-2">
          {icon}
          <span className="text-xs font-medium">{title}</span>
          <Badge variant="outline" className="text-[8px] px-1 py-0 h-3.5 text-zinc-500">No changes</Badge>
        </div>
      </div>
    );
  }

  return (
    <div className={`p-3 rounded-lg border ${color} space-y-2`}>
      <div className="flex items-center gap-2 mb-2">
        {icon}
        <span className="text-xs font-semibold">{title}</span>
        <Badge className="text-[8px] px-1.5 py-0 h-3.5 bg-amber-600/80 text-white border-amber-500/60">
          {significantChanges.length} change{significantChanges.length > 1 ? "s" : ""}
        </Badge>
      </div>
      <div className="space-y-1.5">
        {significantChanges.map((change, i) => (
          <ChangeRow key={i} change={change} />
        ))}
      </div>
    </div>
  );
}

// ─── Main Comparison View ─────────────────────────────────────────

export default function DiscoveryContextComparisonView({
  assetDbId, hostname, currentContext, open, onClose,
}: ComparisonViewProps) {
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string>("");

  const historyQuery = trpc.calderaProxy.getDiscoveryContextHistory.useQuery(
    { assetDbId },
    { enabled: open && assetDbId > 0 }
  );

  const historySnapshots = useMemo(() => {
    if (!historyQuery.data?.discoveryContextHistory) return [];
    const raw = historyQuery.data.discoveryContextHistory;
    if (!Array.isArray(raw)) return [];
    return raw as { context: any; analyzedAt: string; snapshotId: string }[];
  }, [historyQuery.data]);

  // Auto-select most recent snapshot
  const selectedSnapshot = useMemo(() => {
    if (!selectedSnapshotId && historySnapshots.length > 0) {
      return historySnapshots[historySnapshots.length - 1];
    }
    return historySnapshots.find(s => s.snapshotId === selectedSnapshotId) || null;
  }, [selectedSnapshotId, historySnapshots]);

  const changes = useMemo(() => {
    if (!selectedSnapshot || !currentContext) return null;
    return detectChanges(selectedSnapshot.context, currentContext);
  }, [selectedSnapshot, currentContext]);

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-3xl max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base">
            <History className="h-4 w-4 text-purple-400" />
            Discovery Context Changes
            <span className="font-mono text-sm text-muted-foreground">— {hostname}</span>
          </DialogTitle>
          <DialogDescription className="text-xs">
            Compare the current analysis against a previous snapshot to identify intelligence drift.
          </DialogDescription>
        </DialogHeader>

        {historySnapshots.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <History className="h-8 w-8 text-muted-foreground mb-3" />
            <p className="text-sm text-muted-foreground">No previous snapshots available.</p>
            <p className="text-xs text-muted-foreground mt-1">
              Run the analysis again after some time to generate comparison data.
            </p>
          </div>
        ) : (
          <>
            {/* Snapshot Selector */}
            <div className="flex items-center gap-3 pb-3 border-b border-border">
              <span className="text-xs text-muted-foreground font-medium shrink-0">Compare against:</span>
              <Select
                value={selectedSnapshotId || (historySnapshots.length > 0 ? historySnapshots[historySnapshots.length - 1].snapshotId : "")}
                onValueChange={setSelectedSnapshotId}
              >
                <SelectTrigger className="w-[300px]">
                  <SelectValue placeholder="Select a snapshot..." />
                </SelectTrigger>
                <SelectContent>
                  {historySnapshots.map((snap, idx) => (
                    <SelectItem key={snap.snapshotId} value={snap.snapshotId}>
                      <div className="flex items-center gap-2">
                        <Clock className="h-3 w-3 text-muted-foreground" />
                        <span className="text-xs">
                          Snapshot #{idx + 1} — {new Date(snap.analyzedAt).toLocaleString()}
                        </span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Badge variant="outline" className="text-[9px] px-1.5 py-0 h-4 shrink-0">
                {historySnapshots.length} snapshot{historySnapshots.length > 1 ? "s" : ""}
              </Badge>
            </div>

            {/* Changes Summary */}
            {changes && (
              <div className="flex items-center gap-3 py-2">
                {changes.summary.total === 0 ? (
                  <div className="flex items-center gap-2 text-xs text-emerald-400">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    No changes detected between snapshots.
                  </div>
                ) : (
                  <>
                    <Badge className="bg-amber-600/80 text-white border-amber-500/60 text-[9px] px-1.5 py-0 h-4">
                      {changes.summary.total} total change{changes.summary.total > 1 ? "s" : ""}
                    </Badge>
                    {changes.summary.added > 0 && (
                      <Badge className="bg-emerald-600/80 text-white border-emerald-500/60 text-[9px] px-1.5 py-0 h-4">
                        +{changes.summary.added} added
                      </Badge>
                    )}
                    {changes.summary.removed > 0 && (
                      <Badge className="bg-red-600/80 text-white border-red-500/60 text-[9px] px-1.5 py-0 h-4">
                        -{changes.summary.removed} removed
                      </Badge>
                    )}
                    {changes.summary.modified > 0 && (
                      <Badge className="bg-blue-600/80 text-white border-blue-500/60 text-[9px] px-1.5 py-0 h-4">
                        ~{changes.summary.modified} modified
                      </Badge>
                    )}
                  </>
                )}
              </div>
            )}

            {/* Per-Specialist Change Panels */}
            {changes && (
              <ScrollArea className="flex-1 pr-3">
                <div className="space-y-3 pb-4">
                  <SpecialistChangeSection
                    title="Attribution"
                    icon={<Fingerprint className="h-3.5 w-3.5 text-cyan-400" />}
                    changes={changes.attribution}
                    color="border-cyan-500/20 bg-cyan-500/5"
                  />
                  <SpecialistChangeSection
                    title="Asset Role"
                    icon={<Server className="h-3.5 w-3.5 text-blue-400" />}
                    changes={changes.role}
                    color="border-blue-500/20 bg-blue-500/5"
                  />
                  <SpecialistChangeSection
                    title="Lifecycle Stage"
                    icon={<Clock className="h-3.5 w-3.5 text-amber-400" />}
                    changes={changes.lifecycle}
                    color="border-amber-500/20 bg-amber-500/5"
                  />
                  <SpecialistChangeSection
                    title="Business Context"
                    icon={<Building2 className="h-3.5 w-3.5 text-emerald-400" />}
                    changes={changes.businessContext}
                    color="border-emerald-500/20 bg-emerald-500/5"
                  />
                  <SpecialistChangeSection
                    title="Threat Relevance"
                    icon={<Skull className="h-3.5 w-3.5 text-red-400" />}
                    changes={changes.threatRelevance}
                    color="border-red-500/20 bg-red-500/5"
                  />

                  {/* Timeline Bar */}
                  <Separator className="my-4" />
                  <div className="space-y-2">
                    <p className="text-[10px] text-muted-foreground font-medium">Snapshot Timeline</p>
                    <div className="flex items-center gap-1">
                      {historySnapshots.map((snap, idx) => {
                        const isSelected = snap.snapshotId === (selectedSnapshotId || historySnapshots[historySnapshots.length - 1]?.snapshotId);
                        return (
                          <Tooltip key={snap.snapshotId}>
                            <TooltipTrigger asChild>
                              <button
                                onClick={() => setSelectedSnapshotId(snap.snapshotId)}
                                className={`h-6 flex-1 rounded-sm transition-all text-[8px] font-mono ${
                                  isSelected
                                    ? "bg-purple-600/60 border border-purple-400/60 text-white"
                                    : "bg-muted/40 border border-muted hover:bg-muted/60 text-muted-foreground"
                                }`}
                              >
                                #{idx + 1}
                              </button>
                            </TooltipTrigger>
                            <TooltipContent side="top" className="text-xs">
                              {new Date(snap.analyzedAt).toLocaleString()}
                            </TooltipContent>
                          </Tooltip>
                        );
                      })}
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <div className="h-6 flex-1 rounded-sm bg-emerald-600/30 border border-emerald-400/40 flex items-center justify-center text-[8px] font-mono text-emerald-300">
                            Current
                          </div>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="text-xs">
                          Current analysis: {currentContext?.aggregatedAt ? new Date(currentContext.aggregatedAt).toLocaleString() : "Now"}
                        </TooltipContent>
                      </Tooltip>
                    </div>
                  </div>
                </div>
              </ScrollArea>
            )}
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

// Export the change detection helpers for testing
export { detectChanges, detectAttributionChanges, detectRoleChanges, detectLifecycleChanges, detectBusinessContextChanges, detectThreatRelevanceChanges };
export type { FieldChange };
