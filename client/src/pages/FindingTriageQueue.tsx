/**
 * FindingTriageQueue — Analyst triage page for normalized findings.
 *
 * Analysts review normalized findings from any engagement, accept/reject/reclassify
 * them, and feed triage outcomes into the cross-training pipeline to improve
 * future scanner calibration and pattern recognition.
 *
 * Supports both individual and bulk triage actions with multi-select.
 */

import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useToast } from "@/hooks/use-toast";
import {
  CheckCircle2, XCircle, AlertTriangle, RefreshCw, Search, Filter,
  ArrowUpDown, Shield, Bug, Target, Eye, Layers, Brain, ChevronDown,
  ChevronRight, Fingerprint, Clock, ThumbsUp, ThumbsDown, Edit2,
  BarChart3, Zap, Info, Send, Sparkles, CheckSquare, Square, ListChecks,
} from "lucide-react";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

type TriageDecision = "true_positive" | "false_positive" | "reclassify" | "needs_review";
type SortField = "severity" | "title" | "sources";

interface TriagedFinding {
  findingId: string;
  decision: TriageDecision;
  reclassifiedSeverity?: string;
  analystNotes: string;
  timestamp: number;
}

export default function FindingTriageQueue() {
  const { user } = useAuth();
  const { toast } = useToast();

  // Engagement selection
  const [engagementId, setEngagementId] = useState<number | null>(null);
  const [engagementInput, setEngagementInput] = useState("");

  // Triage state
  const [triaged, setTriaged] = useState<Map<string, TriagedFinding>>(new Map());
  const [activeDialog, setActiveDialog] = useState<{ findingId: string; finding: any } | null>(null);
  const [dialogDecision, setDialogDecision] = useState<TriageDecision>("true_positive");
  const [dialogSeverity, setDialogSeverity] = useState("medium");
  const [dialogNotes, setDialogNotes] = useState("");

  // Bulk selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkDialogOpen, setBulkDialogOpen] = useState(false);
  const [bulkDecision, setBulkDecision] = useState<TriageDecision>("true_positive");
  const [bulkSeverity, setBulkSeverity] = useState("medium");
  const [bulkNotes, setBulkNotes] = useState("");

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [triageFilter, setTriageFilter] = useState<string | null>(null);
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

  // Mutations
  const normalizeMut = trpc.vaBugBounty.normalizeEngagementFindings.useMutation();
  const crossTrainMut = trpc.vaBugBounty.processCrossTrainingBatch.useMutation();

  const findings = normalizeMut.data?.findings || [];
  const stats = normalizeMut.data?.stats;

  const handleLoadEngagement = () => {
    const id = parseInt(engagementInput);
    if (!isNaN(id) && id > 0) {
      setEngagementId(id);
      setTriaged(new Map());
      setSelectedIds(new Set());
      normalizeMut.mutate({ engagementId: id });
    }
  };

  // ─── Individual triage actions ──────────────────────────────────────────────

  const quickAccept = (findingId: string) => {
    setTriaged(prev => {
      const next = new Map(prev);
      next.set(findingId, {
        findingId,
        decision: "true_positive",
        analystNotes: "",
        timestamp: Date.now(),
      });
      return next;
    });
    toast({ title: "Finding accepted", description: "Marked as true positive" });
  };

  const quickReject = (findingId: string) => {
    setTriaged(prev => {
      const next = new Map(prev);
      next.set(findingId, {
        findingId,
        decision: "false_positive",
        analystNotes: "",
        timestamp: Date.now(),
      });
      return next;
    });
    toast({ title: "Finding rejected", description: "Marked as false positive" });
  };

  const openTriageDialog = (findingId: string, finding: any) => {
    setActiveDialog({ findingId, finding });
    setDialogDecision("true_positive");
    setDialogSeverity(finding.severity || "medium");
    setDialogNotes("");
  };

  const submitTriageDialog = () => {
    if (!activeDialog) return;
    setTriaged(prev => {
      const next = new Map(prev);
      next.set(activeDialog.findingId, {
        findingId: activeDialog.findingId,
        decision: dialogDecision,
        reclassifiedSeverity: dialogDecision === "reclassify" ? dialogSeverity : undefined,
        analystNotes: dialogNotes,
        timestamp: Date.now(),
      });
      return next;
    });
    toast({
      title: dialogDecision === "reclassify" ? "Finding reclassified" : `Finding ${dialogDecision.replace(/_/g, " ")}`,
      description: dialogNotes ? `Note: ${dialogNotes.slice(0, 50)}...` : undefined,
    });
    setActiveDialog(null);
  };

  // ─── Bulk triage actions ────────────────────────────────────────────────────

  const getFindingId = useCallback((f: any) => f.findingId || f.fingerprint, []);

  const toggleSelect = useCallback((fId: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(fId)) next.delete(fId);
      else next.add(fId);
      return next;
    });
  }, []);

  const selectAllVisible = useCallback(() => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      filtered.forEach((f: any) => next.add(getFindingId(f)));
      return next;
    });
  }, []);

  const deselectAll = useCallback(() => {
    setSelectedIds(new Set());
  }, []);

  const selectPending = useCallback(() => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      filtered.forEach((f: any) => {
        const fId = getFindingId(f);
        if (!triaged.has(fId)) next.add(fId);
      });
      return next;
    });
  }, [triaged]);

  const bulkQuickAccept = () => {
    if (selectedIds.size === 0) return;
    const now = Date.now();
    setTriaged(prev => {
      const next = new Map(prev);
      selectedIds.forEach(fId => {
        next.set(fId, { findingId: fId, decision: "true_positive", analystNotes: "", timestamp: now });
      });
      return next;
    });
    toast({
      title: `${selectedIds.size} findings accepted`,
      description: "Bulk marked as true positive",
    });
    setSelectedIds(new Set());
  };

  const bulkQuickReject = () => {
    if (selectedIds.size === 0) return;
    const now = Date.now();
    setTriaged(prev => {
      const next = new Map(prev);
      selectedIds.forEach(fId => {
        next.set(fId, { findingId: fId, decision: "false_positive", analystNotes: "", timestamp: now });
      });
      return next;
    });
    toast({
      title: `${selectedIds.size} findings rejected`,
      description: "Bulk marked as false positive",
    });
    setSelectedIds(new Set());
  };

  const openBulkDialog = () => {
    if (selectedIds.size === 0) return;
    setBulkDecision("true_positive");
    setBulkSeverity("medium");
    setBulkNotes("");
    setBulkDialogOpen(true);
  };

  const submitBulkDialog = () => {
    const now = Date.now();
    setTriaged(prev => {
      const next = new Map(prev);
      selectedIds.forEach(fId => {
        next.set(fId, {
          findingId: fId,
          decision: bulkDecision,
          reclassifiedSeverity: bulkDecision === "reclassify" ? bulkSeverity : undefined,
          analystNotes: bulkNotes,
          timestamp: now,
        });
      });
      return next;
    });
    toast({
      title: `${selectedIds.size} findings ${bulkDecision === "reclassify" ? "reclassified" : bulkDecision.replace(/_/g, " ")}`,
      description: bulkNotes ? `Note: ${bulkNotes.slice(0, 50)}...` : `Bulk triage applied to ${selectedIds.size} findings`,
    });
    setSelectedIds(new Set());
    setBulkDialogOpen(false);
  };

  // ─── Submit all triage decisions to cross-training ──────────────────────────

  const submitToCrossTraining = () => {
    const outcomes = Array.from(triaged.values()).map(t => {
      const finding = findings.find((f: any) => (f.findingId || f.fingerprint) === t.findingId);
      return {
        engagementId: engagementId!,
        findingId: t.findingId,
        scanner: finding?.sources?.[0]?.scanner || "unknown",
        vulnClass: finding?.vulnClass || "unknown",
        originalSeverity: finding?.severity || "info",
        triageDecision: t.decision,
        reclassifiedSeverity: t.reclassifiedSeverity,
        analystNotes: t.analystNotes,
        timestamp: t.timestamp,
        isTruePositive: t.decision === "true_positive" || t.decision === "reclassify",
        isFalsePositive: t.decision === "false_positive",
      };
    });

    crossTrainMut.mutate({ outcomes }, {
      onSuccess: (data) => {
        toast({
          title: "Cross-training batch submitted",
          description: `Processed ${outcomes.length} triage outcomes. Patterns updated.`,
        });
      },
      onError: (err) => {
        toast({ title: "Cross-training failed", description: err.message, variant: "destructive" });
      },
    });
  };

  // ─── Filter and sort ────────────────────────────────────────────────────────

  const filtered = useMemo(() => {
    let result = [...findings];
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter((f: any) =>
        f.title?.toLowerCase().includes(q) ||
        f.vulnClass?.toLowerCase().includes(q) ||
        f.cveIds?.some((c: string) => c.toLowerCase().includes(q)) ||
        f.affectedAsset?.hostname?.toLowerCase().includes(q)
      );
    }
    if (severityFilter) {
      result = result.filter((f: any) => f.severity === severityFilter);
    }
    if (triageFilter) {
      if (triageFilter === "pending") {
        result = result.filter((f: any) => !triaged.has(f.findingId || f.fingerprint));
      } else {
        result = result.filter((f: any) => triaged.get(f.findingId || f.fingerprint)?.decision === triageFilter);
      }
    }
    result.sort((a: any, b: any) => {
      let cmp = 0;
      switch (sortField) {
        case "severity":
          cmp = (SEVERITY_ORDER[a.severity as keyof typeof SEVERITY_ORDER] ?? 5) - (SEVERITY_ORDER[b.severity as keyof typeof SEVERITY_ORDER] ?? 5);
          break;
        case "title":
          cmp = (a.title || "").localeCompare(b.title || "");
          break;
        case "sources":
          cmp = (a.sources?.length || 0) - (b.sources?.length || 0);
          break;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return result;
  }, [findings, searchQuery, severityFilter, triageFilter, sortField, sortDir, triaged]);

  const toggleExpanded = (id: string) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortField(field); setSortDir("asc"); }
  };

  // Stats
  const triagedCount = triaged.size;
  const tpCount = Array.from(triaged.values()).filter(t => t.decision === "true_positive" || t.decision === "reclassify").length;
  const fpCount = Array.from(triaged.values()).filter(t => t.decision === "false_positive").length;
  const pendingCount = findings.length - triagedCount;

  // Bulk selection helpers
  const allVisibleSelected = filtered.length > 0 && filtered.every((f: any) => selectedIds.has(getFindingId(f)));
  const someVisibleSelected = filtered.some((f: any) => selectedIds.has(getFindingId(f)));

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-foreground flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-violet-500/20 to-purple-500/20 flex items-center justify-center">
            <CheckCircle2 className="h-5 w-5 text-violet-400" />
          </div>
          Finding Triage Queue
        </h2>
        <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
          Review normalized findings from engagement scans. Accept true positives, reject false positives,
          or reclassify severity. Use checkboxes for bulk triage. Triage decisions feed into the cross-training
          pipeline to improve future scanner accuracy and pattern recognition.
        </p>
      </div>

      {/* Engagement Selector */}
      <Card className="border-border/30 bg-card/50">
        <CardContent className="py-4 px-5">
          <div className="flex items-center gap-3">
            <div className="flex-1 max-w-xs">
              <Input
                placeholder="Enter engagement ID..."
                value={engagementInput}
                onChange={e => setEngagementInput(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleLoadEngagement()}
                className="h-9"
              />
            </div>
            <Button onClick={handleLoadEngagement} disabled={normalizeMut.isPending} size="sm" className="gap-2">
              <RefreshCw className={`h-4 w-4 ${normalizeMut.isPending ? "animate-spin" : ""}`} />
              {normalizeMut.isPending ? "Loading..." : "Load & Normalize"}
            </Button>
            {engagementId && (
              <Badge variant="outline" className="text-xs">
                Engagement #{engagementId}
              </Badge>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Triage Progress Bar */}
      {findings.length > 0 && (
        <Card className="border-border/30 bg-card/50">
          <CardContent className="py-4 px-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-foreground">Triage Progress</span>
              <span className="text-xs text-muted-foreground">
                {triagedCount} of {findings.length} findings triaged ({Math.round((triagedCount / findings.length) * 100)}%)
              </span>
            </div>
            <div className="h-2 bg-background/50 rounded-full overflow-hidden flex">
              {tpCount > 0 && (
                <div className="h-full bg-green-500 transition-all" style={{ width: `${(tpCount / findings.length) * 100}%` }} />
              )}
              {fpCount > 0 && (
                <div className="h-full bg-red-500 transition-all" style={{ width: `${(fpCount / findings.length) * 100}%` }} />
              )}
            </div>
            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
              <span className="flex items-center gap-1"><ThumbsUp className="h-3 w-3 text-green-400" /> {tpCount} accepted</span>
              <span className="flex items-center gap-1"><ThumbsDown className="h-3 w-3 text-red-400" /> {fpCount} rejected</span>
              <span className="flex items-center gap-1"><Clock className="h-3 w-3 text-yellow-400" /> {pendingCount} pending</span>
              <div className="ml-auto">
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs gap-1"
                  disabled={triagedCount === 0 || crossTrainMut.isPending}
                  onClick={submitToCrossTraining}
                >
                  <Send className="h-3 w-3" />
                  {crossTrainMut.isPending ? "Submitting..." : `Submit ${triagedCount} to Cross-Training`}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Severity Quick Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {(["critical", "high", "medium", "low", "info"] as const).map(sev => {
            const count = findings.filter((f: any) => f.severity === sev).length;
            const triagedInSev = findings.filter((f: any) => f.severity === sev && triaged.has(f.findingId || f.fingerprint)).length;
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? null : sev)}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg border transition-colors ${
                  severityFilter === sev ? "ring-1 ring-accent bg-accent/10" : "hover:bg-accent/5"
                } border-border/30 bg-card/50`}
              >
                <Badge variant="outline" className={`${SEVERITY_COLORS[sev]} text-[10px] w-16 justify-center`}>
                  {sev}
                </Badge>
                <div className="text-left">
                  <div className="text-sm font-semibold text-foreground">{count}</div>
                  <div className="text-[10px] text-muted-foreground">{triagedInSev}/{count} triaged</div>
                </div>
              </button>
            );
          })}
        </div>
      )}

      {/* Bulk Action Bar — appears when items are selected */}
      {selectedIds.size > 0 && (
        <Card className="border-violet-500/30 bg-violet-500/5 sticky top-0 z-10">
          <CardContent className="py-3 px-5">
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-2">
                <ListChecks className="h-4 w-4 text-violet-400" />
                <span className="text-sm font-medium text-foreground">
                  {selectedIds.size} finding{selectedIds.size !== 1 ? "s" : ""} selected
                </span>
              </div>
              <div className="h-4 w-px bg-border/50" />
              <Button size="sm" variant="ghost" className="h-7 text-xs gap-1.5 text-green-400 hover:text-green-300 hover:bg-green-500/10" onClick={bulkQuickAccept}>
                <ThumbsUp className="h-3.5 w-3.5" />
                Accept All
              </Button>
              <Button size="sm" variant="ghost" className="h-7 text-xs gap-1.5 text-red-400 hover:text-red-300 hover:bg-red-500/10" onClick={bulkQuickReject}>
                <ThumbsDown className="h-3.5 w-3.5" />
                Reject All
              </Button>
              <Button size="sm" variant="ghost" className="h-7 text-xs gap-1.5 text-yellow-400 hover:text-yellow-300 hover:bg-yellow-500/10" onClick={openBulkDialog}>
                <Edit2 className="h-3.5 w-3.5" />
                Detailed Bulk Triage
              </Button>
              <div className="h-4 w-px bg-border/50" />
              <Button size="sm" variant="ghost" className="h-7 text-xs text-muted-foreground" onClick={deselectAll}>
                Clear Selection
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Search and Filter Controls */}
      {findings.length > 0 && (
        <div className="flex items-center gap-3 flex-wrap">
          {/* Select all / pending controls */}
          <div className="flex items-center gap-1">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 w-7 p-0"
                  onClick={() => allVisibleSelected ? deselectAll() : selectAllVisible()}
                >
                  {allVisibleSelected ? (
                    <CheckSquare className="h-4 w-4 text-violet-400" />
                  ) : someVisibleSelected ? (
                    <div className="relative">
                      <Square className="h-4 w-4 text-muted-foreground" />
                      <div className="absolute inset-0 flex items-center justify-center">
                        <div className="h-2 w-2 bg-violet-400 rounded-sm" />
                      </div>
                    </div>
                  ) : (
                    <Square className="h-4 w-4 text-muted-foreground" />
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>{allVisibleSelected ? "Deselect all" : "Select all visible"}</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 text-xs gap-1"
                  onClick={selectPending}
                  disabled={pendingCount === 0}
                >
                  <Clock className="h-3 w-3" />
                  Select Pending ({pendingCount})
                </Button>
              </TooltipTrigger>
              <TooltipContent>Select all un-triaged findings</TooltipContent>
            </Tooltip>
          </div>
          <div className="h-4 w-px bg-border/50" />
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="Search findings, CVEs, hosts..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="pl-8 h-8 text-sm"
            />
          </div>
          <Select value={triageFilter || "all"} onValueChange={v => setTriageFilter(v === "all" ? null : v)}>
            <SelectTrigger className="w-36 h-8 text-xs">
              <SelectValue placeholder="Triage status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All findings</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="true_positive">True Positive</SelectItem>
              <SelectItem value="false_positive">False Positive</SelectItem>
              <SelectItem value="reclassify">Reclassified</SelectItem>
              <SelectItem value="needs_review">Needs Review</SelectItem>
            </SelectContent>
          </Select>
          <div className="flex items-center gap-1">
            {(["severity", "title", "sources"] as SortField[]).map(field => (
              <Button
                key={field}
                variant={sortField === field ? "secondary" : "ghost"}
                size="sm"
                className="h-7 text-xs gap-1"
                onClick={() => toggleSort(field)}
              >
                {field === "severity" ? "Sev" : field === "sources" ? "Sources" : "Title"}
                {sortField === field && <ArrowUpDown className="h-3 w-3" />}
              </Button>
            ))}
          </div>
          <span className="text-xs text-muted-foreground ml-auto">{filtered.length} findings</span>
        </div>
      )}

      {/* Findings List */}
      {findings.length > 0 ? (
        <ScrollArea className="h-[calc(100vh-480px)]">
          <div className="space-y-2">
            {filtered.map((f: any) => {
              const fId = getFindingId(f);
              const triageState = triaged.get(fId);
              const isExpanded = expandedFindings.has(fId);
              const isSelected = selectedIds.has(fId);

              return (
                <Card
                  key={fId}
                  className={`border-border/30 transition-colors ${
                    isSelected ? "ring-1 ring-violet-500/40 bg-violet-500/5" :
                    triageState?.decision === "true_positive" ? "bg-green-500/5 border-green-500/20" :
                    triageState?.decision === "false_positive" ? "bg-red-500/5 border-red-500/20" :
                    triageState?.decision === "reclassify" ? "bg-yellow-500/5 border-yellow-500/20" :
                    "bg-card/50 hover:bg-card/70"
                  }`}
                >
                  <CardContent className="p-3">
                    <div className="flex items-start gap-3">
                      {/* Checkbox for bulk selection */}
                      <div className="flex-none mt-0.5">
                        <Checkbox
                          checked={isSelected}
                          onCheckedChange={() => toggleSelect(fId)}
                          className="data-[state=checked]:bg-violet-500 data-[state=checked]:border-violet-500"
                        />
                      </div>

                      {/* Expand toggle */}
                      <button onClick={() => toggleExpanded(fId)} className="mt-0.5 flex-none">
                        {isExpanded ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
                      </button>

                      {/* Finding info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant="outline" className={`${SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info} text-[10px]`}>
                            {triageState?.reclassifiedSeverity || f.severity}
                          </Badge>
                          {triageState && (
                            <Badge variant="outline" className={`text-[10px] ${
                              triageState.decision === "true_positive" ? "bg-green-500/20 text-green-400 border-green-500/30" :
                              triageState.decision === "false_positive" ? "bg-red-500/20 text-red-400 border-red-500/30" :
                              triageState.decision === "reclassify" ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" :
                              "bg-blue-500/20 text-blue-400 border-blue-500/30"
                            }`}>
                              {triageState.decision.replace(/_/g, " ")}
                            </Badge>
                          )}
                          <span className="text-sm font-medium text-foreground truncate">{f.title}</span>
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                          {f.affectedAsset?.hostname && (
                            <span className="flex items-center gap-1">
                              <Target className="h-3 w-3" /> {f.affectedAsset.hostname}
                              {f.affectedAsset.port && `:${f.affectedAsset.port}`}
                            </span>
                          )}
                          {f.cveIds?.length > 0 && (
                            <span className="flex items-center gap-1 font-mono">
                              <Shield className="h-3 w-3" /> {f.cveIds.slice(0, 2).join(", ")}
                            </span>
                          )}
                          {f.vulnClass && (
                            <span className="flex items-center gap-1">
                              <Bug className="h-3 w-3" /> {f.vulnClass}
                            </span>
                          )}
                          <span className="flex items-center gap-1">
                            <Eye className="h-3 w-3" /> {f.sources?.length || 1} source{(f.sources?.length || 1) !== 1 ? "s" : ""}
                          </span>
                        </div>

                        {/* Expanded details */}
                        {isExpanded && (
                          <div className="mt-3 pt-3 border-t border-border/30 space-y-2">
                            {f.description && <p className="text-sm text-foreground/80">{f.description}</p>}
                            {f.cweIds?.length > 0 && (
                              <div className="text-xs"><span className="text-muted-foreground">CWE:</span> <span className="font-mono">{f.cweIds.join(", ")}</span></div>
                            )}
                            {f.detectionMethod && (
                              <div className="text-xs"><span className="text-muted-foreground">Detection:</span> {f.detectionMethod.replace(/_/g, " ")}</div>
                            )}
                            {f.sources?.length > 0 && (
                              <div className="flex flex-wrap gap-1.5">
                                {f.sources.map((s: any, i: number) => (
                                  <Badge key={i} variant="outline" className="text-[10px] bg-background/50">
                                    {s.scanner}
                                  </Badge>
                                ))}
                              </div>
                            )}
                            {triageState?.analystNotes && (
                              <div className="text-xs bg-background/50 rounded p-2 border border-border/30">
                                <span className="text-muted-foreground">Analyst note:</span> {triageState.analystNotes}
                              </div>
                            )}
                          </div>
                        )}
                      </div>

                      {/* Triage Actions */}
                      <div className="flex items-center gap-1 flex-none">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant={triageState?.decision === "true_positive" ? "default" : "ghost"}
                              size="sm"
                              className="h-7 w-7 p-0"
                              onClick={e => { e.stopPropagation(); quickAccept(fId); }}
                            >
                              <ThumbsUp className="h-3.5 w-3.5 text-green-400" />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Accept (True Positive)</TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant={triageState?.decision === "false_positive" ? "default" : "ghost"}
                              size="sm"
                              className="h-7 w-7 p-0"
                              onClick={e => { e.stopPropagation(); quickReject(fId); }}
                            >
                              <ThumbsDown className="h-3.5 w-3.5 text-red-400" />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Reject (False Positive)</TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 w-7 p-0"
                              onClick={e => { e.stopPropagation(); openTriageDialog(fId, f); }}
                            >
                              <Edit2 className="h-3.5 w-3.5 text-yellow-400" />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Detailed Triage</TooltipContent>
                        </Tooltip>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </ScrollArea>
      ) : !normalizeMut.isPending && !normalizeMut.data ? (
        <Card className="border-border/30 bg-card/30">
          <CardContent className="flex flex-col items-center justify-center py-16 gap-4">
            <div className="h-14 w-14 rounded-xl bg-gradient-to-br from-violet-500/20 to-purple-500/20 flex items-center justify-center">
              <CheckCircle2 className="h-7 w-7 text-violet-400" />
            </div>
            <div className="text-center">
              <p className="text-sm font-medium text-foreground">No engagement loaded</p>
              <p className="text-xs text-muted-foreground mt-1 max-w-md">
                Enter an engagement ID above to load and normalize its findings for triage.
                Your triage decisions will feed into the cross-training pipeline.
              </p>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {normalizeMut.isError && (
        <Card className="border-red-500/30 bg-red-500/5">
          <CardContent className="py-3 px-4">
            <p className="text-sm text-red-400">{normalizeMut.error?.message || "Failed to load findings"}</p>
          </CardContent>
        </Card>
      )}

      {/* Cross-Training Stats */}
      {crossTrainMut.data && (
        <Card className="border-emerald-500/30 bg-emerald-500/5">
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-sm font-medium text-emerald-400 flex items-center gap-2">
              <Sparkles className="h-4 w-4" /> Cross-Training Results
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3 pt-0">
            <div className="grid grid-cols-3 gap-3 text-xs">
              <div>
                <span className="text-muted-foreground">Patterns Updated</span>
                <div className="text-sm font-semibold text-foreground">{crossTrainMut.data.patternsUpdated ?? 0}</div>
              </div>
              <div>
                <span className="text-muted-foreground">Calibrations Adjusted</span>
                <div className="text-sm font-semibold text-foreground">{crossTrainMut.data.calibrationsAdjusted ?? 0}</div>
              </div>
              <div>
                <span className="text-muted-foreground">Tool Effectiveness Updated</span>
                <div className="text-sm font-semibold text-foreground">{crossTrainMut.data.toolEffectivenessUpdated ?? 0}</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Individual Triage Dialog */}
      <Dialog open={!!activeDialog} onOpenChange={open => !open && setActiveDialog(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="text-base">Triage Finding</DialogTitle>
            <DialogDescription className="text-sm">
              {activeDialog?.finding?.title}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Decision</label>
              <Select value={dialogDecision} onValueChange={v => setDialogDecision(v as TriageDecision)}>
                <SelectTrigger className="h-9">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="true_positive">True Positive</SelectItem>
                  <SelectItem value="false_positive">False Positive</SelectItem>
                  <SelectItem value="reclassify">Reclassify Severity</SelectItem>
                  <SelectItem value="needs_review">Needs Further Review</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {dialogDecision === "reclassify" && (
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1.5 block">New Severity</label>
                <Select value={dialogSeverity} onValueChange={setDialogSeverity}>
                  <SelectTrigger className="h-9">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="info">Info</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Analyst Notes</label>
              <Textarea
                placeholder="Optional notes about this finding..."
                value={dialogNotes}
                onChange={e => setDialogNotes(e.target.value)}
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setActiveDialog(null)}>Cancel</Button>
            <Button onClick={submitTriageDialog}>Submit Triage</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Triage Dialog */}
      <Dialog open={bulkDialogOpen} onOpenChange={setBulkDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="text-base flex items-center gap-2">
              <ListChecks className="h-5 w-5 text-violet-400" />
              Bulk Triage — {selectedIds.size} Finding{selectedIds.size !== 1 ? "s" : ""}
            </DialogTitle>
            <DialogDescription className="text-sm">
              Apply the same triage decision to all {selectedIds.size} selected findings. This will
              overwrite any existing individual triage decisions for these findings.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Decision</label>
              <Select value={bulkDecision} onValueChange={v => setBulkDecision(v as TriageDecision)}>
                <SelectTrigger className="h-9">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="true_positive">True Positive</SelectItem>
                  <SelectItem value="false_positive">False Positive</SelectItem>
                  <SelectItem value="reclassify">Reclassify Severity</SelectItem>
                  <SelectItem value="needs_review">Needs Further Review</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {bulkDecision === "reclassify" && (
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1.5 block">New Severity</label>
                <Select value={bulkSeverity} onValueChange={setBulkSeverity}>
                  <SelectTrigger className="h-9">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="info">Info</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Analyst Notes (applied to all)</label>
              <Textarea
                placeholder="Optional notes applied to all selected findings..."
                value={bulkNotes}
                onChange={e => setBulkNotes(e.target.value)}
                rows={3}
              />
            </div>
            {/* Preview of selected findings */}
            <div className="bg-background/50 rounded-lg border border-border/30 p-3 max-h-32 overflow-y-auto">
              <div className="text-xs text-muted-foreground mb-1.5">Selected findings:</div>
              <div className="space-y-1">
                {Array.from(selectedIds).slice(0, 10).map(fId => {
                  const f = findings.find((f: any) => getFindingId(f) === fId);
                  return f ? (
                    <div key={fId} className="flex items-center gap-2 text-xs">
                      <Badge variant="outline" className={`${SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info} text-[9px] px-1`}>
                        {f.severity}
                      </Badge>
                      <span className="truncate text-foreground/80">{f.title}</span>
                    </div>
                  ) : null;
                })}
                {selectedIds.size > 10 && (
                  <div className="text-xs text-muted-foreground">...and {selectedIds.size - 10} more</div>
                )}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setBulkDialogOpen(false)}>Cancel</Button>
            <Button onClick={submitBulkDialog} className="gap-2">
              <ListChecks className="h-4 w-4" />
              Apply to {selectedIds.size} Finding{selectedIds.size !== 1 ? "s" : ""}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
