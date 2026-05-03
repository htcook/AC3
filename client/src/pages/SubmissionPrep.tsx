/**
 * Submission Prep — Bug Bounty Submission Review & Export Panel
 * 
 * Lets operators:
 * 1. Select an engagement to pull hypotheses from
 * 2. Review ranked hypotheses with confidence/severity
 * 3. Generate optimized submissions (single or batch)
 * 4. Edit/refine submission text before filing
 * 5. Export in HackerOne/Bugcrowd format (copy to clipboard)
 * 6. Record rejection feedback to feed the calibration loop
 * 7. View calibration drift status
 */
import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Bug, Shield, Target, FileText, AlertTriangle, Copy, Sparkles,
  Clock, Zap, Eye, Send, Loader2, Info, ChevronDown, ChevronRight,
  FileCheck, Clipboard, Download, RefreshCw, Brain, TrendingUp,
  XCircle, CheckCircle2, BarChart3, ArrowRight, Crosshair,
} from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface HypothesisItem {
  id: string;
  vulnClass: string;
  title: string;
  description: string;
  affectedEndpoint: string;
  confidence: string;
  confidenceScore: number;
  reasoning: string[];
  verificationSteps: Array<{ action: string; expectedOutcome: string }>;
  estimatedEffort: string;
  potentialSeverity: string;
  potentialBountyRange?: { min: number; max: number };
  chainPotential?: Array<{ toVulnClass: string; chainDescription: string; impactMultiplier: number }>;
  duplicateLikelihood?: string;
  tags: string[];
  supportingEvidence: Array<{ type: string; description: string; confidence: number }>;
  disconfirmingEvidence?: Array<{ type: string; description: string; confidence: number }>;
}

interface SubmissionDraft {
  hypothesisId: string;
  hypothesisTitle: string;
  submission: {
    title: string;
    severity: string;
    severityJustification: string;
    summary: string;
    impactStatement: string;
    reproductionSteps: Array<{
      stepNumber: number;
      action: string;
      expectedResult: string;
      evidence?: string;
    }>;
    technicalDetails: string;
    remediation: string;
    references: string[];
    cweId: string;
    cvssVector?: string;
    cvssScore?: number;
    qualityScore: number;
    qualityIssues: string[];
    qualityRecommendations: string[];
  };
  exported: boolean;
  editedMarkdown?: string;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

const confidenceBadge = (level: string) => {
  const colors: Record<string, string> = {
    high: "bg-green-500/15 text-green-400 border-green-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    speculative: "bg-red-500/15 text-red-400 border-red-500/30",
  };
  return colors[level] || "bg-zinc-500/15 text-zinc-400 border-zinc-500/30";
};

const severityBadge = (sev: string) => {
  const colors: Record<string, string> = {
    critical: "bg-red-600/20 text-red-300 border-red-500/40",
    high: "bg-orange-600/20 text-orange-300 border-orange-500/40",
    medium: "bg-yellow-600/20 text-yellow-300 border-yellow-500/40",
    low: "bg-blue-600/20 text-blue-300 border-blue-500/40",
    info: "bg-zinc-600/20 text-zinc-300 border-zinc-500/40",
  };
  return colors[sev?.toLowerCase()] || "bg-zinc-600/20 text-zinc-300 border-zinc-500/40";
};

// ─── Component ─────────────────────────────────────────────────────────────────

export default function SubmissionPrep() {
  const [selectedEngId, setSelectedEngId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState("hypotheses");
  const [selectedHypothesis, setSelectedHypothesis] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<SubmissionDraft[]>([]);
  const [expandedHypothesis, setExpandedHypothesis] = useState<string | null>(null);
  const [platform, setPlatform] = useState<"hackerone" | "bugcrowd" | "intigriti" | "other">("hackerone");
  const [rejectionDialog, setRejectionDialog] = useState<{ open: boolean; draft?: SubmissionDraft }>({ open: false });
  const [rejectionForm, setRejectionForm] = useState({
    reason: "" as string,
    detail: "",
    triagerFeedback: "",
    lessons: "",
  });

  // ─── Queries ───────────────────────────────────────────────────────────────

  const engagementsQ = trpc.engagements.list.useQuery();
  const hypothesesQ = trpc.bountySubmissionPrep.getHypotheses.useQuery(
    { engagementId: selectedEngId! },
    { enabled: !!selectedEngId }
  );
  const calibrationQ = trpc.bountySubmissionPrep.getCalibrationStatus.useQuery();
  const prioritiesQ = trpc.bountySubmissionPrep.getScanPriorities.useQuery(
    { engagementId: selectedEngId! },
    { enabled: !!selectedEngId }
  );

  // ─── Mutations ─────────────────────────────────────────────────────────────

  const regenerateMut = trpc.bountySubmissionPrep.regenerateHypotheses.useMutation({
    onSuccess: () => {
      hypothesesQ.refetch();
      toast.success("Hypotheses regenerated");
    },
    onError: (e) => toast.error(`Regeneration failed: ${e.message}`),
  });

  const generateSubmissionMut = trpc.bountySubmissionPrep.generateSubmission.useMutation({
    onSuccess: (data) => {
      const newDraft: SubmissionDraft = {
        hypothesisId: data.hypothesis.id,
        hypothesisTitle: data.hypothesis.title,
        submission: data.submission,
        exported: false,
      };
      setDrafts(prev => [...prev.filter(d => d.hypothesisId !== data.hypothesis.id), newDraft]);
      setActiveTab("drafts");
      toast.success("Submission generated");
    },
    onError: (e) => toast.error(`Generation failed: ${e.message}`),
  });

  const batchGenerateMut = trpc.bountySubmissionPrep.batchGenerateSubmissions.useMutation({
    onSuccess: (data) => {
      const newDrafts: SubmissionDraft[] = data.submissions.map((s: any) => ({
        hypothesisId: s.hypothesis.id,
        hypothesisTitle: s.hypothesis.title,
        submission: s.submission,
        exported: false,
      }));
      setDrafts(prev => {
        const existingIds = new Set(newDrafts.map(d => d.hypothesisId));
        return [...prev.filter(d => !existingIds.has(d.hypothesisId)), ...newDrafts];
      });
      setActiveTab("drafts");
      toast.success(`${data.total} submissions generated (avg quality: ${data.avgQualityScore.toFixed(0)})`);
    },
    onError: (e) => toast.error(`Batch generation failed: ${e.message}`),
  });

  const exportMut = trpc.bountySubmissionPrep.exportSubmission.useMutation({
    onSuccess: (data) => {
      navigator.clipboard.writeText(data.markdown);
      toast.success(`Copied ${data.platform} submission to clipboard (${data.characterCount} chars)`);
    },
    onError: (e) => toast.error(`Export failed: ${e.message}`),
  });

  const recordRejectionMut = trpc.bountySubmissionPrep.recordRejection.useMutation({
    onSuccess: (data) => {
      calibrationQ.refetch();
      setRejectionDialog({ open: false });
      const msg = data.driftDetected
        ? `Rejection recorded. ⚠️ Calibration drift detected: ${data.driftReport?.direction}`
        : "Rejection recorded and fed into calibration loop";
      toast.success(msg);
    },
    onError: (e) => toast.error(`Failed to record rejection: ${e.message}`),
  });

  // ─── Derived Data ──────────────────────────────────────────────────────────

  const engagements = useMemo(() => {
    if (!engagementsQ.data) return [];
    return (engagementsQ.data as any[]).filter(e =>
      e.engagementType === 'bug_bounty' || e.engagementType === 'pentest' || e.engagementType === 'red_team'
    );
  }, [engagementsQ.data]);

  const hypotheses: HypothesisItem[] = useMemo(() => {
    if (!hypothesesQ.data?.available) return [];
    return (hypothesesQ.data.hypotheses || []) as HypothesisItem[];
  }, [hypothesesQ.data]);

  const handleExportDraft = useCallback((draft: SubmissionDraft) => {
    exportMut.mutate({
      title: draft.submission.title,
      severity: draft.submission.severity,
      severityJustification: draft.submission.severityJustification,
      summary: draft.submission.summary,
      impactStatement: draft.submission.impactStatement,
      reproductionSteps: draft.submission.reproductionSteps,
      technicalDetails: draft.submission.technicalDetails,
      remediation: draft.submission.remediation,
      references: draft.submission.references,
      cweId: draft.submission.cweId,
      cvssVector: draft.submission.cvssVector,
      cvssScore: draft.submission.cvssScore,
      platform,
    });
    setDrafts(prev => prev.map(d => d.hypothesisId === draft.hypothesisId ? { ...d, exported: true } : d));
  }, [exportMut, platform]);

  const handleRecordRejection = useCallback(() => {
    if (!rejectionDialog.draft || !rejectionForm.reason || !selectedEngId) return;
    const d = rejectionDialog.draft;
    recordRejectionMut.mutate({
      engagementId: selectedEngId,
      hypothesisId: d.hypothesisId,
      vulnClass: d.submission.cweId || "unknown",
      title: d.submission.title,
      affectedEndpoint: d.submission.reproductionSteps?.[0]?.action || "unknown",
      severity: d.submission.severity,
      rejectionReason: rejectionForm.reason as any,
      rejectionDetail: rejectionForm.detail,
      triagerFeedback: rejectionForm.triagerFeedback || undefined,
      lessonsLearned: rejectionForm.lessons ? rejectionForm.lessons.split("\n").filter(Boolean) : [],
    });
  }, [rejectionDialog, rejectionForm, selectedEngId, recordRejectionMut]);

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <FileCheck className="h-6 w-6 text-emerald-400" />
            Submission Prep
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Review hypotheses, generate optimized submissions, and export for HackerOne/Bugcrowd
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Select value={platform} onValueChange={(v) => setPlatform(v as any)}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Platform" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="hackerone">HackerOne</SelectItem>
              <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
              <SelectItem value="intigriti">Intigriti</SelectItem>
              <SelectItem value="other">Other</SelectItem>
            </SelectContent>
          </Select>
          <Select
            value={selectedEngId ? String(selectedEngId) : ""}
            onValueChange={(v) => setSelectedEngId(Number(v))}
          >
            <SelectTrigger className="w-[280px]">
              <SelectValue placeholder="Select engagement..." />
            </SelectTrigger>
            <SelectContent>
              {engagements.map((e: any) => (
                <SelectItem key={e.id} value={String(e.id)}>
                  #{e.id} — {e.name || e.customerName}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {!selectedEngId ? (
        <Card className="border-dashed border-2 border-zinc-700">
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <Target className="h-12 w-12 text-zinc-500 mb-4" />
            <h3 className="text-lg font-medium text-zinc-300">Select an Engagement</h3>
            <p className="text-sm text-zinc-500 mt-2 max-w-md">
              Choose an engagement from the dropdown above to view auto-generated vulnerability
              hypotheses and prepare optimized submissions.
            </p>
          </CardContent>
        </Card>
      ) : (
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="hypotheses" className="gap-1.5">
              <Brain className="h-3.5 w-3.5" /> Hypotheses
              {hypotheses.length > 0 && (
                <Badge variant="secondary" className="ml-1 text-xs">{hypotheses.length}</Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="drafts" className="gap-1.5">
              <FileText className="h-3.5 w-3.5" /> Drafts
              {drafts.length > 0 && (
                <Badge variant="secondary" className="ml-1 text-xs">{drafts.length}</Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="calibration" className="gap-1.5">
              <TrendingUp className="h-3.5 w-3.5" /> Calibration
            </TabsTrigger>
            <TabsTrigger value="priorities" className="gap-1.5">
              <Crosshair className="h-3.5 w-3.5" /> Scan Priorities
            </TabsTrigger>
          </TabsList>

          {/* ═══ HYPOTHESES TAB ═══ */}
          <TabsContent value="hypotheses" className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-sm text-muted-foreground">
                {hypothesesQ.isLoading ? "Loading hypotheses..." :
                  hypotheses.length > 0
                    ? `${hypotheses.length} hypotheses generated from recon data`
                    : "No hypotheses available — run or regenerate"}
              </div>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => regenerateMut.mutate({ engagementId: selectedEngId })}
                  disabled={regenerateMut.isPending}
                >
                  {regenerateMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" /> : <RefreshCw className="h-3.5 w-3.5 mr-1" />}
                  Regenerate
                </Button>
                <Button
                  size="sm"
                  onClick={() => batchGenerateMut.mutate({ engagementId: selectedEngId, minConfidence: "medium", platform })}
                  disabled={batchGenerateMut.isPending || hypotheses.length === 0}
                >
                  {batchGenerateMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" /> : <Sparkles className="h-3.5 w-3.5 mr-1" />}
                  Batch Generate Submissions
                </Button>
              </div>
            </div>

            {hypothesesQ.data?.available && hypothesesQ.data.reconQuality && (
              <Card className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="py-3 px-4">
                  <div className="flex items-center gap-6 text-sm">
                    <div className="flex items-center gap-2">
                      <BarChart3 className="h-4 w-4 text-blue-400" />
                      <span className="text-zinc-400">Recon Quality:</span>
                      <span className="font-medium">{(hypothesesQ.data.reconQuality as any).overallScore}/100</span>
                    </div>
                    {hypothesesQ.data.summary && (
                      <>
                        <Separator orientation="vertical" className="h-4" />
                        <div className="flex items-center gap-2">
                          <Clock className="h-4 w-4 text-amber-400" />
                          <span className="text-zinc-400">Est. Research:</span>
                          <span className="font-medium">{(hypothesesQ.data.summary as any).estimatedResearchHours?.toFixed(1)}h</span>
                        </div>
                        <Separator orientation="vertical" className="h-4" />
                        <div className="flex items-center gap-2">
                          <Zap className="h-4 w-4 text-purple-400" />
                          <span className="text-zinc-400">Chain Opportunities:</span>
                          <span className="font-medium">{(hypothesesQ.data.summary as any).topChainOpportunities?.length || 0}</span>
                        </div>
                      </>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}

            <ScrollArea className="h-[calc(100vh-380px)]">
              <div className="space-y-3">
                {hypotheses.map((h) => (
                  <Card
                    key={h.id}
                    className={`border transition-colors cursor-pointer ${
                      expandedHypothesis === h.id ? "border-emerald-500/50 bg-emerald-950/10" : "border-zinc-800 hover:border-zinc-700"
                    }`}
                    onClick={() => setExpandedHypothesis(expandedHypothesis === h.id ? null : h.id)}
                  >
                    <CardContent className="py-3 px-4">
                      <div className="flex items-start justify-between">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            {expandedHypothesis === h.id ? <ChevronDown className="h-4 w-4 text-zinc-500 shrink-0" /> : <ChevronRight className="h-4 w-4 text-zinc-500 shrink-0" />}
                            <span className="font-medium text-sm truncate">{h.title}</span>
                          </div>
                          <div className="flex items-center gap-2 ml-6">
                            <Badge variant="outline" className={`text-xs ${confidenceBadge(h.confidence)}`}>
                              {h.confidence} ({(h.confidenceScore * 100).toFixed(0)}%)
                            </Badge>
                            <Badge variant="outline" className={`text-xs ${severityBadge(h.potentialSeverity)}`}>
                              {h.potentialSeverity}
                            </Badge>
                            <span className="text-xs text-zinc-500">{h.vulnClass}</span>
                            <span className="text-xs text-zinc-600">·</span>
                            <span className="text-xs text-zinc-500">{h.affectedEndpoint}</span>
                            <span className="text-xs text-zinc-600">·</span>
                            <span className="text-xs text-zinc-500">~{h.estimatedEffort}</span>
                          </div>
                        </div>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="shrink-0 ml-2"
                          onClick={(e) => {
                            e.stopPropagation();
                            generateSubmissionMut.mutate({ hypothesisId: h.id, engagementId: selectedEngId, platform });
                          }}
                          disabled={generateSubmissionMut.isPending}
                        >
                          {generateSubmissionMut.isPending && selectedHypothesis === h.id
                            ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            : <Send className="h-3.5 w-3.5" />}
                          <span className="ml-1 text-xs">Generate</span>
                        </Button>
                      </div>

                      {expandedHypothesis === h.id && (
                        <div className="mt-4 ml-6 space-y-3 text-sm">
                          <div>
                            <Label className="text-xs text-zinc-500 uppercase tracking-wider">Description</Label>
                            <p className="text-zinc-300 mt-1">{h.description}</p>
                          </div>
                          {h.reasoning && h.reasoning.length > 0 && (
                            <div>
                              <Label className="text-xs text-zinc-500 uppercase tracking-wider">Reasoning</Label>
                              <ul className="list-disc list-inside text-zinc-400 mt-1 space-y-0.5">
                                {h.reasoning.map((r, i) => <li key={i}>{r}</li>)}
                              </ul>
                            </div>
                          )}
                          {h.verificationSteps && h.verificationSteps.length > 0 && (
                            <div>
                              <Label className="text-xs text-zinc-500 uppercase tracking-wider">Verification Steps</Label>
                              <ol className="list-decimal list-inside text-zinc-400 mt-1 space-y-0.5">
                                {h.verificationSteps.map((s, i) => (
                                  <li key={i}>{s.action} → <span className="text-zinc-500">{s.expectedOutcome}</span></li>
                                ))}
                              </ol>
                            </div>
                          )}
                          {h.supportingEvidence && h.supportingEvidence.length > 0 && (
                            <div>
                              <Label className="text-xs text-zinc-500 uppercase tracking-wider">Supporting Evidence</Label>
                              <div className="flex flex-wrap gap-1.5 mt-1">
                                {h.supportingEvidence.map((e, i) => (
                                  <Badge key={i} variant="outline" className="text-xs bg-green-950/20 border-green-800/30 text-green-400">
                                    {e.description} ({(e.confidence * 100).toFixed(0)}%)
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                          {h.chainPotential && h.chainPotential.length > 0 && (
                            <div>
                              <Label className="text-xs text-zinc-500 uppercase tracking-wider">Chain Potential</Label>
                              <div className="space-y-1 mt-1">
                                {h.chainPotential.map((c, i) => (
                                  <div key={i} className="flex items-center gap-2 text-xs text-purple-400">
                                    <ArrowRight className="h-3 w-3" />
                                    {c.chainDescription} ({c.impactMultiplier}x impact → {c.toVulnClass})
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                          {h.potentialBountyRange && (
                            <div className="flex items-center gap-2 text-xs text-emerald-400">
                              <Zap className="h-3 w-3" />
                              Estimated bounty: ${h.potentialBountyRange.min} – ${h.potentialBountyRange.max}
                            </div>
                          )}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}

                {hypotheses.length === 0 && !hypothesesQ.isLoading && (
                  <Card className="border-dashed border-2 border-zinc-700">
                    <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                      <Brain className="h-10 w-10 text-zinc-600 mb-3" />
                      <h3 className="text-sm font-medium text-zinc-400">No Hypotheses Available</h3>
                      <p className="text-xs text-zinc-500 mt-1 max-w-sm">
                        Hypotheses are auto-generated after the passive discovery phase completes.
                        Click "Regenerate" to manually trigger generation.
                      </p>
                    </CardContent>
                  </Card>
                )}
              </div>
            </ScrollArea>
          </TabsContent>

          {/* ═══ DRAFTS TAB ═══ */}
          <TabsContent value="drafts" className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-sm text-muted-foreground">
                {drafts.length > 0 ? `${drafts.length} submission drafts ready for review` : "No drafts yet — generate from hypotheses"}
              </div>
              {drafts.length > 0 && (
                <Button size="sm" variant="outline" onClick={() => setDrafts([])}>
                  Clear All Drafts
                </Button>
              )}
            </div>

            <ScrollArea className="h-[calc(100vh-340px)]">
              <div className="space-y-4">
                {drafts.map((draft) => (
                  <Card key={draft.hypothesisId} className="border-zinc-800">
                    <CardHeader className="pb-2">
                      <div className="flex items-start justify-between">
                        <div>
                          <CardTitle className="text-base">{draft.submission.title}</CardTitle>
                          <CardDescription className="mt-1">
                            From hypothesis: {draft.hypothesisTitle}
                          </CardDescription>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={`text-xs ${severityBadge(draft.submission.severity)}`}>
                            {draft.submission.severity}
                          </Badge>
                          <Badge variant="outline" className={`text-xs ${
                            draft.submission.qualityScore >= 80 ? "bg-green-500/15 text-green-400 border-green-500/30" :
                            draft.submission.qualityScore >= 60 ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                            "bg-red-500/15 text-red-400 border-red-500/30"
                          }`}>
                            Quality: {draft.submission.qualityScore}/100
                          </Badge>
                          {draft.exported && (
                            <Badge variant="outline" className="text-xs bg-blue-500/15 text-blue-400 border-blue-500/30">
                              <CheckCircle2 className="h-3 w-3 mr-1" /> Exported
                            </Badge>
                          )}
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div>
                        <Label className="text-xs text-zinc-500 uppercase tracking-wider">Summary</Label>
                        <p className="text-sm text-zinc-300 mt-1">{draft.submission.summary}</p>
                      </div>

                      <div>
                        <Label className="text-xs text-zinc-500 uppercase tracking-wider">Impact</Label>
                        <p className="text-sm text-zinc-300 mt-1">{draft.submission.impactStatement}</p>
                      </div>

                      <div>
                        <Label className="text-xs text-zinc-500 uppercase tracking-wider">
                          Reproduction Steps ({draft.submission.reproductionSteps.length})
                        </Label>
                        <ol className="list-decimal list-inside text-sm text-zinc-400 mt-1 space-y-1">
                          {draft.submission.reproductionSteps.map((step) => (
                            <li key={step.stepNumber}>
                              {step.action}
                              <span className="text-zinc-600 ml-1">→ {step.expectedResult}</span>
                            </li>
                          ))}
                        </ol>
                      </div>

                      {draft.submission.qualityIssues.length > 0 && (
                        <div className="bg-amber-950/20 border border-amber-800/30 rounded-md p-3">
                          <Label className="text-xs text-amber-400 uppercase tracking-wider flex items-center gap-1">
                            <AlertTriangle className="h-3 w-3" /> Quality Issues
                          </Label>
                          <ul className="list-disc list-inside text-xs text-amber-300/80 mt-1 space-y-0.5">
                            {draft.submission.qualityIssues.map((issue, i) => <li key={i}>{issue}</li>)}
                          </ul>
                        </div>
                      )}

                      <div className="flex items-center gap-2 pt-2">
                        <Button
                          size="sm"
                          onClick={() => handleExportDraft(draft)}
                          disabled={exportMut.isPending}
                        >
                          {exportMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" /> : <Copy className="h-3.5 w-3.5 mr-1" />}
                          Copy as {platform}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            setRejectionDialog({ open: true, draft });
                            setRejectionForm({ reason: "", detail: "", triagerFeedback: "", lessons: "" });
                          }}
                        >
                          <XCircle className="h-3.5 w-3.5 mr-1" />
                          Record Rejection
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}

                {drafts.length === 0 && (
                  <Card className="border-dashed border-2 border-zinc-700">
                    <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                      <FileText className="h-10 w-10 text-zinc-600 mb-3" />
                      <h3 className="text-sm font-medium text-zinc-400">No Drafts Yet</h3>
                      <p className="text-xs text-zinc-500 mt-1 max-w-sm">
                        Go to the Hypotheses tab and click "Generate" on individual hypotheses,
                        or use "Batch Generate Submissions" to create drafts for all high-confidence findings.
                      </p>
                    </CardContent>
                  </Card>
                )}
              </div>
            </ScrollArea>
          </TabsContent>

          {/* ═══ CALIBRATION TAB ═══ */}
          <TabsContent value="calibration" className="space-y-4">
            {calibrationQ.isLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="h-6 w-6 animate-spin text-zinc-500" />
              </div>
            ) : calibrationQ.data ? (
              <>
                <div className="grid grid-cols-3 gap-4">
                  <Card className="bg-zinc-900/50 border-zinc-800">
                    <CardContent className="py-4 px-4">
                      <div className="flex items-center gap-2 mb-2">
                        <TrendingUp className="h-4 w-4 text-blue-400" />
                        <span className="text-xs text-zinc-500 uppercase tracking-wider">Drift Status</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={`text-sm ${
                          !calibrationQ.data.drift.hasDrift ? "bg-green-500/15 text-green-400 border-green-500/30" :
                          calibrationQ.data.drift.severity === 'mild' ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                          "bg-red-500/15 text-red-400 border-red-500/30"
                        }`}>
                          {calibrationQ.data.drift.hasDrift
                            ? `${calibrationQ.data.drift.direction} (${calibrationQ.data.drift.severity})`
                            : "Well Calibrated"}
                        </Badge>
                      </div>
                      <p className="text-xs text-zinc-500 mt-2">{calibrationQ.data.drift.recommendation}</p>
                    </CardContent>
                  </Card>

                  <Card className="bg-zinc-900/50 border-zinc-800">
                    <CardContent className="py-4 px-4">
                      <div className="flex items-center gap-2 mb-2">
                        <BarChart3 className="h-4 w-4 text-purple-400" />
                        <span className="text-xs text-zinc-500 uppercase tracking-wider">Feedback Loop</span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div>
                          <span className="text-zinc-500">Rejections:</span>{" "}
                          <span className="font-medium">{calibrationQ.data.feedbackStats.totalRejectionsProcessed}</span>
                        </div>
                        <div>
                          <span className="text-zinc-500">Calibrations:</span>{" "}
                          <span className="font-medium">{calibrationQ.data.feedbackStats.totalCalibrationUpdates}</span>
                        </div>
                        <div>
                          <span className="text-zinc-500">Events:</span>{" "}
                          <span className="font-medium">{calibrationQ.data.feedbackStats.totalEventBusPublications}</span>
                        </div>
                        <div>
                          <span className="text-zinc-500">Drift Checks:</span>{" "}
                          <span className="font-medium">{calibrationQ.data.feedbackStats.driftDetectionsRun}</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-zinc-900/50 border-zinc-800">
                    <CardContent className="py-4 px-4">
                      <div className="flex items-center gap-2 mb-2">
                        <XCircle className="h-4 w-4 text-red-400" />
                        <span className="text-xs text-zinc-500 uppercase tracking-wider">Negative Examples</span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div>
                          <span className="text-zinc-500">Total:</span>{" "}
                          <span className="font-medium">{calibrationQ.data.negativeStats.totalExamples}</span>
                        </div>
                        <div>
                          <span className="text-zinc-500">FP Rate:</span>{" "}
                          <span className="font-medium">{(calibrationQ.data.negativeStats.falsePositiveRate * 100).toFixed(1)}%</span>
                        </div>
                        <div>
                          <span className="text-zinc-500">Dup Rate:</span>{" "}
                          <span className="font-medium">{(calibrationQ.data.negativeStats.duplicateRate * 100).toFixed(1)}%</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {calibrationQ.data.drift.worstVulnClasses && calibrationQ.data.drift.worstVulnClasses.length > 0 && (
                  <Card className="bg-zinc-900/50 border-zinc-800">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-amber-400" />
                        Worst Calibrated Vulnerability Classes
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {calibrationQ.data.drift.worstVulnClasses.map((vc: any, i: number) => (
                          <div key={i} className="flex items-center justify-between text-sm">
                            <span className="text-zinc-300">{vc.vulnClass}</span>
                            <div className="flex items-center gap-3">
                              <span className="text-xs text-zinc-500">{vc.sampleSize} samples</span>
                              <Badge variant="outline" className={`text-xs ${
                                vc.bias > 0 ? "bg-red-500/15 text-red-400 border-red-500/30" : "bg-blue-500/15 text-blue-400 border-blue-500/30"
                              }`}>
                                {vc.bias > 0 ? "overconfident" : "underconfident"} by {(Math.abs(vc.bias) * 100).toFixed(1)}%
                              </Badge>
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {calibrationQ.data.topPatterns && calibrationQ.data.topPatterns.length > 0 && (
                  <Card className="bg-zinc-900/50 border-zinc-800">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Eye className="h-4 w-4 text-cyan-400" />
                        Top Rejection Patterns
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {calibrationQ.data.topPatterns.map((p: any, i: number) => (
                          <div key={i} className="flex items-center justify-between text-sm">
                            <span className="text-zinc-300">{p.pattern || p.lesson || p.vulnClass || "Unknown"}</span>
                            <Badge variant="outline" className="text-xs">
                              {p.frequency || p.count || 0}x
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </>
            ) : (
              <Card className="border-dashed border-2 border-zinc-700">
                <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                  <TrendingUp className="h-10 w-10 text-zinc-600 mb-3" />
                  <h3 className="text-sm font-medium text-zinc-400">No Calibration Data</h3>
                  <p className="text-xs text-zinc-500 mt-1">
                    Calibration data will appear after submissions are recorded as accepted or rejected.
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* ═══ SCAN PRIORITIES TAB ═══ */}
          <TabsContent value="priorities" className="space-y-4">
            {prioritiesQ.isLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="h-6 w-6 animate-spin text-zinc-500" />
              </div>
            ) : prioritiesQ.data?.priorities && prioritiesQ.data.priorities.length > 0 ? (
              <div className="space-y-3">
                <p className="text-sm text-muted-foreground">
                  Scan priority adjustments derived from high-confidence hypotheses.
                  These endpoints and vuln classes should be prioritized in active scanning.
                </p>
                {(prioritiesQ.data.priorities as any[]).map((p: any, i: number) => (
                  <Card key={i} className="bg-zinc-900/50 border-zinc-800">
                    <CardContent className="py-3 px-4 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Badge variant="outline" className={`text-xs ${
                          p.priority === 'critical' ? "bg-red-600/20 text-red-300 border-red-500/40" :
                          p.priority === 'high' ? "bg-orange-600/20 text-orange-300 border-orange-500/40" :
                          "bg-yellow-600/20 text-yellow-300 border-yellow-500/40"
                        }`}>
                          {p.priority.toUpperCase()}
                        </Badge>
                        <div>
                          <span className="text-sm font-medium text-zinc-300">{p.endpoint}</span>
                          <span className="text-xs text-zinc-500 ml-2">({p.vulnClass})</span>
                        </div>
                      </div>
                      <span className="text-xs text-zinc-500 max-w-md text-right">{p.reason}</span>
                    </CardContent>
                  </Card>
                ))}
              </div>
            ) : (
              <Card className="border-dashed border-2 border-zinc-700">
                <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                  <Crosshair className="h-10 w-10 text-zinc-600 mb-3" />
                  <h3 className="text-sm font-medium text-zinc-400">No Scan Priorities</h3>
                  <p className="text-xs text-zinc-500 mt-1">
                    Scan priorities are generated from high-confidence hypotheses after recon.
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        </Tabs>
      )}

      {/* ═══ REJECTION DIALOG ═══ */}
      <Dialog open={rejectionDialog.open} onOpenChange={(open) => setRejectionDialog({ open, draft: rejectionDialog.draft })}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <XCircle className="h-5 w-5 text-red-400" />
              Record Rejection Feedback
            </DialogTitle>
            <DialogDescription>
              This rejection will be fed into the calibration loop to improve future hypothesis quality.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Rejection Reason</Label>
              <Select value={rejectionForm.reason} onValueChange={(v) => setRejectionForm(f => ({ ...f, reason: v }))}>
                <SelectTrigger>
                  <SelectValue placeholder="Select reason..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="false_positive">False Positive</SelectItem>
                  <SelectItem value="duplicate">Duplicate</SelectItem>
                  <SelectItem value="out_of_scope">Out of Scope</SelectItem>
                  <SelectItem value="informational_only">Informational Only</SelectItem>
                  <SelectItem value="not_reproducible">Not Reproducible</SelectItem>
                  <SelectItem value="intended_behavior">Intended Behavior</SelectItem>
                  <SelectItem value="insufficient_impact">Insufficient Impact</SelectItem>
                  <SelectItem value="known_issue">Known Issue</SelectItem>
                  <SelectItem value="wont_fix">Won't Fix</SelectItem>
                  <SelectItem value="invalid_vulnerability">Invalid Vulnerability</SelectItem>
                  <SelectItem value="already_patched">Already Patched</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Rejection Detail</Label>
              <Textarea
                placeholder="Describe why the submission was rejected..."
                value={rejectionForm.detail}
                onChange={(e) => setRejectionForm(f => ({ ...f, detail: e.target.value }))}
                rows={3}
              />
            </div>
            <div>
              <Label>Triager Feedback (optional)</Label>
              <Textarea
                placeholder="Copy triager's response here..."
                value={rejectionForm.triagerFeedback}
                onChange={(e) => setRejectionForm(f => ({ ...f, triagerFeedback: e.target.value }))}
                rows={2}
              />
            </div>
            <div>
              <Label>Lessons Learned (one per line)</Label>
              <Textarea
                placeholder="What should the system learn from this rejection?"
                value={rejectionForm.lessons}
                onChange={(e) => setRejectionForm(f => ({ ...f, lessons: e.target.value }))}
                rows={2}
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setRejectionDialog({ open: false })}>Cancel</Button>
              <Button
                onClick={handleRecordRejection}
                disabled={!rejectionForm.reason || !rejectionForm.detail || recordRejectionMut.isPending}
              >
                {recordRejectionMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" /> : null}
                Record Rejection
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
