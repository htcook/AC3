/**
 * Test Plan Review Page
 *
 * Customer-facing review interface for penetration test and red team exercise plans.
 * Supports:
 *   - Markdown-rendered plan viewing
 *   - Approve / Reject / Request Revision workflow
 *   - Version history tracking
 *   - Digital signature audit trail
 *
 * @author Harrison Cook — AceofCloud
 */

import { useState, useMemo } from "react";
import { useRoute, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { Streamdown } from "streamdown";
import {
  FileText,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  Send,
  RotateCcw,
  Trash2,
  Shield,
  History,
  ArrowLeft,
  Download,
  Copy,
  FileCheck,
} from "lucide-react";

// ─── Status Badge ─────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "outline"; icon: React.ReactNode }> = {
    draft: { label: "Draft", variant: "secondary", icon: <FileText className="w-3 h-3" /> },
    pending_review: { label: "Pending Review", variant: "default", icon: <Clock className="w-3 h-3" /> },
    approved: { label: "Approved", variant: "default", icon: <CheckCircle2 className="w-3 h-3" /> },
    rejected: { label: "Rejected", variant: "destructive", icon: <XCircle className="w-3 h-3" /> },
    revision_requested: { label: "Revision Requested", variant: "outline", icon: <AlertTriangle className="w-3 h-3" /> },
  };

  const c = config[status] || config.draft;

  return (
    <Badge variant={c.variant} className="gap-1">
      {c.icon}
      {c.label}
    </Badge>
  );
}

// ─── Plan Viewer ──────────────────────────────────────────────────────────

function PlanViewer({ content }: { content: string }) {
  return (
    <div className="prose prose-invert max-w-none prose-headings:text-foreground prose-p:text-muted-foreground prose-strong:text-foreground prose-li:text-muted-foreground prose-table:text-muted-foreground">
      <Streamdown>{content}</Streamdown>
    </div>
  );
}

// ─── Review Dialog ────────────────────────────────────────────────────────

function ReviewDialog({
  planId,
  planTitle,
  onSuccess,
}: {
  planId: string;
  planTitle: string;
  onSuccess: () => void;
}) {
  const [action, setAction] = useState<"approve" | "reject" | "request_revision">("approve");
  const [comments, setComments] = useState("");
  const [rejectionReason, setRejectionReason] = useState("");
  const [revisionNotes, setRevisionNotes] = useState("");
  const [open, setOpen] = useState(false);

  const reviewMutation = trpc.testPlanApproval.review.useMutation({
    onSuccess: (result) => {
      toast.success(
        action === "approve"
          ? "Test plan approved — pipeline gate is now open"
          : action === "reject"
          ? "Test plan rejected"
          : "Revision requested"
      );
      setOpen(false);
      setComments("");
      setRejectionReason("");
      setRevisionNotes("");
      onSuccess();
    },
    onError: (err) => {
      toast.error(`Review failed: ${err.message}`);
    },
  });

  const handleSubmit = () => {
    reviewMutation.mutate({
      planId,
      action,
      comments: comments || undefined,
      rejectionReason: action === "reject" ? rejectionReason || undefined : undefined,
      revisionNotes: action === "request_revision" ? revisionNotes || undefined : undefined,
    });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="default" className="gap-2">
          <FileCheck className="w-4 h-4" />
          Review Plan
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Review Test Plan</DialogTitle>
          <DialogDescription>{planTitle}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label>Decision</Label>
            <Select value={action} onValueChange={(v) => setAction(v as typeof action)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="approve">
                  <span className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-green-500" />
                    Approve
                  </span>
                </SelectItem>
                <SelectItem value="reject">
                  <span className="flex items-center gap-2">
                    <XCircle className="w-4 h-4 text-red-500" />
                    Reject
                  </span>
                </SelectItem>
                <SelectItem value="request_revision">
                  <span className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-yellow-500" />
                    Request Revision
                  </span>
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>Comments (optional)</Label>
            <Textarea
              value={comments}
              onChange={(e) => setComments(e.target.value)}
              placeholder="General comments about the plan..."
              rows={3}
            />
          </div>

          {action === "reject" && (
            <div className="space-y-2">
              <Label>Rejection Reason</Label>
              <Textarea
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                placeholder="Explain why the plan is being rejected..."
                rows={3}
              />
            </div>
          )}

          {action === "request_revision" && (
            <div className="space-y-2">
              <Label>Revision Notes</Label>
              <Textarea
                value={revisionNotes}
                onChange={(e) => setRevisionNotes(e.target.value)}
                placeholder="Describe what changes are needed..."
                rows={3}
              />
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={reviewMutation.isPending}
            variant={action === "approve" ? "default" : action === "reject" ? "destructive" : "outline"}
          >
            {reviewMutation.isPending ? "Submitting..." : `Submit ${action === "approve" ? "Approval" : action === "reject" ? "Rejection" : "Revision Request"}`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Submit for Review Dialog ─────────────────────────────────────────────

function SubmitForReviewDialog({
  planId,
  onSuccess,
}: {
  planId: string;
  onSuccess: () => void;
}) {
  const [reviewerName, setReviewerName] = useState("");
  const [reviewerEmail, setReviewerEmail] = useState("");
  const [open, setOpen] = useState(false);

  const submitMutation = trpc.testPlanApproval.submitForReview.useMutation({
    onSuccess: () => {
      toast.success("Plan submitted for review");
      setOpen(false);
      onSuccess();
    },
    onError: (err) => {
      toast.error(`Submit failed: ${err.message}`);
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="default" className="gap-2">
          <Send className="w-4 h-4" />
          Submit for Review
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Submit for Customer Review</DialogTitle>
          <DialogDescription>
            Optionally specify the reviewer's details for tracking.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label>Reviewer Name (optional)</Label>
            <Input
              value={reviewerName}
              onChange={(e) => setReviewerName(e.target.value)}
              placeholder="e.g., John Smith"
            />
          </div>
          <div className="space-y-2">
            <Label>Reviewer Email (optional)</Label>
            <Input
              type="email"
              value={reviewerEmail}
              onChange={(e) => setReviewerEmail(e.target.value)}
              placeholder="e.g., john@customer.com"
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            onClick={() =>
              submitMutation.mutate({
                planId,
                reviewerName: reviewerName || undefined,
                reviewerEmail: reviewerEmail || undefined,
              })
            }
            disabled={submitMutation.isPending}
          >
            {submitMutation.isPending ? "Submitting..." : "Submit for Review"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main Page Component ──────────────────────────────────────────────────

export default function TestPlanReview() {
  const [, params] = useRoute("/test-plan/:planId");
  const [, navigate] = useLocation();
  const { user } = useAuth();
  const planId = params?.planId;

  const utils = trpc.useUtils();

  const { data: plan, isLoading, error } = trpc.testPlanApproval.get.useQuery(
    { planId: planId || "" },
    { enabled: !!planId }
  );

  const regenerateMutation = trpc.testPlanApproval.regenerate.useMutation({
    onSuccess: (result) => {
      toast.success(`Plan regenerated (v${result.version})`);
      navigate(`/test-plan/${result.planId}`);
    },
    onError: (err) => {
      toast.error(`Regeneration failed: ${err.message}`);
    },
  });

  const deleteMutation = trpc.testPlanApproval.deleteDraft.useMutation({
    onSuccess: () => {
      toast.success("Draft plan deleted");
      navigate(-1);
    },
    onError: (err) => {
      toast.error(`Delete failed: ${err.message}`);
    },
  });

  const handleCopyContent = () => {
    if (plan?.content) {
      navigator.clipboard.writeText(plan.content);
      toast.success("Plan content copied to clipboard");
    }
  };

  const handleRefresh = () => {
    if (planId) {
      utils.testPlanApproval.get.invalidate({ planId });
    }
  };

  if (!planId) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-muted-foreground">No plan ID specified</p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="p-6 space-y-4 max-w-5xl mx-auto">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-4 w-96" />
        <Skeleton className="h-[600px] w-full" />
      </div>
    );
  }

  if (error || !plan) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <XCircle className="w-12 h-12 text-destructive" />
        <p className="text-muted-foreground">
          {error?.message || "Test plan not found"}
        </p>
        <Button variant="outline" onClick={() => navigate(-1)}>
          <ArrowLeft className="w-4 h-4 mr-2" />
          Go Back
        </Button>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate(-1)}
            className="gap-1 -ml-2 mb-1"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </Button>
          <h1 className="text-2xl font-bold">{plan.title}</h1>
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <StatusBadge status={plan.status} />
            <span>Version {plan.version}</span>
            <span>·</span>
            <span>
              {plan.planType === "red_team" ? "Red Team Exercise" : "Penetration Test"}
            </span>
            {plan.signatureHash && (
              <>
                <span>·</span>
                <span className="flex items-center gap-1 text-green-500">
                  <Shield className="w-3 h-3" />
                  Signed
                </span>
              </>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2">
          {plan.status === "draft" && (
            <>
              <SubmitForReviewDialog
                planId={plan.planId}
                onSuccess={handleRefresh}
              />
              <Button
                variant="outline"
                size="sm"
                onClick={() => regenerateMutation.mutate({ planId: plan.planId })}
                disabled={regenerateMutation.isPending}
                className="gap-1"
              >
                <RotateCcw className="w-4 h-4" />
                Regenerate
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => deleteMutation.mutate({ planId: plan.planId })}
                disabled={deleteMutation.isPending}
                className="gap-1 text-destructive hover:text-destructive"
              >
                <Trash2 className="w-4 h-4" />
              </Button>
            </>
          )}

          {plan.status === "pending_review" && (
            <ReviewDialog
              planId={plan.planId}
              planTitle={plan.title}
              onSuccess={handleRefresh}
            />
          )}

          {(plan.status === "rejected" || plan.status === "revision_requested") && (
            <Button
              variant="default"
              size="sm"
              onClick={() => regenerateMutation.mutate({ planId: plan.planId })}
              disabled={regenerateMutation.isPending}
              className="gap-1"
            >
              <RotateCcw className="w-4 h-4" />
              Regenerate Plan
            </Button>
          )}

          <Button variant="outline" size="sm" onClick={handleCopyContent} className="gap-1">
            <Copy className="w-4 h-4" />
            Copy
          </Button>
        </div>
      </div>

      <Separator />

      {/* Review feedback (if any) */}
      {(plan.reviewComments || plan.rejectionReason || plan.revisionNotes) && (
        <Card className="border-yellow-500/30 bg-yellow-500/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-500" />
              Review Feedback
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {plan.reviewComments && (
              <div>
                <span className="font-medium text-muted-foreground">Comments: </span>
                {plan.reviewComments}
              </div>
            )}
            {plan.rejectionReason && (
              <div>
                <span className="font-medium text-destructive">Rejection Reason: </span>
                {plan.rejectionReason}
              </div>
            )}
            {plan.revisionNotes && (
              <div>
                <span className="font-medium text-yellow-500">Revision Notes: </span>
                {plan.revisionNotes}
              </div>
            )}
            {plan.reviewedAt && (
              <div className="text-xs text-muted-foreground">
                Reviewed: {new Date(plan.reviewedAt).toLocaleString()}
                {plan.reviewerName && ` by ${plan.reviewerName}`}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Approval confirmation (if approved) */}
      {plan.status === "approved" && (
        <Card className="border-green-500/30 bg-green-500/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-green-500" />
              Plan Approved
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm space-y-1">
            <div>
              Approved: {plan.approvedAt ? new Date(plan.approvedAt).toLocaleString() : "N/A"}
              {plan.reviewerName && ` by ${plan.reviewerName}`}
            </div>
            {plan.signatureHash && (
              <div className="font-mono text-xs text-muted-foreground">
                Signature: {plan.signatureHash.slice(0, 16)}...{plan.signatureHash.slice(-8)}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Plan Content */}
      <Tabs defaultValue="rendered">
        <TabsList>
          <TabsTrigger value="rendered">Rendered Plan</TabsTrigger>
          <TabsTrigger value="raw">Raw Markdown</TabsTrigger>
          <TabsTrigger value="metadata">Metadata</TabsTrigger>
        </TabsList>

        <TabsContent value="rendered" className="mt-4">
          <Card>
            <CardContent className="p-6">
              <PlanViewer content={plan.content} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="raw" className="mt-4">
          <Card>
            <CardContent className="p-6">
              <pre className="whitespace-pre-wrap text-sm text-muted-foreground font-mono leading-relaxed">
                {plan.content}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="metadata" className="mt-4">
          <Card>
            <CardContent className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Plan ID:</span>
                  <span className="ml-2 font-mono">{plan.planId}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Engagement ID:</span>
                  <span className="ml-2">{plan.engagementId}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Plan Type:</span>
                  <span className="ml-2">
                    {plan.planType === "red_team" ? "Red Team Exercise" : "Penetration Test"}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Version:</span>
                  <span className="ml-2">{plan.version}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Status:</span>
                  <span className="ml-2"><StatusBadge status={plan.status} /></span>
                </div>
                <div>
                  <span className="text-muted-foreground">Created:</span>
                  <span className="ml-2">
                    {plan.createdAt ? new Date(plan.createdAt).toLocaleString() : "N/A"}
                  </span>
                </div>
                {plan.submittedAt && (
                  <div>
                    <span className="text-muted-foreground">Submitted:</span>
                    <span className="ml-2">{new Date(plan.submittedAt).toLocaleString()}</span>
                  </div>
                )}
                {plan.reviewedAt && (
                  <div>
                    <span className="text-muted-foreground">Reviewed:</span>
                    <span className="ml-2">{new Date(plan.reviewedAt).toLocaleString()}</span>
                  </div>
                )}
                {plan.approvedAt && (
                  <div>
                    <span className="text-muted-foreground">Approved:</span>
                    <span className="ml-2">{new Date(plan.approvedAt).toLocaleString()}</span>
                  </div>
                )}
                {plan.signatureHash && (
                  <div className="col-span-2">
                    <span className="text-muted-foreground">Signature Hash:</span>
                    <span className="ml-2 font-mono text-xs break-all">{plan.signatureHash}</span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
