/**
 * Test Plan Gate Component
 *
 * Embeddable component for the engagement pipeline that shows:
 *   - Current test plan status
 *   - Generate / Submit / Review actions
 *   - Pipeline gate status (open/closed)
 *
 * @author Harrison Cook — AceofCloud
 */

import { useState } from "react";
import { useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import {
  FileText,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  Plus,
  ExternalLink,
  Lock,
  Unlock,
  Shield,
} from "lucide-react";

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "approved":
      return <CheckCircle2 className="w-4 h-4 text-green-500" />;
    case "rejected":
      return <XCircle className="w-4 h-4 text-red-500" />;
    case "pending_review":
      return <Clock className="w-4 h-4 text-blue-500" />;
    case "revision_requested":
      return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
    default:
      return <FileText className="w-4 h-4 text-muted-foreground" />;
  }
}

function StatusLabel({ status }: { status: string }) {
  const labels: Record<string, string> = {
    draft: "Draft",
    pending_review: "Pending Review",
    approved: "Approved",
    rejected: "Rejected",
    revision_requested: "Revision Requested",
  };
  return <span>{labels[status] || status}</span>;
}

interface TestPlanGateProps {
  engagementId: number;
  engagementName: string;
  /** Whether to show the full list or just the gate status */
  compact?: boolean;
}

export default function TestPlanGate({
  engagementId,
  engagementName,
  compact = false,
}: TestPlanGateProps) {
  const [, navigate] = useLocation();
  const [planType, setPlanType] = useState<"pentest" | "red_team">("pentest");
  const utils = trpc.useUtils();

  const { data: approvalStatus, isLoading: statusLoading } =
    trpc.testPlanApproval.getApprovalStatus.useQuery({ engagementId });

  const { data: plans, isLoading: plansLoading } =
    trpc.testPlanApproval.listByEngagement.useQuery(
      { engagementId },
      { enabled: !compact }
    );

  const generateMutation = trpc.testPlanApproval.generate.useMutation({
    onSuccess: (result) => {
      toast.success(`Test plan generated (v${result.version})`);
      utils.testPlanApproval.listByEngagement.invalidate({ engagementId });
      utils.testPlanApproval.getApprovalStatus.invalidate({ engagementId });
      navigate(`/test-plan/${result.planId}`);
    },
    onError: (err) => {
      toast.error(`Generation failed: ${err.message}`);
    },
  });

  if (statusLoading) {
    return (
      <Card>
        <CardContent className="p-4">
          <div className="animate-pulse flex items-center gap-3">
            <div className="w-8 h-8 bg-muted rounded" />
            <div className="flex-1 space-y-2">
              <div className="h-4 bg-muted rounded w-48" />
              <div className="h-3 bg-muted rounded w-32" />
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  // ─── Compact Mode (Pipeline Gate Status) ──────────────────────────────

  if (compact) {
    return (
      <Card className={`border ${approvalStatus?.gateOpen ? "border-green-500/30 bg-green-500/5" : "border-yellow-500/30 bg-yellow-500/5"}`}>
        <CardContent className="p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            {approvalStatus?.gateOpen ? (
              <Unlock className="w-5 h-5 text-green-500" />
            ) : (
              <Lock className="w-5 h-5 text-yellow-500" />
            )}
            <div>
              <p className="font-medium text-sm">
                Test Plan Gate: {approvalStatus?.gateOpen ? "Open" : "Closed"}
              </p>
              <p className="text-xs text-muted-foreground">
                {approvalStatus?.gateOpen
                  ? "Approved test plan on file — active scanning authorized"
                  : approvalStatus?.pendingReviewPlanId
                  ? "Plan pending customer review"
                  : approvalStatus?.draftPlanId
                  ? "Draft plan exists — submit for review"
                  : "No test plan generated yet"}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {!approvalStatus?.gateOpen && !approvalStatus?.totalPlans && (
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  generateMutation.mutate({ engagementId, planType })
                }
                disabled={generateMutation.isPending}
                className="gap-1"
              >
                <Plus className="w-3 h-3" />
                Generate Plan
              </Button>
            )}
            {approvalStatus?.approvedPlanId && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => navigate(`/test-plan/${approvalStatus.approvedPlanId}`)}
                className="gap-1"
              >
                <ExternalLink className="w-3 h-3" />
                View
              </Button>
            )}
            {approvalStatus?.pendingReviewPlanId && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => navigate(`/test-plan/${approvalStatus.pendingReviewPlanId}`)}
                className="gap-1"
              >
                <ExternalLink className="w-3 h-3" />
                Review
              </Button>
            )}
            {approvalStatus?.draftPlanId && !approvalStatus?.pendingReviewPlanId && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => navigate(`/test-plan/${approvalStatus.draftPlanId}`)}
                className="gap-1"
              >
                <ExternalLink className="w-3 h-3" />
                Edit
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    );
  }

  // ─── Full Mode (Plan List + Generation) ───────────────────────────────

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5" />
              Test Plan Approval Gate
            </CardTitle>
            <CardDescription>
              Generate, review, and approve test plans before active scanning begins.
            </CardDescription>
          </div>

          <div className="flex items-center gap-2">
            <Select value={planType} onValueChange={(v) => setPlanType(v as typeof planType)}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="pentest">Penetration Test</SelectItem>
                <SelectItem value="red_team">Red Team Exercise</SelectItem>
              </SelectContent>
            </Select>
            <Button
              onClick={() =>
                generateMutation.mutate({ engagementId, planType })
              }
              disabled={generateMutation.isPending}
              className="gap-1"
            >
              <Plus className="w-4 h-4" />
              {generateMutation.isPending ? "Generating..." : "Generate Plan"}
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent>
        {/* Gate Status Banner */}
        <div
          className={`rounded-lg p-3 mb-4 flex items-center gap-3 ${
            approvalStatus?.gateOpen
              ? "bg-green-500/10 border border-green-500/30"
              : "bg-yellow-500/10 border border-yellow-500/30"
          }`}
        >
          {approvalStatus?.gateOpen ? (
            <Unlock className="w-5 h-5 text-green-500 shrink-0" />
          ) : (
            <Lock className="w-5 h-5 text-yellow-500 shrink-0" />
          )}
          <div className="flex-1">
            <p className="font-medium text-sm">
              Pipeline Gate: {approvalStatus?.gateOpen ? "OPEN" : "CLOSED"}
            </p>
            <p className="text-xs text-muted-foreground">
              {approvalStatus?.gateOpen
                ? "An approved test plan is on file. Active scanning phases are authorized to proceed."
                : "A customer-approved test plan is required before active scanning can begin."}
            </p>
          </div>
          {approvalStatus?.signatureHash && (
            <Badge variant="outline" className="gap-1 shrink-0">
              <Shield className="w-3 h-3" />
              Signed
            </Badge>
          )}
        </div>

        {/* Plan List */}
        {plansLoading ? (
          <div className="space-y-2">
            {[1, 2].map((i) => (
              <div key={i} className="animate-pulse flex items-center gap-3 p-3 rounded border">
                <div className="w-4 h-4 bg-muted rounded" />
                <div className="flex-1 space-y-1">
                  <div className="h-4 bg-muted rounded w-48" />
                  <div className="h-3 bg-muted rounded w-32" />
                </div>
              </div>
            ))}
          </div>
        ) : plans && plans.length > 0 ? (
          <div className="space-y-2">
            {plans.map((plan: any) => (
              <div
                key={plan.planId}
                className="flex items-center gap-3 p-3 rounded border hover:bg-muted/50 cursor-pointer transition-colors"
                onClick={() => navigate(`/test-plan/${plan.planId}`)}
              >
                <StatusIcon status={plan.status} />
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-sm truncate">{plan.title}</p>
                  <p className="text-xs text-muted-foreground">
                    v{plan.version} · <StatusLabel status={plan.status} /> ·{" "}
                    {plan.planType === "red_team" ? "Red Team" : "Pentest"} ·{" "}
                    {plan.createdAt ? new Date(plan.createdAt).toLocaleDateString() : "N/A"}
                  </p>
                </div>
                <ExternalLink className="w-4 h-4 text-muted-foreground shrink-0" />
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-muted-foreground">
            <FileText className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No test plans generated yet</p>
            <p className="text-xs">
              Generate a plan to begin the approval workflow
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
