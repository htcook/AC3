/**
 * ROE Warning Banner
 *
 * Displays a prominent warning when no engagement with an active ROE is selected.
 * Used on pages that perform Orange/Red tier operations:
 * - Phishing (GoPhish, Template Gen, Landing Page Builder)
 * - Exploitation (MSF Sessions, Payload Generator, Validation Engine)
 * - Emulation (Emulation Playbooks, Purple Team)
 */
import { trpc } from "@/lib/trpc";
import { Link } from "wouter";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  Clock,
  ShieldX,
  Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";

type RiskTier = "orange" | "red";

interface ROEWarningBannerProps {
  /** Which risk tier this page operates at */
  riskTier: RiskTier;
  /** Human-readable page/operation name */
  operationName: string;
  /** Optional: if an engagement is already selected, pass its ID to check ROE */
  engagementId?: number | null;
}

const TIER_LABELS: Record<RiskTier, { label: string; color: string }> = {
  orange: { label: "ORANGE", color: "text-orange-400" },
  red: { label: "RED", color: "text-red-400" },
};

export default function ROEWarningBanner({
  riskTier,
  operationName,
  engagementId,
}: ROEWarningBannerProps) {
  // Fetch all engagements to find ones with active ROE
  const { data: engagements, isLoading: engLoading } = trpc.engagements.list.useQuery();

  // If a specific engagement is provided, check its ROE status
  const { data: roeStatus, isLoading: roeLoading } = trpc.roeAudit.getROEStatus.useQuery(
    { engagementId: engagementId! },
    { enabled: !!engagementId }
  );

  // Check if any engagement has an active ROE
  const activeROEEngagements = engagements?.filter(
    (e: any) => e.roeStatus === "signed"
  ) || [];

  const hasActiveROE = engagementId
    ? roeStatus?.roeStatus === "signed"
    : activeROEEngagements.length > 0;

  const isLoading = engLoading || (engagementId ? roeLoading : false);

  // If ROE is active, show a small green confirmation bar
  if (hasActiveROE && !isLoading) {
    const roeName = engagementId
      ? roeStatus?.name
      : activeROEEngagements[0]?.name;
    const roeExpiry = engagementId
      ? roeStatus?.roeExpiryDate
      : (activeROEEngagements[0] as any)?.roeExpiryDate;

    return (
      <div className="bg-green-500/10 border border-green-500/30 px-4 py-2.5 mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs text-green-400">
          <ShieldCheck className="w-4 h-4 shrink-0" />
          <span className="font-display tracking-wider">
            ROE ACTIVE
          </span>
          <span className="text-green-400/70">
            &mdash; {roeName}
            {roeExpiry && ` (expires ${new Date(roeExpiry).toLocaleDateString()})`}
          </span>
        </div>
        <span className={`text-xs font-display tracking-wider ${TIER_LABELS[riskTier].color}`}>
          {TIER_LABELS[riskTier].label} TIER
        </span>
      </div>
    );
  }

  // Loading state
  if (isLoading) {
    return (
      <div className="bg-gray-500/10 border border-gray-500/30 px-4 py-3 mb-4">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Loader2 className="w-4 h-4 animate-spin" />
          <span className="font-display tracking-wider">CHECKING ROE STATUS...</span>
        </div>
      </div>
    );
  }

  // Determine the specific warning based on ROE status
  let statusDetail = "";
  let statusIcon = <ShieldX className="w-5 h-5 shrink-0" />;

  if (engagementId && roeStatus) {
    switch (roeStatus.roeStatus) {
      case "none":
        statusDetail = "No ROE has been uploaded for this engagement.";
        statusIcon = <ShieldX className="w-5 h-5 shrink-0" />;
        break;
      case "pending":
        statusDetail = "ROE is pending approval — not yet authorized.";
        statusIcon = <Clock className="w-5 h-5 shrink-0" />;
        break;
      case "expired":
        statusDetail = `ROE expired on ${roeStatus.roeExpiryDate ? new Date(roeStatus.roeExpiryDate).toLocaleDateString() : "unknown date"}.`;
        statusIcon = <AlertTriangle className="w-5 h-5 shrink-0" />;
        break;
      default:
        statusDetail = "No valid ROE found.";
    }
  } else {
    statusDetail = "No engagement with an active ROE exists.";
  }

  return (
    <div className="bg-red-500/10 border-2 border-red-500/40 px-4 py-4 mb-4">
      <div className="flex items-start gap-3">
        <div className="text-red-400 mt-0.5">
          {statusIcon}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="font-display text-sm tracking-wider text-red-400">
              ROE REQUIRED
            </h4>
            <span className={`text-xs font-display tracking-wider px-1.5 py-0.5 border ${
              riskTier === "red"
                ? "border-red-500/40 bg-red-500/20 text-red-400"
                : "border-orange-500/40 bg-orange-500/20 text-orange-400"
            }`}>
              {TIER_LABELS[riskTier].label} TIER
            </span>
          </div>
          <p className="text-xs text-red-400/80 mb-2">
            <strong>{operationName}</strong> operations are classified as{" "}
            <strong>{TIER_LABELS[riskTier].label}</strong> tier and require a signed Rules of
            Engagement (ROE) document before execution. {statusDetail}
          </p>
          <p className="text-xs text-muted-foreground mb-3">
            All {TIER_LABELS[riskTier].label} tier operations will be <strong>blocked</strong> by the
            ROE enforcement system until a valid, non-expired ROE is uploaded and marked as signed.
          </p>
          <Link href="/engagements">
            <Button
              variant="outline"
              size="sm"
              className="font-display tracking-wider text-xs border-red-500/40 text-red-400 hover:text-red-300 hover:border-red-500/60"
            >
              <ShieldAlert className="w-3.5 h-3.5 mr-1.5" />
              GO TO ENGAGEMENT MANAGER
              <ArrowRight className="w-3.5 h-3.5 ml-1.5" />
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
}
