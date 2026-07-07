/**
 * PlatformTour — Welcome modal that shows on first login for each platform.
 * 
 * Gated by white-label config: only shows when platformName matches the expected platform.
 * Uses localStorage to track whether the user has dismissed the tour.
 * 
 * Tour steps are role-aware and highlight features relevant to the user's role.
 */
import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { useWhiteLabel } from "@/hooks/useWhiteLabel";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
  Sparkles,
  Shield,
  BarChart3,
  Target,
  Users,
  FileText,
  AlertTriangle,
  Zap,
  ChevronRight,
  ChevronLeft,
  X,
} from "lucide-react";

// ─── Tour Step Definitions ──────────────────────────────────────────────────

interface TourStep {
  title: string;
  description: string;
  icon: React.ElementType;
  iconColor: string;
  roles: string[]; // Which roles see this step. Empty = all roles.
}

const AC3_TOUR_STEPS: TourStep[] = [
  {
    title: "Campaign Command Center",
    description: "Orchestrate offensive security campaigns from a unified dashboard. Monitor active operations, track objectives, and coordinate your red team.",
    icon: Target,
    iconColor: "text-cyan-400",
    roles: [],
  },
  {
    title: "Engagement Operations",
    description: "Manage penetration testing engagements end-to-end. From scoping and RoE to automated reconnaissance and vulnerability discovery.",
    icon: Zap,
    iconColor: "text-green-400",
    roles: [],
  },
  {
    title: "Attack Surface Mapping",
    description: "Automated asset discovery, port scanning, and service enumeration. Build comprehensive attack surface maps with passive and active reconnaissance.",
    icon: Shield,
    iconColor: "text-blue-400",
    roles: [],
  },
  {
    title: "Vulnerability Analysis",
    description: "AI-powered vulnerability assessment with Nuclei, ZAP, and custom scanners. Cross-correlate findings and generate exploitation paths.",
    icon: AlertTriangle,
    iconColor: "text-amber-400",
    roles: ["admin", "operator", "analyst"],
  },
  {
    title: "Reporting & Evidence",
    description: "Generate professional pentest reports with findings, risk ratings, and remediation recommendations. Export for client delivery.",
    icon: FileText,
    iconColor: "text-purple-400",
    roles: [],
  },
  {
    title: "Team & Access Control",
    description: "Manage operators, analysts, and clients. Control engagement access and maintain audit trails for all activities.",
    icon: Users,
    iconColor: "text-pink-400",
    roles: ["admin", "team_lead"],
  },
];

const PBS_TOUR_STEPS: TourStep[] = [
  {
    title: "Vulnerability Dashboard",
    description: "Get a real-time overview of your security posture. View critical vulnerabilities, risk scores, and remediation progress across all your assets.",
    icon: BarChart3,
    iconColor: "text-blue-400",
    roles: [],
  },
  {
    title: "Asset Management",
    description: "Track and manage all your digital assets. Organize by business unit, assign ownership, and monitor exposure across your attack surface.",
    icon: Target,
    iconColor: "text-cyan-400",
    roles: [],
  },
  {
    title: "Vulnerability Findings",
    description: "Detailed vulnerability reports with CVSS scoring, proof-of-concept evidence, and step-by-step remediation guidance prioritized by business impact.",
    icon: AlertTriangle,
    iconColor: "text-amber-400",
    roles: [],
  },
  {
    title: "Remediation Tracking",
    description: "Assign vulnerabilities to team members, set SLA deadlines, and track remediation progress with automated status updates.",
    icon: Zap,
    iconColor: "text-green-400",
    roles: ["admin", "operator", "team_lead", "analyst", "soc"],
  },
  {
    title: "Compliance & Reports",
    description: "Generate executive reports, compliance evidence, and trend analysis. Export to PDF for stakeholder presentations and audit requirements.",
    icon: FileText,
    iconColor: "text-purple-400",
    roles: ["admin", "executive", "team_lead", "client"],
  },
  {
    title: "Team Collaboration",
    description: "Manage team members, assign roles, and control access. Collaborate on findings with comments, tags, and workflow automation.",
    icon: Users,
    iconColor: "text-pink-400",
    roles: ["admin", "team_lead"],
  },
];

// ─── Component ──────────────────────────────────────────────────────────────

interface PlatformTourProps {
  /** Which platform this tour is for. Only shows if white-label platformName matches. */
  targetPlatform: "PBS" | "AC3";
}

export default function PlatformTour({ targetPlatform }: PlatformTourProps) {
  const { user } = useAuth();
  const { platformName } = useWhiteLabel();
  const [isOpen, setIsOpen] = useState(false);
  const [currentStep, setCurrentStep] = useState(-1); // -1 = welcome screen, 0+ = tour steps
  const [hasChecked, setHasChecked] = useState(false);

  const storageKey = `platform-tour-dismissed-${targetPlatform.toLowerCase()}`;

  // Determine if tour should show
  useEffect(() => {
    if (!user || hasChecked) return;

    // Show tour for any platform — the targetPlatform prop just selects which step set to use.
    // The actual platform name displayed comes from the white-label config.
    const normalizedPlatform = platformName?.toUpperCase?.() || "";
    const normalizedTarget = targetPlatform.toUpperCase();
    
    // Determine if this is the correct tour variant for the current deployment
    const isCorrectPlatform = normalizedPlatform.includes(normalizedTarget) || 
      // If platform doesn't match either variant, show the tour that matches the DashboardLayout prop
      (!normalizedPlatform.includes("PBS") && !normalizedPlatform.includes("AC3"));
    
    if (!isCorrectPlatform) {
      setHasChecked(true);
      return;
    }

    // Check if user has already dismissed
    const dismissed = localStorage.getItem(storageKey);
    if (dismissed === "true") {
      setHasChecked(true);
      return;
    }

    // Show the tour
    setIsOpen(true);
    setHasChecked(true);
  }, [user, platformName, hasChecked, storageKey, targetPlatform]);

  // Get steps filtered by user role
  const allSteps = targetPlatform === "PBS" ? PBS_TOUR_STEPS : AC3_TOUR_STEPS;
  const filteredSteps = allSteps.filter(
    (step) => step.roles.length === 0 || (user?.role && step.roles.includes(user.role))
  );

  const handleDismiss = useCallback(() => {
    localStorage.setItem(storageKey, "true");
    setIsOpen(false);
    setCurrentStep(-1);
  }, [storageKey]);

  const handleStartTour = () => {
    setCurrentStep(0);
  };

  const handleNext = () => {
    if (currentStep < filteredSteps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      handleDismiss();
    }
  };

  const handlePrev = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    } else {
      setCurrentStep(-1);
    }
  };

  if (!isOpen || !user) return null;

  const platformDisplayName = (platformName || targetPlatform).toUpperCase();
  const firstName = user?.name?.split(" ")[0] || "there";

  // Welcome screen
  if (currentStep === -1) {
    return (
      <Dialog open={isOpen} onOpenChange={(open) => !open && handleDismiss()}>
        <DialogContent className="sm:max-w-md border-2 border-primary/20 bg-card">
          <button
            onClick={handleDismiss}
            className="absolute right-4 top-4 rounded-sm opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
          >
            <X className="h-4 w-4" />
            <span className="sr-only">Close</span>
          </button>
          <div className="flex flex-col items-center text-center pt-4 pb-2">
            <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mb-4">
              <Sparkles className="w-8 h-8 text-primary" />
            </div>
            <DialogHeader className="space-y-2">
              <DialogTitle className="font-display text-2xl tracking-wider">
                WELCOME TO {platformDisplayName}
              </DialogTitle>
              <DialogDescription className="text-base text-muted-foreground">
                Hi {firstName}! Let's take a quick tour to help you get oriented with the key features available to your role.
              </DialogDescription>
            </DialogHeader>
          </div>
          <DialogFooter className="flex flex-col gap-2 sm:flex-col pt-2">
            <Button onClick={handleStartTour} className="w-full font-display tracking-wider">
              <Sparkles className="w-4 h-4 mr-2" />
              Start Tour
            </Button>
            <button
              onClick={handleDismiss}
              className="text-sm text-muted-foreground hover:text-foreground transition-colors font-medium"
            >
              Skip for now
            </button>
            <p className="text-xs text-muted-foreground/60 mt-1">
              You can replay this tour anytime from Help & Guides
            </p>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );
  }

  // Tour step view
  const step = filteredSteps[currentStep];
  const StepIcon = step.icon;
  const isLastStep = currentStep === filteredSteps.length - 1;

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && handleDismiss()}>
      <DialogContent className="sm:max-w-md border-2 border-primary/20 bg-card">
        <button
          onClick={handleDismiss}
          className="absolute right-4 top-4 rounded-sm opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
        >
          <X className="h-4 w-4" />
          <span className="sr-only">Close</span>
        </button>
        <div className="flex flex-col items-center text-center pt-4 pb-2">
          <div className={`w-14 h-14 rounded-full bg-muted/50 flex items-center justify-center mb-4`}>
            <StepIcon className={`w-7 h-7 ${step.iconColor}`} />
          </div>
          <DialogHeader className="space-y-2">
            <DialogTitle className="font-display text-xl tracking-wider">
              {step.title.toUpperCase()}
            </DialogTitle>
            <DialogDescription className="text-sm text-muted-foreground leading-relaxed">
              {step.description}
            </DialogDescription>
          </DialogHeader>
        </div>

        {/* Progress dots */}
        <div className="flex items-center justify-center gap-1.5 py-2">
          {filteredSteps.map((_, idx) => (
            <div
              key={idx}
              className={`w-2 h-2 rounded-full transition-colors ${
                idx === currentStep ? "bg-primary" : "bg-muted-foreground/20"
              }`}
            />
          ))}
        </div>

        <DialogFooter className="flex flex-row justify-between sm:justify-between pt-2">
          <Button variant="ghost" size="sm" onClick={handlePrev}>
            <ChevronLeft className="w-4 h-4 mr-1" />
            Back
          </Button>
          <span className="text-xs text-muted-foreground self-center">
            {currentStep + 1} / {filteredSteps.length}
          </span>
          <Button size="sm" onClick={handleNext}>
            {isLastStep ? "Finish" : "Next"}
            {!isLastStep && <ChevronRight className="w-4 h-4 ml-1" />}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
