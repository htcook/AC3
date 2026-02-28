/**
 * WorkflowLauncher — Guided Scenario Navigation with State Persistence
 * ─────────────────────────────────────────────────────────────────────
 * Replaces the need to navigate 108 sidebar items by providing
 * guided workflows that surface the right modules in sequence.
 *
 * Each workflow is a multi-step scenario with:
 * - Clear description of what it accomplishes
 * - Sequential steps that link to the right pages
 * - Persistent progress tracking (saved to DB via tRPC)
 * - Resume capability for in-progress workflows
 * - Contextual tips for each step
 */

import { useState, useCallback } from "react";
import { Link, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import {
  Crosshair, Shield, Search, Rocket, Fish, Cloud, FileText,
  ChevronRight, ChevronDown, Play, CheckCircle2, Circle,
  ArrowRight, Brain, Target, Zap, BookOpen, Activity,
  AlertTriangle, Globe2, Server, Eye, Workflow, Layers,
  ShieldCheck, Radio, Radar, Bug, ClipboardCheck, Gauge,
  ScrollText, Briefcase, BarChart3, Clock, Network,
  RotateCcw, Pause, History, Loader2, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

// ─── Workflow Definitions ────────────────────────────────────────────

interface WorkflowStep {
  id: string;
  title: string;
  description: string;
  href: string;
  icon: any;
  tip?: string;
  optional?: boolean;
}

interface WorkflowDefinition {
  id: string;
  title: string;
  subtitle: string;
  description: string;
  icon: any;
  iconColor: string;
  bgGradient: string;
  estimatedTime: string;
  difficulty: "beginner" | "intermediate" | "advanced";
  steps: WorkflowStep[];
  tags: string[];
}

const WORKFLOWS: WorkflowDefinition[] = [
  {
    id: "new-engagement",
    title: "Start a New Engagement",
    subtitle: "End-to-end red team engagement setup",
    description: "Set up a complete red team engagement from rules of engagement through domain reconnaissance, risk scoring, campaign design, and execution. This is the primary workflow for new client assessments.",
    icon: Briefcase,
    iconColor: "text-amber-400",
    bgGradient: "from-amber-500/10 to-amber-600/5",
    estimatedTime: "2-4 hours",
    difficulty: "intermediate",
    tags: ["engagement", "red team", "assessment"],
    steps: [
      { id: "roe", title: "Define Rules of Engagement", description: "Set scope, boundaries, and authorization for the assessment", href: "/roe-builder", icon: ScrollText, tip: "Start with the target organization's legal authorization and scope limitations" },
      { id: "engagement", title: "Create Engagement Record", description: "Register the engagement with client details and timeline", href: "/engagements/new", icon: Briefcase, tip: "Link the ROE document and set engagement milestones" },
      { id: "domain-intel", title: "Run Domain Intelligence", description: "Discover the target's attack surface with 27 passive recon connectors", href: "/domain-intel", icon: Search, tip: "Enter the primary domain — the pipeline runs Shodan, Censys, SecurityTrails, and 24 other sources automatically" },
      { id: "web-crawl", title: "Crawl Discovered Web Assets", description: "Scan discovered URLs for security headers, technologies, and exposed paths", href: "/web-crawler", icon: Search, tip: "Lightweight web scanner — grades security headers, detects tech stacks, finds exposed files" },
      { id: "scoring", title: "Review Risk Scoring", description: "Analyze hybrid risk scores and prioritize targets", href: "/scoring", icon: Crosshair, tip: "Focus on assets with high mission impact and low defensive posture" },
      { id: "campaign", title: "Design Campaign", description: "Build attack campaigns using discovered intelligence", href: "/campaign-execution", icon: Rocket, tip: "The AI Attack Planner can auto-generate campaigns from scan findings" },
      { id: "kill-chain", title: "Track Kill Chain", description: "Monitor engagement progress through the kill chain timeline", href: "/engagement-timeline", icon: Workflow, tip: "Use the timeline to coordinate team activities and track milestones" },
      { id: "report", title: "Generate Report", description: "Compile findings into a professional engagement report", href: "/post-engagement-report", icon: FileText, tip: "Include evidence chain, risk scores, and remediation recommendations" },
    ],
  },
  {
    id: "domain-recon",
    title: "Run Domain Reconnaissance",
    subtitle: "Comprehensive attack surface discovery",
    description: "Execute a full domain intelligence scan with 27 passive recon connectors, cross-module enrichment, and LLM-powered analysis. Discover subdomains, technologies, vulnerabilities, and exposure risks.",
    icon: Search,
    iconColor: "text-cyan-400",
    bgGradient: "from-cyan-500/10 to-cyan-600/5",
    estimatedTime: "15-30 min",
    difficulty: "beginner",
    tags: ["recon", "OSINT", "discovery", "scanning"],
    steps: [
      { id: "scan", title: "Launch Domain Scan", description: "Enter the target domain and start the intelligence pipeline", href: "/domain-intel", icon: Radar, tip: "The scan runs 27 connectors in parallel — Shodan, Censys, SecurityTrails, CISA KEV, NVD, and more" },
      { id: "results", title: "Review Scan Results", description: "Analyze discovered assets, findings, and risk scores", href: "/domain-intel/history", icon: ClipboardCheck, tip: "Check the Enrichment tab for cross-module intelligence and the Analysis tab for LLM-powered insights" },
      { id: "web-crawl", title: "Crawl Discovered Web Assets", description: "Scan discovered URLs for security headers, technologies, exposed paths, and attack surface", href: "/web-crawler", icon: Search, tip: "The web crawler analyzes HTTP headers, fingerprints tech stacks, finds exposed .env/.git files, and grades security posture" },
      { id: "compare", title: "Compare with Previous Scans", description: "Track infrastructure changes between scans", href: "/scan-compare", icon: BarChart3, tip: "Compare two scans of the same domain to detect drift and new exposure", optional: true },
      { id: "schedule", title: "Schedule Recurring Scans", description: "Set up automated monitoring for the domain", href: "/scan-scheduler", icon: Clock, tip: "Weekly scans catch infrastructure changes before attackers do", optional: true },
      { id: "threat-enrich", title: "Deep Threat Enrichment", description: "Cross-reference findings with threat intelligence", href: "/threat-enrichment", icon: Brain, tip: "Maps findings to known threat actor TTPs and active campaigns", optional: true },
    ],
  },
  {
    id: "detection-validation",
    title: "Validate Detection Coverage",
    subtitle: "Test your security controls against ATT&CK",
    description: "Run ATT&CK-mapped tests against your environment, validate SIEM/EDR detection rules, and identify coverage gaps. Essential for purple team exercises and detection engineering.",
    icon: ShieldCheck,
    iconColor: "text-green-400",
    bgGradient: "from-green-500/10 to-green-600/5",
    estimatedTime: "1-3 hours",
    difficulty: "intermediate",
    tags: ["detection", "purple team", "ATT&CK", "SIEM"],
    steps: [
      { id: "atomic", title: "Select ATT&CK Tests", description: "Choose techniques to validate from 1,400+ atomic tests", href: "/atomic-red-team", icon: Target, tip: "Start with high-priority techniques from your threat model" },
      { id: "siem", title: "Connect SIEM/EDR", description: "Link your security tools for detection correlation", href: "/siem-connectors", icon: Radio, tip: "Supports Splunk, Elastic, Sentinel, CrowdStrike, and more" },
      { id: "execute", title: "Execute Validation Tests", description: "Run selected tests and capture results", href: "/continuous-validation", icon: Play, tip: "Run in controlled environment first, then production with change control" },
      { id: "coverage", title: "Review Coverage Matrix", description: "Analyze detection gaps across ATT&CK framework", href: "/detection-coverage", icon: Layers, tip: "Focus on techniques with no detection — these are your blind spots" },
      { id: "purple", title: "Purple Team Remediation", description: "Collaborate with defenders to close detection gaps", href: "/purple-team", icon: Eye, tip: "Create detection rules for each gap and re-validate" },
      { id: "rules", title: "Validate Detection Rules", description: "Test and score your detection rule library", href: "/rule-validator", icon: ShieldCheck, tip: "The rule validator scores rules on coverage, accuracy, and performance" },
    ],
  },
  {
    id: "phishing-campaign",
    title: "Launch Phishing Campaign",
    subtitle: "Social engineering assessment",
    description: "Design and execute a phishing campaign with advanced techniques (BITB, AiTM, HTML smuggling), custom landing pages, and real-time tracking. Integrates with GoPhish for delivery.",
    icon: Fish,
    iconColor: "text-rose-400",
    bgGradient: "from-rose-500/10 to-rose-600/5",
    estimatedTime: "2-4 hours",
    difficulty: "intermediate",
    tags: ["phishing", "social engineering", "GoPhish"],
    steps: [
      { id: "template", title: "Create Email Template", description: "Design the phishing email with AI-assisted content generation", href: "/template-generator", icon: FileText, tip: "Use target intelligence from Domain Intel to craft convincing pretexts" },
      { id: "landing", title: "Build Landing Page", description: "Create a credential harvesting or payload delivery page", href: "/landing-page-builder", icon: Globe2, tip: "17 advanced techniques available including BITB, AiTM, and OAuth abuse" },
      { id: "targets", title: "Configure Target List", description: "Import or build the target recipient list", href: "/phishing-ops", icon: Crosshair, tip: "Use OSINT data from Domain Intel to identify high-value targets" },
      { id: "launch", title: "Launch Campaign", description: "Deploy the campaign through GoPhish with tracking", href: "/campaign-wizard", icon: Rocket, tip: "Schedule delivery during business hours for maximum engagement" },
      { id: "monitor", title: "Monitor Results", description: "Track opens, clicks, and credential submissions in real-time", href: "/phishing-ops", icon: Activity, tip: "The live dashboard shows campaign metrics as they happen" },
      { id: "report", title: "Generate Campaign Report", description: "Compile results with click rates, credential captures, and recommendations", href: "/reports/generate", icon: BarChart3, tip: "Include screenshots of landing pages and email templates as evidence" },
    ],
  },
  {
    id: "cloud-security",
    title: "Assess Cloud Security",
    subtitle: "Cloud infrastructure attack simulation",
    description: "Evaluate cloud security posture across AWS, Azure, and GCP. Discover misconfigurations, test attack paths, validate credentials, and assess EDR coverage in cloud environments.",
    icon: Cloud,
    iconColor: "text-blue-400",
    bgGradient: "from-blue-500/10 to-blue-600/5",
    estimatedTime: "1-2 hours",
    difficulty: "advanced",
    tags: ["cloud", "AWS", "Azure", "GCP", "credentials"],
    steps: [
      { id: "cloud-paths", title: "Discover Cloud Attack Paths", description: "Map privilege escalation and lateral movement paths", href: "/cloud-attack-paths", icon: Network, tip: "Focus on cross-account access and service principal abuse" },
      { id: "credentials", title: "Audit Cloud Credentials", description: "Review credential age, permissions, and rotation status", href: "/cloud-credentials", icon: Shield, tip: "Flag credentials older than 90 days and over-privileged service accounts" },
      { id: "rotation", title: "Test Credential Rotation", description: "Validate automated credential rotation capabilities", href: "/credential-auto-rotation", icon: Zap, tip: "Ensure rotation doesn't break dependent services" },
      { id: "edr", title: "Validate Cloud EDR", description: "Test endpoint detection in cloud workloads", href: "/edr-validation", icon: ShieldCheck, tip: "Run cloud-specific ATT&CK techniques to test detection" },
      { id: "alerts", title: "Review Credential Alerts", description: "Check for exposed or compromised credentials", href: "/credential-alerts", icon: AlertTriangle, tip: "Cross-reference with breach data from Domain Intel scans" },
    ],
  },
  {
    id: "compliance-report",
    title: "Generate Compliance Report",
    subtitle: "Regulatory compliance documentation",
    description: "Map assessment findings to compliance frameworks (NIST 800-53, FedRAMP, SOC2, ISO 27001), generate BIA reports, and export OSCAL packages for continuous monitoring.",
    icon: FileText,
    iconColor: "text-purple-400",
    bgGradient: "from-purple-500/10 to-purple-600/5",
    estimatedTime: "30-60 min",
    difficulty: "beginner",
    tags: ["compliance", "FedRAMP", "NIST", "OSCAL", "audit"],
    steps: [
      { id: "mapper", title: "Map to Compliance Framework", description: "Link findings to specific compliance controls", href: "/compliance-mapper", icon: ClipboardCheck, tip: "Supports NIST 800-53, FedRAMP, SOC2, ISO 27001, and custom frameworks" },
      { id: "bia", title: "Generate BIA Report", description: "Auto-generate Business Impact Analysis from scan data", href: "/bia-report", icon: BarChart3, tip: "Uses hybrid risk scores to quantify business impact" },
      { id: "oscal", title: "Export OSCAL Package", description: "Generate machine-readable compliance documentation", href: "/oscal-export", icon: FileText, tip: "OSCAL format is required for FedRAMP continuous monitoring" },
      { id: "evidence", title: "Compile Evidence Chain", description: "Gather and organize assessment evidence", href: "/evidence", icon: Shield, tip: "Evidence chain links findings to specific test procedures and results" },
      { id: "report", title: "Generate Final Report", description: "Produce the compliance assessment report", href: "/reports/generate", icon: FileText, tip: "Use report templates for framework-specific formatting" },
    ],
  },
];

// ─── Difficulty Badge ────────────────────────────────────────────────

function DifficultyBadge({ level }: { level: "beginner" | "intermediate" | "advanced" }) {
  const styles = {
    beginner: "bg-green-500/20 text-green-400 border-green-500/30",
    intermediate: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    advanced: "bg-red-500/20 text-red-400 border-red-500/30",
  };
  return (
    <span className={`text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 border ${styles[level]}`}>
      {level}
    </span>
  );
}

// ─── Progress Bar ───────────────────────────────────────────────────

function ProgressBar({ current, total }: { current: number; total: number }) {
  const pct = total > 0 ? Math.round((current / total) * 100) : 0;
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-border/30 overflow-hidden">
        <div
          className="h-full bg-primary transition-all duration-500"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-[10px] font-mono text-muted-foreground whitespace-nowrap">
        {current}/{total}
      </span>
    </div>
  );
}

// ─── Workflow Card ───────────────────────────────────────────────────

interface ActiveSession {
  id: number;
  workflowId: string;
  currentStepIndex: number;
  status: string;
  startedAt: string | number;
}

function WorkflowCard({
  workflow,
  onSelect,
  activeSession,
  onResume,
}: {
  workflow: WorkflowDefinition;
  onSelect: () => void;
  activeSession?: ActiveSession;
  onResume?: (sessionId: number) => void;
}) {
  const Icon = workflow.icon;
  const isActive = !!activeSession;

  return (
    <button
      onClick={isActive && onResume ? () => onResume(activeSession.id) : onSelect}
      className={`group relative w-full text-left p-5 border bg-gradient-to-br ${workflow.bgGradient} transition-all duration-300 hover:shadow-lg hover:shadow-primary/5 ${
        isActive
          ? "border-primary/50 hover:border-primary/70 ring-1 ring-primary/20"
          : "border-border/50 hover:border-primary/40"
      }`}
    >
      {/* Active indicator */}
      {isActive && (
        <div className="absolute top-2 right-2 flex items-center gap-1.5 px-2 py-0.5 bg-primary/20 border border-primary/30">
          <div className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse" />
          <span className="text-[9px] font-mono uppercase tracking-wider text-primary">In Progress</span>
        </div>
      )}

      <div className="flex items-start gap-4">
        <div className={`flex-shrink-0 p-2.5 border border-border/50 bg-background/50 ${workflow.iconColor}`}>
          <Icon className="w-5 h-5" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="font-display text-sm tracking-wider text-foreground group-hover:text-primary transition-colors">
              {workflow.title}
            </h3>
            <DifficultyBadge level={workflow.difficulty} />
          </div>
          <p className="text-xs text-muted-foreground mb-3">{workflow.subtitle}</p>

          {/* Progress bar for active workflows */}
          {isActive && (
            <div className="mb-3">
              <ProgressBar
                current={activeSession.currentStepIndex}
                total={workflow.steps.length}
              />
            </div>
          )}

          <div className="flex items-center gap-4 text-[10px] text-muted-foreground font-mono uppercase tracking-wider">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {workflow.estimatedTime}
            </span>
            <span className="flex items-center gap-1">
              <Layers className="w-3 h-3" />
              {workflow.steps.length} steps
            </span>
            {isActive && (
              <span className="flex items-center gap-1 text-primary">
                <Play className="w-3 h-3" />
                Resume
              </span>
            )}
          </div>
        </div>
        <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors flex-shrink-0 mt-1" />
      </div>
    </button>
  );
}

// ─── Workflow Detail View ────────────────────────────────────────────

function WorkflowDetail({
  workflow,
  onBack,
  session,
  onStart,
  onAdvance,
  onAbandon,
  isStarting,
}: {
  workflow: WorkflowDefinition;
  onBack: () => void;
  session?: any;
  onStart: () => void;
  onAdvance: (stepIndex: number) => void;
  onAbandon: () => void;
  isStarting: boolean;
}) {
  const [, navigate] = useLocation();
  const [expandedStep, setExpandedStep] = useState<string | null>(null);
  const Icon = workflow.icon;

  const currentStepIndex = session?.currentStepIndex ?? 0;
  const isActive = session?.status === "in_progress";
  const isCompleted = session?.status === "completed";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start gap-4">
        <button
          onClick={onBack}
          className="text-xs text-muted-foreground hover:text-primary font-mono uppercase tracking-wider flex items-center gap-1 mt-1"
        >
          <ChevronRight className="w-3 h-3 rotate-180" />
          Back
        </button>
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <div className={`p-2 border border-border/50 bg-background/50 ${workflow.iconColor}`}>
              <Icon className="w-5 h-5" />
            </div>
            <div>
              <h2 className="font-display text-lg tracking-wider text-foreground">{workflow.title}</h2>
              <div className="flex items-center gap-3 mt-1">
                <DifficultyBadge level={workflow.difficulty} />
                <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {workflow.estimatedTime}
                </span>
                {isActive && (
                  <span className="text-[10px] text-primary font-mono uppercase tracking-wider flex items-center gap-1">
                    <div className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse" />
                    In Progress
                  </span>
                )}
                {isCompleted && (
                  <span className="text-[10px] text-green-400 font-mono uppercase tracking-wider flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" />
                    Completed
                  </span>
                )}
              </div>
            </div>
          </div>
          <p className="text-sm text-muted-foreground leading-relaxed">{workflow.description}</p>

          {/* Progress bar */}
          {isActive && (
            <div className="mt-3">
              <ProgressBar current={currentStepIndex} total={workflow.steps.length} />
            </div>
          )}
        </div>
      </div>

      {/* Steps */}
      <div className="space-y-2">
        <h3 className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-3">
          Workflow Steps
        </h3>
        {workflow.steps.map((step, index) => {
          const StepIcon = step.icon;
          const isExpanded = expandedStep === step.id;
          const isStepCompleted = isActive && index < currentStepIndex;
          const isCurrentStep = isActive && index === currentStepIndex;
          const isPending = !isActive || index > currentStepIndex;

          return (
            <div
              key={step.id}
              className={`border transition-all ${
                isStepCompleted
                  ? "border-green-500/30 bg-green-500/5"
                  : isCurrentStep
                  ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
                  : step.optional
                  ? "border-dashed border-border/50 bg-card/30"
                  : "border-border/50 bg-card/30"
              }`}
            >
              <button
                onClick={() => setExpandedStep(isExpanded ? null : step.id)}
                className="w-full flex items-center gap-3 p-3 text-left hover:bg-muted/20 transition-colors"
              >
                <div className={`flex-shrink-0 w-6 h-6 border flex items-center justify-center text-[10px] font-mono ${
                  isStepCompleted
                    ? "border-green-500/50 bg-green-500/20 text-green-400"
                    : isCurrentStep
                    ? "border-primary/50 bg-primary/20 text-primary"
                    : "border-border/50 text-muted-foreground"
                }`}>
                  {isStepCompleted ? (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  ) : isCurrentStep ? (
                    <Play className="w-3 h-3" />
                  ) : (
                    index + 1
                  )}
                </div>
                <StepIcon className={`w-4 h-4 flex-shrink-0 ${
                  isStepCompleted ? "text-green-400" : isCurrentStep ? "text-primary" : "text-muted-foreground"
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`text-sm font-medium ${
                      isStepCompleted ? "text-green-400" : isCurrentStep ? "text-primary" : "text-foreground"
                    }`}>
                      {step.title}
                    </span>
                    {step.optional && (
                      <span className="text-[9px] font-mono uppercase tracking-wider text-muted-foreground border border-border/50 px-1.5 py-0.5">
                        Optional
                      </span>
                    )}
                    {isCurrentStep && (
                      <span className="text-[9px] font-mono uppercase tracking-wider text-primary border border-primary/30 px-1.5 py-0.5 bg-primary/10">
                        Current
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground truncate">{step.description}</p>
                </div>
                {isExpanded ? (
                  <ChevronDown className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                )}
              </button>
              {isExpanded && (
                <div className="px-3 pb-3 pt-0 ml-9 border-t border-border/30">
                  {step.tip && (
                    <div className="flex items-start gap-2 mt-2 mb-3 p-2 bg-primary/5 border border-primary/20">
                      <Gauge className="w-3.5 h-3.5 text-primary flex-shrink-0 mt-0.5" />
                      <p className="text-xs text-primary/80">{step.tip}</p>
                    </div>
                  )}
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-xs font-mono uppercase tracking-wider"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(step.href);
                      }}
                    >
                      <ArrowRight className="w-3 h-3 mr-1.5" />
                      Open {step.title}
                    </Button>
                    {isActive && isCurrentStep && (
                      <Button
                        size="sm"
                        className="text-xs font-mono uppercase tracking-wider bg-green-600 hover:bg-green-700"
                        onClick={(e) => {
                          e.stopPropagation();
                          onAdvance(index);
                        }}
                      >
                        <CheckCircle2 className="w-3 h-3 mr-1.5" />
                        Mark Complete
                      </Button>
                    )}
                    {isActive && isStepCompleted && (
                      <span className="text-[10px] font-mono text-green-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> Completed
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Action Bar */}
      <div className={`border p-4 ${
        isActive ? "border-primary/30 bg-primary/5" : isCompleted ? "border-green-500/30 bg-green-500/5" : "border-primary/30 bg-primary/5"
      }`}>
        <div className="flex items-center justify-between">
          <div>
            {isActive ? (
              <>
                <h4 className="text-sm font-display tracking-wider text-primary">Continue Workflow</h4>
                <p className="text-xs text-muted-foreground mt-1">
                  Step {currentStepIndex + 1} of {workflow.steps.length}: {workflow.steps[currentStepIndex]?.title}
                </p>
              </>
            ) : isCompleted ? (
              <>
                <h4 className="text-sm font-display tracking-wider text-green-400">Workflow Completed</h4>
                <p className="text-xs text-muted-foreground mt-1">All steps have been completed</p>
              </>
            ) : (
              <>
                <h4 className="text-sm font-display tracking-wider text-primary">Quick Start</h4>
                <p className="text-xs text-muted-foreground mt-1">Begin this workflow and track your progress</p>
              </>
            )}
          </div>
          <div className="flex items-center gap-2">
            {isActive && (
              <Button
                size="sm"
                variant="outline"
                className="font-mono uppercase tracking-wider text-xs text-rose-400 border-rose-500/30 hover:bg-rose-500/10"
                onClick={onAbandon}
              >
                <X className="w-3 h-3 mr-1.5" />
                Abandon
              </Button>
            )}
            {isActive ? (
              <Button
                size="sm"
                className="font-mono uppercase tracking-wider text-xs"
                onClick={() => navigate(workflow.steps[currentStepIndex]?.href ?? workflow.steps[0].href)}
              >
                <Play className="w-3 h-3 mr-1.5" />
                Go to Current Step
              </Button>
            ) : isCompleted ? (
              <Button
                size="sm"
                variant="outline"
                className="font-mono uppercase tracking-wider text-xs"
                onClick={onStart}
                disabled={isStarting}
              >
                <RotateCcw className="w-3 h-3 mr-1.5" />
                Start Again
              </Button>
            ) : (
              <Button
                size="sm"
                className="font-mono uppercase tracking-wider text-xs"
                onClick={onStart}
                disabled={isStarting}
              >
                {isStarting ? (
                  <Loader2 className="w-3 h-3 mr-1.5 animate-spin" />
                ) : (
                  <Play className="w-3 h-3 mr-1.5" />
                )}
                Begin Workflow
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Workflow History ────────────────────────────────────────────────

function WorkflowHistory({ onClose }: { onClose: () => void }) {
  const { data: history, isLoading } = trpc.workflow.getHistory.useQuery({ limit: 20 });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
          Workflow History
        </h3>
        <button
          onClick={onClose}
          className="text-xs text-muted-foreground hover:text-primary font-mono uppercase tracking-wider"
        >
          Close
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
        </div>
      ) : !history?.length ? (
        <div className="text-center py-8 text-muted-foreground">
          <History className="w-8 h-8 mx-auto mb-3 opacity-50" />
          <p className="text-sm">No workflow history yet</p>
          <p className="text-xs mt-1">Start a workflow to begin tracking progress</p>
        </div>
      ) : (
        <div className="space-y-2">
          {history.map((session: any) => {
            const wf = WORKFLOWS.find(w => w.id === session.workflowId);
            if (!wf) return null;
            const Icon = wf.icon;
            return (
              <div
                key={session.id}
                className="flex items-center gap-3 p-3 border border-border/50 bg-card/30"
              >
                <div className={`flex-shrink-0 p-1.5 border border-border/50 bg-background/50 ${wf.iconColor}`}>
                  <Icon className="w-3.5 h-3.5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-foreground">{wf.title}</span>
                    <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${
                      session.status === "completed"
                        ? "text-green-400 border-green-500/30 bg-green-500/10"
                        : session.status === "abandoned"
                        ? "text-rose-400 border-rose-500/30 bg-rose-500/10"
                        : "text-amber-400 border-amber-500/30 bg-amber-500/10"
                    }`}>
                      {session.status}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground font-mono">
                    <span>Step {session.currentStepIndex}/{wf.steps.length}</span>
                    <span>{new Date(session.startedAt).toLocaleDateString()}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────

export default function WorkflowLauncher() {
  const [selectedWorkflow, setSelectedWorkflow] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [showHistory, setShowHistory] = useState(false);

  // tRPC queries and mutations
  const { data: activeWorkflows, refetch: refetchActive } = trpc.workflow.getActive.useQuery(
    undefined,
    { refetchOnWindowFocus: false }
  );

  const startMutation = trpc.workflow.start.useMutation({
    onSuccess: () => {
      refetchActive();
      toast.success("Workflow started — your progress will be saved automatically.");
    },
    onError: (err) => {
      toast.error(`Failed to start workflow: ${err.message}`);
    },
  });

  const advanceMutation = trpc.workflow.advanceStep.useMutation({
    onSuccess: (data) => {
      refetchActive();
      if (data?.status === "completed") {
        toast.success("Workflow completed! All steps have been finished.");
      } else {
        toast.success("Step completed — moving to the next step.");
      }
    },
    onError: (err) => {
      toast.error(`Failed to advance step: ${err.message}`);
    },
  });

  const abandonMutation = trpc.workflow.abandon.useMutation({
    onSuccess: () => {
      refetchActive();
      setSelectedWorkflow(null);
      toast.success("Workflow abandoned. You can start a new one anytime.");
    },
    onError: (err) => {
      toast.error(`Failed to abandon workflow: ${err.message}`);
    },
  });

  // Find active session for a given workflow
  const getActiveSession = useCallback(
    (workflowId: string): ActiveSession | undefined => {
      return (activeWorkflows as any[])?.find(
        (s: any) => s.workflowId === workflowId && s.status === "in_progress"
      );
    },
    [activeWorkflows]
  );

  const selected = WORKFLOWS.find(w => w.id === selectedWorkflow);
  const activeSession = selectedWorkflow ? getActiveSession(selectedWorkflow) : undefined;

  const filteredWorkflows = searchQuery
    ? WORKFLOWS.filter(w =>
        w.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        w.subtitle.toLowerCase().includes(searchQuery.toLowerCase()) ||
        w.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase())) ||
        w.steps.some(s => s.title.toLowerCase().includes(searchQuery.toLowerCase()))
      )
    : WORKFLOWS;

  const activeCount = (activeWorkflows as any[])?.filter((s: any) => s.status === "in_progress").length ?? 0;

  if (showHistory) {
    return <WorkflowHistory onClose={() => setShowHistory(false)} />;
  }

  if (selected) {
    return (
      <WorkflowDetail
        workflow={selected}
        onBack={() => setSelectedWorkflow(null)}
        session={activeSession}
        onStart={() => startMutation.mutate({ workflowId: selected.id })}
        onAdvance={(stepIndex) =>
          activeSession &&
          advanceMutation.mutate({
            sessionId: activeSession.id,
            completedStepIndex: stepIndex,
          })
        }
        onAbandon={() =>
          activeSession && abandonMutation.mutate({ sessionId: activeSession.id })
        }
        isStarting={startMutation.isPending}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="font-display text-lg tracking-wider text-foreground">Mission Workflows</h2>
          <p className="text-sm text-muted-foreground mt-1">
            Guided scenarios that surface the right modules in sequence. Choose a workflow to get started.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {activeCount > 0 && (
            <span className="text-[10px] font-mono uppercase tracking-wider text-primary flex items-center gap-1.5 px-2 py-1 border border-primary/30 bg-primary/10">
              <div className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse" />
              {activeCount} Active
            </span>
          )}
          <Button
            size="sm"
            variant="outline"
            className="text-xs font-mono uppercase tracking-wider"
            onClick={() => setShowHistory(true)}
          >
            <History className="w-3 h-3 mr-1.5" />
            History
          </Button>
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <input
          type="text"
          placeholder="Search workflows... (e.g., phishing, recon, compliance)"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full pl-10 pr-4 py-2.5 bg-background border border-border/50 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary/50 font-mono"
        />
      </div>

      {/* Workflow Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {filteredWorkflows.map(workflow => (
          <WorkflowCard
            key={workflow.id}
            workflow={workflow}
            onSelect={() => setSelectedWorkflow(workflow.id)}
            activeSession={getActiveSession(workflow.id)}
            onResume={(sessionId) => setSelectedWorkflow(workflow.id)}
          />
        ))}
      </div>

      {filteredWorkflows.length === 0 && (
        <div className="text-center py-12 text-muted-foreground">
          <Search className="w-8 h-8 mx-auto mb-3 opacity-50" />
          <p className="text-sm">No workflows match "{searchQuery}"</p>
          <p className="text-xs mt-1">Try searching for "recon", "phishing", or "compliance"</p>
        </div>
      )}

      {/* Power User Tip */}
      <div className="border border-border/30 bg-muted/10 p-3 flex items-start gap-3">
        <BookOpen className="w-4 h-4 text-muted-foreground flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-xs text-muted-foreground">
            <span className="text-foreground font-medium">Power users:</span> All 108 modules are still accessible via the sidebar navigation.
            Workflows provide guided paths through the most common scenarios. Your progress is automatically saved and can be resumed anytime.
          </p>
        </div>
      </div>
    </div>
  );
}
