/**
 * VA Engagement Creation Wizard
 * 
 * Multi-step wizard for creating Vulnerability Assessment engagements.
 * Steps: Profile Selection → Target Configuration → Framework Selection → Review & Launch
 */

import { useState, useMemo, useCallback } from "react";
import { useLocation } from "wouter";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Shield, ChevronRight, ChevronLeft, Check, Target, FileText,
  Layers, Rocket, AlertTriangle, Info, Plus, X, Scan, Lock,
  CheckCircle2, Clock, Zap, ShieldCheck, Building2, Stethoscope,
  Eye, ArrowRight,
} from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface VerificationProfile {
  id: string;
  name: string;
  description: string;
  category: string;
  maxVerificationDepth: string;
  complianceFrameworks: string[];
  scannerConfig: {
    enabledScanners: string[];
  };
  reportConfig: {
    includeComplianceMapping: boolean;
    includeRemediationTimeline: boolean;
  };
}

type WizardStep = 'profile' | 'targets' | 'frameworks' | 'review';

const STEPS: { id: WizardStep; label: string; icon: React.ElementType }[] = [
  { id: 'profile', label: 'Assessment Profile', icon: Shield },
  { id: 'targets', label: 'Targets', icon: Target },
  { id: 'frameworks', label: 'Compliance Frameworks', icon: FileText },
  { id: 'review', label: 'Review & Launch', icon: Rocket },
];

const PROFILE_ICONS: Record<string, React.ElementType> = {
  'standard-va': Scan,
  'compliance-pci-asv': Lock,
  'compliance-fedramp-conmon': Building2,
  'compliance-hipaa': Stethoscope,
  'compliance-soc2': ShieldCheck,
  'deep-assessment': Eye,
  'continuous-monitoring': Clock,
};

const PROFILE_COLORS: Record<string, string> = {
  'standard-va': 'border-emerald-500/30 bg-emerald-500/5',
  'compliance-pci-asv': 'border-blue-500/30 bg-blue-500/5',
  'compliance-fedramp-conmon': 'border-indigo-500/30 bg-indigo-500/5',
  'compliance-hipaa': 'border-rose-500/30 bg-rose-500/5',
  'compliance-soc2': 'border-violet-500/30 bg-violet-500/5',
  'deep-assessment': 'border-amber-500/30 bg-amber-500/5',
  'continuous-monitoring': 'border-cyan-500/30 bg-cyan-500/5',
};

const AVAILABLE_FRAMEWORKS = [
  { id: 'nist-800-53', name: 'NIST SP 800-53 Rev 5', category: 'Federal', description: 'Security and privacy controls for federal information systems' },
  { id: 'pci-dss-v4', name: 'PCI DSS v4.0', category: 'Industry', description: 'Payment Card Industry Data Security Standard' },
  { id: 'hipaa-security', name: 'HIPAA Security Rule', category: 'Healthcare', description: 'Health Insurance Portability and Accountability Act' },
  { id: 'soc2-tsc', name: 'SOC 2 Trust Services Criteria', category: 'Audit', description: 'Service Organization Control 2 reporting framework' },
  { id: 'iso-27001', name: 'ISO 27001:2022', category: 'International', description: 'Information security management systems' },
  { id: 'cis-controls-v8', name: 'CIS Controls v8', category: 'Best Practice', description: 'Center for Internet Security critical security controls' },
  { id: 'cmmc-l2', name: 'CMMC Level 2', category: 'Defense', description: 'Cybersecurity Maturity Model Certification' },
  { id: 'fedramp-moderate', name: 'FedRAMP Moderate', category: 'Federal', description: 'Federal Risk and Authorization Management Program' },
];

// ─── Component ─────────────────────────────────────────────────────────────────

export default function VAWizard() {
  const [, navigate] = useLocation();
  const [currentStep, setCurrentStep] = useState<WizardStep>('profile');
  const [selectedProfileId, setSelectedProfileId] = useState<string>('');
  const [engagementName, setEngagementName] = useState('');
  const [targets, setTargets] = useState<string[]>([]);
  const [targetInput, setTargetInput] = useState('');
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);
  const [isLaunching, setIsLaunching] = useState(false);

  // Fetch verification profiles
  const { data: profiles, isLoading: profilesLoading } = trpc.vaBugBounty.listVerificationProfiles.useQuery();

  // Build pipeline config mutation
  const buildConfig = trpc.vaBugBounty.buildVAPipelineConfig.useMutation();

  const currentStepIndex = STEPS.findIndex(s => s.id === currentStep);
  const selectedProfile = profiles?.find((p: VerificationProfile) => p.id === selectedProfileId);

  // Auto-select frameworks from profile
  const profileFrameworks = useMemo(() => {
    if (!selectedProfile) return [];
    return selectedProfile.complianceFrameworks || [];
  }, [selectedProfile]);

  // Merge profile frameworks with user-selected
  const allFrameworks = useMemo(() => {
    const set = new Set([...profileFrameworks, ...selectedFrameworks]);
    return Array.from(set);
  }, [profileFrameworks, selectedFrameworks]);

  const canProceed = useCallback(() => {
    switch (currentStep) {
      case 'profile': return !!selectedProfileId;
      case 'targets': return targets.length > 0 && engagementName.trim().length > 0;
      case 'frameworks': return true; // Frameworks are optional
      case 'review': return true;
      default: return false;
    }
  }, [currentStep, selectedProfileId, targets, engagementName]);

  const handleNext = () => {
    if (currentStepIndex < STEPS.length - 1) {
      setCurrentStep(STEPS[currentStepIndex + 1].id);
    }
  };

  const handleBack = () => {
    if (currentStepIndex > 0) {
      setCurrentStep(STEPS[currentStepIndex - 1].id);
    }
  };

  const handleAddTargets = () => {
    const newTargets = targetInput
      .split(/[\n,;]+/)
      .map(t => t.trim())
      .filter(t => t.length > 0 && !targets.includes(t));
    if (newTargets.length > 0) {
      setTargets(prev => [...prev, ...newTargets]);
      setTargetInput('');
    }
  };

  const handleRemoveTarget = (target: string) => {
    setTargets(prev => prev.filter(t => t !== target));
  };

  const toggleFramework = (fwId: string) => {
    setSelectedFrameworks(prev =>
      prev.includes(fwId)
        ? prev.filter(f => f !== fwId)
        : [...prev, fwId]
    );
  };

  const handleLaunch = async () => {
    setIsLaunching(true);
    try {
      const config = await buildConfig.mutateAsync({
        engagementId: 0, // Will be assigned by backend
        profileId: selectedProfileId,
        targets,
        selectedFrameworks: allFrameworks,
      });
      toast.success('VA Pipeline configured successfully', {
        description: `${config.phases.length} phases ready for ${targets.length} targets`,
      });
      // Navigate to engagement ops or pipeline view
      navigate('/engagement-ops');
    } catch (err: any) {
      toast.error('Failed to launch VA pipeline', { description: err.message });
    } finally {
      setIsLaunching(false);
    }
  };

  return (
    <div className="min-h-screen p-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
            <Shield className="h-5 w-5 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Vulnerability Assessment Wizard</h1>
            <p className="text-sm text-muted-foreground">
              Configure and launch a multi-scanner vulnerability assessment with compliance mapping, finding normalization, and automated reporting.
            </p>
          </div>
        </div>
      </div>

      {/* Step Indicator */}
      <div className="flex items-center gap-2 mb-8 p-4 rounded-lg bg-card border border-border">
        {STEPS.map((step, i) => {
          const StepIcon = step.icon;
          const isActive = step.id === currentStep;
          const isComplete = i < currentStepIndex;
          return (
            <div key={step.id} className="flex items-center gap-2 flex-1">
              <button
                onClick={() => i <= currentStepIndex && setCurrentStep(step.id)}
                className={`flex items-center gap-2 px-3 py-2 rounded-md transition-all text-sm font-medium ${
                  isActive
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                    : isComplete
                    ? 'text-emerald-400/70 hover:bg-muted/50 cursor-pointer'
                    : 'text-muted-foreground'
                }`}
                disabled={i > currentStepIndex}
              >
                {isComplete ? (
                  <CheckCircle2 className="h-4 w-4" />
                ) : (
                  <StepIcon className="h-4 w-4" />
                )}
                <span className="hidden sm:inline">{step.label}</span>
              </button>
              {i < STEPS.length - 1 && (
                <ChevronRight className="h-4 w-4 text-muted-foreground/40 flex-shrink-0" />
              )}
            </div>
          );
        })}
      </div>

      {/* Step Content */}
      <div className="mb-8">
        {currentStep === 'profile' && (
          <ProfileStep
            profiles={profiles || []}
            loading={profilesLoading}
            selectedId={selectedProfileId}
            onSelect={setSelectedProfileId}
          />
        )}
        {currentStep === 'targets' && (
          <TargetsStep
            engagementName={engagementName}
            onNameChange={setEngagementName}
            targets={targets}
            targetInput={targetInput}
            onTargetInputChange={setTargetInput}
            onAddTargets={handleAddTargets}
            onRemoveTarget={handleRemoveTarget}
            selectedProfile={selectedProfile}
          />
        )}
        {currentStep === 'frameworks' && (
          <FrameworksStep
            selectedFrameworks={allFrameworks}
            profileFrameworks={profileFrameworks}
            onToggle={toggleFramework}
          />
        )}
        {currentStep === 'review' && (
          <ReviewStep
            profile={selectedProfile}
            engagementName={engagementName}
            targets={targets}
            frameworks={allFrameworks}
          />
        )}
      </div>

      {/* Navigation */}
      <div className="flex items-center justify-between pt-4 border-t border-border">
        <Button
          variant="outline"
          onClick={handleBack}
          disabled={currentStepIndex === 0}
          className="gap-2"
        >
          <ChevronLeft className="h-4 w-4" />
          Back
        </Button>
        <div className="flex items-center gap-3">
          <span className="text-xs text-muted-foreground">
            Step {currentStepIndex + 1} of {STEPS.length}
          </span>
          {currentStep === 'review' ? (
            <Button
              onClick={handleLaunch}
              disabled={isLaunching || !canProceed()}
              className="gap-2 bg-emerald-600 hover:bg-emerald-700"
            >
              {isLaunching ? (
                <>
                  <div className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Launching...
                </>
              ) : (
                <>
                  <Rocket className="h-4 w-4" />
                  Launch VA Pipeline
                </>
              )}
            </Button>
          ) : (
            <Button
              onClick={handleNext}
              disabled={!canProceed()}
              className="gap-2"
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Step: Profile Selection ───────────────────────────────────────────────────

function ProfileStep({
  profiles,
  loading,
  selectedId,
  onSelect,
}: {
  profiles: VerificationProfile[];
  loading: boolean;
  selectedId: string;
  onSelect: (id: string) => void;
}) {
  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <Card key={i} className="animate-pulse">
            <CardHeader><div className="h-5 w-32 bg-muted rounded" /><div className="h-3 w-48 bg-muted/50 rounded mt-2" /></CardHeader>
          </Card>
        ))}
      </div>
    );
  }

  return (
    <div>
      <div className="mb-4">
        <h2 className="text-lg font-semibold">Choose Assessment Profile</h2>
        <p className="text-sm text-muted-foreground">
          Each profile configures scanner depth, verification boundaries, compliance mapping, and reporting format.
          The profile determines what the VA pipeline can and cannot do — no exploitation is ever performed.
        </p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {profiles.map((profile: VerificationProfile) => {
          const Icon = PROFILE_ICONS[profile.id] || Shield;
          const colorClass = PROFILE_COLORS[profile.id] || 'border-border bg-card';
          const isSelected = selectedId === profile.id;
          return (
            <Card
              key={profile.id}
              className={`cursor-pointer transition-all hover:shadow-md ${
                isSelected
                  ? 'ring-2 ring-emerald-500 border-emerald-500/50 bg-emerald-500/5'
                  : colorClass
              }`}
              onClick={() => onSelect(profile.id)}
            >
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${isSelected ? 'bg-emerald-500/20' : 'bg-muted'}`}>
                      <Icon className={`h-5 w-5 ${isSelected ? 'text-emerald-400' : 'text-muted-foreground'}`} />
                    </div>
                    <div>
                      <CardTitle className="text-base">{profile.name}</CardTitle>
                      <Badge variant="outline" className="mt-1 text-[10px]">{profile.category}</Badge>
                    </div>
                  </div>
                  {isSelected && (
                    <div className="p-1 rounded-full bg-emerald-500">
                      <Check className="h-3 w-3 text-white" />
                    </div>
                  )}
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                <p className="text-xs text-muted-foreground mb-3">{profile.description}</p>
                <div className="flex flex-wrap gap-1.5">
                  <Badge variant="secondary" className="text-[10px]">
                    Depth: {profile.maxVerificationDepth}
                  </Badge>
                  <Badge variant="secondary" className="text-[10px]">
                    {profile.scannerConfig.enabledScanners.length} scanners
                  </Badge>
                  {profile.complianceFrameworks.length > 0 && (
                    <Badge variant="secondary" className="text-[10px]">
                      {profile.complianceFrameworks.length} frameworks
                    </Badge>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

// ─── Step: Target Configuration ────────────────────────────────────────────────

function TargetsStep({
  engagementName,
  onNameChange,
  targets,
  targetInput,
  onTargetInputChange,
  onAddTargets,
  onRemoveTarget,
  selectedProfile,
}: {
  engagementName: string;
  onNameChange: (v: string) => void;
  targets: string[];
  targetInput: string;
  onTargetInputChange: (v: string) => void;
  onAddTargets: () => void;
  onRemoveTarget: (t: string) => void;
  selectedProfile?: VerificationProfile;
}) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold mb-1">Configure Targets</h2>
        <p className="text-sm text-muted-foreground">
          Name this engagement and specify the targets (domains, IPs, CIDR ranges, or URLs) to assess.
        </p>
      </div>

      {/* Engagement Name */}
      <div className="space-y-2">
        <Label htmlFor="engagement-name">Engagement Name</Label>
        <Input
          id="engagement-name"
          placeholder="e.g., Q2 2026 External VA — Production"
          value={engagementName}
          onChange={e => onNameChange(e.target.value)}
          className="max-w-lg"
        />
      </div>

      {/* Target Input */}
      <div className="space-y-2">
        <Label>Targets</Label>
        <div className="flex gap-2 max-w-lg">
          <Textarea
            placeholder="Enter domains, IPs, CIDR ranges, or URLs (one per line, or comma-separated)"
            value={targetInput}
            onChange={e => onTargetInputChange(e.target.value)}
            rows={4}
            className="flex-1"
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                onAddTargets();
              }
            }}
          />
        </div>
        <Button variant="outline" size="sm" onClick={onAddTargets} className="gap-1">
          <Plus className="h-3 w-3" />
          Add Targets
        </Button>
      </div>

      {/* Target List */}
      {targets.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label>{targets.length} target{targets.length !== 1 ? 's' : ''} configured</Label>
          </div>
          <ScrollArea className="max-h-60">
            <div className="flex flex-wrap gap-2">
              {targets.map(target => (
                <Badge
                  key={target}
                  variant="secondary"
                  className="gap-1 pl-2 pr-1 py-1 text-xs"
                >
                  <Target className="h-3 w-3 text-emerald-400" />
                  {target}
                  <button
                    onClick={() => onRemoveTarget(target)}
                    className="ml-1 p-0.5 rounded hover:bg-destructive/20 transition-colors"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </Badge>
              ))}
            </div>
          </ScrollArea>
        </div>
      )}

      {/* Profile Summary */}
      {selectedProfile && (
        <Card className="border-dashed">
          <CardContent className="pt-4">
            <div className="flex items-center gap-2 mb-2">
              <Info className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">Selected Profile: {selectedProfile.name}</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {selectedProfile.scannerConfig.enabledScanners.map((s: string) => (
                <Badge key={s} variant="outline" className="text-[10px]">{s}</Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Step: Framework Selection ─────────────────────────────────────────────────

function FrameworksStep({
  selectedFrameworks,
  profileFrameworks,
  onToggle,
}: {
  selectedFrameworks: string[];
  profileFrameworks: string[];
  onToggle: (id: string) => void;
}) {
  const categories = useMemo(() => {
    const cats = new Map<string, typeof AVAILABLE_FRAMEWORKS>();
    for (const fw of AVAILABLE_FRAMEWORKS) {
      const existing = cats.get(fw.category) || [];
      existing.push(fw);
      cats.set(fw.category, existing);
    }
    return cats;
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold mb-1">Compliance Framework Mapping</h2>
        <p className="text-sm text-muted-foreground">
          Select which compliance frameworks to map findings against. Frameworks from your assessment profile are pre-selected.
          The VA report will include control mapping and gap analysis for each selected framework.
        </p>
      </div>

      {selectedFrameworks.length > 0 && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          <span className="text-sm">{selectedFrameworks.length} framework{selectedFrameworks.length !== 1 ? 's' : ''} selected</span>
        </div>
      )}

      {Array.from(categories).map(([category, frameworks]) => (
        <div key={category}>
          <h3 className="text-sm font-medium text-muted-foreground mb-3">{category}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {frameworks.map(fw => {
              const isSelected = selectedFrameworks.includes(fw.id);
              const isFromProfile = profileFrameworks.includes(fw.id);
              return (
                <Card
                  key={fw.id}
                  className={`cursor-pointer transition-all hover:shadow-sm ${
                    isSelected
                      ? 'ring-1 ring-emerald-500/50 border-emerald-500/30 bg-emerald-500/5'
                      : 'hover:border-muted-foreground/30'
                  }`}
                  onClick={() => !isFromProfile && onToggle(fw.id)}
                >
                  <CardContent className="pt-4 pb-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">{fw.name}</span>
                          {isFromProfile && (
                            <Badge variant="outline" className="text-[9px] border-emerald-500/30 text-emerald-400">
                              Profile
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">{fw.description}</p>
                      </div>
                      <div className={`p-1 rounded-full flex-shrink-0 ${isSelected ? 'bg-emerald-500' : 'bg-muted'}`}>
                        <Check className={`h-3 w-3 ${isSelected ? 'text-white' : 'text-transparent'}`} />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Step: Review & Launch ─────────────────────────────────────────────────────

function ReviewStep({
  profile,
  engagementName,
  targets,
  frameworks,
}: {
  profile?: VerificationProfile;
  engagementName: string;
  targets: string[];
  frameworks: string[];
}) {
  if (!profile) return null;

  const frameworkNames = frameworks.map(fId => {
    const fw = AVAILABLE_FRAMEWORKS.find(f => f.id === fId);
    return fw?.name || fId;
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold mb-1">Review Configuration</h2>
        <p className="text-sm text-muted-foreground">
          Verify your VA pipeline configuration before launching. The pipeline will run all phases sequentially — no exploitation is performed.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Engagement Info */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Layers className="h-4 w-4 text-emerald-400" />
              Engagement
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div>
              <span className="text-xs text-muted-foreground">Name</span>
              <p className="text-sm font-medium">{engagementName}</p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">Type</span>
              <p className="text-sm font-medium">Vulnerability Assessment</p>
            </div>
          </CardContent>
        </Card>

        {/* Profile Info */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4 text-emerald-400" />
              Assessment Profile
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div>
              <span className="text-xs text-muted-foreground">Profile</span>
              <p className="text-sm font-medium">{profile.name}</p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">Max Verification Depth</span>
              <p className="text-sm font-medium capitalize">{profile.maxVerificationDepth.replace(/_/g, ' ')}</p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">Scanners</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {profile.scannerConfig.enabledScanners.map((s: string) => (
                  <Badge key={s} variant="secondary" className="text-[10px]">{s}</Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Targets */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Target className="h-4 w-4 text-emerald-400" />
              Targets ({targets.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-32">
              <div className="flex flex-wrap gap-1.5">
                {targets.map(t => (
                  <Badge key={t} variant="outline" className="text-[10px]">{t}</Badge>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Frameworks */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <FileText className="h-4 w-4 text-emerald-400" />
              Compliance Frameworks ({frameworks.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {frameworkNames.length > 0 ? (
              <div className="space-y-1">
                {frameworkNames.map(name => (
                  <div key={name} className="flex items-center gap-2 text-xs">
                    <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                    {name}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">No frameworks selected</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Pipeline Phases */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Zap className="h-4 w-4 text-emerald-400" />
            Pipeline Phases
          </CardTitle>
          <CardDescription className="text-xs">
            The VA pipeline will execute these phases in order. No exploitation is performed.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 flex-wrap">
            {['Asset Discovery', 'Port Scanning', 'Service Fingerprinting', 'Vulnerability Detection', 'Verification', 'LLM Synthesis', 'Reporting'].map((phase, i) => (
              <div key={phase} className="flex items-center gap-1">
                <Badge variant="secondary" className="text-[10px] gap-1">
                  <span className="text-emerald-400 font-bold">{i + 1}</span>
                  {phase}
                </Badge>
                {i < 6 && <ArrowRight className="h-3 w-3 text-muted-foreground/40" />}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Safety Notice */}
      <div className="flex items-start gap-3 p-4 rounded-lg bg-amber-500/5 border border-amber-500/20">
        <AlertTriangle className="h-5 w-5 text-amber-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-amber-400">VA Safety Boundary</p>
          <p className="text-xs text-muted-foreground mt-1">
            This pipeline performs vulnerability <strong>assessment</strong> only — no exploitation, no payload delivery, no post-exploitation.
            Maximum verification depth is <strong>{profile.maxVerificationDepth.replace(/_/g, ' ')}</strong>.
            Findings are normalized, deduplicated, and mapped to compliance controls.
          </p>
        </div>
      </div>
    </div>
  );
}
