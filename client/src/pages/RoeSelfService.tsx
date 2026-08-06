// @ts-nocheck
/**
 * RoeSelfService.tsx — Customer Self-Service Rules of Engagement Wizard
 * ═════════════════════════════════════════════════════════════════════
 * A guided, interview-style ROE creation flow designed for customers who
 * have never written an ROE before. Features contextual help, compliance
 * badges (NIST/FedRAMP/CISA), progress tracking, collaboration comments,
 * and document upload with LLM-powered field extraction.
 */
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useCallback, useRef, useMemo, useEffect } from "react";
import { useLocation, useRoute } from "wouter";
import AppShell from "@/components/AppShell";
import {
  Shield, Target, Calendar, MessageSquare, Lock, Scale, Users, FileCheck,
  ChevronRight, ChevronLeft, HelpCircle, Upload, FileText, CheckCircle2,
  XCircle, AlertTriangle, Info, Zap, Globe, Network, Mail, Building,
  Wifi, Download, Package, Key, Loader2, Send, ArrowRight, Plus, Trash2,
  Clock, Eye, MessageCircle, Crosshair, Smartphone, Factory, Skull,
  ShieldCheck, ClipboardCheck, FileWarning, Sparkles, BookOpen, ExternalLink
} from "lucide-react";

// ─── Types ──────────────────────────────────────────────────────────────────────

type WizardView = "landing" | "create" | "edit" | "list";

// ─── Icon Map ───────────────────────────────────────────────────────────────────

const ICON_MAP: Record<string, any> = {
  globe: Globe, network: Network, cloud: Globe, skull: Skull,
  factory: Factory, mail: Mail, smartphone: Smartphone, shield: Shield,
  zap: Zap, building: Building, wifi: Wifi, download: Download,
  package: Package, key: Key, lock: Lock, file: FileText,
};

// ─── Section Icons ──────────────────────────────────────────────────────────────

const SECTION_ICONS: Record<string, any> = {
  engagement_type: Crosshair,
  scope: Target,
  exclusions: Shield,
  schedule: Calendar,
  boundaries: Zap,
  communication: MessageSquare,
  credentials: Key,
  data_handling: Lock,
  authorization: Scale,
  compliance: ShieldCheck,
  reporting: FileCheck,
  review: ClipboardCheck,
};

// ─── Main Component ─────────────────────────────────────────────────────────────

export default function RoeSelfService() {
  const [view, setView] = useState<WizardView>("landing");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [, params] = useRoute("/roe-self-service/:id");

  useEffect(() => {
    if (params?.id) {
      setSelectedId(parseInt(params.id));
      setView("edit");
    }
  }, [params?.id]);

  return (
    <AppShell activePath="/roe-self-service">
      <div className="min-h-screen bg-background text-foreground">
        {view === "landing" && (
          <LandingView
            onCreateNew={() => setView("create")}
            onViewList={() => setView("list")}
            onEdit={(id) => { setSelectedId(id); setView("edit"); }}
          />
        )}
        {view === "create" && (
          <CreateWizard
            onBack={() => setView("landing")}
            onCreated={(id) => { setSelectedId(id); setView("edit"); }}
          />
        )}
        {view === "edit" && selectedId && (
          <EditWizard
            roeId={selectedId}
            onBack={() => { setSelectedId(null); setView("landing"); }}
          />
        )}
        {view === "list" && (
          <ListView
            onBack={() => setView("landing")}
            onEdit={(id) => { setSelectedId(id); setView("edit"); }}
          />
        )}
      </div>
    </AppShell>
  );
}

// ─── Landing View ───────────────────────────────────────────────────────────────

function LandingView({ onCreateNew, onViewList, onEdit }: {
  onCreateNew: () => void;
  onViewList: () => void;
  onEdit: (id: number) => void;
}) {
  const recentRoes = trpc.roeSelfService.listMyRoes.useQuery();

  return (
    <div className="max-w-5xl mx-auto px-4 py-10">
      {/* Hero Section */}
      <div className="text-center mb-12">
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium mb-6">
          <Shield className="w-4 h-4" />
          Rules of Engagement
        </div>
        <h1 className="text-4xl font-bold tracking-tight mb-4">
          Define Your Security Assessment Scope
        </h1>
        <p className="text-lg text-muted-foreground max-w-2xl mx-auto leading-relaxed">
          A Rules of Engagement (ROE) document defines exactly what our security team can and cannot do
          during your assessment. This guided wizard will walk you through every section — no prior
          experience needed.
        </p>
      </div>

      {/* What is an ROE? */}
      <Card className="mb-8 border-primary/20 bg-primary/5">
        <CardContent className="p-6">
          <div className="flex gap-4">
            <BookOpen className="w-6 h-6 text-primary shrink-0 mt-1" />
            <div>
              <h3 className="font-semibold text-base mb-2">What is a Rules of Engagement document?</h3>
              <p className="text-sm text-muted-foreground leading-relaxed mb-3">
                Think of it as a contract between you and our security testing team. It specifies:
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="flex items-start gap-2">
                  <Target className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                  <span className="text-sm"><strong>What to test</strong> — your domains, IPs, and applications</span>
                </div>
                <div className="flex items-start gap-2">
                  <Shield className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                  <span className="text-sm"><strong>What NOT to test</strong> — your critical systems that are off-limits</span>
                </div>
                <div className="flex items-start gap-2">
                  <Calendar className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                  <span className="text-sm"><strong>When to test</strong> — dates, hours, and business constraints</span>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Compliance Badges */}
      <div className="flex flex-wrap items-center justify-center gap-3 mb-10">
        <Badge variant="outline" className="gap-1.5 py-1.5 px-3 text-xs">
          <ShieldCheck className="w-3.5 h-3.5" /> NIST SP 800-115 Compliant
        </Badge>
        <Badge variant="outline" className="gap-1.5 py-1.5 px-3 text-xs">
          <ShieldCheck className="w-3.5 h-3.5" /> FedRAMP Ready
        </Badge>
        <Badge variant="outline" className="gap-1.5 py-1.5 px-3 text-xs">
          <ShieldCheck className="w-3.5 h-3.5" /> CISA BOD Aligned
        </Badge>
        <Badge variant="outline" className="gap-1.5 py-1.5 px-3 text-xs">
          <ShieldCheck className="w-3.5 h-3.5" /> PCI DSS
        </Badge>
        <Badge variant="outline" className="gap-1.5 py-1.5 px-3 text-xs">
          <ShieldCheck className="w-3.5 h-3.5" /> HIPAA
        </Badge>
      </div>

      {/* Action Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-10">
        <Card
          className="cursor-pointer hover:border-primary/50 transition-all hover:shadow-lg group"
          onClick={onCreateNew}
        >
          <CardContent className="p-6 text-center">
            <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center mx-auto mb-4 group-hover:bg-primary/20 transition-colors">
              <Plus className="w-6 h-6 text-primary" />
            </div>
            <h3 className="font-semibold mb-2">Start New ROE</h3>
            <p className="text-sm text-muted-foreground">
              Choose an engagement type and we'll guide you through each section step by step.
            </p>
          </CardContent>
        </Card>

        <Card
          className="cursor-pointer hover:border-primary/50 transition-all hover:shadow-lg group"
          onClick={onViewList}
        >
          <CardContent className="p-6 text-center">
            <div className="w-12 h-12 rounded-xl bg-blue-500/10 flex items-center justify-center mx-auto mb-4 group-hover:bg-blue-500/20 transition-colors">
              <FileText className="w-6 h-6 text-blue-500" />
            </div>
            <h3 className="font-semibold mb-2">Continue Existing</h3>
            <p className="text-sm text-muted-foreground">
              Resume filling out an ROE you've already started, or review a completed one.
            </p>
          </CardContent>
        </Card>

        <Card
          className="cursor-pointer hover:border-primary/50 transition-all hover:shadow-lg group"
          onClick={() => toast.info("Upload a PDF or Word document from the wizard to auto-fill fields.")}
        >
          <CardContent className="p-6 text-center">
            <div className="w-12 h-12 rounded-xl bg-amber-500/10 flex items-center justify-center mx-auto mb-4 group-hover:bg-amber-500/20 transition-colors">
              <Upload className="w-6 h-6 text-amber-500" />
            </div>
            <h3 className="font-semibold mb-2">Upload Existing ROE</h3>
            <p className="text-sm text-muted-foreground">
              Have an existing ROE document? Upload it and we'll extract the fields automatically.
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Recent ROEs */}
      {recentRoes.data && recentRoes.data.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-4">Recent Documents</h2>
          <div className="space-y-2">
            {recentRoes.data.slice(0, 5).map((roe: any) => (
              <Card
                key={roe.id}
                className="cursor-pointer hover:border-primary/30 transition-all"
                onClick={() => onEdit(roe.id)}
              >
                <CardContent className="p-4 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <FileText className="w-5 h-5 text-muted-foreground" />
                    <div>
                      <div className="font-medium text-sm">{roe.title || "Untitled ROE"}</div>
                      <div className="text-xs text-muted-foreground">
                        {roe.organizationName} · {new Date(roe.createdAt).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <StatusBadge status={roe.status} />
                    <ChevronRight className="w-4 h-4 text-muted-foreground" />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Status Badge ───────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "outline" }> = {
    draft: { label: "Draft", variant: "secondary" },
    pending_review: { label: "Pending Review", variant: "default" },
    approved: { label: "Approved", variant: "default" },
    active: { label: "Active", variant: "default" },
    completed: { label: "Completed", variant: "outline" },
    archived: { label: "Archived", variant: "outline" },
  };
  const c = config[status] || { label: status, variant: "secondary" as const };
  return <Badge variant={c.variant} className="text-xs">{c.label}</Badge>;
}

// ─── Create Wizard (Engagement Type Selection) ──────────────────────────────────

function CreateWizard({ onBack, onCreated }: { onBack: () => void; onCreated: (id: number) => void }) {
  const defs = trpc.roeSelfService.getSectionDefinitions.useQuery();
  const createMut = trpc.roeSelfService.createFromPreset.useMutation({
    onSuccess: (data) => {
      toast.success("ROE created! Let's start filling it out.");
      onCreated(data.id);
    },
    onError: (e) => toast.error(sanitizeErrorForToast(e.message)),
  });
  const [orgName, setOrgName] = useState("");
  const [selectedType, setSelectedType] = useState<string | null>(null);

  if (!defs.data) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const types = defs.data.engagementTypes;

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <Button variant="ghost" size="sm" onClick={onBack} className="mb-6">
        <ChevronLeft className="w-4 h-4 mr-1" /> Back
      </Button>

      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold mb-2">What kind of security testing do you need?</h2>
        <p className="text-muted-foreground">
          Choose the type that best describes your needs. Don't worry — you can customize everything later.
        </p>
      </div>

      {/* Organization Name */}
      <div className="max-w-md mx-auto mb-8">
        <Label className="text-sm font-medium">Your Organization Name</Label>
        <Input
          value={orgName}
          onChange={(e) => setOrgName(e.target.value)}
          placeholder="e.g., Acme Corporation"
          className="mt-1.5"
        />
      </div>

      {/* Engagement Type Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
        {types.map((t: any) => {
          const Icon = ICON_MAP[t.icon] || Shield;
          const isSelected = selectedType === t.id;
          return (
            <Card
              key={t.id}
              className={`cursor-pointer transition-all ${
                isSelected
                  ? "border-primary ring-2 ring-primary/20"
                  : "hover:border-primary/30"
              }`}
              onClick={() => setSelectedType(t.id)}
            >
              <CardContent className="p-5">
                <div className="flex items-start gap-4">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${
                    isSelected ? "bg-primary text-primary-foreground" : "bg-muted"
                  }`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="font-semibold text-sm">{t.label}</h3>
                      <span className="text-xs text-muted-foreground">{t.typicalDuration}</span>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">{t.description}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Not sure? */}
      <div className="text-center mb-6">
        <p className="text-sm text-muted-foreground">
          <HelpCircle className="w-3.5 h-3.5 inline mr-1" />
          Not sure which to choose? <strong>Web Application Test</strong> is the most common starting point.
          You can always change this later.
        </p>
      </div>

      {/* Create Button */}
      <div className="flex justify-center">
        <Button
          size="lg"
          disabled={!orgName.trim() || !selectedType || createMut.isPending}
          onClick={() => createMut.mutate({ engagementTypeId: selectedType!, organizationName: orgName.trim() })}
          className="min-w-[200px]"
        >
          {createMut.isPending ? (
            <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Creating...</>
          ) : (
            <>Start Building ROE <ArrowRight className="w-4 h-4 ml-2" /></>
          )}
        </Button>
      </div>
    </div>
  );
}

// ─── List View ──────────────────────────────────────────────────────────────────

function ListView({ onBack, onEdit }: { onBack: () => void; onEdit: (id: number) => void }) {
  const roes = trpc.roeSelfService.listMyRoes.useQuery();

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <Button variant="ghost" size="sm" onClick={onBack} className="mb-6">
        <ChevronLeft className="w-4 h-4 mr-1" /> Back
      </Button>

      <h2 className="text-2xl font-bold mb-6">Your ROE Documents</h2>

      {roes.isLoading && (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      )}

      {roes.data && roes.data.length === 0 && (
        <Card className="text-center py-16">
          <CardContent>
            <FileText className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="font-semibold mb-2">No ROE documents yet</h3>
            <p className="text-sm text-muted-foreground mb-4">Create your first Rules of Engagement document to get started.</p>
            <Button onClick={onBack}>Create New ROE</Button>
          </CardContent>
        </Card>
      )}

      {roes.data && roes.data.length > 0 && (
        <div className="space-y-3">
          {roes.data.map((roe: any) => (
            <Card
              key={roe.id}
              className="cursor-pointer hover:border-primary/30 transition-all"
              onClick={() => onEdit(roe.id)}
            >
              <CardContent className="p-5 flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-muted flex items-center justify-center">
                    <FileText className="w-5 h-5 text-muted-foreground" />
                  </div>
                  <div>
                    <div className="font-medium">{roe.title || "Untitled ROE"}</div>
                    <div className="text-sm text-muted-foreground">
                      {roe.organizationName} · Created {new Date(roe.createdAt).toLocaleDateString()}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <StatusBadge status={roe.status} />
                  <ChevronRight className="w-4 h-4 text-muted-foreground" />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Edit Wizard (Guided Interview) ─────────────────────────────────────────────

function EditWizard({ roeId, onBack }: { roeId: number; onBack: () => void }) {
  const [currentSection, setCurrentSection] = useState(0);
  const [showUploadDialog, setShowUploadDialog] = useState(false);
  const [showCommentDialog, setShowCommentDialog] = useState(false);
  const [showCompliancePanel, setShowCompliancePanel] = useState(false);

  const defs = trpc.roeSelfService.getSectionDefinitions.useQuery();
  const doc = trpc.roeSelfService.getWithCollaboration.useQuery({ id: roeId });
  const compliance = trpc.roeSelfService.validateCompliance.useQuery({ roeId });
  const updateMut = trpc.roeSelfService.updateSection.useMutation({
    onSuccess: () => doc.refetch(),
  });
  const submitMut = trpc.roeSelfService.submitForReview.useMutation({
    onSuccess: () => { doc.refetch(); toast.success("ROE submitted for operator review!"); },
    onError: (e) => toast.error(sanitizeErrorForToast(e.message)),
  });

  if (!defs.data || !doc.data) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const { roe, sectionCompletion, overallCompletion, comments, versions } = doc.data;
  const sections = Object.entries(defs.data.sections);
  const sectionKeys = sections.map(([k]) => k);
  const [currentKey, currentDef] = sections[currentSection] || sections[0];
  const SectionIcon = SECTION_ICONS[currentKey] || Shield;

  const saveField = (field: string, value: any) => {
    updateMut.mutate({
      id: roeId,
      section: currentKey,
      fields: { [field]: typeof value === "object" ? JSON.stringify(value) : value },
    });
  };

  const saveFields = (fields: Record<string, any>) => {
    const processed: Record<string, any> = {};
    for (const [k, v] of Object.entries(fields)) {
      processed[k] = typeof v === "object" && v !== null ? JSON.stringify(v) : v;
    }
    updateMut.mutate({ id: roeId, section: currentKey, fields: processed });
  };

  const sectionComments = comments.filter((c: any) => c.section === currentKey);

  return (
    <div className="max-w-6xl mx-auto px-4 py-6">
      {/* Top Bar */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={onBack}>
            <ChevronLeft className="w-4 h-4 mr-1" /> Back
          </Button>
          <div>
            <h1 className="text-lg font-bold">{roe.title || "Untitled ROE"}</h1>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <StatusBadge status={roe.status} />
              <span>·</span>
              <span>{roe.organizationName}</span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowUploadDialog(true)}>
            <Upload className="w-3.5 h-3.5 mr-1.5" /> Upload Doc
          </Button>
          <Button variant="outline" size="sm" onClick={() => setShowCompliancePanel(!showCompliancePanel)}>
            <ShieldCheck className="w-3.5 h-3.5 mr-1.5" /> Compliance
            {compliance.data && (
              <Badge variant="secondary" className="ml-1.5 text-[10px]">
                {compliance.data.overallPercentage}%
              </Badge>
            )}
          </Button>
        </div>
      </div>

      {/* Overall Progress */}
      <div className="mb-6">
        <div className="flex items-center justify-between text-sm mb-2">
          <span className="text-muted-foreground">Overall Progress</span>
          <span className="font-medium">{overallCompletion}%</span>
        </div>
        <Progress value={overallCompletion} className="h-2" />
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Left: Section Navigation */}
        <div className="col-span-3">
          <div className="sticky top-6 space-y-1">
            {sections.map(([key, def], idx) => {
              const Icon = SECTION_ICONS[key] || Shield;
              const completion = sectionCompletion[key] || 0;
              const isActive = idx === currentSection;
              const hasComments = comments.some((c: any) => c.section === key && !c.isResolved);
              return (
                <button
                  key={key}
                  onClick={() => setCurrentSection(idx)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-all text-sm ${
                    isActive
                      ? "bg-primary/10 text-primary border border-primary/20"
                      : "hover:bg-muted/50 text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <div className={`w-7 h-7 rounded-md flex items-center justify-center shrink-0 ${
                    completion === 100
                      ? "bg-green-500/10 text-green-500"
                      : isActive
                        ? "bg-primary/10 text-primary"
                        : "bg-muted text-muted-foreground"
                  }`}>
                    {completion === 100 ? (
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    ) : (
                      <Icon className="w-3.5 h-3.5" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium truncate">{(def as any).label}</div>
                    <div className="flex items-center gap-1.5">
                      <div className="flex-1 h-1 bg-muted rounded-full">
                        <div
                          className={`h-1 rounded-full transition-all ${
                            completion === 100 ? "bg-green-500" : completion > 0 ? "bg-primary" : "bg-transparent"
                          }`}
                          style={{ width: `${completion}%` }}
                        />
                      </div>
                      <span className="text-[10px] text-muted-foreground w-7 text-right">{completion}%</span>
                    </div>
                  </div>
                  {hasComments && (
                    <div className="w-2 h-2 rounded-full bg-amber-500 shrink-0" />
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Center: Section Content */}
        <div className="col-span-6">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                  <SectionIcon className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <CardTitle className="text-lg">{(currentDef as any).label}</CardTitle>
                  <CardDescription>{(currentDef as any).description}</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {/* Contextual Help Banner */}
              <div className="flex items-start gap-3 p-3 rounded-lg bg-blue-500/5 border border-blue-500/10 mb-6">
                <Info className="w-4 h-4 text-blue-500 shrink-0 mt-0.5" />
                <p className="text-xs text-blue-400/80 leading-relaxed">{(currentDef as any).helpText}</p>
              </div>

              {/* Compliance Reference */}
              {(currentDef as any).complianceRef && (
                <div className="flex flex-wrap gap-1.5 mb-5">
                  {(currentDef as any).complianceRef.map((ref: string) => (
                    <Badge key={ref} variant="outline" className="text-[10px] gap-1">
                      <ShieldCheck className="w-2.5 h-2.5" /> {ref}
                    </Badge>
                  ))}
                </div>
              )}

              {/* Section-specific content */}
              {currentKey === "engagement_type" && <EngagementTypeSection roe={roe} saveField={saveField} />}
              {currentKey === "scope" && <ScopeSection roe={roe} saveField={saveField} saveFields={saveFields} />}
              {currentKey === "exclusions" && <ExclusionsSection roe={roe} saveField={saveField} saveFields={saveFields} />}
              {currentKey === "schedule" && <ScheduleSection roe={roe} saveField={saveField} />}
              {currentKey === "boundaries" && <BoundariesSection roe={roe} saveField={saveField} defs={defs.data} />}
              {currentKey === "communication" && <CommunicationSection roe={roe} saveField={saveField} />}
              {currentKey === "credentials" && <CredentialsSection roe={roe} saveField={saveField} />}
              {currentKey === "data_handling" && <DataHandlingSection roe={roe} saveField={saveField} />}
              {currentKey === "authorization" && <AuthorizationSection roe={roe} saveField={saveField} />}
              {currentKey === "compliance" && <ComplianceSection roe={roe} saveField={saveField} defs={defs.data} />}
              {currentKey === "reporting" && <ReportingSection roe={roe} saveField={saveField} />}
              {currentKey === "review" && (
                <ReviewSection
                  roe={roe}
                  sectionCompletion={sectionCompletion}
                  overallCompletion={overallCompletion}
                  compliance={compliance.data}
                  onSubmit={() => submitMut.mutate({ id: roeId })}
                  isSubmitting={submitMut.isPending}
                />
              )}

              {/* Navigation */}
              <div className="flex items-center justify-between mt-8 pt-4 border-t border-border">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={currentSection === 0}
                  onClick={() => setCurrentSection(Math.max(0, currentSection - 1))}
                >
                  <ChevronLeft className="w-4 h-4 mr-1" /> Previous
                </Button>
                <span className="text-xs text-muted-foreground">
                  Step {currentSection + 1} of {sections.length}
                </span>
                <Button
                  size="sm"
                  disabled={currentSection === sections.length - 1}
                  onClick={() => setCurrentSection(Math.min(sections.length - 1, currentSection + 1))}
                >
                  Next <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right: Comments & Activity */}
        <div className="col-span-3">
          <div className="sticky top-6 space-y-4">
            {/* Section Comments */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <MessageCircle className="w-4 h-4" /> Comments
                  {sectionComments.length > 0 && (
                    <Badge variant="secondary" className="text-[10px]">{sectionComments.length}</Badge>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {sectionComments.length === 0 ? (
                  <p className="text-xs text-muted-foreground py-4 text-center">
                    No comments on this section yet.
                    <br />
                    Questions? Leave a comment for your operator.
                  </p>
                ) : (
                  <ScrollArea className="max-h-[200px]">
                    <div className="space-y-3">
                      {sectionComments.map((c: any) => (
                        <div key={c.id} className={`p-2.5 rounded-lg text-xs ${
                          c.authorRole === "operator"
                            ? "bg-primary/5 border border-primary/10"
                            : "bg-muted/50 border border-border"
                        }`}>
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-medium">{c.authorName}</span>
                            <Badge variant="outline" className="text-[9px]">{c.authorRole}</Badge>
                          </div>
                          <p className="text-muted-foreground">{c.commentText}</p>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full mt-3"
                  onClick={() => setShowCommentDialog(true)}
                >
                  <Plus className="w-3 h-3 mr-1" /> Add Comment
                </Button>
              </CardContent>
            </Card>

            {/* Compliance Summary */}
            {showCompliancePanel && compliance.data && (
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4" /> Compliance
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {compliance.data.frameworks.map((fw: any) => (
                      <div key={fw.framework}>
                        <div className="flex items-center justify-between text-xs mb-1">
                          <span className="font-medium">{fw.framework}</span>
                          <span className={fw.percentage >= 80 ? "text-green-500" : fw.percentage >= 50 ? "text-amber-500" : "text-red-400"}>
                            {fw.metRequirements}/{fw.totalRequirements}
                          </span>
                        </div>
                        <Progress value={fw.percentage} className="h-1.5" />
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Version History */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Clock className="w-4 h-4" /> Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="max-h-[200px]">
                  <div className="space-y-2">
                    {versions.slice(0, 10).map((v: any) => (
                      <div key={v.id} className="flex items-start gap-2 text-xs">
                        <div className="w-1.5 h-1.5 rounded-full bg-muted-foreground mt-1.5 shrink-0" />
                        <div>
                          <span className="text-muted-foreground">{v.changeSummary}</span>
                          <div className="text-[10px] text-muted-foreground/60 mt-0.5">
                            {new Date(v.createdAt).toLocaleString()}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      {/* Upload Dialog */}
      <UploadDialog
        open={showUploadDialog}
        onOpenChange={setShowUploadDialog}
        roeId={roeId}
        onExtracted={() => { doc.refetch(); compliance.refetch(); }}
      />

      {/* Comment Dialog */}
      <CommentDialog
        open={showCommentDialog}
        onOpenChange={setShowCommentDialog}
        roeId={roeId}
        section={currentKey}
        onAdded={() => doc.refetch()}
      />
    </div>
  );
}

// ─── Section Components ─────────────────────────────────────────────────────────

function EngagementTypeSection({ roe, saveField }: { roe: any; saveField: (f: string, v: any) => void }) {
  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <Label className="flex items-center gap-2">
          Document Title
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger><HelpCircle className="w-3.5 h-3.5 text-muted-foreground" /></TooltipTrigger>
              <TooltipContent className="max-w-xs text-xs">
                A descriptive title like "Acme Corp — Web Application Penetration Test Q2 2026"
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </Label>
        <Input
          defaultValue={roe.title || ""}
          onBlur={(e) => saveField("title", e.target.value)}
          placeholder="e.g., Acme Corp — Web Application Penetration Test Q2 2026"
        />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Your Organization Name</Label>
          <Input
            defaultValue={roe.organizationName || ""}
            onBlur={(e) => saveField("organizationName", e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label>Testing Firm</Label>
          <Input
            defaultValue={roe.testingFirmName || "AC3 — AceofCloud"}
            onBlur={(e) => saveField("testingFirmName", e.target.value)}
            className="text-muted-foreground"
          />
        </div>
      </div>
      <div className="space-y-2">
        <Label className="flex items-center gap-2">
          Purpose Statement
          <Badge variant="outline" className="text-[10px]">NIST SP 800-115 §7.1</Badge>
        </Label>
        <Textarea
          defaultValue={roe.purpose || ""}
          onBlur={(e) => saveField("purpose", e.target.value)}
          rows={4}
          placeholder="Describe why this security assessment is being conducted. Example: 'To identify and evaluate security vulnerabilities in Acme Corp's customer-facing web applications before the Q3 product launch.'"
        />
        <p className="text-[11px] text-muted-foreground">
          This becomes the official purpose statement in the signed ROE document.
        </p>
      </div>
    </div>
  );
}

function ScopeSection({ roe, saveField, saveFields }: { roe: any; saveField: (f: string, v: any) => void; saveFields: (f: Record<string, any>) => void }) {
  const [newDomain, setNewDomain] = useState("");
  const [newIp, setNewIp] = useState("");
  const [newApp, setNewApp] = useState({ name: "", url: "", type: "web" });

  const domains = useMemo(() => {
    try { return JSON.parse(roe.inScopeDomains || "[]"); } catch { return []; }
  }, [roe.inScopeDomains]);

  const ips = useMemo(() => {
    try { return JSON.parse(roe.inScopeIpRanges || "[]"); } catch { return []; }
  }, [roe.inScopeIpRanges]);

  const apps = useMemo(() => {
    try { return JSON.parse(roe.inScopeApplications || "[]"); } catch { return []; }
  }, [roe.inScopeApplications]);

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Label className="flex items-center gap-2">
          Scope Description
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger><HelpCircle className="w-3.5 h-3.5 text-muted-foreground" /></TooltipTrigger>
              <TooltipContent className="max-w-xs text-xs">
                A high-level description of what's being tested. For FedRAMP, this defines the authorization boundary.
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </Label>
        <Textarea
          defaultValue={roe.scopeDescription || ""}
          onBlur={(e) => saveField("scopeDescription", e.target.value)}
          rows={3}
          placeholder="e.g., All customer-facing web applications hosted on *.acme.com, including the API gateway and authentication service."
        />
      </div>

      <Separator />

      {/* Domains */}
      <div className="space-y-3">
        <Label className="flex items-center gap-2">
          <Globe className="w-4 h-4" /> Domains to Test
        </Label>
        {domains.length > 0 && (
          <div className="space-y-1.5">
            {domains.map((d: any, i: number) => (
              <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-muted/50 text-sm">
                <Globe className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="flex-1 font-mono text-xs">{d.domain || d}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 w-6 p-0"
                  onClick={() => {
                    const updated = domains.filter((_: any, idx: number) => idx !== i);
                    saveField("inScopeDomains", updated);
                  }}
                >
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            ))}
          </div>
        )}
        <div className="flex gap-2">
          <Input
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            placeholder="e.g., app.acme.com or *.acme.com"
            className="flex-1 font-mono text-xs"
            onKeyDown={(e) => {
              if (e.key === "Enter" && newDomain.trim()) {
                saveField("inScopeDomains", [...domains, { domain: newDomain.trim(), includeSubdomains: newDomain.includes("*") }]);
                setNewDomain("");
              }
            }}
          />
          <Button
            variant="outline"
            size="sm"
            disabled={!newDomain.trim()}
            onClick={() => {
              saveField("inScopeDomains", [...domains, { domain: newDomain.trim(), includeSubdomains: newDomain.includes("*") }]);
              setNewDomain("");
            }}
          >
            <Plus className="w-3.5 h-3.5" />
          </Button>
        </div>
        <p className="text-[11px] text-muted-foreground">
          Use wildcard (*.acme.com) to include all subdomains. Press Enter or click + to add.
        </p>
      </div>

      <Separator />

      {/* IP Ranges */}
      <div className="space-y-3">
        <Label className="flex items-center gap-2">
          <Network className="w-4 h-4" /> IP Ranges to Test
        </Label>
        {ips.length > 0 && (
          <div className="space-y-1.5">
            {ips.map((ip: any, i: number) => (
              <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-muted/50 text-sm">
                <Network className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="flex-1 font-mono text-xs">{ip.cidr || ip}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 w-6 p-0"
                  onClick={() => {
                    const updated = ips.filter((_: any, idx: number) => idx !== i);
                    saveField("inScopeIpRanges", updated);
                  }}
                >
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            ))}
          </div>
        )}
        <div className="flex gap-2">
          <Input
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
            placeholder="e.g., 10.0.0.0/24 or 192.168.1.100"
            className="flex-1 font-mono text-xs"
            onKeyDown={(e) => {
              if (e.key === "Enter" && newIp.trim()) {
                saveField("inScopeIpRanges", [...ips, { cidr: newIp.trim() }]);
                setNewIp("");
              }
            }}
          />
          <Button
            variant="outline"
            size="sm"
            disabled={!newIp.trim()}
            onClick={() => {
              saveField("inScopeIpRanges", [...ips, { cidr: newIp.trim() }]);
              setNewIp("");
            }}
          >
            <Plus className="w-3.5 h-3.5" />
          </Button>
        </div>
        <p className="text-[11px] text-muted-foreground">
          Use CIDR notation (10.0.0.0/24) for ranges, or single IPs (192.168.1.100).
        </p>
      </div>

      <Separator />

      {/* Applications */}
      <div className="space-y-3">
        <Label className="flex items-center gap-2">
          <Smartphone className="w-4 h-4" /> Applications to Test
        </Label>
        {apps.length > 0 && (
          <div className="space-y-1.5">
            {apps.map((app: any, i: number) => (
              <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-muted/50 text-sm">
                <Smartphone className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="flex-1 text-xs">
                  <strong>{app.name}</strong>
                  {app.url && <span className="text-muted-foreground ml-2 font-mono">{app.url}</span>}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 w-6 p-0"
                  onClick={() => {
                    const updated = apps.filter((_: any, idx: number) => idx !== i);
                    saveField("inScopeApplications", updated);
                  }}
                >
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            ))}
          </div>
        )}
        <div className="flex gap-2">
          <Input
            value={newApp.name}
            onChange={(e) => setNewApp({ ...newApp, name: e.target.value })}
            placeholder="App name"
            className="flex-1 text-xs"
          />
          <Input
            value={newApp.url}
            onChange={(e) => setNewApp({ ...newApp, url: e.target.value })}
            placeholder="URL (optional)"
            className="flex-1 text-xs font-mono"
          />
          <Button
            variant="outline"
            size="sm"
            disabled={!newApp.name.trim()}
            onClick={() => {
              saveField("inScopeApplications", [...apps, { name: newApp.name.trim(), url: newApp.url.trim(), type: newApp.type }]);
              setNewApp({ name: "", url: "", type: "web" });
            }}
          >
            <Plus className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>
    </div>
  );
}

function ExclusionsSection({ roe, saveField, saveFields }: { roe: any; saveField: (f: string, v: any) => void; saveFields: (f: Record<string, any>) => void }) {
  const [newExDomain, setNewExDomain] = useState("");
  const [newExIp, setNewExIp] = useState("");

  const exDomains = useMemo(() => {
    try { return JSON.parse(roe.outOfScopeDomains || "[]"); } catch { return []; }
  }, [roe.outOfScopeDomains]);

  const exIps = useMemo(() => {
    try { return JSON.parse(roe.outOfScopeIpRanges || "[]"); } catch { return []; }
  }, [roe.outOfScopeIpRanges]);

  return (
    <div className="space-y-6">
      <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/10">
        <div className="flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
          <p className="text-xs text-red-400/80">
            <strong>Critical:</strong> Everything listed here is completely off-limits. Our team will hard-block
            these systems from all testing activities. Include production databases, payment processors,
            identity providers, and any system where disruption would cause business impact.
          </p>
        </div>
      </div>

      {/* Excluded Domains */}
      <div className="space-y-3">
        <Label>Domains NOT to Test</Label>
        {exDomains.length > 0 && (
          <div className="space-y-1.5">
            {exDomains.map((d: any, i: number) => (
              <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-red-500/5 border border-red-500/10 text-sm">
                <Shield className="w-3.5 h-3.5 text-red-400" />
                <span className="flex-1 font-mono text-xs">{d.domain || d}</span>
                <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => {
                  saveField("outOfScopeDomains", exDomains.filter((_: any, idx: number) => idx !== i));
                }}>
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            ))}
          </div>
        )}
        <div className="flex gap-2">
          <Input
            value={newExDomain}
            onChange={(e) => setNewExDomain(e.target.value)}
            placeholder="e.g., payments.acme.com"
            className="flex-1 font-mono text-xs"
            onKeyDown={(e) => {
              if (e.key === "Enter" && newExDomain.trim()) {
                saveField("outOfScopeDomains", [...exDomains, { domain: newExDomain.trim() }]);
                setNewExDomain("");
              }
            }}
          />
          <Button variant="outline" size="sm" disabled={!newExDomain.trim()} onClick={() => {
            saveField("outOfScopeDomains", [...exDomains, { domain: newExDomain.trim() }]);
            setNewExDomain("");
          }}>
            <Plus className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* Excluded IPs */}
      <div className="space-y-3">
        <Label>IP Ranges NOT to Test</Label>
        {exIps.length > 0 && (
          <div className="space-y-1.5">
            {exIps.map((ip: any, i: number) => (
              <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-red-500/5 border border-red-500/10 text-sm">
                <Shield className="w-3.5 h-3.5 text-red-400" />
                <span className="flex-1 font-mono text-xs">{ip.cidr || ip}</span>
                <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => {
                  saveField("outOfScopeIpRanges", exIps.filter((_: any, idx: number) => idx !== i));
                }}>
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            ))}
          </div>
        )}
        <div className="flex gap-2">
          <Input
            value={newExIp}
            onChange={(e) => setNewExIp(e.target.value)}
            placeholder="e.g., 10.0.1.0/24"
            className="flex-1 font-mono text-xs"
            onKeyDown={(e) => {
              if (e.key === "Enter" && newExIp.trim()) {
                saveField("outOfScopeIpRanges", [...exIps, { cidr: newExIp.trim() }]);
                setNewExIp("");
              }
            }}
          />
          <Button variant="outline" size="sm" disabled={!newExIp.trim()} onClick={() => {
            saveField("outOfScopeIpRanges", [...exIps, { cidr: newExIp.trim() }]);
            setNewExIp("");
          }}>
            <Plus className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      <Separator />

      <div className="space-y-2">
        <Label>Assumptions & Recovery Plan</Label>
        <Textarea
          defaultValue={roe.assumptions || ""}
          onBlur={(e) => saveField("assumptions", e.target.value)}
          rows={3}
          placeholder="e.g., 'Production database backups are taken hourly. If testing causes disruption, the team will restore from the most recent backup within 30 minutes.'"
        />
        <p className="text-[11px] text-muted-foreground">
          NIST SP 800-115 requires a documented backup/recovery plan in case testing causes unintended disruption.
        </p>
      </div>
    </div>
  );
}

function ScheduleSection({ roe, saveField }: { roe: any; saveField: (f: string, v: any) => void }) {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Start Date</Label>
          <Input
            type="date"
            defaultValue={roe.testScheduleStart ? new Date(roe.testScheduleStart).toISOString().split("T")[0] : ""}
            onChange={(e) => saveField("testScheduleStart", e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label>End Date</Label>
          <Input
            type="date"
            defaultValue={roe.testScheduleEnd ? new Date(roe.testScheduleEnd).toISOString().split("T")[0] : ""}
            onChange={(e) => saveField("testScheduleEnd", e.target.value)}
          />
        </div>
      </div>
      <div className="space-y-2">
        <Label>Timezone</Label>
        <Select
          defaultValue={roe.testTimezone || "America/New_York"}
          onValueChange={(v) => saveField("testTimezone", v)}
        >
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="America/New_York">Eastern (ET)</SelectItem>
            <SelectItem value="America/Chicago">Central (CT)</SelectItem>
            <SelectItem value="America/Denver">Mountain (MT)</SelectItem>
            <SelectItem value="America/Los_Angeles">Pacific (PT)</SelectItem>
            <SelectItem value="UTC">UTC</SelectItem>
            <SelectItem value="Europe/London">London (GMT/BST)</SelectItem>
            <SelectItem value="Europe/Berlin">Berlin (CET)</SelectItem>
            <SelectItem value="Asia/Tokyo">Tokyo (JST)</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <Separator />
      <div className="space-y-2">
        <Label className="flex items-center gap-2">
          Preferred Testing Hours
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger><HelpCircle className="w-3.5 h-3.5 text-muted-foreground" /></TooltipTrigger>
              <TooltipContent className="max-w-xs text-xs">
                Most customers prefer after-hours testing (6 PM – 6 AM) to minimize business impact.
                We'll only test during the hours you specify.
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </Label>
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">From</Label>
            <Input
              type="time"
              defaultValue={roe.testingWindowStart || "18:00"}
              onChange={(e) => saveField("testingWindowStart", e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">To</Label>
            <Input
              type="time"
              defaultValue={roe.testingWindowEnd || "06:00"}
              onChange={(e) => saveField("testingWindowEnd", e.target.value)}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

function BoundariesSection({ roe, saveField, defs }: { roe: any; saveField: (f: string, v: any) => void; defs: any }) {
  const explanations = defs.boundaryExplanations || {};
  const riskColors: Record<string, string> = {
    high: "text-red-400 bg-red-500/10",
    medium: "text-amber-400 bg-amber-500/10",
    low: "text-green-400 bg-green-500/10",
  };

  return (
    <div className="space-y-4">
      {Object.entries(explanations).map(([key, exp]: [string, any]) => {
        const Icon = ICON_MAP[exp.icon] || Shield;
        const isEnabled = !!roe[key];
        return (
          <div key={key} className="flex items-start gap-4 p-4 rounded-lg border border-border hover:border-primary/20 transition-all">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
              isEnabled ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground"
            }`}>
              <Icon className="w-4 h-4" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-medium">{exp.label}</span>
                <Badge className={`text-[10px] ${riskColors[exp.risk] || ""}`}>
                  {exp.risk} risk
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mb-2">{exp.description}</p>
              <p className="text-[11px] text-blue-400/60 italic">{exp.recommendation}</p>
            </div>
            <Switch
              checked={isEnabled}
              onCheckedChange={(v) => saveField(key, v ? 1 : 0)}
            />
          </div>
        );
      })}
    </div>
  );
}

function CommunicationSection({ roe, saveField }: { roe: any; saveField: (f: string, v: any) => void }) {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Status Update Frequency</Label>
          <Select
            defaultValue={roe.communicationFrequency || "daily"}
            onValueChange={(v) => saveField("communicationFrequency", v)}
          >
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="daily">Daily</SelectItem>
              <SelectItem value="weekly">Weekly</SelectItem>
              <SelectItem value="bi-weekly">Bi-Weekly</SelectItem>
              <SelectItem value="as-needed">As Needed</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Communication Method</Label>
          <Select
            defaultValue={roe.communicationMethod || "secure_portal"}
            onValueChange={(v) => saveField("communicationMethod", v)}
          >
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="secure_portal">Secure Portal (Recommended)</SelectItem>
              <SelectItem value="encrypted_email">Encrypted Email</SelectItem>
              <SelectItem value="email">Standard Email</SelectItem>
              <SelectItem value="phone">Phone</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <Separator />

      <div className="space-y-2">
        <Label className="flex items-center gap-2">
          Emergency Halt Criteria
          <Badge variant="outline" className="text-[10px]">NIST SP 800-115 Required</Badge>
        </Label>
        <Textarea
          defaultValue={roe.emergencyHaltCriteria || ""}
          onBlur={(e) => saveField("emergencyHaltCriteria", e.target.value)}
          rows={4}
          placeholder="Define when testing must immediately stop. Examples:&#10;• Production system becomes unresponsive&#10;• Customer data is inadvertently accessed&#10;• Testing causes service degradation above 10%&#10;• Client requests immediate halt via emergency phone line"
        />
        <p className="text-[11px] text-muted-foreground">
          This is a critical safety mechanism. Define clear, measurable criteria for when our team must stop all testing immediately.
        </p>
      </div>
    </div>
  );
}

function CredentialsSection({ roe, saveField }: { roe: any; saveField: (f: string, v: any) => void }) {
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between p-4 rounded-lg border border-border">
        <div>
          <div className="text-sm font-medium">Provide Test Credentials?</div>
          <div className="text-xs text-muted-foreground">
            Authenticated testing finds 3x more vulnerabilities than unauthenticated testing alone.
          </div>
        </div>
        <Switch
          checked={!!roe.credentialedTesting}
          onCheckedChange={(v) => saveField("credentialedTesting", v ? 1 : 0)}
        />
      </div>

      {roe.credentialedTesting ? (
        <div className="p-4 rounded-lg bg-green-500/5 border border-green-500/10">
          <div className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-green-500 shrink-0 mt-0.5" />
            <div className="text-xs text-green-400/80">
              <strong>Great choice.</strong> We'll coordinate credential delivery through a secure channel
              before testing begins. Never send credentials via email — use the secure portal or
              an encrypted password manager share link.
            </div>
          </div>
        </div>
      ) : (
        <div className="p-4 rounded-lg bg-amber-500/5 border border-amber-500/10">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
            <div className="text-xs text-amber-400/80">
              Without test credentials, we can only test unauthenticated attack surfaces.
              Many critical vulnerabilities (privilege escalation, IDOR, business logic) require authentication to discover.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DataHandlingSection({ roe, saveField }: { roe: any; saveField: (f: string, v: any) => void }) {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label className="flex items-center gap-2">
            Evidence Retention Period
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger><HelpCircle className="w-3.5 h-3.5 text-muted-foreground" /></TooltipTrigger>
                <TooltipContent className="max-w-xs text-xs">
                  How long we keep screenshots, logs, and other evidence after the engagement ends.
                  90 days is standard. FedRAMP requires at least 90 days.
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </Label>
          <Select
            defaultValue={String(roe.evidenceRetentionDays || 90)}
            onValueChange={(v) => saveField("evidenceRetentionDays", parseInt(v))}
          >
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="30">30 days</SelectItem>
              <SelectItem value="60">60 days</SelectItem>
              <SelectItem value="90">90 days (Standard)</SelectItem>
              <SelectItem value="180">180 days</SelectItem>
              <SelectItem value="365">1 year</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Evidence Destruction Method</Label>
          <Select
            defaultValue={roe.evidenceDestructionMethod || "secure_delete"}
            onValueChange={(v) => saveField("evidenceDestructionMethod", v)}
          >
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="secure_delete">Secure Delete (DoD 5220.22-M)</SelectItem>
              <SelectItem value="crypto_shred">Cryptographic Shredding</SelectItem>
              <SelectItem value="physical_destruction">Physical Destruction</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="flex items-center justify-between p-4 rounded-lg border border-border">
        <div>
          <div className="text-sm font-medium">Require Evidence Encryption</div>
          <div className="text-xs text-muted-foreground">All evidence encrypted at rest with AES-256</div>
        </div>
        <Switch
          checked={!!roe.evidenceEncryptionRequired}
          onCheckedChange={(v) => saveField("evidenceEncryptionRequired", v ? 1 : 0)}
        />
      </div>

      <div className="space-y-2">
        <Label>Data Handling Procedure</Label>
        <Textarea
          defaultValue={roe.dataHandlingProcedure || ""}
          onBlur={(e) => saveField("dataHandlingProcedure", e.target.value)}
          rows={4}
          placeholder="Describe how sensitive data should be handled during testing. Example:&#10;• All PII encountered will be immediately reported and not stored&#10;• Screenshots will be redacted before inclusion in reports&#10;• No production data will be extracted from the environment"
        />
      </div>
    </div>
  );
}

function AuthorizationSection({ roe, saveField }: { roe: any; saveField: (f: string, v: any) => void }) {
  return (
    <div className="space-y-5">
      <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/10 mb-2">
        <div className="flex items-start gap-2">
          <Scale className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
          <p className="text-xs text-amber-400/80">
            <strong>NIST SP 800-115 §7.1:</strong> Written authorization from the system owner is required
            before any testing begins. Without proper authorization, penetration testing may violate
            the Computer Fraud and Abuse Act (CFAA).
          </p>
        </div>
      </div>

      <div className="space-y-2">
        <Label>Legal Jurisdiction</Label>
        <Input
          defaultValue={roe.legalJurisdiction || ""}
          onBlur={(e) => saveField("legalJurisdiction", e.target.value)}
          placeholder="e.g., State of Virginia, United States"
        />
      </div>

      <div className="flex items-center justify-between p-4 rounded-lg border border-border">
        <div>
          <div className="text-sm font-medium">Non-Disclosure Agreement (NDA)</div>
          <div className="text-xs text-muted-foreground">Require signed NDA before engagement begins</div>
        </div>
        <Switch
          checked={!!roe.ndaRequired}
          onCheckedChange={(v) => saveField("ndaRequired", v ? 1 : 0)}
        />
      </div>

      <div className="space-y-2">
        <Label>Liability Waiver / Indemnification</Label>
        <Textarea
          defaultValue={roe.liabilityWaiver || ""}
          onBlur={(e) => saveField("liabilityWaiver", e.target.value)}
          rows={4}
          placeholder="Liability waiver and indemnification terms. Our standard template covers mutual indemnification for authorized testing activities."
        />
      </div>

      <Separator />

      <div className="space-y-3">
        <Label className="text-sm font-medium">Authorization Checklist</Label>
        <div className="space-y-2">
          {[
            { field: "authorizationObtained", label: "Written authorization obtained from system owner", desc: "The person or entity who owns the systems being tested has given explicit written permission." },
            { field: "managementApproval", label: "Management approval chain documented", desc: "All relevant managers and executives are aware of and have approved the testing." },
            { field: "legalReviewCompleted", label: "Legal review completed", desc: "Your legal team has reviewed the ROE and confirmed compliance with applicable laws." },
          ].map((item) => (
            <div key={item.field} className="flex items-start gap-3 p-3 rounded-lg border border-border hover:border-primary/20 transition-all">
              <Switch
                checked={!!roe[item.field]}
                onCheckedChange={(v) => saveField(item.field, v ? 1 : 0)}
                className="mt-0.5"
              />
              <div>
                <div className="text-sm font-medium">{item.label}</div>
                <div className="text-xs text-muted-foreground">{item.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ComplianceSection({ roe, saveField, defs }: { roe: any; saveField: (f: string, v: any) => void; defs: any }) {
  const frameworks = defs.complianceFrameworks || {};
  const selectedFrameworks = useMemo(() => {
    try { return JSON.parse(roe.complianceFrameworks || "[]"); } catch { return []; }
  }, [roe.complianceFrameworks]);

  return (
    <div className="space-y-5">
      <div className="space-y-3">
        <Label className="text-sm font-medium">Which compliance frameworks apply to your systems?</Label>
        <p className="text-xs text-muted-foreground">
          Select all that apply. This ensures our testing methodology covers all required elements
          and our reports map to the right control frameworks.
        </p>
        <div className="space-y-3">
          {Object.entries(frameworks).map(([key, fw]: [string, any]) => {
            const isSelected = selectedFrameworks.includes(key);
            return (
              <div
                key={key}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  isSelected
                    ? "border-primary/50 bg-primary/5"
                    : "border-border hover:border-primary/20"
                }`}
                onClick={() => {
                  const updated = isSelected
                    ? selectedFrameworks.filter((f: string) => f !== key)
                    : [...selectedFrameworks, key];
                  saveField("complianceFrameworks", updated);
                }}
              >
                <div className="flex items-start gap-3">
                  <div className={`w-5 h-5 rounded border-2 flex items-center justify-center shrink-0 mt-0.5 ${
                    isSelected ? "border-primary bg-primary" : "border-muted-foreground/30"
                  }`}>
                    {isSelected && <CheckCircle2 className="w-3 h-3 text-primary-foreground" />}
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-semibold text-sm">{fw.label}</span>
                      <span className="text-xs text-muted-foreground">— {fw.fullName}</span>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">{fw.description}</p>
                    {isSelected && (
                      <div className="mt-2 text-xs text-primary/80">
                        {fw.requirements.length} requirements will be validated
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function ReportingSection({ roe, saveField }: { roe: any; saveField: (f: string, v: any) => void }) {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Report Delivery Format</Label>
          <Select
            defaultValue={roe.reportFrequency || "final_only"}
            onValueChange={(v) => saveField("reportFrequency", v)}
          >
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="final_only">Final Report Only</SelectItem>
              <SelectItem value="interim_and_final">Interim + Final Report</SelectItem>
              <SelectItem value="weekly_and_final">Weekly Updates + Final Report</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Status Report Frequency</Label>
          <Select
            defaultValue={roe.statusReportFrequency || "daily"}
            onValueChange={(v) => saveField("statusReportFrequency", v)}
          >
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="daily">Daily</SelectItem>
              <SelectItem value="weekly">Weekly</SelectItem>
              <SelectItem value="bi-weekly">Bi-Weekly</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="p-4 rounded-lg bg-muted/30 border border-border">
        <h4 className="text-sm font-medium mb-2">Report Contents (Standard)</h4>
        <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-3 h-3 text-green-500" /> Executive Summary
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-3 h-3 text-green-500" /> Technical Findings
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-3 h-3 text-green-500" /> Risk Ratings (CVSS)
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-3 h-3 text-green-500" /> Remediation Guidance
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-3 h-3 text-green-500" /> Evidence Screenshots
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-3 h-3 text-green-500" /> Retest Recommendations
          </div>
        </div>
      </div>

      <div className="p-3 rounded-lg bg-blue-500/5 border border-blue-500/10">
        <p className="text-xs text-blue-400/80">
          <strong>FedRAMP note:</strong> If you selected FedRAMP compliance, findings will automatically
          be mapped to SAR Appendix F format with PoA&M integration guidance.
        </p>
      </div>
    </div>
  );
}

function ReviewSection({ roe, sectionCompletion, overallCompletion, compliance, onSubmit, isSubmitting }: {
  roe: any;
  sectionCompletion: Record<string, number>;
  overallCompletion: number;
  compliance: any;
  onSubmit: () => void;
  isSubmitting: boolean;
}) {
  return (
    <div className="space-y-6">
      {/* Overall Score */}
      <div className="text-center p-6 rounded-lg border border-border">
        <div className={`text-5xl font-bold mb-2 ${
          overallCompletion >= 80 ? "text-green-400" : overallCompletion >= 50 ? "text-amber-400" : "text-red-400"
        }`}>
          {overallCompletion}%
        </div>
        <div className="text-sm text-muted-foreground">Document Completeness</div>
        <Progress value={overallCompletion} className="h-2 mt-3 max-w-xs mx-auto" />
      </div>

      {/* Section Summary */}
      <div className="space-y-2">
        <h3 className="text-sm font-semibold uppercase text-muted-foreground">Section Status</h3>
        {Object.entries(sectionCompletion)
          .filter(([k]) => k !== "review")
          .map(([key, pct]) => (
            <div key={key} className="flex items-center gap-3 p-2 rounded-lg">
              {pct >= 80 ? (
                <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
              ) : pct > 0 ? (
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              ) : (
                <XCircle className="w-4 h-4 text-red-400 shrink-0" />
              )}
              <span className="text-sm flex-1 capitalize">{key.replace(/_/g, " ")}</span>
              <span className="text-xs text-muted-foreground">{pct}%</span>
            </div>
          ))}
      </div>

      {/* Compliance Summary */}
      {compliance && compliance.frameworks.length > 0 && (
        <>
          <Separator />
          <div className="space-y-2">
            <h3 className="text-sm font-semibold uppercase text-muted-foreground">Compliance Validation</h3>
            {compliance.frameworks.map((fw: any) => (
              <div key={fw.framework} className="flex items-center gap-3 p-2 rounded-lg">
                <ShieldCheck className={`w-4 h-4 shrink-0 ${
                  fw.percentage >= 80 ? "text-green-400" : fw.percentage >= 50 ? "text-amber-400" : "text-red-400"
                }`} />
                <span className="text-sm flex-1">{fw.framework}</span>
                <span className="text-xs text-muted-foreground">
                  {fw.metRequirements}/{fw.totalRequirements} ({fw.percentage}%)
                </span>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Submit */}
      <div className="pt-4">
        {roe.status === "draft" && (
          <Button
            size="lg"
            className="w-full"
            disabled={overallCompletion < 50 || isSubmitting}
            onClick={onSubmit}
          >
            {isSubmitting ? (
              <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Submitting...</>
            ) : (
              <><Send className="w-4 h-4 mr-2" /> Submit for Operator Review</>
            )}
          </Button>
        )}
        {roe.status === "pending_review" && (
          <div className="text-center p-4 rounded-lg bg-primary/5 border border-primary/10">
            <Clock className="w-6 h-6 text-primary mx-auto mb-2" />
            <p className="text-sm font-medium">Submitted for Review</p>
            <p className="text-xs text-muted-foreground mt-1">
              Our team is reviewing your ROE. You'll be notified when it's approved or if changes are needed.
            </p>
          </div>
        )}
        {roe.status === "approved" && (
          <div className="text-center p-4 rounded-lg bg-green-500/5 border border-green-500/10">
            <CheckCircle2 className="w-6 h-6 text-green-500 mx-auto mb-2" />
            <p className="text-sm font-medium text-green-400">ROE Approved</p>
            <p className="text-xs text-muted-foreground mt-1">
              This ROE has been approved and the engagement is ready to begin.
            </p>
          </div>
        )}
        {overallCompletion < 50 && roe.status === "draft" && (
          <p className="text-xs text-amber-400 text-center mt-2">
            Document must be at least 50% complete before submission.
          </p>
        )}
      </div>
    </div>
  );
}

// ─── Upload Dialog ──────────────────────────────────────────────────────────────

function UploadDialog({ open, onOpenChange, roeId, onExtracted }: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  roeId: number;
  onExtracted: () => void;
}) {
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const extractMut = trpc.roeSelfService.uploadAndExtract.useMutation();

  const handleFile = useCallback(async (file: File) => {
    if (!file) return;
    setUploading(true);
    setResult(null);
    try {
      const reader = new FileReader();
      reader.onload = async () => {
        const base64 = (reader.result as string).split(",")[1];
        const res = await extractMut.mutateAsync({
          roeId,
          fileContent: base64,
          fileName: file.name,
          mimeType: file.type,
        });
        setResult(res);
        if (res.success) {
          toast.success(`Extracted ${res.extractedFields} fields from ${file.name}`);
          onExtracted();
        } else {
          toast.error(res.error || "Failed to parse document");
        }
        setUploading(false);
      };
      reader.readAsDataURL(file);
    } catch (e: any) {
      toast.error(e.message || "Upload failed");
      setUploading(false);
    }
  }, [roeId, extractMut, onExtracted]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-primary" /> Upload Existing ROE Document
          </DialogTitle>
          <DialogDescription>
            Upload a PDF or Word document and our AI will extract fields automatically.
            You can review and edit all extracted data before saving.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <input
            ref={fileRef}
            type="file"
            accept=".pdf,.doc,.docx"
            className="hidden"
            onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
          />

          <div
            className="border-2 border-dashed border-border rounded-lg p-8 text-center cursor-pointer hover:border-primary/50 transition-all"
            onClick={() => fileRef.current?.click()}
          >
            {uploading ? (
              <div className="space-y-2">
                <Loader2 className="w-8 h-8 animate-spin text-primary mx-auto" />
                <p className="text-sm text-muted-foreground">Analyzing document with AI...</p>
              </div>
            ) : (
              <div className="space-y-2">
                <Upload className="w-8 h-8 text-muted-foreground mx-auto" />
                <p className="text-sm font-medium">Click to upload or drag and drop</p>
                <p className="text-xs text-muted-foreground">PDF or Word (.docx) up to 50MB</p>
              </div>
            )}
          </div>

          {result && result.success && (
            <div className="p-4 rounded-lg bg-green-500/5 border border-green-500/10">
              <div className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-green-500 shrink-0 mt-0.5" />
                <div className="text-xs">
                  <p className="font-medium text-green-400">Successfully extracted:</p>
                  <ul className="mt-1 space-y-0.5 text-muted-foreground">
                    <li>{result.extractedFields} fields populated</li>
                    <li>{result.extractedPersonnel} personnel identified</li>
                    <li>{result.sectionsUpdated.length} sections updated: {result.sectionsUpdated.join(", ")}</li>
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Comment Dialog ─────────────────────────────────────────────────────────────

function CommentDialog({ open, onOpenChange, roeId, section, onAdded }: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  roeId: number;
  section: string;
  onAdded: () => void;
}) {
  const [text, setText] = useState("");
  const addMut = trpc.roeSelfService.addComment.useMutation({
    onSuccess: () => {
      toast.success("Comment added");
      setText("");
      onAdded();
      onOpenChange(false);
    },
    onError: (e) => toast.error(sanitizeErrorForToast(e.message)),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Add Comment</DialogTitle>
          <DialogDescription>
            Leave a question or note for the operator about this section.
          </DialogDescription>
        </DialogHeader>
        <Textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={4}
          placeholder="e.g., 'Should we include the staging environment in scope?'"
        />
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            disabled={!text.trim() || addMut.isPending}
            onClick={() => addMut.mutate({ roeId, section, commentText: text.trim() })}
          >
            {addMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : "Add Comment"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
