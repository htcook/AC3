/**
 * Rules of Engagement (RoE) Builder
 * 
 * Interactive multi-step wizard for creating FedRAMP/NIST 800-115 compliant
 * Rules of Engagement documents. Supports scope definition, testing type
 * selection, personnel management, and document lifecycle management.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import {
  Shield, FileText, Plus, Trash2, ChevronRight, ChevronLeft,
  Building2, Users, Target, Calendar, MessageSquare, AlertTriangle,
  Lock, Scale, CheckCircle2, Send, Copy, Archive, Eye, Pencil,
  Globe, Server, Network, Cloud, Wifi, MapPin, Clock, Loader2,
  ShieldCheck, ShieldAlert, Crosshair, Zap, Brain, Bug, Skull,
  Mail, Phone, User, Briefcase, FileCheck, Download, MoreVertical,
  Play, Pause, XCircle, RefreshCw, Search
} from "lucide-react";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuTrigger, DropdownMenuSeparator
} from "@/components/ui/dropdown-menu";

// ─── Status Helpers ─────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: any }> = {
  draft: { label: "Draft", color: "text-gray-400 bg-gray-500/10 border-gray-500/30", icon: Pencil },
  pending_review: { label: "Pending Review", color: "text-amber-400 bg-amber-500/10 border-amber-500/30", icon: Clock },
  approved: { label: "Approved", color: "text-green-400 bg-green-500/10 border-green-500/30", icon: CheckCircle2 },
  active: { label: "Active", color: "text-blue-400 bg-blue-500/10 border-blue-500/30", icon: Play },
  completed: { label: "Completed", color: "text-purple-400 bg-purple-500/10 border-purple-500/30", icon: FileCheck },
  archived: { label: "Archived", color: "text-gray-500 bg-gray-600/10 border-gray-600/30", icon: Archive },
};

const WIZARD_STEPS = [
  { id: "intro", label: "Authorization", icon: Shield, description: "Organization details and document purpose" },
  { id: "scope", label: "Scope", icon: Target, description: "In-scope and out-of-scope assets" },
  { id: "testing", label: "Testing Types", icon: Crosshair, description: "Select testing methodologies and attack vectors" },
  { id: "schedule", label: "Schedule", icon: Calendar, description: "Testing windows, dates, and logistics" },
  { id: "comms", label: "Communications", icon: MessageSquare, description: "Communication protocols and incident response" },
  { id: "data", label: "Data Handling", icon: Lock, description: "Evidence handling, PII, and retention policies" },
  { id: "legal", label: "Legal", icon: Scale, description: "Legal jurisdiction, NDA, and compliance" },
  { id: "personnel", label: "Personnel", icon: Users, description: "Points of contact and team members" },
  { id: "review", label: "Review", icon: FileCheck, description: "Final review and submission" },
];

// ─── Main Component ─────────────────────────────────────────────────────────────

export default function RoeBuilder() {
  const [view, setView] = useState<"list" | "create" | "edit">("list");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");

  return (
    <AppShell activePath="/roe-builder">
      <div className="min-h-screen bg-background text-foreground">
        <div className="max-w-7xl mx-auto px-4 py-6">
          {view === "list" && (
            <RoeListView
              onCreateNew={() => setView("create")}
              onEdit={(id) => { setSelectedId(id); setView("edit"); }}
              filterStatus={filterStatus}
              setFilterStatus={setFilterStatus}
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
            />
          )}
          {view === "create" && (
            <RoeCreateWizard
              onBack={() => setView("list")}
              onCreated={(id) => { setSelectedId(id); setView("edit"); }}
            />
          )}
          {view === "edit" && selectedId && (
            <RoeEditWizard
              roeId={selectedId}
              onBack={() => { setSelectedId(null); setView("list"); }}
            />
          )}
        </div>
      </div>
    </AppShell>
  );
}

// ─── List View ──────────────────────────────────────────────────────────────────

function RoeListView({
  onCreateNew, onEdit, filterStatus, setFilterStatus, searchQuery, setSearchQuery,
}: {
  onCreateNew: () => void;
  onEdit: (id: number) => void;
  filterStatus: string;
  setFilterStatus: (s: string) => void;
  searchQuery: string;
  setSearchQuery: (s: string) => void;
}) {
  const stats = trpc.roeBuilder.getStats.useQuery();
  const list = trpc.roeBuilder.list.useQuery(
    filterStatus !== "all" ? { status: filterStatus as any } : undefined
  );
  const deleteMut = trpc.roeBuilder.delete.useMutation({
    onSuccess: () => { list.refetch(); stats.refetch(); toast.success("RoE document deleted"); },
    onError: (e) => toast.error(sanitizeErrorForToast(e.message)),
  });
  const duplicateMut = trpc.roeBuilder.duplicate.useMutation({
    onSuccess: (data) => { list.refetch(); stats.refetch(); toast.success("RoE document duplicated"); onEdit(data.id); },
    onError: (e) => toast.error(sanitizeErrorForToast(e.message)),
  });
  const submitMut = trpc.roeBuilder.submitForReview.useMutation({
    onSuccess: () => { list.refetch(); stats.refetch(); toast.success("Submitted for review"); },
  });
  const approveMut = trpc.roeBuilder.approve.useMutation({
    onSuccess: () => { list.refetch(); stats.refetch(); toast.success("RoE approved"); },
  });
  const activateMut = trpc.roeBuilder.activate.useMutation({
    onSuccess: () => { list.refetch(); stats.refetch(); toast.success("RoE activated"); },
  });
  const archiveMut = trpc.roeBuilder.archive.useMutation({
    onSuccess: () => { list.refetch(); stats.refetch(); toast.success("RoE archived"); },
  });

  const handleExportPdf = async (docId: number) => {
    try {
      toast.success("Generating PDF...");
      const resp = await fetch(`/api/trpc/roeBuilder.exportPdfHtml?batch=1&input=${encodeURIComponent(JSON.stringify({ "0": { json: { id: docId } } }))}`, {
        credentials: "include",
      });
      const json = await resp.json();
      const html = json?.[0]?.result?.data?.json?.html;
      if (!html) {
        toast.error("Could not generate PDF. Document may be empty.");
        return;
      }
      const pdfWindow = window.open("", "_blank");
      if (pdfWindow) {
        pdfWindow.document.write(html);
        pdfWindow.document.close();
        setTimeout(() => pdfWindow.print(), 500);
      }
    } catch (err) {
      toast.error("PDF export failed. Please try again.");
    }
  };

  const filteredDocs = useMemo(() => {
    const docs = list.data || [];
    if (!searchQuery) return docs;
    const q = searchQuery.toLowerCase();
    return docs.filter((d: any) =>
      d.title?.toLowerCase().includes(q) ||
      d.organizationName?.toLowerCase().includes(q)
    );
  }, [list.data, searchQuery]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="w-7 h-7 text-primary" />
            Rules of Engagement
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Create and manage FedRAMP/NIST 800-115 compliant RoE documents for security assessments
          </p>
        </div>
        <Button onClick={onCreateNew} className="gap-2">
          <Plus className="w-4 h-4" /> New RoE Document
        </Button>
      </div>

      {/* Stats Cards */}
      {stats.data && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
          {[
            { label: "Total", value: stats.data.total, color: "text-foreground" },
            { label: "Draft", value: stats.data.draft, color: "text-gray-400" },
            { label: "Pending", value: stats.data.pendingReview, color: "text-amber-400" },
            { label: "Approved", value: stats.data.approved, color: "text-green-400" },
            { label: "Active", value: stats.data.active, color: "text-blue-400" },
            { label: "Completed", value: stats.data.completed, color: "text-purple-400" },
            { label: "Archived", value: stats.data.archived, color: "text-gray-500" },
          ].map((s) => (
            <Card key={s.label} className="text-center">
              <CardContent className="py-3 px-2">
                <div className={`text-xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-[10px] text-muted-foreground uppercase">{s.label}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-3 items-center">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search by title or organization..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Filter by status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="draft">Draft</SelectItem>
            <SelectItem value="pending_review">Pending Review</SelectItem>
            <SelectItem value="approved">Approved</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="archived">Archived</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Document List */}
      {list.isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          <span className="ml-2 text-muted-foreground">Loading documents...</span>
        </div>
      ) : filteredDocs.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Shield className="w-12 h-12 text-muted-foreground/40 mb-4" />
            <h3 className="text-lg font-medium mb-2">No RoE Documents</h3>
            <p className="text-sm text-muted-foreground max-w-md mb-4">
              Create your first Rules of Engagement document to define the scope, authorization, and terms for a security assessment.
            </p>
            <Button onClick={onCreateNew} variant="outline" className="gap-2">
              <Plus className="w-4 h-4" /> Create First RoE
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filteredDocs.map((doc: any) => {
            const statusCfg = STATUS_CONFIG[doc.status] || STATUS_CONFIG.draft;
            const StatusIcon = statusCfg.icon;
            return (
              <Card key={doc.id} className="hover:border-primary/30 transition-colors cursor-pointer" onClick={() => onEdit(doc.id)}>
                <CardContent className="py-4 px-5">
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-1">
                        <h3 className="font-semibold text-base truncate">{doc.title}</h3>
                        <Badge className={`${statusCfg.color} text-xs shrink-0`}>
                          <StatusIcon className="w-3 h-3 mr-1" />
                          {statusCfg.label}
                        </Badge>
                        {doc.fedrampCompliant && (
                          <Badge variant="outline" className="text-blue-400 border-blue-500/30 text-[10px]">FedRAMP</Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        {doc.organizationName && (
                          <span className="flex items-center gap-1"><Building2 className="w-3 h-3" />{doc.organizationName}</span>
                        )}
                        <span className="flex items-center gap-1"><FileText className="w-3 h-3" />v{doc.version}</span>
                        <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{new Date(doc.updatedAt).toLocaleDateString()}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 ml-4" onClick={(e) => e.stopPropagation()}>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" className="h-8 w-8">
                            <MoreVertical className="w-4 h-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => onEdit(doc.id)}>
                            <Pencil className="w-4 h-4 mr-2" /> Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => duplicateMut.mutate({ id: doc.id, newTitle: `${doc.title} (Copy)` })}>
                            <Copy className="w-4 h-4 mr-2" /> Duplicate
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleExportPdf(doc.id)}>
                            <Download className="w-4 h-4 mr-2" /> Export PDF
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          {doc.status === "draft" && (
                            <DropdownMenuItem onClick={() => submitMut.mutate({ id: doc.id })}>
                              <Send className="w-4 h-4 mr-2" /> Submit for Review
                            </DropdownMenuItem>
                          )}
                          {doc.status === "pending_review" && (
                            <DropdownMenuItem onClick={() => approveMut.mutate({ id: doc.id })}>
                              <CheckCircle2 className="w-4 h-4 mr-2" /> Approve
                            </DropdownMenuItem>
                          )}
                          {doc.status === "approved" && (
                            <DropdownMenuItem onClick={() => activateMut.mutate({ id: doc.id })}>
                              <Play className="w-4 h-4 mr-2" /> Activate
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuSeparator />
                          <DropdownMenuItem onClick={() => archiveMut.mutate({ id: doc.id })} className="text-amber-400">
                            <Archive className="w-4 h-4 mr-2" /> Archive
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => { if (confirm("Delete this RoE document?")) deleteMut.mutate({ id: doc.id }); }} className="text-red-400">
                            <Trash2 className="w-4 h-4 mr-2" /> Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Create Wizard ──────────────────────────────────────────────────────────────

function RoeCreateWizard({ onBack, onCreated }: { onBack: () => void; onCreated: (id: number) => void }) {
  const [title, setTitle] = useState("");
  const [orgName, setOrgName] = useState("");
  const [firmName, setFirmName] = useState("ACE C3 — AceofCloud");
  const [fedramp, setFedramp] = useState(false);
  const [impactLevel, setImpactLevel] = useState("not_applicable");
  const [serviceModel, setServiceModel] = useState("not_applicable");

  const createMut = trpc.roeBuilder.create.useMutation({
    onSuccess: (data) => {
      toast.success("RoE document created");
      onCreated(data.id);
    },
    onError: (e) => toast.error(sanitizeErrorForToast(e.message)),
  });

  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" onClick={onBack} className="gap-1">
          <ChevronLeft className="w-4 h-4" /> Back
        </Button>
        <h2 className="text-xl font-bold">Create New RoE Document</h2>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            Document Setup
          </CardTitle>
          <CardDescription>
            Configure the basic properties for your Rules of Engagement document
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="space-y-2">
            <Label>Document Title *</Label>
            <Input
              placeholder="e.g., Q1 2026 External Penetration Test — Acme Corp"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Client Organization</Label>
              <Input
                placeholder="Organization name"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Testing Firm</Label>
              <Input
                value={firmName}
                onChange={(e) => setFirmName(e.target.value)}
              />
            </div>
          </div>

          <Separator />

          <div className="flex items-center justify-between">
            <div>
              <Label className="text-base">FedRAMP Compliance</Label>
              <p className="text-xs text-muted-foreground mt-0.5">
                Enable FedRAMP-specific requirements per FedRAMP Penetration Test Guidance v4.0
              </p>
            </div>
            <Switch checked={fedramp} onCheckedChange={setFedramp} />
          </div>

          {fedramp && (
            <div className="grid grid-cols-2 gap-4 p-4 rounded-lg border border-blue-500/20 bg-blue-500/5">
              <div className="space-y-2">
                <Label>Impact Level</Label>
                <Select value={impactLevel} onValueChange={setImpactLevel}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="moderate">Moderate</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="not_applicable">Not Applicable</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Service Model</Label>
                <Select value={serviceModel} onValueChange={setServiceModel}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="iaas">IaaS</SelectItem>
                    <SelectItem value="paas">PaaS</SelectItem>
                    <SelectItem value="saas">SaaS</SelectItem>
                    <SelectItem value="hybrid">Hybrid</SelectItem>
                    <SelectItem value="not_applicable">Not Applicable</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          <Button
            onClick={() => createMut.mutate({
              title,
              organizationName: orgName || undefined,
              testingFirmName: firmName || undefined,
              fedrampCompliant: fedramp,
              fedrampImpactLevel: impactLevel as any,
              serviceModel: serviceModel as any,
            })}
            disabled={!title || createMut.isPending}
            className="w-full"
            size="lg"
          >
            {createMut.isPending ? (
              <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Creating...</>
            ) : (
              <><Plus className="w-4 h-4 mr-2" /> Create RoE Document</>
            )}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Edit Wizard ────────────────────────────────────────────────────────────────

function RoeEditWizard({ roeId, onBack }: { roeId: number; onBack: () => void }) {
  const [currentStep, setCurrentStep] = useState(0);
  const doc = trpc.roeBuilder.getById.useQuery({ id: roeId });
  const defaults = trpc.roeBuilder.getDefaults.useQuery();
  const updateMut = trpc.roeBuilder.update.useMutation({
    onSuccess: () => { doc.refetch(); toast.success("Saved"); },
    onError: (e) => toast.error(sanitizeErrorForToast(e.message)),
  });

  if (doc.isLoading || defaults.isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!doc.data) {
    return (
      <div className="text-center py-20">
        <p className="text-muted-foreground">Document not found</p>
        <Button variant="outline" onClick={onBack} className="mt-4">Go Back</Button>
      </div>
    );
  }

  const roe = doc.data;
  const step = WIZARD_STEPS[currentStep];
  const statusCfg = STATUS_CONFIG[roe.status] || STATUS_CONFIG.draft;

  const saveField = (field: string, value: any) => {
    updateMut.mutate({ id: roeId, [field]: value } as any);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={onBack} className="gap-1">
            <ChevronLeft className="w-4 h-4" /> Back
          </Button>
          <div>
            <h2 className="text-xl font-bold">{roe.title}</h2>
            <div className="flex items-center gap-2 mt-0.5">
              <Badge className={`${statusCfg.color} text-xs`}>{statusCfg.label}</Badge>
              <span className="text-xs text-muted-foreground">v{roe.version}</span>
              {roe.fedrampCompliant && (
                <Badge variant="outline" className="text-blue-400 border-blue-500/30 text-[10px]">FedRAMP</Badge>
              )}
            </div>
          </div>
        </div>
        <div className="flex gap-2">
          {updateMut.isPending && <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />}
        </div>
      </div>

      {/* Step Navigation */}
      <div className="flex gap-1 overflow-x-auto pb-2">
        {WIZARD_STEPS.map((s, idx) => {
          const StepIcon = s.icon;
          const isActive = idx === currentStep;
          const isPast = idx < currentStep;
          return (
            <button
              key={s.id}
              onClick={() => setCurrentStep(idx)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-all shrink-0 ${
                isActive
                  ? "bg-primary text-primary-foreground"
                  : isPast
                  ? "bg-primary/10 text-primary hover:bg-primary/20"
                  : "bg-muted/50 text-muted-foreground hover:bg-muted"
              }`}
            >
              <StepIcon className="w-3.5 h-3.5" />
              {s.label}
            </button>
          );
        })}
      </div>

      {/* Step Content */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {(() => { const I = step.icon; return <I className="w-5 h-5 text-primary" />; })()}
            {step.label}
          </CardTitle>
          <CardDescription>{step.description}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {currentStep === 0 && <AuthorizationStep roe={roe} saveField={saveField} />}
          {currentStep === 1 && <ScopeStep roe={roe} saveField={saveField} />}
          {currentStep === 2 && <TestingTypesStep roe={roe} saveField={saveField} defaults={defaults.data} />}
          {currentStep === 3 && <ScheduleStep roe={roe} saveField={saveField} defaults={defaults.data} />}
          {currentStep === 4 && <CommunicationsStep roe={roe} saveField={saveField} />}
          {currentStep === 5 && <DataHandlingStep roe={roe} saveField={saveField} />}
          {currentStep === 6 && <LegalStep roe={roe} saveField={saveField} defaults={defaults.data} />}
          {currentStep === 7 && <PersonnelStep roeId={roeId} personnel={roe.personnel} defaults={defaults.data} refetch={doc.refetch} />}
          {currentStep === 8 && <ReviewStep roe={roe} onBack={onBack} refetch={doc.refetch} />}
        </CardContent>
      </Card>

      {/* Navigation Buttons */}
      <div className="flex justify-between">
        <Button
          variant="outline"
          onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
          disabled={currentStep === 0}
          className="gap-1"
        >
          <ChevronLeft className="w-4 h-4" /> Previous
        </Button>
        <Button
          onClick={() => setCurrentStep(Math.min(WIZARD_STEPS.length - 1, currentStep + 1))}
          disabled={currentStep === WIZARD_STEPS.length - 1}
          className="gap-1"
        >
          Next <ChevronRight className="w-4 h-4" />
        </Button>
      </div>
    </div>
  );
}

// ─── Step 1: Authorization ──────────────────────────────────────────────────────

function AuthorizationStep({ roe, saveField }: { roe: any; saveField: (f: string, v: any) => void }) {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Document Title</Label>
          <Input defaultValue={roe.title || ""} onBlur={(e) => saveField("title", e.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>Version</Label>
          <Input defaultValue={roe.version || "1.0"} onBlur={(e) => saveField("version", e.target.value)} />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Client Organization Name</Label>
          <Input defaultValue={roe.organizationName || ""} onBlur={(e) => saveField("organizationName", e.target.value)} />
        </div>
        <div className="space-y-2">
          <Label>Testing Firm Name</Label>
          <Input defaultValue={roe.testingFirmName || ""} onBlur={(e) => saveField("testingFirmName", e.target.value)} />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Client Organization Address</Label>
          <Textarea defaultValue={roe.organizationAddress || ""} onBlur={(e) => saveField("organizationAddress", e.target.value)} rows={3} />
        </div>
        <div className="space-y-2">
          <Label>Testing Firm Address</Label>
          <Textarea defaultValue={roe.testingFirmAddress || ""} onBlur={(e) => saveField("testingFirmAddress", e.target.value)} rows={3} />
        </div>
      </div>

      <div className="space-y-2">
        <Label>Purpose Statement (NIST 800-115 Section 1)</Label>
        <Textarea
          defaultValue={roe.purpose || ""}
          onBlur={(e) => saveField("purpose", e.target.value)}
          rows={5}
          placeholder="Describe the purpose and authorization for this security assessment..."
        />
      </div>

      <div className="space-y-2">
        <Label>Assumptions</Label>
        <Textarea
          defaultValue={roe.assumptions || ""}
          onBlur={(e) => saveField("assumptions", e.target.value)}
          rows={3}
          placeholder="List any assumptions made for this engagement..."
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Limitations</Label>
          <Textarea
            defaultValue={roe.limitations || ""}
            onBlur={(e) => saveField("limitations", e.target.value)}
            rows={3}
            placeholder="Known limitations or constraints..."
          />
        </div>
        <div className="space-y-2">
          <Label>Risks</Label>
          <Textarea
            defaultValue={roe.risks || ""}
            onBlur={(e) => saveField("risks", e.target.value)}
            rows={3}
            placeholder="Potential risks associated with testing..."
          />
        </div>
      </div>
    </div>
  );
}

// ─── Step 2: Scope ──────────────────────────────────────────────────────────────

function ScopeStep({ roe, saveField }: { roe: any; saveField: (f: string, v: any) => void }) {
  const [newDomain, setNewDomain] = useState("");
  const [newIpRange, setNewIpRange] = useState("");
  const [newApp, setNewApp] = useState("");
  const [newExclDomain, setNewExclDomain] = useState("");

  const inScopeDomains = (roe.inScopeDomains as any[]) || [];
  const outOfScopeDomains = (roe.outOfScopeDomains as any[]) || [];
  const inScopeIpRanges = (roe.inScopeIpRanges as any[]) || [];
  const inScopeApplications = (roe.inScopeApplications as any[]) || [];

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Label>Scope Description</Label>
        <Textarea
          defaultValue={roe.scopeDescription || ""}
          onBlur={(e) => saveField("scopeDescription", e.target.value)}
          rows={3}
          placeholder="High-level description of the assessment scope..."
        />
      </div>

      {/* In-Scope Domains */}
      <div className="space-y-3">
        <Label className="flex items-center gap-2"><Globe className="w-4 h-4 text-green-400" /> In-Scope Domains</Label>
        <div className="flex gap-2">
          <Input
            placeholder="example.com"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && newDomain) {
                saveField("inScopeDomains", [...inScopeDomains, { domain: newDomain, includeSubdomains: true }]);
                setNewDomain("");
              }
            }}
          />
          <Button variant="outline" size="sm" onClick={() => {
            if (newDomain) {
              saveField("inScopeDomains", [...inScopeDomains, { domain: newDomain, includeSubdomains: true }]);
              setNewDomain("");
            }
          }}>
            <Plus className="w-4 h-4" />
          </Button>
        </div>
        <div className="flex flex-wrap gap-2">
          {inScopeDomains.map((d: any, i: number) => (
            <Badge key={i} variant="outline" className="text-green-400 border-green-500/30 gap-1">
              <Globe className="w-3 h-3" /> {d.domain}
              {d.includeSubdomains && <span className="text-[9px] opacity-60">+subs</span>}
              <button onClick={() => saveField("inScopeDomains", inScopeDomains.filter((_: any, j: number) => j !== i))} className="ml-1 hover:text-red-400">
                <XCircle className="w-3 h-3" />
              </button>
            </Badge>
          ))}
        </div>
      </div>

      {/* In-Scope IP Ranges */}
      <div className="space-y-3">
        <Label className="flex items-center gap-2"><Network className="w-4 h-4 text-blue-400" /> In-Scope IP Ranges</Label>
        <div className="flex gap-2">
          <Input
            placeholder="10.0.0.0/24"
            value={newIpRange}
            onChange={(e) => setNewIpRange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && newIpRange) {
                saveField("inScopeIpRanges", [...inScopeIpRanges, { cidr: newIpRange }]);
                setNewIpRange("");
              }
            }}
          />
          <Button variant="outline" size="sm" onClick={() => {
            if (newIpRange) {
              saveField("inScopeIpRanges", [...inScopeIpRanges, { cidr: newIpRange }]);
              setNewIpRange("");
            }
          }}>
            <Plus className="w-4 h-4" />
          </Button>
        </div>
        <div className="flex flex-wrap gap-2">
          {inScopeIpRanges.map((r: any, i: number) => (
            <Badge key={i} variant="outline" className="text-blue-400 border-blue-500/30 gap-1">
              <Network className="w-3 h-3" /> {r.cidr}
              <button onClick={() => saveField("inScopeIpRanges", inScopeIpRanges.filter((_: any, j: number) => j !== i))} className="ml-1 hover:text-red-400">
                <XCircle className="w-3 h-3" />
              </button>
            </Badge>
          ))}
        </div>
      </div>

      {/* In-Scope Applications */}
      <div className="space-y-3">
        <Label className="flex items-center gap-2"><Target className="w-4 h-4 text-purple-400" /> In-Scope Applications</Label>
        <div className="flex gap-2">
          <Input
            placeholder="Application name or URL"
            value={newApp}
            onChange={(e) => setNewApp(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && newApp) {
                saveField("inScopeApplications", [...inScopeApplications, { name: newApp }]);
                setNewApp("");
              }
            }}
          />
          <Button variant="outline" size="sm" onClick={() => {
            if (newApp) {
              saveField("inScopeApplications", [...inScopeApplications, { name: newApp }]);
              setNewApp("");
            }
          }}>
            <Plus className="w-4 h-4" />
          </Button>
        </div>
        <div className="flex flex-wrap gap-2">
          {inScopeApplications.map((a: any, i: number) => (
            <Badge key={i} variant="outline" className="text-purple-400 border-purple-500/30 gap-1">
              <Target className="w-3 h-3" /> {a.name}
              <button onClick={() => saveField("inScopeApplications", inScopeApplications.filter((_: any, j: number) => j !== i))} className="ml-1 hover:text-red-400">
                <XCircle className="w-3 h-3" />
              </button>
            </Badge>
          ))}
        </div>
      </div>

      <Separator />

      {/* Out-of-Scope Domains */}
      <div className="space-y-3">
        <Label className="flex items-center gap-2"><ShieldAlert className="w-4 h-4 text-red-400" /> Out-of-Scope / Exclusions</Label>
        <div className="flex gap-2">
          <Input
            placeholder="excluded-system.example.com"
            value={newExclDomain}
            onChange={(e) => setNewExclDomain(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && newExclDomain) {
                saveField("outOfScopeDomains", [...outOfScopeDomains, { domain: newExclDomain }]);
                setNewExclDomain("");
              }
            }}
          />
          <Button variant="outline" size="sm" onClick={() => {
            if (newExclDomain) {
              saveField("outOfScopeDomains", [...outOfScopeDomains, { domain: newExclDomain }]);
              setNewExclDomain("");
            }
          }}>
            <Plus className="w-4 h-4" />
          </Button>
        </div>
        <div className="flex flex-wrap gap-2">
          {outOfScopeDomains.map((d: any, i: number) => (
            <Badge key={i} variant="outline" className="text-red-400 border-red-500/30 gap-1">
              <XCircle className="w-3 h-3" /> {d.domain}
              <button onClick={() => saveField("outOfScopeDomains", outOfScopeDomains.filter((_: any, j: number) => j !== i))} className="ml-1 hover:text-red-400">
                <XCircle className="w-3 h-3" />
              </button>
            </Badge>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Step 3: Testing Types ──────────────────────────────────────────────────────

function TestingTypesStep({ roe, saveField, defaults }: { roe: any; saveField: (f: string, v: any) => void; defaults: any }) {
  const testingTypes = (roe.testingTypes as any[]) || defaults?.testingTypes || [];
  const attackVectors = (roe.attackVectors as any[]) || defaults?.attackVectors || [];

  const categoryIcons: Record<string, any> = {
    pentest: Bug,
    red_team: Skull,
    purple_team: Eye,
    social_engineering: Mail,
    physical: MapPin,
    wireless: Wifi,
    cloud: Cloud,
  };

  const categoryLabels: Record<string, string> = {
    pentest: "Penetration Testing",
    red_team: "Red Team Operations",
    purple_team: "Purple Team Exercises",
    social_engineering: "Social Engineering",
    physical: "Physical Security",
    wireless: "Wireless Security",
    cloud: "Cloud Security",
  };

  const grouped = testingTypes.reduce((acc: Record<string, any[]>, t: any) => {
    if (!acc[t.category]) acc[t.category] = [];
    acc[t.category].push(t);
    return acc;
  }, {});

  const toggleTestingType = (typeId: string) => {
    const updated = testingTypes.map((t: any) =>
      t.id === typeId ? { ...t, enabled: !t.enabled } : t
    );
    saveField("testingTypes", updated);
  };

  const toggleAttackVector = (vectorId: string) => {
    const updated = attackVectors.map((v: any) =>
      v.id === vectorId ? { ...v, enabled: !v.enabled } : v
    );
    saveField("attackVectors", updated);
  };

  const enabledCount = testingTypes.filter((t: any) => t.enabled).length;
  const enabledVectors = attackVectors.filter((v: any) => v.enabled).length;

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="flex gap-4">
        <div className="text-center p-3 rounded-lg bg-primary/10 border border-primary/20 flex-1">
          <div className="text-2xl font-bold text-primary">{enabledCount}</div>
          <div className="text-xs text-muted-foreground">Testing Types Selected</div>
        </div>
        <div className="text-center p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 flex-1">
          <div className="text-2xl font-bold text-amber-400">{enabledVectors}</div>
          <div className="text-xs text-muted-foreground">Attack Vectors Enabled</div>
        </div>
      </div>

      {/* Testing Types by Category */}
      <div className="space-y-4">
        <h3 className="text-sm font-semibold uppercase text-muted-foreground">Testing Methodologies</h3>
        {Object.entries(grouped).map(([category, types]) => {
          const Icon = categoryIcons[category] || Crosshair;
          const label = categoryLabels[category] || category;
          return (
            <div key={category} className="space-y-2">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <Icon className="w-4 h-4 text-muted-foreground" />
                {label}
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {(types as any[]).map((t: any) => (
                  <button
                    key={t.id}
                    onClick={() => toggleTestingType(t.id)}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      t.enabled
                        ? "border-primary bg-primary/10 ring-1 ring-primary/30"
                        : "border-border hover:border-muted-foreground/30"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-sm">{t.name}</span>
                      <Switch checked={t.enabled} onCheckedChange={() => toggleTestingType(t.id)} />
                    </div>
                    <p className="text-xs text-muted-foreground line-clamp-2">{t.description}</p>
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      <Separator />

      {/* Attack Vectors */}
      <div className="space-y-4">
        <h3 className="text-sm font-semibold uppercase text-muted-foreground">
          Attack Vectors
          {roe.fedrampCompliant && (
            <Badge variant="outline" className="ml-2 text-blue-400 border-blue-500/30 text-[10px]">FedRAMP Required Vectors Marked</Badge>
          )}
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {attackVectors.map((v: any) => (
            <button
              key={v.id}
              onClick={() => toggleAttackVector(v.id)}
              className={`p-3 rounded-lg border text-left transition-all ${
                v.enabled
                  ? "border-amber-500 bg-amber-500/10 ring-1 ring-amber-500/30"
                  : v.fedrampRequired && roe.fedrampCompliant
                  ? "border-blue-500/30 bg-blue-500/5"
                  : "border-border hover:border-muted-foreground/30"
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-sm">{v.name}</span>
                  {v.fedrampRequired && roe.fedrampCompliant && (
                    <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30 text-[9px] px-1">FedRAMP</Badge>
                  )}
                </div>
                <Switch checked={v.enabled} onCheckedChange={() => toggleAttackVector(v.id)} />
              </div>
              <p className="text-xs text-muted-foreground line-clamp-2">{v.description}</p>
            </button>
          ))}
        </div>
      </div>

      <Separator />

      {/* Execution Constraints */}
      <div className="space-y-4">
        <h3 className="text-sm font-semibold uppercase text-muted-foreground">Execution Constraints</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {[
            { field: "dosTestingAllowed", label: "DoS Testing", desc: "Allow denial-of-service testing" },
            { field: "physicalTestingAllowed", label: "Physical Testing", desc: "Allow physical access testing" },
            { field: "wirelessTestingAllowed", label: "Wireless Testing", desc: "Allow wireless network testing" },
            { field: "socialEngineeringAllowed", label: "Social Engineering", desc: "Allow social engineering attacks" },
            { field: "credentialedTesting", label: "Credentialed Testing", desc: "Provide test credentials" },
            { field: "pivotingAllowed", label: "Pivoting", desc: "Allow lateral movement" },
            { field: "exfiltrationAllowed", label: "Data Exfiltration", desc: "Allow data exfiltration testing" },
            { field: "persistenceAllowed", label: "Persistence", desc: "Allow persistence mechanisms" },
            { field: "fileModificationAllowed", label: "File Modification", desc: "Allow modifying target files" },
          ].map((c) => (
            <div key={c.field} className="flex items-center justify-between p-3 rounded-lg border border-border">
              <div>
                <div className="text-sm font-medium">{c.label}</div>
                <div className="text-[10px] text-muted-foreground">{c.desc}</div>
              </div>
              <Switch
                checked={!!(roe as any)[c.field]}
                onCheckedChange={(v) => saveField(c.field, v)}
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Step 4: Schedule ───────────────────────────────────────────────────────────

function ScheduleStep({ roe, saveField, defaults }: { roe: any; saveField: (f: string, v: any) => void; defaults: any }) {
  const testingDays = (roe.testingDays as string[]) || [];
  const allDays = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Test Start Date</Label>
          <Input
            type="date"
            defaultValue={roe.testScheduleStart ? new Date(roe.testScheduleStart).toISOString().split("T")[0] : ""}
            onChange={(e) => saveField("testScheduleStart", e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label>Test End Date</Label>
          <Input
            type="date"
            defaultValue={roe.testScheduleEnd ? new Date(roe.testScheduleEnd).toISOString().split("T")[0] : ""}
            onChange={(e) => saveField("testScheduleEnd", e.target.value)}
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Testing Window Start (Time)</Label>
          <Input
            type="time"
            defaultValue={roe.testingWindowStart || "08:00"}
            onChange={(e) => saveField("testingWindowStart", e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label>Testing Window End (Time)</Label>
          <Input
            type="time"
            defaultValue={roe.testingWindowEnd || "18:00"}
            onChange={(e) => saveField("testingWindowEnd", e.target.value)}
          />
        </div>
      </div>

      <div className="space-y-2">
        <Label>Timezone</Label>
        <Select defaultValue={roe.testTimezone || "America/New_York"} onValueChange={(v) => saveField("testTimezone", v)}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            {(defaults?.timezones || []).map((tz: string) => (
              <SelectItem key={tz} value={tz}>{tz}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <Label>Testing Days</Label>
        <div className="flex flex-wrap gap-2">
          {allDays.map((day) => (
            <button
              key={day}
              onClick={() => {
                const updated = testingDays.includes(day)
                  ? testingDays.filter((d: string) => d !== day)
                  : [...testingDays, day];
                saveField("testingDays", updated);
              }}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium capitalize transition-all ${
                testingDays.includes(day)
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted text-muted-foreground hover:bg-muted/80"
              }`}
            >
              {day}
            </button>
          ))}
        </div>
      </div>

      <Separator />

      <div className="grid grid-cols-3 gap-3">
        <div className="flex items-center justify-between p-3 rounded-lg border border-border">
          <div>
            <div className="text-sm font-medium">Remote Testing</div>
            <div className="text-[10px] text-muted-foreground">Allow remote access</div>
          </div>
          <Switch checked={!!roe.remoteTestingAllowed} onCheckedChange={(v) => saveField("remoteTestingAllowed", v)} />
        </div>
        <div className="flex items-center justify-between p-3 rounded-lg border border-border">
          <div>
            <div className="text-sm font-medium">VPN Required</div>
            <div className="text-[10px] text-muted-foreground">Require VPN connection</div>
          </div>
          <Switch checked={!!roe.vpnRequired} onCheckedChange={(v) => saveField("vpnRequired", v)} />
        </div>
        <div className="flex items-center justify-between p-3 rounded-lg border border-border">
          <div>
            <div className="text-sm font-medium">Badge/Escort</div>
            <div className="text-[10px] text-muted-foreground">Require badge or escort</div>
          </div>
          <Switch checked={!!roe.badgeEscortRequired} onCheckedChange={(v) => saveField("badgeEscortRequired", v)} />
        </div>
      </div>
    </div>
  );
}

// ─── Step 5: Communications ─────────────────────────────────────────────────────

function CommunicationsStep({ roe, saveField }: { roe: any; saveField: (f: string, v: any) => void }) {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-3 gap-4">
        <div className="space-y-2">
          <Label>Communication Frequency</Label>
          <Select defaultValue={roe.communicationFrequency || "daily"} onValueChange={(v) => saveField("communicationFrequency", v)}>
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
          <Select defaultValue={roe.communicationMethod || "secure_portal"} onValueChange={(v) => saveField("communicationMethod", v)}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="email">Email</SelectItem>
              <SelectItem value="phone">Phone</SelectItem>
              <SelectItem value="secure_portal">Secure Portal</SelectItem>
              <SelectItem value="encrypted_email">Encrypted Email</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Status Report Frequency</Label>
          <Select defaultValue={roe.statusReportFrequency || "daily"} onValueChange={(v) => saveField("statusReportFrequency", v)}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="daily">Daily</SelectItem>
              <SelectItem value="weekly">Weekly</SelectItem>
              <SelectItem value="milestone-based">Milestone-Based</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-2">
        <Label>Incident Response Procedure</Label>
        <Textarea
          defaultValue={roe.incidentResponseProcedure || ""}
          onBlur={(e) => saveField("incidentResponseProcedure", e.target.value)}
          rows={5}
          placeholder="Define the incident response procedure during testing..."
        />
      </div>

      <div className="space-y-2">
        <Label>Emergency Halt Criteria</Label>
        <Textarea
          defaultValue={roe.emergencyHaltCriteria || ""}
          onBlur={(e) => saveField("emergencyHaltCriteria", e.target.value)}
          rows={4}
          placeholder="Define conditions that require immediate halt of testing..."
        />
      </div>

      <div className="space-y-2">
        <Label>Resumption Procedure</Label>
        <Textarea
          defaultValue={roe.resumptionProcedure || ""}
          onBlur={(e) => saveField("resumptionProcedure", e.target.value)}
          rows={3}
          placeholder="Procedure for resuming testing after a halt..."
        />
      </div>

      <div className="space-y-2">
        <Label>Critical Finding Notification Policy</Label>
        <Textarea
          defaultValue={roe.criticalFindingNotification || ""}
          onBlur={(e) => saveField("criticalFindingNotification", e.target.value)}
          rows={3}
          placeholder="How and when critical findings will be reported..."
        />
      </div>

      <div className="space-y-2">
        <Label>Shunning Policy</Label>
        <Select defaultValue={roe.shunningPolicy || "notify_first"} onValueChange={(v) => saveField("shunningPolicy", v)}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="allowed">Allowed — Client may block test IPs</SelectItem>
            <SelectItem value="not_allowed">Not Allowed — Client must not block test IPs</SelectItem>
            <SelectItem value="notify_first">Notify First — Client notifies before blocking</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}

// ─── Step 6: Data Handling ──────────────────────────────────────────────────────

function DataHandlingStep({ roe, saveField }: { roe: any; saveField: (f: string, v: any) => void }) {
  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <Label>Data Handling Procedure (NIST 800-115 Section 5.3)</Label>
        <Textarea
          defaultValue={roe.dataHandlingProcedure || ""}
          onBlur={(e) => saveField("dataHandlingProcedure", e.target.value)}
          rows={5}
        />
      </div>

      <div className="space-y-2">
        <Label>PII/PHI Handling Policy</Label>
        <Textarea
          defaultValue={roe.piiHandlingPolicy || ""}
          onBlur={(e) => saveField("piiHandlingPolicy", e.target.value)}
          rows={4}
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="space-y-2">
          <Label>Evidence Retention (Days)</Label>
          <Input
            type="number"
            defaultValue={roe.evidenceRetentionDays || 90}
            onBlur={(e) => saveField("evidenceRetentionDays", parseInt(e.target.value))}
          />
        </div>
        <div className="space-y-2">
          <Label>Destruction Method</Label>
          <Select defaultValue={roe.evidenceDestructionMethod || "secure_delete"} onValueChange={(v) => saveField("evidenceDestructionMethod", v)}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="secure_delete">Secure Delete (DoD 5220.22-M)</SelectItem>
              <SelectItem value="physical_destruction">Physical Destruction</SelectItem>
              <SelectItem value="crypto_erase">Cryptographic Erasure</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center justify-between p-3 rounded-lg border border-border">
          <div>
            <div className="text-sm font-medium">Encryption Required</div>
            <div className="text-[10px] text-muted-foreground">AES-256 at rest</div>
          </div>
          <Switch checked={!!roe.evidenceEncryptionRequired} onCheckedChange={(v) => saveField("evidenceEncryptionRequired", v)} />
        </div>
      </div>

      <Separator />

      <div className="space-y-2">
        <Label>Report Frequency</Label>
        <Select defaultValue={roe.reportFrequency || "final_only"} onValueChange={(v) => saveField("reportFrequency", v)}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="daily">Daily Reports</SelectItem>
            <SelectItem value="weekly">Weekly Reports</SelectItem>
            <SelectItem value="final_only">Final Report Only</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Report Deliverables */}
      <div className="space-y-3">
        <Label>Report Deliverables</Label>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {((roe.reportDeliverables as any[]) || []).map((d: any, i: number) => (
            <div key={d.id} className={`p-3 rounded-lg border ${d.required ? "border-primary/30 bg-primary/5" : "border-border"}`}>
              <div className="flex items-center justify-between mb-1">
                <span className="font-medium text-sm">{d.name}</span>
                {d.required && <Badge className="bg-primary/20 text-primary text-[9px]">Required</Badge>}
              </div>
              <p className="text-xs text-muted-foreground">{d.description}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Step 7: Legal ──────────────────────────────────────────────────────────────

function LegalStep({ roe, saveField, defaults }: { roe: any; saveField: (f: string, v: any) => void; defaults: any }) {
  const frameworks = (roe.complianceFrameworks as string[]) || [];

  return (
    <div className="space-y-5">
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
          <div className="text-xs text-muted-foreground">Require signed NDA before engagement</div>
        </div>
        <Switch checked={!!roe.ndaRequired} onCheckedChange={(v) => saveField("ndaRequired", v)} />
      </div>

      {roe.ndaRequired && (
        <div className="space-y-2">
          <Label>NDA Reference Number</Label>
          <Input
            defaultValue={roe.ndaReference || ""}
            onBlur={(e) => saveField("ndaReference", e.target.value)}
            placeholder="e.g., NDA-2026-001"
          />
        </div>
      )}

      <div className="space-y-2">
        <Label>Liability Waiver / Indemnification</Label>
        <Textarea
          defaultValue={roe.liabilityWaiver || ""}
          onBlur={(e) => saveField("liabilityWaiver", e.target.value)}
          rows={4}
          placeholder="Liability waiver and indemnification terms..."
        />
      </div>

      <Separator />

      <div className="space-y-3">
        <Label>Applicable Compliance Frameworks</Label>
        <div className="flex flex-wrap gap-2">
          {(defaults?.complianceFrameworks || []).map((fw: string) => (
            <button
              key={fw}
              onClick={() => {
                const updated = frameworks.includes(fw)
                  ? frameworks.filter((f: string) => f !== fw)
                  : [...frameworks, fw];
                saveField("complianceFrameworks", updated);
              }}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                frameworks.includes(fw)
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted text-muted-foreground hover:bg-muted/80"
              }`}
            >
              {fw}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Step 8: Personnel ──────────────────────────────────────────────────────────

function PersonnelStep({ roeId, personnel, defaults, refetch }: { roeId: number; personnel: any[]; defaults: any; refetch: () => void }) {
  const [showAdd, setShowAdd] = useState(false);
  const [newPerson, setNewPerson] = useState({ role: "customer_poc" as const, name: "", title: "", organization: "", email: "", phone: "" });

  const addMut = trpc.roeBuilder.addPersonnel.useMutation({
    onSuccess: () => { refetch(); setShowAdd(false); setNewPerson({ role: "customer_poc" as const, name: "", title: "", organization: "", email: "", phone: "" }); toast.success("Personnel added"); },
    onError: (e) => toast.error(sanitizeErrorForToast(e.message)),
  });
  const removeMut = trpc.roeBuilder.removePersonnel.useMutation({
    onSuccess: () => { refetch(); toast.success("Personnel removed"); },
  });

  const roleLabels = Object.fromEntries((defaults?.personnelRoles || []).map((r: any) => [r.value, r.label]));

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold">Points of Contact</h3>
          <p className="text-xs text-muted-foreground">{personnel.length} personnel assigned</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setShowAdd(true)} className="gap-1">
          <Plus className="w-4 h-4" /> Add Personnel
        </Button>
      </div>

      {personnel.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-8 text-center">
            <Users className="w-10 h-10 text-muted-foreground/40 mb-3" />
            <p className="text-sm text-muted-foreground">No personnel assigned yet. Add points of contact for this engagement.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {personnel.map((p: any) => (
            <Card key={p.id}>
              <CardContent className="py-3 px-4">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-sm">{p.name}</span>
                      <Badge variant="outline" className="text-[10px]">{roleLabels[p.role] || p.role}</Badge>
                      {p.isPrimary && <Badge className="bg-primary/20 text-primary text-[9px]">Primary</Badge>}
                    </div>
                    {p.title && <div className="text-xs text-muted-foreground">{p.title}</div>}
                    {p.organization && <div className="text-xs text-muted-foreground">{p.organization}</div>}
                    <div className="flex gap-3 mt-1">
                      {p.email && <span className="text-xs text-muted-foreground flex items-center gap-1"><Mail className="w-3 h-3" />{p.email}</span>}
                      {p.phone && <span className="text-xs text-muted-foreground flex items-center gap-1"><Phone className="w-3 h-3" />{p.phone}</span>}
                    </div>
                  </div>
                  <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => removeMut.mutate({ id: p.id })}>
                    <Trash2 className="w-3.5 h-3.5 text-red-400" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Add Personnel Dialog */}
      <Dialog open={showAdd} onOpenChange={setShowAdd}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Personnel</DialogTitle>
            <DialogDescription>Add a point of contact for this engagement</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Role</Label>
              <Select value={newPerson.role} onValueChange={(v) => setNewPerson({ ...newPerson, role: v as any })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {(defaults?.personnelRoles || []).map((r: any) => (
                    <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label>Full Name *</Label>
                <Input value={newPerson.name} onChange={(e) => setNewPerson({ ...newPerson, name: e.target.value })} />
              </div>
              <div className="space-y-2">
                <Label>Title</Label>
                <Input value={newPerson.title} onChange={(e) => setNewPerson({ ...newPerson, title: e.target.value })} />
              </div>
            </div>
            <div className="space-y-2">
              <Label>Organization</Label>
              <Input value={newPerson.organization} onChange={(e) => setNewPerson({ ...newPerson, organization: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label>Email</Label>
                <Input type="email" value={newPerson.email} onChange={(e) => setNewPerson({ ...newPerson, email: e.target.value })} />
              </div>
              <div className="space-y-2">
                <Label>Phone</Label>
                <Input value={newPerson.phone} onChange={(e) => setNewPerson({ ...newPerson, phone: e.target.value })} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAdd(false)}>Cancel</Button>
            <Button
              onClick={() => addMut.mutate({ roeId, ...newPerson, role: newPerson.role as any })}
              disabled={!newPerson.name || addMut.isPending}
            >
              {addMut.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Plus className="w-4 h-4 mr-2" />}
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Step 9: Review ─────────────────────────────────────────────────────────────

function ReviewStep({ roe, onBack, refetch }: { roe: any; onBack: () => void; refetch: () => void }) {
  const submitMut = trpc.roeBuilder.submitForReview.useMutation({
    onSuccess: () => { refetch(); toast.success("RoE submitted for review"); },
    onError: (e) => toast.error(sanitizeErrorForToast(e.message)),
  });

  const enabledTests = ((roe.testingTypes as any[]) || []).filter((t: any) => t.enabled);
  const enabledVectors = ((roe.attackVectors as any[]) || []).filter((v: any) => v.enabled);
  const inScopeDomains = (roe.inScopeDomains as any[]) || [];
  const inScopeIpRanges = (roe.inScopeIpRanges as any[]) || [];
  const inScopeApps = (roe.inScopeApplications as any[]) || [];
  const frameworks = (roe.complianceFrameworks as string[]) || [];

  // Completeness checks
  const checks = [
    { label: "Organization name", ok: !!roe.organizationName },
    { label: "Purpose statement", ok: !!roe.purpose },
    { label: "At least one in-scope asset", ok: inScopeDomains.length > 0 || inScopeIpRanges.length > 0 || inScopeApps.length > 0 },
    { label: "At least one testing type selected", ok: enabledTests.length > 0 },
    { label: "Test schedule dates", ok: !!roe.testScheduleStart && !!roe.testScheduleEnd },
    { label: "Emergency halt criteria", ok: !!roe.emergencyHaltCriteria },
    { label: "Data handling procedure", ok: !!roe.dataHandlingProcedure },
    { label: "At least one personnel assigned", ok: (roe.personnel || []).length > 0 },
  ];

  if (roe.fedrampCompliant) {
    const requiredVectors = ((roe.attackVectors as any[]) || []).filter((v: any) => v.fedrampRequired);
    const allRequiredEnabled = requiredVectors.every((v: any) => v.enabled);
    checks.push({ label: "All FedRAMP-required attack vectors enabled", ok: allRequiredEnabled });
  }

  const completionPct = Math.round((checks.filter(c => c.ok).length / checks.length) * 100);

  return (
    <div className="space-y-6">
      {/* Completion Score */}
      <div className="text-center p-6 rounded-lg border border-border">
        <div className={`text-4xl font-bold mb-2 ${completionPct === 100 ? "text-green-400" : completionPct >= 70 ? "text-amber-400" : "text-red-400"}`}>
          {completionPct}%
        </div>
        <div className="text-sm text-muted-foreground">Document Completeness</div>
        <div className="w-full bg-muted rounded-full h-2 mt-3 max-w-xs mx-auto">
          <div
            className={`h-2 rounded-full transition-all ${completionPct === 100 ? "bg-green-500" : completionPct >= 70 ? "bg-amber-500" : "bg-red-500"}`}
            style={{ width: `${completionPct}%` }}
          />
        </div>
      </div>

      {/* Checklist */}
      <div className="space-y-2">
        <h3 className="text-sm font-semibold uppercase text-muted-foreground">Completeness Checklist</h3>
        {checks.map((c, i) => (
          <div key={i} className="flex items-center gap-3 p-2 rounded-lg">
            {c.ok ? (
              <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
            ) : (
              <XCircle className="w-4 h-4 text-red-400 shrink-0" />
            )}
            <span className={`text-sm ${c.ok ? "text-foreground" : "text-muted-foreground"}`}>{c.label}</span>
          </div>
        ))}
      </div>

      <Separator />

      {/* Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="text-center p-3 rounded-lg bg-muted/50 border border-border">
          <div className="text-xl font-bold">{enabledTests.length}</div>
          <div className="text-[10px] text-muted-foreground">Testing Types</div>
        </div>
        <div className="text-center p-3 rounded-lg bg-muted/50 border border-border">
          <div className="text-xl font-bold">{enabledVectors.length}</div>
          <div className="text-[10px] text-muted-foreground">Attack Vectors</div>
        </div>
        <div className="text-center p-3 rounded-lg bg-muted/50 border border-border">
          <div className="text-xl font-bold">{inScopeDomains.length + inScopeIpRanges.length + inScopeApps.length}</div>
          <div className="text-[10px] text-muted-foreground">In-Scope Assets</div>
        </div>
        <div className="text-center p-3 rounded-lg bg-muted/50 border border-border">
          <div className="text-xl font-bold">{(roe.personnel || []).length}</div>
          <div className="text-[10px] text-muted-foreground">Personnel</div>
        </div>
      </div>

      {/* Compliance Frameworks */}
      {frameworks.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium">Compliance Frameworks</h4>
          <div className="flex flex-wrap gap-2">
            {frameworks.map((fw: string) => (
              <Badge key={fw} variant="outline">{fw}</Badge>
            ))}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-3">
        <Button
          variant="outline"
          onClick={async () => {
            try {
              toast.success("Generating PDF...");
              const resp = await fetch(`/api/trpc/roeBuilder.exportPdfHtml?batch=1&input=${encodeURIComponent(JSON.stringify({ "0": { json: { id: roe.id } } }))}`, { credentials: "include" });
              const json = await resp.json();
              const html = json?.[0]?.result?.data?.json?.html;
              if (!html) { toast.error("Could not generate PDF."); return; }
              const pdfWindow = window.open("", "_blank");
              if (pdfWindow) { pdfWindow.document.write(html); pdfWindow.document.close(); setTimeout(() => pdfWindow.print(), 500); }
            } catch { toast.error("PDF export failed."); }
          }}
          className="flex-1"
          size="lg"
        >
          <Download className="w-4 h-4 mr-2" /> Export PDF
        </Button>
        {roe.status === "draft" && (
          <Button
            onClick={() => submitMut.mutate({ id: roe.id })}
            disabled={completionPct < 70 || submitMut.isPending}
            className="flex-1"
            size="lg"
          >
            {submitMut.isPending ? (
              <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Submitting...</>
            ) : (
              <><Send className="w-4 h-4 mr-2" /> Submit for Review</>
            )}
          </Button>
        )}
      </div>

      {completionPct < 70 && roe.status === "draft" && (
        <p className="text-xs text-amber-400 text-center">
          Document must be at least 70% complete before submission
        </p>
      )}
    </div>
  );
}
