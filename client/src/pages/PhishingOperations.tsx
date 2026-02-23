import AppShell from "@/components/AppShell";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { useLocation } from "wouter";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { TemplatePreviewModal } from "@/components/TemplatePreview";
import {
  Fish, Zap, Target, Shield, RefreshCw, Play, Trash2, Edit,
  Eye, Send, Globe, Mail, Users, FileText, Crosshair, Activity,
  AlertTriangle, CheckCircle, Clock, ChevronDown, ChevronUp,
  Loader2, Plus, Copy, ExternalLink, Cpu, BarChart3, Search,
  ArrowRight, Rocket, X, Save, MousePointer, ShieldAlert, Brain,
  Database, Layers, Download, ShieldCheck, ArrowLeft, Printer
} from "lucide-react";
import { GoPhishManagerContent } from "./GoPhish";
import TyposquatManagerComponent from "@/components/TyposquatManager";
import ROEWarningBanner from "@/components/ROEWarningBanner";

import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
// ─── Priority badge colors ───
function priorityBadge(priority: string) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };
  return (
    <Badge variant="outline" className={colors[priority] || colors.medium}>
      {(priority || "medium").toUpperCase()}
    </Badge>
  );
}

// ─── Status badge ───
function statusBadge(status: string) {
  const colors: Record<string, string> = {
    draft: "bg-slate-500/20 text-slate-400 border-slate-500/30",
    approved: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    deployed: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    launched: "bg-primary/20 text-primary border-primary/30",
    completed: "bg-green-500/20 text-green-400 border-green-500/30",
    archived: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  };
  return (
    <Badge variant="outline" className={colors[status] || colors.draft}>
      {(status || "draft").toUpperCase()}
    </Badge>
  );
}

// ═══════════════════════════════════════════════════════════════════
// INTELLIGENCE FEED TAB
// ═══════════════════════════════════════════════════════════════════
function IntelFeedTab() {
  const [statusFilter, setStatusFilter] = useState<"all" | "unmaterialized" | "materialized">("all");
  const { data: feedData, isLoading, refetch } = trpc.phishingOps.getIntelFeed.useQuery({ limit: 50, statusFilter });
  const materialize = trpc.phishingOps.materialize.useMutation({
    onSuccess: (data) => {
      toast.success(`Draft created: ${data.campaignName}`);
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 animate-spin text-primary mr-3" />
        <span className="text-muted-foreground">Loading intelligence feed...</span>
      </div>
    );
  }

  const feed = feedData?.feed || [];

  return (
    <div className="space-y-6">
      {/* Header stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-4">
        <Card className="bg-card border-border">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Brain className="w-5 h-5 text-primary" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{feedData?.totalScans || 0}</p>
              <p className="text-xs text-muted-foreground">Completed Scans</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-orange-500/10">
              <Target className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{feedData?.totalRecommendations || 0}</p>
              <p className="text-xs text-muted-foreground">Campaign Opportunities</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-green-500/10">
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">
                {feed.filter(f => f.materialized).length}
              </p>
              <p className="text-xs text-muted-foreground">Materialized Drafts</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filter bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
        <div className="flex gap-1 bg-muted rounded-lg p-1 flex-wrap">
          {(["all", "unmaterialized", "materialized"] as const).map(f => (
            <button
              key={f}
              onClick={() => setStatusFilter(f)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                statusFilter === f
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {f === "all" ? "All" : f === "unmaterialized" ? "Available" : "Materialized"}
            </button>
          ))}
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
        </Button>
      </div>

      {/* Feed items */}
      {feed.length === 0 ? (
        <Card className="bg-card border-border">
          <CardContent className="p-12 text-center">
            <Brain className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-foreground mb-2">No Campaign Opportunities</h3>
            <p className="text-muted-foreground text-sm max-w-md mx-auto">
              Run a domain intelligence scan to discover phishing campaign opportunities.
              Scan results with campaign recommendations will appear here.
            </p>
            <Button className="mt-4" onClick={() => window.location.href = "/domain-intel"}>
              <Globe className="w-4 h-4 mr-2" /> Start Domain Scan
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {feed.map((item, idx) => (
            <Card key={`${item.scanId}-${item.recommendationIndex}`} className="bg-card border-border hover:border-primary/30 transition-colors">
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      {priorityBadge(item.recommendation?.priority || "medium")}
                      <span className="text-xs text-muted-foreground font-mono">
                        {item.domain}
                      </span>
                      {item.sector && (
                        <Badge variant="outline" className="text-xs bg-card-elevated border-border">
                          {item.sector}
                        </Badge>
                      )}
                      {item.materialized && statusBadge(item.draftStatus || "draft")}
                    </div>
                    <h4 className="text-sm font-semibold text-foreground truncate">
                      {item.recommendation?.name || `Campaign ${item.recommendationIndex + 1}`}
                    </h4>
                    <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                      {item.recommendation?.description || "No description available"}
                    </p>
                    <div className="flex items-center gap-3 mt-2">
                      <span className="text-xs text-muted-dim">
                        Type: {item.recommendation?.type || "phishing"}
                      </span>
                      {item.recommendation?.mitreTactics?.length > 0 && (
                        <span className="text-xs text-muted-dim">
                          MITRE: {item.recommendation.mitreTactics.slice(0, 3).join(", ")}
                        </span>
                      )}
                      <span className="text-xs text-muted-dim">
                        Scan: {new Date(item.scanDate).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                  <div className="flex-shrink-0">
                    {item.materialized ? (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => window.location.href = `/phishing-ops/draft/${item.draftId}`}
                      >
                        <Eye className="w-3.5 h-3.5 mr-1.5" /> View Draft
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        disabled={materialize.isPending}
                        onClick={() => materialize.mutate({
                          scanId: item.scanId,
                          recommendationIndex: item.recommendationIndex,
                        })}
                      >
                        {materialize.isPending ? (
                          <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                        ) : (
                          <Zap className="w-3.5 h-3.5 mr-1.5" />
                        )}
                        Materialize
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// CAMPAIGN BUILDER TAB
// ═══════════════════════════════════════════════════════════════════
function CampaignBuilderTab() {
  const [selectedDraftId, setSelectedDraftId] = useState<number | null>(null);
  const [editMode, setEditMode] = useState(false);
  // Inline edit fields
  const [editSubject, setEditSubject] = useState("");
  const [editHtml, setEditHtml] = useState("");
  const [editCampaignName, setEditCampaignName] = useState("");
  const [editLandingHtml, setEditLandingHtml] = useState("");
  const [editRedirectUrl, setEditRedirectUrl] = useState("");
  const [editCaptureCreds, setEditCaptureCreds] = useState(true);
  const [editCapturePasswords, setEditCapturePasswords] = useState(false);
  const [editTargetEmails, setEditTargetEmails] = useState(""); // CSV format: email,firstName,lastName,position
  const [showHtmlSource, setShowHtmlSource] = useState(false);
  const [showLandingSource, setShowLandingSource] = useState(false);
  const [previewHtml, setPreviewHtml] = useState<{ html: string; title: string; type: "email" | "landing-page" } | null>(null);

  const { data: draftsData, isLoading, refetch } = trpc.phishingOps.listDrafts.useQuery({ status: "all" });
  const { data: selectedDraft, refetch: refetchDraft } = trpc.phishingOps.getDraft.useQuery(
    { id: selectedDraftId! },
    { enabled: !!selectedDraftId }
  );

  // Populate edit fields when entering edit mode
  const enterEditMode = () => {
    if (!selectedDraft) return;
    setEditCampaignName(selectedDraft.campaignName || "");
    setEditSubject(selectedDraft.templateSubject || "");
    setEditHtml(selectedDraft.templateHtml || "");
    setEditLandingHtml(selectedDraft.landingPageHtml || "");
    setEditRedirectUrl(selectedDraft.landingPageRedirectUrl || "");
    setEditCaptureCreds(selectedDraft.captureCredentials ?? true);
    setEditCapturePasswords(selectedDraft.capturePasswords ?? false);
    // Convert target emails array to CSV
    const targets = (selectedDraft.targetEmails as any[]) || [];
    setEditTargetEmails(
      targets.map((t: any) => [t.email, t.firstName || "", t.lastName || "", t.position || ""].join(",")).join("\n")
    );
    setEditMode(true);
  };

  const saveEdits = () => {
    if (!selectedDraft) return;
    // Parse target emails from CSV
    const parsedTargets = editTargetEmails.trim()
      ? editTargetEmails.trim().split("\n").map((line) => {
          const [email, firstName, lastName, position] = line.split(",").map((s) => s.trim());
          return { email: email || "", firstName, lastName, position };
        }).filter((t) => t.email.includes("@"))
      : undefined;

    updateDraft.mutate({
      id: selectedDraft.id,
      campaignName: editCampaignName || undefined,
      templateSubject: editSubject || undefined,
      templateHtml: editHtml || undefined,
      landingPageHtml: editLandingHtml || undefined,
      landingPageRedirectUrl: editRedirectUrl || undefined,
      captureCredentials: editCaptureCreds,
      capturePasswords: editCapturePasswords,
      targetEmails: parsedTargets,
    });
  };

  const updateDraft = trpc.phishingOps.updateDraft.useMutation({
    onSuccess: () => {
      toast.success("Draft updated");
      refetchDraft();
      setEditMode(false);
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const deployDraft = trpc.phishingOps.deployToGophish.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success("Deployed to phishing platform!");
      } else {
        toast.error(`Deployment had errors: ${data.errors.join(", ")}`);
      }
      refetchDraft();
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const deleteDraft = trpc.phishingOps.deleteDraft.useMutation({
    onSuccess: () => {
      toast.success("Draft deleted");
      setSelectedDraftId(null);
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const drafts = draftsData?.drafts || [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 animate-spin text-primary mr-3" />
        <span className="text-muted-foreground">Loading drafts...</span>
      </div>
    );
  }

  // Draft detail view
  if (selectedDraftId && selectedDraft) {
    return (
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="flex items-center gap-2 sm:gap-3 flex-wrap">
            <Button variant="outline" size="sm" onClick={() => { setSelectedDraftId(null); setEditMode(false); }}>
              <ChevronDown className="w-3.5 h-3.5 mr-1 rotate-90" /> Back
            </Button>
            <h3 className="text-base sm:text-lg font-semibold text-foreground">{selectedDraft.campaignName}</h3>
            {statusBadge(selectedDraft.status)}
            {priorityBadge(selectedDraft.priority || "medium")}
          </div>
          <div className="flex gap-2 flex-wrap">
            {(selectedDraft.status === "draft" || selectedDraft.status === "approved") && (
              <>
                {editMode ? (
                  <>
                    <Button variant="outline" size="sm" onClick={() => setEditMode(false)}>
                      <X className="w-3.5 h-3.5 mr-1.5" /> Cancel
                    </Button>
                    <Button size="sm" disabled={updateDraft.isPending} onClick={saveEdits}>
                      {updateDraft.isPending ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Save className="w-3.5 h-3.5 mr-1.5" />}
                      Save Changes
                    </Button>
                  </>
                ) : (
                  <Button variant="outline" size="sm" onClick={enterEditMode}>
                    <Edit className="w-3.5 h-3.5 mr-1.5" /> Edit
                  </Button>
                )}
                {!editMode && (
                  <Button
                    size="sm"
                    disabled={deployDraft.isPending}
                    onClick={() => deployDraft.mutate({ draftId: selectedDraft.id })}
                  >
                    {deployDraft.isPending ? (
                      <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                    ) : (
                      <Send className="w-3.5 h-3.5 mr-1.5" />
                    )}
                    Deploy to the phishing platform
                  </Button>
                )}
              </>
            )}
            {selectedDraft.status !== "launched" && (
              <Button
                variant="outline"
                size="sm"
                className="text-red-400 hover:text-red-300"
                onClick={() => {
                  if (confirm("Delete this draft?")) {
                    deleteDraft.mutate({ id: selectedDraft.id });
                  }
                }}
              >
                <Trash2 className="w-3.5 h-3.5 mr-1.5" /> Delete
              </Button>
            )}
          </div>
        </div>

        {/* Draft details grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left: Campaign Info */}
          <div className="space-y-4">
            <Card className="bg-card border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Target className="w-4 h-4 text-primary" /> Campaign Info
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Target Domain</span>
                  <span className="font-mono text-foreground">{selectedDraft.targetDomain || "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Sector</span>
                  <span className="text-foreground">{selectedDraft.targetSector || "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Campaign Type</span>
                  <span className="text-foreground">{selectedDraft.campaignType || "phishing"}</span>
                </div>
                {selectedDraft.threatActorName && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Matched Actor</span>
                    <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30">
                      {selectedDraft.threatActorName}
                    </Badge>
                  </div>
                )}
                {selectedDraft.gophishTemplateId && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Phishing Template ID</span>
                    <span className="font-mono text-primary">{selectedDraft.gophishTemplateId}</span>
                  </div>
                )}
                {selectedDraft.gophishCampaignId && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Phishing Campaign ID</span>
                    <span className="font-mono text-primary">{selectedDraft.gophishCampaignId}</span>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Attack Chain */}
            {Array.isArray(selectedDraft.attackChain) && selectedDraft.attackChain.length > 0 && (
              <Card className="bg-card border-border">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Crosshair className="w-4 h-4 text-orange-400" /> Attack Chain
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {(selectedDraft.attackChain as any[]).map((step: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        <div className="w-6 h-6 rounded-full bg-primary/10 text-primary flex items-center justify-center font-mono text-xs">
                          {i + 1}
                        </div>
                        <span className="text-foreground">{String(step.name || step.description || step)}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Right: Email Template + Landing Page + Targets */}
          <div className="space-y-4">
            {/* Email Template */}
            <Card className="bg-card border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Mail className="w-4 h-4 text-primary" /> Email Template
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {editMode ? (
                  <>
                    <div>
                      <Label className="text-xs text-muted-foreground">Subject Line</Label>
                      <Input
                        value={editSubject}
                        onChange={(e) => setEditSubject(e.target.value)}
                        placeholder="Email subject line..."
                        className="mt-1 bg-background border-border"
                      />
                    </div>
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <Label className="text-xs text-muted-foreground">HTML Body</Label>
                        <Button variant="ghost" size="sm" className="h-6 text-xs" onClick={() => setShowHtmlSource(!showHtmlSource)}>
                          {showHtmlSource ? <Eye className="w-3 h-3 mr-1" /> : <FileText className="w-3 h-3 mr-1" />}
                          {showHtmlSource ? "Preview" : "Source"}
                        </Button>
                      </div>
                      {showHtmlSource ? (
                        <Textarea
                          value={editHtml}
                          onChange={(e) => setEditHtml(e.target.value)}
                          rows={12}
                          className="mt-1 bg-background border-border font-mono text-xs"
                          placeholder="<html><body>...</body></html>"
                        />
                      ) : (
                        <div className="mt-1 bg-white rounded-md overflow-hidden border border-border" style={{ height: "200px" }}>
                          <iframe
                            srcDoc={editHtml || "<p style='padding:16px;color:#666'>No template</p>"}
                            className="w-full h-full border-0"
                            sandbox="allow-same-origin"
                            title="Email preview"
                          />
                        </div>
                      )}
                      <p className="text-[10px] text-muted-foreground mt-1">
                        Template variables: {"{{.FirstName}}"}, {"{{.LastName}}"}, {"{{.Email}}"}, {"{{.URL}}"}, {"{{.TrackingURL}}"}, {"{{.From}}"}
                      </p>
                    </div>
                  </>
                ) : (
                  <>
                    <div>
                      <Label className="text-xs text-muted-foreground">Subject</Label>
                      <p className="text-sm font-medium text-foreground mt-1">
                        {selectedDraft.templateSubject || "—"}
                      </p>
                    </div>
                    <div>
                      <div className="flex items-center justify-between">
                        <Label className="text-xs text-muted-foreground">Email Preview</Label>
                        <Button variant="ghost" size="sm" className="h-6 text-xs" onClick={() => setPreviewHtml({ html: selectedDraft.templateHtml || "", title: selectedDraft.campaignName || "Email Template", type: "email" })}>
                          <ExternalLink className="w-3 h-3 mr-1" /> Full Preview
                        </Button>
                      </div>
                      <div className="mt-1 bg-white rounded-md overflow-hidden border border-border" style={{ height: "200px" }}>
                        <iframe
                          srcDoc={selectedDraft.templateHtml || "<p style='padding:16px;color:#666'>No template</p>"}
                          className="w-full h-full border-0"
                          sandbox="allow-same-origin"
                          title="Email preview"
                        />
                      </div>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            {/* Landing Page */}
            <Card className="bg-card border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Globe className="w-4 h-4 text-primary" /> Landing Page
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {editMode ? (
                  <>
                    <div>
                      <Label className="text-xs text-muted-foreground">Redirect URL</Label>
                      <Input
                        value={editRedirectUrl}
                        onChange={(e) => setEditRedirectUrl(e.target.value)}
                        placeholder="https://target-domain.com"
                        className="mt-1 bg-background border-border font-mono text-xs"
                      />
                    </div>
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <Label className="text-xs text-muted-foreground">Landing Page HTML</Label>
                        <Button variant="ghost" size="sm" className="h-6 text-xs" onClick={() => setShowLandingSource(!showLandingSource)}>
                          {showLandingSource ? <Eye className="w-3 h-3 mr-1" /> : <FileText className="w-3 h-3 mr-1" />}
                          {showLandingSource ? "Preview" : "Source"}
                        </Button>
                      </div>
                      {showLandingSource ? (
                        <Textarea
                          value={editLandingHtml}
                          onChange={(e) => setEditLandingHtml(e.target.value)}
                          rows={8}
                          className="mt-1 bg-background border-border font-mono text-xs"
                          placeholder="<html><body>...</body></html>"
                        />
                      ) : (
                        <div className="mt-1 bg-white rounded-md overflow-hidden border border-border" style={{ height: "160px" }}>
                          <iframe
                            srcDoc={editLandingHtml || "<p style='padding:16px;color:#666'>No landing page</p>"}
                            className="w-full h-full border-0"
                            sandbox="allow-same-origin"
                            title="Landing page preview"
                          />
                        </div>
                      )}
                    </div>
                    <div className="flex gap-6">
                      <div className="flex items-center gap-2">
                        <Switch checked={editCaptureCreds} onCheckedChange={setEditCaptureCreds} />
                        <Label className="text-xs text-muted-foreground">Capture Credentials</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <Switch checked={editCapturePasswords} onCheckedChange={setEditCapturePasswords} />
                        <Label className="text-xs text-muted-foreground">Capture Passwords</Label>
                      </div>
                    </div>
                  </>
                ) : (
                  <>
                    <div>
                      <Label className="text-xs text-muted-foreground">Redirect URL</Label>
                      <p className="text-sm font-mono text-foreground mt-1">
                        {selectedDraft.landingPageRedirectUrl || "—"}
                      </p>
                    </div>
                    {selectedDraft.landingPageHtml && (
                      <div>
                        <div className="flex items-center justify-between">
                          <Label className="text-xs text-muted-foreground">Landing Page Preview</Label>
                          <Button variant="ghost" size="sm" className="h-6 text-xs" onClick={() => setPreviewHtml({ html: selectedDraft.landingPageHtml || "", title: selectedDraft.campaignName + " - Landing Page" || "Landing Page", type: "landing-page" })}>
                            <ExternalLink className="w-3 h-3 mr-1" /> Full Preview
                          </Button>
                        </div>
                        <div className="mt-1 bg-white rounded-md overflow-hidden border border-border" style={{ height: "160px" }}>
                          <iframe
                            srcDoc={selectedDraft.landingPageHtml}
                            className="w-full h-full border-0"
                            sandbox="allow-same-origin"
                            title="Landing page preview"
                          />
                        </div>
                      </div>
                    )}
                    <div className="flex gap-3 text-xs">
                      <span className="text-muted-foreground">
                        Capture Credentials: {selectedDraft.captureCredentials ? "Yes" : "No"}
                      </span>
                      <span className="text-muted-foreground">
                        Capture Passwords: {selectedDraft.capturePasswords ? "Yes" : "No"}
                      </span>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            {/* Target Emails */}
            <Card className="bg-card border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Users className="w-4 h-4 text-primary" /> Target List
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {editMode ? (
                  <>
                    <Textarea
                      value={editTargetEmails}
                      onChange={(e) => setEditTargetEmails(e.target.value)}
                      rows={6}
                      className="bg-background border-border font-mono text-xs"
                      placeholder={"email,firstName,lastName,position\njohn@example.com,John,Doe,CEO\njane@example.com,Jane,Smith,CFO"}
                    />
                    <p className="text-[10px] text-muted-foreground">
                      CSV format: email,firstName,lastName,position (one per line)
                    </p>
                  </>
                ) : (
                  <>
                    {Array.isArray(selectedDraft.targetEmails) && (selectedDraft.targetEmails as any[]).length > 0 ? (
                      <div className="space-y-1">
                        {(selectedDraft.targetEmails as any[]).slice(0, 10).map((t: any, i: number) => (
                          <div key={i} className="flex items-center gap-2 text-xs">
                            <Mail className="w-3 h-3 text-muted-foreground" />
                            <span className="font-mono text-foreground">{t.email}</span>
                            {t.firstName && <span className="text-muted-foreground">({t.firstName} {t.lastName || ""})</span>}
                            {t.position && <Badge variant="outline" className="text-[10px] py-0">{t.position}</Badge>}
                          </div>
                        ))}
                        {(selectedDraft.targetEmails as any[]).length > 10 && (
                          <p className="text-xs text-muted-foreground">...and {(selectedDraft.targetEmails as any[]).length - 10} more</p>
                        )}
                      </div>
                    ) : (
                      <p className="text-xs text-muted-foreground italic">No targets defined yet. Click Edit to add target emails.</p>
                    )}
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Full-screen template/landing page preview modal */}
        {previewHtml && (
          <TemplatePreviewModal
            html={previewHtml.html}
            title={previewHtml.title}
            type={previewHtml.type}
            onClose={() => setPreviewHtml(null)}
          />
        )}
      </div>
    );
  }

  // Draft list view
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {drafts.length} draft{drafts.length !== 1 ? "s" : ""} — Review, edit, and deploy phishing campaigns
        </p>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
        </Button>
      </div>

      {drafts.length === 0 ? (
        <Card className="bg-card border-border">
          <CardContent className="p-12 text-center">
            <FileText className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-foreground mb-2">No Campaign Drafts</h3>
            <p className="text-muted-foreground text-sm max-w-md mx-auto">
              Materialize campaign recommendations from the Intelligence Feed to create drafts here.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {drafts.map((draft) => (
            <Card
              key={draft.id}
              className="bg-card border-border hover:border-primary/30 transition-colors cursor-pointer"
              onClick={() => setSelectedDraftId(draft.id)}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      {statusBadge(draft.status)}
                      {priorityBadge(draft.priority || "medium")}
                      {draft.threatActorName && (
                        <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/30">
                          {draft.threatActorName}
                        </Badge>
                      )}
                    </div>
                    <h4 className="text-sm font-semibold text-foreground truncate">
                      {draft.campaignName}
                    </h4>
                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                      <span className="font-mono">{draft.targetDomain || "—"}</span>
                      <span>{draft.campaignType || "phishing"}</span>
                      <span>{new Date(draft.createdAt).toLocaleDateString()}</span>
                    </div>
                  </div>
                  <ArrowRight className="w-4 h-4 text-muted-foreground" />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// ACTIVE CAMPAIGNS TAB
// ═══════════════════════════════════════════════════════════════════
function ActiveCampaignsTab() {
  const [reportData, setReportData] = useState<any>(null);
  const [reportDraftId, setReportDraftId] = useState<number | null>(null);
  const { data: draftsData, isLoading, refetch } = trpc.phishingOps.listDrafts.useQuery({ status: "all" });
  const syncStats = trpc.phishingOps.syncCampaignStats.useMutation({
    onSuccess: (data) => {
      toast.success(`Synced ${data.synced} campaign(s)`);
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const triggerCaldera = trpc.phishingOps.triggerCaldera.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const generateReport = trpc.phishingOps.generateReport.useMutation({
    onSuccess: (data) => {
      setReportData(data);
      toast.success("Report generated!");
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  // Filter to only launched/completed campaigns
  const activeCampaigns = useMemo(() => {
    return (draftsData?.drafts || []).filter(
      d => d.status === "launched" || d.status === "completed" || d.status === "deployed"
    );
  }, [draftsData]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 animate-spin text-primary mr-3" />
        <span className="text-muted-foreground">Loading active campaigns...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {activeCampaigns.length} active campaign{activeCampaigns.length !== 1 ? "s" : ""}
        </p>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={syncStats.isPending}
            onClick={() => syncStats.mutate(undefined)}
          >
            {syncStats.isPending ? (
              <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
            ) : (
              <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
            )}
            Sync Stats
          </Button>
        </div>
      </div>

      {activeCampaigns.length === 0 ? (
        <Card className="bg-card border-border">
          <CardContent className="p-12 text-center">
            <Activity className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-foreground mb-2">No Active Campaigns</h3>
            <p className="text-muted-foreground text-sm max-w-md mx-auto">
              Deploy and launch campaigns from the Campaign Builder to see them here.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {activeCampaigns.map((campaign) => {
            const stats = campaign.campaignStats as any;
            return (
              <Card key={campaign.id} className="bg-card border-border">
                <CardContent className="p-5">
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        {statusBadge(campaign.status)}
                        {campaign.gophishCampaignId && (
                          <Badge variant="outline" className="text-xs bg-card-elevated border-border font-mono">
                            GP#{campaign.gophishCampaignId}
                          </Badge>
                        )}
                      </div>
                      <h4 className="text-base font-semibold text-foreground">{campaign.campaignName}</h4>
                      <p className="text-xs text-muted-foreground mt-1">
                        {campaign.targetDomain} · {campaign.campaignType} · Launched {campaign.launchDate ? new Date(campaign.launchDate).toLocaleDateString() : "—"}
                      </p>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-primary border-primary/30"
                        disabled={generateReport.isPending && reportDraftId === campaign.id}
                        onClick={() => {
                          setReportDraftId(campaign.id);
                          generateReport.mutate({ draftId: campaign.id });
                        }}
                      >
                        {generateReport.isPending && reportDraftId === campaign.id ? (
                          <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                        ) : (
                          <FileText className="w-3.5 h-3.5 mr-1.5" />
                        )}
                        Generate Report
                      </Button>
                      {stats && (stats.submitted || 0) > 0 && !campaign.calderaOperationId && (
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-orange-400 border-orange-500/30"
                          disabled={triggerCaldera.isPending}
                          onClick={() => triggerCaldera.mutate({ draftId: campaign.id })}
                        >
                          {triggerCaldera.isPending ? (
                            <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                          ) : (
                            <Cpu className="w-3.5 h-3.5 mr-1.5" />
                          )}
                          Trigger Emulation
                        </Button>
                      )}
                      {campaign.calderaOperationId && (
                        <Badge variant="outline" className="bg-orange-500/10 text-orange-400 border-orange-500/30">
                          <Cpu className="w-3 h-3 mr-1" /> Operation: {campaign.calderaOperationId}
                        </Badge>
                      )}
                    </div>
                  </div>

                  {/* Campaign stats */}
                  {stats ? (
                    <div className="grid grid-cols-5 gap-3">
                      {[
                        { label: "Sent", value: stats.sent || 0, icon: Send, color: "text-blue-400" },
                        { label: "Opened", value: stats.opened || 0, icon: Eye, color: "text-yellow-400" },
                        { label: "Clicked", value: stats.clicked || 0, icon: MousePointer, color: "text-orange-400" },
                        { label: "Submitted", value: stats.submitted || 0, icon: ShieldAlert, color: "text-red-400" },
                        { label: "Reported", value: stats.reported || 0, icon: AlertTriangle, color: "text-green-400" },
                      ].map(({ label, value, icon: Icon, color }) => (
                        <div key={label} className="bg-card-elevated rounded-lg p-3 text-center">
                          <Icon className={`w-4 h-4 ${color} mx-auto mb-1`} />
                          <p className="text-lg font-bold text-foreground">{value}</p>
                          <p className="text-xs text-muted-foreground">{label}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="bg-card-elevated rounded-lg p-4 text-center text-sm text-muted-foreground">
                      <Clock className="w-4 h-4 mx-auto mb-2" />
                      No stats yet — click "Sync Stats" to pull data from the phishing platform
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* ── Report View Panel ── */}
      {reportData && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-start justify-center overflow-y-auto py-8">
          <div className="bg-card border border-border rounded-xl max-w-4xl w-full mx-4 shadow-2xl">
            {/* Report Header */}
            <div className="border-b border-border p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                    <FileText className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-foreground">Post-Campaign Assessment Report</h2>
                    <p className="text-xs text-muted-foreground font-mono">{reportData.reportId}</p>
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => {
                    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url; a.download = `${reportData.reportId}.json`; a.click();
                    URL.revokeObjectURL(url);
                  }}>
                    <Download className="w-3.5 h-3.5 mr-1.5" /> Export JSON
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setReportData(null)}>
                    <X className="w-4 h-4" />
                  </Button>
                </div>
              </div>
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span>{reportData.branding.company} — {reportData.branding.platform}</span>
                <span>·</span>
                <span>Prepared by {reportData.branding.author}</span>
                <span>·</span>
                <span>{new Date(reportData.generatedAt).toLocaleDateString()}</span>
              </div>
            </div>

            {/* Campaign Overview */}
            <div className="p-6 border-b border-border">
              <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">Campaign Overview</h3>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div><span className="text-muted-foreground">Campaign:</span> <span className="text-foreground font-medium">{reportData.campaign.name}</span></div>
                <div><span className="text-muted-foreground">Type:</span> <span className="text-foreground">{reportData.campaign.type}</span></div>
                <div><span className="text-muted-foreground">Target Domain:</span> <span className="text-foreground font-mono">{reportData.campaign.targetDomain}</span></div>
                <div><span className="text-muted-foreground">Sector:</span> <span className="text-foreground">{reportData.campaign.targetSector || "—"}</span></div>
                {reportData.campaign.threatActorSimulated && (
                  <div className="col-span-2"><span className="text-muted-foreground">Threat Actor Simulated:</span> <span className="text-red-400 font-medium">{reportData.campaign.threatActorSimulated}</span></div>
                )}
              </div>
            </div>

            {/* Statistics */}
            <div className="p-6 border-b border-border">
              <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">Campaign Results</h3>
              <div className="grid grid-cols-3 gap-3 mb-4">
                {[
                  { label: "Total Targets", value: reportData.statistics.total, color: "text-foreground" },
                  { label: "Emails Sent", value: reportData.statistics.sent, color: "text-blue-400" },
                  { label: "Opened", value: `${reportData.statistics.opened} (${reportData.statistics.openRate}%)`, color: "text-yellow-400" },
                  { label: "Clicked", value: `${reportData.statistics.clicked} (${reportData.statistics.clickRate}%)`, color: "text-orange-400" },
                  { label: "Credentials Submitted", value: `${reportData.statistics.submitted} (${reportData.statistics.submitRate}%)`, color: "text-red-400" },
                  { label: "Reported as Phishing", value: `${reportData.statistics.reported} (${reportData.statistics.reportRate}%)`, color: "text-green-400" },
                ].map(({ label, value, color }) => (
                  <div key={label} className="bg-card-elevated rounded-lg p-3">
                    <p className={`text-lg font-bold ${color}`}>{value}</p>
                    <p className="text-xs text-muted-foreground">{label}</p>
                  </div>
                ))}
              </div>
              <div className="flex items-center gap-4 bg-card-elevated rounded-lg p-4">
                <div className="text-center">
                  <p className={`text-3xl font-bold ${
                    reportData.statistics.riskScore >= 70 ? "text-red-400" :
                    reportData.statistics.riskScore >= 50 ? "text-orange-400" :
                    reportData.statistics.riskScore >= 30 ? "text-yellow-400" : "text-green-400"
                  }`}>{reportData.statistics.riskScore}</p>
                  <p className="text-xs text-muted-foreground">Risk Score</p>
                </div>
                <div className="flex-1">
                  <div className="h-3 bg-background rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        reportData.statistics.riskScore >= 70 ? "bg-red-500" :
                        reportData.statistics.riskScore >= 50 ? "bg-orange-500" :
                        reportData.statistics.riskScore >= 30 ? "bg-yellow-500" : "bg-green-500"
                      }`}
                      style={{ width: `${reportData.statistics.riskScore}%` }}
                    />
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">Risk Level: <span className="font-semibold text-foreground">{reportData.statistics.riskLevel}</span></p>
                </div>
              </div>
            </div>

            {/* Compliance Framework Analysis */}
            {reportData.compliance?.hasFrameworks && reportData.compliance.analysis.length > 0 && (
              <div className="p-6 border-b border-border">
                <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4" /> Compliance Framework Analysis
                </h3>
                <div className="flex flex-wrap gap-2 mb-4">
                  {reportData.compliance.frameworks.map((f: string) => (
                    <Badge key={f} variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/30">{f}</Badge>
                  ))}
                </div>
                <div className="space-y-4">
                  {reportData.compliance.analysis.map((item: any, idx: number) => {
                    const statusColors: Record<string, string> = {
                      compliant: "text-green-400 bg-green-500/10 border-green-500/30",
                      partial: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
                      at_risk: "text-orange-400 bg-orange-500/10 border-orange-500/30",
                      non_compliant: "text-red-400 bg-red-500/10 border-red-500/30",
                    };
                    return (
                      <Card key={idx} className="bg-card-elevated border-border">
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <ShieldCheck className="w-4 h-4 text-blue-400" />
                              <span className="font-semibold text-foreground">{item.fullName}</span>
                            </div>
                            <Badge variant="outline" className={statusColors[item.status] || statusColors.partial}>
                              {item.status.replace("_", " ").toUpperCase()}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground mb-3">{item.findings}</p>
                          <div className="mb-3">
                            <p className="text-xs font-semibold text-muted-foreground mb-1">Impacted Controls:</p>
                            <div className="flex flex-wrap gap-1">
                              {(item.impactedControls || []).map((ctrl: string, i: number) => (
                                <Badge key={i} variant="outline" className="text-xs font-mono bg-card border-border">{ctrl}</Badge>
                              ))}
                            </div>
                          </div>
                          <div>
                            <p className="text-xs font-semibold text-muted-foreground mb-1">Remediation Steps:</p>
                            <ul className="text-sm text-muted-foreground space-y-1">
                              {(item.remediationSteps || []).map((step: string, i: number) => (
                                <li key={i} className="flex items-start gap-2">
                                  <ArrowRight className="w-3 h-3 mt-1 text-primary shrink-0" />
                                  <span>{step}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Executive Summary */}
            {reportData.executiveSummary && (
              <div className="p-6 border-b border-border">
                <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">Executive Summary</h3>
                <div className="text-sm text-foreground/90 leading-relaxed whitespace-pre-wrap">{reportData.executiveSummary}</div>
              </div>
            )}

            {/* Recommendations */}
            {reportData.recommendations?.length > 0 && (
              <div className="p-6 border-b border-border">
                <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">Recommendations</h3>
                <div className="space-y-2">
                  {reportData.recommendations.map((rec: string, i: number) => (
                    <div key={i} className="flex items-start gap-3 text-sm">
                      <span className="w-6 h-6 rounded-full bg-primary/10 text-primary flex items-center justify-center text-xs font-bold shrink-0">{i + 1}</span>
                      <span className="text-foreground/90">{rec}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Emulation Post-Exploitation */}
            {reportData.caldera && (
              <div className="p-6 border-b border-border">
                <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">Post-Exploitation</h3>
                <div className="grid grid-cols-3 gap-3 mb-3">
                  <div className="bg-card-elevated rounded-lg p-3">
                    <p className="text-lg font-bold text-orange-400">{reportData.caldera.stepsExecuted}</p>
                    <p className="text-xs text-muted-foreground">Steps Executed</p>
                  </div>
                  <div className="bg-card-elevated rounded-lg p-3">
                    <p className="text-sm font-medium text-foreground">{reportData.caldera.operationName}</p>
                    <p className="text-xs text-muted-foreground">Operation</p>
                  </div>
                  <div className="bg-card-elevated rounded-lg p-3">
                    <p className="text-sm font-medium text-foreground">{reportData.caldera.state}</p>
                    <p className="text-xs text-muted-foreground">State</p>
                  </div>
                </div>
                {reportData.caldera.abilities?.length > 0 && (
                  <div className="space-y-1">
                    {reportData.caldera.abilities.map((ab: any, i: number) => (
                      <div key={i} className="flex items-center gap-3 text-sm bg-card-elevated rounded px-3 py-2">
                        <Badge variant="outline" className="text-xs font-mono">{ab.tactic}</Badge>
                        <span className="text-foreground">{ab.name}</span>
                        <Badge variant="outline" className={`ml-auto text-xs ${ab.status === 'success' ? 'text-green-400 border-green-500/30' : 'text-yellow-400 border-yellow-500/30'}`}>{ab.status}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Timeline */}
            {reportData.timeline?.length > 0 && (
              <div className="p-6 border-b border-border">
                <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">Event Timeline ({reportData.timeline.length} events)</h3>
                <div className="max-h-60 overflow-y-auto space-y-1">
                  {reportData.timeline.map((evt: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 text-xs bg-card-elevated rounded px-3 py-2">
                      <span className="text-muted-foreground font-mono w-40 shrink-0">{new Date(evt.time).toLocaleString()}</span>
                      <span className="text-foreground">{evt.message}</span>
                      {evt.email && <span className="text-muted-foreground ml-auto">{evt.email}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Footer */}
            <div className="p-6 text-center text-xs text-muted-foreground">
              <p>This report was generated by the Ace C3 platform. © {new Date().getFullYear()} AceofCloud. All rights reserved.</p>
              <p className="mt-1">{reportData.branding.website}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// ARSENAL TAB
// ═══════════════════════════════════════════════════════════════════
function ArsenalTab() {
  const [showCleanup, setShowCleanup] = useState(false);
  const [selectedStaleTemplates, setSelectedStaleTemplates] = useState<number[]>([]);
  const [selectedStalePages, setSelectedStalePages] = useState<number[]>([]);
  const [selectedStaleGroups, setSelectedStaleGroups] = useState<number[]>([]);

  const { data: arsenal, isLoading, refetch } = trpc.phishingOps.getArsenal.useQuery();
  const { data: staleData, refetch: refetchStale, isLoading: staleLoading } = trpc.phishingOps.identifyStaleResources.useQuery(undefined, { enabled: showCleanup });
  const bulkCleanup = trpc.phishingOps.bulkCleanup.useMutation({
    onSuccess: (data) => {
      const total = data.deletedTemplates + data.deletedPages + data.deletedGroups;
      toast.success(`Cleaned up ${total} stale resource${total !== 1 ? 's' : ''}`);
      if (data.errors.length > 0) toast.error(`${data.errors.length} error(s): ${data.errors[0]}`);
      setSelectedStaleTemplates([]); setSelectedStalePages([]); setSelectedStaleGroups([]);
      refetch(); refetchStale();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });
  const deleteTemplate = trpc.phishingOps.deleteGophishTemplate.useMutation({
    onSuccess: () => { toast.success("Template deleted"); refetch(); },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });
  const deletePage = trpc.phishingOps.deleteGophishPage.useMutation({
    onSuccess: () => { toast.success("Landing page deleted"); refetch(); },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });
  const deleteGroup = trpc.phishingOps.deleteGophishGroup.useMutation({
    onSuccess: () => { toast.success("Group deleted"); refetch(); },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 animate-spin text-primary mr-3" />
        <span className="text-muted-foreground">Loading phishing arsenal...</span>
      </div>
    );
  }

  if (!arsenal?.online) {
    return (
      <Card className="bg-card border-border">
        <CardContent className="p-12 text-center">
          <AlertTriangle className="w-12 h-12 text-yellow-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-foreground mb-2">Phishing Platform Offline</h3>
          <p className="text-muted-foreground text-sm">
            Cannot connect to phishing server. Check the server configuration.
          </p>
        </CardContent>
      </Card>
    );
  }

  const sections = [
    {
      title: "Email Templates",
      icon: Mail,
      items: arsenal.templates,
      onDelete: (id: number) => deleteTemplate.mutate({ id }),
      fields: ["name", "subject"],
    },
    {
      title: "Landing Pages",
      icon: Globe,
      items: arsenal.landingPages,
      onDelete: (id: number) => deletePage.mutate({ id }),
      fields: ["name"],
    },
    {
      title: "Target Groups",
      icon: Users,
      items: arsenal.groups,
      onDelete: (id: number) => deleteGroup.mutate({ id }),
      fields: ["name"],
    },
    {
      title: "Sending Profiles",
      icon: Send,
      items: arsenal.sendingProfiles,
      onDelete: null,
      fields: ["name", "host"],
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-sm text-green-400">Phishing Platform Online</span>
        </div>
        <div className="flex gap-2">
          <Button
            variant={showCleanup ? "default" : "outline"}
            size="sm"
            onClick={() => setShowCleanup(!showCleanup)}
          >
            <Search className="w-3.5 h-3.5 mr-1.5" /> {showCleanup ? "Hide Cleanup" : "Find Stale Resources"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
          </Button>
        </div>
      </div>

      {/* Stale Resource Cleanup Panel */}
      {showCleanup && (
        <Card className="bg-card border-yellow-500/30">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400" /> Stale Resource Cleanup
            </CardTitle>
            <CardDescription className="text-xs">
              Resources identified as empty, test, or placeholder items that can be safely removed.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {staleLoading ? (
              <div className="flex items-center gap-2 py-4">
                <Loader2 className="w-4 h-4 animate-spin text-primary" />
                <span className="text-sm text-muted-foreground">Scanning for stale resources...</span>
              </div>
            ) : staleData && staleData.summary.totalStale > 0 ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <p className="text-sm text-muted-foreground">
                    Found <span className="text-yellow-400 font-semibold">{staleData.summary.totalStale}</span> stale resource{staleData.summary.totalStale !== 1 ? 's' : ''}
                  </p>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-xs"
                      onClick={() => {
                        setSelectedStaleTemplates(staleData.staleTemplates.map((t: any) => t.id));
                        setSelectedStalePages(staleData.stalePages.map((p: any) => p.id));
                        setSelectedStaleGroups(staleData.staleGroups.map((g: any) => g.id));
                      }}
                    >
                      Select All
                    </Button>
                    <Button
                      size="sm"
                      className="text-xs bg-red-600 hover:bg-red-700"
                      disabled={bulkCleanup.isPending || (selectedStaleTemplates.length + selectedStalePages.length + selectedStaleGroups.length) === 0}
                      onClick={() => {
                        const total = selectedStaleTemplates.length + selectedStalePages.length + selectedStaleGroups.length;
                        if (confirm(`Delete ${total} stale resource${total !== 1 ? 's' : ''}? This cannot be undone.`)) {
                          bulkCleanup.mutate({
                            templateIds: selectedStaleTemplates,
                            pageIds: selectedStalePages,
                            groupIds: selectedStaleGroups,
                          });
                        }
                      }}
                    >
                      {bulkCleanup.isPending ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Trash2 className="w-3 h-3 mr-1" />}
                      Delete Selected ({selectedStaleTemplates.length + selectedStalePages.length + selectedStaleGroups.length})
                    </Button>
                  </div>
                </div>

                {/* Stale Templates */}
                {staleData.staleTemplates.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-2">Templates ({staleData.staleTemplates.length})</p>
                    <div className="space-y-1">
                      {staleData.staleTemplates.map((t: any) => (
                        <label key={t.id} className="flex items-center gap-2 p-2 rounded-md hover:bg-muted/50 cursor-pointer text-xs">
                          <input
                            type="checkbox"
                            checked={selectedStaleTemplates.includes(t.id)}
                            onChange={(e) => setSelectedStaleTemplates(prev => e.target.checked ? [...prev, t.id] : prev.filter(id => id !== t.id))}
                            className="rounded"
                          />
                          <Mail className="w-3 h-3 text-muted-foreground" />
                          <span className="text-foreground">{t.name}</span>
                          <Badge variant="outline" className="text-[10px] py-0 bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
                            {t.reason === 'empty_body' ? 'Empty' : t.reason === 'test_name' ? 'Test' : 'No Subject'}
                          </Badge>
                          <span className="text-muted-foreground ml-auto">{t.htmlLength} chars</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                {/* Stale Pages */}
                {staleData.stalePages.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-2">Landing Pages ({staleData.stalePages.length})</p>
                    <div className="space-y-1">
                      {staleData.stalePages.map((p: any) => (
                        <label key={p.id} className="flex items-center gap-2 p-2 rounded-md hover:bg-muted/50 cursor-pointer text-xs">
                          <input
                            type="checkbox"
                            checked={selectedStalePages.includes(p.id)}
                            onChange={(e) => setSelectedStalePages(prev => e.target.checked ? [...prev, p.id] : prev.filter(id => id !== p.id))}
                            className="rounded"
                          />
                          <Globe className="w-3 h-3 text-muted-foreground" />
                          <span className="text-foreground">{p.name}</span>
                          <Badge variant="outline" className="text-[10px] py-0 bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
                            {p.reason === 'empty_body' ? 'Empty' : 'Test'}
                          </Badge>
                          <span className="text-muted-foreground ml-auto">{p.htmlLength} chars</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                {/* Stale Groups */}
                {staleData.staleGroups.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-2">Target Groups ({staleData.staleGroups.length})</p>
                    <div className="space-y-1">
                      {staleData.staleGroups.map((g: any) => (
                        <label key={g.id} className="flex items-center gap-2 p-2 rounded-md hover:bg-muted/50 cursor-pointer text-xs">
                          <input
                            type="checkbox"
                            checked={selectedStaleGroups.includes(g.id)}
                            onChange={(e) => setSelectedStaleGroups(prev => e.target.checked ? [...prev, g.id] : prev.filter(id => id !== g.id))}
                            className="rounded"
                          />
                          <Users className="w-3 h-3 text-muted-foreground" />
                          <span className="text-foreground">{g.name}</span>
                          <Badge variant="outline" className="text-[10px] py-0 bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
                            {g.reason === 'no_targets' ? 'Empty' : 'Test'}
                          </Badge>
                          <span className="text-muted-foreground ml-auto">{g.targetCount} target(s)</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : staleData ? (
              <div className="flex items-center gap-2 py-4">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-sm text-muted-foreground">No stale resources found. Your phishing arsenal is clean.</span>
              </div>
            ) : null}
          </CardContent>
        </Card>
      )}

      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-4">
        {sections.map(({ title, icon: Icon, items }) => (
          <Card key={title} className="bg-card border-border">
            <CardContent className="p-4 flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10">
                <Icon className="w-4 h-4 text-primary" />
              </div>
              <div>
                <p className="text-xl font-bold text-foreground">{items.length}</p>
                <p className="text-xs text-muted-foreground">{title}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Resource lists */}
      {sections.map(({ title, icon: Icon, items, onDelete, fields }) => (
        <Card key={title} className="bg-card border-border">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Icon className="w-4 h-4 text-primary" /> {title}
              <Badge variant="outline" className="ml-auto">{items.length}</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {items.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No {title.toLowerCase()} found</p>
            ) : (
              <div className="space-y-2">
                {items.map((item: any) => (
                  <div key={item.id} className="flex items-center justify-between bg-card-elevated rounded-lg p-3">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-foreground truncate">{item.name}</p>
                      {fields.includes("subject") && item.subject && (
                        <p className="text-xs text-muted-foreground truncate">Subject: {item.subject}</p>
                      )}
                      {fields.includes("host") && item.host && (
                        <p className="text-xs text-muted-foreground truncate">Host: {item.host}</p>
                      )}
                      {item.targets && (
                        <p className="text-xs text-muted-foreground">{item.targets.length} target(s)</p>
                      )}
                      <p className="text-xs text-muted-dim">
                        Modified: {item.modified_date ? new Date(item.modified_date).toLocaleDateString() : "—"}
                      </p>
                    </div>
                    {onDelete && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                        onClick={() => {
                          if (confirm(`Delete "${item.name}"?`)) {
                            onDelete(item.id);
                          }
                        }}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════════════════════════════
export default function PhishingOperations() {
  const [activeTab, setActiveTab] = useState("intel-feed");

  return (
    <AppShell>
    <div className="space-y-6">
      {/* ROE Warning Banner */}
      <ROEWarningBanner riskTier="red" operationName="Phishing" />

      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Fish className="w-6 h-6 text-primary" />
            </div>
            Phishing Operations
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Unified phishing campaign pipeline — from domain intelligence to post-exploitation
          </p>
        </div>
      </div>

      {/* Pipeline visualization */}
      <Card className="bg-card border-border">
        <CardContent className="p-4">
          <div className="flex items-center justify-between gap-2 overflow-x-auto">
            {[
              { icon: Globe, label: "Domain Scan", color: "text-blue-400" },
              { icon: Brain, label: "APT Match", color: "text-purple-400" },
              { icon: Zap, label: "Materialize", color: "text-yellow-400" },
              { icon: Edit, label: "Review", color: "text-orange-400" },
              { icon: Send, label: "Deploy", color: "text-primary" },
              { icon: Rocket, label: "Launch", color: "text-green-400" },
              { icon: BarChart3, label: "Track", color: "text-blue-400" },
              { icon: Cpu, label: "emulation framework", color: "text-red-400" },
            ].map(({ icon: Icon, label, color }, i) => (
              <div key={label} className="flex items-center gap-2 flex-shrink-0">
                <div className="flex flex-col items-center gap-1">
                  <div className={`p-1.5 rounded-md bg-card-elevated`}>
                    <Icon className={`w-3.5 h-3.5 ${color}`} />
                  </div>
                  <span className="text-[10px] text-muted-foreground whitespace-nowrap">{label}</span>
                </div>
                {i < 7 && <ArrowRight className="w-3 h-3 text-muted-dim flex-shrink-0" />}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted w-full justify-start">
          <TabsTrigger value="intel-feed" className="flex items-center gap-1.5">
            <Brain className="w-3.5 h-3.5" /> Intelligence Feed
          </TabsTrigger>
          <TabsTrigger value="campaign-builder" className="flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5" /> Campaign Builder
          </TabsTrigger>
          <TabsTrigger value="active-campaigns" className="flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5" /> Active Campaigns
          </TabsTrigger>
          <TabsTrigger value="arsenal" className="flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5" /> Arsenal
          </TabsTrigger>
          <TabsTrigger value="gophish-manager" className="flex items-center gap-1.5">
            <Fish className="w-3.5 h-3.5" /> Phishing Manager
          </TabsTrigger>
          <TabsTrigger value="typosquat" className="flex items-center gap-1.5">
            <Globe className="w-3.5 h-3.5" /> Typosquat Domains
          </TabsTrigger>
        </TabsList>

        <TabsContent value="intel-feed">
          <IntelFeedTab />
        </TabsContent>
        <TabsContent value="campaign-builder">
          <CampaignBuilderTab />
        </TabsContent>
        <TabsContent value="active-campaigns">
          <ActiveCampaignsTab />
        </TabsContent>
        <TabsContent value="arsenal">
          <ArsenalTab />
        </TabsContent>
        <TabsContent value="gophish-manager">
          <GoPhishManagerContent />
        </TabsContent>
        <TabsContent value="typosquat">
          <TyposquatManagerComponent />
        </TabsContent>
      </Tabs>
    </div>
    </AppShell>
  );
}
