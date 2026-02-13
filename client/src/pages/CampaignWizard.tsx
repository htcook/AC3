import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import TemplatePreview, { TemplatePreviewCard } from "@/components/TemplatePreview";
import {
  Activity, Key, Target, Cpu, Zap, Users, FileText, Cloud, BookOpen,
  Shield, Globe2, LogOut, Menu, X, ChevronRight, ChevronLeft, Check,
  Mail, Send, Globe, UserPlus, Briefcase, Rocket, Eye, Plus, Trash2,
  Upload, Clock, AlertTriangle, Search, LayoutTemplate, MousePointerClick
} from "lucide-react";
import { useState, useMemo, useCallback, useEffect } from "react";

function NavItem({ href, icon, label, active }: { href: string; icon: React.ReactNode; label: string; active?: boolean }) {
  return (
    <Link href={href}>
      <div className={`flex items-center gap-3 px-4 py-2.5 text-sm tracking-wider cursor-pointer transition-colors ${active ? 'bg-primary/10 text-primary border-l-2 border-primary' : 'text-muted-foreground hover:text-foreground hover:bg-accent/50'}`}>
        <span className="w-5 h-5">{icon}</span>
        <span className="font-display">{label}</span>
      </div>
    </Link>
  );
}

// Wizard steps
const STEPS = [
  { id: 1, title: "ENGAGEMENT", icon: <Briefcase className="w-4 h-4" />, description: "Select customer engagement" },
  { id: 2, title: "TEMPLATE", icon: <LayoutTemplate className="w-4 h-4" />, description: "Choose email template" },
  { id: 3, title: "TARGETS", icon: <Users className="w-4 h-4" />, description: "Configure target group" },
  { id: 4, title: "SMTP", icon: <Send className="w-4 h-4" />, description: "Select sending profile" },
  { id: 5, title: "LANDING PAGE", icon: <Globe className="w-4 h-4" />, description: "Choose landing page" },
  { id: 6, title: "REVIEW", icon: <Eye className="w-4 h-4" />, description: "Review and launch" },
];

interface TargetEntry {
  first_name: string;
  last_name: string;
  email: string;
  position: string;
}

export default function CampaignWizard() {
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [currentStep, setCurrentStep] = useState(1);
  const [cloneApplied, setCloneApplied] = useState(false);

  // Wizard state
  const [campaignName, setCampaignName] = useState("");
  const [selectedEngagementId, setSelectedEngagementId] = useState<number | null>(null);
  const [selectedTemplateId, setSelectedTemplateId] = useState<number | null>(null);
  const [selectedGroupId, setSelectedGroupId] = useState<number | null>(null);
  const [selectedSmtpId, setSelectedSmtpId] = useState<number | null>(null);
  const [selectedPageId, setSelectedPageId] = useState<number | null>(null);
  const [phishingUrl, setPhishingUrl] = useState("https://");
  const [launchDate, setLaunchDate] = useState("");
  const [sendByDate, setSendByDate] = useState("");

  // New group creation
  const [createNewGroup, setCreateNewGroup] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [newTargets, setNewTargets] = useState<TargetEntry[]>([
    { first_name: "", last_name: "", email: "", position: "" },
  ]);
  const [csvImport, setCsvImport] = useState("");

  // Preview state
  const [previewTemplateHtml, setPreviewTemplateHtml] = useState<string | null>(null);
  const [previewPageHtml, setPreviewPageHtml] = useState<string | null>(null);

  // Fetch data
  const { data: engagements } = trpc.engagements.list.useQuery();
  const { data: templates } = trpc.gophishProxy.getTemplates.useQuery();
  const { data: groups } = trpc.gophishProxy.getGroups.useQuery();
  const { data: sendingProfiles } = trpc.gophishProxy.getSendingProfiles.useQuery();
  const { data: landingPages } = trpc.gophishProxy.getLandingPages.useQuery();

  // Mutations
  const createGroupMutation = trpc.gophishProxy.createGroup.useMutation();
  const launchCampaignMutation = trpc.gophishProxy.launchCampaign.useMutation();
  const linkCampaignMutation = trpc.campaignEngagements.link.useMutation();

  // Derived data
  const selectedTemplate = useMemo(() =>
    templates?.find((t: any) => t.id === selectedTemplateId), [templates, selectedTemplateId]);
  const selectedGroup = useMemo(() =>
    groups?.find((g: any) => g.id === selectedGroupId), [groups, selectedGroupId]);
  const selectedSmtp = useMemo(() =>
    sendingProfiles?.find((s: any) => s.id === selectedSmtpId), [sendingProfiles, selectedSmtpId]);
  const selectedPage = useMemo(() =>
    landingPages?.find((p: any) => p.id === selectedPageId), [landingPages, selectedPageId]);
  const selectedEngagement = useMemo(() =>
    engagements?.find((e: any) => e.id === selectedEngagementId), [engagements, selectedEngagementId]);

  // Clone pre-fill from URL params
  useEffect(() => {
    if (cloneApplied) return;
    const params = new URLSearchParams(window.location.search);
    if (params.get('clone') !== '1') return;
    if (!templates || !sendingProfiles || !landingPages || !groups) return;

    const name = params.get('name');
    const templateName = params.get('template');
    const pageName = params.get('page');
    const smtpName = params.get('smtp');
    const groupName = params.get('group');
    const url = params.get('url');

    if (name) setCampaignName(name);
    if (url) setPhishingUrl(url);

    if (templateName) {
      const t = templates.find((t: any) => t.name === templateName);
      if (t) setSelectedTemplateId(t.id);
    }
    if (pageName) {
      const p = landingPages.find((p: any) => p.name === pageName);
      if (p) setSelectedPageId(p.id);
    }
    if (smtpName) {
      const s = sendingProfiles.find((s: any) => s.name === smtpName);
      if (s) setSelectedSmtpId(s.id);
    }
    if (groupName) {
      const g = groups.find((g: any) => g.name === groupName);
      if (g) setSelectedGroupId(g.id);
    }

    setCloneApplied(true);
    setCurrentStep(6); // Jump to review step
    toast.success('Campaign configuration cloned — review and adjust before launching');
  }, [cloneApplied, templates, sendingProfiles, landingPages, groups]);

  // Validation per step
  const canProceed = useCallback(() => {
    switch (currentStep) {
      case 1: return true; // engagement is optional
      case 2: return selectedTemplateId !== null;
      case 3: return selectedGroupId !== null || (createNewGroup && newGroupName && newTargets.some(t => t.email));
      case 4: return selectedSmtpId !== null;
      case 5: return selectedPageId !== null;
      case 6: return campaignName.trim().length > 0 && phishingUrl.length > 8;
      default: return false;
    }
  }, [currentStep, selectedTemplateId, selectedGroupId, selectedSmtpId, selectedPageId, campaignName, phishingUrl, createNewGroup, newGroupName, newTargets]);

  const addTargetRow = () => {
    setNewTargets([...newTargets, { first_name: "", last_name: "", email: "", position: "" }]);
  };

  const removeTargetRow = (index: number) => {
    setNewTargets(newTargets.filter((_, i) => i !== index));
  };

  const updateTarget = (index: number, field: keyof TargetEntry, value: string) => {
    const updated = [...newTargets];
    updated[index] = { ...updated[index], [field]: value };
    setNewTargets(updated);
  };

  const handleCsvImport = () => {
    if (!csvImport.trim()) return;
    const lines = csvImport.trim().split("\n");
    const parsed: TargetEntry[] = [];
    for (const line of lines) {
      const parts = line.split(",").map(s => s.trim());
      if (parts.length >= 1 && parts[0].includes("@")) {
        parsed.push({
          email: parts[0],
          first_name: parts[1] || "",
          last_name: parts[2] || "",
          position: parts[3] || "",
        });
      } else if (parts.length >= 3) {
        parsed.push({
          first_name: parts[0],
          last_name: parts[1],
          email: parts[2],
          position: parts[3] || "",
        });
      }
    }
    if (parsed.length > 0) {
      setNewTargets(parsed);
      toast.success(`Imported ${parsed.length} targets`);
      setCsvImport("");
    } else {
      toast.error("No valid targets found in CSV");
    }
  };

  const handleLaunch = async () => {
    try {
      // If creating a new group, create it first
      let groupName = selectedGroup?.name;
      if (createNewGroup && newGroupName) {
        const validTargets = newTargets.filter(t => t.email.trim());
        if (validTargets.length === 0) {
          toast.error("Add at least one target email");
          return;
        }
        const newGroup = await createGroupMutation.mutateAsync({
          name: newGroupName,
          targets: validTargets,
        });
        if (!newGroup) {
          toast.error("Failed to create target group");
          return;
        }
        groupName = newGroupName;
      }

      if (!groupName || !selectedTemplate || !selectedSmtp || !selectedPage) {
        toast.error("Missing required selections");
        return;
      }

      // Launch the campaign
      const campaignData: any = {
        name: campaignName,
        template: { name: selectedTemplate.name },
        page: { name: selectedPage.name },
        smtp: { name: selectedSmtp.name },
        url: phishingUrl,
        groups: [{ name: groupName }],
      };

      if (launchDate) {
        campaignData.launch_date = new Date(launchDate).toISOString();
      }
      if (sendByDate) {
        campaignData.send_by_date = new Date(sendByDate).toISOString();
      }

      const result = await launchCampaignMutation.mutateAsync(campaignData);

      // Link to engagement if selected
      if (selectedEngagementId && result?.id) {
        await linkCampaignMutation.mutateAsync({
          engagementId: selectedEngagementId,
          gophishCampaignId: result.id,
          gophishCampaignName: campaignName,
        });
      }

      toast.success("Campaign launched successfully!");
      navigate("/gophish");
    } catch (error: any) {
      toast.error(error.message || "Failed to launch campaign");
    }
  };

  const nextStep = () => {
    if (canProceed() && currentStep < 6) setCurrentStep(currentStep + 1);
  };
  const prevStep = () => {
    if (currentStep > 1) setCurrentStep(currentStep - 1);
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-card border-r border-border transform transition-transform duration-200 lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex flex-col h-full">
          <div className="p-6 border-b border-border">
            <Link href="/" className="flex items-center gap-3">
              <Cloud className="w-8 h-8 text-primary" />
              <div className="flex flex-col">
                <span className="font-display text-xl tracking-wider">ACE OF CLOUD</span>
                <span className="text-xs text-muted-foreground tracking-widest">C3 — <span className="text-primary/70">CYBER CAMPAIGN COMMAND</span></span>
              </div>
            </Link>
          </div>
          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity />} label="DASHBOARD" />
            <NavItem href="/engagements" icon={<Briefcase />} label="ENGAGEMENTS" />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" />
            <NavItem href="/agents" icon={<Cpu />} label="AGENTS" />
            <NavItem href="/campaigns" icon={<Zap />} label="CAMPAIGNS" />
            <NavItem href="/gophish" icon={<Zap />} label="GOPHISH" />
            <NavItem href="/campaign-wizard" icon={<Rocket />} label="LAUNCH WIZARD" active />
            <NavItem href="/team" icon={<Users />} label="TEAM" />
            <NavItem href="/activity" icon={<FileText />} label="ACTIVITY" />
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">THREAT INTEL</p>
              <NavItem href="/apt-library" icon={<Shield className="w-4 h-4" />} label="APT SCENARIOS" />
              <NavItem href="/compliance" icon={<FileText className="w-4 h-4" />} label="COMPLIANCE" />
              <NavItem href="/infra-reference" icon={<Globe2 className="w-4 h-4" />} label="INFRASTRUCTURE" />
            </div>
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">GUIDES</p>
              <NavItem href="/guide/gophish" icon={<BookOpen />} label="GOPHISH GUIDE" />
              <NavItem href="/guide/caldera" icon={<BookOpen />} label="CALDERA GUIDE" />
              <NavItem href="/templates" icon={<FileText />} label="TEMPLATE LIBRARY" />
            </div>
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">REPORTS</p>
              <NavItem href="/reports/security" icon={<FileText />} label="SECURITY REPORT" />
            </div>
          </nav>
          <div className="p-4 border-t border-border">
            <Link href="/">
              <Button variant="outline" size="sm" className="w-full font-display tracking-wider">
                <LogOut className="w-4 h-4 mr-2" />
                EXIT
              </Button>
            </Link>
          </div>
        </div>
      </aside>

      <button
        className="fixed top-4 left-4 z-50 lg:hidden p-2 bg-card border border-border"
        onClick={() => setSidebarOpen(!sidebarOpen)}
      >
        {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      {/* Main Content */}
      <main className="flex-1 lg:ml-64 p-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="font-display text-3xl tracking-wider flex items-center gap-3">
              <Rocket className="w-8 h-8 text-primary" />
              CAMPAIGN LAUNCH WIZARD
            </h1>
            <p className="text-muted-foreground text-sm mt-1">Create and launch GoPhish phishing campaigns step by step</p>
          </div>
          <Button variant="outline" onClick={() => navigate("/gophish")} className="font-display tracking-wider">
            <X className="w-4 h-4 mr-2" /> CANCEL
          </Button>
        </div>

        {/* Step indicator */}
        <div className="flex items-center gap-1 mb-8 overflow-x-auto pb-2">
          {STEPS.map((step, i) => (
            <div key={step.id} className="flex items-center">
              <button
                onClick={() => {
                  // Allow going back to completed steps
                  if (step.id <= currentStep) setCurrentStep(step.id);
                }}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-display tracking-wider transition-all whitespace-nowrap ${
                  step.id === currentStep
                    ? "bg-primary text-primary-foreground"
                    : step.id < currentStep
                    ? "bg-primary/20 text-primary cursor-pointer hover:bg-primary/30"
                    : "bg-card text-muted-foreground border border-border"
                }`}
              >
                <span className={`w-5 h-5 flex items-center justify-center text-[10px] font-bold rounded-full ${
                  step.id < currentStep ? "bg-primary text-primary-foreground" : step.id === currentStep ? "bg-primary-foreground text-primary" : "bg-muted text-muted-foreground"
                }`}>
                  {step.id < currentStep ? <Check className="w-3 h-3" /> : step.id}
                </span>
                {step.title}
              </button>
              {i < STEPS.length - 1 && (
                <ChevronRight className={`w-4 h-4 mx-1 flex-shrink-0 ${step.id < currentStep ? "text-primary" : "text-muted-foreground/30"}`} />
              )}
            </div>
          ))}
        </div>

        {/* Step content */}
        <div className="bg-card border border-border p-6 min-h-[500px]">
          {/* Step 1: Engagement Selection */}
          {currentStep === 1 && (
            <div>
              <h2 className="font-display text-xl tracking-wider mb-1">SELECT ENGAGEMENT</h2>
              <p className="text-muted-foreground text-sm mb-6">
                Optionally link this campaign to a customer engagement for tracking and filtering.
              </p>

              <div className="grid gap-3 max-w-3xl">
                {/* No engagement option */}
                <button
                  onClick={() => setSelectedEngagementId(null)}
                  className={`flex items-center gap-4 p-4 border text-left transition-all ${
                    selectedEngagementId === null
                      ? "border-primary bg-primary/5 ring-1 ring-primary/30"
                      : "border-border hover:border-primary/50"
                  }`}
                >
                  <div className={`w-10 h-10 flex items-center justify-center rounded ${
                    selectedEngagementId === null ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"
                  }`}>
                    <Globe2 className="w-5 h-5" />
                  </div>
                  <div>
                    <p className="font-medium text-sm">No Engagement (Standalone)</p>
                    <p className="text-xs text-muted-foreground">Launch campaign without linking to an engagement</p>
                  </div>
                </button>

                {engagements?.map((eng: any) => (
                  <button
                    key={eng.id}
                    onClick={() => setSelectedEngagementId(eng.id)}
                    className={`flex items-center gap-4 p-4 border text-left transition-all ${
                      selectedEngagementId === eng.id
                        ? "border-primary bg-primary/5 ring-1 ring-primary/30"
                        : "border-border hover:border-primary/50"
                    }`}
                  >
                    <div className={`w-10 h-10 flex items-center justify-center rounded ${
                      selectedEngagementId === eng.id ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"
                    }`}>
                      <Briefcase className="w-5 h-5" />
                    </div>
                    <div className="flex-1">
                      <p className="font-medium text-sm">{eng.name}</p>
                      <p className="text-xs text-muted-foreground">{eng.customerName} — {eng.engagementType?.replace("_", " ")}</p>
                    </div>
                    <span className={`text-xs px-2 py-0.5 rounded ${
                      eng.status === "active" ? "bg-green-500/20 text-green-400" :
                      eng.status === "planning" ? "bg-gray-500/20 text-gray-400" :
                      "bg-yellow-500/20 text-yellow-400"
                    }`}>
                      {eng.status}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Step 2: Template Selection */}
          {currentStep === 2 && (
            <div>
              <h2 className="font-display text-xl tracking-wider mb-1">SELECT EMAIL TEMPLATE</h2>
              <p className="text-muted-foreground text-sm mb-6">
                Choose a phishing email template from your GoPhish library. Click to preview.
              </p>

              {previewTemplateHtml ? (
                <div className="border border-border rounded overflow-hidden" style={{ height: "500px" }}>
                  <TemplatePreview
                    html={previewTemplateHtml}
                    name={selectedTemplate?.name}
                    subject={selectedTemplate?.subject}
                    onClose={() => setPreviewTemplateHtml(null)}
                  />
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {templates?.map((template: any) => (
                    <div key={template.id} className="relative">
                      <TemplatePreviewCard
                        html={template.html || "<p>No HTML content</p>"}
                        name={template.name}
                        subject={template.subject}
                        selected={selectedTemplateId === template.id}
                        onClick={() => setSelectedTemplateId(template.id)}
                      />
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedTemplateId(template.id);
                          setPreviewTemplateHtml(template.html);
                        }}
                        className="absolute top-2 left-2 p-1.5 bg-black/60 text-white rounded hover:bg-black/80 transition-colors"
                        title="Full Preview"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                  {(!templates || templates.length === 0) && (
                    <div className="col-span-full text-center py-12 text-muted-foreground">
                      <LayoutTemplate className="w-12 h-12 mx-auto mb-3 opacity-50" />
                      <p>No templates found in GoPhish.</p>
                      <p className="text-xs mt-1">Create templates in the GoPhish admin panel first.</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Step 3: Target Group */}
          {currentStep === 3 && (
            <div>
              <h2 className="font-display text-xl tracking-wider mb-1">CONFIGURE TARGETS</h2>
              <p className="text-muted-foreground text-sm mb-6">
                Select an existing target group or create a new one.
              </p>

              <div className="flex gap-3 mb-6">
                <Button
                  variant={!createNewGroup ? "default" : "outline"}
                  onClick={() => setCreateNewGroup(false)}
                  className="font-display tracking-wider"
                >
                  <Users className="w-4 h-4 mr-2" /> EXISTING GROUP
                </Button>
                <Button
                  variant={createNewGroup ? "default" : "outline"}
                  onClick={() => setCreateNewGroup(true)}
                  className="font-display tracking-wider"
                >
                  <Plus className="w-4 h-4 mr-2" /> NEW GROUP
                </Button>
              </div>

              {!createNewGroup ? (
                <div className="grid gap-3 max-w-3xl">
                  {groups?.map((group: any) => (
                    <button
                      key={group.id}
                      onClick={() => setSelectedGroupId(group.id)}
                      className={`flex items-center gap-4 p-4 border text-left transition-all ${
                        selectedGroupId === group.id
                          ? "border-primary bg-primary/5 ring-1 ring-primary/30"
                          : "border-border hover:border-primary/50"
                      }`}
                    >
                      <div className={`w-10 h-10 flex items-center justify-center rounded ${
                        selectedGroupId === group.id ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"
                      }`}>
                        <Users className="w-5 h-5" />
                      </div>
                      <div className="flex-1">
                        <p className="font-medium text-sm">{group.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {group.targets?.length || 0} targets
                        </p>
                      </div>
                    </button>
                  ))}
                  {(!groups || groups.length === 0) && (
                    <div className="text-center py-8 text-muted-foreground">
                      <Users className="w-10 h-10 mx-auto mb-2 opacity-50" />
                      <p>No target groups found. Create a new group.</p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="max-w-4xl space-y-4">
                  <div>
                    <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">GROUP NAME</label>
                    <input
                      type="text"
                      value={newGroupName}
                      onChange={(e) => setNewGroupName(e.target.value)}
                      placeholder="e.g., Acme Corp IT Department"
                      className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                    />
                  </div>

                  {/* CSV Import */}
                  <div className="border border-border p-4 bg-background/50">
                    <label className="text-xs font-display tracking-wider text-muted-foreground mb-2 block flex items-center gap-2">
                      <Upload className="w-3.5 h-3.5" /> BULK IMPORT (CSV)
                    </label>
                    <textarea
                      value={csvImport}
                      onChange={(e) => setCsvImport(e.target.value)}
                      placeholder="email@example.com, First, Last, Position&#10;john@acme.com, John, Doe, IT Manager&#10;jane@acme.com, Jane, Smith, CFO"
                      className="w-full px-3 py-2 bg-background border border-border text-xs font-mono h-20 focus:outline-none focus:border-primary resize-none"
                    />
                    <Button size="sm" variant="outline" onClick={handleCsvImport} className="mt-2 text-xs">
                      <Upload className="w-3 h-3 mr-1" /> Import CSV
                    </Button>
                  </div>

                  {/* Manual target entry */}
                  <div>
                    <label className="text-xs font-display tracking-wider text-muted-foreground mb-2 block">TARGETS</label>
                    <div className="space-y-2">
                      {newTargets.map((target, i) => (
                        <div key={i} className="flex gap-2 items-center">
                          <input
                            type="text"
                            value={target.first_name}
                            onChange={(e) => updateTarget(i, "first_name", e.target.value)}
                            placeholder="First Name"
                            className="flex-1 px-2 py-1.5 bg-background border border-border text-xs focus:outline-none focus:border-primary"
                          />
                          <input
                            type="text"
                            value={target.last_name}
                            onChange={(e) => updateTarget(i, "last_name", e.target.value)}
                            placeholder="Last Name"
                            className="flex-1 px-2 py-1.5 bg-background border border-border text-xs focus:outline-none focus:border-primary"
                          />
                          <input
                            type="email"
                            value={target.email}
                            onChange={(e) => updateTarget(i, "email", e.target.value)}
                            placeholder="Email *"
                            className="flex-[2] px-2 py-1.5 bg-background border border-border text-xs focus:outline-none focus:border-primary"
                          />
                          <input
                            type="text"
                            value={target.position}
                            onChange={(e) => updateTarget(i, "position", e.target.value)}
                            placeholder="Position"
                            className="flex-1 px-2 py-1.5 bg-background border border-border text-xs focus:outline-none focus:border-primary"
                          />
                          {newTargets.length > 1 && (
                            <button onClick={() => removeTargetRow(i)} className="text-destructive hover:text-destructive/80 p-1">
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                    <Button size="sm" variant="outline" onClick={addTargetRow} className="mt-2 text-xs">
                      <Plus className="w-3 h-3 mr-1" /> Add Target
                    </Button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 4: Sending Profile */}
          {currentStep === 4 && (
            <div>
              <h2 className="font-display text-xl tracking-wider mb-1">SELECT SENDING PROFILE</h2>
              <p className="text-muted-foreground text-sm mb-6">
                Choose the SMTP sending profile for this campaign.
              </p>

              <div className="grid gap-3 max-w-3xl">
                {sendingProfiles?.map((smtp: any) => (
                  <button
                    key={smtp.id}
                    onClick={() => setSelectedSmtpId(smtp.id)}
                    className={`flex items-center gap-4 p-4 border text-left transition-all ${
                      selectedSmtpId === smtp.id
                        ? "border-primary bg-primary/5 ring-1 ring-primary/30"
                        : "border-border hover:border-primary/50"
                    }`}
                  >
                    <div className={`w-10 h-10 flex items-center justify-center rounded ${
                      selectedSmtpId === smtp.id ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"
                    }`}>
                      <Send className="w-5 h-5" />
                    </div>
                    <div className="flex-1">
                      <p className="font-medium text-sm">{smtp.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {smtp.from_address} via {smtp.host}
                      </p>
                    </div>
                  </button>
                ))}
                {(!sendingProfiles || sendingProfiles.length === 0) && (
                  <div className="text-center py-8 text-muted-foreground">
                    <Send className="w-10 h-10 mx-auto mb-2 opacity-50" />
                    <p>No sending profiles found.</p>
                    <p className="text-xs mt-1">Create an SMTP profile in GoPhish first.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Step 5: Landing Page */}
          {currentStep === 5 && (
            <div>
              <h2 className="font-display text-xl tracking-wider mb-1">SELECT LANDING PAGE</h2>
              <p className="text-muted-foreground text-sm mb-6">
                Choose the landing page targets will see after clicking the phishing link.
              </p>

              {previewPageHtml ? (
                <div className="border border-border rounded overflow-hidden" style={{ height: "500px" }}>
                  <TemplatePreview
                    html={previewPageHtml}
                    name={selectedPage?.name}
                    onClose={() => setPreviewPageHtml(null)}
                  />
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {landingPages?.map((page: any) => (
                    <div key={page.id} className="relative">
                      <TemplatePreviewCard
                        html={page.html || "<p>No HTML content</p>"}
                        name={page.name}
                        selected={selectedPageId === page.id}
                        onClick={() => setSelectedPageId(page.id)}
                      />
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedPageId(page.id);
                          setPreviewPageHtml(page.html);
                        }}
                        className="absolute top-2 left-2 p-1.5 bg-black/60 text-white rounded hover:bg-black/80 transition-colors"
                        title="Full Preview"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                  {(!landingPages || landingPages.length === 0) && (
                    <div className="col-span-full text-center py-12 text-muted-foreground">
                      <Globe className="w-12 h-12 mx-auto mb-3 opacity-50" />
                      <p>No landing pages found in GoPhish.</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Step 6: Review & Launch */}
          {currentStep === 6 && (
            <div>
              <h2 className="font-display text-xl tracking-wider mb-1">REVIEW & LAUNCH</h2>
              <p className="text-muted-foreground text-sm mb-6">
                Review your campaign configuration and launch when ready.
              </p>

              <div className="max-w-3xl space-y-6">
                {/* Campaign name */}
                <div>
                  <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">CAMPAIGN NAME *</label>
                  <input
                    type="text"
                    value={campaignName}
                    onChange={(e) => setCampaignName(e.target.value)}
                    placeholder="e.g., Acme Corp Q1 Phishing Assessment"
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                  />
                </div>

                {/* Phishing URL */}
                <div>
                  <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">PHISHING URL *</label>
                  <input
                    type="url"
                    value={phishingUrl}
                    onChange={(e) => setPhishingUrl(e.target.value)}
                    placeholder="https://your-phishing-domain.com"
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                  />
                  <p className="text-xs text-muted-foreground mt-1">The URL where the landing page will be hosted (GoPhish listener)</p>
                </div>

                {/* Schedule */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block flex items-center gap-1">
                      <Clock className="w-3 h-3" /> LAUNCH DATE (OPTIONAL)
                    </label>
                    <input
                      type="datetime-local"
                      value={launchDate}
                      onChange={(e) => setLaunchDate(e.target.value)}
                      className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block flex items-center gap-1">
                      <Clock className="w-3 h-3" /> SEND BY DATE (OPTIONAL)
                    </label>
                    <input
                      type="datetime-local"
                      value={sendByDate}
                      onChange={(e) => setSendByDate(e.target.value)}
                      className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                    />
                  </div>
                </div>

                {/* Summary */}
                <div className="border border-border bg-background/50 p-4 space-y-3">
                  <h3 className="font-display text-sm tracking-wider text-primary">CAMPAIGN SUMMARY</h3>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <span className="text-xs text-muted-foreground">Engagement</span>
                      <p className="font-medium">{selectedEngagement ? selectedEngagement.name : "None (Standalone)"}</p>
                    </div>
                    <div>
                      <span className="text-xs text-muted-foreground">Email Template</span>
                      <p className="font-medium">{selectedTemplate?.name || "—"}</p>
                    </div>
                    <div>
                      <span className="text-xs text-muted-foreground">Target Group</span>
                      <p className="font-medium">
                        {createNewGroup ? `${newGroupName} (new, ${newTargets.filter(t => t.email).length} targets)` : selectedGroup?.name || "—"}
                      </p>
                    </div>
                    <div>
                      <span className="text-xs text-muted-foreground">Sending Profile</span>
                      <p className="font-medium">{selectedSmtp?.name || "—"}</p>
                    </div>
                    <div>
                      <span className="text-xs text-muted-foreground">Landing Page</span>
                      <p className="font-medium">{selectedPage?.name || "—"}</p>
                    </div>
                    <div>
                      <span className="text-xs text-muted-foreground">Phishing URL</span>
                      <p className="font-medium truncate">{phishingUrl || "—"}</p>
                    </div>
                  </div>
                </div>

                {/* Warning */}
                <div className="flex items-start gap-3 p-3 border border-yellow-500/30 bg-yellow-500/5 text-sm">
                  <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-medium text-yellow-400">Ready to Launch</p>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      This will create and launch a live phishing campaign in GoPhish. Emails will be sent to all targets in the selected group.
                      {!launchDate && " The campaign will launch immediately."}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Navigation buttons */}
        <div className="flex items-center justify-between mt-6">
          <Button
            variant="outline"
            onClick={prevStep}
            disabled={currentStep === 1}
            className="font-display tracking-wider"
          >
            <ChevronLeft className="w-4 h-4 mr-2" /> BACK
          </Button>

          <div className="flex items-center gap-3">
            <span className="text-xs text-muted-foreground">
              Step {currentStep} of {STEPS.length}
            </span>

            {currentStep < 6 ? (
              <Button
                onClick={nextStep}
                disabled={!canProceed()}
                className="font-display tracking-wider"
              >
                NEXT <ChevronRight className="w-4 h-4 ml-2" />
              </Button>
            ) : (
              <Button
                onClick={handleLaunch}
                disabled={!canProceed() || launchCampaignMutation.isPending}
                className="font-display tracking-wider bg-red-600 hover:bg-red-700 text-white"
              >
                {launchCampaignMutation.isPending ? (
                  <>LAUNCHING...</>
                ) : (
                  <>
                    <Rocket className="w-4 h-4 mr-2" /> LAUNCH CAMPAIGN
                  </>
                )}
              </Button>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
