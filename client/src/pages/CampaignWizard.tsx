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
import { Radar, ShieldAlert, ShieldCheck, Brain } from "lucide-react";

import AppShell from "@/components/AppShell";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
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

  // Attack template state (from threat intel pipeline)
  const [selectedAttackTemplateId, setSelectedAttackTemplateId] = useState<number | null>(null);

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
  const createInternalCampaign = trpc.campaign.create.useMutation();
  const applyTemplateMutation = trpc.threatIntelTraining.applyTemplateToCampaign.useMutation();

  // Fetch engagement ROE data for social engineering check
  const { data: engagementDetail } = trpc.engagements.get.useQuery(
    { id: selectedEngagementId! },
    { enabled: !!selectedEngagementId }
  );

  // Check if social engineering is allowed in ROE
  const socialEngAllowed = useMemo(() => {
    if (!selectedEngagementId || !engagementDetail) return true; // standalone = allowed
    // Check roeScope JSON for socialEngineeringAllowed
    const roeScope = (engagementDetail as any).roeScope;
    if (roeScope && typeof roeScope === 'object') {
      if ('socialEngineeringAllowed' in roeScope) {
        return !!roeScope.socialEngineeringAllowed;
      }
      // Also check nested scope.socialEngineering
      if ('socialEngineering' in roeScope) {
        return !!roeScope.socialEngineering;
      }
    }
    // If ROE status is 'none' (no ROE document), allow by default but warn
    if ((engagementDetail as any).roeStatus === 'none') return true;
    // If ROE is signed but no explicit social eng scope, default to not allowed (conservative)
    if ((engagementDetail as any).roeStatus === 'signed' && roeScope) return false;
    return true; // default to allowed if not specified
  }, [selectedEngagementId, engagementDetail]);

  // ROE status for display
  const roeStatus = useMemo(() => {
    if (!engagementDetail) return null;
    return {
      status: (engagementDetail as any).roeStatus || 'none',
      hasRoe: (engagementDetail as any).roeStatus !== 'none',
      isSigned: (engagementDetail as any).roeStatus === 'signed',
    };
  }, [engagementDetail]);

  // Fetch OSINT recon data for domain spoofing intelligence
  const { data: reconData } = trpc.osint.getRecon.useQuery(
    { engagementId: selectedEngagementId! },
    { enabled: !!selectedEngagementId }
  );
  const { data: typosquatData } = trpc.osint.getTyposquats.useQuery(
    { engagementId: selectedEngagementId! },
    { enabled: !!selectedEngagementId }
  );

  // Domain spoofing intelligence
  const spoofIntel = useMemo(() => {
    const latestRecon = Array.isArray(reconData) ? reconData[0] : null;
    if (!latestRecon) return null;
    const spoofScore = latestRecon.spoofScore || 0;
    const hasSPF = !!latestRecon.spfRecord;
    const hasDMARC = !!latestRecon.dmarcRecord;
    const spfRaw = latestRecon.spfRecord || '';
    const dmarcRaw = latestRecon.dmarcRecord || '';
    // Typosquats: show unregistered (available for purchase) or already purchased/configured
    const availableTyposquats = (typosquatData || []).filter((t: any) =>
      !t.isRegistered || t.status === 'purchased' || t.status === 'configured' || t.status === 'in_use'
    );
    
    // Decision logic:
    // HIGH spoof score (>=70) = weak defenses = recommend spoofing target domain
    // MODERATE (40-69) = partial defenses = spoofing may work, have fallback ready
    // LOW (<40) = strong defenses = use typosquat or owned domain
    let recommendation: 'spoof_target' | 'spoof_possible' | 'use_alternate';
    let rationale: string;
    
    if (spoofScore >= 70) {
      recommendation = 'spoof_target';
      rationale = `Target domain has weak email security (spoofability: ${spoofScore}%). ${!hasSPF ? 'No SPF record found.' : `SPF: ${spfRaw.substring(0, 80)}`} ${!hasDMARC ? 'No DMARC record found.' : `DMARC: ${dmarcRaw.substring(0, 80)}`} Domain spoofing is highly likely to succeed — use the target's own domain as the sender address.`;
    } else if (spoofScore >= 40) {
      recommendation = 'spoof_possible';
      rationale = `Target domain has moderate email security (spoofability: ${spoofScore}%). ${hasSPF ? `SPF exists: ${spfRaw.substring(0, 60)}` : 'No SPF.'} ${hasDMARC ? `DMARC exists: ${dmarcRaw.substring(0, 60)}` : 'No DMARC.'} Spoofing may succeed against some recipients — prepare a fallback domain.`;
    } else {
      recommendation = 'use_alternate';
      rationale = `Target domain is well-hardened against spoofing (spoofability: ${spoofScore}%). ${hasSPF ? 'SPF: ✓ enforced' : ''} ${hasDMARC ? 'DMARC: ✓ enforced' : ''} Spoofing will likely be blocked — use a typosquat or owned domain instead.`;
    }
    
    return {
      spoofScore,
      hasSPF,
      hasDMARC,
      spfRaw,
      dmarcRaw,
      recommendation,
      rationale,
      availableTyposquats: availableTyposquats.slice(0, 5),
      targetDomain: selectedEngagement?.targetDomain || '',
    };
  }, [reconData, typosquatData, selectedEngagement]);

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

      // If an attack template was selected, create an internal campaign and apply template abilities
      if (selectedAttackTemplateId) {
        try {
          const internalCampaign = await createInternalCampaign.mutateAsync({
            name: campaignName,
            description: `Phishing campaign with attack template applied. Campaign ID: ${result?.id || 'unknown'}`,
          });
          if (internalCampaign?.id) {
            const applyResult = await applyTemplateMutation.mutateAsync({
              templateId: selectedAttackTemplateId,
              campaignId: internalCampaign.id,
            });
            if (applyResult.success) {
              toast.success(`Attack template applied: ${applyResult.abilitiesAdded} abilities added to campaign`);
            }
          }
        } catch (templateError: any) {
          console.error('Failed to apply attack template:', templateError);
          toast.error('Campaign launched but failed to apply attack template abilities');
        }
      }

      toast.success("Campaign launched successfully!");
      navigate("/phishing-ops");
    } catch (error: any) {
      toast.error(sanitizeErrorForToast(error));
    }
  };

  const nextStep = () => {
    if (canProceed() && currentStep < 6) setCurrentStep(currentStep + 1);
  };
  const prevStep = () => {
    if (currentStep > 1) setCurrentStep(currentStep - 1);
  };

  return (
    <AppShell activePath="/engagements">
{/* Sidebar */}
{/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="font-display text-3xl tracking-wider flex items-center gap-3">
              <Rocket className="w-8 h-8 text-primary" />
              CAMPAIGN LAUNCH WIZARD
            </h1>
            <p className="text-muted-foreground text-sm mt-1">Create and launch phishing campaigns step by step</p>
          </div>
          <Button variant="outline" onClick={() => navigate("/phishing-ops")} className="font-display tracking-wider">
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
                      {eng.targetDomain && <p className="text-xs font-mono text-primary/70 mt-0.5">{eng.targetDomain}</p>}
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

              {/* ROE Social Engineering Check */}
              {selectedEngagementId && !socialEngAllowed && (
                <div className="mt-4 border border-red-500/40 bg-red-500/10 p-4">
                  <div className="flex items-center gap-3">
                    <ShieldAlert className="w-5 h-5 text-red-400 flex-shrink-0" />
                    <div>
                      <h3 className="font-display text-sm tracking-wider text-red-400">SOCIAL ENGINEERING NOT AUTHORIZED</h3>
                      <p className="text-xs text-muted-foreground mt-1">
                        The Rules of Engagement for this engagement do not authorize social engineering / phishing operations.
                        {roeStatus?.isSigned
                          ? ' The ROE is signed but does not include social engineering in scope.'
                          : roeStatus?.hasRoe
                          ? ' The ROE exists but has not been signed yet.'
                          : ''}
                      </p>
                      <div className="flex gap-2 mt-2">
                        <button
                          onClick={() => setSelectedEngagementId(null)}
                          className="text-[10px] px-2 py-1 border border-border hover:border-primary/50 font-display tracking-wider"
                        >
                          PROCEED STANDALONE
                        </button>
                        <button
                          onClick={() => navigate(`/engagement/${selectedEngagementId}`)}
                          className="text-[10px] px-2 py-1 border border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10 font-display tracking-wider"
                        >
                          UPDATE ROE SCOPE
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* ROE Status indicator when social engineering IS allowed */}
              {selectedEngagementId && socialEngAllowed && roeStatus?.hasRoe && (
                <div className="mt-4 border border-green-500/30 bg-green-500/5 p-3">
                  <div className="flex items-center gap-3">
                    <ShieldCheck className="w-4 h-4 text-green-400" />
                    <div>
                      <span className="text-xs font-display tracking-wider text-green-400">SOCIAL ENGINEERING AUTHORIZED</span>
                      <p className="text-[10px] text-muted-foreground">
                        ROE {roeStatus.isSigned ? 'signed and' : ''} includes social engineering in scope.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* OSINT Findings Panel - shows when an engagement is selected */}
              {selectedEngagementId && selectedEngagement?.targetDomain && (
                <OsintFindingsPanel engagementId={selectedEngagementId} domain={selectedEngagement.targetDomain} />
              )}

              {/* Attack Template Picker - optional enrichment from threat intel */}
              <AttackTemplatePicker
                selectedAttackTemplateId={selectedAttackTemplateId}
                onSelectTemplate={setSelectedAttackTemplateId}
              />
            </div>
          )}

          {/* Step 2: Template Selection */}
          {currentStep === 2 && (
            <div>
              <h2 className="font-display text-xl tracking-wider mb-1">SELECT EMAIL TEMPLATE</h2>
              <p className="text-muted-foreground text-sm mb-6">
                Choose a phishing email template from your template library. Click to preview.
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
                      <p>No templates found in the phishing platform.</p>
                      <p className="text-xs mt-1">Create templates in the phishing admin panel first.</p>
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

              {/* Domain Spoofing Intelligence Advisor */}
              {spoofIntel && (
                <div className={`mb-6 border p-4 space-y-3 ${
                  spoofIntel.recommendation === 'spoof_target'
                    ? 'border-green-500/30 bg-green-500/5'
                    : spoofIntel.recommendation === 'spoof_possible'
                    ? 'border-yellow-500/30 bg-yellow-500/5'
                    : 'border-red-500/30 bg-red-500/5'
                }`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Radar className="w-5 h-5 text-primary" />
                      <div>
                        <h3 className="font-display text-sm tracking-wider">DOMAIN SPOOFING INTELLIGENCE</h3>
                        <p className="text-[10px] text-muted-foreground">Based on OSINT recon of {spoofIntel.targetDomain}</p>
                      </div>
                    </div>
                    <div className={`text-2xl font-display ${
                      spoofIntel.spoofScore >= 70 ? 'text-green-400' : spoofIntel.spoofScore >= 40 ? 'text-yellow-400' : 'text-red-400'
                    }`}>
                      {spoofIntel.spoofScore}%
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <span className={`text-[10px] px-2 py-0.5 rounded font-display ${
                      spoofIntel.hasSPF ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                    }`}>SPF {spoofIntel.hasSPF ? 'PRESENT' : 'MISSING'}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-display ${
                      spoofIntel.hasDMARC ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                    }`}>DMARC {spoofIntel.hasDMARC ? 'PRESENT' : 'MISSING'}</span>
                  </div>

                  <div className={`p-3 border ${
                    spoofIntel.recommendation === 'spoof_target'
                      ? 'border-green-500/20 bg-green-500/5'
                      : spoofIntel.recommendation === 'spoof_possible'
                      ? 'border-yellow-500/20 bg-yellow-500/5'
                      : 'border-red-500/20 bg-red-500/5'
                  }`}>
                    <div className="flex items-center gap-2 mb-1">
                      {spoofIntel.recommendation === 'spoof_target' ? (
                        <ShieldCheck className="w-4 h-4 text-green-400" />
                      ) : spoofIntel.recommendation === 'spoof_possible' ? (
                        <ShieldAlert className="w-4 h-4 text-yellow-400" />
                      ) : (
                        <ShieldAlert className="w-4 h-4 text-red-400" />
                      )}
                      <span className="font-display text-xs tracking-wider">
                        {spoofIntel.recommendation === 'spoof_target'
                          ? 'RECOMMENDED: SPOOF TARGET DOMAIN'
                          : spoofIntel.recommendation === 'spoof_possible'
                          ? 'SPOOFING MAY WORK — PREPARE FALLBACK'
                          : 'RECOMMENDED: USE ALTERNATE DOMAIN'}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground">{spoofIntel.rationale}</p>
                  </div>

                  {spoofIntel.availableTyposquats.length > 0 && (
                    <div className="border border-border bg-background p-3">
                      <span className="text-[10px] font-display tracking-wider text-muted-foreground">
                        {spoofIntel.recommendation === 'spoof_target' ? 'FALLBACK TYPOSQUAT DOMAINS' : 'RECOMMENDED ALTERNATE DOMAINS'}
                      </span>
                      <div className="mt-1.5 space-y-1">
                        {spoofIntel.availableTyposquats.map((t: any, i: number) => (
                          <div key={i} className="flex items-center justify-between text-xs">
                            <span className="font-mono text-primary">{t.permutedDomain}</span>
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-muted-foreground">{t.permutationType}</span>
                              <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                                t.status === 'purchased' || t.status === 'configured' || t.status === 'in_use'
                                  ? 'bg-green-500/20 text-green-400'
                                  : t.isRegistered
                                  ? 'bg-red-500/20 text-red-400'
                                  : 'bg-blue-500/20 text-blue-400'
                              }`}>
                                {t.status === 'purchased' || t.status === 'configured' || t.status === 'in_use'
                                  ? t.status.toUpperCase()
                                  : t.isRegistered ? 'TAKEN' : 'AVAILABLE'}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                      <p className="text-[10px] text-muted-foreground mt-2">
                        {spoofIntel.recommendation === 'spoof_target'
                          ? 'These domains are available as fallback if direct spoofing is detected.'
                          : 'Register one of the available domains and configure an SMTP sending profile to use it.'}
                      </p>
                    </div>
                  )}
                </div>
              )}

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
                    <p className="text-xs mt-1">Create an SMTP profile in the phishing platform first.</p>
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
                      <p>No landing pages found in the phishing platform.</p>
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
                  <p className="text-xs text-muted-foreground mt-1">The URL where the landing page will be hosted (phishing platform listener)</p>
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
                    {spoofIntel && (
                      <div>
                        <span className="text-xs text-muted-foreground">Domain Strategy</span>
                        <p className={`font-medium text-sm ${
                          spoofIntel.recommendation === 'spoof_target' ? 'text-green-400' :
                          spoofIntel.recommendation === 'spoof_possible' ? 'text-yellow-400' : 'text-red-400'
                        }`}>
                          {spoofIntel.recommendation === 'spoof_target' ? `Spoof ${spoofIntel.targetDomain}` :
                           spoofIntel.recommendation === 'spoof_possible' ? 'Spoof (with fallback)' : 'Use alternate domain'}
                        </p>
                      </div>
                    )}
                    {roeStatus?.hasRoe && (
                      <div>
                        <span className="text-xs text-muted-foreground">ROE Status</span>
                        <p className={`font-medium text-sm ${
                          socialEngAllowed ? 'text-green-400' : 'text-red-400'
                        }`}>
                          {socialEngAllowed ? 'Social Eng. Authorized' : 'NOT Authorized'}
                        </p>
                      </div>
                    )}
                  </div>
                </div>

                {/* Attack Template Summary */}
                {selectedAttackTemplateId && (
                  <AttackTemplateSummary templateId={selectedAttackTemplateId} />
                )}

                {/* Warning */}
                <div className="flex items-start gap-3 p-3 border border-yellow-500/30 bg-yellow-500/5 text-sm">
                  <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-medium text-yellow-400">Ready to Launch</p>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      This will create and launch a live phishing campaign in the phishing platform. Emails will be sent to all targets in the selected group.
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
    </AppShell>
  );
}

function OsintFindingsPanel({ engagementId, domain }: { engagementId: number; domain: string }) {
  const [, navigate] = useLocation();
  const { data: recons } = trpc.osint.getRecon.useQuery(
    { engagementId },
    { enabled: !!engagementId }
  );
  const { data: typosquats } = trpc.osint.getTyposquats.useQuery(
    { engagementId },
    { enabled: !!engagementId }
  );
  const { data: findings } = trpc.osint.getFindings.useQuery(
    { engagementId },
    { enabled: !!engagementId }
  );

  // Get the latest recon for this domain
  const latestRecon = Array.isArray(recons) ? recons[0] : null;
  const typosquatList = typosquats || [];
  const findingsList = findings || [];

  if (!latestRecon) {
    return (
      <div className="mt-6 border border-dashed border-primary/30 bg-primary/5 p-4">
        <div className="flex items-center gap-3 mb-2">
          <Radar className="w-5 h-5 text-primary" />
          <h3 className="font-display text-sm tracking-wider">OSINT RECONNAISSANCE</h3>
        </div>
        <p className="text-sm text-muted-foreground mb-3">
          No recon data found for <span className="font-mono text-primary">{domain}</span>. Run a domain scan to discover email security posture, typosquat candidates, and auto-generate campaign suggestions.
        </p>
        <Button
          size="sm"
          onClick={() => navigate(`/engagements/${engagementId}/recon`)}
          className="font-display tracking-wider text-xs"
        >
          <Radar className="w-3.5 h-3.5 mr-1.5" /> RUN DOMAIN RECON
        </Button>
      </div>
    );
  }

  const spoofScore = latestRecon.spoofScore || 0;
  const spoofColor = spoofScore >= 70 ? "text-red-400" : spoofScore >= 40 ? "text-yellow-400" : "text-green-400";
  const spoofLabel = spoofScore >= 70 ? "HIGH RISK" : spoofScore >= 40 ? "MODERATE" : "LOW RISK";
  const topTyposquats = typosquatList.filter((t: any) => t.available).slice(0, 5);
  const aiCampaigns = findingsList.filter((f: any) => f.category === 'campaign_suggestion');

  return (
    <div className="mt-6 border border-primary/30 bg-card p-4 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Radar className="w-5 h-5 text-primary" />
          <div>
            <h3 className="font-display text-sm tracking-wider">OSINT INTEL FOR {domain.toUpperCase()}</h3>
            <p className="text-[10px] text-muted-foreground">Last scanned {new Date(latestRecon.createdAt).toLocaleDateString()}</p>
          </div>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => navigate(`/engagements/${engagementId}/recon`)}
          className="font-display tracking-wider text-[10px] h-7"
        >
          FULL RECON
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {/* Spoofability */}
        <div className="bg-background border border-border p-3">
          <div className="flex items-center gap-2 mb-1">
            {spoofScore >= 70 ? <ShieldAlert className="w-4 h-4 text-red-400" /> : <ShieldCheck className="w-4 h-4 text-green-400" />}
            <span className="text-[10px] font-display tracking-wider text-muted-foreground">SPOOFABILITY</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-2xl font-display ${spoofColor}`}>{spoofScore}%</span>
            <span className={`text-[10px] font-display ${spoofColor}`}>{spoofLabel}</span>
          </div>
          <div className="flex gap-1 mt-1.5">
            <span className={`text-[9px] px-1.5 py-0.5 rounded ${latestRecon.spfRecord ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
              SPF {latestRecon.spfRecord ? 'YES' : 'NO'}
            </span>
            <span className={`text-[9px] px-1.5 py-0.5 rounded ${latestRecon.dmarcRecord ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
              DMARC {latestRecon.dmarcRecord ? 'YES' : 'NO'}
            </span>
          </div>
        </div>

        {/* Typosquats */}
        <div className="bg-background border border-border p-3">
          <span className="text-[10px] font-display tracking-wider text-muted-foreground">AVAILABLE TYPOSQUATS</span>
          <p className="text-2xl font-display text-primary">{topTyposquats.length}</p>
          {topTyposquats.length > 0 && (
            <div className="mt-1 space-y-0.5">
              {topTyposquats.slice(0, 3).map((t: any, i: number) => (
                <p key={i} className="text-[10px] font-mono text-muted-foreground truncate">{t.domain}</p>
              ))}
            </div>
          )}
        </div>

        {/* AI Suggestions */}
        <div className="bg-background border border-border p-3">
          <span className="text-[10px] font-display tracking-wider text-muted-foreground">AI CAMPAIGN DESIGNS</span>
          <p className="text-2xl font-display text-primary">{aiCampaigns.length}</p>
          {aiCampaigns.length > 0 && (
            <div className="mt-1 space-y-0.5">
              {aiCampaigns.slice(0, 2).map((f: any, i: number) => (
                <p key={i} className="text-[10px] text-muted-foreground truncate">{f.title}</p>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


function AttackTemplateSummary({ templateId }: { templateId: number }) {
  const { data: template } = trpc.threatIntelTraining.getTemplate.useQuery({ id: templateId });
  if (!template) return null;

  const phases: any[] = (() => {
    try {
      return typeof template.phases === "string" ? JSON.parse(template.phases as string) : (template.phases as any[]) || [];
    } catch { return []; }
  })();

  const totalTechniques = phases.reduce((sum: number, p: any) => sum + (Array.isArray(p.techniques) ? p.techniques.length : 0), 0);
  const tactics = Array.from(new Set(phases.map((p: any) => p.tactic).filter(Boolean)));

  return (
    <div className="border border-purple-500/30 bg-purple-500/5 p-4 space-y-2">
      <div className="flex items-center gap-2">
        <Brain className="w-4 h-4 text-purple-400" />
        <h3 className="font-display text-sm tracking-wider text-purple-400">ATTACK TEMPLATE WILL BE APPLIED</h3>
      </div>
      <p className="text-sm font-medium">{template.name}</p>
      <div className="flex flex-wrap gap-2 text-xs">
        <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded">
          {totalTechniques} techniques
        </span>
        <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded">
          {phases.length} phases
        </span>
        {tactics.map((t: string) => (
          <span key={t} className="px-2 py-0.5 bg-secondary text-muted-foreground rounded">
            {t.replace(/-/g, " ").toUpperCase()}
          </span>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        After launch, {totalTechniques} MITRE ATT&CK abilities will be auto-populated into an internal campaign for adversary emulation tracking.
      </p>
    </div>
  );
}

function AttackTemplatePicker({ selectedAttackTemplateId, onSelectTemplate }: {
  selectedAttackTemplateId: number | null;
  onSelectTemplate: (id: number | null) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  const { data: templates } = trpc.threatIntelTraining.listTemplates.useQuery(
    { limit: 10, offset: 0, status: "production" },
    { enabled: expanded }
  );

  const selectedTemplate = templates?.templates?.find((t: any) => t.id === selectedAttackTemplateId);

  const phases = (() => {
    if (!selectedTemplate) return [];
    try {
      return typeof selectedTemplate.phases === "string"
        ? JSON.parse(selectedTemplate.phases)
        : selectedTemplate.phases || [];
    } catch { return []; }
  })();

  return (
    <div className="mt-6 border border-dashed border-purple-500/30 bg-purple-500/5 p-4">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between"
      >
        <div className="flex items-center gap-3">
          <Brain className="w-5 h-5 text-purple-400" />
          <div className="text-left">
            <h3 className="font-display text-sm tracking-wider">ATTACK TEMPLATE LIBRARY</h3>
            <p className="text-xs text-muted-foreground">
              Optionally select a real-world attack sequence template to guide campaign design
            </p>
          </div>
        </div>
        {expanded ? <ChevronLeft className="w-4 h-4 text-muted-foreground rotate-90" /> : <ChevronRight className="w-4 h-4 text-muted-foreground rotate-90" />}
      </button>

      {expanded && (
        <div className="mt-4 space-y-3">
          {templates?.templates && templates.templates.length > 0 ? (
            <>
              <div className="grid gap-2 max-h-[300px] overflow-y-auto pr-1">
                {templates.templates.map((template: any) => {
                  const isSelected = selectedAttackTemplateId === template.id;
                  const tPhases = (() => {
                    try {
                      return typeof template.phases === "string"
                        ? JSON.parse(template.phases)
                        : template.phases || [];
                    } catch { return []; }
                  })();
                  return (
                    <button
                      key={template.id}
                      onClick={() => onSelectTemplate(isSelected ? null : template.id)}
                      className={`w-full text-left p-3 border transition-all ${
                        isSelected
                          ? "border-purple-500 bg-purple-500/10 ring-1 ring-purple-500/30"
                          : "border-border hover:border-purple-500/50"
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-display text-xs tracking-wider truncate">{template.name}</span>
                        <div className="flex gap-1">
                          {template.attackType && (
                            <span className="text-[9px] px-1.5 py-0.5 bg-purple-500/20 text-purple-400 rounded">
                              {template.attackType.replace(/_/g, " ").toUpperCase()}
                            </span>
                          )}
                          {template.complexity && (
                            <span className="text-[9px] px-1.5 py-0.5 bg-secondary text-muted-foreground rounded">
                              {(template.complexity || '').toUpperCase()}
                            </span>
                          )}
                        </div>
                      </div>
                      <p className="text-[10px] text-muted-foreground truncate">{template.description}</p>
                      <div className="flex gap-2 mt-1 text-[10px] text-muted-foreground">
                        <span>{tPhases.length} phases</span>
                        {template.targetEnvironment && <span>• {template.targetEnvironment}</span>}
                        {template.successRate && <span>• {Math.round(Number(template.successRate) * 100)}% success</span>}
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Selected template detail */}
              {selectedTemplate && phases.length > 0 && (
                <div className="bg-card border border-purple-500/30 p-3">
                  <h4 className="font-display text-xs tracking-wider text-purple-400 mb-2">
                    ATTACK PHASES — {selectedTemplate.name}
                  </h4>
                  <div className="space-y-1.5">
                    {phases.map((phase: any, i: number) => (
                      <div key={i} className="flex items-start gap-2 text-xs">
                        <span className="w-5 h-5 flex items-center justify-center rounded-full bg-purple-500/20 text-purple-400 text-[10px] font-display shrink-0">
                          {i + 1}
                        </span>
                        <div>
                          <span className="font-display text-[10px] tracking-wider">
                            {phase.tactic?.toUpperCase() || `PHASE ${i + 1}`}
                          </span>
                          {phase.technique && (
                            <span className="ml-2 font-mono text-[10px] text-muted-foreground">{phase.technique}</span>
                          )}
                          {phase.description && (
                            <p className="text-[10px] text-muted-foreground">{phase.description}</p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                  {Boolean(selectedTemplate.commonDetections) && (
                    <div className="mt-2 pt-2 border-t border-border">
                      <span className="text-[10px] font-display text-yellow-400">COMMON DETECTIONS: </span>
                      <span className="text-[10px] text-muted-foreground">
                        {(() => {
                          try {
                            const raw = selectedTemplate.commonDetections as any;
                            const dets = typeof raw === "string" ? JSON.parse(raw) : raw;
                            return Array.isArray(dets) ? dets.join(", ") : "—";
                          } catch { return "—"; }
                        })()}
                      </span>
                    </div>
                  )}
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-6 text-muted-foreground">
              <Brain className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No production-ready attack templates available yet</p>
              <p className="text-xs mt-1">Process threat intel reports in the Training Dashboard to generate templates</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
