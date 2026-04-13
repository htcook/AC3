// @ts-nocheck
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import {
  Activity, Key, Target, Cpu, Zap, Users, FileText, Cloud, BookOpen,
  Shield, Globe2, LogOut, Menu, X, Plus, Briefcase, Calendar, MapPin,
  MoreVertical, Pencil, Trash2, ChevronRight, Search, Filter, Rocket,
  Send, Link2, Unlink, ExternalLink, Fish, Eye, BarChart3, Radar,
  Play, Pause, CheckCircle, Clock, Crosshair, AlertTriangle, RefreshCw,
  Bug, Skull, ChevronDown, ChevronUp
} from "lucide-react";
import { useState, useMemo, useEffect } from "react";
import { Scan, ShieldAlert, ShieldCheck } from "lucide-react";

import AppShell from "@/components/AppShell";
import ShareLinkManager from "@/components/ShareLinkManager";
import ROEPanel from "@/components/ROEPanel";
import { Scale } from "lucide-react";

import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
const ENGAGEMENT_TYPES = [
  { value: 'red_team', label: 'Red Team', color: 'text-red-400 bg-red-500/10' },
  { value: 'phishing', label: 'Phishing', color: 'text-yellow-400 bg-yellow-500/10' },
  { value: 'pentest', label: 'Pentest', color: 'text-blue-400 bg-blue-500/10' },
  { value: 'purple_team', label: 'Purple Team', color: 'text-purple-400 bg-purple-500/10' },
  { value: 'tabletop', label: 'Tabletop', color: 'text-green-400 bg-green-500/10' },
] as const;

const STATUS_OPTIONS = [
  { value: 'planning', label: 'Planning', color: 'text-gray-400 bg-gray-500/10' },
  { value: 'active', label: 'Active', color: 'text-green-400 bg-green-500/10' },
  { value: 'paused', label: 'Paused', color: 'text-yellow-400 bg-yellow-500/10' },
  { value: 'completed', label: 'Completed', color: 'text-blue-400 bg-blue-500/10' },
  { value: 'archived', label: 'Archived', color: 'text-gray-500 bg-gray-600/10' },
] as const;

// Engagement workflow phases — external attack vectors BEFORE phishing
const WORKFLOW_PHASES = [
  { id: 1, label: 'OSINT & Recon', icon: Radar, description: 'Domain intel, passive recon, asset discovery' },
  { id: 2, label: 'External Attack Surface', icon: Bug, description: 'Exploit external-facing vulns (RCE, auth bypass, SSRF)' },
  { id: 3, label: 'emulation framework Operations', icon: Crosshair, description: 'Deploy exploit abilities, run red team operations' },
  { id: 4, label: 'Phishing Campaign', icon: Fish, description: 'Social engineering if external access not achieved' },
  { id: 5, label: 'Post-Exploitation', icon: Skull, description: 'Lateral movement, persistence, data exfiltration' },
  { id: 6, label: 'Reporting', icon: FileText, description: 'Generate engagement report with findings' },
];

const OP_STATUS_STYLES: Record<string, { bg: string; text: string; icon: React.ReactNode }> = {
  paused: { bg: 'bg-yellow-500/20 border-yellow-500', text: 'text-yellow-400', icon: <Pause className="w-4 h-4" /> },
  running: { bg: 'bg-green-500/20 border-green-500', text: 'text-green-400', icon: <Play className="w-4 h-4" /> },
  finished: { bg: 'bg-blue-500/20 border-blue-500', text: 'text-blue-400', icon: <CheckCircle className="w-4 h-4" /> },
  cleanup: { bg: 'bg-orange-500/20 border-orange-500', text: 'text-orange-400', icon: <AlertTriangle className="w-4 h-4" /> },
};

type EngagementType = typeof ENGAGEMENT_TYPES[number]['value'];
type StatusType = typeof STATUS_OPTIONS[number]['value'];

export default function Engagements() {
  const [, navigate] = useLocation();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [activeTab, setActiveTab] = useState<'engagements' | 'operations'>('engagements');

  // Auto-populate from Domain Intel scan
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const fromIntel = params.get('fromIntel');
    if (fromIntel) {
      fetch(`/api/trpc/domainIntel.getScan?input=${encodeURIComponent(JSON.stringify({ json: { id: Number(fromIntel) } }))}`, { credentials: 'include' })
        .then(r => r.json())
        .then((res: any) => {
          const scan = res?.result?.data?.json?.scan || res?.result?.data?.scan;
          if (scan) {
            const customerName = scan.customerName || scan.orgProfile?.customerName || '';
            setFormData(prev => ({
              ...prev,
              name: `${customerName || scan.primaryDomain} - Intel-Driven Engagement`,
              customerName: customerName,
              targetDomain: scan.primaryDomain || '',
              description: `Auto-generated from Domain Intel scan. Risk: ${scan.overallRiskBand || 'Unknown'} (${scan.overallRiskScore || 0}/100). ${scan.totalAssets || 0} assets discovered.`,
              engagementType: 'red_team' as EngagementType,
            }));
            setShowCreateForm(true);
          }
        })
        .catch((err) => {
          console.error('[Engagements] Failed to fetch scan for fromIntel:', err);
        });
    }
  }, []);

  const [editingId, setEditingId] = useState<number | null>(null);
  const [showTemplateSelector, setShowTemplateSelector] = useState(false);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [bulkMode, setBulkMode] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    customerName: '',
    description: '',
    engagementType: 'red_team' as EngagementType,
    status: 'planning' as StatusType,
    targetDomain: '',
    targetIpRange: '',
    phishingDomain: '',
    notes: '',
    roeDocumentId: undefined as number | null,
  });

  // RoE documents for the selector dropdown
  const { data: roeDocuments } = trpc.roeBuilder.list.useQuery();

  // Engagement templates
  const { data: templates } = trpc.engagements.listTemplates.useQuery();

  // Engagement data
  const { data: engagements, refetch } = trpc.engagements.list.useQuery();
  const { data: allCampaignLinks, refetch: refetchLinks } = trpc.campaignEngagements.listAll.useQuery();
  const { data: gophishCampaigns } = trpc.gophishProxy.getCampaigns.useQuery(undefined, {
    staleTime: 60_000, // Cache for 60s to avoid re-fetching on every navigation
    refetchOnWindowFocus: false,
  });

  // Live ops status for all engagements (polls every 5s if any are running)
  const engagementIds = useMemo(() => (engagements || []).map((e: any) => e.id), [engagements]);
  const { data: liveOpsStatus } = trpc.engagementOps.batchGetLiveStatus.useQuery(
    { engagementIds },
    {
      enabled: engagementIds.length > 0,
      refetchInterval: (query: any) => {
        const data = query?.state?.data;
        return Object.values(data || {}).some((s: any) => s?.isRunning) ? 5000 : 30000;
      },
    }
  );

  // adversary operations data
  const { data: operations, isLoading: opsLoading, refetch: refetchOps, isRefetching } = trpc.calderaProxy.getOperations.useQuery(undefined, {
    staleTime: 60_000, // Cache for 60s — Caldera API can be slow/unreachable
    refetchOnWindowFocus: false,
  });
  const { data: allAbilities } = trpc.calderaProxy.getAbilities.useQuery(undefined, {
    staleTime: 120_000, // Cache abilities for 2min — they rarely change
    refetchOnWindowFocus: false,
  });

  const abilityMap = useMemo(() => {
    if (!allAbilities) return new Map();
    return new Map(allAbilities.map((a: any) => [a.ability_id, a]));
  }, [allAbilities]);

  const enrichedOperations = useMemo(() => {
    if (!operations) return [];
    return operations.map((op: any) => {
      const abilities = op.adversary?.atomic_ordering || [];
      return {
        ...op,
        description: op.adversary?.description || 'Red team operation',
        abilityCount: abilities.length,
      };
    });
  }, [operations]);

  const unlinkMutation = trpc.campaignEngagements.unlink.useMutation({
    onSuccess: () => { toast.success('Campaign unlinked'); refetchLinks(); },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });
  const linkMutation = trpc.campaignEngagements.link.useMutation({
    onSuccess: () => { toast.success('Campaign linked'); refetchLinks(); },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });
  const [expandedEngagement, setExpandedEngagement] = useState<number | null>(null);
  const [linkingEngagementId, setLinkingEngagementId] = useState<number | null>(null);
  const [selectedCampaignToLink, setSelectedCampaignToLink] = useState<number | null>(null);
  const [showTrainingLabDialog, setShowTrainingLabDialog] = useState(false);
  const [trainingLabTarget, setTrainingLabTarget] = useState('demo.testfire.net');
  const [trainingLabScanMode, setTrainingLabScanMode] = useState<'strict_passive' | 'standard' | 'active'>('active');

  const launchTrainingLabMutation = trpc.engagementAutomation.launchTrainingLab.useMutation({
    onSuccess: (data) => {
      toast.success(`Training lab launched: ${data.labProfile}`);
      setShowTrainingLabDialog(false);
      refetch();
      // Navigate to the engagement ops page
      navigate(`/engagements/${data.engagementId}/ops`);
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err.message)),
  });

  const createMutation = trpc.engagements.create.useMutation({
    onSuccess: () => {
      toast.success('Engagement created');
      setShowCreateForm(false);
      setShowTemplateSelector(false);
      setSelectedTemplateId(null);
      resetForm();
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const createFromTemplateMutation = trpc.engagements.createFromTemplate.useMutation({
    onSuccess: (result) => {
      toast.success(`Engagement created from template! RoE auto-generated.`);
      setShowCreateForm(false);
      setShowTemplateSelector(false);
      setSelectedTemplateId(null);
      resetForm();
      refetch();
      // Navigate to the new engagement ops page
      navigate(`/engagement-ops/${result.id}`);
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const updateMutation = trpc.engagements.update.useMutation({
    onSuccess: () => {
      toast.success('Engagement updated');
      setEditingId(null);
      resetForm();
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const deleteMutation = trpc.engagements.delete.useMutation({
    onSuccess: () => {
      toast.success('Engagement deleted');
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const bulkDeleteMutation = trpc.engagements.bulkDelete.useMutation({
    onSuccess: (data) => {
      toast.success(`Deleted ${data.deleted} engagement(s) and related records`);
      setSelectedIds(new Set());
      setBulkMode(false);
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const resetMutation = trpc.engagements.resetEngagement.useMutation({
    onSuccess: (data) => {
      const c = data.cleared;
      toast.success(`Engagement reset — cleared ${c.scanResults ?? 0} scans, ${c.timelineEvents ?? 0} events, ${c.opsSnapshots ?? 0} snapshots, ${c.testPlans ?? 0} test plans`);
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const bulkResetMutation = trpc.engagements.bulkResetEngagements.useMutation({
    onSuccess: (data) => {
      toast.success(`Reset ${data.results.length} engagement(s) for fresh rerun`);
      setSelectedIds(new Set());
      setBulkMode(false);
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  function toggleSelect(id: number) {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function selectAllFiltered() {
    setSelectedIds(new Set(filteredEngagements.map((e: any) => e.id)));
  }

  function deselectAll() {
    setSelectedIds(new Set());
  }

  function handleBulkDelete() {
    const count = selectedIds.size;
    if (count === 0) return;
    if (confirm(`Delete ${count} engagement(s) and all their related reports and campaign links? This cannot be undone.`)) {
      bulkDeleteMutation.mutate({ ids: Array.from(selectedIds) });
    }
  }

  function handleBulkReset() {
    const count = selectedIds.size;
    if (count === 0) return;
    if (confirm(`Reset ${count} engagement(s) for a fresh rerun? This will clear all scan results, timeline events, ops snapshots, and test plans.`)) {
      bulkResetMutation.mutate({ ids: Array.from(selectedIds) });
    }
  }

  function resetForm() {
    setFormData({
      name: '', customerName: '', description: '',
      engagementType: 'red_team', status: 'planning',
      targetDomain: '', targetIpRange: '', phishingDomain: '', notes: '',
      roeDocumentId: undefined,
    });
    setSelectedTemplateId(null);
  }

  function applyTemplate(templateId: string) {
    const tmpl = templates?.find((t: any) => t.id === templateId);
    if (!tmpl) return;
    setSelectedTemplateId(templateId);
    setFormData(prev => ({
      ...prev,
      engagementType: tmpl.engagementType as EngagementType,
      description: tmpl.description,
    }));
    setShowTemplateSelector(false);
    setShowCreateForm(true);
  }

  function handleTemplateSubmit() {
    if (!selectedTemplateId || !formData.name || !formData.customerName) {
      toast.error('Name and customer name are required');
      return;
    }
    createFromTemplateMutation.mutate({
      templateId: selectedTemplateId,
      name: formData.name,
      customerName: formData.customerName,
      targetDomain: formData.targetDomain || undefined,
      targetIpRange: formData.targetIpRange || undefined,
      phishingDomain: formData.phishingDomain || undefined,
      notes: formData.notes || undefined,
    });
  }

  function handleEdit(engagement: any) {
    setEditingId(engagement.id);
    setFormData({
      name: engagement.name || '',
      customerName: engagement.customerName || '',
      description: engagement.description || '',
      engagementType: engagement.engagementType || 'red_team',
      status: engagement.status || 'planning',
      targetDomain: engagement.targetDomain || '',
      targetIpRange: engagement.targetIpRange || '',
      phishingDomain: engagement.phishingDomain || '',
      notes: engagement.notes || '',
      roeDocumentId: engagement.roeDocumentId || null,
    });
    setShowCreateForm(true);
  }

  function handleSubmit() {
    if (!formData.name || !formData.customerName) {
      toast.error('Name and customer name are required');
      return;
    }
    // Enforce: at least one target domain or IP range required
    if (!editingId && !formData.targetDomain && !formData.targetIpRange) {
      toast.error('At least one target domain or IP range is required to create an engagement.');
      return;
    }
    if (editingId) {
      updateMutation.mutate({ id: editingId, ...formData });
    } else {
      if (!formData.roeDocumentId) {
        toast.info('A Rules of Engagement document will be auto-created with your target scope. Review it in the RoE Builder.', { duration: 5000 });
      }
      createMutation.mutate(formData);
    }
  }

  const filteredEngagements = useMemo(() => {
    if (!engagements) return [];
    return engagements.filter((e: any) => {
      const matchesSearch = searchQuery === '' ||
        (e.name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        (e.customerName || '').toLowerCase().includes(searchQuery.toLowerCase());
      const matchesType = filterType === 'all' || e.engagementType === filterType;
      const matchesStatus = filterStatus === 'all' || e.status === filterStatus;
      return matchesSearch && matchesType && matchesStatus;
    });
  }, [engagements, searchQuery, filterType, filterStatus]);

  const getTypeConfig = (type: string) => ENGAGEMENT_TYPES.find(t => t.value === type) || ENGAGEMENT_TYPES[0];
  const getStatusConfig = (status: string) => STATUS_OPTIONS.find(s => s.value === status) || STATUS_OPTIONS[0];

  return (
    <AppShell activePath="/engagements">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-6 sm:mb-8">
        <div>
          <h1 className="font-display text-2xl sm:text-3xl tracking-wider">ENGAGEMENT MANAGER</h1>
          <p className="text-muted-foreground text-xs sm:text-sm mt-1">
            Manage engagements, adversary operations, and campaign execution
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={() => { setShowTemplateSelector(true); setShowCreateForm(false); setEditingId(null); resetForm(); setActiveTab('engagements'); }}
            className="font-display tracking-wider"
            size="sm"
          >
            <Plus className="w-4 h-4 mr-2" />
            NEW ENGAGEMENT
          </Button>
          <Button
            variant="outline"
            onClick={() => { setShowCreateForm(true); setShowTemplateSelector(false); setEditingId(null); resetForm(); setActiveTab('engagements'); }}
            className="font-display tracking-wider"
            size="sm"
          >
            <FileText className="w-4 h-4 mr-2" />
            BLANK
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="font-display tracking-wider"
            onClick={() => window.open('https://caldera.aceofcloud.io', '_blank')}
          >
            <ExternalLink className="w-4 h-4 mr-2" />
            EMULATION UI
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="font-display tracking-wider text-emerald-400 border-emerald-500/40 hover:bg-emerald-500/10"
            onClick={() => window.location.href = '/engagements/upload'}
          >
            <FileText className="w-4 h-4 mr-2" />
            UPLOAD ROE
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="font-display tracking-wider text-amber-400 border-amber-500/40 hover:bg-amber-500/10"
            onClick={() => setShowTrainingLabDialog(true)}
          >
            <Target className="w-4 h-4 mr-2" />
            TRAINING LAB
          </Button>
        </div>
      </div>

      {/* Workflow Phases Banner */}
      <div className="bg-card border border-border p-4 mb-6 overflow-x-auto">
        <p className="text-[10px] text-muted-foreground tracking-wider mb-3 uppercase">Engagement Workflow — External Attack Vectors Before Phishing</p>
        <div className="flex items-center gap-1 min-w-max">
          {WORKFLOW_PHASES.map((phase, i) => (
            <div key={phase.id} className="flex items-center gap-1">
              <div className="flex items-center gap-2 px-3 py-2 bg-background border border-border hover:border-primary/50 transition-colors group cursor-default">
                <phase.icon className="w-4 h-4 text-primary shrink-0" />
                <div>
                  <p className="text-xs font-display tracking-wider whitespace-nowrap">{phase.label}</p>
                  <p className="text-[9px] text-muted-foreground whitespace-nowrap hidden group-hover:block">{phase.description}</p>
                </div>
              </div>
              {i < WORKFLOW_PHASES.length - 1 && (
                <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Tab Switcher */}
      <div className="flex gap-0 mb-6 border-b border-border">
        <button
          onClick={() => setActiveTab('engagements')}
          className={`px-6 py-3 font-display tracking-wider text-sm border-b-2 transition-colors ${
            activeTab === 'engagements'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
        >
          <Briefcase className="w-4 h-4 inline mr-2" />
          ENGAGEMENTS ({engagements?.length || 0})
        </button>
        <button
          onClick={() => setActiveTab('operations')}
          className={`px-6 py-3 font-display tracking-wider text-sm border-b-2 transition-colors ${
            activeTab === 'operations'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
        >
          <Crosshair className="w-4 h-4 inline mr-2" />
          EMULATION OPERATIONS ({enrichedOperations.length})
        </button>
      </div>

      {/* ===== ENGAGEMENTS TAB ===== */}
      {activeTab === 'engagements' && (
        <>
          {/* Filters */}
          <div className="flex flex-wrap gap-4 mb-6">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search engagements..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-card border border-border text-sm focus:outline-none focus:border-primary"
              />
            </div>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="bg-card border border-border px-3 py-2 text-sm focus:outline-none focus:border-primary"
            >
              <option value="all">All Types</option>
              {ENGAGEMENT_TYPES.map(t => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-card border border-border px-3 py-2 text-sm focus:outline-none focus:border-primary"
            >
              <option value="all">All Statuses</option>
              {STATUS_OPTIONS.map(s => (
                <option key={s.value} value={s.value}>{s.label}</option>
              ))}
            </select>
          </div>

          {/* Template Selector */}
          {showTemplateSelector && !showCreateForm && (
            <div className="bg-card border border-border p-6 mb-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="font-display text-lg tracking-wider">SELECT ENGAGEMENT TEMPLATE</h2>
                  <p className="text-xs text-muted-foreground mt-1">Choose a pre-configured profile to auto-fill RoE, scan configs, and phase settings</p>
                </div>
                <Button variant="ghost" size="sm" onClick={() => setShowTemplateSelector(false)}>
                  <X className="w-4 h-4" />
                </Button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {templates?.map((tmpl: any) => {
                  const iconMap: Record<string, any> = {
                    globe: Globe2, network: Activity, skull: Skull, fish: Fish,
                    cloud: Cloud, shield: Shield, clipboard: FileText,
                  };
                  const Icon = iconMap[tmpl.icon] || Target;
                  const difficultyColors: Record<string, string> = {
                    beginner: 'text-green-400 bg-green-500/10',
                    intermediate: 'text-yellow-400 bg-yellow-500/10',
                    advanced: 'text-orange-400 bg-orange-500/10',
                    expert: 'text-red-400 bg-red-500/10',
                  };
                  const categoryColors: Record<string, string> = {
                    pentest: 'border-blue-500/30 hover:border-blue-500/60',
                    red_team: 'border-red-500/30 hover:border-red-500/60',
                    phishing: 'border-yellow-500/30 hover:border-yellow-500/60',
                    purple_team: 'border-purple-500/30 hover:border-purple-500/60',
                    tabletop: 'border-green-500/30 hover:border-green-500/60',
                  };
                  return (
                    <button
                      key={tmpl.id}
                      onClick={() => applyTemplate(tmpl.id)}
                      className={`text-left p-4 bg-background border ${categoryColors[tmpl.category] || 'border-border'} hover:bg-muted/50 transition-all group`}
                    >
                      <div className="flex items-start gap-3">
                        <div className="p-2 bg-primary/10 text-primary">
                          <Icon className="w-5 h-5" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="font-display text-sm tracking-wider group-hover:text-primary transition-colors">{tmpl.shortName}</p>
                          <p className="text-[10px] text-muted-foreground mt-1 line-clamp-2">{tmpl.description}</p>
                          <div className="flex flex-wrap gap-1.5 mt-2">
                            <span className={`text-[9px] px-1.5 py-0.5 ${difficultyColors[tmpl.difficulty] || ''}`}>
                              {(tmpl.difficulty || '').toUpperCase()}
                            </span>
                            <span className="text-[9px] px-1.5 py-0.5 text-muted-foreground bg-muted">
                              {tmpl.estimatedDuration}
                            </span>
                            <span className="text-[9px] px-1.5 py-0.5 text-muted-foreground bg-muted">
                              {tmpl.teamSize}
                            </span>
                          </div>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Create/Edit Form */}
          {showCreateForm && (
            <div className="bg-card border border-border p-6 mb-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="font-display text-lg tracking-wider">
                    {editingId ? 'EDIT ENGAGEMENT' : selectedTemplateId ? `NEW ENGAGEMENT — ${templates?.find((t: any) => t.id === selectedTemplateId)?.shortName?.toUpperCase() || 'TEMPLATE'}` : 'NEW ENGAGEMENT'}
                  </h2>
                  {selectedTemplateId && (
                    <p className="text-xs text-emerald-400 mt-1">Template applied — RoE, scan config, and phase settings will be auto-configured</p>
                  )}
                </div>
                {selectedTemplateId && !editingId && (
                  <Button variant="ghost" size="sm" onClick={() => { setSelectedTemplateId(null); }}>
                    <X className="w-3.5 h-3.5 mr-1" /> CLEAR TEMPLATE
                  </Button>
                )}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1">ENGAGEMENT NAME *</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData(p => ({ ...p, name: e.target.value }))}
                    placeholder="e.g., Q1 2026 Red Team Assessment"
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1">CUSTOMER NAME *</label>
                  <input
                    type="text"
                    value={formData.customerName}
                    onChange={(e) => setFormData(p => ({ ...p, customerName: e.target.value }))}
                    placeholder="e.g., Acme Corp"
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1">TYPE</label>
                  <select
                    value={formData.engagementType}
                    onChange={(e) => setFormData(p => ({ ...p, engagementType: e.target.value as EngagementType }))}
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                  >
                    {ENGAGEMENT_TYPES.map(t => (
                      <option key={t.value} value={t.value}>{t.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1">STATUS</label>
                  <select
                    value={formData.status}
                    onChange={(e) => setFormData(p => ({ ...p, status: e.target.value as StatusType }))}
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                  >
                    {STATUS_OPTIONS.map(s => (
                      <option key={s.value} value={s.value}>{s.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1">TARGET DOMAIN {!editingId && <span className="text-destructive">*</span>}</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={formData.targetDomain}
                      onChange={(e) => setFormData(p => ({ ...p, targetDomain: e.target.value }))}
                      placeholder="e.g., acmecorp.com"
                      className="flex-1 px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                    />
                    {formData.targetDomain && (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={() => navigate(`/domain-recon?domain=${encodeURIComponent(formData.targetDomain)}`)}
                        className="font-display tracking-wider text-[10px] whitespace-nowrap border-primary text-primary hover:bg-primary/10"
                      >
                        <Scan className="w-3.5 h-3.5 mr-1" /> SCAN
                      </Button>
                    )}
                  </div>
                  <p className="text-[10px] text-muted-foreground mt-1">Enter domain(s) and click SCAN to run OSINT recon. Comma-separated for multiple. {!editingId && <span className="text-amber-500">Required: at least one domain or IP range.</span>}</p>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1">TARGET IP RANGE {!editingId && <span className="text-destructive">*</span>}</label>
                  <input
                    type="text"
                    value={formData.targetIpRange}
                    onChange={(e) => setFormData(p => ({ ...p, targetIpRange: e.target.value }))}
                    placeholder="e.g., 10.0.0.0/24"
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1">PHISHING DOMAIN</label>
                  <input
                    type="text"
                    value={formData.phishingDomain}
                    onChange={(e) => setFormData(p => ({ ...p, phishingDomain: e.target.value }))}
                    placeholder="e.g., acme-secure.com"
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1">DESCRIPTION</label>
                  <textarea
                    value={formData.description}
                    onChange={(e) => setFormData(p => ({ ...p, description: e.target.value }))}
                    placeholder="Brief description of the engagement scope and objectives..."
                    rows={2}
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary resize-none"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1">NOTES</label>
                  <textarea
                    value={formData.notes}
                    onChange={(e) => setFormData(p => ({ ...p, notes: e.target.value }))}
                    placeholder="Internal notes, RoE references, contact info..."
                    rows={2}
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary resize-none"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1 flex items-center gap-1.5">
                    <Crosshair className="w-3.5 h-3.5" /> C2 FRAMEWORK
                  </label>
                  <select
                    value={(formData as any).c2Framework || 'caldera'}
                    onChange={(e) => setFormData(p => ({ ...p, c2Framework: e.target.value } as any))}
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                  >
                    <option value="caldera">Cyber C2 (Default)</option>
                    <option value="sliver">Sliver</option>
                    <option value="metasploit">Metasploit</option>
                    <option value="cobalt_strike">Cobalt Strike</option>
                  </select>
                  <p className="text-[10px] text-muted-foreground mt-1">
                    {!editingId ? (
                      <span className="text-emerald-500">A Cyber C2 operation will be auto-created. You can switch C2 frameworks after creation.</span>
                    ) : (
                      <span>Change the C2 framework for this engagement. Cyber C2 operations sync automatically.</span>
                    )}
                  </p>
                </div>
                <div className="md:col-span-2">
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1 flex items-center gap-1.5">
                    <Scale className="w-3.5 h-3.5" /> RULES OF ENGAGEMENT
                  </label>
                  <select
                    value={formData.roeDocumentId ?? ''}
                    onChange={(e) => setFormData(p => ({ ...p, roeDocumentId: e.target.value ? Number(e.target.value) : null }))}
                    className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                  >
                    <option value="">— Auto-create RoE from targets —</option>
                    {roeDocuments?.map((doc: any) => (
                      <option key={doc.id} value={doc.id}>
                        {doc.title} (v{doc.version}) — {doc.status.replace(/_/g, ' ').toUpperCase()}
                      </option>
                    ))}
                  </select>
                  <p className="text-[10px] text-muted-foreground mt-1">
                    {!editingId && !formData.roeDocumentId ? (
                      <span className="text-amber-500">A draft RoE will be auto-created with your target domains/IPs as in-scope items. Review it in the <a href="/roe-builder" className="text-primary hover:underline">RoE Builder</a> before activating.</span>
                    ) : (
                      <span>Link an existing Rules of Engagement document. <a href="/roe-builder" className="text-primary hover:underline">Create new RoE</a></span>
                    )}
                  </p>
                </div>
              </div>
              <div className="flex gap-3 mt-4">
                <Button
                  onClick={selectedTemplateId && !editingId ? handleTemplateSubmit : handleSubmit}
                  disabled={createFromTemplateMutation.isPending || createMutation.isPending}
                  className="font-display tracking-wider"
                >
                  {(createFromTemplateMutation.isPending || createMutation.isPending) ? 'CREATING...' : editingId ? 'UPDATE' : selectedTemplateId ? 'CREATE FROM TEMPLATE' : 'CREATE'} {!createFromTemplateMutation.isPending && !createMutation.isPending && 'ENGAGEMENT'}
                </Button>
                <Button
                  variant="outline"
                  onClick={() => { setShowCreateForm(false); setEditingId(null); resetForm(); }}
                  className="font-display tracking-wider"
                >
                  CANCEL
                </Button>
              </div>
            </div>
          )}

          {/* Bulk Actions Bar */}
          <div className="flex items-center gap-2 sm:gap-3 mb-4 flex-wrap">
            <Button
              variant={bulkMode ? "default" : "outline"}
              size="sm"
              onClick={() => { setBulkMode(!bulkMode); if (bulkMode) setSelectedIds(new Set()); }}
              className="font-display tracking-wider"
            >
              {bulkMode ? <X className="w-3.5 h-3.5 mr-1" /> : <Trash2 className="w-3.5 h-3.5 mr-1" />}
              {bulkMode ? 'EXIT BULK MODE' : 'BULK ACTIONS'}
            </Button>
            {bulkMode && (
              <>
                <Button variant="outline" size="sm" onClick={selectAllFiltered} className="font-display tracking-wider text-xs">
                  SELECT ALL ({filteredEngagements.length})
                </Button>
                <Button variant="outline" size="sm" onClick={deselectAll} className="font-display tracking-wider text-xs">
                  DESELECT ALL
                </Button>
                <span className="text-xs text-muted-foreground font-display tracking-wider">
                  {selectedIds.size} SELECTED
                </span>
                {selectedIds.size > 0 && (
                  <>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleBulkReset}
                      disabled={bulkResetMutation.isPending}
                      className="font-display tracking-wider text-amber-400 hover:text-amber-300 border-amber-500/50 hover:border-amber-400"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 mr-1 ${bulkResetMutation.isPending ? 'animate-spin' : ''}`} />
                      {bulkResetMutation.isPending ? 'RESETTING...' : `RESET ${selectedIds.size} SELECTED`}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleBulkDelete}
                      disabled={bulkDeleteMutation.isPending}
                      className="font-display tracking-wider text-destructive hover:text-destructive border-destructive/50 hover:border-destructive"
                    >
                      <Trash2 className="w-3.5 h-3.5 mr-1" />
                      {bulkDeleteMutation.isPending ? 'DELETING...' : `DELETE ${selectedIds.size} SELECTED`}
                    </Button>
                  </>
                )}
              </>
            )}
          </div>

          {/* Stats Summary */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 sm:gap-4 mb-6">
            {STATUS_OPTIONS.map(s => {
              const count = engagements?.filter((e: any) => e.status === s.value).length || 0;
              return (
                <div key={s.value} className="bg-card border border-border p-4">
                  <p className="text-xs text-muted-foreground tracking-wider">{(s.label || '').toUpperCase()}</p>
                  <p className="text-2xl font-display mt-1">{count}</p>
                </div>
              );
            })}
          </div>

          {/* Engagements List */}
          {filteredEngagements.length === 0 ? (
            <div className="bg-card border border-border p-12 text-center">
              <Briefcase className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-lg font-display tracking-wider mb-2">NO ENGAGEMENTS</p>
              <p className="text-sm text-muted-foreground mb-4">
                {engagements?.length === 0
                  ? 'Create your first customer engagement to get started.'
                  : 'No engagements match your current filters.'}
              </p>
              {engagements?.length === 0 && (
                <Button onClick={() => { setShowCreateForm(true); resetForm(); }} className="font-display tracking-wider">
                  <Plus className="w-4 h-4 mr-2" />
                  CREATE ENGAGEMENT
                </Button>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              {filteredEngagements.map((engagement: any) => {
                const typeConfig = getTypeConfig(engagement.engagementType);
                const statusConfig = getStatusConfig(engagement.status);
                return (
                  <div key={engagement.id} className={`bg-card border p-5 hover:border-primary/30 transition-colors group ${selectedIds.has(engagement.id) ? 'border-destructive/60 bg-destructive/5' : 'border-border'}`}>
                    <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between">
                      <div className="flex-1 min-w-0 flex items-start gap-3">
                        {bulkMode && (
                          <input
                            type="checkbox"
                            checked={selectedIds.has(engagement.id)}
                            onChange={() => toggleSelect(engagement.id)}
                            className="mt-1.5 w-4 h-4 accent-red-500 cursor-pointer shrink-0"
                          />
                        )}
                        <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 sm:gap-3 mb-2 flex-wrap">
                          <h3 className="font-display text-lg tracking-wider truncate">{engagement.name}</h3>
                          <span className={`text-xs px-2 py-0.5 ${typeConfig.color} font-display tracking-wider`}>
                            {(typeConfig.label || '').toUpperCase()}
                          </span>
                          <span className={`text-xs px-2 py-0.5 ${statusConfig.color} font-display tracking-wider`}>
                            {(statusConfig.label || '').toUpperCase()}
                          </span>
                          {/* Live ops status indicator */}
                          {(() => {
                            const ops = liveOpsStatus?.[engagement.id];
                            if (!ops) return null;
                            if (ops.isRunning) {
                              return (
                                <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 bg-green-500/20 text-green-400 font-display tracking-wider animate-pulse">
                                  <Play className="w-3 h-3" />
                                  {ops.phase.replace(/_/g, ' ').toUpperCase()} ({ops.progress}%)
                                </span>
                              );
                            }
                            if (ops.phase === 'complete' || ops.phase === 'reporting') {
                              return (
                                <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 bg-blue-500/20 text-blue-400 font-display tracking-wider">
                                  <CheckCircle className="w-3 h-3" />
                                  COMPLETE
                                </span>
                              );
                            }
                            if (ops.phase === 'error') {
                              return (
                                <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 bg-red-500/20 text-red-400 font-display tracking-wider">
                                  <AlertTriangle className="w-3 h-3" />
                                  ERROR
                                </span>
                              );
                            }
                            if (ops.assetsDiscovered > 0 || ops.vulnsFound > 0) {
                              return (
                                <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 bg-yellow-500/20 text-yellow-400 font-display tracking-wider">
                                  <Pause className="w-3 h-3" />
                                  PAUSED
                                </span>
                              );
                            }
                            return null;
                          })()}
                        </div>
                        {/* Live ops stats bar */}
                        {(() => {
                          const ops = liveOpsStatus?.[engagement.id];
                          if (!ops || (!ops.isRunning && ops.assetsDiscovered === 0 && ops.vulnsFound === 0)) return null;
                          return (
                            <div className="flex items-center gap-3 mt-2 flex-wrap">
                              {ops.isRunning && ops.progress > 0 && (
                                <div className="w-32 h-1.5 bg-muted rounded-full overflow-hidden">
                                  <div className="h-full bg-primary rounded-full transition-all duration-500" style={{ width: `${ops.progress}%` }} />
                                </div>
                              )}
                              <span className="flex items-center gap-1 text-xs text-muted-foreground">
                                <Target className="w-3 h-3 text-cyan-400" />
                                {ops.assetsDiscovered} assets
                              </span>
                              <span className="flex items-center gap-1 text-xs text-muted-foreground">
                                <Bug className="w-3 h-3 text-orange-400" />
                                {ops.vulnsFound} vulns
                              </span>
                              {ops.exploitsRun > 0 && (
                                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                                  <Zap className="w-3 h-3 text-red-400" />
                                  {ops.exploitsSucceeded}/{ops.exploitsRun} exploits
                                </span>
                              )}
                              {ops.isRunning && ops.lastLogMessage && (
                                <span className="text-xs text-muted-foreground/70 truncate max-w-[300px]" title={ops.lastLogMessage}>
                                  {ops.lastLogMessage}
                                </span>
                              )}
                            </div>
                          );
                        })()}
                        <div className="flex items-center gap-2 sm:gap-4 text-xs sm:text-sm text-muted-foreground flex-wrap">
                          <span className="flex items-center gap-1">
                            <Users className="w-3.5 h-3.5" />
                            {engagement.customerName}
                          </span>
                          {engagement.targetDomain && (
                            <span className="flex items-center gap-1">
                              <Globe2 className="w-3.5 h-3.5" />
                              {engagement.targetDomain}
                            </span>
                          )}
                          {engagement.phishingDomain && (
                            <span className="flex items-center gap-1">
                              <MapPin className="w-3.5 h-3.5" />
                              {engagement.phishingDomain}
                            </span>
                          )}
                          <span className="flex items-center gap-1">
                            <Calendar className="w-3.5 h-3.5" />
                            {new Date(engagement.createdAt).toLocaleDateString()}
                          </span>
                        </div>
                        {engagement.description && (
                          <p className="text-sm text-muted-foreground mt-2 line-clamp-1">{engagement.description}</p>
                        )}
                        {/* Cyber C2 Operation */}
                        {(engagement as any).calderaOperationId && (
                          <a
                            href="https://caldera.aceofcloud.io"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1.5 mt-2 text-xs text-orange-400 hover:text-orange-300 font-display tracking-wider"
                          >
                            <Crosshair className="w-3 h-3" />
                            CYBER C2 OP: {(engagement as any).calderaOperationId.substring(0, 8)}...
                            <span className="px-1.5 py-0.5 text-[10px] bg-orange-500/20 text-orange-300">
                              C2 LINKED
                            </span>
                          </a>
                        )}
                        {/* Linked RoE document */}
                        {engagement.roeDocumentId && (() => {
                          const linkedRoe = roeDocuments?.find((d: any) => d.id === engagement.roeDocumentId);
                          return linkedRoe ? (
                            <a
                              href="/roe-builder"
                              className="flex items-center gap-1.5 mt-2 text-xs text-teal-400 hover:text-teal-300 font-display tracking-wider"
                            >
                              <Scale className="w-3 h-3" />
                              ROE: {linkedRoe.title} (v{linkedRoe.version})
                              <span className={`px-1.5 py-0.5 text-[10px] ${
                                linkedRoe.status === 'active' ? 'bg-green-500/20 text-green-300' :
                                linkedRoe.status === 'approved' ? 'bg-blue-500/20 text-blue-300' :
                                linkedRoe.status === 'draft' ? 'bg-gray-500/20 text-gray-300' :
                                'bg-yellow-500/20 text-yellow-300'
                              }`}>
                                {linkedRoe.status.replace(/_/g, ' ').toUpperCase()}
                              </span>
                            </a>
                          ) : (
                            <span className="flex items-center gap-1.5 mt-2 text-xs text-muted-foreground font-display tracking-wider">
                              <Scale className="w-3 h-3" /> ROE #{engagement.roeDocumentId} (LINKED)
                            </span>
                          );
                        })()}
                        {/* Linked campaigns count */}
                        {(() => {
                          const linkedCount = allCampaignLinks?.filter((l: any) => l.engagementId === engagement.id).length || 0;
                          return linkedCount > 0 ? (
                            <button
                              onClick={() => setExpandedEngagement(expandedEngagement === engagement.id ? null : engagement.id)}
                              className="flex items-center gap-1.5 mt-2 text-xs text-primary hover:text-primary/80 font-display tracking-wider"
                            >
                              <Send className="w-3 h-3" />
                              {linkedCount} LINKED CAMPAIGN{linkedCount > 1 ? 'S' : ''}
                              <ChevronRight className={`w-3 h-3 transition-transform ${expandedEngagement === engagement.id ? 'rotate-90' : ''}`} />
                            </button>
                          ) : null;
                        })()}
                        </div>
                      </div>
                      <div className="flex items-center gap-1 sm:gap-2 flex-wrap sm:opacity-0 sm:group-hover:opacity-100 transition-opacity mt-2 sm:mt-0">
                        <Link href={`/engagement-ops/${engagement.id}`}>
                          <Button
                            variant="outline"
                            size="sm"
                            className="font-display tracking-wider text-red-400 hover:text-red-300"
                          >
                            <Rocket className="w-3.5 h-3.5 mr-1" />
                            LAUNCH
                          </Button>
                        </Link>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setLinkingEngagementId(linkingEngagementId === engagement.id ? null : engagement.id);
                            setSelectedCampaignToLink(null);
                          }}
                          className="font-display tracking-wider"
                        >
                          <Link2 className="w-3.5 h-3.5 mr-1" />
                          LINK
                        </Button>
                        <Link href={`/engagements/${engagement.id}/results`}>
                          <Button
                            variant="outline"
                            size="sm"
                            className="font-display tracking-wider text-primary hover:text-primary/80"
                          >
                            <BarChart3 className="w-3.5 h-3.5 mr-1" />
                            RESULTS
                          </Button>
                        </Link>
                        <Link href={`/engagements/${engagement.id}/recon`}>
                          <Button
                            variant="outline"
                            size="sm"
                            className="font-display tracking-wider text-orange-400 hover:text-orange-300"
                          >
                            <Radar className="w-3.5 h-3.5 mr-1" />
                            RECON
                          </Button>
                        </Link>
                        <Link href="/reports/generate">
                          <Button
                            variant="outline"
                            size="sm"
                            className="font-display tracking-wider text-cyan-400 hover:text-cyan-300"
                          >
                            <FileText className="w-3.5 h-3.5 mr-1" />
                            REPORT
                          </Button>
                        </Link>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setExpandedEngagement(expandedEngagement === engagement.id ? null : engagement.id)}
                          className="font-display tracking-wider"
                        >
                          <Eye className="w-3.5 h-3.5 mr-1" />
                          VIEW
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleEdit(engagement)}
                          className="font-display tracking-wider"
                        >
                          <Pencil className="w-3.5 h-3.5 mr-1" />
                          EDIT
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            if (confirm(`Reset engagement "${engagement.name}" for a fresh rerun?\n\nThis will clear all scan results, timeline events, ops snapshots, and test plans.`)) {
                              resetMutation.mutate({ id: engagement.id });
                            }
                          }}
                          disabled={resetMutation.isPending}
                          className="font-display tracking-wider text-amber-400 hover:text-amber-300"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${resetMutation.isPending ? 'animate-spin' : ''}`} />
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            if (confirm(`Delete engagement "${engagement.name}"?`)) {
                              deleteMutation.mutate({ id: engagement.id });
                            }
                          }}
                          className="font-display tracking-wider text-destructive hover:text-destructive"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      </div>
                    </div>

                    {/* Link campaign inline form */}
                    {linkingEngagementId === engagement.id && (
                      <div className="mt-3 pt-3 border-t border-border">
                        <div className="flex items-center gap-3">
                          <Link2 className="w-4 h-4 text-primary" />
                          <span className="text-xs font-display tracking-wider text-muted-foreground">LINK EXISTING CAMPAIGN:</span>
                          <select
                            value={selectedCampaignToLink ?? ''}
                            onChange={(e) => setSelectedCampaignToLink(e.target.value ? Number(e.target.value) : null)}
                            className="bg-background border border-border px-3 py-1.5 text-xs focus:outline-none focus:border-primary flex-1 max-w-sm"
                          >
                            <option value="">Select a phishing campaign...</option>
                            {gophishCampaigns?.map((c: any) => {
                              const alreadyLinked = allCampaignLinks?.some((l: any) => l.gophishCampaignId === c.id && l.engagementId === engagement.id);
                              return (
                                <option key={c.id} value={c.id} disabled={alreadyLinked}>
                                  {c.name} {alreadyLinked ? '(already linked)' : ''}
                                </option>
                              );
                            })}
                          </select>
                          <Button
                            size="sm"
                            disabled={!selectedCampaignToLink || linkMutation.isPending}
                            onClick={() => {
                              if (selectedCampaignToLink) {
                                const campaign = gophishCampaigns?.find((c: any) => c.id === selectedCampaignToLink);
                                linkMutation.mutate({
                                  engagementId: engagement.id,
                                  gophishCampaignId: selectedCampaignToLink,
                                  gophishCampaignName: campaign?.name,
                                });
                                setSelectedCampaignToLink(null);
                                setLinkingEngagementId(null);
                              }
                            }}
                            className="font-display tracking-wider text-xs"
                          >
                            LINK
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setLinkingEngagementId(null)}
                            className="text-xs"
                          >
                            <X className="w-3.5 h-3.5" />
                          </Button>
                        </div>
                      </div>
                    )}

                    {/* Expanded campaign links */}
                    {expandedEngagement === engagement.id && (
                      <div className="mt-3 pt-3 border-t border-border space-y-4">
                        {/* Rules of Engagement */}
                        <ROEPanel
                          engagementId={engagement.id}
                          engagementName={engagement.name}
                          targetDomain={engagement.targetDomain}
                        />

                        {/* Client Portal Share Links */}
                        <ShareLinkManager engagementId={engagement.id} />

                        <h4 className="text-xs font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-2">
                          <Send className="w-3.5 h-3.5" /> LINKED CAMPAIGNS
                        </h4>
                        {(() => {
                          const links = allCampaignLinks?.filter((l: any) => l.engagementId === engagement.id) || [];
                          if (links.length === 0) {
                            return (
                              <p className="text-xs text-muted-foreground py-2">
                                No campaigns linked yet. Use the LINK button or Launch Wizard to associate campaigns.
                              </p>
                            );
                          }
                          return (
                            <div className="space-y-2">
                              {links.map((link: any) => {
                                const campaign = gophishCampaigns?.find((c: any) => c.id === link.gophishCampaignId);
                                return (
                                  <div key={link.id} className="flex items-center justify-between p-2 bg-background/50 border border-border">
                                    <div className="flex items-center gap-3">
                                      <Fish className="w-4 h-4 text-orange-500" />
                                      <div>
                                        <p className="text-sm font-medium">{link.gophishCampaignName || `Campaign #${link.gophishCampaignId}`}</p>
                                        <p className="text-xs text-muted-foreground">
                                          Campaign ID: {link.gophishCampaignId}
                                          {campaign?.status && ` — ${campaign.status}`}
                                          {campaign?.stats && ` — ${campaign.stats.total || 0} targets, ${campaign.stats.submitted_data || 0} creds`}
                                        </p>
                                      </div>
                                    </div>
                                    <div className="flex items-center gap-2">
                                      <a
                                        href={`https://gophish.aceofcloud.io/campaigns/${link.gophishCampaignId}`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-xs text-orange-500 hover:text-orange-400 font-display tracking-wider flex items-center gap-1"
                                      >
                                        <ExternalLink className="w-3 h-3" /> PHISHING
                                      </a>
                                      <Button
                                        variant="ghost"
                                        size="sm"
                                        onClick={() => {
                                          if (confirm('Unlink this campaign from the engagement?')) {
                                            unlinkMutation.mutate({ id: link.id });
                                          }
                                        }}
                                        className="h-7 w-7 p-0 text-destructive hover:text-destructive/80"
                                      >
                                        <Unlink className="w-3.5 h-3.5" />
                                      </Button>
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          );
                        })()}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      {/* ===== EMULATION OPERATIONS TAB ===== */}
      {activeTab === 'operations' && (
        <>
          {/* Operations Header */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-6">
            <p className="text-sm text-muted-foreground">
              Live operations synced from the emulation framework — deploy exploit abilities from Domain Intel scans
            </p>
            <Button
              variant="outline"
              size="sm"
              className="font-display tracking-wider"
              onClick={() => { refetchOps(); toast.success('Refreshing operations...'); }}
              disabled={isRefetching}
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${isRefetching ? 'animate-spin' : ''}`} />
              REFRESH
            </Button>
          </div>

          {/* Operations Stats */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-4 mb-6">
            <div className="bg-card border border-border p-4">
              <div className="flex items-center gap-2 text-muted-foreground mb-2">
                <Crosshair className="w-4 h-4" />
                <span className="text-xs uppercase tracking-wider">Total Operations</span>
              </div>
              <p className="font-display text-3xl text-primary">{enrichedOperations.length}</p>
            </div>
            <div className="bg-card border border-border p-4">
              <div className="flex items-center gap-2 text-muted-foreground mb-2">
                <Zap className="w-4 h-4" />
                <span className="text-xs uppercase tracking-wider">Total Abilities</span>
              </div>
              <p className="font-display text-3xl text-primary">
                {enrichedOperations.reduce((sum: number, op: any) => sum + op.abilityCount, 0)}
              </p>
            </div>
            <div className="bg-card border border-border p-4">
              <div className="flex items-center gap-2 text-muted-foreground mb-2">
                <Play className="w-4 h-4" />
                <span className="text-xs uppercase tracking-wider">Running</span>
              </div>
              <p className="font-display text-3xl text-green-400">
                {enrichedOperations.filter((op: any) => op.state === 'running').length}
              </p>
            </div>
          </div>

          {/* Loading State */}
          {opsLoading && (
            <div className="flex items-center justify-center py-12">
              <div className="text-center">
                <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full mx-auto mb-4" />
                <p className="text-muted-foreground">Loading operations from the emulation framework...</p>
              </div>
            </div>
          )}

          {/* No Operations */}
          {!opsLoading && enrichedOperations.length === 0 && (
            <div className="bg-card border border-border p-8 text-center">
              <AlertTriangle className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
              <h3 className="font-display text-xl mb-2">No Operations Found</h3>
              <p className="text-muted-foreground mb-4">
                Run a Domain Intel scan to discover exploits, then deploy them as adversary abilities.
              </p>
              <div className="flex gap-3 justify-center">
                <Button onClick={() => navigate('/domain-intel')} variant="outline">
                  <Radar className="w-4 h-4 mr-2" />
                  Domain Intel
                </Button>
                <Button onClick={() => window.open('https://caldera.aceofcloud.io', '_blank')}>
                  <ExternalLink className="w-4 h-4 mr-2" />
                  Open Emulation UI
                </Button>
              </div>
            </div>
          )}

          {/* Operation List */}
          {!opsLoading && enrichedOperations.length > 0 && (
            <div className="grid gap-4">
              {enrichedOperations.map((operation: any) => {
                const statusStyle = OP_STATUS_STYLES[operation.state] || OP_STATUS_STYLES.paused;
                return (
                  <Link key={operation.id} href={`/operations/${operation.id}`}>
                    <div className="bg-card border border-border hover:border-primary transition-colors p-6 cursor-pointer">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-3 mb-2 flex-wrap">
                            <Crosshair className="w-5 h-5 text-primary flex-shrink-0" />
                            <h3 className="font-display text-xl">{operation.name}</h3>
                            <span className={`px-2 py-1 text-xs font-display border ${statusStyle.bg} ${statusStyle.text} flex items-center gap-1`}>
                              {statusStyle.icon}
                              {(operation.state || '').toUpperCase()}
                            </span>
                            <span className="px-2 py-1 text-xs font-display bg-primary/20 text-primary border border-primary">
                              {operation.abilityCount} ABILITIES
                            </span>
                          </div>
                          {operation.description && (
                            <p className="text-sm text-muted-foreground mb-3 line-clamp-2">{operation.description}</p>
                          )}
                          <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                            {operation.adversary?.name && (
                              <span className="flex items-center gap-1">
                                <Target className="w-3 h-3" />
                                {operation.adversary.name}
                              </span>
                            )}
                            <span className="flex items-center gap-1">
                              <Cpu className="w-3 h-3" />
                              {operation.host_group?.length || 0} Agents
                            </span>
                          </div>
                        </div>
                        <ChevronRight className="w-5 h-5 text-muted-foreground flex-shrink-0" />
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}

          {/* Info Banner */}
          <div className="bg-blue-500/10 border border-blue-500/30 p-4 mt-6">
            <p className="text-sm text-blue-400">
              <strong>Workflow:</strong> OSINT &rarr; External Attack Surface &rarr; Adversary Operations &rarr; Phishing (only if external access not achieved) &rarr; Post-Exploitation &rarr; Reporting.
              External attack vectors are tested before phishing is performed.
            </p>
          </div>
        </>
      )}
      {/* Training Lab Dialog */}
      {showTrainingLabDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setShowTrainingLabDialog(false)}>
          <div className="bg-card border border-amber-500/30 p-6 w-full max-w-md mx-4" onClick={e => e.stopPropagation()}>
            <h2 className="font-display text-lg tracking-wider text-amber-400 mb-4 flex items-center gap-2">
              <Target className="w-5 h-5" />
              LAUNCH TRAINING LAB
            </h2>
            <p className="text-xs text-muted-foreground mb-4">
              Run the full engagement pipeline against an authorized training lab target.
              All approval gates will be auto-approved. Exploitable vulns will be automatically exploited.
            </p>

            <div className="space-y-4">
              <div>
                <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">TARGET</label>
                <select
                  value={trainingLabTarget}
                  onChange={e => setTrainingLabTarget(e.target.value)}
                  className="w-full bg-background border border-border p-2 text-sm"
                >
                  <option value="demo.testfire.net">Altoro Mutual (demo.testfire.net) — SQLi, XSS, Auth Bypass</option>
                  <option value="zero.webappsecurity.com">Zero Bank (zero.webappsecurity.com) — SQLi, XSS, CSRF</option>
                  <option value="testphp.vulnweb.com">Acunetix PHP (testphp.vulnweb.com) — SQLi, XSS, File Inclusion</option>
                  <option value="dvwa.co.uk">DVWA (dvwa.co.uk) — 14 Vuln Exercises</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">SCAN MODE</label>
                <div className="flex gap-2">
                  {(['strict_passive', 'standard', 'active'] as const).map(mode => (
                    <button
                      key={mode}
                      onClick={() => setTrainingLabScanMode(mode)}
                      className={`flex-1 p-2 text-xs font-display tracking-wider border transition-colors ${
                        trainingLabScanMode === mode
                          ? mode === 'active' ? 'bg-red-500/20 border-red-500 text-red-400'
                            : mode === 'standard' ? 'bg-yellow-500/20 border-yellow-500 text-yellow-400'
                            : 'bg-green-500/20 border-green-500 text-green-400'
                          : 'border-border text-muted-foreground hover:border-border/80'
                      }`}
                    >
                      {mode === 'strict_passive' ? '\uD83D\uDD12 PASSIVE' : mode === 'standard' ? '\uD83D\uDD0D STANDARD' : '\u26A1 ACTIVE'}
                    </button>
                  ))}
                </div>
                <p className="text-[10px] text-muted-foreground mt-1">
                  {trainingLabScanMode === 'active' ? 'Full exploitation pipeline — will attempt to pop shells on discovered vulns' :
                   trainingLabScanMode === 'standard' ? 'Enumeration + vuln detection, no active exploitation' :
                   'Passive recon only — no direct target interaction'}
                </p>
              </div>

              <div className="bg-amber-500/10 border border-amber-500/20 p-3">
                <p className="text-[10px] text-amber-400">
                  <strong>\u26A0\uFE0F AUTHORIZED TARGETS ONLY:</strong> Training labs are intentionally vulnerable applications.
                  All approval gates will be auto-approved and RoE auto-signed.
                  KEV-listed vulns will be prioritized for exploitation.
                </p>
              </div>

              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1 font-display tracking-wider"
                  onClick={() => setShowTrainingLabDialog(false)}
                >
                  CANCEL
                </Button>
                <Button
                  size="sm"
                  className="flex-1 font-display tracking-wider bg-amber-600 hover:bg-amber-700 text-white"
                  disabled={launchTrainingLabMutation.isPending}
                  onClick={() => {
                    launchTrainingLabMutation.mutate({
                      target: trainingLabTarget,
                      scanMode: trainingLabScanMode,
                      engagementType: 'pentest',
                    });
                  }}
                >
                  {launchTrainingLabMutation.isPending ? 'LAUNCHING...' : '\uD83D\uDE80 LAUNCH'}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
