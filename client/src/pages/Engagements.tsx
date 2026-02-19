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
  { id: 3, label: 'Caldera Operations', icon: Crosshair, description: 'Deploy exploit abilities, run red team operations' },
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
      fetch(`/api/trpc/domainIntel.getScan?input=${encodeURIComponent(JSON.stringify({ id: Number(fromIntel) }))}`, { credentials: 'include' })
        .then(r => r.json())
        .then((res: any) => {
          const scan = res?.result?.data?.scan;
          if (scan) {
            setFormData(prev => ({
              ...prev,
              name: `${scan.customerName || scan.primaryDomain} - Intel-Driven Engagement`,
              customerName: scan.customerName || '',
              targetDomain: scan.primaryDomain || '',
              description: `Auto-generated from Domain Intel scan. Risk: ${scan.overallRiskBand} (${scan.overallRiskScore}/100). ${scan.totalAssets || 0} assets discovered.`,
              engagementType: 'red_team' as EngagementType,
            }));
            setShowCreateForm(true);
          }
        })
        .catch(() => {});
    }
  }, []);

  const [editingId, setEditingId] = useState<number | null>(null);
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
  });

  // Engagement data
  const { data: engagements, refetch } = trpc.engagements.list.useQuery();
  const { data: allCampaignLinks, refetch: refetchLinks } = trpc.campaignEngagements.listAll.useQuery();
  const { data: gophishCampaigns } = trpc.gophishProxy.getCampaigns.useQuery();

  // Caldera operations data
  const { data: operations, isLoading: opsLoading, refetch: refetchOps, isRefetching } = trpc.calderaProxy.getOperations.useQuery();
  const { data: allAbilities } = trpc.calderaProxy.getAbilities.useQuery();

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
    onError: (err) => toast.error(err.message),
  });
  const linkMutation = trpc.campaignEngagements.link.useMutation({
    onSuccess: () => { toast.success('Campaign linked'); refetchLinks(); },
    onError: (err) => toast.error(err.message),
  });
  const [expandedEngagement, setExpandedEngagement] = useState<number | null>(null);
  const [linkingEngagementId, setLinkingEngagementId] = useState<number | null>(null);
  const [selectedCampaignToLink, setSelectedCampaignToLink] = useState<number | null>(null);

  const createMutation = trpc.engagements.create.useMutation({
    onSuccess: () => {
      toast.success('Engagement created');
      setShowCreateForm(false);
      resetForm();
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const updateMutation = trpc.engagements.update.useMutation({
    onSuccess: () => {
      toast.success('Engagement updated');
      setEditingId(null);
      resetForm();
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const deleteMutation = trpc.engagements.delete.useMutation({
    onSuccess: () => {
      toast.success('Engagement deleted');
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const bulkDeleteMutation = trpc.engagements.bulkDelete.useMutation({
    onSuccess: (data) => {
      toast.success(`Deleted ${data.deleted} engagement(s) and related records`);
      setSelectedIds(new Set());
      setBulkMode(false);
      refetch();
    },
    onError: (err) => toast.error(err.message),
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

  function resetForm() {
    setFormData({
      name: '', customerName: '', description: '',
      engagementType: 'red_team', status: 'planning',
      targetDomain: '', targetIpRange: '', phishingDomain: '', notes: '',
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
    });
    setShowCreateForm(true);
  }

  function handleSubmit() {
    if (!formData.name || !formData.customerName) {
      toast.error('Name and customer name are required');
      return;
    }
    if (editingId) {
      updateMutation.mutate({ id: editingId, ...formData });
    } else {
      createMutation.mutate(formData);
    }
  }

  const filteredEngagements = useMemo(() => {
    if (!engagements) return [];
    return engagements.filter((e: any) => {
      const matchesSearch = searchQuery === '' ||
        e.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        e.customerName.toLowerCase().includes(searchQuery.toLowerCase());
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
            Manage engagements, Caldera operations, and campaign execution
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={() => { setShowCreateForm(true); setEditingId(null); resetForm(); setActiveTab('engagements'); }}
            className="font-display tracking-wider"
            size="sm"
          >
            <Plus className="w-4 h-4 mr-2" />
            NEW ENGAGEMENT
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="font-display tracking-wider"
            onClick={() => window.open('https://caldera.aceofcloud.io', '_blank')}
          >
            <ExternalLink className="w-4 h-4 mr-2" />
            CALDERA
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
          CALDERA OPERATIONS ({enrichedOperations.length})
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

          {/* Create/Edit Form */}
          {showCreateForm && (
            <div className="bg-card border border-border p-6 mb-6">
              <h2 className="font-display text-lg tracking-wider mb-4">
                {editingId ? 'EDIT ENGAGEMENT' : 'NEW ENGAGEMENT'}
              </h2>
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
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1">TARGET DOMAIN</label>
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
                  <p className="text-[10px] text-muted-foreground mt-1">Enter domain and click SCAN to run OSINT recon before creating the engagement</p>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground tracking-wider block mb-1">TARGET IP RANGE</label>
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
              </div>
              <div className="flex gap-3 mt-4">
                <Button onClick={handleSubmit} className="font-display tracking-wider">
                  {editingId ? 'UPDATE' : 'CREATE'} ENGAGEMENT
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
          <div className="flex items-center gap-3 mb-4">
            <Button
              variant={bulkMode ? "default" : "outline"}
              size="sm"
              onClick={() => { setBulkMode(!bulkMode); if (bulkMode) setSelectedIds(new Set()); }}
              className="font-display tracking-wider"
            >
              {bulkMode ? <X className="w-3.5 h-3.5 mr-1" /> : <Trash2 className="w-3.5 h-3.5 mr-1" />}
              {bulkMode ? 'EXIT BULK MODE' : 'BULK DELETE'}
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
                )}
              </>
            )}
          </div>

          {/* Stats Summary */}
          <div className="grid grid-cols-2 md:grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
            {STATUS_OPTIONS.map(s => {
              const count = engagements?.filter((e: any) => e.status === s.value).length || 0;
              return (
                <div key={s.value} className="bg-card border border-border p-4">
                  <p className="text-xs text-muted-foreground tracking-wider">{s.label.toUpperCase()}</p>
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
                    <div className="flex items-start justify-between">
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
                        <div className="flex items-center gap-3 mb-2">
                          <h3 className="font-display text-lg tracking-wider truncate">{engagement.name}</h3>
                          <span className={`text-xs px-2 py-0.5 ${typeConfig.color} font-display tracking-wider`}>
                            {typeConfig.label.toUpperCase()}
                          </span>
                          <span className={`text-xs px-2 py-0.5 ${statusConfig.color} font-display tracking-wider`}>
                            {statusConfig.label.toUpperCase()}
                          </span>
                        </div>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
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
                      <div className="flex items-center gap-1 sm:gap-2 flex-wrap sm:opacity-0 sm:group-hover:opacity-100 transition-opacity">
                        <Link href={`/campaign-wizard`}>
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
                            <option value="">Select a GoPhish campaign...</option>
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
                      <div className="mt-3 pt-3 border-t border-border">
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
                                          GoPhish ID: {link.gophishCampaignId}
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
                                        <ExternalLink className="w-3 h-3" /> GOPHISH
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

      {/* ===== CALDERA OPERATIONS TAB ===== */}
      {activeTab === 'operations' && (
        <>
          {/* Operations Header */}
          <div className="flex items-center justify-between mb-6">
            <p className="text-sm text-muted-foreground">
              Live operations synced from Caldera — deploy exploit abilities from Domain Intel scans
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
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
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
                <p className="text-muted-foreground">Loading operations from Caldera...</p>
              </div>
            </div>
          )}

          {/* No Operations */}
          {!opsLoading && enrichedOperations.length === 0 && (
            <div className="bg-card border border-border p-8 text-center">
              <AlertTriangle className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
              <h3 className="font-display text-xl mb-2">No Operations Found</h3>
              <p className="text-muted-foreground mb-4">
                Run a Domain Intel scan to discover exploits, then deploy them as Caldera abilities.
              </p>
              <div className="flex gap-3 justify-center">
                <Button onClick={() => navigate('/domain-intel')} variant="outline">
                  <Radar className="w-4 h-4 mr-2" />
                  Domain Intel
                </Button>
                <Button onClick={() => window.open('https://caldera.aceofcloud.io', '_blank')}>
                  <ExternalLink className="w-4 h-4 mr-2" />
                  Open Caldera
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
                              {operation.state.toUpperCase()}
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
              <strong>Workflow:</strong> OSINT &rarr; External Attack Surface &rarr; Caldera Operations &rarr; Phishing (only if external access not achieved) &rarr; Post-Exploitation &rarr; Reporting.
              External attack vectors are tested before phishing is performed.
            </p>
          </div>
        </>
      )}
    </AppShell>
  );
}
