import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import {
  Activity, Key, Target, Cpu, Zap, Users, FileText, Cloud, BookOpen,
  Shield, Globe2, LogOut, Menu, X, Plus, Briefcase, Calendar, MapPin,
  MoreVertical, Pencil, Trash2, ChevronRight, Search, Filter, Rocket,
  Send, Link2, Unlink, ExternalLink, Fish, Eye, BarChart3, Radar
} from "lucide-react";
import { useState, useMemo } from "react";

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

type EngagementType = typeof ENGAGEMENT_TYPES[number]['value'];
type StatusType = typeof STATUS_OPTIONS[number]['value'];

export default function Engagements() {
  const [, navigate] = useLocation();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');

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

  const { data: engagements, refetch } = trpc.engagements.list.useQuery();
  const { data: allCampaignLinks, refetch: refetchLinks } = trpc.campaignEngagements.listAll.useQuery();
  const { data: gophishCampaigns } = trpc.gophishProxy.getCampaigns.useQuery();
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
{/* Sidebar */}
{/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-6 sm:mb-8">
          <div>
            <h1 className="font-display text-2xl sm:text-3xl tracking-wider">ENGAGEMENTS</h1>
            <p className="text-muted-foreground text-xs sm:text-sm mt-1">Manage customer assessments and red team exercises</p>
          </div>
          <Button
            onClick={() => { setShowCreateForm(true); setEditingId(null); resetForm(); }}
            className="font-display tracking-wider w-full sm:w-auto"
            size="sm"
          >
            <Plus className="w-4 h-4 mr-2" />
            NEW ENGAGEMENT
          </Button>
        </div>

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
                <input
                  type="text"
                  value={formData.targetDomain}
                  onChange={(e) => setFormData(p => ({ ...p, targetDomain: e.target.value }))}
                  placeholder="e.g., acmecorp.com"
                  className="w-full px-3 py-2 bg-background border border-border text-sm focus:outline-none focus:border-primary"
                />
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
                <div key={engagement.id} className="bg-card border border-border p-5 hover:border-primary/30 transition-colors group">
                  <div className="flex items-start justify-between">
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
    </AppShell>
  );
}
