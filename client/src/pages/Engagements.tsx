import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import {
  Activity, Key, Target, Cpu, Zap, Users, FileText, Cloud, BookOpen,
  Shield, Globe2, LogOut, Menu, X, Plus, Briefcase, Calendar, MapPin,
  MoreVertical, Pencil, Trash2, ChevronRight, Search, Filter
} from "lucide-react";
import { useState, useMemo } from "react";

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
  const [sidebarOpen, setSidebarOpen] = useState(false);
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
            <NavItem href="/engagements" icon={<Briefcase />} label="ENGAGEMENTS" active />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" />
            <NavItem href="/agents" icon={<Cpu />} label="AGENTS" />
            <NavItem href="/campaigns" icon={<Zap />} label="CAMPAIGNS" />
            <NavItem href="/gophish" icon={<Zap />} label="GOPHISH" />
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
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="font-display text-3xl tracking-wider">ENGAGEMENTS</h1>
            <p className="text-muted-foreground text-sm mt-1">Manage customer assessments and red team exercises</p>
          </div>
          <Button
            onClick={() => { setShowCreateForm(true); setEditingId(null); resetForm(); }}
            className="font-display tracking-wider"
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
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
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
                    </div>
                    <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
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
                </div>
              );
            })}
          </div>
        )}
      </main>

      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/50 z-40 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}
    </div>
  );
}
