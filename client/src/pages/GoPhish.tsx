import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { 
  Cloud, Activity, Key, Users, LogOut, Menu, X, Target, FileText,
  Zap, Cpu, ExternalLink, Mail, Fish, Send, Globe, UserPlus,
  Plus, RefreshCw, CheckCircle, Clock, AlertTriangle, Play,
  Crosshair, BarChart3, MousePointer, ShieldAlert, Eye, Trash2,
  Edit, Save, XCircle, ChevronDown, ChevronUp, Copy, BookOpen,
  Shield, Globe2, Briefcase, Rocket, Filter
} from "lucide-react";
import { useState, useMemo } from "react";

const NAV_ITEMS = [
  { href: "/dashboard", icon: <Activity className="w-4 h-4" />, label: "DASHBOARD" },
  { href: "/engagements", icon: <Briefcase className="w-4 h-4" />, label: "ENGAGEMENTS" },
  { href: "/credentials", icon: <Key className="w-4 h-4" />, label: "CREDENTIALS" },
  { href: "/adversaries", icon: <Target className="w-4 h-4" />, label: "ADVERSARIES" },
  { href: "/agents", icon: <Cpu className="w-4 h-4" />, label: "AGENTS" },
  { href: "/campaigns", icon: <Crosshair className="w-4 h-4" />, label: "CAMPAIGNS" },
  { href: "/gophish", icon: <Fish className="w-4 h-4" />, label: "GOPHISH" },
  { href: "/campaign-wizard", icon: <Rocket className="w-4 h-4" />, label: "LAUNCH WIZARD" },
  { href: "/team", icon: <Users className="w-4 h-4" />, label: "TEAM" },
  { href: "/activity", icon: <FileText className="w-4 h-4" />, label: "ACTIVITY" },
];

const GUIDE_ITEMS = [
  { href: "/guide/gophish", icon: <BookOpen className="w-4 h-4" />, label: "GOPHISH GUIDE" },
  { href: "/guide/caldera", icon: <BookOpen className="w-4 h-4" />, label: "CALDERA GUIDE" },
  { href: "/templates", icon: <FileText className="w-4 h-4" />, label: "TEMPLATE LIBRARY" },
];

export default function GoPhish() {
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'campaigns' | 'templates' | 'pages' | 'groups' | 'smtp'>('overview');
  const [selectedEngagementId, setSelectedEngagementId] = useState<number | null>(null);

  const utils = trpc.useUtils();

  // Fetch engagements for filtering
  const { data: engagements } = trpc.engagements.list.useQuery();
  const { data: campaignLinks } = trpc.campaignEngagements.listAll.useQuery();

  // Fetch GoPhish data
  const { data: status, refetch: refetchStatus } = trpc.gophishProxy.getStatus.useQuery(undefined, { refetchInterval: 30000 });
  const { data: campaigns, refetch: refetchCampaigns } = trpc.gophishProxy.getCampaigns.useQuery(undefined, { enabled: activeTab === 'campaigns' || activeTab === 'overview' });
  const { data: templates, refetch: refetchTemplates } = trpc.gophishProxy.getTemplates.useQuery(undefined, { enabled: activeTab === 'templates' || activeTab === 'overview' || activeTab === 'campaigns' });
  const { data: landingPages, refetch: refetchPages } = trpc.gophishProxy.getLandingPages.useQuery(undefined, { enabled: activeTab === 'pages' || activeTab === 'overview' || activeTab === 'campaigns' });
  const { data: groups, refetch: refetchGroups } = trpc.gophishProxy.getGroups.useQuery(undefined, { enabled: activeTab === 'groups' || activeTab === 'overview' || activeTab === 'campaigns' });
  const { data: sendingProfiles, refetch: refetchSmtp } = trpc.gophishProxy.getSendingProfiles.useQuery(undefined, { enabled: activeTab === 'smtp' || activeTab === 'overview' || activeTab === 'campaigns' });
  const { data: calderaHealth } = trpc.calderaProxy.checkHealth.useQuery();

  // Mutations
  const createTemplate = trpc.gophishProxy.createTemplate.useMutation({ onSuccess: () => { refetchTemplates(); refetchStatus(); toast.success("Template created"); } });
  const updateTemplate = trpc.gophishProxy.updateTemplate.useMutation({ onSuccess: () => { refetchTemplates(); toast.success("Template updated"); } });
  const deleteTemplate = trpc.gophishProxy.deleteTemplate.useMutation({ onSuccess: () => { refetchTemplates(); refetchStatus(); toast.success("Template deleted"); } });
  const createPage = trpc.gophishProxy.createLandingPage.useMutation({ onSuccess: () => { refetchPages(); refetchStatus(); toast.success("Landing page created"); } });
  const updatePage = trpc.gophishProxy.updateLandingPage.useMutation({ onSuccess: () => { refetchPages(); toast.success("Landing page updated"); } });
  const deletePage = trpc.gophishProxy.deleteLandingPage.useMutation({ onSuccess: () => { refetchPages(); refetchStatus(); toast.success("Landing page deleted"); } });
  const createGroup = trpc.gophishProxy.createGroup.useMutation({ onSuccess: () => { refetchGroups(); refetchStatus(); toast.success("Group created"); } });
  const updateGroup = trpc.gophishProxy.updateGroup.useMutation({ onSuccess: () => { refetchGroups(); toast.success("Group updated"); } });
  const deleteGroup = trpc.gophishProxy.deleteGroup.useMutation({ onSuccess: () => { refetchGroups(); refetchStatus(); toast.success("Group deleted"); } });
  const createSmtp = trpc.gophishProxy.createSendingProfile.useMutation({ onSuccess: () => { refetchSmtp(); refetchStatus(); toast.success("Sending profile created"); } });
  const updateSmtp = trpc.gophishProxy.updateSendingProfile.useMutation({ onSuccess: () => { refetchSmtp(); toast.success("Sending profile updated"); } });
  const deleteSmtp = trpc.gophishProxy.deleteSendingProfile.useMutation({ onSuccess: () => { refetchSmtp(); refetchStatus(); toast.success("Sending profile deleted"); } });
  const launchCampaign = trpc.gophishProxy.launchCampaign.useMutation({ onSuccess: () => { refetchCampaigns(); refetchStatus(); toast.success("Campaign launched!"); } });
  const deleteCampaign = trpc.gophishProxy.deleteCampaign.useMutation({ onSuccess: () => { refetchCampaigns(); refetchStatus(); toast.success("Campaign deleted"); } });
  const completeCampaign = trpc.gophishProxy.completeCampaign.useMutation({ onSuccess: () => { refetchCampaigns(); toast.success("Campaign completed"); } });

  const handleRefresh = () => {
    refetchStatus(); refetchCampaigns(); refetchTemplates(); refetchPages(); refetchGroups(); refetchSmtp();
    toast.success("Refreshing all GoPhish data...");
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
                <span className="text-[10px] text-muted-foreground tracking-widest">C3 — <span className="text-primary/70">CYBER CAMPAIGN COMMAND</span></span>
              </div>
            </Link>
          </div>
          <nav className="flex-1 p-4 space-y-2">
            {NAV_ITEMS.map(item => (
              <NavItem key={item.href} href={item.href} icon={item.icon} label={item.label} active={item.href === '/gophish'} />
            ))}
            <div className="border-t border-border my-3 pt-3">
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">THREAT INTEL</p>
              <NavItem href="/apt-library" icon={<Shield className="w-4 h-4" />} label="APT SCENARIOS" />
              <NavItem href="/compliance" icon={<FileText className="w-4 h-4" />} label="COMPLIANCE" />
              <NavItem href="/infra-reference" icon={<Globe2 className="w-4 h-4" />} label="INFRASTRUCTURE" />
            </div>
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">GUIDES</p>
              {GUIDE_ITEMS.map(item => (
                <NavItem key={item.href} href={item.href} icon={item.icon} label={item.label} />
              ))}
            </div>
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">REPORTS</p>
              <NavItem href="/reports/security" icon={<FileText className="w-4 h-4" />} label="SECURITY REPORT" />
            </div>
          </nav>
          <div className="p-4 border-t border-border">
            <Link href="/"><Button variant="outline" size="sm" className="w-full font-display tracking-wider"><LogOut className="w-4 h-4 mr-2" />EXIT</Button></Link>
          </div>
        </div>
      </aside>

      {sidebarOpen && <div className="fixed inset-0 bg-black/50 z-40 lg:hidden" onClick={() => setSidebarOpen(false)} />}

      <main className="flex-1 lg:ml-64">
        {/* Header */}
        <header className="sticky top-0 z-30 bg-card/80 backdrop-blur-sm border-b border-border px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Button variant="ghost" size="sm" className="lg:hidden" onClick={() => setSidebarOpen(!sidebarOpen)}>
                {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
              </Button>
              <div>
                <h1 className="font-display text-2xl tracking-wider flex items-center gap-2">
                  <Fish className="w-6 h-6 text-orange-500" />
                  GOPHISH MANAGER
                </h1>
                <p className="text-sm text-muted-foreground">Phishing Campaign Management & Caldera Integration</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className={`flex items-center gap-2 px-3 py-1.5 text-xs font-display tracking-wider ${status?.online ? 'bg-green-500/20 text-green-400 border border-green-500/50' : 'bg-red-500/20 text-red-400 border border-red-500/50'}`}>
                <div className={`w-2 h-2 rounded-full ${status?.online ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                GOPHISH {status?.online ? 'ONLINE' : 'OFFLINE'}
              </div>
              <Button variant="outline" size="sm" className="font-display tracking-wider" onClick={handleRefresh}>
                <RefreshCw className="w-4 h-4 mr-2" />REFRESH
              </Button>
              <Link href="/campaign-wizard">
                <Button size="sm" className="font-display tracking-wider bg-red-600 hover:bg-red-700 text-white">
                  <Rocket className="w-4 h-4 mr-2" />LAUNCH WIZARD
                </Button>
              </Link>
              <a href="https://gophish.aceofcloud.io" target="_blank" rel="noopener noreferrer">
                <Button size="sm" className="font-display tracking-wider bg-orange-500 hover:bg-orange-600 text-black">
                  <ExternalLink className="w-4 h-4 mr-2" />OPEN GOPHISH UI
                </Button>
              </a>
            </div>
          </div>
        </header>

        <div className="p-6 space-y-6">
          {/* Tab Navigation */}
          <div className="flex gap-2 border-b border-border pb-2 overflow-x-auto">
            {[
              { id: 'overview', label: 'OVERVIEW', icon: <BarChart3 className="w-4 h-4" /> },
              { id: 'campaigns', label: 'CAMPAIGNS', icon: <Send className="w-4 h-4" /> },
              { id: 'templates', label: 'EMAIL TEMPLATES', icon: <Mail className="w-4 h-4" /> },
              { id: 'pages', label: 'LANDING PAGES', icon: <Globe className="w-4 h-4" /> },
              { id: 'groups', label: 'TARGET GROUPS', icon: <UserPlus className="w-4 h-4" /> },
              { id: 'smtp', label: 'SENDING PROFILES', icon: <Send className="w-4 h-4" /> },
            ].map(tab => (
              <Button
                key={tab.id}
                variant={activeTab === tab.id ? 'default' : 'ghost'}
                size="sm"
                className={`font-display tracking-wider whitespace-nowrap ${activeTab === tab.id ? 'bg-orange-500 hover:bg-orange-600 text-black' : ''}`}
                onClick={() => setActiveTab(tab.id as any)}
              >
                {tab.icon}
                <span className="ml-2">{tab.label}</span>
              </Button>
            ))}
          </div>

          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                <StatusCard label="CAMPAIGNS" value={status?.campaigns ?? 0} icon={<Send className="w-5 h-5" />} color="orange" />
                <StatusCard label="TEMPLATES" value={status?.templates ?? 0} icon={<Mail className="w-5 h-5" />} color="blue" />
                <StatusCard label="LANDING PAGES" value={status?.landingPages ?? 0} icon={<Globe className="w-5 h-5" />} color="green" />
                <StatusCard label="TARGET GROUPS" value={status?.groups ?? 0} icon={<UserPlus className="w-5 h-5" />} color="purple" />
                <StatusCard label="SMTP PROFILES" value={status?.sendingProfiles ?? 0} icon={<Send className="w-5 h-5" />} color="cyan" />
                <StatusCard label="CALDERA LINK" value={calderaHealth ? 'ACTIVE' : 'DOWN'} icon={<Zap className="w-5 h-5" />} color={calderaHealth ? 'emerald' : 'red'} />
              </div>

              {/* Integration Status */}
              <div className="bg-card border-2 border-border p-6">
                <h2 className="font-display text-xl tracking-wider mb-4 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-500" />
                  CALDERA-GOPHISH INTEGRATION
                </h2>
                <div className="grid md:grid-cols-2 gap-6">
                  <div className="space-y-3">
                    <h3 className="font-display text-sm tracking-wider text-muted-foreground">INTEGRATION BRIDGE</h3>
                    <div className="bg-background/50 border border-border p-4 space-y-2">
                      <div className="flex items-center justify-between"><span className="text-sm">Bridge Service</span><span className="text-xs font-display tracking-wider text-green-400 bg-green-500/20 px-2 py-0.5">RUNNING</span></div>
                      <div className="flex items-center justify-between"><span className="text-sm">Auto-trigger on Credential Capture</span><span className="text-xs font-display tracking-wider text-green-400 bg-green-500/20 px-2 py-0.5">ENABLED</span></div>
                      <div className="flex items-center justify-between"><span className="text-sm">Monitoring Interval</span><span className="text-xs font-display tracking-wider text-blue-400">30 SECONDS</span></div>
                    </div>
                  </div>
                  <div className="space-y-3">
                    <h3 className="font-display text-sm tracking-wider text-muted-foreground">WORKFLOW</h3>
                    <div className="bg-background/50 border border-border p-4 space-y-3">
                      <div className="flex items-center gap-3"><div className="w-8 h-8 bg-orange-500/20 flex items-center justify-center text-orange-500 font-display text-xs">1</div><span className="text-sm">GoPhish sends phishing email</span></div>
                      <div className="flex items-center gap-3"><div className="w-8 h-8 bg-yellow-500/20 flex items-center justify-center text-yellow-500 font-display text-xs">2</div><span className="text-sm">Target clicks link / submits credentials</span></div>
                      <div className="flex items-center gap-3"><div className="w-8 h-8 bg-red-500/20 flex items-center justify-center text-red-500 font-display text-xs">3</div><span className="text-sm">Bridge detects event & triggers Caldera</span></div>
                      <div className="flex items-center gap-3"><div className="w-8 h-8 bg-emerald-500/20 flex items-center justify-center text-emerald-500 font-display text-xs">4</div><span className="text-sm">Caldera launches post-exploitation operation</span></div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Quick Actions */}
              <div className="grid md:grid-cols-4 gap-4">
                <Button className="h-20 font-display tracking-wider bg-blue-600 hover:bg-blue-700" onClick={() => setActiveTab('templates')}>
                  <div className="text-center"><Mail className="w-6 h-6 mx-auto mb-1" /><span className="text-xs">CREATE TEMPLATE</span></div>
                </Button>
                <Button className="h-20 font-display tracking-wider bg-green-600 hover:bg-green-700" onClick={() => setActiveTab('pages')}>
                  <div className="text-center"><Globe className="w-6 h-6 mx-auto mb-1" /><span className="text-xs">CREATE LANDING PAGE</span></div>
                </Button>
                <Button className="h-20 font-display tracking-wider bg-purple-600 hover:bg-purple-700" onClick={() => setActiveTab('groups')}>
                  <div className="text-center"><UserPlus className="w-6 h-6 mx-auto mb-1" /><span className="text-xs">CREATE TARGET GROUP</span></div>
                </Button>
                <Button className="h-20 font-display tracking-wider bg-orange-600 hover:bg-orange-700" onClick={() => setActiveTab('campaigns')}>
                  <div className="text-center"><Send className="w-6 h-6 mx-auto mb-1" /><span className="text-xs">LAUNCH CAMPAIGN</span></div>
                </Button>
              </div>
            </div>
          )}

          {/* Engagement Filter Bar */}
          {(activeTab === 'campaigns' || activeTab === 'overview') && engagements && engagements.length > 0 && (
            <div className="flex items-center gap-3 p-3 bg-card border border-border">
              <Filter className="w-4 h-4 text-muted-foreground" />
              <span className="text-xs font-display tracking-wider text-muted-foreground">FILTER BY ENGAGEMENT:</span>
              <select
                value={selectedEngagementId ?? ''}
                onChange={(e) => setSelectedEngagementId(e.target.value ? Number(e.target.value) : null)}
                className="bg-background border border-border px-3 py-1.5 text-xs focus:outline-none focus:border-primary"
              >
                <option value="">All Campaigns</option>
                {engagements.map((eng: any) => (
                  <option key={eng.id} value={eng.id}>{eng.name} ({eng.customerName})</option>
                ))}
              </select>
              {selectedEngagementId && (
                <button
                  onClick={() => setSelectedEngagementId(null)}
                  className="text-xs text-primary hover:text-primary/80 font-display tracking-wider"
                >
                  CLEAR FILTER
                </button>
              )}
            </div>
          )}

          {/* Campaigns Tab */}
          {activeTab === 'campaigns' && (
            <CampaignsPanel
              campaigns={campaigns}
              templates={templates}
              landingPages={landingPages}
              groups={groups}
              sendingProfiles={sendingProfiles}
              onLaunch={(data: any) => launchCampaign.mutate(data)}
              onDelete={(id: number) => { if (confirm('Delete this campaign?')) deleteCampaign.mutate({ id }); }}
              onComplete={(id: number) => { if (confirm('Mark this campaign as complete?')) completeCampaign.mutate({ id }); }}
              isLaunching={launchCampaign.isPending}
              engagementFilter={selectedEngagementId}
              campaignLinks={campaignLinks}
            />
          )}

          {/* Templates Tab */}
          {activeTab === 'templates' && (
            <TemplatesPanel
              templates={templates}
              onCreate={(data: any) => createTemplate.mutate(data)}
              onUpdate={(data: any) => updateTemplate.mutate(data)}
              onDelete={(id: number) => { if (confirm('Delete this template?')) deleteTemplate.mutate({ id }); }}
              isCreating={createTemplate.isPending}
            />
          )}

          {/* Landing Pages Tab */}
          {activeTab === 'pages' && (
            <LandingPagesPanel
              pages={landingPages}
              onCreate={(data: any) => createPage.mutate(data)}
              onUpdate={(data: any) => updatePage.mutate(data)}
              onDelete={(id: number) => { if (confirm('Delete this landing page?')) deletePage.mutate({ id }); }}
              isCreating={createPage.isPending}
            />
          )}

          {/* Target Groups Tab */}
          {activeTab === 'groups' && (
            <GroupsPanel
              groups={groups}
              onCreate={(data: any) => createGroup.mutate(data)}
              onUpdate={(data: any) => updateGroup.mutate(data)}
              onDelete={(id: number) => { if (confirm('Delete this group?')) deleteGroup.mutate({ id }); }}
              isCreating={createGroup.isPending}
            />
          )}

          {/* Sending Profiles Tab */}
          {activeTab === 'smtp' && (
            <SmtpPanel
              profiles={sendingProfiles}
              onCreate={(data: any) => createSmtp.mutate(data)}
              onUpdate={(data: any) => updateSmtp.mutate(data)}
              onDelete={(id: number) => { if (confirm('Delete this sending profile?')) deleteSmtp.mutate({ id }); }}
              isCreating={createSmtp.isPending}
            />
          )}
        </div>
      </main>
    </div>
  );
}

// ==================== CAMPAIGNS PANEL ====================
function CampaignsPanel({ campaigns, templates, landingPages, groups, sendingProfiles, onLaunch, onDelete, onComplete, isLaunching, engagementFilter, campaignLinks }: any) {
  const [, navigate] = useLocation();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: '', template: '', page: '', smtp: '', group: '', url: 'https://aceofcloud.io' });

  // Filter campaigns by engagement
  const filteredCampaigns = useMemo(() => {
    if (!campaigns || !engagementFilter) return campaigns;
    if (!campaignLinks) return campaigns;
    const linkedCampaignIds = new Set(
      campaignLinks
        .filter((link: any) => link.engagementId === engagementFilter)
        .map((link: any) => link.gophishCampaignId)
    );
    return campaigns.filter((c: any) => linkedCampaignIds.has(c.id));
  }, [campaigns, engagementFilter, campaignLinks]);

  const handleLaunch = () => {
    if (!form.name || !form.template || !form.page || !form.smtp || !form.group) {
      toast.error("All fields are required"); return;
    }
    onLaunch({
      name: form.name,
      template: { name: form.template },
      page: { name: form.page },
      smtp: { name: form.smtp },
      groups: [{ name: form.group }],
      url: form.url,
    });
    setShowForm(false);
    setForm({ name: '', template: '', page: '', smtp: '', group: '', url: 'https://aceofcloud.io' });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="font-display text-xl tracking-wider">
          PHISHING CAMPAIGNS
          {engagementFilter && <span className="text-sm text-primary ml-2">(Filtered)</span>}
        </h2>
        <div className="flex gap-2">
          <Link href="/campaign-wizard">
            <Button size="sm" className="font-display tracking-wider bg-red-600 hover:bg-red-700 text-white">
              <Rocket className="w-4 h-4 mr-2" />LAUNCH WIZARD
            </Button>
          </Link>
          <Button size="sm" className="font-display tracking-wider bg-orange-500 hover:bg-orange-600 text-black" onClick={() => setShowForm(!showForm)}>
            {showForm ? <><XCircle className="w-4 h-4 mr-2" />CANCEL</> : <><Plus className="w-4 h-4 mr-2" />QUICK LAUNCH</>}
          </Button>
        </div>
      </div>

      {showForm && (
        <div className="bg-card border-2 border-orange-500/50 p-6 space-y-4">
          <h3 className="font-display text-lg tracking-wider text-orange-500">LAUNCH NEW CAMPAIGN</h3>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">CAMPAIGN NAME *</label>
              <input type="text" value={form.name} onChange={e => setForm({...form, name: e.target.value})} placeholder="Q1 Security Awareness Test" className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">PHISHING URL</label>
              <input type="text" value={form.url} onChange={e => setForm({...form, url: e.target.value})} className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">EMAIL TEMPLATE *</label>
              <select value={form.template} onChange={e => setForm({...form, template: e.target.value})} className="w-full px-3 py-2 bg-background border border-border rounded text-sm">
                <option value="">Select template...</option>
                {Array.isArray(templates) && templates.map((t: any) => <option key={t.id} value={t.name}>{t.name}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">LANDING PAGE *</label>
              <select value={form.page} onChange={e => setForm({...form, page: e.target.value})} className="w-full px-3 py-2 bg-background border border-border rounded text-sm">
                <option value="">Select landing page...</option>
                {Array.isArray(landingPages) && landingPages.map((p: any) => <option key={p.id} value={p.name}>{p.name}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">SENDING PROFILE *</label>
              <select value={form.smtp} onChange={e => setForm({...form, smtp: e.target.value})} className="w-full px-3 py-2 bg-background border border-border rounded text-sm">
                <option value="">Select sending profile...</option>
                {Array.isArray(sendingProfiles) && sendingProfiles.map((s: any) => <option key={s.id} value={s.name}>{s.name}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">TARGET GROUP *</label>
              <select value={form.group} onChange={e => setForm({...form, group: e.target.value})} className="w-full px-3 py-2 bg-background border border-border rounded text-sm">
                <option value="">Select target group...</option>
                {Array.isArray(groups) && groups.map((g: any) => <option key={g.id} value={g.name}>{g.name}</option>)}
              </select>
            </div>
          </div>
          <Button className="font-display tracking-wider bg-orange-500 hover:bg-orange-600 text-black" onClick={handleLaunch} disabled={isLaunching}>
            <Play className="w-4 h-4 mr-2" />{isLaunching ? 'LAUNCHING...' : 'LAUNCH CAMPAIGN'}
          </Button>
        </div>
      )}

      {Array.isArray(filteredCampaigns) && filteredCampaigns.length > 0 ? (
        <div className="space-y-3">
          {filteredCampaigns.map((campaign: any) => (
            <CampaignCard key={campaign.id} campaign={campaign} onDelete={onDelete} onComplete={onComplete} campaignLinks={campaignLinks} />
          ))}
        </div>
      ) : (
        <EmptyState icon={<Send className="w-12 h-12 text-orange-500/50" />} title={engagementFilter ? "NO CAMPAIGNS FOR THIS ENGAGEMENT" : "NO CAMPAIGNS YET"} description={engagementFilter ? "No campaigns are linked to this engagement. Use the Launch Wizard to create a campaign linked to an engagement." : "Launch your first phishing campaign using the Launch Wizard or Quick Launch above."} />
      )}
    </div>
  );
}

// ==================== TEMPLATES PANEL ====================
function TemplatesPanel({ templates, onCreate, onUpdate, onDelete, isCreating }: any) {
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState<number | null>(null);
  const [form, setForm] = useState({ name: '', subject: '', html: '', text: '' });

  const handleSave = () => {
    if (!form.name || !form.subject || !form.html) { toast.error("Name, subject, and HTML are required"); return; }
    if (editId) {
      onUpdate({ id: editId, ...form });
      setEditId(null);
    } else {
      onCreate(form);
    }
    setShowForm(false);
    setForm({ name: '', subject: '', html: '', text: '' });
  };

  const startEdit = (t: any) => {
    setForm({ name: t.name, subject: t.subject || '', html: t.html || '', text: t.text || '' });
    setEditId(t.id);
    setShowForm(true);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="font-display text-xl tracking-wider">EMAIL TEMPLATES</h2>
        <Button size="sm" className="font-display tracking-wider bg-blue-500 hover:bg-blue-600 text-white" onClick={() => { setShowForm(!showForm); setEditId(null); setForm({ name: '', subject: '', html: '', text: '' }); }}>
          {showForm ? <><XCircle className="w-4 h-4 mr-2" />CANCEL</> : <><Plus className="w-4 h-4 mr-2" />NEW TEMPLATE</>}
        </Button>
      </div>

      {showForm && (
        <div className="bg-card border-2 border-blue-500/50 p-6 space-y-4">
          <h3 className="font-display text-lg tracking-wider text-blue-500">{editId ? 'EDIT' : 'CREATE'} EMAIL TEMPLATE</h3>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">TEMPLATE NAME *</label>
              <input type="text" value={form.name} onChange={e => setForm({...form, name: e.target.value})} placeholder="Password Reset Notice" className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">EMAIL SUBJECT *</label>
              <input type="text" value={form.subject} onChange={e => setForm({...form, subject: e.target.value})} placeholder="Action Required: Password Reset" className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
            </div>
          </div>
          <div>
            <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">HTML BODY * <span className="text-muted-foreground/60">(Use {"{{.URL}}"} for phishing link, {"{{.FirstName}}"} for target name)</span></label>
            <textarea value={form.html} onChange={e => setForm({...form, html: e.target.value})} rows={12} placeholder='<html><body><p>Dear {{.FirstName}},</p><p>Your password is about to expire. Please <a href="{{.URL}}">click here</a> to reset it.</p></body></html>' className="w-full px-3 py-2 bg-background border border-border rounded text-sm font-mono" />
          </div>
          <div>
            <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">PLAIN TEXT (optional)</label>
            <textarea value={form.text} onChange={e => setForm({...form, text: e.target.value})} rows={4} placeholder="Dear {{.FirstName}}, Your password is about to expire..." className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
          </div>
          <Button className="font-display tracking-wider bg-blue-500 hover:bg-blue-600 text-white" onClick={handleSave} disabled={isCreating}>
            <Save className="w-4 h-4 mr-2" />{editId ? 'UPDATE TEMPLATE' : 'CREATE TEMPLATE'}
          </Button>
        </div>
      )}

      {Array.isArray(templates) && templates.length > 0 ? (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {templates.map((t: any) => (
            <div key={t.id} className="bg-card border-2 border-border hover:border-blue-500 p-4 transition-colors group">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2 min-w-0">
                  <Mail className="w-4 h-4 text-blue-500 shrink-0" />
                  <h3 className="font-display text-sm tracking-wider truncate">{t.name}</h3>
                </div>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => startEdit(t)}><Edit className="w-3 h-3" /></Button>
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-red-500" onClick={() => onDelete(t.id)}><Trash2 className="w-3 h-3" /></Button>
                </div>
              </div>
              <p className="text-xs text-muted-foreground mb-1">Subject: {t.subject || 'N/A'}</p>
              <p className="text-xs text-muted-foreground">Modified: {new Date(t.modified_date).toLocaleDateString()}</p>
              {t.html && <div className="mt-2 p-2 bg-background/50 border border-border rounded text-[10px] text-muted-foreground max-h-20 overflow-hidden">{t.html.replace(/<[^>]*>/g, '').substring(0, 150)}...</div>}
            </div>
          ))}
        </div>
      ) : (
        <EmptyState icon={<Mail className="w-12 h-12 text-blue-500/50" />} title="NO EMAIL TEMPLATES" description="Create email templates to use in phishing campaigns. Templates support GoPhish variables like {{.URL}} and {{.FirstName}}." />
      )}
    </div>
  );
}

// ==================== LANDING PAGES PANEL ====================
function LandingPagesPanel({ pages, onCreate, onUpdate, onDelete, isCreating }: any) {
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState<number | null>(null);
  const [form, setForm] = useState({ name: '', html: '', capture_credentials: true, capture_passwords: true, redirect_url: '' });

  const handleSave = () => {
    if (!form.name || !form.html) { toast.error("Name and HTML are required"); return; }
    if (editId) {
      onUpdate({ id: editId, ...form });
      setEditId(null);
    } else {
      onCreate(form);
    }
    setShowForm(false);
    setForm({ name: '', html: '', capture_credentials: true, capture_passwords: true, redirect_url: '' });
  };

  const startEdit = (p: any) => {
    setForm({ name: p.name, html: p.html || '', capture_credentials: p.capture_credentials ?? true, capture_passwords: p.capture_passwords ?? true, redirect_url: p.redirect_url || '' });
    setEditId(p.id);
    setShowForm(true);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="font-display text-xl tracking-wider">LANDING PAGES</h2>
        <Button size="sm" className="font-display tracking-wider bg-green-500 hover:bg-green-600 text-black" onClick={() => { setShowForm(!showForm); setEditId(null); setForm({ name: '', html: '', capture_credentials: true, capture_passwords: true, redirect_url: '' }); }}>
          {showForm ? <><XCircle className="w-4 h-4 mr-2" />CANCEL</> : <><Plus className="w-4 h-4 mr-2" />NEW LANDING PAGE</>}
        </Button>
      </div>

      {showForm && (
        <div className="bg-card border-2 border-green-500/50 p-6 space-y-4">
          <h3 className="font-display text-lg tracking-wider text-green-500">{editId ? 'EDIT' : 'CREATE'} LANDING PAGE</h3>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">PAGE NAME *</label>
              <input type="text" value={form.name} onChange={e => setForm({...form, name: e.target.value})} placeholder="Office 365 Login" className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">REDIRECT URL (after submit)</label>
              <input type="text" value={form.redirect_url} onChange={e => setForm({...form, redirect_url: e.target.value})} placeholder="https://office.com" className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
            </div>
          </div>
          <div className="flex gap-6">
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={form.capture_credentials} onChange={e => setForm({...form, capture_credentials: e.target.checked})} className="rounded" />
              <span>Capture Credentials</span>
            </label>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={form.capture_passwords} onChange={e => setForm({...form, capture_passwords: e.target.checked})} className="rounded" />
              <span>Capture Passwords</span>
            </label>
          </div>
          <div>
            <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">HTML CONTENT *</label>
            <textarea value={form.html} onChange={e => setForm({...form, html: e.target.value})} rows={12} placeholder='<html><body><form method="POST"><input name="username" placeholder="Email"><input name="password" type="password" placeholder="Password"><button type="submit">Sign In</button></form></body></html>' className="w-full px-3 py-2 bg-background border border-border rounded text-sm font-mono" />
          </div>
          <Button className="font-display tracking-wider bg-green-500 hover:bg-green-600 text-black" onClick={handleSave} disabled={isCreating}>
            <Save className="w-4 h-4 mr-2" />{editId ? 'UPDATE PAGE' : 'CREATE PAGE'}
          </Button>
        </div>
      )}

      {Array.isArray(pages) && pages.length > 0 ? (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {pages.map((p: any) => (
            <div key={p.id} className="bg-card border-2 border-border hover:border-green-500 p-4 transition-colors group">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2 min-w-0">
                  <Globe className="w-4 h-4 text-green-500 shrink-0" />
                  <h3 className="font-display text-sm tracking-wider truncate">{p.name}</h3>
                </div>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => startEdit(p)}><Edit className="w-3 h-3" /></Button>
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-red-500" onClick={() => onDelete(p.id)}><Trash2 className="w-3 h-3" /></Button>
                </div>
              </div>
              <div className="flex gap-2 mt-2">
                {p.capture_credentials && <span className="text-[10px] font-display tracking-wider bg-yellow-500/20 text-yellow-400 px-2 py-0.5">CAPTURES CREDS</span>}
                {p.capture_passwords && <span className="text-[10px] font-display tracking-wider bg-red-500/20 text-red-400 px-2 py-0.5">CAPTURES PASSWORDS</span>}
              </div>
              {p.redirect_url && <p className="text-xs text-muted-foreground mt-2">Redirect: {p.redirect_url}</p>}
              <p className="text-xs text-muted-foreground mt-1">Modified: {new Date(p.modified_date).toLocaleDateString()}</p>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState icon={<Globe className="w-12 h-12 text-green-500/50" />} title="NO LANDING PAGES" description="Create landing pages with credential capture forms for phishing simulations." />
      )}
    </div>
  );
}

// ==================== GROUPS PANEL ====================
function GroupsPanel({ groups, onCreate, onUpdate, onDelete, isCreating }: any) {
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState<number | null>(null);
  const [form, setForm] = useState({ name: '', targets: [{ first_name: '', last_name: '', email: '', position: '' }] });

  const addTarget = () => setForm({...form, targets: [...form.targets, { first_name: '', last_name: '', email: '', position: '' }]});
  const removeTarget = (i: number) => setForm({...form, targets: form.targets.filter((_: any, idx: number) => idx !== i)});
  const updateTarget = (i: number, field: string, value: string) => {
    const targets = [...form.targets];
    targets[i] = { ...targets[i], [field]: value };
    setForm({...form, targets});
  };

  const handleSave = () => {
    if (!form.name) { toast.error("Group name is required"); return; }
    const validTargets = form.targets.filter((t: any) => t.email);
    if (validTargets.length === 0) { toast.error("At least one target with email is required"); return; }
    if (editId) {
      onUpdate({ id: editId, name: form.name, targets: validTargets });
      setEditId(null);
    } else {
      onCreate({ name: form.name, targets: validTargets });
    }
    setShowForm(false);
    setForm({ name: '', targets: [{ first_name: '', last_name: '', email: '', position: '' }] });
  };

  const startEdit = (g: any) => {
    setForm({ name: g.name, targets: g.targets?.length > 0 ? g.targets.map((t: any) => ({ first_name: t.first_name || '', last_name: t.last_name || '', email: t.email || '', position: t.position || '' })) : [{ first_name: '', last_name: '', email: '', position: '' }] });
    setEditId(g.id);
    setShowForm(true);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="font-display text-xl tracking-wider">TARGET GROUPS</h2>
        <Button size="sm" className="font-display tracking-wider bg-purple-500 hover:bg-purple-600 text-white" onClick={() => { setShowForm(!showForm); setEditId(null); setForm({ name: '', targets: [{ first_name: '', last_name: '', email: '', position: '' }] }); }}>
          {showForm ? <><XCircle className="w-4 h-4 mr-2" />CANCEL</> : <><Plus className="w-4 h-4 mr-2" />NEW GROUP</>}
        </Button>
      </div>

      {showForm && (
        <div className="bg-card border-2 border-purple-500/50 p-6 space-y-4">
          <h3 className="font-display text-lg tracking-wider text-purple-500">{editId ? 'EDIT' : 'CREATE'} TARGET GROUP</h3>
          <div>
            <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">GROUP NAME *</label>
            <input type="text" value={form.name} onChange={e => setForm({...form, name: e.target.value})} placeholder="IT Department" className="w-full px-3 py-2 bg-background border border-border rounded text-sm max-w-md" />
          </div>
          <div>
            <label className="text-xs font-display tracking-wider text-muted-foreground block mb-2">TARGETS</label>
            <div className="space-y-2">
              {form.targets.map((t: any, i: number) => (
                <div key={i} className="flex gap-2 items-center">
                  <input type="text" value={t.first_name} onChange={e => updateTarget(i, 'first_name', e.target.value)} placeholder="First Name" className="flex-1 px-3 py-2 bg-background border border-border rounded text-sm" />
                  <input type="text" value={t.last_name} onChange={e => updateTarget(i, 'last_name', e.target.value)} placeholder="Last Name" className="flex-1 px-3 py-2 bg-background border border-border rounded text-sm" />
                  <input type="email" value={t.email} onChange={e => updateTarget(i, 'email', e.target.value)} placeholder="email@example.com *" className="flex-1 px-3 py-2 bg-background border border-border rounded text-sm" />
                  <input type="text" value={t.position} onChange={e => updateTarget(i, 'position', e.target.value)} placeholder="Position" className="flex-1 px-3 py-2 bg-background border border-border rounded text-sm" />
                  {form.targets.length > 1 && <Button variant="ghost" size="sm" className="h-9 w-9 p-0 text-red-500" onClick={() => removeTarget(i)}><Trash2 className="w-4 h-4" /></Button>}
                </div>
              ))}
            </div>
            <Button variant="outline" size="sm" className="mt-2 font-display tracking-wider" onClick={addTarget}>
              <Plus className="w-4 h-4 mr-2" />ADD TARGET
            </Button>
          </div>
          <Button className="font-display tracking-wider bg-purple-500 hover:bg-purple-600 text-white" onClick={handleSave} disabled={isCreating}>
            <Save className="w-4 h-4 mr-2" />{editId ? 'UPDATE GROUP' : 'CREATE GROUP'}
          </Button>
        </div>
      )}

      {Array.isArray(groups) && groups.length > 0 ? (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {groups.map((g: any) => (
            <div key={g.id} className="bg-card border-2 border-border hover:border-purple-500 p-4 transition-colors group">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2 min-w-0">
                  <UserPlus className="w-4 h-4 text-purple-500 shrink-0" />
                  <h3 className="font-display text-sm tracking-wider truncate">{g.name}</h3>
                </div>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => startEdit(g)}><Edit className="w-3 h-3" /></Button>
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-red-500" onClick={() => onDelete(g.id)}><Trash2 className="w-3 h-3" /></Button>
                </div>
              </div>
              <p className="text-sm font-display text-purple-400">{g.targets?.length || 0} targets</p>
              {g.targets?.slice(0, 3).map((t: any, i: number) => (
                <p key={i} className="text-xs text-muted-foreground truncate">{t.first_name} {t.last_name} — {t.email}</p>
              ))}
              {g.targets?.length > 3 && <p className="text-xs text-muted-foreground">+{g.targets.length - 3} more</p>}
              <p className="text-xs text-muted-foreground mt-2">Modified: {new Date(g.modified_date).toLocaleDateString()}</p>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState icon={<UserPlus className="w-12 h-12 text-purple-500/50" />} title="NO TARGET GROUPS" description="Create target groups with email addresses for phishing campaigns." />
      )}
    </div>
  );
}

// ==================== SMTP PANEL ====================
function SmtpPanel({ profiles, onCreate, onUpdate, onDelete, isCreating }: any) {
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState<number | null>(null);
  const [form, setForm] = useState({ name: '', host: 'localhost:25', from_address: '', username: '', password: '', ignore_cert_errors: true });

  const handleSave = () => {
    if (!form.name || !form.host || !form.from_address) { toast.error("Name, host, and from address are required"); return; }
    if (editId) {
      onUpdate({ id: editId, ...form });
      setEditId(null);
    } else {
      onCreate(form);
    }
    setShowForm(false);
    setForm({ name: '', host: 'localhost:25', from_address: '', username: '', password: '', ignore_cert_errors: true });
  };

  const startEdit = (s: any) => {
    setForm({ name: s.name, host: s.host || '', from_address: s.from_address || '', username: s.username || '', password: '', ignore_cert_errors: s.ignore_cert_errors ?? true });
    setEditId(s.id);
    setShowForm(true);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="font-display text-xl tracking-wider">SENDING PROFILES</h2>
        <Button size="sm" className="font-display tracking-wider bg-cyan-500 hover:bg-cyan-600 text-black" onClick={() => { setShowForm(!showForm); setEditId(null); setForm({ name: '', host: 'localhost:25', from_address: '', username: '', password: '', ignore_cert_errors: true }); }}>
          {showForm ? <><XCircle className="w-4 h-4 mr-2" />CANCEL</> : <><Plus className="w-4 h-4 mr-2" />NEW PROFILE</>}
        </Button>
      </div>

      {showForm && (
        <div className="bg-card border-2 border-cyan-500/50 p-6 space-y-4">
          <h3 className="font-display text-lg tracking-wider text-cyan-500">{editId ? 'EDIT' : 'CREATE'} SENDING PROFILE</h3>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">PROFILE NAME *</label>
              <input type="text" value={form.name} onChange={e => setForm({...form, name: e.target.value})} placeholder="Internal Relay" className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">SMTP HOST:PORT *</label>
              <input type="text" value={form.host} onChange={e => setForm({...form, host: e.target.value})} placeholder="smtp.example.com:587" className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">FROM ADDRESS *</label>
              <input type="text" value={form.from_address} onChange={e => setForm({...form, from_address: e.target.value})} placeholder="IT Security <security@company.com>" className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">USERNAME (optional)</label>
              <input type="text" value={form.username} onChange={e => setForm({...form, username: e.target.value})} placeholder="smtp_user" className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1">PASSWORD (optional)</label>
              <input type="password" value={form.password} onChange={e => setForm({...form, password: e.target.value})} placeholder="••••••••" className="w-full px-3 py-2 bg-background border border-border rounded text-sm" />
            </div>
            <div className="flex items-center">
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input type="checkbox" checked={form.ignore_cert_errors} onChange={e => setForm({...form, ignore_cert_errors: e.target.checked})} className="rounded" />
                <span>Ignore Certificate Errors</span>
              </label>
            </div>
          </div>
          <Button className="font-display tracking-wider bg-cyan-500 hover:bg-cyan-600 text-black" onClick={handleSave} disabled={isCreating}>
            <Save className="w-4 h-4 mr-2" />{editId ? 'UPDATE PROFILE' : 'CREATE PROFILE'}
          </Button>
        </div>
      )}

      {Array.isArray(profiles) && profiles.length > 0 ? (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {profiles.map((s: any) => (
            <div key={s.id} className="bg-card border-2 border-border hover:border-cyan-500 p-4 transition-colors group">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2 min-w-0">
                  <Send className="w-4 h-4 text-cyan-500 shrink-0" />
                  <h3 className="font-display text-sm tracking-wider truncate">{s.name}</h3>
                </div>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => startEdit(s)}><Edit className="w-3 h-3" /></Button>
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-red-500" onClick={() => onDelete(s.id)}><Trash2 className="w-3 h-3" /></Button>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">Host: {s.host || 'N/A'}</p>
              <p className="text-xs text-muted-foreground">From: {s.from_address || 'N/A'}</p>
              <p className="text-xs text-muted-foreground">Modified: {new Date(s.modified_date).toLocaleDateString()}</p>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState icon={<Send className="w-12 h-12 text-cyan-500/50" />} title="NO SENDING PROFILES" description="Configure SMTP sending profiles for email delivery. Use localhost:25 for the local Postfix relay or configure an external SMTP server." />
      )}
    </div>
  );
}

// ==================== HELPER COMPONENTS ====================
function StatusCard({ label, value, icon, color }: { label: string; value: number | string; icon: React.ReactNode; color: string }) {
  const colorMap: Record<string, string> = {
    orange: 'text-orange-500 bg-orange-500/10 border-orange-500/30',
    blue: 'text-blue-500 bg-blue-500/10 border-blue-500/30',
    green: 'text-green-500 bg-green-500/10 border-green-500/30',
    purple: 'text-purple-500 bg-purple-500/10 border-purple-500/30',
    cyan: 'text-cyan-500 bg-cyan-500/10 border-cyan-500/30',
    emerald: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30',
    red: 'text-red-500 bg-red-500/10 border-red-500/30',
  };
  return (
    <div className={`border-2 p-4 ${colorMap[color] || colorMap.orange}`}>
      <div className="flex items-center gap-2 mb-2">{icon}<span className="text-xs font-display tracking-wider">{label}</span></div>
      <div className="text-2xl font-display">{value}</div>
    </div>
  );
}

function CampaignCard({ campaign, onDelete, onComplete, campaignLinks }: { campaign: any; onDelete: (id: number) => void; onComplete: (id: number) => void; campaignLinks?: any[] }) {
  const linkedEngagement = campaignLinks?.find((link: any) => link.gophishCampaignId === campaign.id);
  const statusColors: Record<string, string> = {
    'In progress': 'bg-green-500/20 text-green-400 border-green-500',
    'Completed': 'bg-blue-500/20 text-blue-400 border-blue-500',
    'Created': 'bg-yellow-500/20 text-yellow-400 border-yellow-500',
    'Queued': 'bg-orange-500/20 text-orange-400 border-orange-500',
  };
  const statusStyle = statusColors[campaign.status] || 'bg-gray-500/20 text-gray-400 border-gray-500';
  const stats = campaign.stats || {};

  return (
    <div className="bg-card border-2 border-border hover:border-orange-500 p-4 transition-colors">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <Send className="w-5 h-5 text-orange-500" />
          <h3 className="font-display text-lg tracking-wider">{campaign.name}</h3>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-xs font-display tracking-wider px-3 py-1 border ${statusStyle}`}>{campaign.status?.toUpperCase() || 'UNKNOWN'}</span>
          {campaign.status !== 'Completed' && <Button variant="ghost" size="sm" className="h-7 text-blue-400" onClick={() => onComplete(campaign.id)}><CheckCircle className="w-4 h-4" /></Button>}
          <Button variant="ghost" size="sm" className="h-7 text-red-500" onClick={() => onDelete(campaign.id)}><Trash2 className="w-4 h-4" /></Button>
        </div>
      </div>
      <div className="grid grid-cols-5 gap-4 mb-3">
        <div className="text-center"><div className="text-lg font-display text-blue-400">{stats.total || 0}</div><div className="text-[10px] font-display tracking-wider text-muted-foreground">TARGETS</div></div>
        <div className="text-center"><div className="text-lg font-display text-cyan-400">{stats.sent || 0}</div><div className="text-[10px] font-display tracking-wider text-muted-foreground">SENT</div></div>
        <div className="text-center"><div className="text-lg font-display text-yellow-400">{stats.opened || 0}</div><div className="text-[10px] font-display tracking-wider text-muted-foreground">OPENED</div></div>
        <div className="text-center"><div className="text-lg font-display text-orange-400">{stats.clicked || 0}</div><div className="text-[10px] font-display tracking-wider text-muted-foreground">CLICKED</div></div>
        <div className="text-center"><div className="text-lg font-display text-red-400">{stats.submitted_data || 0}</div><div className="text-[10px] font-display tracking-wider text-muted-foreground">CREDS</div></div>
      </div>
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <div className="flex items-center gap-3">
          <span>Created: {new Date(campaign.created_date).toLocaleString()}</span>
          {linkedEngagement && (
            <span className="text-primary bg-primary/10 px-2 py-0.5 font-display tracking-wider">
              <Briefcase className="w-3 h-3 inline mr-1" />{linkedEngagement.gophishCampaignName || 'Linked'}
            </span>
          )}
        </div>
        <a href={`https://gophish.aceofcloud.io/campaigns/${campaign.id}`} target="_blank" rel="noopener noreferrer" className="text-orange-500 hover:text-orange-400 font-display tracking-wider flex items-center gap-1">
          VIEW IN GOPHISH <ExternalLink className="w-3 h-3" />
        </a>
      </div>
    </div>
  );
}

function EmptyState({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <div className="bg-card border-2 border-dashed border-border p-12 text-center">
      <div className="flex justify-center mb-4">{icon}</div>
      <h3 className="font-display text-lg tracking-wider mb-2">{title}</h3>
      <p className="text-sm text-muted-foreground max-w-md mx-auto">{description}</p>
    </div>
  );
}

function NavItem({ href, icon, label, active }: { href: string; icon: React.ReactNode; label: string; active?: boolean }) {
  return (
    <Link href={href}>
      <div className={`flex items-center gap-3 px-4 py-3 font-display tracking-wider text-sm transition-colors ${active ? 'bg-primary/20 text-primary border-l-2 border-primary' : 'hover:bg-secondary'}`}>
        {icon}
        {label}
      </div>
    </Link>
  );
}
