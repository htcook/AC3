import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { 
  Cloud, Activity, Key, Users, LogOut, Menu, X, Target, FileText,
  Zap, Cpu, ExternalLink, Mail, Fish, Send, Globe, UserPlus,
  Plus, RefreshCw, CheckCircle, Clock, AlertTriangle, Play,
  Crosshair, BarChart3, MousePointer, ShieldAlert, Eye
} from "lucide-react";
import { useState, useMemo } from "react";

// Sidebar navigation items
const NAV_ITEMS = [
  { href: "/dashboard", icon: <Activity className="w-4 h-4" />, label: "DASHBOARD" },
  { href: "/credentials", icon: <Key className="w-4 h-4" />, label: "CREDENTIALS" },
  { href: "/adversaries", icon: <Target className="w-4 h-4" />, label: "ADVERSARIES" },
  { href: "/agents", icon: <Cpu className="w-4 h-4" />, label: "AGENTS" },
  { href: "/campaigns", icon: <Crosshair className="w-4 h-4" />, label: "CAMPAIGNS" },
  { href: "/gophish", icon: <Fish className="w-4 h-4" />, label: "GOPHISH" },
  { href: "/team", icon: <Users className="w-4 h-4" />, label: "TEAM" },
  { href: "/activity", icon: <FileText className="w-4 h-4" />, label: "ACTIVITY" },
];

export default function GoPhish() {
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'campaigns' | 'templates' | 'pages' | 'groups' | 'smtp'>('overview');

  // Fetch GoPhish data
  const { data: status, refetch: refetchStatus } = trpc.gophishProxy.getStatus.useQuery(undefined, {
    refetchInterval: 30000,
  });
  const { data: campaigns, refetch: refetchCampaigns } = trpc.gophishProxy.getCampaigns.useQuery(undefined, {
    enabled: activeTab === 'campaigns' || activeTab === 'overview',
  });
  const { data: templates } = trpc.gophishProxy.getTemplates.useQuery(undefined, {
    enabled: activeTab === 'templates' || activeTab === 'overview',
  });
  const { data: landingPages } = trpc.gophishProxy.getLandingPages.useQuery(undefined, {
    enabled: activeTab === 'pages' || activeTab === 'overview',
  });
  const { data: groups } = trpc.gophishProxy.getGroups.useQuery(undefined, {
    enabled: activeTab === 'groups' || activeTab === 'overview',
  });
  const { data: sendingProfiles } = trpc.gophishProxy.getSendingProfiles.useQuery(undefined, {
    enabled: activeTab === 'smtp' || activeTab === 'overview',
  });

  // Caldera health check
  const { data: calderaHealth } = trpc.calderaProxy.checkHealth.useQuery();

  const handleRefresh = () => {
    refetchStatus();
    refetchCampaigns();
    toast.success("Refreshing GoPhish data...");
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
                <span className="text-[10px] text-muted-foreground tracking-widest">GOPHISH MANAGER</span>
              </div>
            </Link>
          </div>
          <nav className="flex-1 p-4 space-y-2">
            {NAV_ITEMS.map(item => (
              <NavItem key={item.href} href={item.href} icon={item.icon} label={item.label} active={item.href === '/gophish'} />
            ))}
          </nav>
          <div className="p-4 border-t border-border">
            <Link href="/">
              <Button variant="outline" size="sm" className="w-full font-display tracking-wider">
                <LogOut className="w-4 h-4 mr-2" />EXIT
              </Button>
            </Link>
          </div>
        </div>
      </aside>

      {/* Mobile overlay */}
      {sidebarOpen && <div className="fixed inset-0 bg-black/50 z-40 lg:hidden" onClick={() => setSidebarOpen(false)} />}

      {/* Main content */}
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
              <a href="https://137.184.7.224:3333" target="_blank" rel="noopener noreferrer">
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
              {/* Status Cards */}
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
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Bridge Service</span>
                        <span className="text-xs font-display tracking-wider text-green-400 bg-green-500/20 px-2 py-0.5">RUNNING</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Auto-trigger on Credential Capture</span>
                        <span className="text-xs font-display tracking-wider text-green-400 bg-green-500/20 px-2 py-0.5">ENABLED</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Monitoring Interval</span>
                        <span className="text-xs font-display tracking-wider text-blue-400">30 SECONDS</span>
                      </div>
                    </div>
                  </div>
                  <div className="space-y-3">
                    <h3 className="font-display text-sm tracking-wider text-muted-foreground">WORKFLOW</h3>
                    <div className="bg-background/50 border border-border p-4 space-y-3">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-orange-500/20 flex items-center justify-center text-orange-500 font-display text-xs">1</div>
                        <span className="text-sm">GoPhish sends phishing email</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-yellow-500/20 flex items-center justify-center text-yellow-500 font-display text-xs">2</div>
                        <span className="text-sm">Target clicks link / submits credentials</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-red-500/20 flex items-center justify-center text-red-500 font-display text-xs">3</div>
                        <span className="text-sm">Bridge detects event &amp; triggers Caldera</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-emerald-500/20 flex items-center justify-center text-emerald-500 font-display text-xs">4</div>
                        <span className="text-sm">Caldera launches post-exploitation operation</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Server Details */}
              <div className="grid md:grid-cols-2 gap-6">
                <div className="bg-card border-2 border-border p-6">
                  <h3 className="font-display text-lg tracking-wider mb-4 flex items-center gap-2">
                    <Fish className="w-5 h-5 text-orange-500" />
                    GOPHISH SERVER
                  </h3>
                  <div className="space-y-3 text-sm">
                    <div className="flex justify-between"><span className="text-muted-foreground">Admin URL</span><span className="font-mono text-orange-400">https://137.184.7.224:3333</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Phishing Server</span><span className="font-mono text-orange-400">http://137.184.7.224:8080</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Username</span><span className="font-mono">admin</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Password</span><span className="font-mono">ADMIN123</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Version</span><span className="font-mono">0.12.1</span></div>
                  </div>
                </div>
                <div className="bg-card border-2 border-border p-6">
                  <h3 className="font-display text-lg tracking-wider mb-4 flex items-center gap-2">
                    <ShieldAlert className="w-5 h-5 text-red-500" />
                    CALDERA SERVER
                  </h3>
                  <div className="space-y-3 text-sm">
                    <div className="flex justify-between"><span className="text-muted-foreground">API URL</span><span className="font-mono text-red-400">http://137.184.7.224:8888</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">UI URL</span><span className="font-mono text-red-400">http://137.184.7.224:8888</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Username</span><span className="font-mono">red</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">API Key</span><span className="font-mono">ADMIN123</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Version</span><span className="font-mono">5.3.0</span></div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Campaigns Tab */}
          {activeTab === 'campaigns' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="font-display text-xl tracking-wider">PHISHING CAMPAIGNS</h2>
                <a href="https://137.184.7.224:3333/campaigns" target="_blank" rel="noopener noreferrer">
                  <Button size="sm" className="font-display tracking-wider bg-orange-500 hover:bg-orange-600 text-black">
                    <Plus className="w-4 h-4 mr-2" />NEW CAMPAIGN IN GOPHISH
                  </Button>
                </a>
              </div>
              {Array.isArray(campaigns) && campaigns.length > 0 ? (
                <div className="space-y-3">
                  {campaigns.map((campaign: any) => (
                    <CampaignCard key={campaign.id} campaign={campaign} />
                  ))}
                </div>
              ) : (
                <EmptyState
                  icon={<Send className="w-12 h-12 text-orange-500/50" />}
                  title="NO CAMPAIGNS YET"
                  description="Create your first phishing campaign in GoPhish to see it here. Campaigns will automatically integrate with Caldera operations."
                  actionLabel="OPEN GOPHISH"
                  actionHref="https://137.184.7.224:3333/campaigns"
                />
              )}
            </div>
          )}

          {/* Templates Tab */}
          {activeTab === 'templates' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="font-display text-xl tracking-wider">EMAIL TEMPLATES</h2>
                <a href="https://137.184.7.224:3333/templates" target="_blank" rel="noopener noreferrer">
                  <Button size="sm" className="font-display tracking-wider bg-blue-500 hover:bg-blue-600 text-white">
                    <Plus className="w-4 h-4 mr-2" />NEW TEMPLATE IN GOPHISH
                  </Button>
                </a>
              </div>
              {Array.isArray(templates) && templates.length > 0 ? (
                <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {templates.map((template: any) => (
                    <div key={template.id} className="bg-card border-2 border-border hover:border-blue-500 p-4 transition-colors">
                      <div className="flex items-center gap-2 mb-2">
                        <Mail className="w-4 h-4 text-blue-500" />
                        <h3 className="font-display text-sm tracking-wider truncate">{template.name}</h3>
                      </div>
                      <p className="text-xs text-muted-foreground mb-2">Subject: {template.subject || 'N/A'}</p>
                      <p className="text-xs text-muted-foreground">Modified: {new Date(template.modified_date).toLocaleDateString()}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  icon={<Mail className="w-12 h-12 text-blue-500/50" />}
                  title="NO EMAIL TEMPLATES"
                  description="Create email templates in GoPhish to use in phishing campaigns."
                  actionLabel="CREATE TEMPLATE"
                  actionHref="https://137.184.7.224:3333/templates"
                />
              )}
            </div>
          )}

          {/* Landing Pages Tab */}
          {activeTab === 'pages' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="font-display text-xl tracking-wider">LANDING PAGES</h2>
                <a href="https://137.184.7.224:3333/landing_pages" target="_blank" rel="noopener noreferrer">
                  <Button size="sm" className="font-display tracking-wider bg-green-500 hover:bg-green-600 text-black">
                    <Plus className="w-4 h-4 mr-2" />NEW PAGE IN GOPHISH
                  </Button>
                </a>
              </div>
              {Array.isArray(landingPages) && landingPages.length > 0 ? (
                <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {landingPages.map((page: any) => (
                    <div key={page.id} className="bg-card border-2 border-border hover:border-green-500 p-4 transition-colors">
                      <div className="flex items-center gap-2 mb-2">
                        <Globe className="w-4 h-4 text-green-500" />
                        <h3 className="font-display text-sm tracking-wider truncate">{page.name}</h3>
                      </div>
                      <div className="flex gap-2 mt-2">
                        {page.capture_credentials && <span className="text-[10px] font-display tracking-wider bg-yellow-500/20 text-yellow-400 px-2 py-0.5">CAPTURES CREDS</span>}
                        {page.capture_passwords && <span className="text-[10px] font-display tracking-wider bg-red-500/20 text-red-400 px-2 py-0.5">CAPTURES PASSWORDS</span>}
                      </div>
                      <p className="text-xs text-muted-foreground mt-2">Modified: {new Date(page.modified_date).toLocaleDateString()}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  icon={<Globe className="w-12 h-12 text-green-500/50" />}
                  title="NO LANDING PAGES"
                  description="Create landing pages in GoPhish for credential capture and phishing simulations."
                  actionLabel="CREATE PAGE"
                  actionHref="https://137.184.7.224:3333/landing_pages"
                />
              )}
            </div>
          )}

          {/* Target Groups Tab */}
          {activeTab === 'groups' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="font-display text-xl tracking-wider">TARGET GROUPS</h2>
                <a href="https://137.184.7.224:3333/users" target="_blank" rel="noopener noreferrer">
                  <Button size="sm" className="font-display tracking-wider bg-purple-500 hover:bg-purple-600 text-white">
                    <Plus className="w-4 h-4 mr-2" />NEW GROUP IN GOPHISH
                  </Button>
                </a>
              </div>
              {Array.isArray(groups) && groups.length > 0 ? (
                <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {groups.map((group: any) => (
                    <div key={group.id} className="bg-card border-2 border-border hover:border-purple-500 p-4 transition-colors">
                      <div className="flex items-center gap-2 mb-2">
                        <UserPlus className="w-4 h-4 text-purple-500" />
                        <h3 className="font-display text-sm tracking-wider truncate">{group.name}</h3>
                      </div>
                      <p className="text-xs text-muted-foreground">{group.targets?.length || 0} targets</p>
                      <p className="text-xs text-muted-foreground">Modified: {new Date(group.modified_date).toLocaleDateString()}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  icon={<UserPlus className="w-12 h-12 text-purple-500/50" />}
                  title="NO TARGET GROUPS"
                  description="Create target groups in GoPhish with email addresses for phishing campaigns."
                  actionLabel="CREATE GROUP"
                  actionHref="https://137.184.7.224:3333/users"
                />
              )}
            </div>
          )}

          {/* Sending Profiles Tab */}
          {activeTab === 'smtp' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="font-display text-xl tracking-wider">SENDING PROFILES</h2>
                <a href="https://137.184.7.224:3333/sending_profiles" target="_blank" rel="noopener noreferrer">
                  <Button size="sm" className="font-display tracking-wider bg-cyan-500 hover:bg-cyan-600 text-black">
                    <Plus className="w-4 h-4 mr-2" />NEW PROFILE IN GOPHISH
                  </Button>
                </a>
              </div>
              {Array.isArray(sendingProfiles) && sendingProfiles.length > 0 ? (
                <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {sendingProfiles.map((profile: any) => (
                    <div key={profile.id} className="bg-card border-2 border-border hover:border-cyan-500 p-4 transition-colors">
                      <div className="flex items-center gap-2 mb-2">
                        <Send className="w-4 h-4 text-cyan-500" />
                        <h3 className="font-display text-sm tracking-wider truncate">{profile.name}</h3>
                      </div>
                      <p className="text-xs text-muted-foreground">Host: {profile.host || 'N/A'}</p>
                      <p className="text-xs text-muted-foreground">From: {profile.from_address || 'N/A'}</p>
                      <p className="text-xs text-muted-foreground">Modified: {new Date(profile.modified_date).toLocaleDateString()}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  icon={<Send className="w-12 h-12 text-cyan-500/50" />}
                  title="NO SENDING PROFILES"
                  description="Configure SMTP sending profiles in GoPhish for email delivery."
                  actionLabel="CREATE PROFILE"
                  actionHref="https://137.184.7.224:3333/sending_profiles"
                />
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

// Status card component
function StatusCard({ label, value, icon, color }: { label: string; value: number | string; icon: React.ReactNode; color: string }) {
  const colorMap: Record<string, string> = {
    orange: 'text-orange-500 bg-orange-500/10 border-orange-500/30',
    blue: 'text-blue-500 bg-blue-500/10 border-blue-500/30',
    green: 'text-green-500 bg-green-500/10 border-green-500/30',
    purple: 'text-purple-500 bg-purple-500/10 border-purple-500/30',
    cyan: 'text-cyan-500 bg-cyan-500/10 border-cyan-500/30',
    emerald: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30',
    red: 'text-red-500 bg-red-500/10 border-red-500/30',
    yellow: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30',
  };
  return (
    <div className={`border-2 p-4 ${colorMap[color] || colorMap.orange}`}>
      <div className="flex items-center gap-2 mb-2">{icon}<span className="text-xs font-display tracking-wider">{label}</span></div>
      <div className="text-2xl font-display">{value}</div>
    </div>
  );
}

// Campaign card component
function CampaignCard({ campaign }: { campaign: any }) {
  const statusColors: Record<string, string> = {
    'In progress': 'bg-green-500/20 text-green-400 border-green-500',
    'Completed': 'bg-blue-500/20 text-blue-400 border-blue-500',
    'Created': 'bg-yellow-500/20 text-yellow-400 border-yellow-500',
    'Queued': 'bg-orange-500/20 text-orange-400 border-orange-500',
  };
  const statusStyle = statusColors[campaign.status] || 'bg-gray-500/20 text-gray-400 border-gray-500';

  const stats = campaign.stats || {};
  const totalTargets = stats.total || 0;
  const sent = stats.sent || 0;
  const opened = stats.opened || 0;
  const clicked = stats.clicked || 0;
  const submitted = stats.submitted_data || 0;

  return (
    <div className="bg-card border-2 border-border hover:border-orange-500 p-4 transition-colors">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <Send className="w-5 h-5 text-orange-500" />
          <h3 className="font-display text-lg tracking-wider">{campaign.name}</h3>
        </div>
        <span className={`text-xs font-display tracking-wider px-3 py-1 border ${statusStyle}`}>
          {campaign.status?.toUpperCase() || 'UNKNOWN'}
        </span>
      </div>
      <div className="grid grid-cols-5 gap-4 mb-3">
        <div className="text-center">
          <div className="text-lg font-display text-blue-400">{totalTargets}</div>
          <div className="text-[10px] font-display tracking-wider text-muted-foreground">TARGETS</div>
        </div>
        <div className="text-center">
          <div className="text-lg font-display text-cyan-400">{sent}</div>
          <div className="text-[10px] font-display tracking-wider text-muted-foreground">SENT</div>
        </div>
        <div className="text-center">
          <div className="text-lg font-display text-yellow-400">{opened}</div>
          <div className="text-[10px] font-display tracking-wider text-muted-foreground">OPENED</div>
        </div>
        <div className="text-center">
          <div className="text-lg font-display text-orange-400">{clicked}</div>
          <div className="text-[10px] font-display tracking-wider text-muted-foreground">CLICKED</div>
        </div>
        <div className="text-center">
          <div className="text-lg font-display text-red-400">{submitted}</div>
          <div className="text-[10px] font-display tracking-wider text-muted-foreground">CREDS</div>
        </div>
      </div>
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>Created: {new Date(campaign.created_date).toLocaleString()}</span>
        <a href={`https://137.184.7.224:3333/campaigns/${campaign.id}`} target="_blank" rel="noopener noreferrer" className="text-orange-500 hover:text-orange-400 font-display tracking-wider flex items-center gap-1">
          VIEW IN GOPHISH <ExternalLink className="w-3 h-3" />
        </a>
      </div>
    </div>
  );
}

// Empty state component
function EmptyState({ icon, title, description, actionLabel, actionHref }: { icon: React.ReactNode; title: string; description: string; actionLabel: string; actionHref: string }) {
  return (
    <div className="bg-card border-2 border-dashed border-border p-12 text-center">
      <div className="flex justify-center mb-4">{icon}</div>
      <h3 className="font-display text-lg tracking-wider mb-2">{title}</h3>
      <p className="text-sm text-muted-foreground mb-4 max-w-md mx-auto">{description}</p>
      <a href={actionHref} target="_blank" rel="noopener noreferrer">
        <Button className="font-display tracking-wider bg-orange-500 hover:bg-orange-600 text-black">
          <ExternalLink className="w-4 h-4 mr-2" />{actionLabel}
        </Button>
      </a>
    </div>
  );
}

// NavItem component
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
