import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { 
  Activity, 
  Terminal, 
  Users, 
  Key,
  ExternalLink,
  RefreshCw,
  Server,
  Cpu,
  HardDrive,
  Clock,
  Copy,
  LogOut,
  Menu,
  X,
  ChevronRight,
  Zap,
  Target,
  FileText,
  Cloud,
  BookOpen,
  Fish,
  Mail,
  MousePointerClick,
  Eye,
  FileWarning,
  Send,
  LayoutTemplate,
  Globe,
  UserCheck,
  Shield,
  Globe2,
  Briefcase
} from "lucide-react";
import { useState, useEffect } from "react";

import AppShell from "@/components/AppShell";
// Default server config for the DigitalOcean deployment
const DEFAULT_SERVER = {
  id: 1,
  name: "Caldera Production",
  ipAddress: "137.184.7.224",
  httpsUrl: "https://dashboard.aceofcloud.io",
  httpUrl: "https://caldera.aceofcloud.io",
  region: "San Francisco (sfo3)",
  dropletSize: "s-2vcpu-4gb",
  status: "online" as const,
};

export default function Dashboard() {
  const [, navigate] = useLocation();
  const [serverStatus, setServerStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const [gophishStatus, setGophishStatus] = useState<'online' | 'offline' | 'checking'>('checking');

  // Live stats from DigitalOcean Caldera API via server proxy
  const { data: stats, refetch: refetchStats } = trpc.calderaProxy.getStats.useQuery(undefined, {
    refetchInterval: 30000,
  });

  const calderaStats = stats || {
    totalAdversaries: 0,
    totalAbilities: 0,
    activeOperations: 0,
    totalAgents: 0,
  };

  // Check server health via server proxy
  const { data: healthData } = trpc.calderaProxy.checkHealth.useQuery(undefined, {
    refetchInterval: 30000,
  });

  // GoPhish stats
  const { data: gophishData, refetch: refetchGophish } = trpc.gophishProxy.getStats.useQuery(undefined, {
    refetchInterval: 30000,
  });

  useEffect(() => {
    if (healthData !== undefined) {
      setServerStatus(healthData ? 'online' : 'offline');
    }
  }, [healthData]);

  useEffect(() => {
    if (gophishData !== undefined) {
      setGophishStatus(gophishData.online ? 'online' : 'offline');
    }
  }, [gophishData]);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  const refreshAll = () => {
    refetchStats();
    refetchGophish();
    toast.success('Refreshing all data...');
  };

  // Compute GoPhish metrics
  const gophish = gophishData || {
    online: false,
    totalCampaigns: 0,
    activeCampaigns: 0,
    completedCampaigns: 0,
    totalTemplates: 0,
    totalLandingPages: 0,
    totalGroups: 0,
    totalSendingProfiles: 0,
    totalTargets: 0,
    emailMetrics: { sent: 0, opened: 0, clicked: 0, submitted: 0, reported: 0 },
    recentEvents: [] as Array<{ time: string; message: string; campaign: string; status: string }>,
    campaigns: [] as Array<{ id: number; name: string; status: string; created_date: string; completed_date: string; stats: any }>,
  };

  const openRate = gophish.emailMetrics.sent > 0 ? ((gophish.emailMetrics.opened / gophish.emailMetrics.sent) * 100).toFixed(1) : '0';
  const clickRate = gophish.emailMetrics.sent > 0 ? ((gophish.emailMetrics.clicked / gophish.emailMetrics.sent) * 100).toFixed(1) : '0';
  const submitRate = gophish.emailMetrics.sent > 0 ? ((gophish.emailMetrics.submitted / gophish.emailMetrics.sent) * 100).toFixed(1) : '0';

  return (
    <AppShell activePath="/dashboard">
{/* Sidebar */}
{/* Header */}
        <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4 flex items-center justify-between">
            <div>
              <h1 className="font-display text-3xl md:text-2xl sm:text-3xl lg:text-4xl">COMMAND CENTER</h1>
              <p className="text-sm text-muted-foreground">Unified server and campaign monitoring dashboard</p>
            </div>
            <div className="flex items-center gap-4">
              <Button variant="outline" className="font-display tracking-wider border-2" onClick={refreshAll}>
                <RefreshCw className="w-4 h-4 mr-2" />
                REFRESH ALL
              </Button>
              <a href={DEFAULT_SERVER.httpUrl} target="_blank" rel="noopener noreferrer">
                <Button variant="outline" className="font-display tracking-wider border-2">
                  <ExternalLink className="w-4 h-4 mr-2" />
                  CALDERA UI
                </Button>
              </a>
            </div>
          </div>
          {/* Divider */}
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">

          {/* ═══════════════════════════════════════════════════════════════ */}
          {/* SERVER STATUS — Both Caldera and GoPhish side by side         */}
          {/* ═══════════════════════════════════════════════════════════════ */}
          <section>
            <h2 className="font-display text-2xl mb-4">SERVER STATUS</h2>
            <div className="grid md:grid-cols-2 gap-4">
              {/* Caldera Server */}
              <a href={DEFAULT_SERVER.httpUrl} target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border p-6 cursor-pointer hover:border-primary transition-colors group block">
                <div className="flex items-center gap-4 mb-4">
                  <div className={`w-4 h-4 ${serverStatus === 'online' ? 'bg-green-500' : serverStatus === 'offline' ? 'bg-red-500' : 'bg-yellow-500 animate-pulse'}`} />
                  <div className="flex-1">
                    <h3 className="font-display text-lg">CALDERA SERVER</h3>
                    <p className="text-xs text-muted-foreground">{DEFAULT_SERVER.ipAddress}:8888</p>
                  </div>
                  <span className={`px-2 py-1 text-xs font-display tracking-wider ${serverStatus === 'online' ? 'bg-green-500/20 text-green-400 border border-green-500/30' : serverStatus === 'offline' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'}`}>
                    {serverStatus.toUpperCase()}
                  </span>
                </div>
                <div className="flex flex-wrap gap-3">
                  <StatusBadge icon={<Server />} label="REGION" value={DEFAULT_SERVER.region} />
                  <StatusBadge icon={<Cpu />} label="SIZE" value={DEFAULT_SERVER.dropletSize} />
                </div>
                <div className="text-[10px] mt-3 text-muted-foreground tracking-wider opacity-0 group-hover:opacity-100 transition-opacity text-center">OPEN CALDERA UI →</div>
              </a>

              {/* GoPhish Server */}
              <a href="https://gophish.aceofcloud.io" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-emerald-500/30 p-6 cursor-pointer hover:border-emerald-500 transition-colors group block">
                <div className="flex items-center gap-4 mb-4">
                  <div className={`w-4 h-4 ${gophishStatus === 'online' ? 'bg-emerald-500' : gophishStatus === 'offline' ? 'bg-red-500' : 'bg-yellow-500 animate-pulse'}`} />
                  <div className="flex-1">
                    <h3 className="font-display text-lg text-emerald-500">GOPHISH SERVER</h3>
                    <p className="text-xs text-muted-foreground">{DEFAULT_SERVER.ipAddress}:3333</p>
                  </div>
                  <span className={`px-2 py-1 text-xs font-display tracking-wider ${gophishStatus === 'online' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : gophishStatus === 'offline' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'}`}>
                    {gophishStatus.toUpperCase()}
                  </span>
                </div>
                <div className="flex flex-wrap gap-3">
                  <StatusBadge icon={<Fish />} label="CAMPAIGNS" value={`${gophish.totalCampaigns} total`} />
                  <StatusBadge icon={<Mail />} label="ACTIVE" value={`${gophish.activeCampaigns} running`} />
                </div>
                <div className="text-[10px] mt-3 text-emerald-500/70 tracking-wider opacity-0 group-hover:opacity-100 transition-opacity text-center">OPEN GOPHISH ADMIN →</div>
              </a>
            </div>
          </section>

          {/* Divider */}
          <div className="w-full h-0.5 bg-primary" />

          {/* ═══════════════════════════════════════════════════════════════ */}
          {/* CALDERA STATISTICS                                            */}
          {/* ═══════════════════════════════════════════════════════════════ */}
          <section>
            <h2 className="font-display text-2xl mb-4">CALDERA STATISTICS</h2>
            <div className="grid grid-cols-2 lg:grid-cols-2 sm:grid-cols-2 lg:grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard value={calderaStats.totalAdversaries.toString()} label="ADVERSARIES" color="text-white" href="/adversaries" />
              <StatCard value={calderaStats.totalAbilities.toString()} label="ABILITIES" color="text-white" href="https://caldera.aceofcloud.io/#/abilities" external />
              <StatCard value={calderaStats.activeOperations.toString()} label="OPERATIONS" color="text-white" href="/operations/monitor" />
              <StatCard value={calderaStats.totalAgents.toString()} label="AGENTS" color="text-white" href="/agents" />
            </div>
          </section>

          {/* Divider */}
          <div className="w-full h-0.5 bg-emerald-500/50" />

          {/* ═══════════════════════════════════════════════════════════════ */}
          {/* GOPHISH STATISTICS                                            */}
          {/* ═══════════════════════════════════════════════════════════════ */}
          <section>
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-display text-2xl flex items-center gap-2">
                <Fish className="w-6 h-6 text-emerald-500" />
                GOPHISH STATISTICS
              </h2>
              <a href="https://gophish.aceofcloud.io" target="_blank" rel="noopener noreferrer">
                <Button variant="outline" size="sm" className="font-display tracking-wider border-emerald-500/50 text-emerald-500 hover:bg-emerald-500/10">
                  <ExternalLink className="w-4 h-4 mr-1" />
                  GOPHISH ADMIN
                </Button>
              </a>
            </div>

            {/* Top-level GoPhish counts */}
            <div className="grid grid-cols-2 lg:grid-cols-2 sm:grid-cols-2 lg:grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
              <StatCard value={gophish.totalCampaigns.toString()} label="CAMPAIGNS" color="text-emerald-500" href="/gophish" />
              <StatCard value={gophish.totalTemplates.toString()} label="TEMPLATES" color="text-emerald-500" href="https://gophish.aceofcloud.io/templates" external />
              <StatCard value={gophish.totalLandingPages.toString()} label="LANDING PAGES" color="text-emerald-500" href="https://gophish.aceofcloud.io/landing_pages" external />
              <StatCard value={gophish.totalSendingProfiles.toString()} label="SMTP PROFILES" color="text-emerald-500" href="https://gophish.aceofcloud.io/sending_profiles" external />
            </div>

            {/* Email Metrics Funnel */}
            <h3 className="font-display text-lg mb-3 text-muted-foreground">EMAIL METRICS</h3>
            <div className="grid grid-cols-2 lg:grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
              <MetricCard icon={<Send />} value={gophish.emailMetrics.sent} label="EMAILS SENT" color="text-emerald-500" href="/gophish" />
              <MetricCard icon={<Eye />} value={gophish.emailMetrics.opened} label="OPENED" subtext={`${openRate}% rate`} color="text-blue-400" href="/gophish" />
              <MetricCard icon={<MousePointerClick />} value={gophish.emailMetrics.clicked} label="CLICKED" subtext={`${clickRate}% rate`} color="text-yellow-400" href="/gophish" />
              <MetricCard icon={<UserCheck />} value={gophish.emailMetrics.submitted} label="SUBMITTED" subtext={`${submitRate}% rate`} color="text-red-400" href="/gophish" />
              <MetricCard icon={<FileWarning />} value={gophish.emailMetrics.reported} label="REPORTED" color="text-purple-400" href="/gophish" />
            </div>

            {/* Campaign Breakdown + GoPhish Resources */}
            <div className="grid md:grid-cols-2 gap-4">
              {/* Campaign Status Breakdown */}
              <div className="bg-card border-2 border-emerald-500/30 p-5">
                <h3 className="font-display text-lg mb-4 text-emerald-500">CAMPAIGN STATUS</h3>
                <div className="space-y-3">
                  <Link href="/gophish" className="group flex items-center justify-between cursor-pointer hover:bg-emerald-500/5 -mx-2 px-2 py-1 rounded transition-colors">
                    <span className="text-sm text-muted-foreground group-hover:text-emerald-400 transition-colors">Active Campaigns</span>
                    <div className="flex items-center gap-2">
                      <span className="font-display text-lg text-emerald-400">{gophish.activeCampaigns}</span>
                      <ChevronRight className="w-4 h-4 text-emerald-500 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </Link>
                  <div className="w-full h-px bg-border" />
                  <Link href="/gophish" className="group flex items-center justify-between cursor-pointer hover:bg-emerald-500/5 -mx-2 px-2 py-1 rounded transition-colors">
                    <span className="text-sm text-muted-foreground group-hover:text-blue-400 transition-colors">Completed Campaigns</span>
                    <div className="flex items-center gap-2">
                      <span className="font-display text-lg text-blue-400">{gophish.completedCampaigns}</span>
                      <ChevronRight className="w-4 h-4 text-blue-500 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </Link>
                  <div className="w-full h-px bg-border" />
                  <a href="https://gophish.aceofcloud.io/users" target="_blank" rel="noopener noreferrer" className="group flex items-center justify-between cursor-pointer hover:bg-emerald-500/5 -mx-2 px-2 py-1 rounded transition-colors">
                    <span className="text-sm text-muted-foreground group-hover:text-yellow-400 transition-colors">Total Targets</span>
                    <div className="flex items-center gap-2">
                      <span className="font-display text-lg text-yellow-400">{gophish.totalTargets}</span>
                      <ExternalLink className="w-3 h-3 text-yellow-500 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </a>
                  <div className="w-full h-px bg-border" />
                  <a href="https://gophish.aceofcloud.io/users" target="_blank" rel="noopener noreferrer" className="group flex items-center justify-between cursor-pointer hover:bg-emerald-500/5 -mx-2 px-2 py-1 rounded transition-colors">
                    <span className="text-sm text-muted-foreground group-hover:text-purple-400 transition-colors">Target Groups</span>
                    <div className="flex items-center gap-2">
                      <span className="font-display text-lg text-purple-400">{gophish.totalGroups}</span>
                      <ExternalLink className="w-3 h-3 text-purple-500 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </a>
                </div>
              </div>

              {/* GoPhish Resources */}
              <div className="bg-card border-2 border-emerald-500/30 p-5">
                <h3 className="font-display text-lg mb-4 text-emerald-500">GOPHISH RESOURCES</h3>
                <div className="space-y-3">
                  <ResourceRow icon={<LayoutTemplate />} label="Email Templates" count={gophish.totalTemplates} href="https://gophish.aceofcloud.io/templates" external />
                  <div className="w-full h-px bg-border" />
                  <ResourceRow icon={<Globe />} label="Landing Pages" count={gophish.totalLandingPages} href="https://gophish.aceofcloud.io/landing_pages" external />
                  <div className="w-full h-px bg-border" />
                  <ResourceRow icon={<Send />} label="Sending Profiles (SMTP)" count={gophish.totalSendingProfiles} href="https://gophish.aceofcloud.io/sending_profiles" external />
                  <div className="w-full h-px bg-border" />
                  <ResourceRow icon={<Users />} label="Target Groups" count={gophish.totalGroups} href="https://gophish.aceofcloud.io/users" external />
                </div>
              </div>
            </div>

            {/* Recent Campaign Activity */}
            {gophish.campaigns.length > 0 && (
              <div className="mt-4">
                <h3 className="font-display text-lg mb-3 text-muted-foreground">RECENT CAMPAIGNS</h3>
                <div className="bg-card border-2 border-border overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border bg-secondary/50">
                        <th className="text-left text-xs font-display tracking-wider text-muted-foreground px-4 py-3">CAMPAIGN</th>
                        <th className="text-left text-xs font-display tracking-wider text-muted-foreground px-4 py-3">STATUS</th>
                        <th className="text-center text-xs font-display tracking-wider text-muted-foreground px-4 py-3">SENT</th>
                        <th className="text-center text-xs font-display tracking-wider text-muted-foreground px-4 py-3">OPENED</th>
                        <th className="text-center text-xs font-display tracking-wider text-muted-foreground px-4 py-3">CLICKED</th>
                        <th className="text-center text-xs font-display tracking-wider text-muted-foreground px-4 py-3">SUBMITTED</th>
                        <th className="text-left text-xs font-display tracking-wider text-muted-foreground px-4 py-3">CREATED</th>
                      </tr>
                    </thead>
                    <tbody>
                      {gophish.campaigns.slice(0, 5).map((campaign) => (
                        <tr key={campaign.id} className="border-b border-border/50 hover:bg-secondary/30 transition-colors">
                          <td className="px-4 py-3">
                            <Link href={`/campaigns/${campaign.id}`} className="text-sm font-medium hover:text-emerald-500 transition-colors">
                              {campaign.name}
                            </Link>
                          </td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-0.5 text-[10px] font-display tracking-wider ${
                              campaign.status === 'In progress' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                              campaign.status === 'Completed' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                              'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                            }`}>
                              {campaign.status?.toUpperCase() || 'UNKNOWN'}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-center text-sm">{campaign.stats?.sent || 0}</td>
                          <td className="px-4 py-3 text-center text-sm text-blue-400">{campaign.stats?.opened || 0}</td>
                          <td className="px-4 py-3 text-center text-sm text-yellow-400">{campaign.stats?.clicked || 0}</td>
                          <td className="px-4 py-3 text-center text-sm text-red-400">{campaign.stats?.submitted_data || 0}</td>
                          <td className="px-4 py-3 text-xs text-muted-foreground">
                            {campaign.created_date ? new Date(campaign.created_date).toLocaleDateString() : '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {gophish.campaigns.length === 0 && (
                    <div className="p-4 sm:p-6 lg:p-8 text-center text-muted-foreground">
                      <Fish className="w-8 h-8 mx-auto mb-2 opacity-50" />
                      <p className="text-sm">No campaigns found. Launch your first campaign from the GoPhish page.</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* GoPhish Recent Events */}
            {gophish.recentEvents.length > 0 && (
              <div className="mt-4">
                <h3 className="font-display text-lg mb-3 text-muted-foreground">RECENT ACTIVITY</h3>
                <div className="bg-card border-2 border-border p-4 space-y-2 max-h-64 overflow-y-auto">
                  {gophish.recentEvents.map((event, i) => (
                    <div key={i} className="flex items-start gap-3 py-2 border-b border-border/30 last:border-0">
                      <div className="w-2 h-2 mt-1.5 bg-emerald-500 shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm truncate">{event.message || event.status}</p>
                        <p className="text-xs text-muted-foreground">{event.campaign}</p>
                      </div>
                      <span className="text-xs text-muted-foreground shrink-0">
                        {event.time ? new Date(event.time).toLocaleString() : ''}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>

          {/* Divider */}
          <div className="w-full h-0.5 bg-primary" />

          {/* ═══════════════════════════════════════════════════════════════ */}
          {/* QUICK ACTIONS                                                 */}
          {/* ═══════════════════════════════════════════════════════════════ */}
          <section>
            <h2 className="font-display text-2xl mb-4">QUICK ACTIONS</h2>
            <div className="grid md:grid-cols-2 lg:grid-cols-2 sm:grid-cols-2 lg:grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <QuickAction
                icon={<ExternalLink />}
                label="OPEN CALDERA"
                onClick={() => window.open(DEFAULT_SERVER.httpUrl, '_blank')}
              />
              <QuickAction
                icon={<Fish />}
                label="OPEN GOPHISH"
                onClick={() => window.open('https://gophish.aceofcloud.io', '_blank')}
              />
              <QuickAction
                icon={<Terminal />}
                label="COPY SSH"
                onClick={() => copyToClipboard(`ssh -i ~/.ssh/caldera_do_key root@${DEFAULT_SERVER.ipAddress}`, 'SSH command')}
              />
              <QuickAction
                icon={<Key />}
                label="VIEW CREDENTIALS"
                onClick={() => navigate('/credentials')}
              />
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-2 sm:grid-cols-2 lg:grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-4">
              <QuickAction
                icon={<Target />}
                label="BROWSE ADVERSARIES"
                onClick={() => navigate('/adversaries')}
              />
              <QuickAction
                icon={<Cpu />}
                label="DEPLOY AGENTS"
                onClick={() => navigate('/agents/deploy')}
              />
              <QuickAction
                icon={<FileText />}
                label="GENERATE REPORT"
                onClick={() => navigate('/reports/security')}
              />
              <QuickAction
                icon={<RefreshCw />}
                label="REFRESH DATA"
                onClick={refreshAll}
              />
            </div>
          </section>

          {/* Divider */}
          <div className="w-full h-0.5 bg-primary" />

          {/* ═══════════════════════════════════════════════════════════════ */}
          {/* ACTIVE OPERATIONS                                             */}
          {/* ═══════════════════════════════════════════════════════════════ */}
          <section>
            <h2 className="font-display text-2xl mb-4">ACTIVE OPERATIONS</h2>
            <div className="grid md:grid-cols-3 gap-4 mb-8">
              {/* MSP Target Complete - Merged Operation */}
              <div className="bg-card border-2 border-emerald-500 p-5 hover:border-emerald-500/80 transition-colors md:col-span-2">
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-xs text-muted-foreground">59 ABILITIES</span>
                  <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 text-[10px] font-display tracking-wider">MERGED</span>
                </div>
                <h3 className="font-display text-xl text-emerald-500 mb-2">MSP TARGET COMPLETE RED TEAM EXERCISE</h3>
                <p className="text-sm text-muted-foreground mb-3">
                  Comprehensive adversary profile combining APT29 VCD Cloud Compromise with CrowdStrike Falcon bypass defense evasion. Full attack lifecycle from initial access through exfiltration with EDR evasion.
                </p>
                <div className="flex flex-wrap gap-1 mb-4">
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-xs border border-emerald-500/30">APT29</span>
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-xs border border-emerald-500/30">VCD</span>
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-xs border border-emerald-500/30">CROWDSTRIKE BYPASS</span>
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-xs border border-emerald-500/30">DEFENSE EVASION</span>
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-xs border border-emerald-500/30">CLOUD</span>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <Link href="/adversaries/MSP_Target_Complete_APT29_VCD_CrowdStrike">
                    <Button size="sm" className="w-full font-display tracking-wider bg-emerald-500 hover:bg-emerald-500/90 text-black">
                      VIEW PROFILE
                    </Button>
                  </Link>
                  <a href="https://caldera.aceofcloud.io/#/operations" target="_blank" rel="noopener noreferrer">
                    <Button size="sm" variant="outline" className="w-full font-display tracking-wider border-emerald-500 text-emerald-500 hover:bg-emerald-500/10">
                      OPEN IN CALDERA
                    </Button>
                  </a>
                </div>
              </div>

              {/* APT29 VCD Campaign */}
              <div className="bg-card border-2 border-primary p-5 hover:border-primary/80 transition-colors">
                <div className="flex items-center gap-2 mb-3">
                  <span className="px-2 py-0.5 bg-primary/20 text-primary text-xs font-display tracking-wider border border-primary">ACTIVE</span>
                  <span className="text-xs text-muted-foreground">48 ABILITIES</span>
                </div>
                <h3 className="font-display text-lg text-primary mb-2">APT29 VCD ENHANCED</h3>
                <p className="text-sm text-muted-foreground mb-3">
                  VMware Cloud Director campaign with authentic APT29 TTPs.
                </p>
                <div className="flex flex-wrap gap-1 mb-4">
                  <span className="px-2 py-0.5 bg-secondary text-xs">CLOUD</span>
                  <span className="px-2 py-0.5 bg-secondary text-xs">VCD</span>
                </div>
                <Link href="/adversaries/APT29_VCD_Cloud_Compromise_Enhanced">
                  <Button size="sm" className="w-full font-display tracking-wider bg-primary hover:bg-primary/90">
                    VIEW DETAILS
                  </Button>
                </Link>
              </div>

              {/* CrowdStrike Falcon Bypass */}
              <div className="bg-card border-2 border-yellow-500 p-5 hover:border-yellow-500/80 transition-colors">
                <div className="flex items-center gap-2 mb-3">
                  <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-500 text-xs font-display tracking-wider border border-yellow-500">EDR</span>
                  <span className="text-xs text-muted-foreground">12 ABILITIES</span>
                </div>
                <h3 className="font-display text-lg text-yellow-500 mb-2">CROWDSTRIKE BYPASS</h3>
                <p className="text-sm text-muted-foreground mb-3">
                  Defense evasion for CrowdStrike Falcon-protected endpoints.
                </p>
                <div className="flex flex-wrap gap-1 mb-4">
                  <span className="px-2 py-0.5 bg-yellow-500/20 text-xs border border-yellow-500/30">T1562.001</span>
                  <span className="px-2 py-0.5 bg-yellow-500/20 text-xs border border-yellow-500/30">STEALTH</span>
                </div>
                <Link href="/adversaries/MSP_Target_CrowdStrike_Bypass">
                  <Button size="sm" className="w-full font-display tracking-wider bg-yellow-500 hover:bg-yellow-500/90 text-black">
                    VIEW DETAILS
                  </Button>
                </Link>
              </div>

              {/* Operation Status Card */}
              <div className="bg-card border-2 border-border p-5 md:col-span-2">
                <h3 className="font-display text-lg mb-3">OPERATION STATUS</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="text-2xl font-display text-emerald-500">3</div>
                    <div className="text-xs text-muted-foreground">OPERATIONS</div>
                  </div>
                  <div>
                    <div className="text-2xl font-display text-primary">119</div>
                    <div className="text-xs text-muted-foreground">TOTAL ABILITIES</div>
                  </div>
                  <div>
                    <div className="text-2xl font-display text-yellow-500">PAUSED</div>
                    <div className="text-xs text-muted-foreground">AWAITING AGENTS</div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* APT Threat Actor Library */}
          <section>
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-display text-2xl">APT THREAT ACTOR LIBRARY</h2>
              <Link href="/adversaries">
                <Button variant="outline" size="sm" className="font-display tracking-wider">
                  VIEW ALL <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </Link>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
              {/* APT29 */}
              <a href="https://caldera.aceofcloud.io/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-blue-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-blue-500 mb-1">APT29</div>
                <div className="text-xs text-muted-foreground mb-2">COZY BEAR</div>
                <div className="text-xs text-blue-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">Russia • G0016</div>
              </a>
              {/* APT28 */}
              <a href="https://caldera.aceofcloud.io/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-red-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-red-500 mb-1">APT28</div>
                <div className="text-xs text-muted-foreground mb-2">FANCY BEAR</div>
                <div className="text-xs text-red-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">Russia • G0007</div>
              </a>
              {/* APT41 */}
              <a href="https://caldera.aceofcloud.io/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-orange-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-orange-500 mb-1">APT41</div>
                <div className="text-xs text-muted-foreground mb-2">DOUBLE DRAGON</div>
                <div className="text-xs text-orange-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">China • G0096</div>
              </a>
              {/* Lazarus */}
              <a href="https://caldera.aceofcloud.io/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-purple-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-purple-500 mb-1">LAZARUS</div>
                <div className="text-xs text-muted-foreground mb-2">HIDDEN COBRA</div>
                <div className="text-xs text-purple-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">N. Korea • G0032</div>
              </a>
              {/* FIN7 */}
              <a href="https://caldera.aceofcloud.io/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-green-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-green-500 mb-1">FIN7</div>
                <div className="text-xs text-muted-foreground mb-2">CARBANAK</div>
                <div className="text-xs text-green-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">Financial • G0046</div>
              </a>
              {/* Cobalt Group */}
              <a href="https://caldera.aceofcloud.io/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-cyan-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-cyan-500 mb-1">COBALT</div>
                <div className="text-xs text-muted-foreground mb-2">COBALT GROUP</div>
                <div className="text-xs text-cyan-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">Financial • G0080</div>
              </a>
            </div>
          </section>
        </div>
      </AppShell>
  );
}

function StatusBadge({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2 px-4 py-2 bg-secondary">
      <span className="text-muted-foreground">{icon}</span>
      <div>
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-sm font-medium">{value}</p>
      </div>
    </div>
  );
}

function StatCard({ value, label, color = "text-white", href, external }: { value: string; label: string; color?: string; href?: string; external?: boolean }) {
  const content = (
    <>
      <div className={`font-display text-5xl md:text-6xl mb-2 ${color}`}>{value}</div>
      <div className="text-xs tracking-widest text-muted-foreground">{label}</div>
      {href && <div className={`text-[10px] mt-2 tracking-wider opacity-0 group-hover:opacity-100 transition-opacity ${color}`}>VIEW DETAILS →</div>}
    </>
  );
  if (href && external) {
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" className="group bg-card border-2 border-border p-6 text-center hover:border-primary transition-colors cursor-pointer block">
        {content}
      </a>
    );
  }
  if (href) {
    return (
      <Link href={href} className="group bg-card border-2 border-border p-6 text-center hover:border-primary transition-colors cursor-pointer block">
        {content}
      </Link>
    );
  }
  return (
    <div className="bg-card border-2 border-border p-6 text-center hover:border-primary transition-colors">
      {content}
    </div>
  );
}

function MetricCard({ icon, value, label, subtext, color = "text-white", href, external }: { icon: React.ReactNode; value: number; label: string; subtext?: string; color?: string; href?: string; external?: boolean }) {
  const content = (
    <>
      <div className={`flex justify-center mb-2 ${color}`}>{icon}</div>
      <div className={`font-display text-3xl md:text-4xl mb-1 ${color}`}>{value}</div>
      <div className="text-[10px] tracking-widest text-muted-foreground">{label}</div>
      {subtext && <div className={`text-xs mt-1 ${color} opacity-70`}>{subtext}</div>}
      {href && <div className={`text-[10px] mt-2 tracking-wider opacity-0 group-hover:opacity-100 transition-opacity ${color}`}>DETAILS →</div>}
    </>
  );
  if (href && external) {
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" className="group bg-card border-2 border-border p-4 text-center hover:border-emerald-500/50 transition-colors cursor-pointer block">
        {content}
      </a>
    );
  }
  if (href) {
    return (
      <Link href={href} className="group bg-card border-2 border-border p-4 text-center hover:border-emerald-500/50 transition-colors cursor-pointer block">
        {content}
      </Link>
    );
  }
  return (
    <div className="bg-card border-2 border-border p-4 text-center hover:border-emerald-500/50 transition-colors">
      {content}
    </div>
  );
}

function ResourceRow({ icon, label, count, href, external }: { icon: React.ReactNode; label: string; count: number; href?: string; external?: boolean }) {
  const content = (
    <>
      <div className="flex items-center gap-2">
        <span className="text-emerald-500">{icon}</span>
        <span className="text-sm text-muted-foreground group-hover:text-emerald-400 transition-colors">{label}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="font-display text-lg text-emerald-400">{count}</span>
        {href && <ChevronRight className="w-4 h-4 text-emerald-500 opacity-0 group-hover:opacity-100 transition-opacity" />}
      </div>
    </>
  );
  if (href && external) {
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" className="group flex items-center justify-between cursor-pointer hover:bg-emerald-500/5 -mx-2 px-2 py-1 rounded transition-colors">
        {content}
      </a>
    );
  }
  if (href) {
    return (
      <Link href={href} className="group flex items-center justify-between cursor-pointer hover:bg-emerald-500/5 -mx-2 px-2 py-1 rounded transition-colors">
        {content}
      </Link>
    );
  }
  return (
    <div className="flex items-center justify-between">
      {content}
    </div>
  );
}

function QuickAction({ icon, label, onClick }: { icon: React.ReactNode; label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center justify-center gap-3 bg-card border-2 border-border p-4 font-display tracking-wider hover:border-primary hover:text-primary transition-colors"
    >
      {icon}
      {label}
    </button>
  );
}
