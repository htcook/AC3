import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation, useRoute } from "wouter";
import { toast } from "sonner";
import {
  Activity, Key, Target, Cpu, Zap, Users, FileText, Cloud, BookOpen,
  Shield, Globe2, LogOut, Menu, X, Briefcase, ChevronLeft, Send,
  Mail, Eye, MousePointer, ShieldAlert, BarChart3, Clock, Fish,
  ExternalLink, Download, Rocket, CheckCircle, AlertTriangle,
  TrendingUp, UserCheck, Lock
} from "lucide-react";
import { useState, useMemo } from "react";

import AppShell from "@/components/AppShell";
function MetricCard({ label, value, icon, color, subtitle }: { label: string; value: string | number; icon: React.ReactNode; color: string; subtitle?: string }) {
  return (
    <div className={`bg-card border-2 border-${color}-500/30 p-5`}>
      <div className="flex items-center justify-between mb-2">
        <span className={`text-${color}-500`}>{icon}</span>
        <span className="text-xs font-display tracking-wider text-muted-foreground">{label}</span>
      </div>
      <div className={`text-3xl font-display text-${color}-400`}>{value}</div>
      {subtitle && <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>}
    </div>
  );
}

function ProgressBar({ value, max, color, label }: { value: number; max: number; color: string; label: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="font-display tracking-wider text-muted-foreground">{label}</span>
        <span className="font-display">{pct}% ({value}/{max})</span>
      </div>
      <div className="w-full h-2 bg-background border border-border">
        <div className={`h-full bg-${color}-500 transition-all`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export default function EngagementResults() {
  const [, navigate] = useLocation();
  const [, params] = useRoute("/engagements/:id/results");
  const engagementId = params?.id ? parseInt(params.id) : null;
  const [expandedCampaign, setExpandedCampaign] = useState<number | null>(null);

  // Fetch engagement details
  const { data: engagement, isLoading: engLoading } = trpc.engagements.get.useQuery(
    { id: engagementId! },
    { enabled: !!engagementId }
  );

  // Fetch all campaign links for this engagement
  const { data: campaignLinks } = trpc.campaignEngagements.byEngagement.useQuery(
    { engagementId: engagementId! },
    { enabled: !!engagementId }
  );

  // Fetch all GoPhish campaigns to get stats
  const { data: allCampaigns } = trpc.gophishProxy.getCampaigns.useQuery();

  // Compute aggregated stats
  const { linkedCampaigns, totals, timelineEvents } = useMemo(() => {
    if (!campaignLinks || !allCampaigns) return { linkedCampaigns: [], totals: { sent: 0, opened: 0, clicked: 0, submitted: 0, reported: 0, total: 0, campaigns: 0 }, timelineEvents: [] };

    const linkedIds = new Set(campaignLinks.map((l: any) => l.gophishCampaignId));
    const linked = allCampaigns.filter((c: any) => linkedIds.has(c.id));

    const totals = { sent: 0, opened: 0, clicked: 0, submitted: 0, reported: 0, total: 0, campaigns: linked.length };
    const timelineEvents: any[] = [];

    for (const c of linked) {
      const s = c.stats || {};
      totals.sent += s.sent || 0;
      totals.opened += s.opened || 0;
      totals.clicked += s.clicked || 0;
      totals.submitted += s.submitted_data || 0;
      totals.reported += s.email_reported || 0;
      totals.total += s.total || 0;

      if (Array.isArray(c.timeline)) {
        for (const event of c.timeline) {
          timelineEvents.push({ ...event, campaignName: c.name, campaignId: c.id });
        }
      }
    }

    timelineEvents.sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());

    return { linkedCampaigns: linked, totals, timelineEvents };
  }, [campaignLinks, allCampaigns]);

  // Credential events (submitted_data)
  const credentialEvents = useMemo(() => {
    return timelineEvents.filter((e: any) =>
      e.message?.toLowerCase().includes('submitted') ||
      e.message?.toLowerCase().includes('credential') ||
      e.message?.toLowerCase().includes('data')
    );
  }, [timelineEvents]);

  if (!engagementId) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
          <p className="font-display tracking-wider text-lg">INVALID ENGAGEMENT ID</p>
          <Link href="/engagements"><Button className="mt-4 font-display tracking-wider">BACK TO ENGAGEMENTS</Button></Link>
        </div>
      </div>
    );
  }

  return (
    <AppShell activePath="/engagements">
{/* Sidebar */}
{/* Header */}
        <header className="sticky top-0 z-30 bg-card/80 backdrop-blur-sm border-b border-border px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link href="/engagements">
                <Button variant="ghost" size="sm" className="font-display tracking-wider">
                  <ChevronLeft className="w-4 h-4 mr-1" />BACK
                </Button>
              </Link>
              <div>
                <h1 className="font-display text-2xl tracking-wider flex items-center gap-2">
                  <BarChart3 className="w-6 h-6 text-primary" />
                  ENGAGEMENT RESULTS
                </h1>
                <p className="text-sm text-muted-foreground">
                  {engLoading ? 'Loading...' : engagement ? `${engagement.name} — ${engagement.customerName}` : 'Unknown Engagement'}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Link href={`/campaign-wizard`}>
                <Button size="sm" className="font-display tracking-wider bg-red-600 hover:bg-red-700 text-white">
                  <Rocket className="w-4 h-4 mr-2" />ADD CAMPAIGN
                </Button>
              </Link>
            </div>
          </div>
        </header>

        <div className="p-6 space-y-6">
          {/* Engagement Info Bar */}
          {engagement && (
            <div className="bg-card border-2 border-primary/30 p-4 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <Briefcase className="w-6 h-6 text-primary" />
                <div>
                  <h2 className="font-display text-lg tracking-wider">{engagement.name}</h2>
                  <p className="text-sm text-muted-foreground">{engagement.customerName} — {engagement.engagementType?.replace('_', ' ').toUpperCase()}</p>
                </div>
                <span className={`text-xs px-2 py-0.5 font-display tracking-wider ${
                  engagement.status === 'active' ? 'text-green-400 bg-green-500/10' :
                  engagement.status === 'completed' ? 'text-blue-400 bg-blue-500/10' :
                  'text-gray-400 bg-gray-500/10'
                }`}>
                  {engagement.status?.toUpperCase()}
                </span>
              </div>
              <div className="text-xs text-muted-foreground">
                {engagement.targetDomain && <span className="mr-4">Domain: {engagement.targetDomain}</span>}
                {engagement.phishingDomain && <span>Phishing: {engagement.phishingDomain}</span>}
              </div>
            </div>
          )}

          {/* Aggregate Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 lg:grid-cols-7 gap-4">
            <MetricCard label="CAMPAIGNS" value={totals.campaigns} icon={<Send className="w-5 h-5" />} color="orange" />
            <MetricCard label="TARGETS" value={totals.total} icon={<Users className="w-5 h-5" />} color="blue" />
            <MetricCard label="EMAILS SENT" value={totals.sent} icon={<Mail className="w-5 h-5" />} color="cyan" />
            <MetricCard label="OPENED" value={totals.opened} icon={<Eye className="w-5 h-5" />} color="yellow" />
            <MetricCard label="CLICKED" value={totals.clicked} icon={<MousePointer className="w-5 h-5" />} color="orange" />
            <MetricCard label="CREDS CAPTURED" value={totals.submitted} icon={<Lock className="w-5 h-5" />} color="red" subtitle={totals.total > 0 ? `${Math.round((totals.submitted / totals.total) * 100)}% capture rate` : undefined} />
            <MetricCard label="REPORTED" value={totals.reported} icon={<ShieldAlert className="w-5 h-5" />} color="green" subtitle={totals.total > 0 ? `${Math.round((totals.reported / totals.total) * 100)}% report rate` : undefined} />
          </div>

          {/* Phishing Funnel */}
          {totals.total > 0 && (
            <div className="bg-card border-2 border-border p-6">
              <h3 className="font-display text-lg tracking-wider mb-4 flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-primary" />
                PHISHING FUNNEL
              </h3>
              <div className="space-y-3">
                <ProgressBar value={totals.sent} max={totals.total} color="cyan" label="EMAILS SENT" />
                <ProgressBar value={totals.opened} max={totals.total} color="yellow" label="EMAILS OPENED" />
                <ProgressBar value={totals.clicked} max={totals.total} color="orange" label="LINKS CLICKED" />
                <ProgressBar value={totals.submitted} max={totals.total} color="red" label="CREDENTIALS SUBMITTED" />
                <ProgressBar value={totals.reported} max={totals.total} color="green" label="EMAILS REPORTED" />
              </div>
            </div>
          )}

          {/* Campaign Breakdown */}
          <div className="bg-card border-2 border-border p-6">
            <h3 className="font-display text-lg tracking-wider mb-4 flex items-center gap-2">
              <Send className="w-5 h-5 text-orange-500" />
              CAMPAIGN BREAKDOWN
            </h3>
            {linkedCampaigns.length === 0 ? (
              <div className="text-center py-8">
                <Fish className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                <p className="font-display tracking-wider mb-2">NO CAMPAIGNS LINKED</p>
                <p className="text-sm text-muted-foreground mb-4">Link campaigns to this engagement from the GoPhish page or use the Launch Wizard.</p>
                <Link href="/campaign-wizard">
                  <Button className="font-display tracking-wider"><Rocket className="w-4 h-4 mr-2" />LAUNCH WIZARD</Button>
                </Link>
              </div>
            ) : (
              <div className="space-y-3">
                {linkedCampaigns.map((campaign: any) => {
                  const stats = campaign.stats || {};
                  const isExpanded = expandedCampaign === campaign.id;
                  const statusColors: Record<string, string> = {
                    'In progress': 'text-green-400 bg-green-500/20',
                    'Completed': 'text-blue-400 bg-blue-500/20',
                    'Created': 'text-yellow-400 bg-yellow-500/20',
                  };
                  return (
                    <div key={campaign.id} className="border border-border">
                      <div
                        className="p-4 flex items-center justify-between cursor-pointer hover:bg-accent/30 transition-colors"
                        onClick={() => setExpandedCampaign(isExpanded ? null : campaign.id)}
                      >
                        <div className="flex items-center gap-3">
                          <Send className="w-4 h-4 text-orange-500" />
                          <span className="font-display tracking-wider">{campaign.name}</span>
                          <span className={`text-xs px-2 py-0.5 font-display tracking-wider ${statusColors[campaign.status] || 'text-gray-400 bg-gray-500/20'}`}>
                            {campaign.status?.toUpperCase()}
                          </span>
                        </div>
                        <div className="flex items-center gap-6 text-sm">
                          <span className="text-blue-400">{stats.total || 0} targets</span>
                          <span className="text-cyan-400">{stats.sent || 0} sent</span>
                          <span className="text-yellow-400">{stats.opened || 0} opened</span>
                          <span className="text-orange-400">{stats.clicked || 0} clicked</span>
                          <span className="text-red-400 font-bold">{stats.submitted_data || 0} creds</span>
                          <a
                            href={`https://gophish.aceofcloud.io/campaigns/${campaign.id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-orange-500 hover:text-orange-400"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <ExternalLink className="w-4 h-4" />
                          </a>
                        </div>
                      </div>
                      {isExpanded && (
                        <div className="border-t border-border p-4 bg-background/50">
                          <div className="grid grid-cols-2 md:grid-cols-2 sm:grid-cols-2 lg:grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
                            <div>
                              <p className="text-xs text-muted-foreground tracking-wider">CREATED</p>
                              <p className="text-sm">{campaign.created_date ? new Date(campaign.created_date).toLocaleString() : 'N/A'}</p>
                            </div>
                            <div>
                              <p className="text-xs text-muted-foreground tracking-wider">LAUNCHED</p>
                              <p className="text-sm">{campaign.launch_date ? new Date(campaign.launch_date).toLocaleString() : 'N/A'}</p>
                            </div>
                            <div>
                              <p className="text-xs text-muted-foreground tracking-wider">COMPLETED</p>
                              <p className="text-sm">{campaign.completed_date ? new Date(campaign.completed_date).toLocaleString() : 'In Progress'}</p>
                            </div>
                            <div>
                              <p className="text-xs text-muted-foreground tracking-wider">TEMPLATE</p>
                              <p className="text-sm">{campaign.template?.name || 'N/A'}</p>
                            </div>
                          </div>
                          {/* Per-campaign funnel */}
                          <div className="space-y-2">
                            <ProgressBar value={stats.sent || 0} max={stats.total || 1} color="cyan" label="SENT" />
                            <ProgressBar value={stats.opened || 0} max={stats.total || 1} color="yellow" label="OPENED" />
                            <ProgressBar value={stats.clicked || 0} max={stats.total || 1} color="orange" label="CLICKED" />
                            <ProgressBar value={stats.submitted_data || 0} max={stats.total || 1} color="red" label="CREDENTIALS" />
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Recent Timeline Events */}
          {timelineEvents.length > 0 && (
            <div className="bg-card border-2 border-border p-6">
              <h3 className="font-display text-lg tracking-wider mb-4 flex items-center gap-2">
                <Clock className="w-5 h-5 text-primary" />
                RECENT EVENTS
              </h3>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {timelineEvents.slice(0, 50).map((event: any, i: number) => {
                  const isCredential = event.message?.toLowerCase().includes('submitted') || event.message?.toLowerCase().includes('credential');
                  const isClick = event.message?.toLowerCase().includes('clicked');
                  const isOpen = event.message?.toLowerCase().includes('opened');
                  return (
                    <div key={i} className={`flex items-center gap-3 p-2 text-sm border-l-2 ${
                      isCredential ? 'border-red-500 bg-red-500/5' :
                      isClick ? 'border-orange-500 bg-orange-500/5' :
                      isOpen ? 'border-yellow-500 bg-yellow-500/5' :
                      'border-border'
                    }`}>
                      <span className="text-xs text-muted-foreground whitespace-nowrap">
                        {event.time ? new Date(event.time).toLocaleString() : 'N/A'}
                      </span>
                      <span className={`text-xs font-display tracking-wider px-2 py-0.5 ${
                        isCredential ? 'text-red-400 bg-red-500/20' :
                        isClick ? 'text-orange-400 bg-orange-500/20' :
                        isOpen ? 'text-yellow-400 bg-yellow-500/20' :
                        'text-muted-foreground bg-accent/50'
                      }`}>
                        {isCredential ? 'CRED' : isClick ? 'CLICK' : isOpen ? 'OPEN' : 'EVENT'}
                      </span>
                      <span className="flex-1 truncate">{event.message || event.details || 'Event'}</span>
                      <span className="text-xs text-muted-foreground">{event.email || ''}</span>
                      <span className="text-xs text-orange-500 font-display tracking-wider">{event.campaignName}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Credential Harvest Summary */}
          {totals.submitted > 0 && (
            <div className="bg-card border-2 border-red-500/30 p-6">
              <h3 className="font-display text-lg tracking-wider mb-4 flex items-center gap-2">
                <Lock className="w-5 h-5 text-red-500" />
                CREDENTIAL HARVEST SUMMARY
              </h3>
              <div className="grid md:grid-cols-3 gap-4 mb-4">
                <div className="bg-background/50 border border-border p-4 text-center">
                  <p className="text-3xl font-display text-red-400">{totals.submitted}</p>
                  <p className="text-xs font-display tracking-wider text-muted-foreground mt-1">TOTAL CREDENTIALS</p>
                </div>
                <div className="bg-background/50 border border-border p-4 text-center">
                  <p className="text-3xl font-display text-orange-400">
                    {totals.total > 0 ? Math.round((totals.submitted / totals.total) * 100) : 0}%
                  </p>
                  <p className="text-xs font-display tracking-wider text-muted-foreground mt-1">CAPTURE RATE</p>
                </div>
                <div className="bg-background/50 border border-border p-4 text-center">
                  <p className="text-3xl font-display text-yellow-400">
                    {totals.clicked > 0 ? Math.round((totals.submitted / totals.clicked) * 100) : 0}%
                  </p>
                  <p className="text-xs font-display tracking-wider text-muted-foreground mt-1">CLICK-TO-CRED RATE</p>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                Note: Detailed credential data (usernames/passwords) is available in the GoPhish UI for each campaign.
                This dashboard shows aggregate counts only for operational security.
              </p>
            </div>
          )}
        </div>
    </AppShell>
  );
}
