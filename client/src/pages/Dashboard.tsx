import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { 
  Activity, Terminal, Users, Key, ExternalLink, RefreshCw, Server, Cpu,
  Clock, Copy, ChevronRight, ChevronDown, Zap, Target, FileText, Cloud,
  Fish, Mail, MousePointerClick, Eye, FileWarning, Send, Globe, Shield,
  Search, Scan, Brain, AlertTriangle, Crosshair, Bug, ShieldAlert,
  Rocket, Building2, ArrowRight, Layers, BarChart3, Play, Pause,
  CheckCircle2, XCircle, Loader2, Plus, History, Radar, Flame, Radio,
  Briefcase, ShieldCheck
} from "lucide-react";
import ZeroDayFeed from "@/components/ZeroDayFeed";
import { useState, useEffect, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { useDashboardEvents } from "@/hooks/useWebSocket";

import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
const DEFAULT_SERVER = {
  id: 1,
  name: "Production Server",
  ipAddress: "134.199.213.248",
  httpsUrl: "https://dashboard.aceofcloud.io",
  httpUrl: "https://caldera.aceofcloud.io",
  region: "San Francisco (sfo3)",
  dropletSize: "s-2vcpu-4gb",
  status: "online" as const,
};

const CLIENT_TYPES = [
  { value: "enterprise", label: "Enterprise" },
  { value: "msp", label: "Managed Service Provider" },
  { value: "saas", label: "SaaS Provider" },
  { value: "paas", label: "PaaS Provider" },
  { value: "iaas", label: "IaaS Provider" },
  { value: "mixed_hosting", label: "Mixed Hosting" },
  { value: "other", label: "Other" },
];

const SECTORS = [
  "Technology", "Financial Services", "Healthcare", "Government", "Education",
  "Manufacturing", "Retail", "Energy", "Telecommunications", "Defense",
  "Legal", "Media", "Transportation", "Real Estate", "Consulting",
];

export default function Dashboard() {
  const [, navigate] = useLocation();
  const [serverStatus, setServerStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const [gophishStatus, setGophishStatus] = useState<'online' | 'offline' | 'checking'>('checking');

  // Start Engagement form state
  const [domain, setDomain] = useState('');
  const [companyName, setCompanyName] = useState('');
  const [clientType, setClientType] = useState('enterprise');
  const [sector, setSector] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<string[]>([]);
  const [dashScanId, setDashScanId] = useState<number | null>(null);

  // Collapsible sections
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    servers: true,
    caldera: true,
    gophish: false,
    threats: false,
    vulnFeed: false,
    operations: false,
  });

  const toggleSection = (key: string) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  // Live stats
  const { data: stats, refetch: refetchStats } = trpc.calderaProxy.getStats.useQuery(undefined, {
    refetchInterval: 30000,
  });
  const calderaStats = stats || { totalAdversaries: 0, totalAbilities: 0, activeOperations: 0, totalAgents: 0 };

  const { data: healthData } = trpc.calderaProxy.checkHealth.useQuery(undefined, { refetchInterval: 30000 });
  const { data: gophishData, refetch: refetchGophish } = trpc.gophishProxy.getStats.useQuery(undefined, { refetchInterval: 30000 });

  // Recent domain intel scans
  const { data: recentScans } = trpc.domainIntel.listScans.useQuery();

  // Real threat actor data from DB
  const { data: threatStats } = trpc.threatIntel.stats.useQuery();
  const { data: topActorsData } = trpc.threatIntel.list.useQuery({
    page: 1,
    pageSize: 5,
    type: 'all',
    threatLevel: 'all',
    sortBy: 'threatLevel',
    sortOrder: 'desc',
  });
  const { data: iocStats } = trpc.iocFeed.stats.useQuery();
  const { data: kevData } = trpc.calderaProxy.getKevCatalog.useQuery(undefined, { staleTime: 5 * 60 * 1000 });

  // Derived threat data
  const topActors = topActorsData?.actors || [];
  const iocCount = iocStats?.total ?? 0;
  const kevCount = kevData?.totalVulnerabilities ?? 0;

  // Domain intel scan mutation (async fire-and-forget)
  const startScan = trpc.domainIntel.startScan.useMutation({
    onSuccess: (data) => {
      setDashScanId(data.scanId);
      toast.success('Pipeline started! Monitoring progress...');
    },
    onError: (err) => {
      setIsScanning(false);
      setScanProgress([]);
      setDashScanId(null);
      toast.error(`Scan failed: ${sanitizeErrorForToast(err)}`);
    },
  });

  // Poll for scan status while running from Dashboard
  const dashScanStatus = trpc.domainIntel.getScanStatus.useQuery(
    { scanId: dashScanId! },
    {
      enabled: isScanning && dashScanId !== null,
      refetchInterval: 3000,
    }
  );

  // React to scan status changes from Dashboard
  useEffect(() => {
    if (!dashScanStatus.data || !isScanning) return;
    const { status } = dashScanStatus.data;
    if (status === 'completed' || status === 'scan_complete') {
      setIsScanning(false);
      setScanProgress([]);
      toast.success(status === 'scan_complete' ? 'Domain scan complete! Review results before starting engagement...' : 'Domain Intel scan completed! Redirecting to results...');
      navigate(`/domain-intel/${dashScanId}`);
    } else if (status === 'failed') {
      setIsScanning(false);
      setScanProgress([]);
      setDashScanId(null);
      toast.error('Pipeline failed. Please try again.');
    }
  }, [dashScanStatus.data, isScanning, dashScanId, navigate]);

  useEffect(() => {
    if (healthData !== undefined) setServerStatus(healthData ? 'online' : 'offline');
  }, [healthData]);

  useEffect(() => {
    if (gophishData !== undefined) setGophishStatus(gophishData.online ? 'online' : 'offline');
  }, [gophishData]);

  const gophish = gophishData || {
    online: false, totalCampaigns: 0, activeCampaigns: 0, completedCampaigns: 0,
    totalTemplates: 0, totalLandingPages: 0, totalGroups: 0, totalSendingProfiles: 0,
    totalTargets: 0,
    emailMetrics: { sent: 0, opened: 0, clicked: 0, submitted: 0, reported: 0 },
    recentEvents: [] as Array<{ time: string; message: string; campaign: string; status: string }>,
    campaigns: [] as Array<{ id: number; name: string; status: string; created_date: string; completed_date: string; stats: any }>,
  };

  const openRate = gophish.emailMetrics.sent > 0 ? ((gophish.emailMetrics.opened / gophish.emailMetrics.sent) * 100).toFixed(1) : '0';
  const clickRate = gophish.emailMetrics.sent > 0 ? ((gophish.emailMetrics.clicked / gophish.emailMetrics.sent) * 100).toFixed(1) : '0';
  const submitRate = gophish.emailMetrics.sent > 0 ? ((gophish.emailMetrics.submitted / gophish.emailMetrics.sent) * 100).toFixed(1) : '0';

  // Real-time WebSocket events for dashboard
  const { events: wsEvents, isConnected: wsConnected, eventCounts } = useDashboardEvents();

  // Auto-refresh stats when WS events arrive
  useEffect(() => {
    if (wsEvents.length > 0) {
      refetchStats();
      refetchGophish();
    }
  }, [wsEvents.length]);

  const refreshAll = () => {
    refetchStats();
    refetchGophish();
    toast.success('Refreshing all data...');
  };

  const handleStartEngagement = () => {
    if (!domain.trim()) {
      toast.error('Enter a target domain to begin');
      return;
    }
    setIsScanning(true);
    setScanProgress(['Initializing OSINT pipeline...']);

    // Simulate progress updates
    const steps = [
      { delay: 2000, msg: 'Running passive asset discovery...' },
      { delay: 5000, msg: 'Enumerating DNS records and subdomains...' },
      { delay: 8000, msg: 'Analyzing tech stack and infrastructure...' },
      { delay: 12000, msg: 'Running business impact risk assessment...' },
      { delay: 16000, msg: 'Matching threat actors to target profile...' },
      { delay: 20000, msg: 'Generating campaign recommendations...' },
    ];
    steps.forEach(({ delay, msg }) => {
      setTimeout(() => setScanProgress(prev => [...prev, msg]), delay);
    });

    startScan.mutate({
      primaryDomain: domain.trim(),
      clientType: clientType as any,
      sector: sector || 'Technology',
      customerName: companyName || domain.trim(),
      criticalFunctions: [],
    });
  };

  const recentCompletedScans = useMemo(() => {
    if (!recentScans) return [];
    return recentScans
      .filter((s: any) => s.status === 'completed' || s.status === 'scan_complete')
      .slice(0, 5);
  }, [recentScans]);

  return (
    <AppShell activePath="/dashboard">
      <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="px-4 sm:px-6 py-3 flex items-center justify-between">
          <div>
            <h1 className="font-display text-2xl sm:text-3xl">ACE C3 COMMAND CENTER</h1>
            <p className="text-xs text-muted-foreground">Offensive Security Execution Platform</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 mr-2">
              <div className={`w-2.5 h-2.5 rounded-full ${serverStatus === 'online' ? 'bg-green-500' : serverStatus === 'offline' ? 'bg-red-500' : 'bg-yellow-500 animate-pulse'}`} />
              <span className="text-[10px] font-display tracking-wider text-muted-foreground hidden sm:inline">EMULATION</span>
              <div className={`w-2.5 h-2.5 rounded-full ml-2 ${gophishStatus === 'online' ? 'bg-emerald-500' : gophishStatus === 'offline' ? 'bg-red-500' : 'bg-yellow-500 animate-pulse'}`} />
              <span className="text-[10px] font-display tracking-wider text-muted-foreground hidden sm:inline">PHISHING</span>
              <div className={`w-2.5 h-2.5 rounded-full ml-2 ${wsConnected ? 'bg-cyan-500 animate-pulse' : 'bg-gray-500'}`} />
              <span className="text-[10px] font-display tracking-wider text-muted-foreground hidden sm:inline">LIVE</span>
            </div>
            <Button variant="outline" size="sm" className="font-display tracking-wider text-xs" onClick={refreshAll}>
              <RefreshCw className="w-3.5 h-3.5 mr-1" />
              REFRESH
            </Button>
          </div>
        </div>
        <div className="w-full h-1 bg-gradient-to-r from-primary via-cyan-500 to-emerald-500" />
      </header>

      <div className="p-4 sm:p-6 space-y-6">

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* DOMAIN SCAN — Quick scan bar                                    */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <section className="bg-gradient-to-r from-cyan-950/40 via-card to-card border-2 border-cyan-500/30 p-5 sm:p-6">
          <div className="flex items-center gap-2 mb-3">
            <Radar className="w-5 h-5 text-cyan-400" />
            <h2 className="font-display text-lg tracking-wider text-cyan-400">DOMAIN INTELLIGENCE</h2>
          </div>
          <p className="text-sm text-muted-foreground mb-4">
            Launch an AI-powered reconnaissance pipeline with active DNS verification,
            banner fingerprinting, vulnerability correlation, and threat actor matching.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const val = (e.currentTarget.elements.namedItem('quickDomain') as HTMLInputElement)?.value?.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
              if (val) navigate(`/domain-intel?domain=${encodeURIComponent(val)}`);
            }}
            className="flex items-center gap-0 max-w-2xl"
          >
            <div className="relative flex-1">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-cyan-500/60" />
              <input
                name="quickDomain"
                type="text"
                placeholder="Enter a domain (e.g., example.com)"
                className="w-full pl-11 pr-4 py-3.5 bg-background/80 border-2 border-cyan-500/30 border-r-0 text-sm font-mono placeholder:text-muted-foreground/50 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>
            <button
              type="submit"
              className="flex items-center gap-2 px-6 py-3.5 bg-cyan-500 hover:bg-cyan-400 text-black font-display tracking-wider text-sm transition-colors border-2 border-cyan-500 hover:border-cyan-400"
            >
              <Search className="w-4 h-4" />
              SCAN
            </button>
          </form>
          <div className="flex items-center gap-4 sm:gap-6 mt-4 text-[10px] text-muted-foreground font-display tracking-wider flex-wrap">
            <span className="flex items-center gap-1.5"><CheckCircle2 className="w-3 h-3 text-green-500" /> DNS VERIFICATION</span>
            <span className="flex items-center gap-1.5"><CheckCircle2 className="w-3 h-3 text-green-500" /> BANNER DETECTION</span>
            <span className="flex items-center gap-1.5"><CheckCircle2 className="w-3 h-3 text-green-500" /> CVE CORRELATION</span>
            <span className="flex items-center gap-1.5"><CheckCircle2 className="w-3 h-3 text-green-500" /> THREAT MATCHING</span>
          </div>
        </section>

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* START ENGAGEMENT — Hero Section                                */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <section className="relative overflow-hidden bg-gradient-to-br from-card via-card to-primary/5 border-2 border-primary/40 p-5 sm:p-8">
          <div className="absolute top-0 right-0 w-64 h-64 bg-primary/5 rounded-full -translate-y-1/2 translate-x-1/2" />
          <div className="absolute bottom-0 left-0 w-48 h-48 bg-cyan-500/5 rounded-full translate-y-1/2 -translate-x-1/2" />
          
          <div className="relative">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 bg-primary/20 border border-primary/40 flex items-center justify-center">
                <Rocket className="w-5 h-5 text-primary" />
              </div>
              <div>
                <h2 className="font-display text-xl sm:text-2xl tracking-wider">START NEW ENGAGEMENT</h2>
                <p className="text-xs text-muted-foreground">Enter a domain to begin automated OSINT discovery, threat modeling, and campaign generation</p>
              </div>
            </div>

            <div className="mt-5 space-y-4">
              {/* Domain Input — Primary */}
              <div>
                <label className="text-[10px] font-display tracking-widest text-muted-foreground mb-1.5 block">TARGET DOMAIN *</label>
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-primary/60" />
                    <input
                      type="text"
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                      placeholder="e.g., acmecorp.com"
                      className="w-full pl-10 pr-4 py-3 bg-background/80 border-2 border-primary/30 text-sm font-mono focus:outline-none focus:border-primary transition-colors"
                      onKeyDown={(e) => e.key === 'Enter' && !isScanning && handleStartEngagement()}
                      disabled={isScanning}
                    />
                  </div>
                </div>
              </div>

              {/* Context Fields */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-[10px] font-display tracking-widest text-muted-foreground mb-1.5 block">COMPANY NAME</label>
                  <div className="relative">
                    <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
                    <input
                      type="text"
                      value={companyName}
                      onChange={(e) => setCompanyName(e.target.value)}
                      placeholder="Acme Corporation"
                      className="w-full pl-10 pr-3 py-2.5 bg-background/60 border border-border text-sm focus:outline-none focus:border-primary/50 transition-colors"
                      disabled={isScanning}
                    />
                  </div>
                </div>
                <div>
                  <label className="text-[10px] font-display tracking-widest text-muted-foreground mb-1.5 block">CLIENT TYPE</label>
                  <select
                    value={clientType}
                    onChange={(e) => setClientType(e.target.value)}
                    className="w-full px-3 py-2.5 bg-background/60 border border-border text-sm focus:outline-none focus:border-primary/50 transition-colors"
                    disabled={isScanning}
                  >
                    {CLIENT_TYPES.map(ct => (
                      <option key={ct.value} value={ct.value}>{ct.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] font-display tracking-widest text-muted-foreground mb-1.5 block">INDUSTRY SECTOR</label>
                  <select
                    value={sector}
                    onChange={(e) => setSector(e.target.value)}
                    className="w-full px-3 py-2.5 bg-background/60 border border-border text-sm focus:outline-none focus:border-primary/50 transition-colors"
                    disabled={isScanning}
                  >
                    <option value="">Select sector...</option>
                    {SECTORS.map(s => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Pipeline Steps Preview */}
              <div className="flex flex-wrap items-center gap-1 text-[10px] text-muted-foreground">
                {['OSINT Discovery', 'Asset Enumeration', 'BIA Risk Scoring', 'Threat Actor Matching', 'Campaign Generation'].map((step, i) => (
                  <span key={step} className="flex items-center gap-1">
                    {i > 0 && <ArrowRight className="w-3 h-3 text-primary/40" />}
                    <span className="px-2 py-0.5 bg-primary/10 border border-primary/20 font-display tracking-wider">{step}</span>
                  </span>
                ))}
              </div>

              {/* Launch Button */}
              <div className="flex items-center gap-3">
                <Button
                  onClick={handleStartEngagement}
                  disabled={isScanning || !domain.trim()}
                  className="font-display tracking-wider bg-primary hover:bg-primary/90 text-primary-foreground px-8 py-3 text-sm"
                  size="lg"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      SCANNING...
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4 mr-2" />
                      LAUNCH PIPELINE
                    </>
                  )}
                </Button>
                <Link href="/domain-intel">
                  <Button variant="outline" size="lg" className="font-display tracking-wider text-sm">
                    ADVANCED OPTIONS
                  </Button>
                </Link>
              </div>

              {/* Scan Progress */}
              {isScanning && scanProgress.length > 0 && (
                <div className="bg-background/80 border border-primary/30 p-4 mt-3">
                  <div className="flex items-center gap-2 mb-2">
                    <Loader2 className="w-4 h-4 text-primary animate-spin" />
                    <span className="text-xs font-display tracking-wider text-primary">PIPELINE IN PROGRESS</span>
                  </div>
                  <div className="space-y-1">
                    {scanProgress.map((msg, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        {i < scanProgress.length - 1 ? (
                          <CheckCircle2 className="w-3 h-3 text-green-500 shrink-0" />
                        ) : (
                          <Loader2 className="w-3 h-3 text-primary animate-spin shrink-0" />
                        )}
                        <span className={i < scanProgress.length - 1 ? 'text-muted-foreground' : 'text-foreground'}>{msg}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* MISSION WORKFLOWS — Guided scenario quick-start                 */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <section>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Rocket className="w-4 h-4 text-primary" />
              <h3 className="font-display text-sm tracking-wider text-muted-foreground">MISSION WORKFLOWS</h3>
              <span className="text-[9px] bg-primary/20 text-primary px-1.5 py-0.5 font-mono uppercase tracking-wider">New</span>
            </div>
            <Link href="/workflows">
              <Button variant="ghost" size="sm" className="text-xs font-display tracking-wider">
                VIEW ALL <ChevronRight className="w-3 h-3 ml-1" />
              </Button>
            </Link>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {[
              { title: "New Engagement", desc: "ROE → Recon → Scoring → Campaign → Report", href: "/workflows", icon: Briefcase, color: "text-amber-400 border-amber-500/30", steps: 7 },
              { title: "Domain Recon", desc: "27-connector passive recon with LLM analysis", href: "/workflows", icon: Search, color: "text-cyan-400 border-cyan-500/30", steps: 5 },
              { title: "Detection Validation", desc: "ATT&CK tests → SIEM → Coverage gaps → Purple team", href: "/workflows", icon: ShieldCheck, color: "text-green-400 border-green-500/30", steps: 6 },
              { title: "Phishing Campaign", desc: "Template → Landing page → Launch → Monitor", href: "/workflows", icon: Fish, color: "text-rose-400 border-rose-500/30", steps: 6 },
              { title: "Cloud Security", desc: "Attack paths → Credentials → EDR → Alerts", href: "/workflows", icon: Cloud, color: "text-blue-400 border-blue-500/30", steps: 5 },
              { title: "Compliance Report", desc: "Map → BIA → OSCAL → Evidence → Report", href: "/workflows", icon: FileText, color: "text-purple-400 border-purple-500/30", steps: 5 },
            ].map((wf) => (
              <Link key={wf.title} href={wf.href}>
                <div className={`bg-card border-2 ${wf.color} p-3 hover:bg-secondary/30 transition-all cursor-pointer group`}>
                  <div className="flex items-center gap-2 mb-1">
                    <wf.icon className={`w-4 h-4 ${wf.color.split(' ')[0]}`} />
                    <span className="font-display text-sm tracking-wider group-hover:text-primary transition-colors">{wf.title}</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground">{wf.desc}</p>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-border">
                    <span className="text-[9px] text-muted-foreground font-mono">{wf.steps} STEPS</span>
                    <span className="text-[9px] font-display tracking-wider text-primary">START →</span>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </section>

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* RECENT SCANS — Quick access to previous results                */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        {recentCompletedScans.length > 0 && (
          <section>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-muted-foreground" />
                <h3 className="font-display text-sm tracking-wider text-muted-foreground">RECENT SCANS</h3>
              </div>
              <Link href="/domain-intel">
                <Button variant="ghost" size="sm" className="text-xs font-display tracking-wider">
                  VIEW ALL <ChevronRight className="w-3 h-3 ml-1" />
                </Button>
              </Link>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2">
              {recentCompletedScans.map((scan: any) => {
                const output = scan.pipelineOutput as any;
                const riskScore = output?.riskScore || scan.riskScore || 0;
                const riskColor = riskScore >= 80 ? 'text-red-500 border-red-500/30' : riskScore >= 60 ? 'text-orange-500 border-orange-500/30' : riskScore >= 40 ? 'text-yellow-500 border-yellow-500/30' : 'text-green-500 border-green-500/30';
                const assetCount = output?.assets?.length || scan.totalAssets || 0;
                const findingCount = output?.postureFindings?.length || 0;
                const confirmedCount = output?.postureFindings?.filter((f: any) => f.corroborationTier === 'confirmed').length || 0;
                const probableCount = output?.postureFindings?.filter((f: any) => f.corroborationTier === 'probable').length || 0;
                return (
                  <Link key={scan.id} href={`/domain-intel/${scan.id}`}>
                    <div className={`bg-card border-2 ${riskColor} p-3 hover:bg-secondary/30 transition-all cursor-pointer h-full`}>
                      <div className="font-mono text-sm truncate">{scan.primaryDomain}</div>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-[10px] text-muted-foreground">{scan.clientType?.toUpperCase() || 'SCAN'}</span>
                        <span className={`font-display text-lg ${riskColor.split(' ')[0]}`}>{riskScore}</span>
                      </div>
                      <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                        <span className="text-[9px] bg-muted px-1.5 py-0.5 rounded">{assetCount} assets</span>
                        {findingCount > 0 && <span className="text-[9px] bg-muted px-1.5 py-0.5 rounded">{findingCount} findings</span>}
                        {confirmedCount > 0 && <span className="text-[9px] bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">{confirmedCount} confirmed</span>}
                        {probableCount > 0 && <span className="text-[9px] bg-orange-500/20 text-orange-400 px-1.5 py-0.5 rounded">{probableCount} probable</span>}
                      </div>
                      <div className="flex items-center justify-between mt-2 pt-2 border-t border-border">
                        <span className="text-[10px] text-muted-foreground">
                          {scan.createdAt ? new Date(scan.createdAt).toLocaleDateString() : ''}
                        </span>
                        <span className="text-[9px] font-display tracking-wider text-primary">VIEW RESULTS →</span>
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
          </section>
        )}

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* QUICK ACCESS — Most important features                         */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <section>
          <h2 className="font-display text-lg tracking-wider mb-3">QUICK ACCESS</h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
            <QuickAccessCard icon={<Brain />} label="DOMAIN INTEL" desc="AI-powered pipeline" href="/domain-intel" color="text-cyan-400 border-cyan-500/30" />
            <QuickAccessCard icon={<Target />} label="THREAT ACTORS" desc={`${threatStats?.totalActors ?? '...'}+ actor profiles`} href="/threat-catalog" color="text-red-400 border-red-500/30" />
            <QuickAccessCard icon={<Layers />} label="ENGAGEMENTS" desc="Manage campaigns" href="/engagements" color="text-primary border-primary/30" />
            <QuickAccessCard icon={<Fish />} label="PHISHING" desc="Phishing campaigns" href="/phishing-ops" color="text-emerald-400 border-emerald-500/30" />
            <QuickAccessCard icon={<Activity />} label="CAMPAIGN EXEC" desc="Live operations" href="/operations/monitor" color="text-yellow-400 border-yellow-500/30" />
            <QuickAccessCard icon={<BarChart3 />} label="REPORTS" desc="Generate reports" href="/reports/engagement" color="text-purple-400 border-purple-500/30" />
          </div>
        </section>

        <div className="w-full h-0.5 bg-primary/30" />

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* LIVE STATS — Emulation + Phishing at a glance                    */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <section>
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
            <MiniStat value={calderaStats.totalAdversaries.toString()} label="ADVERSARIES" color="text-primary" href="/adversaries" />
            <MiniStat value={calderaStats.totalAbilities.toString()} label="ABILITIES" color="text-primary" href="/abilities-library" />
            <MiniStat value={calderaStats.activeOperations.toString()} label="OPERATIONS" color="text-primary" href="/operations/monitor" />
            <MiniStat value={calderaStats.totalAgents.toString()} label="AGENTS" color="text-primary" href="/agents" />
            <MiniStat value={gophish.totalCampaigns.toString()} label="CAMPAIGNS" color="text-emerald-400" href="/phishing-ops" />
            <MiniStat value={gophish.totalTemplates.toString()} label="TEMPLATES" color="text-emerald-400" href="/templates" />
            <MiniStat value={`${clickRate}%`} label="CLICK RATE" color="text-yellow-400" href="/phishing-ops" />
            <MiniStat value={`${submitRate}%`} label="SUBMIT RATE" color="text-red-400" href="/phishing-ops" />
          </div>
        </section>

        <div className="w-full h-0.5 bg-border" />

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* SERVER STATUS — Collapsible                                    */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <CollapsibleSection
          title="SERVER STATUS"
          expanded={expandedSections.servers}
          onToggle={() => toggleSection('servers')}
          badge={
            <div className="flex items-center gap-2">
              <StatusDot status={serverStatus} label="EMULATION" />
              <StatusDot status={gophishStatus} label="PHISHING" />
            </div>
          }
        >
          <div className="grid md:grid-cols-2 gap-3">
            <a href={DEFAULT_SERVER.httpUrl} target="_blank" rel="noopener noreferrer" className="bg-card border border-border p-4 cursor-pointer hover:border-primary transition-colors group block">
              <div className="flex items-center gap-3 mb-3">
                <div className={`w-3 h-3 ${serverStatus === 'online' ? 'bg-green-500' : serverStatus === 'offline' ? 'bg-red-500' : 'bg-yellow-500 animate-pulse'}`} />
                <div className="flex-1">
                  <h3 className="font-display text-sm">EMULATION SERVER</h3>
                  <p className="text-[10px] text-muted-foreground">{DEFAULT_SERVER.ipAddress}:8888</p>
                </div>
                <span className={`px-2 py-0.5 text-[10px] font-display tracking-wider ${serverStatus === 'online' ? 'bg-green-500/20 text-green-400 border border-green-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>
                  {serverStatus.toUpperCase()}
                </span>
              </div>
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <span className="px-2 py-0.5 bg-secondary">{DEFAULT_SERVER.region}</span>
                <span className="px-2 py-0.5 bg-secondary">{DEFAULT_SERVER.dropletSize}</span>
              </div>
            </a>
            <a href="https://gophish.aceofcloud.io" target="_blank" rel="noopener noreferrer" className="bg-card border border-emerald-500/30 p-4 cursor-pointer hover:border-emerald-500 transition-colors group block">
              <div className="flex items-center gap-3 mb-3">
                <div className={`w-3 h-3 ${gophishStatus === 'online' ? 'bg-emerald-500' : gophishStatus === 'offline' ? 'bg-red-500' : 'bg-yellow-500 animate-pulse'}`} />
                <div className="flex-1">
                  <h3 className="font-display text-sm text-emerald-500">PHISHING SERVER</h3>
                  <p className="text-[10px] text-muted-foreground">{DEFAULT_SERVER.ipAddress}:3333</p>
                </div>
                <span className={`px-2 py-0.5 text-[10px] font-display tracking-wider ${gophishStatus === 'online' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>
                  {gophishStatus.toUpperCase()}
                </span>
              </div>
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <span className="px-2 py-0.5 bg-secondary">{gophish.totalCampaigns} campaigns</span>
                <span className="px-2 py-0.5 bg-secondary">{gophish.activeCampaigns} active</span>
              </div>
            </a>
          </div>
        </CollapsibleSection>

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* PHISHING METRICS — Collapsible                                  */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <CollapsibleSection
          title="PHISHING EMAIL METRICS"
          expanded={expandedSections.gophish}
          onToggle={() => toggleSection('gophish')}
          icon={<Fish className="w-4 h-4 text-emerald-500" />}
          badge={
            <span className="text-xs text-muted-foreground">{gophish.emailMetrics.sent} sent · {openRate}% open · {clickRate}% click</span>
          }
        >
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-4">
            <MetricCard icon={<Send />} value={gophish.emailMetrics.sent} label="SENT" color="text-emerald-500" />
            <MetricCard icon={<Eye />} value={gophish.emailMetrics.opened} label="OPENED" subtext={`${openRate}%`} color="text-blue-400" />
            <MetricCard icon={<MousePointerClick />} value={gophish.emailMetrics.clicked} label="CLICKED" subtext={`${clickRate}%`} color="text-yellow-400" />
            <MetricCard icon={<Key />} value={gophish.emailMetrics.submitted} label="CREDS" subtext={`${submitRate}%`} color="text-red-400" />
            <MetricCard icon={<FileWarning />} value={gophish.emailMetrics.reported} label="REPORTED" color="text-purple-400" />
          </div>
          {gophish.campaigns.length > 0 && (
            <div className="bg-card border border-border overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border bg-secondary/50">
                    <th className="text-left text-[10px] font-display tracking-wider text-muted-foreground px-3 py-2">CAMPAIGN</th>
                    <th className="text-left text-[10px] font-display tracking-wider text-muted-foreground px-3 py-2">STATUS</th>
                    <th className="text-center text-[10px] font-display tracking-wider text-muted-foreground px-3 py-2">SENT</th>
                    <th className="text-center text-[10px] font-display tracking-wider text-muted-foreground px-3 py-2">CLICKED</th>
                    <th className="text-center text-[10px] font-display tracking-wider text-muted-foreground px-3 py-2">CREDS</th>
                  </tr>
                </thead>
                <tbody>
                  {gophish.campaigns.slice(0, 5).map((campaign) => (
                    <tr key={campaign.id} className="border-b border-border/50 hover:bg-secondary/30 transition-colors">
                      <td className="px-3 py-2">
                        <Link href={`/campaigns/${campaign.id}`} className="text-xs font-medium hover:text-emerald-500 transition-colors">
                          {campaign.name}
                        </Link>
                      </td>
                      <td className="px-3 py-2">
                        <span className={`px-1.5 py-0.5 text-[9px] font-display tracking-wider ${
                          campaign.status === 'In progress' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                          campaign.status === 'Completed' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                          'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                        }`}>
                          {campaign.status?.toUpperCase() || 'UNKNOWN'}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-center text-xs">{campaign.stats?.sent || 0}</td>
                      <td className="px-3 py-2 text-center text-xs text-yellow-400">{campaign.stats?.clicked || 0}</td>
                      <td className="px-3 py-2 text-center text-xs text-red-400">{campaign.stats?.submitted_data || 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CollapsibleSection>

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* THREAT AWARENESS — Collapsible                                 */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <CollapsibleSection
          title="THREAT AWARENESS"
          expanded={expandedSections.threats}
          onToggle={() => toggleSection('threats')}
          icon={<ShieldAlert className="w-4 h-4 text-red-500" />}
          badge={<span className="text-xs text-muted-foreground">{threatStats?.totalActors ?? '...'} actors · {(iocCount / 1000).toFixed(1)}K IOCs</span>}
        >
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            <div className="bg-card border border-red-500/30 p-3 text-center">
              <div className="font-display text-2xl text-red-500">{threatStats?.totalActors ?? '...'}</div>
              <div className="text-[10px] tracking-widest text-muted-foreground">THREAT ACTORS</div>
            </div>
            <div className="bg-card border border-orange-500/30 p-3 text-center">
              <div className="font-display text-2xl text-orange-500">{threatStats?.byThreatLevel?.critical ?? '...'}</div>
              <div className="text-[10px] tracking-widest text-muted-foreground">CRITICAL</div>
            </div>
            <div className="bg-card border border-yellow-500/30 p-3 text-center">
              <div className="font-display text-2xl text-yellow-500">{iocCount > 0 ? (iocCount >= 1000 ? `${(iocCount / 1000).toFixed(1)}K` : iocCount) : '...'}</div>
              <div className="text-[10px] tracking-widest text-muted-foreground">IOCs TRACKED</div>
            </div>
            <div className="bg-card border border-purple-500/30 p-3 text-center">
              <div className="font-display text-2xl text-purple-500">{kevCount > 0 ? (kevCount >= 1000 ? `${(kevCount / 1000).toFixed(0)}K` : kevCount) : '...'}</div>
              <div className="text-[10px] tracking-widest text-muted-foreground">KNOWN EXPLOITED</div>
            </div>
          </div>
          <div className="bg-card border border-border p-4">
            <h3 className="font-display text-xs tracking-wider mb-3 text-red-400">TOP THREAT ACTORS</h3>
            <div className="space-y-1.5">
              {topActors.length === 0 ? (
                <div className="text-xs text-muted-foreground py-2">Loading threat actors...</div>
              ) : topActors.map((t) => (
                <div key={t.actorId || t.name} className="flex items-center justify-between py-1 border-b border-border/30 last:border-0">
                  <div className="flex items-center gap-2">
                    <div className={`w-1.5 h-1.5 ${t.threatLevel === 'critical' ? 'bg-red-500' : t.threatLevel === 'high' ? 'bg-orange-500' : 'bg-yellow-500'}`} />
                    <span className="text-xs font-medium">{t.name}</span>
                    {t.origin && <span className="text-[10px] text-muted-foreground">({t.origin})</span>}
                  </div>
                  <span className={`text-[9px] font-display tracking-wider px-1.5 py-0.5 border ${t.threatLevel === 'critical' ? 'border-red-500/30 text-red-400 bg-red-500/10' : 'border-orange-500/30 text-orange-400 bg-orange-500/10'}`}>{(t.threatLevel || 'unknown').toUpperCase()}</span>
                </div>
              ))}
            </div>
            <Link href="/threat-catalog">
              <Button variant="ghost" size="sm" className="w-full mt-3 font-display tracking-wider text-xs text-red-400 hover:text-red-300">
                VIEW ALL {threatStats?.totalActors ?? ''} THREAT ACTORS <ChevronRight className="w-3 h-3 ml-1" />
              </Button>
            </Link>
          </div>
        </CollapsibleSection>

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* 0-DAY VULNERABILITY FEED — Live threat intelligence             */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <CollapsibleSection
          title="0-DAY VULNERABILITY FEED"
          expanded={expandedSections.vulnFeed}
          onToggle={() => toggleSection('vulnFeed')}
          icon={<Flame className="w-4 h-4 text-red-500" />}
          badge={<span className="text-xs text-muted-foreground">Live CVE tracking from multiple authoritative sources</span>}
        >
          <ZeroDayFeed />
        </CollapsibleSection>

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* MORE TOOLS — Grid of remaining features                        */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <section>
          <h2 className="font-display text-lg tracking-wider mb-3">MORE TOOLS</h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
            <ToolCard icon={<Scan />} label="Domain Intel" desc="DNS, WHOIS, SPF/DKIM" href="/domain-intel" />
            <ToolCard icon={<Shield />} label="Rule Validator" desc="Sigma/YARA/Suricata" href="/rule-validator" />
            <ToolCard icon={<BarChart3 />} label="Coverage Matrix" desc="Detection gap analysis" href="/detection-coverage" />
            <ToolCard icon={<Layers />} label="Abilities Library" desc="6,340+ attack abilities" href="/abilities-library" />
            <ToolCard icon={<FileText />} label="Template Library" desc="26 phishing templates" href="/templates" />
            <ToolCard icon={<Globe />} label="Page Builder" desc="Visual landing pages" href="/landing-page-builder" />
            <ToolCard icon={<ShieldAlert />} label="IOC Feeds" desc="Aggregated threat intelligence" href="/ioc-feed" />
            <ToolCard icon={<Terminal />} label="Offensive Tools" desc="Exploit framework catalog" href="/infra-reference" />
            <ToolCard icon={<Radio />} label="ICS/OT Security" desc="SCADA/IoT assessment" href="/ics-ot-security" />
          </div>
        </section>

      </div>
    </AppShell>
  );
}

/* ═══════════════════════════════════════════════════════════════ */
/* Helper Components                                              */
/* ═══════════════════════════════════════════════════════════════ */

function CollapsibleSection({ title, expanded, onToggle, children, icon, badge }: {
  title: string; expanded: boolean; onToggle: () => void; children: React.ReactNode;
  icon?: React.ReactNode; badge?: React.ReactNode;
}) {
  return (
    <section>
      <button onClick={onToggle} className="w-full flex items-center justify-between py-2 group">
        <div className="flex items-center gap-2">
          {icon}
          <h2 className="font-display text-lg tracking-wider">{title}</h2>
          {!expanded && badge && <span className="ml-2">{badge}</span>}
        </div>
        <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform ${expanded ? 'rotate-180' : ''}`} />
      </button>
      {expanded && <div className="mt-2">{children}</div>}
    </section>
  );
}

function StatusDot({ status, label }: { status: string; label: string }) {
  return (
    <div className="flex items-center gap-1">
      <div className={`w-2 h-2 rounded-full ${status === 'online' ? 'bg-green-500' : status === 'offline' ? 'bg-red-500' : 'bg-yellow-500 animate-pulse'}`} />
      <span className="text-[10px] font-display tracking-wider text-muted-foreground">{label}</span>
    </div>
  );
}

function QuickAccessCard({ icon, label, desc, href, color }: { icon: React.ReactNode; label: string; desc: string; href: string; color: string }) {
  return (
    <Link href={href}>
      <div className={`bg-card border-2 ${color} p-3 hover:bg-secondary/30 transition-colors cursor-pointer text-center`}>
        <div className={`flex justify-center mb-1.5 ${color.split(' ')[0]}`}>{icon}</div>
        <div className="font-display text-xs tracking-wider">{label}</div>
        <div className="text-[10px] text-muted-foreground mt-0.5">{desc}</div>
      </div>
    </Link>
  );
}

function MiniStat({ value, label, color, href }: { value: string; label: string; color: string; href?: string }) {
  const content = (
    <div className="bg-card border border-border p-2.5 text-center hover:border-primary/30 transition-colors">
      <div className={`font-display text-xl ${color}`}>{value}</div>
      <div className="text-[9px] tracking-widest text-muted-foreground">{label}</div>
    </div>
  );
  if (href) return <Link href={href} className="block">{content}</Link>;
  return content;
}

function MetricCard({ icon, value, label, subtext, color = "text-white" }: { icon: React.ReactNode; value: number; label: string; subtext?: string; color?: string }) {
  return (
    <div className="bg-card border border-border p-3 text-center">
      <div className={`flex justify-center mb-1 ${color}`}>{icon}</div>
      <div className={`font-display text-2xl ${color}`}>{value}</div>
      <div className="text-[9px] tracking-widest text-muted-foreground">{label}</div>
      {subtext && <div className={`text-xs mt-0.5 ${color} opacity-70`}>{subtext}</div>}
    </div>
  );
}

function ToolCard({ icon, label, desc, href }: { icon: React.ReactNode; label: string; desc: string; href: string }) {
  return (
    <Link href={href}>
      <div className="bg-card border border-border p-3 hover:border-primary/40 transition-colors cursor-pointer flex items-center gap-3">
        <div className="text-muted-foreground shrink-0">{icon}</div>
        <div>
          <div className="text-xs font-medium">{label}</div>
          <div className="text-[10px] text-muted-foreground">{desc}</div>
        </div>
      </div>
    </Link>
  );
}
