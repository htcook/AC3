import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation, useParams } from "wouter";
import { toast } from "sonner";
import {
  Activity, Key, Target, Cpu, Zap, Users, FileText, Cloud, BookOpen,
  Shield, Globe2, LogOut, Menu, X, Search, Radar, Mail, Server,
  AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronUp,
  ExternalLink, Copy, Globe, Lock, Unlock, ShieldAlert, ShieldCheck,
  ArrowLeft, RefreshCw, Crosshair, Eye, Briefcase, BarChart3,
  Network, Fingerprint, Scan, Sparkles, Download
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

// Spoofability gauge component
function SpoofGauge({ score }: { score: number }) {
  const color = score >= 60 ? 'text-red-400' : score >= 40 ? 'text-yellow-400' : 'text-green-400';
  const bgColor = score >= 60 ? 'bg-red-500' : score >= 40 ? 'bg-yellow-500' : 'bg-green-500';
  const label = score >= 60 ? 'HIGHLY SPOOFABLE' : score >= 40 ? 'MODERATELY SPOOFABLE' : 'WELL PROTECTED';

  return (
    <div className="text-center">
      <div className="relative w-32 h-32 mx-auto mb-3">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="6" className="text-border" />
          <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="6"
            className={color}
            strokeDasharray={`${score * 2.64} 264`}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-3xl font-display ${color}`}>{score}</span>
        </div>
      </div>
      <div className={`text-xs font-display tracking-wider px-3 py-1 inline-block ${bgColor}/20 ${color} border border-current`}>
        {label}
      </div>
    </div>
  );
}

// DNS record display
function DnsRecordRow({ label, value, status }: { label: string; value: string | null; status: 'good' | 'warn' | 'bad' | 'info' }) {
  const statusIcon = {
    good: <ShieldCheck className="w-4 h-4 text-green-400" />,
    warn: <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    bad: <ShieldAlert className="w-4 h-4 text-red-400" />,
    info: <Globe2 className="w-4 h-4 text-blue-400" />,
  }[status];

  return (
    <div className="flex items-start gap-3 py-2 border-b border-border/50 last:border-0">
      {statusIcon}
      <div className="flex-1 min-w-0">
        <div className="text-xs font-display tracking-wider text-muted-foreground">{label}</div>
        <div className="text-sm font-mono break-all mt-0.5">{value || <span className="text-red-400 italic">NOT CONFIGURED</span>}</div>
      </div>
    </div>
  );
}

export default function OsintRecon() {
  const params = useParams<{ id: string }>();
  const engagementId = parseInt(params.id || '0');
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [domainInput, setDomainInput] = useState('');
  const [activeTab, setActiveTab] = useState<'overview' | 'typosquats' | 'subdomains' | 'findings'>('overview');
  const [typosquatFilter, setTyposquatFilter] = useState<string>('all');
  const [showAvailableOnly, setShowAvailableOnly] = useState(false);
  const [expandedFactor, setExpandedFactor] = useState<number | null>(null);

  // Data queries
  const { data: engagement } = trpc.engagements.get.useQuery({ id: engagementId });
  const { data: reconList, refetch: refetchRecon } = trpc.osint.getRecon.useQuery({ engagementId });
  const { data: typosquats, refetch: refetchTyposquats } = trpc.osint.getTyposquats.useQuery({ engagementId });
  const { data: findings } = trpc.osint.getFindings.useQuery({ engagementId });

  // Mutations
  const startRecon = trpc.osint.startRecon.useMutation();
  const batchCheck = trpc.osint.batchCheckTyposquats.useMutation();
  const updateTyposquatStatus = trpc.osint.updateTyposquatStatus.useMutation();
  const autoCampaign = trpc.osint.autoCampaignDesign.useMutation();

  const latestRecon = reconList?.[0];

  // Parse spoof factors from the recon data
  const spoofFactors = useMemo(() => {
    if (!latestRecon) return [];
    const factors: Array<{ factor: string; impact: string; detail: string }> = [];
    // Reconstruct from stored data
    if (!latestRecon.spfRecord) {
      factors.push({ factor: 'No SPF Record', impact: 'critical', detail: 'Domain has no SPF record. Any server can send email claiming to be from this domain.' });
    } else if (latestRecon.spfRecord.includes('~all')) {
      factors.push({ factor: 'SPF Soft Fail (~all)', impact: 'high', detail: 'SPF uses soft fail (~all). Spoofed emails may still be delivered to inbox.' });
    } else if (latestRecon.spfRecord.includes('-all')) {
      factors.push({ factor: 'SPF Hard Fail (-all)', impact: 'low', detail: 'SPF uses hard fail (-all). Spoofed emails should be rejected.' });
    }
    if (!latestRecon.dmarcRecord) {
      factors.push({ factor: 'No DMARC Record', impact: 'critical', detail: 'No DMARC policy. Receiving servers have no guidance on handling spoofed emails.' });
    } else {
      const policy = latestRecon.dmarcRecord.match(/;\s*p=(\w+)/)?.[1];
      if (policy === 'none') factors.push({ factor: 'DMARC Policy: none', impact: 'high', detail: 'DMARC monitoring only, no enforcement.' });
      else if (policy === 'quarantine') factors.push({ factor: 'DMARC Policy: quarantine', impact: 'medium', detail: 'DMARC quarantines failed emails.' });
      else if (policy === 'reject') factors.push({ factor: 'DMARC Policy: reject', impact: 'low', detail: 'DMARC rejects failed emails.' });
    }
    return factors;
  }, [latestRecon]);

  // Typosquat filtering
  const filteredTyposquats = useMemo(() => {
    if (!typosquats) return [];
    let filtered = typosquats;
    if (typosquatFilter !== 'all') {
      filtered = filtered.filter((t: any) => t.permutationType === typosquatFilter);
    }
    if (showAvailableOnly) {
      filtered = filtered.filter((t: any) => t.dnsResolved === false || t.isRegistered === false);
    }
    return filtered;
  }, [typosquats, typosquatFilter, showAvailableOnly]);

  const typosquatTypes = useMemo(() => {
    if (!typosquats) return [];
    const types = new Set(typosquats.map((t: any) => t.permutationType));
    return Array.from(types).sort();
  }, [typosquats]);

  const handleStartRecon = async () => {
    const domain = domainInput || engagement?.targetDomain;
    if (!domain) {
      toast.error('Enter a target domain');
      return;
    }
    toast.info(`Starting OSINT reconnaissance for ${domain}...`);
    try {
      const result = await startRecon.mutateAsync({ engagementId, domain });
      toast.success(`Recon complete! Spoof score: ${result.spoofScore}/100, ${result.subdomainCount} subdomains, ${result.typosquatCount} typosquats generated`);
      refetchRecon();
      refetchTyposquats();
    } catch (err: any) {
      toast.error(err.message || 'Recon failed');
    }
  };

  const handleBatchCheck = async () => {
    if (!latestRecon) return;
    toast.info('Checking typosquat domain availability...');
    try {
      const results = await batchCheck.mutateAsync({ reconId: latestRecon.id, limit: 30 });
      const available = results.filter(r => !r.resolved).length;
      const registered = results.filter(r => r.resolved).length;
      toast.success(`Checked ${results.length} domains: ${available} available, ${registered} already registered`);
      refetchTyposquats();
    } catch (err: any) {
      toast.error(err.message || 'Batch check failed');
    }
  };

  const handleAutoCampaign = async () => {
    if (!latestRecon) return;
    toast.info('AI is designing campaigns based on OSINT findings...');
    try {
      const result = await autoCampaign.mutateAsync({ engagementId, reconId: latestRecon.id });
      toast.success(`Generated ${result.campaigns?.length || 0} campaign designs!`);
      // Store in state for display
      setAutoCampaigns(result.campaigns || []);
    } catch (err: any) {
      toast.error(err.message || 'Campaign design failed');
    }
  };

  const [autoCampaigns, setAutoCampaigns] = useState<any[]>([]);

  const TABS = [
    { id: 'overview', label: 'OVERVIEW', icon: <Radar className="w-4 h-4" /> },
    { id: 'typosquats', label: 'TYPOSQUATS', icon: <Globe className="w-4 h-4" /> },
    { id: 'subdomains', label: 'SUBDOMAINS', icon: <Network className="w-4 h-4" /> },
    { id: 'findings', label: 'FINDINGS', icon: <Fingerprint className="w-4 h-4" /> },
  ] as const;

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-card border-r-2 border-border transform transition-transform lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex items-center gap-3 px-6 py-5 border-b-2 border-border">
          <Shield className="w-6 h-6 text-primary" />
          <span className="font-display text-lg tracking-wider">C3 PLATFORM</span>
        </div>
        <nav className="py-4 space-y-1">
          <NavItem href="/dashboard" icon={<Activity className="w-5 h-5" />} label="DASHBOARD" />
          <NavItem href="/gophish" icon={<Target className="w-5 h-5" />} label="GOPHISH" />
          <NavItem href="/engagements" icon={<Briefcase className="w-5 h-5" />} label="ENGAGEMENTS" active />
          <NavItem href="/campaigns" icon={<Zap className="w-5 h-5" />} label="CAMPAIGNS" />
          <NavItem href="/campaign-wizard" icon={<Crosshair className="w-5 h-5" />} label="LAUNCH WIZARD" />
          <NavItem href="/templates" icon={<FileText className="w-5 h-5" />} label="TEMPLATES" />
          <NavItem href="/compliance" icon={<BookOpen className="w-5 h-5" />} label="COMPLIANCE" />
          <NavItem href="/infrastructure" icon={<Cloud className="w-5 h-5" />} label="INFRASTRUCTURE" />
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 lg:ml-64">
        {/* Header */}
        <header className="sticky top-0 z-40 bg-card/95 backdrop-blur border-b-2 border-border px-6 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <button className="lg:hidden" onClick={() => setSidebarOpen(!sidebarOpen)}>
                {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
              <Link href={`/engagements`}>
                <Button variant="ghost" size="sm" className="font-display tracking-wider">
                  <ArrowLeft className="w-4 h-4 mr-2" />BACK
                </Button>
              </Link>
              <div>
                <h1 className="font-display text-xl tracking-wider flex items-center gap-2">
                  <Radar className="w-5 h-5 text-primary" />
                  OSINT RECONNAISSANCE
                </h1>
                <p className="text-xs text-muted-foreground">
                  {engagement?.name || 'Loading...'} — {engagement?.customerName}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {latestRecon && (
                <Button
                  size="sm"
                  className="font-display tracking-wider bg-purple-600 hover:bg-purple-700 text-white"
                  onClick={handleAutoCampaign}
                  disabled={autoCampaign.isPending}
                >
                  <Sparkles className="w-4 h-4 mr-2" />
                  {autoCampaign.isPending ? 'DESIGNING...' : 'AI CAMPAIGN DESIGN'}
                </Button>
              )}
              <Link href={`/engagements/${engagementId}/results`}>
                <Button variant="outline" size="sm" className="font-display tracking-wider">
                  <BarChart3 className="w-4 h-4 mr-2" />RESULTS
                </Button>
              </Link>
            </div>
          </div>
        </header>

        <div className="p-6 space-y-6">
          {/* Domain Input / Scan Trigger */}
          <div className="bg-card border-2 border-primary/30 p-6">
            <h2 className="font-display text-lg tracking-wider mb-4 flex items-center gap-2">
              <Scan className="w-5 h-5 text-primary" />
              DOMAIN RECONNAISSANCE
            </h2>
            <div className="flex gap-3">
              <input
                type="text"
                value={domainInput || engagement?.targetDomain || ''}
                onChange={e => setDomainInput(e.target.value)}
                placeholder="Enter target domain (e.g., example.com)"
                className="flex-1 px-4 py-2.5 bg-background border-2 border-border font-mono text-sm focus:border-primary outline-none"
              />
              <Button
                className="font-display tracking-wider bg-primary hover:bg-primary/90 text-primary-foreground px-6"
                onClick={handleStartRecon}
                disabled={startRecon.isPending}
              >
                <Radar className="w-4 h-4 mr-2" />
                {startRecon.isPending ? 'SCANNING...' : 'RUN RECON'}
              </Button>
            </div>
            {startRecon.isPending && (
              <div className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Analyzing DNS records, enumerating subdomains via crt.sh, generating typosquat candidates, scoring spoofability...</span>
              </div>
            )}
          </div>

          {/* Tab Navigation */}
          {latestRecon && (
            <div className="flex gap-1 border-b-2 border-border">
              {TABS.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-4 py-2.5 font-display text-sm tracking-wider transition-colors border-b-2 -mb-[2px] ${
                    activeTab === tab.id
                      ? 'border-primary text-primary'
                      : 'border-transparent text-muted-foreground hover:text-foreground'
                  }`}
                >
                  {tab.icon}
                  {tab.label}
                </button>
              ))}
            </div>
          )}

          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && latestRecon && (
            <div className="grid lg:grid-cols-3 gap-6">
              {/* Spoofability Score */}
              <div className="bg-card border-2 border-border p-6">
                <h3 className="font-display tracking-wider text-sm text-muted-foreground mb-4">EMAIL SPOOFABILITY</h3>
                <SpoofGauge score={latestRecon.spoofScore || 0} />
                <div className="mt-4 text-center">
                  <span className={`text-xs font-display tracking-wider px-3 py-1 border ${
                    latestRecon.spoofScore && latestRecon.spoofScore >= 60
                      ? 'bg-red-500/10 text-red-400 border-red-500'
                      : latestRecon.spoofScore && latestRecon.spoofScore >= 30
                        ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500'
                        : 'bg-green-500/10 text-green-400 border-green-500'
                  }`}>
                    {latestRecon.spoofScore && latestRecon.spoofScore >= 60
                      ? 'RECOMMEND: DIRECT SPOOF'
                      : latestRecon.spoofScore && latestRecon.spoofScore >= 30
                        ? 'RECOMMEND: SPOOF + LOOKALIKE'
                        : 'RECOMMEND: BUY LOOKALIKE DOMAIN'}
                  </span>
                </div>
              </div>

              {/* DNS Records */}
              <div className="bg-card border-2 border-border p-6">
                <h3 className="font-display tracking-wider text-sm text-muted-foreground mb-4">DNS & EMAIL SECURITY</h3>
                <div className="space-y-0">
                  <DnsRecordRow
                    label="MX RECORDS"
                    value={(latestRecon.mxRecords as any[])?.map((r: any) => `${r.exchange} (pri: ${r.priority})`).join(', ') || null}
                    status={(latestRecon.mxRecords as any[])?.length ? 'info' : 'warn'}
                  />
                  <DnsRecordRow
                    label="SPF RECORD"
                    value={latestRecon.spfRecord}
                    status={!latestRecon.spfRecord ? 'bad' : latestRecon.spfRecord.includes('-all') ? 'good' : 'warn'}
                  />
                  <DnsRecordRow
                    label="DMARC RECORD"
                    value={latestRecon.dmarcRecord}
                    status={!latestRecon.dmarcRecord ? 'bad' : latestRecon.dmarcRecord.includes('p=reject') ? 'good' : 'warn'}
                  />
                  <DnsRecordRow
                    label="NAMESERVERS"
                    value={(latestRecon.nsRecords as string[])?.join(', ') || null}
                    status="info"
                  />
                  <DnsRecordRow
                    label="A RECORDS"
                    value={(latestRecon.aRecords as string[])?.join(', ') || null}
                    status="info"
                  />
                </div>
              </div>

              {/* Quick Stats */}
              <div className="space-y-4">
                <div className="bg-card border-2 border-border p-4">
                  <div className="text-xs font-display tracking-wider text-muted-foreground">SUBDOMAINS FOUND</div>
                  <div className="text-3xl font-display text-primary mt-1">{(latestRecon.subdomains as any[])?.length || 0}</div>
                  <div className="text-xs text-muted-foreground mt-1">via Certificate Transparency</div>
                </div>
                <div className="bg-card border-2 border-border p-4">
                  <div className="text-xs font-display tracking-wider text-muted-foreground">TYPOSQUAT CANDIDATES</div>
                  <div className="text-3xl font-display text-orange-400 mt-1">{typosquats?.length || 0}</div>
                  <div className="text-xs text-muted-foreground mt-1">12 permutation algorithms</div>
                </div>
                <div className="bg-card border-2 border-border p-4">
                  <div className="text-xs font-display tracking-wider text-muted-foreground">OSINT FINDINGS</div>
                  <div className="text-3xl font-display text-yellow-400 mt-1">{findings?.length || 0}</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {findings?.filter((f: any) => f.severity === 'critical').length || 0} critical,{' '}
                    {findings?.filter((f: any) => f.severity === 'high').length || 0} high
                  </div>
                </div>
              </div>

              {/* LLM Analysis */}
              {latestRecon.spoofAnalysis && (
                <div className="lg:col-span-3 bg-card border-2 border-purple-500/30 p-6">
                  <h3 className="font-display tracking-wider text-sm text-purple-400 mb-3 flex items-center gap-2">
                    <Sparkles className="w-4 h-4" />
                    AI TACTICAL ASSESSMENT
                  </h3>
                  <p className="text-sm leading-relaxed">{latestRecon.spoofAnalysis}</p>
                </div>
              )}

              {/* Spoofability Factors */}
              {spoofFactors.length > 0 && (
                <div className="lg:col-span-3 bg-card border-2 border-border p-6">
                  <h3 className="font-display tracking-wider text-sm text-muted-foreground mb-4">SPOOFABILITY FACTORS</h3>
                  <div className="space-y-2">
                    {spoofFactors.map((factor, i) => (
                      <div key={i} className={`p-3 border-l-4 ${
                        factor.impact === 'critical' ? 'border-red-500 bg-red-500/5' :
                        factor.impact === 'high' ? 'border-orange-500 bg-orange-500/5' :
                        factor.impact === 'medium' ? 'border-yellow-500 bg-yellow-500/5' :
                        'border-green-500 bg-green-500/5'
                      }`}>
                        <div className="flex items-center justify-between">
                          <span className="font-display text-sm tracking-wider">{factor.factor}</span>
                          <span className={`text-[10px] font-display tracking-wider px-2 py-0.5 ${
                            factor.impact === 'critical' ? 'bg-red-500/20 text-red-400' :
                            factor.impact === 'high' ? 'bg-orange-500/20 text-orange-400' :
                            factor.impact === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-green-500/20 text-green-400'
                          }`}>{factor.impact.toUpperCase()}</span>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">{factor.detail}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TYPOSQUATS TAB */}
          {activeTab === 'typosquats' && latestRecon && (
            <div className="space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-3">
                <div className="flex items-center gap-3">
                  <select
                    value={typosquatFilter}
                    onChange={e => setTyposquatFilter(e.target.value)}
                    className="px-3 py-2 bg-background border-2 border-border text-sm font-display"
                  >
                    <option value="all">ALL TYPES</option>
                    {typosquatTypes.map(t => (
                      <option key={t} value={t}>{t.toUpperCase().replace('_', ' ')}</option>
                    ))}
                  </select>
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={showAvailableOnly}
                      onChange={e => setShowAvailableOnly(e.target.checked)}
                      className="rounded"
                    />
                    <span className="font-display tracking-wider text-xs">AVAILABLE ONLY</span>
                  </label>
                  <span className="text-xs text-muted-foreground">{filteredTyposquats.length} domains</span>
                </div>
                <Button
                  size="sm"
                  className="font-display tracking-wider bg-orange-500 hover:bg-orange-600 text-black"
                  onClick={handleBatchCheck}
                  disabled={batchCheck.isPending}
                >
                  <Scan className="w-4 h-4 mr-2" />
                  {batchCheck.isPending ? 'CHECKING...' : 'CHECK AVAILABILITY'}
                </Button>
              </div>

              {/* Typosquat Legend */}
              <div className="bg-card border-2 border-border p-4 flex flex-wrap gap-4 text-xs">
                <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-green-500" /> Available (not registered)</div>
                <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-red-500" /> Registered (potential threat)</div>
                <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-gray-500" /> Unchecked</div>
                <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-blue-500" /> Purchased by us</div>
              </div>

              {/* Typosquat Grid */}
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
                {filteredTyposquats.slice(0, 60).map((t: any) => (
                  <div key={t.id} className={`bg-card border-2 p-3 transition-colors group ${
                    t.status === 'purchased' || t.status === 'in_use' ? 'border-blue-500/50' :
                    t.dnsResolved === true ? 'border-red-500/50' :
                    t.dnsResolved === false ? 'border-green-500/50' :
                    'border-border'
                  }`}>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-mono text-sm truncate flex-1">{t.permutedDomain}</span>
                      <div className="flex items-center gap-1 ml-2">
                        {t.dnsResolved === true && <div className="w-2 h-2 rounded-full bg-red-500" title="Registered" />}
                        {t.dnsResolved === false && <div className="w-2 h-2 rounded-full bg-green-500" title="Available" />}
                        {t.dnsResolved === null && <div className="w-2 h-2 rounded-full bg-gray-500" title="Unchecked" />}
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-display tracking-wider text-muted-foreground bg-accent/50 px-2 py-0.5">
                        {t.permutationType.toUpperCase().replace('_', ' ')}
                      </span>
                      <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        {t.dnsResolved === false && t.status === 'discovered' && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 text-[10px] font-display text-green-400"
                            onClick={() => {
                              updateTyposquatStatus.mutate(
                                { id: t.id, status: 'recommended' },
                                { onSuccess: () => { toast.success('Marked as recommended'); refetchTyposquats(); } }
                              );
                            }}
                          >
                            RECOMMEND
                          </Button>
                        )}
                        {(t.status === 'recommended' || t.status === 'discovered') && t.dnsResolved === false && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 text-[10px] font-display text-blue-400"
                            onClick={() => {
                              updateTyposquatStatus.mutate(
                                { id: t.id, status: 'purchased' },
                                { onSuccess: () => { toast.success('Marked as purchased'); refetchTyposquats(); } }
                              );
                            }}
                          >
                            PURCHASED
                          </Button>
                        )}
                      </div>
                    </div>
                    {t.resolvedIp && (
                      <div className="text-[10px] text-muted-foreground mt-1 font-mono">IP: {t.resolvedIp}</div>
                    )}
                    {t.status !== 'discovered' && (
                      <div className={`text-[10px] font-display tracking-wider mt-1 px-2 py-0.5 inline-block ${
                        t.status === 'purchased' ? 'bg-blue-500/20 text-blue-400' :
                        t.status === 'recommended' ? 'bg-green-500/20 text-green-400' :
                        t.status === 'in_use' ? 'bg-primary/20 text-primary' :
                        t.status === 'transferred' ? 'bg-purple-500/20 text-purple-400' :
                        'bg-gray-500/20 text-gray-400'
                      }`}>
                        {t.status.toUpperCase().replace('_', ' ')}
                      </div>
                    )}
                  </div>
                ))}
              </div>
              {filteredTyposquats.length > 60 && (
                <p className="text-xs text-muted-foreground text-center">Showing 60 of {filteredTyposquats.length} domains. Use filters to narrow results.</p>
              )}
            </div>
          )}

          {/* SUBDOMAINS TAB */}
          {activeTab === 'subdomains' && latestRecon && (
            <div className="space-y-4">
              <div className="bg-card border-2 border-border p-6">
                <h3 className="font-display tracking-wider text-sm text-muted-foreground mb-4">
                  DISCOVERED SUBDOMAINS ({(latestRecon.subdomains as string[])?.length || 0})
                </h3>
                <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {(latestRecon.subdomains as string[])?.map((sub, i) => (
                    <div key={i} className="flex items-center gap-2 px-3 py-2 bg-background border border-border text-sm font-mono">
                      <Network className="w-3.5 h-3.5 text-primary shrink-0" />
                      <span className="truncate">{sub}</span>
                      <button
                        onClick={() => { navigator.clipboard.writeText(sub); toast.success('Copied!'); }}
                        className="ml-auto opacity-0 hover:opacity-100 transition-opacity"
                      >
                        <Copy className="w-3 h-3 text-muted-foreground" />
                      </button>
                    </div>
                  ))}
                </div>
                {!(latestRecon.subdomains as string[])?.length && (
                  <p className="text-sm text-muted-foreground text-center py-8">No subdomains found via Certificate Transparency logs.</p>
                )}
              </div>
            </div>
          )}

          {/* FINDINGS TAB */}
          {activeTab === 'findings' && (
            <div className="space-y-4">
              {findings && findings.length > 0 ? findings.map((f: any) => (
                <div key={f.id} className={`bg-card border-2 p-4 ${
                  f.severity === 'critical' ? 'border-red-500/50' :
                  f.severity === 'high' ? 'border-orange-500/50' :
                  f.severity === 'medium' ? 'border-yellow-500/50' :
                  'border-border'
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-display tracking-wider px-2 py-0.5 ${
                        f.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                        f.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        f.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        f.severity === 'low' ? 'bg-blue-500/20 text-blue-400' :
                        'bg-gray-500/20 text-gray-400'
                      }`}>{f.severity?.toUpperCase()}</span>
                      <span className="text-[10px] font-display tracking-wider text-muted-foreground bg-accent/50 px-2 py-0.5">
                        {f.category?.toUpperCase().replace('_', ' ')}
                      </span>
                    </div>
                    <span className="text-[10px] text-muted-foreground">{f.source}</span>
                  </div>
                  <h4 className="font-display text-sm tracking-wider mb-1">{f.title}</h4>
                  <p className="text-xs text-muted-foreground">{f.description}</p>
                </div>
              )) : (
                <div className="bg-card border-2 border-dashed border-border p-12 text-center">
                  <Fingerprint className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
                  <h3 className="font-display text-lg tracking-wider mb-2">NO FINDINGS YET</h3>
                  <p className="text-sm text-muted-foreground">Run a domain reconnaissance scan to discover OSINT findings.</p>
                </div>
              )}
            </div>
          )}

          {/* AI Campaign Designs */}
          {autoCampaigns.length > 0 && (
            <div className="space-y-4">
              <h2 className="font-display text-xl tracking-wider flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-purple-400" />
                AI-DESIGNED CAMPAIGNS
              </h2>
              <div className="grid lg:grid-cols-3 gap-4">
                {autoCampaigns.map((c: any, i: number) => (
                  <div key={i} className="bg-card border-2 border-purple-500/30 p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-display text-sm tracking-wider text-purple-400">{c.name}</h3>
                      <span className={`text-[10px] font-display tracking-wider px-2 py-0.5 ${
                        c.riskLevel === 'high' ? 'bg-red-500/20 text-red-400' :
                        c.riskLevel === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>{c.riskLevel?.toUpperCase()} RISK</span>
                    </div>
                    <div className="space-y-2 text-xs">
                      <div><span className="text-muted-foreground font-display tracking-wider">VECTOR:</span> <span>{c.attackVector}</span></div>
                      <div><span className="text-muted-foreground font-display tracking-wider">PRETEXT:</span> <span>{c.pretext}</span></div>
                      <div><span className="text-muted-foreground font-display tracking-wider">TEMPLATE:</span> <span>{c.templateType}</span></div>
                      <div><span className="text-muted-foreground font-display tracking-wider">TARGETS:</span> <span>{c.targetAudience}</span></div>
                      <div><span className="text-muted-foreground font-display tracking-wider">LANDING:</span> <span>{c.landingPageStrategy}</span></div>
                      <div><span className="text-muted-foreground font-display tracking-wider">DOMAIN:</span> <span className="font-mono">{c.sendingDomain}</span></div>
                    </div>
                    <Link href="/campaign-wizard">
                      <Button size="sm" className="w-full font-display tracking-wider bg-purple-600 hover:bg-purple-700 text-white mt-2">
                        <Crosshair className="w-3.5 h-3.5 mr-2" />USE THIS DESIGN
                      </Button>
                    </Link>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* No Recon Yet */}
          {!latestRecon && !startRecon.isPending && (
            <div className="bg-card border-2 border-dashed border-border p-16 text-center">
              <Radar className="w-16 h-16 text-muted-foreground/30 mx-auto mb-4" />
              <h3 className="font-display text-xl tracking-wider mb-2">NO RECONNAISSANCE DATA</h3>
              <p className="text-sm text-muted-foreground max-w-lg mx-auto mb-6">
                Enter the target domain above and run a scan to discover DNS records, email security configuration, subdomains, and generate typosquat domain candidates for your engagement.
              </p>
            </div>
          )}
        </div>
      </main>

      {/* Mobile overlay */}
      {sidebarOpen && <div className="fixed inset-0 bg-black/50 z-40 lg:hidden" onClick={() => setSidebarOpen(false)} />}
    </div>
  );
}
