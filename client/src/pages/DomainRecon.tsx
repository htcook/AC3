import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import {
  Radar, Globe, Search, Shield, ShieldAlert, ShieldCheck, AlertTriangle,
  Mail, Server, Lock, Unlock, Network, Fingerprint, Sparkles, ArrowRight,
  ChevronDown, ChevronUp, ExternalLink, Copy, Eye, Briefcase, Plus,
  CheckCircle, XCircle, Globe2, Scan, RefreshCw
} from "lucide-react";
import { useState, useMemo, useEffect } from "react";
import AppShell from "@/components/AppShell";

// Spoofability gauge component
function SpoofGauge({ score }: { score: number }) {
  const color = score >= 60 ? 'text-red-400' : score >= 40 ? 'text-yellow-400' : 'text-green-400';
  const bgColor = score >= 60 ? 'bg-red-500' : score >= 40 ? 'bg-yellow-500' : 'bg-green-500';
  const label = score >= 60 ? 'HIGHLY SPOOFABLE' : score >= 40 ? 'MODERATELY SPOOFABLE' : 'WELL PROTECTED';

  return (
    <div className="text-center">
      <div className="relative w-24 h-24 mx-auto mb-2">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="6" className="text-border" />
          <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="6"
            className={color}
            strokeDasharray={`${score * 2.64} 264`}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-2xl font-display ${color}`}>{score}</span>
        </div>
      </div>
      <div className={`text-[10px] font-display tracking-wider px-2 py-0.5 inline-block ${bgColor}/20 ${color} border border-current`}>
        {label}
      </div>
    </div>
  );
}

function DnsRow({ label, value, status }: { label: string; value: string | null; status: 'good' | 'warn' | 'bad' | 'info' }) {
  const icons = {
    good: <ShieldCheck className="w-4 h-4 text-green-400 shrink-0" />,
    warn: <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />,
    bad: <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />,
    info: <Globe2 className="w-4 h-4 text-blue-400 shrink-0" />,
  };
  return (
    <div className="flex items-start gap-3 py-2 border-b border-border/50 last:border-0">
      {icons[status]}
      <div className="flex-1 min-w-0">
        <div className="text-xs font-display tracking-wider text-muted-foreground">{label}</div>
        <div className="text-sm font-mono break-all mt-0.5">{value || <span className="text-red-400 italic">NOT CONFIGURED</span>}</div>
      </div>
    </div>
  );
}

export default function DomainRecon() {
  const [, navigate] = useLocation();
  const [domain, setDomain] = useState('');
  const [selectedEngagementId, setSelectedEngagementId] = useState<number | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [typosquats, setTyposquats] = useState<any[]>([]);
  const [showAllTyposquats, setShowAllTyposquats] = useState(false);
  const [activeTab, setActiveTab] = useState<'results' | 'typosquats' | 'campaigns'>('results');
  const [autoCampaigns, setAutoCampaigns] = useState<any[]>([]);

  // Read URL params for pre-fill from dashboard quick-search
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const domainParam = params.get('domain');
    if (domainParam && !domain) setDomain(domainParam);
    const engId = params.get('engagementId');
    if (engId && !selectedEngagementId) setSelectedEngagementId(Number(engId));
  }, []);

  // Fetch engagements for linking
  const { data: engagements } = trpc.engagements.list.useQuery();

  // OSINT mutations
  const startRecon = trpc.osint.startRecon.useMutation();
  const batchCheck = trpc.osint.batchCheckTyposquats.useMutation();
  const autoCampaign = trpc.osint.autoCampaignDesign.useMutation();

  // If an engagement is selected, fetch its existing recon
  const { data: existingRecon } = trpc.osint.getRecon.useQuery(
    { engagementId: selectedEngagementId! },
    { enabled: !!selectedEngagementId }
  );
  const { data: existingTyposquats } = trpc.osint.getTyposquats.useQuery(
    { engagementId: selectedEngagementId! },
    { enabled: !!selectedEngagementId }
  );

  // Load existing recon when engagement is selected
  const latestExistingRecon = existingRecon?.[0];

  const handleScan = async () => {
    if (!domain.trim()) {
      toast.error('Enter a domain to scan');
      return;
    }

    // If no engagement selected, create a temporary one or scan without
    if (!selectedEngagementId) {
      toast.error('Select or create an engagement first to save recon results');
      return;
    }

    setIsScanning(true);
    toast.info(`Scanning ${domain}...`);
    try {
      const result = await startRecon.mutateAsync({
        engagementId: selectedEngagementId,
        domain: domain.trim(),
      });
      setScanResult(result);
      toast.success(`Scan complete! Spoof score: ${result.spoofScore}/100, ${result.subdomainCount} subdomains, ${result.typosquatCount} typosquats`);
    } catch (err: any) {
      toast.error(err.message || 'Scan failed');
    } finally {
      setIsScanning(false);
    }
  };

  const handleAutoCampaign = async () => {
    const reconId = scanResult?.reconId || latestExistingRecon?.id;
    if (!reconId || !selectedEngagementId) return;
    toast.info('AI is designing campaigns based on OSINT findings...');
    try {
      const result = await autoCampaign.mutateAsync({
        engagementId: selectedEngagementId,
        reconId,
      });
      setAutoCampaigns(result.campaigns || []);
      setActiveTab('campaigns');
      toast.success(`Generated ${result.campaigns?.length || 0} campaign designs!`);
    } catch (err: any) {
      toast.error(err.message || 'Campaign design failed');
    }
  };

  // Use scan result or existing recon
  const displayRecon = scanResult ? {
    spoofScore: scanResult.spoofScore,
    mxRecords: scanResult.mxRecords?.join(', '),
    spfRecord: scanResult.spfRecord,
    dmarcRecord: scanResult.dmarcRecord,
    subdomainCount: scanResult.subdomainCount,
    typosquatCount: scanResult.typosquatCount,
    subdomains: scanResult.subdomains,
  } : latestExistingRecon ? {
    spoofScore: latestExistingRecon.spoofScore,
    mxRecords: latestExistingRecon.mxRecords as string | null,
    spfRecord: latestExistingRecon.spfRecord,
    dmarcRecord: latestExistingRecon.dmarcRecord,
    subdomainCount: latestExistingRecon.subdomains ? (typeof latestExistingRecon.subdomains === 'string' ? latestExistingRecon.subdomains.split(',').length : Array.isArray(latestExistingRecon.subdomains) ? (latestExistingRecon.subdomains as any[]).length : 0) : 0,
    typosquatCount: existingTyposquats?.length || 0,
    subdomains: latestExistingRecon.subdomains,
  } : null;

  const displayTyposquats = existingTyposquats || typosquats;
  const visibleTyposquats = showAllTyposquats ? displayTyposquats : displayTyposquats.slice(0, 20);

  // Spoof factors from recon
  const spoofFactors = useMemo(() => {
    if (!displayRecon) return [];
    const factors: Array<{ factor: string; impact: string; detail: string }> = [];
    if (!displayRecon.spfRecord) {
      factors.push({ factor: 'No SPF Record', impact: 'critical', detail: 'Domain has no SPF record. Any server can send email claiming to be from this domain.' });
    } else if (displayRecon.spfRecord.includes('~all')) {
      factors.push({ factor: 'SPF Soft Fail (~all)', impact: 'high', detail: 'SPF uses soft fail. Spoofed emails may still be delivered.' });
    } else if (displayRecon.spfRecord.includes('-all')) {
      factors.push({ factor: 'SPF Hard Fail (-all)', impact: 'low', detail: 'SPF uses hard fail. Spoofed emails should be rejected.' });
    }
    if (!displayRecon.dmarcRecord) {
      factors.push({ factor: 'No DMARC Record', impact: 'critical', detail: 'No DMARC policy. No guidance on handling spoofed emails.' });
    } else {
      const policy = displayRecon.dmarcRecord.match(/;\s*p=(\w+)/)?.[1];
      if (policy === 'none') factors.push({ factor: 'DMARC Policy: none', impact: 'high', detail: 'DMARC monitoring only, no enforcement.' });
      else if (policy === 'quarantine') factors.push({ factor: 'DMARC Policy: quarantine', impact: 'medium', detail: 'DMARC quarantines failed emails.' });
      else if (policy === 'reject') factors.push({ factor: 'DMARC Policy: reject', impact: 'low', detail: 'DMARC rejects failed emails.' });
    }
    if (!displayRecon.mxRecords) {
      factors.push({ factor: 'No MX Records', impact: 'info', detail: 'Domain has no mail exchange records.' });
    }
    return factors;
  }, [displayRecon]);

  const TABS = [
    { id: 'results', label: 'SCAN RESULTS', count: displayRecon ? 1 : 0 },
    { id: 'typosquats', label: 'TYPOSQUATS', count: displayTyposquats.length },
    { id: 'campaigns', label: 'AI CAMPAIGNS', count: autoCampaigns.length },
  ] as const;

  return (
    <AppShell activePath="/domain-recon">
      {/* Page description */}
      <div className="mb-6">
        <h1 className="font-display text-2xl sm:text-3xl tracking-wider flex items-center gap-3">
          <Radar className="w-6 h-6 sm:w-7 sm:h-7 text-primary" />
          DOMAIN RECONNAISSANCE
        </h1>
        <p className="text-muted-foreground text-xs sm:text-sm mt-1">
          Search any customer domain for OSINT data — DNS records, email spoofability, subdomains, typosquat candidates, and AI-designed phishing campaigns. Results are saved to the linked engagement.
        </p>
      </div>

      {/* Domain Search Bar */}
      <div className="bg-card border-2 border-primary/30 p-4 sm:p-6 mb-6">
        <div className="flex flex-col gap-4">
          {/* Engagement selector */}
          <div>
            <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1.5">LINK TO ENGAGEMENT</label>
            <div className="flex flex-col sm:flex-row gap-2">
              <select
                value={selectedEngagementId ?? ''}
                onChange={(e) => {
                  const id = e.target.value ? Number(e.target.value) : null;
                  setSelectedEngagementId(id);
                  if (id) {
                    const eng = engagements?.find((en: any) => en.id === id);
                    if (eng?.targetDomain && !domain) setDomain(eng.targetDomain);
                  }
                }}
                className="flex-1 px-3 py-2.5 bg-background border border-border text-sm focus:outline-none focus:border-primary"
              >
                <option value="">Select an engagement...</option>
                {engagements?.map((e: any) => (
                  <option key={e.id} value={e.id}>
                    {e.name} — {e.customerName} {e.targetDomain ? `(${e.targetDomain})` : ''}
                  </option>
                ))}
              </select>
              <Link href="/engagements">
                <Button variant="outline" size="sm" className="font-display tracking-wider whitespace-nowrap h-[42px]">
                  <Plus className="w-4 h-4 mr-1" />NEW
                </Button>
              </Link>
            </div>
          </div>

          {/* Domain input + scan button */}
          <div>
            <label className="text-xs font-display tracking-wider text-muted-foreground block mb-1.5">TARGET DOMAIN</label>
            <div className="flex flex-col sm:flex-row gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="e.g., acmecorp.com"
                  className="w-full pl-10 pr-4 py-2.5 bg-background border border-border text-sm focus:outline-none focus:border-primary font-mono"
                  onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                />
              </div>
              <Button
                onClick={handleScan}
                disabled={isScanning || !domain.trim() || !selectedEngagementId}
                className="font-display tracking-wider bg-primary hover:bg-primary/90 whitespace-nowrap"
              >
                {isScanning ? (
                  <><RefreshCw className="w-4 h-4 mr-2 animate-spin" />SCANNING...</>
                ) : (
                  <><Scan className="w-4 h-4 mr-2" />SCAN DOMAIN</>
                )}
              </Button>
            </div>
            {!selectedEngagementId && (
              <p className="text-xs text-yellow-400 mt-1.5 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                Select an engagement above to save scan results
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Results Area */}
      {displayRecon && (
        <>
          {/* Tab Navigation */}
          <div className="flex gap-1 mb-4 overflow-x-auto scrollbar-none">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2 text-xs font-display tracking-wider whitespace-nowrap transition-colors ${
                  activeTab === tab.id
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-card border border-border hover:border-primary/50'
                }`}
              >
                {tab.label}
                {tab.count > 0 && (
                  <span className="ml-2 px-1.5 py-0.5 bg-background/20 text-[10px] rounded-sm">{tab.count}</span>
                )}
              </button>
            ))}
            <div className="flex-1" />
            {(scanResult?.reconId || latestExistingRecon?.id) && (
              <Button
                size="sm"
                className="font-display tracking-wider bg-purple-600 hover:bg-purple-700 text-white whitespace-nowrap"
                onClick={handleAutoCampaign}
                disabled={autoCampaign.isPending}
              >
                <Sparkles className="w-4 h-4 mr-1" />
                {autoCampaign.isPending ? 'DESIGNING...' : 'AI CAMPAIGN DESIGN'}
              </Button>
            )}
          </div>

          {/* Scan Results Tab */}
          {activeTab === 'results' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Spoofability Score */}
              <div className="bg-card border border-border p-5">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-4">SPOOFABILITY SCORE</h3>
                <SpoofGauge score={displayRecon.spoofScore || 0} />
                <div className="mt-4 space-y-2">
                  {spoofFactors.map((f, i) => (
                    <div key={i} className={`flex items-start gap-2 text-xs p-2 border ${
                      f.impact === 'critical' ? 'border-red-500/30 bg-red-500/5' :
                      f.impact === 'high' ? 'border-orange-500/30 bg-orange-500/5' :
                      f.impact === 'medium' ? 'border-yellow-500/30 bg-yellow-500/5' :
                      'border-green-500/30 bg-green-500/5'
                    }`}>
                      {f.impact === 'critical' || f.impact === 'high' ? (
                        <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                      ) : (
                        <ShieldCheck className="w-3.5 h-3.5 text-green-400 shrink-0 mt-0.5" />
                      )}
                      <div>
                        <span className="font-display tracking-wider">{f.factor}</span>
                        <p className="text-muted-foreground mt-0.5">{f.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* DNS Records */}
              <div className="bg-card border border-border p-5">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-4">DNS & EMAIL RECORDS</h3>
                <DnsRow label="MX RECORDS" value={displayRecon.mxRecords || null} status={displayRecon.mxRecords ? 'info' : 'warn'} />
                <DnsRow label="SPF RECORD" value={displayRecon.spfRecord || null} status={displayRecon.spfRecord?.includes('-all') ? 'good' : displayRecon.spfRecord ? 'warn' : 'bad'} />
                <DnsRow label="DMARC RECORD" value={displayRecon.dmarcRecord || null} status={displayRecon.dmarcRecord?.includes('p=reject') ? 'good' : displayRecon.dmarcRecord ? 'warn' : 'bad'} />
              </div>

              {/* Quick Stats */}
              <div className="space-y-4">
                <div className="bg-card border border-border p-5">
                  <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3">DISCOVERY SUMMARY</h3>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="text-center p-3 bg-background border border-border">
                      <div className="text-2xl font-display text-primary">{displayRecon.subdomainCount || 0}</div>
                      <div className="text-[10px] text-muted-foreground tracking-wider">SUBDOMAINS</div>
                    </div>
                    <div className="text-center p-3 bg-background border border-border">
                      <div className="text-2xl font-display text-orange-400">{displayRecon.typosquatCount || 0}</div>
                      <div className="text-[10px] text-muted-foreground tracking-wider">TYPOSQUATS</div>
                    </div>
                  </div>
                </div>

                {/* Subdomains preview */}
                {displayRecon.subdomains && (
                  <div className="bg-card border border-border p-5">
                    <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3">SUBDOMAINS (crt.sh)</h3>
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                      {(typeof displayRecon.subdomains === 'string'
                        ? displayRecon.subdomains.split(',')
                        : displayRecon.subdomains
                      ).slice(0, 15).map((sub: string, i: number) => (
                        <div key={i} className="text-xs font-mono text-muted-foreground py-0.5 flex items-center gap-2">
                          <Network className="w-3 h-3 text-primary/50" />
                          {sub.trim()}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actions */}
                <div className="flex flex-col gap-2">
                  {selectedEngagementId && (
                    <Link href={`/engagements/${selectedEngagementId}/recon`}>
                      <Button variant="outline" className="w-full font-display tracking-wider text-xs">
                        <ExternalLink className="w-3.5 h-3.5 mr-2" />
                        FULL RECON DETAILS
                      </Button>
                    </Link>
                  )}
                  <Link href="/campaign-wizard">
                    <Button className="w-full font-display tracking-wider text-xs bg-red-600 hover:bg-red-700">
                      <Sparkles className="w-3.5 h-3.5 mr-2" />
                      LAUNCH CAMPAIGN FROM FINDINGS
                    </Button>
                  </Link>
                </div>
              </div>
            </div>
          )}

          {/* Typosquats Tab */}
          {activeTab === 'typosquats' && (
            <div className="bg-card border border-border">
              <div className="p-4 border-b border-border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground">
                  {displayTyposquats.length} TYPOSQUAT CANDIDATES
                </h3>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    className="font-display tracking-wider text-xs"
                    onClick={() => {
                      const reconId = scanResult?.reconId || latestExistingRecon?.id;
                      if (reconId) {
                        toast.info('Checking domain availability...');
                        batchCheck.mutateAsync({ reconId, limit: 30 }).then(results => {
                          const available = results.filter((r: any) => !r.resolved).length;
                          toast.success(`Checked ${results.length}: ${available} available`);
                        });
                      }
                    }}
                    disabled={batchCheck.isPending}
                  >
                    <Scan className="w-3.5 h-3.5 mr-1" />
                    CHECK AVAILABILITY
                  </Button>
                </div>
              </div>
              <div className="divide-y divide-border/50 max-h-[500px] overflow-y-auto">
                {visibleTyposquats.map((t: any, i: number) => (
                  <div key={i} className="flex items-center justify-between px-4 py-2 hover:bg-secondary/30 transition-colors">
                    <div className="flex items-center gap-3 min-w-0">
                      <Globe className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                      <span className="text-sm font-mono truncate">{t.domain}</span>
                      <span className="text-[10px] px-1.5 py-0.5 bg-secondary text-muted-foreground font-display tracking-wider shrink-0">
                        {t.permutationType?.replace(/-/g, ' ').toUpperCase()}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {t.dnsResolved === true && (
                        <span className="text-[10px] px-1.5 py-0.5 bg-red-500/10 text-red-400 border border-red-500/30">REGISTERED</span>
                      )}
                      {t.dnsResolved === false && (
                        <span className="text-[10px] px-1.5 py-0.5 bg-green-500/10 text-green-400 border border-green-500/30">AVAILABLE</span>
                      )}
                      {t.spoofScore != null && (
                        <span className={`text-[10px] px-1.5 py-0.5 ${
                          t.spoofScore >= 60 ? 'text-red-400' : t.spoofScore >= 40 ? 'text-yellow-400' : 'text-green-400'
                        }`}>
                          {t.spoofScore}/100
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
              {displayTyposquats.length > 20 && !showAllTyposquats && (
                <div className="p-3 text-center border-t border-border">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowAllTyposquats(true)}
                    className="font-display tracking-wider text-xs"
                  >
                    SHOW ALL {displayTyposquats.length} TYPOSQUATS
                    <ChevronDown className="w-3.5 h-3.5 ml-1" />
                  </Button>
                </div>
              )}
            </div>
          )}

          {/* AI Campaigns Tab */}
          {activeTab === 'campaigns' && (
            <div className="space-y-4">
              {autoCampaigns.length === 0 ? (
                <div className="bg-card border border-border p-8 text-center">
                  <Sparkles className="w-10 h-10 text-purple-400 mx-auto mb-3" />
                  <p className="font-display tracking-wider mb-2">NO AI CAMPAIGNS YET</p>
                  <p className="text-sm text-muted-foreground mb-4">
                    Click "AI CAMPAIGN DESIGN" to generate phishing campaigns based on the OSINT findings.
                  </p>
                  <Button
                    onClick={handleAutoCampaign}
                    disabled={autoCampaign.isPending}
                    className="font-display tracking-wider bg-purple-600 hover:bg-purple-700"
                  >
                    <Sparkles className="w-4 h-4 mr-2" />
                    GENERATE CAMPAIGNS
                  </Button>
                </div>
              ) : (
                autoCampaigns.map((campaign: any, i: number) => (
                  <div key={i} className="bg-card border border-border p-5">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h3 className="font-display text-lg tracking-wider">{campaign.name || `Campaign ${i + 1}`}</h3>
                        <p className="text-xs text-muted-foreground mt-0.5">{campaign.type || 'Phishing'}</p>
                      </div>
                      <span className={`text-xs px-2 py-0.5 font-display tracking-wider ${
                        campaign.difficulty === 'hard' ? 'bg-red-500/10 text-red-400 border border-red-500/30' :
                        campaign.difficulty === 'medium' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30' :
                        'bg-green-500/10 text-green-400 border border-green-500/30'
                      }`}>
                        {(campaign.difficulty || 'medium').toUpperCase()}
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground mb-3">{campaign.description}</p>
                    {campaign.subject && (
                      <div className="text-xs bg-background border border-border p-2 mb-3">
                        <span className="text-muted-foreground">Subject: </span>
                        <span className="font-mono">{campaign.subject}</span>
                      </div>
                    )}
                    {campaign.pretext && (
                      <div className="text-xs bg-background border border-border p-2 mb-3">
                        <span className="text-muted-foreground">Pretext: </span>
                        <span>{campaign.pretext}</span>
                      </div>
                    )}
                    <div className="flex gap-2">
                      <Link href="/campaign-wizard">
                        <Button size="sm" className="font-display tracking-wider text-xs">
                          <ArrowRight className="w-3.5 h-3.5 mr-1" />
                          USE IN WIZARD
                        </Button>
                      </Link>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </>
      )}

      {/* Empty state when no results */}
      {!displayRecon && !isScanning && (
        <div className="bg-card border border-border p-8 sm:p-12 text-center">
          <Radar className="w-12 h-12 text-primary/30 mx-auto mb-4" />
          <h2 className="font-display text-xl tracking-wider mb-2">READY TO SCAN</h2>
          <p className="text-sm text-muted-foreground max-w-md mx-auto mb-6">
            Enter a customer domain above to discover DNS records, email security posture, subdomains via certificate transparency, and generate typosquat candidates for phishing campaigns.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-lg mx-auto">
            <div className="p-3 bg-background border border-border">
              <Shield className="w-6 h-6 text-primary mx-auto mb-2" />
              <p className="text-xs font-display tracking-wider">SPF / DKIM / DMARC</p>
            </div>
            <div className="p-3 bg-background border border-border">
              <Globe className="w-6 h-6 text-orange-400 mx-auto mb-2" />
              <p className="text-xs font-display tracking-wider">TYPOSQUATS</p>
            </div>
            <div className="p-3 bg-background border border-border">
              <Sparkles className="w-6 h-6 text-purple-400 mx-auto mb-2" />
              <p className="text-xs font-display tracking-wider">AI CAMPAIGNS</p>
            </div>
          </div>
        </div>
      )}

      {/* Scanning state */}
      {isScanning && (
        <div className="bg-card border-2 border-primary/30 p-8 text-center">
          <RefreshCw className="w-10 h-10 text-primary mx-auto mb-4 animate-spin" />
          <h2 className="font-display text-xl tracking-wider mb-2">SCANNING {domain.toUpperCase()}</h2>
          <p className="text-sm text-muted-foreground">
            Analyzing DNS records, enumerating subdomains via crt.sh, generating typosquat candidates, scoring spoofability...
          </p>
        </div>
      )}

      {/* Recent Engagements with Recon */}
      {!displayRecon && !isScanning && engagements && engagements.length > 0 && (
        <div className="mt-6">
          <h3 className="font-display text-lg tracking-wider mb-3">RECENT ENGAGEMENTS</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {engagements.filter((e: any) => e.targetDomain).slice(0, 6).map((eng: any) => (
              <button
                key={eng.id}
                onClick={() => {
                  setSelectedEngagementId(eng.id);
                  setDomain(eng.targetDomain);
                }}
                className="bg-card border border-border p-4 text-left hover:border-primary/50 transition-colors group"
              >
                <div className="flex items-center gap-2 mb-1">
                  <Briefcase className="w-4 h-4 text-muted-foreground" />
                  <span className="font-display text-sm tracking-wider truncate">{eng.name}</span>
                </div>
                <div className="text-xs text-muted-foreground">{eng.customerName}</div>
                <div className="text-xs font-mono text-primary mt-1">{eng.targetDomain}</div>
                <div className="text-[10px] text-primary opacity-0 group-hover:opacity-100 transition-opacity mt-2 font-display tracking-wider">
                  SCAN THIS DOMAIN →
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </AppShell>
  );
}
