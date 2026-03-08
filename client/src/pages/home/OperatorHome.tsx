import { useState, useMemo } from "react";
import { Link, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  ShieldAlert, Activity, Crosshair, Zap, ArrowRight, Clock,
  AlertTriangle, CheckCircle2, Target, Brain, Network, Lock,
  Scan, Globe, Play, Plus, Loader2, Radar, Eye, Briefcase,
  ChevronRight, BarChart3, RefreshCw
} from "lucide-react";

// ─── OPSEC Risk Gauge ─────────────────────────────────────────────────────────

function OpsecGauge({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score));
  const color = pct > 70 ? "text-red-500" : pct > 40 ? "text-amber-500" : "text-emerald-500";
  const label = pct > 70 ? "HIGH RISK" : pct > 40 ? "MODERATE" : "LOW RISK";
  const circumference = 2 * Math.PI * 60;
  const dashOffset = circumference - (pct / 100) * circumference * 0.75;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-40 h-40">
        <svg className="w-full h-full -rotate-[135deg]" viewBox="0 0 140 140">
          <circle cx="70" cy="70" r="60" fill="none" stroke="currentColor"
            className="text-secondary" strokeWidth="10" strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`} strokeLinecap="round" />
          <circle cx="70" cy="70" r="60" fill="none" stroke="currentColor"
            className={color} strokeWidth="10" strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
            strokeDashoffset={dashOffset} strokeLinecap="round" style={{ transition: "stroke-dashoffset 1s ease" }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-display font-bold ${color}`}>{pct}</span>
          <span className="text-[10px] font-display tracking-widest text-muted-foreground">{label}</span>
        </div>
      </div>
    </div>
  );
}

// ─── Quick Action Card ────────────────────────────────────────────────────────

function QuickAction({ href, icon: Icon, label, description, color }: {
  href: string; icon: React.ComponentType<{ className?: string }>; label: string; description: string; color: string;
}) {
  return (
    <Link href={href}>
      <Card className="group cursor-pointer hover:border-primary/30 transition-all duration-200 hover:shadow-lg hover:shadow-primary/5">
        <CardContent className="p-4 flex items-center gap-4">
          <div className={`w-10 h-10 rounded-lg ${color} flex items-center justify-center shrink-0`}>
            <Icon className="w-5 h-5 text-white" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-display tracking-wider font-medium truncate">{label}</p>
            <p className="text-xs text-muted-foreground truncate">{description}</p>
          </div>
          <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors shrink-0" />
        </CardContent>
      </Card>
    </Link>
  );
}

// ─── Stat Card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, trend, color }: {
  label: string; value: string | number; icon: React.ComponentType<{ className?: string }>; trend?: string; color: string;
}) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between mb-2">
          <div className={`w-8 h-8 rounded ${color} flex items-center justify-center`}>
            <Icon className="w-4 h-4 text-white" />
          </div>
          {trend && <span className="text-[10px] font-display tracking-wider text-muted-foreground">{trend}</span>}
        </div>
        <p className="text-2xl font-display font-bold">{value}</p>
        <p className="text-[11px] font-display tracking-wider text-muted-foreground mt-1">{label}</p>
      </CardContent>
    </Card>
  );
}

// ─── Status helpers ──────────────────────────────────────────────────────────

const SCAN_STATUS_CONFIG: Record<string, { color: string; icon: React.ComponentType<{ className?: string }>; label: string }> = {
  discovering: { color: "bg-blue-500/20 text-blue-400 border-blue-500/30", icon: Radar, label: "DISCOVERING" },
  passive_recon: { color: "bg-purple-500/20 text-purple-400 border-purple-500/30", icon: Eye, label: "RECON" },
  analyzing: { color: "bg-amber-500/20 text-amber-400 border-amber-500/30", icon: Brain, label: "ANALYZING" },
  scoring: { color: "bg-orange-500/20 text-orange-400 border-orange-500/30", icon: BarChart3, label: "SCORING" },
  recommending: { color: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30", icon: Target, label: "RECOMMENDING" },
  completed: { color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", icon: CheckCircle2, label: "COMPLETED" },
  scan_complete: { color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", icon: CheckCircle2, label: "SCAN COMPLETE" },
  engagement_running: { color: "bg-red-500/20 text-red-400 border-red-500/30", icon: Crosshair, label: "ENGAGEMENT" },
  failed: { color: "bg-red-500/20 text-red-400 border-red-500/30", icon: AlertTriangle, label: "FAILED" },
};

const ENGAGEMENT_STATUS_CONFIG: Record<string, { color: string; label: string }> = {
  planning: { color: "bg-blue-500/20 text-blue-400", label: "PLANNING" },
  active: { color: "bg-emerald-500/20 text-emerald-400", label: "ACTIVE" },
  completed: { color: "bg-gray-500/20 text-gray-400", label: "COMPLETED" },
  paused: { color: "bg-amber-500/20 text-amber-400", label: "PAUSED" },
};

// ─── Main Component ───────────────────────────────────────────────────────────

export default function OperatorHome() {
  const [, navigate] = useLocation();
  const [opsecScore] = useState(35);

  // Fetch recent scans (most recently updated first)
  const scansQuery = trpc.domainIntel.listScans.useQuery(undefined, {
    refetchInterval: 15000, // auto-refresh every 15s to catch status changes
  });
  const engagementsQuery = trpc.engagements.list.useQuery();

  const recentScans = useMemo(() => {
    const scans = scansQuery.data || [];
    return scans.slice(0, 5); // Already sorted by updatedAt desc from backend
  }, [scansQuery.data]);

  const activeEngagements = useMemo(() => {
    const engs = engagementsQuery.data || [];
    return engs
      .filter((e: any) => e.status === 'active' || e.status === 'planning')
      .slice(0, 4);
  }, [engagementsQuery.data]);

  const totalScans = scansQuery.data?.length || 0;
  const runningScans = (scansQuery.data || []).filter((s: any) =>
    ['discovering', 'passive_recon', 'analyzing', 'scoring', 'recommending'].includes(s.status)
  ).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-display tracking-wider font-bold">OPERATOR DASHBOARD</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Active operations, scans, engagements, and quick-launch tools
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link href="/domain-intel">
            <Button size="sm" className="text-[10px] font-display tracking-wider h-8 gap-1.5">
              <Plus className="w-3.5 h-3.5" />
              NEW SCAN
            </Button>
          </Link>
          <Link href="/engagements/new">
            <Button variant="outline" size="sm" className="text-[10px] font-display tracking-wider h-8 gap-1.5">
              <Briefcase className="w-3.5 h-3.5" />
              NEW ENGAGEMENT
            </Button>
          </Link>
        </div>
      </div>

      {/* ═══ SCAN & ENGAGEMENT COMMAND CENTER ═══ */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Recent Scans — 3 columns */}
        <div className="lg:col-span-3">
          <Card className="h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Scan className="w-4 h-4 text-primary" />
                  RECENT SCANS
                  {runningScans > 0 && (
                    <span className="text-[9px] bg-blue-500/20 text-blue-400 border border-blue-500/30 px-2 py-0.5 rounded-full font-display tracking-widest animate-pulse">
                      {runningScans} RUNNING
                    </span>
                  )}
                </CardTitle>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-muted-foreground font-display tracking-wider">{totalScans} total</span>
                  <Link href="/domain-intel">
                    <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                      VIEW ALL <ArrowRight className="w-3 h-3 ml-1" />
                    </Button>
                  </Link>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              {scansQuery.isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                </div>
              ) : recentScans.length === 0 ? (
                <div className="text-center py-8">
                  <Globe className="w-8 h-8 text-muted-foreground/40 mx-auto mb-2" />
                  <p className="text-xs text-muted-foreground">No scans yet</p>
                  <Link href="/domain-intel">
                    <Button variant="outline" size="sm" className="mt-3 text-[10px] font-display tracking-wider h-7 gap-1">
                      <Plus className="w-3 h-3" /> START FIRST SCAN
                    </Button>
                  </Link>
                </div>
              ) : (
                recentScans.map((scan: any) => {
                  const statusCfg = SCAN_STATUS_CONFIG[scan.status] || SCAN_STATUS_CONFIG.discovering;
                  const StatusIcon = statusCfg.icon;
                  const isRunning = ['discovering', 'passive_recon', 'analyzing', 'scoring', 'recommending'].includes(scan.status);
                  const updatedAt = scan.updatedAt ? new Date(scan.updatedAt) : new Date(scan.createdAt);
                  const timeAgo = getTimeAgo(updatedAt);

                  return (
                    <div
                      key={scan.id}
                      className="flex items-center gap-3 p-3 rounded-lg bg-secondary/20 hover:bg-secondary/40 cursor-pointer transition-colors group"
                      onClick={() => navigate(`/domain-intel/${scan.id}`)}
                    >
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border ${statusCfg.color}`}>
                        <StatusIcon className={`w-4 h-4 ${isRunning ? 'animate-pulse' : ''}`} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-display tracking-wider font-medium truncate">
                            {scan.primaryDomain}
                          </span>
                          <Badge variant="outline" className={`text-[8px] font-display tracking-widest px-1.5 py-0 h-4 border ${statusCfg.color}`}>
                            {statusCfg.label}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-3 mt-0.5">
                          <span className="text-[10px] text-muted-foreground">{(scan.orgProfile as any)?.customerName || scan.sector}</span>
                          <span className="text-[10px] text-muted-foreground/60">·</span>
                          <span className="text-[10px] text-muted-foreground">{timeAgo}</span>
                        </div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-muted-foreground/40 group-hover:text-primary transition-colors shrink-0" />
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>
        </div>

        {/* Active Engagements — 2 columns */}
        <div className="lg:col-span-2">
          <Card className="h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Briefcase className="w-4 h-4 text-amber-400" />
                  ENGAGEMENTS
                </CardTitle>
                <Link href="/engagements">
                  <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                    MANAGE <ArrowRight className="w-3 h-3 ml-1" />
                  </Button>
                </Link>
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              {engagementsQuery.isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                </div>
              ) : activeEngagements.length === 0 ? (
                <div className="text-center py-8">
                  <Briefcase className="w-8 h-8 text-muted-foreground/40 mx-auto mb-2" />
                  <p className="text-xs text-muted-foreground">No active engagements</p>
                  <Link href="/engagements/new">
                    <Button variant="outline" size="sm" className="mt-3 text-[10px] font-display tracking-wider h-7 gap-1">
                      <Plus className="w-3 h-3" /> CREATE ENGAGEMENT
                    </Button>
                  </Link>
                </div>
              ) : (
                activeEngagements.map((eng: any) => {
                  const statusCfg = ENGAGEMENT_STATUS_CONFIG[eng.status] || ENGAGEMENT_STATUS_CONFIG.planning;
                  const scanCount = eng.scanCount || 0;
                  return (
                    <div
                      key={eng.id}
                      className="p-3 rounded-lg bg-secondary/20 hover:bg-secondary/40 cursor-pointer transition-colors group"
                      onClick={() => navigate(`/engagements`)}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-sm font-display tracking-wider font-medium truncate">{eng.name}</span>
                        <Badge variant="outline" className={`text-[8px] font-display tracking-widest px-1.5 py-0 h-4 ${statusCfg.color}`}>
                          {statusCfg.label}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                        <span>{eng.customerName}</span>
                        <span className="text-muted-foreground/40">·</span>
                        <span>{scanCount} scan{scanCount !== 1 ? 's' : ''}</span>
                        {eng.startDate && (
                          <>
                            <span className="text-muted-foreground/40">·</span>
                            <span>{new Date(eng.startDate).toLocaleDateString()}</span>
                          </>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Top Row: Stats + OPSEC Gauge */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard label="ACTIVE ENGAGEMENTS" value={activeEngagements.length} icon={Crosshair} trend={`${totalScans} scans`} color="bg-red-500/80" />
          <StatCard label="FINDINGS TODAY" value={12} icon={AlertTriangle} trend="+4 new" color="bg-amber-500/80" />
          <StatCard label="SHELLS ACTIVE" value={5} icon={Target} trend="3 meterpreter" color="bg-emerald-500/80" />
          <StatCard label="CREDS FOUND" value={28} icon={Lock} trend="8 validated" color="bg-blue-500/80" />
        </div>
        <Card>
          <CardHeader className="pb-0 pt-3 px-4">
            <CardTitle className="text-[11px] font-display tracking-widest text-muted-foreground flex items-center gap-2">
              <ShieldAlert className="w-3.5 h-3.5" /> OPSEC EXPOSURE
            </CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            <OpsecGauge score={opsecScore} />
          </CardContent>
        </Card>
      </div>

      {/* Middle Row: Active Operations Timeline + Campaign Advisor */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Active Operations */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4 text-primary" /> ACTIVE OPERATIONS
              </CardTitle>
              <Link href="/engagements">
                <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                  VIEW ALL <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {[
              { name: "Project Nightfall", phase: "Gaining Access", progress: 45, status: "active" },
              { name: "Red Team Exercise Q1", phase: "Lateral Movement", progress: 72, status: "active" },
              { name: "Cloud Pentest - AWS", phase: "Reconnaissance", progress: 15, status: "planning" },
            ].map((op) => (
              <div key={op.name} className="p-3 bg-secondary/30 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-display tracking-wider font-medium">{op.name}</span>
                  <span className={`text-[9px] font-display tracking-widest px-2 py-0.5 rounded-full ${
                    op.status === "active" ? "bg-emerald-500/20 text-emerald-400" : "bg-blue-500/20 text-blue-400"
                  }`}>
                    {(op.status || '').toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex-1 bg-secondary rounded-full h-1.5">
                    <div className="bg-primary h-full rounded-full transition-all" style={{ width: `${op.progress}%` }} />
                  </div>
                  <span className="text-[10px] text-muted-foreground font-display tracking-wider">{op.phase}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Campaign Advisor Quick Access */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Brain className="w-4 h-4 text-purple-400" /> CAMPAIGN ADVISOR
              </CardTitle>
              <Link href="/campaign-advisor">
                <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                  OPEN CHAT <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="p-3 bg-purple-500/10 border border-purple-500/20 rounded-lg">
              <p className="text-xs text-purple-300 font-display tracking-wider mb-2">RECOMMENDED NEXT ACTION</p>
              <p className="text-sm">Based on current engagement state, consider escalating privileges on the compromised web server before attempting lateral movement to the domain controller.</p>
              <div className="flex items-center gap-2 mt-2">
                <span className="text-[9px] bg-purple-500/20 text-purple-400 px-2 py-0.5 rounded font-display tracking-wider">PRIVESC</span>
                <span className="text-[9px] bg-amber-500/20 text-amber-400 px-2 py-0.5 rounded font-display tracking-wider">OPSEC: MODERATE</span>
              </div>
            </div>
            <div className="p-3 bg-secondary/30 rounded-lg">
              <p className="text-xs text-muted-foreground font-display tracking-wider mb-1">ENGAGEMENT CONTEXT</p>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div><span className="text-muted-foreground">Phase:</span> <span className="text-foreground">Gaining Access</span></div>
                <div><span className="text-muted-foreground">Targets:</span> <span className="text-foreground">12 hosts</span></div>
                <div><span className="text-muted-foreground">Compromised:</span> <span className="text-foreground">3 hosts</span></div>
                <div><span className="text-muted-foreground">OPSEC Level:</span> <span className="text-amber-400">Moderate</span></div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <div>
        <h2 className="text-sm font-display tracking-widest text-muted-foreground mb-3">QUICK LAUNCH</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <QuickAction href="/credential-attacks" icon={Lock} label="CREDENTIAL ATTACKS" description="Launch brute force with Hydra/Medusa/NetExec" color="bg-red-500/80" />
          <QuickAction href="/exploitation-bridge" icon={Crosshair} label="EXPLOIT BRIDGE" description="Match vulns to exploits with LLM guidance" color="bg-orange-500/80" />
          <QuickAction href="/lateral-movement" icon={Network} label="LATERAL MOVEMENT" description="Plan pivots and tunnel configurations" color="bg-blue-500/80" />
          <QuickAction href="/privilege-escalation" icon={Zap} label="PRIVESC ENGINE" description="Enumerate escalation paths (Win/Linux/Cloud)" color="bg-purple-500/80" />
          <QuickAction href="/nuclei-scanner" icon={Target} label="VULN SCANNING" description="Run Nuclei templates against targets" color="bg-emerald-500/80" />
          <QuickAction href="/opsec-dashboard" icon={ShieldAlert} label="OPSEC DASHBOARD" description="Monitor detection risk and burn indicators" color="bg-amber-500/80" />
        </div>
      </div>

      {/* Recent Activity */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
            <Clock className="w-4 h-4 text-muted-foreground" /> RECENT ACTIVITY
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {[
              { time: "2 min ago", action: "Credential found", detail: "admin:P@ssw0rd123 on 10.0.1.50:22 (SSH)", type: "success" },
              { time: "8 min ago", action: "OPSEC alert", detail: "Port scan detected by NDR on subnet 10.0.2.0/24", type: "warning" },
              { time: "15 min ago", action: "Exploit executed", detail: "CVE-2021-44228 (Log4Shell) on 10.0.1.100:8080", type: "success" },
              { time: "22 min ago", action: "Scan completed", detail: "Nuclei scan: 47 findings across 12 hosts", type: "info" },
              { time: "1 hr ago", action: "Engagement started", detail: "Project Nightfall — Phase: Reconnaissance", type: "info" },
            ].map((event, i) => (
              <div key={i} className="flex items-center gap-3 p-2 rounded hover:bg-secondary/30 transition-colors">
                <div className={`w-2 h-2 rounded-full shrink-0 ${
                  event.type === "success" ? "bg-emerald-500" : event.type === "warning" ? "bg-amber-500" : "bg-blue-500"
                }`} />
                <span className="text-[10px] text-muted-foreground font-mono w-16 shrink-0">{event.time}</span>
                <span className="text-xs font-display tracking-wider font-medium w-32 shrink-0">{event.action}</span>
                <span className="text-xs text-muted-foreground truncate">{event.detail}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getTimeAgo(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;
  return date.toLocaleDateString();
}
