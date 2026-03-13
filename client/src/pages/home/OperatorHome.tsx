/**
 * Operator Cockpit — Redesigned
 * 
 * Your real-time command center. View live operations, active scans,
 * engagement status, and OPSEC exposure at a glance.
 * 
 * 3-column layout:
 *   Left   — Live Activity Timeline (what's happening now)
 *   Center — Scan Queue + Engagements (active operations)
 *   Right  — OPSEC Gauge + Campaign Advisor + Quick Launch
 */
import { useMemo, useState } from "react";
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
  const circumference = 2 * Math.PI * 45;
  const dashOffset = circumference - (pct / 100) * circumference * 0.75;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-28 h-28">
        <svg className="w-full h-full -rotate-[135deg]" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="45" fill="none" stroke="currentColor"
            className="text-secondary" strokeWidth="8" strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`} strokeLinecap="round" />
          <circle cx="50" cy="50" r="45" fill="none" stroke="currentColor"
            className={color} strokeWidth="8" strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
            strokeDashoffset={dashOffset} strokeLinecap="round" style={{ transition: "stroke-dashoffset 1s ease" }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-2xl font-display font-bold ${color}`}>{pct}</span>
          <span className="text-[8px] font-display tracking-widest text-muted-foreground">{label}</span>
        </div>
      </div>
    </div>
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

  // Fetch real data
  const scansQuery = trpc.domainIntel.listScans.useQuery(undefined, {
    refetchInterval: 15000,
  });
  const engagementsQuery = trpc.engagements.list.useQuery();

  const recentScans = useMemo(() => {
    return (scansQuery.data || []).slice(0, 6);
  }, [scansQuery.data]);

  const activeEngagements = useMemo(() => {
    return (engagementsQuery.data || [])
      .filter((e: any) => e.status === "active" || e.status === "planning")
      .slice(0, 5);
  }, [engagementsQuery.data]);

  const totalScans = scansQuery.data?.length || 0;
  const runningScans = (scansQuery.data || []).filter((s: any) =>
    ["discovering", "passive_recon", "analyzing", "scoring", "recommending"].includes(s.status)
  ).length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-display tracking-wider font-bold">OPERATOR COCKPIT</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Real-time command center for active operations, scans, and engagement status
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

      {/* ═══ 3-COLUMN LAYOUT ═══ */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">

        {/* ─── LEFT: Live Activity Timeline ─────────────────────────────── */}
        <div className="xl:col-span-3 space-y-4">
          <Card className="h-full">
            <CardHeader className="pb-2 pt-4 px-4">
              <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-primary" />
                LIVE ACTIVITY
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4">
              <div className="relative">
                {/* Timeline spine */}
                <div className="absolute left-[7px] top-0 bottom-0 w-px bg-border" />
                <div className="space-y-0">
                  {[
                    { time: "2m", action: "Credential found", detail: "admin:P@ss on 10.0.1.50:22", type: "success" as const },
                    { time: "8m", action: "OPSEC alert", detail: "Port scan detected by NDR", type: "warning" as const },
                    { time: "15m", action: "Exploit executed", detail: "CVE-2021-44228 on :8080", type: "success" as const },
                    { time: "22m", action: "Scan completed", detail: "47 findings across 12 hosts", type: "info" as const },
                    { time: "1h", action: "Engagement started", detail: "Project Nightfall", type: "info" as const },
                    { time: "2h", action: "Shell established", detail: "Meterpreter on 10.0.1.100", type: "success" as const },
                    { time: "3h", action: "Recon complete", detail: "DNS enum: 34 subdomains", type: "info" as const },
                    { time: "5h", action: "Phish delivered", detail: "12/15 emails opened", type: "warning" as const },
                  ].map((event, i) => (
                    <div key={i} className="flex items-start gap-3 py-2 pl-0 relative">
                      <div className={`w-[15px] h-[15px] rounded-full shrink-0 z-10 flex items-center justify-center ${
                        event.type === "success" ? "bg-emerald-500/20 border border-emerald-500/50" :
                        event.type === "warning" ? "bg-amber-500/20 border border-amber-500/50" :
                        "bg-blue-500/20 border border-blue-500/50"
                      }`}>
                        <div className={`w-[5px] h-[5px] rounded-full ${
                          event.type === "success" ? "bg-emerald-500" :
                          event.type === "warning" ? "bg-amber-500" :
                          "bg-blue-500"
                        }`} />
                      </div>
                      <div className="flex-1 min-w-0 -mt-0.5">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-display tracking-wider font-medium">{event.action}</span>
                          <span className="text-[9px] text-muted-foreground/60 font-mono">{event.time}</span>
                        </div>
                        <p className="text-[10px] text-muted-foreground truncate mt-0.5">{event.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ─── CENTER: Scan Queue + Engagements ─────────────────────────── */}
        <div className="xl:col-span-5 space-y-4">
          {/* Scan Queue */}
          <Card>
            <CardHeader className="pb-2 pt-4 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                  <Scan className="w-3.5 h-3.5 text-primary" />
                  SCAN QUEUE
                  {runningScans > 0 && (
                    <span className="text-[8px] bg-blue-500/20 text-blue-400 border border-blue-500/30 px-1.5 py-0.5 rounded-full font-display tracking-widest animate-pulse">
                      {runningScans} LIVE
                    </span>
                  )}
                </CardTitle>
                <div className="flex items-center gap-2">
                  <span className="text-[9px] text-muted-foreground font-display tracking-wider">{totalScans} total</span>
                  <Link href="/domain-intel">
                    <Button variant="ghost" size="sm" className="text-[9px] font-display tracking-wider h-6 px-2">
                      ALL <ArrowRight className="w-3 h-3 ml-1" />
                    </Button>
                  </Link>
                </div>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-1.5">
              {scansQuery.isLoading ? (
                <div className="flex items-center justify-center py-6">
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                </div>
              ) : recentScans.length === 0 ? (
                <div className="text-center py-6">
                  <Globe className="w-6 h-6 text-muted-foreground/40 mx-auto mb-2" />
                  <p className="text-[10px] text-muted-foreground">No scans yet</p>
                  <Link href="/domain-intel">
                    <Button variant="outline" size="sm" className="mt-2 text-[9px] font-display tracking-wider h-6 gap-1">
                      <Plus className="w-3 h-3" /> START SCAN
                    </Button>
                  </Link>
                </div>
              ) : (
                recentScans.map((scan: any) => {
                  const statusCfg = SCAN_STATUS_CONFIG[scan.status] || SCAN_STATUS_CONFIG.discovering;
                  const StatusIcon = statusCfg.icon;
                  const isRunning = ["discovering", "passive_recon", "analyzing", "scoring", "recommending"].includes(scan.status);
                  const updatedAt = scan.updatedAt ? new Date(scan.updatedAt) : new Date(scan.createdAt);

                  return (
                    <div
                      key={scan.id}
                      className="flex items-center gap-2.5 p-2.5 rounded-lg bg-secondary/20 hover:bg-secondary/40 cursor-pointer transition-colors group"
                      onClick={() => navigate(`/domain-intel/${scan.id}`)}
                    >
                      <div className={`w-7 h-7 rounded flex items-center justify-center shrink-0 border ${statusCfg.color}`}>
                        <StatusIcon className={`w-3.5 h-3.5 ${isRunning ? "animate-pulse" : ""}`} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-display tracking-wider font-medium truncate">
                            {scan.primaryDomain}
                          </span>
                          <Badge variant="outline" className={`text-[7px] font-display tracking-widest px-1 py-0 h-3.5 border ${statusCfg.color}`}>
                            {statusCfg.label}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-[9px] text-muted-foreground">{(scan.orgProfile as any)?.customerName || scan.sector}</span>
                          <span className="text-[9px] text-muted-foreground/40">·</span>
                          <span className="text-[9px] text-muted-foreground">{getTimeAgo(updatedAt)}</span>
                        </div>
                      </div>
                      <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/30 group-hover:text-primary transition-colors shrink-0" />
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>

          {/* Active Engagements */}
          <Card>
            <CardHeader className="pb-2 pt-4 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                  <Briefcase className="w-3.5 h-3.5 text-amber-400" />
                  ENGAGEMENTS
                </CardTitle>
                <Link href="/engagements">
                  <Button variant="ghost" size="sm" className="text-[9px] font-display tracking-wider h-6 px-2">
                    MANAGE <ArrowRight className="w-3 h-3 ml-1" />
                  </Button>
                </Link>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-1.5">
              {engagementsQuery.isLoading ? (
                <div className="flex items-center justify-center py-6">
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                </div>
              ) : activeEngagements.length === 0 ? (
                <div className="text-center py-6">
                  <Briefcase className="w-6 h-6 text-muted-foreground/40 mx-auto mb-2" />
                  <p className="text-[10px] text-muted-foreground">No active engagements</p>
                  <Link href="/engagements/new">
                    <Button variant="outline" size="sm" className="mt-2 text-[9px] font-display tracking-wider h-6 gap-1">
                      <Plus className="w-3 h-3" /> CREATE
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
                      className="p-2.5 rounded-lg bg-secondary/20 hover:bg-secondary/40 cursor-pointer transition-colors group"
                      onClick={() => navigate("/engagements")}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-display tracking-wider font-medium truncate">{eng.name}</span>
                        <Badge variant="outline" className={`text-[7px] font-display tracking-widest px-1 py-0 h-3.5 ${statusCfg.color}`}>
                          {statusCfg.label}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 text-[9px] text-muted-foreground">
                        <span>{eng.customerName}</span>
                        <span className="text-muted-foreground/40">·</span>
                        <span>{scanCount} scan{scanCount !== 1 ? "s" : ""}</span>
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

          {/* Active Operations */}
          <Card>
            <CardHeader className="pb-2 pt-4 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-primary" />
                  ACTIVE OPERATIONS
                </CardTitle>
                <Link href="/engagements">
                  <Button variant="ghost" size="sm" className="text-[9px] font-display tracking-wider h-6 px-2">
                    VIEW ALL <ArrowRight className="w-3 h-3 ml-1" />
                  </Button>
                </Link>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-2">
              {[
                { name: "Project Nightfall", phase: "Gaining Access", progress: 45, status: "active" },
                { name: "Red Team Exercise Q1", phase: "Lateral Movement", progress: 72, status: "active" },
                { name: "Cloud Pentest - AWS", phase: "Reconnaissance", progress: 15, status: "planning" },
              ].map((op) => (
                <div key={op.name} className="p-2.5 bg-secondary/30 rounded-lg">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-display tracking-wider font-medium truncate">{op.name}</span>
                    <span className={`text-[8px] font-display tracking-widest px-1.5 py-0.5 rounded-full ${
                      op.status === "active" ? "bg-emerald-500/20 text-emerald-400" : "bg-blue-500/20 text-blue-400"
                    }`}>
                      {(op.status || "").toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 bg-secondary rounded-full h-1">
                      <div className="bg-primary h-full rounded-full transition-all" style={{ width: `${op.progress}%` }} />
                    </div>
                    <span className="text-[9px] text-muted-foreground font-display tracking-wider shrink-0">{op.phase}</span>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* ─── RIGHT: Context Inspector ─────────────────────────────────── */}
        <div className="xl:col-span-4 space-y-4">
          {/* Stats Row */}
          <div className="grid grid-cols-2 gap-3">
            <StatMini label="ENGAGEMENTS" value={activeEngagements.length} icon={Crosshair} color="text-red-400" />
            <StatMini label="FINDINGS" value={12} icon={AlertTriangle} color="text-amber-400" />
            <StatMini label="SHELLS" value={5} icon={Target} color="text-emerald-400" />
            <StatMini label="CREDS" value={28} icon={Lock} color="text-blue-400" />
          </div>

          {/* OPSEC Gauge */}
          <Card>
            <CardHeader className="pb-0 pt-3 px-4">
              <CardTitle className="text-[10px] font-display tracking-widest text-muted-foreground flex items-center gap-2">
                <ShieldAlert className="w-3 h-3" /> OPSEC EXPOSURE
              </CardTitle>
            </CardHeader>
            <CardContent className="p-3 flex justify-center">
              <OpsecGauge score={opsecScore} />
            </CardContent>
          </Card>

          {/* Campaign Advisor */}
          <Card>
            <CardHeader className="pb-2 pt-4 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                  <Brain className="w-3.5 h-3.5 text-purple-400" />
                  CAMPAIGN ADVISOR
                </CardTitle>
                <Link href="/campaign-advisor">
                  <Button variant="ghost" size="sm" className="text-[9px] font-display tracking-wider h-6 px-2">
                    CHAT <ArrowRight className="w-3 h-3 ml-1" />
                  </Button>
                </Link>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-2">
              <div className="p-3 bg-purple-500/10 border border-purple-500/20 rounded-lg">
                <p className="text-[9px] text-purple-300 font-display tracking-wider mb-1.5">RECOMMENDED NEXT ACTION</p>
                <p className="text-xs leading-relaxed">Consider escalating privileges on the compromised web server before lateral movement to the domain controller.</p>
                <div className="flex items-center gap-1.5 mt-2">
                  <span className="text-[8px] bg-purple-500/20 text-purple-400 px-1.5 py-0.5 rounded font-display tracking-wider">PRIVESC</span>
                  <span className="text-[8px] bg-amber-500/20 text-amber-400 px-1.5 py-0.5 rounded font-display tracking-wider">OPSEC: MODERATE</span>
                </div>
              </div>
              <div className="p-2.5 bg-secondary/30 rounded-lg">
                <p className="text-[9px] text-muted-foreground font-display tracking-wider mb-1">CONTEXT</p>
                <div className="grid grid-cols-2 gap-1.5 text-[10px]">
                  <div><span className="text-muted-foreground">Phase:</span> <span className="text-foreground">Gaining Access</span></div>
                  <div><span className="text-muted-foreground">Targets:</span> <span className="text-foreground">12 hosts</span></div>
                  <div><span className="text-muted-foreground">Compromised:</span> <span className="text-foreground">3 hosts</span></div>
                  <div><span className="text-muted-foreground">OPSEC:</span> <span className="text-amber-400">Moderate</span></div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Quick Launch */}
          <Card>
            <CardHeader className="pb-2 pt-4 px-4">
              <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-yellow-400" />
                QUICK LAUNCH
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4">
              <div className="grid grid-cols-2 gap-2">
                {[
                  { href: "/credential-attacks", icon: Lock, label: "CRED ATTACKS", color: "bg-red-500/80" },
                  { href: "/exploitation-bridge", icon: Crosshair, label: "EXPLOIT BRIDGE", color: "bg-orange-500/80" },
                  { href: "/lateral-movement", icon: Network, label: "LATERAL MOVE", color: "bg-blue-500/80" },
                  { href: "/privilege-escalation", icon: Zap, label: "PRIVESC", color: "bg-purple-500/80" },
                  { href: "/nuclei-scanner", icon: Target, label: "VULN SCAN", color: "bg-emerald-500/80" },
                  { href: "/opsec-dashboard", icon: ShieldAlert, label: "OPSEC", color: "bg-amber-500/80" },
                ].map(action => (
                  <Link key={action.href} href={action.href}>
                    <button className="w-full flex items-center gap-2 p-2 rounded-lg bg-secondary/30 hover:bg-secondary/50 transition-colors text-left group">
                      <div className={`w-7 h-7 rounded flex items-center justify-center shrink-0 ${action.color}`}>
                        <action.icon className="w-3.5 h-3.5 text-white" />
                      </div>
                      <span className="text-[9px] font-display tracking-wider font-medium truncate">{action.label}</span>
                    </button>
                  </Link>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

// ─── Mini Stat Card ──────────────────────────────────────────────────────────

function StatMini({ label, value, icon: Icon, color }: {
  label: string; value: string | number; icon: React.ComponentType<{ className?: string }>; color: string;
}) {
  return (
    <Card>
      <CardContent className="p-3">
        <div className="flex items-center gap-2 mb-1">
          <Icon className={`w-3.5 h-3.5 ${color}`} />
          <span className="text-[9px] font-display tracking-widest text-muted-foreground">{label}</span>
        </div>
        <p className="text-xl font-display font-bold">{value}</p>
      </CardContent>
    </Card>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getTimeAgo(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;
  return date.toLocaleDateString();
}
