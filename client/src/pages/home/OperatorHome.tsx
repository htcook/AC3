import { useState, useMemo } from "react";
import { Link } from "wouter";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  ShieldAlert, Activity, Crosshair, Zap, ArrowRight, Clock,
  AlertTriangle, CheckCircle2, Target, Brain, Network, Lock
} from "lucide-react";

// ─── OPSEC Risk Gauge ─────────────────────────────────────────────────────────

function OpsecGauge({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score));
  const color = pct > 70 ? "text-red-500" : pct > 40 ? "text-amber-500" : "text-emerald-500";
  const bgColor = pct > 70 ? "bg-red-500" : pct > 40 ? "bg-amber-500" : "bg-emerald-500";
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

// ─── Main Component ───────────────────────────────────────────────────────────

export default function OperatorHome() {
  const [opsecScore] = useState(35);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-display tracking-wider font-bold">OPERATOR DASHBOARD</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Active operations, OPSEC status, and quick-launch tools
        </p>
      </div>

      {/* Top Row: Stats + OPSEC Gauge */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard label="ACTIVE ENGAGEMENTS" value={3} icon={Crosshair} trend="2 this week" color="bg-red-500/80" />
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
                    {op.status.toUpperCase()}
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
