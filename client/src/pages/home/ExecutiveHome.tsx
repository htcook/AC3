import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  TrendingUp, TrendingDown, Shield, AlertTriangle, CheckCircle2,
  ArrowRight, BarChart3, Target, DollarSign, Clock
} from "lucide-react";

function RiskScoreRing({ score, label, color }: { score: number; label: string; color: string }) {
  const circumference = 2 * Math.PI * 36;
  const dashOffset = circumference - (score / 100) * circumference;
  return (
    <div className="flex flex-col items-center">
      <div className="relative w-24 h-24">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 80 80">
          <circle cx="40" cy="40" r="36" fill="none" stroke="currentColor" className="text-secondary" strokeWidth="6" />
          <circle cx="40" cy="40" r="36" fill="none" stroke="currentColor" className={color} strokeWidth="6"
            strokeDasharray={circumference} strokeDashoffset={dashOffset} strokeLinecap="round"
            style={{ transition: "stroke-dashoffset 1s ease" }} />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-lg font-display font-bold ${color}`}>{score}</span>
        </div>
      </div>
      <span className="text-[10px] font-display tracking-widest text-muted-foreground mt-1">{label}</span>
    </div>
  );
}

function KpiCard({ label, value, change, changeType, icon: Icon }: {
  label: string; value: string; change: string; changeType: "up" | "down" | "neutral"; icon: React.ComponentType<{ className?: string }>;
}) {
  const TrendIcon = changeType === "up" ? TrendingUp : changeType === "down" ? TrendingDown : Clock;
  const changeColor = changeType === "up" ? "text-emerald-400" : changeType === "down" ? "text-red-400" : "text-muted-foreground";
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between mb-3">
          <Icon className="w-5 h-5 text-muted-foreground" />
          <div className={`flex items-center gap-1 text-[10px] font-display tracking-wider ${changeColor}`}>
            <TrendIcon className="w-3 h-3" /> {change}
          </div>
        </div>
        <p className="text-2xl font-display font-bold">{value}</p>
        <p className="text-[10px] font-display tracking-widest text-muted-foreground mt-1">{label}</p>
      </CardContent>
    </Card>
  );
}

export default function ExecutiveHome() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display tracking-wider font-bold">EXECUTIVE OVERVIEW</h1>
        <p className="text-sm text-muted-foreground mt-1">Business risk posture, compliance status, and security investment ROI</p>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard label="OVERALL RISK SCORE" value="67/100" change="-8 vs last quarter" changeType="down" icon={Shield} />
        <KpiCard label="CRITICAL FINDINGS" value="14" change="+3 this month" changeType="up" icon={AlertTriangle} />
        <KpiCard label="REMEDIATION RATE" value="78%" change="+12% improvement" changeType="up" icon={CheckCircle2} />
        <KpiCard label="COST PER FINDING" value="$847" change="-$120 vs benchmark" changeType="down" icon={DollarSign} />
      </div>

      {/* Risk Posture + Compliance */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-primary" /> RISK POSTURE BY DOMAIN
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex justify-around">
              <RiskScoreRing score={72} label="NETWORK" color="text-amber-500" />
              <RiskScoreRing score={45} label="WEB APPS" color="text-red-500" />
              <RiskScoreRing score={88} label="CLOUD" color="text-emerald-500" />
              <RiskScoreRing score={61} label="IDENTITY" color="text-amber-500" />
            </div>
            <div className="mt-4 p-3 bg-secondary/30 rounded-lg">
              <p className="text-xs text-muted-foreground">
                <span className="text-red-400 font-medium">Web Applications</span> remain the highest risk domain with 14 critical and 23 high-severity findings across 8 external-facing applications.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400" /> COMPLIANCE STATUS
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {[
              { framework: "PCI DSS 4.0", score: 92, status: "compliant" },
              { framework: "SOC 2 Type II", score: 87, status: "compliant" },
              { framework: "NIST CSF 2.0", score: 74, status: "partial" },
              { framework: "ISO 27001", score: 81, status: "compliant" },
              { framework: "HIPAA", score: 68, status: "partial" },
            ].map((fw) => (
              <div key={fw.framework} className="flex items-center gap-3">
                <span className="text-xs font-display tracking-wider w-28 shrink-0">{fw.framework}</span>
                <div className="flex-1 bg-secondary rounded-full h-2">
                  <div className={`h-full rounded-full transition-all ${
                    fw.score >= 85 ? "bg-emerald-500" : fw.score >= 70 ? "bg-amber-500" : "bg-red-500"
                  }`} style={{ width: `${fw.score}%` }} />
                </div>
                <span className="text-[10px] font-display tracking-wider w-8 text-right">{fw.score}%</span>
                <span className={`text-[9px] font-display tracking-widest px-2 py-0.5 rounded-full ${
                  fw.status === "compliant" ? "bg-emerald-500/20 text-emerald-400" : "bg-amber-500/20 text-amber-400"
                }`}>{fw.status.toUpperCase()}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Engagement Summary + Investment ROI */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Target className="w-4 h-4 text-red-400" /> ENGAGEMENT SUMMARY
              </CardTitle>
              <Link href="/engagements">
                <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                  DETAILS <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div className="text-center p-3 bg-secondary/30 rounded-lg">
                <p className="text-xl font-display font-bold">3</p>
                <p className="text-[9px] font-display tracking-widest text-muted-foreground">ACTIVE</p>
              </div>
              <div className="text-center p-3 bg-secondary/30 rounded-lg">
                <p className="text-xl font-display font-bold">12</p>
                <p className="text-[9px] font-display tracking-widest text-muted-foreground">COMPLETED</p>
              </div>
              <div className="text-center p-3 bg-secondary/30 rounded-lg">
                <p className="text-xl font-display font-bold">247</p>
                <p className="text-[9px] font-display tracking-widest text-muted-foreground">TOTAL FINDINGS</p>
              </div>
            </div>
            <div className="space-y-2">
              {[
                { name: "Project Nightfall", type: "Red Team", status: "In Progress", severity: "high" },
                { name: "Q1 External Pentest", type: "Pentest", status: "Reporting", severity: "medium" },
                { name: "Cloud Security Audit", type: "Cloud", status: "Planning", severity: "low" },
              ].map((eng) => (
                <div key={eng.name} className="flex items-center justify-between p-2 bg-secondary/20 rounded">
                  <div>
                    <p className="text-xs font-display tracking-wider">{eng.name}</p>
                    <p className="text-[10px] text-muted-foreground">{eng.type}</p>
                  </div>
                  <span className={`text-[9px] font-display tracking-widest px-2 py-0.5 rounded-full ${
                    eng.status === "In Progress" ? "bg-blue-500/20 text-blue-400" :
                    eng.status === "Reporting" ? "bg-purple-500/20 text-purple-400" : "bg-gray-500/20 text-gray-400"
                  }`}>{eng.status.toUpperCase()}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
              <DollarSign className="w-4 h-4 text-emerald-400" /> SECURITY INVESTMENT ROI
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-center">
                <p className="text-xl font-display font-bold text-emerald-400">$2.4M</p>
                <p className="text-[9px] font-display tracking-widest text-muted-foreground">RISK REDUCED</p>
              </div>
              <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg text-center">
                <p className="text-xl font-display font-bold text-blue-400">340%</p>
                <p className="text-[9px] font-display tracking-widest text-muted-foreground">ROI</p>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">Annual platform cost</span>
                <span>$120,000</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">Findings remediated</span>
                <span>189 / 247</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">Mean time to remediate</span>
                <span>4.2 days</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">Breach prevention estimate</span>
                <span className="text-emerald-400">$2.4M saved</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
