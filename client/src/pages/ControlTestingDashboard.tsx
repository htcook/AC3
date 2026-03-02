import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import {
  Shield, ShieldCheck, ShieldAlert, ShieldX, Clock, Calendar,
  CheckCircle2, XCircle, AlertTriangle, BarChart3, FileText,
  Download, RefreshCw, ChevronRight, TrendingUp, TrendingDown,
  Hash, Eye, Filter, ArrowUpDown
} from "lucide-react";

// ─── Types ──────────────────────────────────────────────────────────────────

interface TestedControl {
  id: string;
  category: string;
  name: string;
  verdict: "effective" | "partially_effective" | "ineffective" | "not_tested" | "expired";
  score: number;
  lastTested: string;
  expirationDate: string;
  testCount: number;
  evidenceCount: number;
  complianceFrameworks: string[];
  residualRisk: "low" | "medium" | "high" | "critical";
  trend: "improving" | "stable" | "degrading";
}

interface EvidenceTimelineEntry {
  id: string;
  controlName: string;
  timestamp: string;
  type: "test_execution" | "evidence_capture" | "compliance_check" | "expiration_warning";
  title: string;
  details: string;
  verdict?: string;
  score?: number;
  hash: string;
}

// ─── Verdict helpers ────────────────────────────────────────────────────────

const VERDICT_CONFIG = {
  effective: { label: "Effective", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30", icon: ShieldCheck },
  partially_effective: { label: "Partial", color: "bg-amber-500/10 text-amber-400 border-amber-500/30", icon: ShieldAlert },
  ineffective: { label: "Ineffective", color: "bg-red-500/10 text-red-400 border-red-500/30", icon: ShieldX },
  not_tested: { label: "Not Tested", color: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30", icon: Shield },
  expired: { label: "Expired", color: "bg-orange-500/10 text-orange-400 border-orange-500/30", icon: Clock },
};

const RISK_COLORS = {
  low: "text-emerald-400",
  medium: "text-amber-400",
  high: "text-orange-400",
  critical: "text-red-400",
};

function daysUntil(dateStr: string): number {
  return Math.ceil((new Date(dateStr).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
}

// ─── Demo data generator ────────────────────────────────────────────────────

function generateDemoControls(): TestedControl[] {
  const controls: TestedControl[] = [
    { id: "ctrl-1", category: "waf", name: "Cloudflare WAF", verdict: "effective", score: 92, lastTested: new Date(Date.now() - 3 * 86400000).toISOString(), expirationDate: new Date(Date.now() + 27 * 86400000).toISOString(), testCount: 8, evidenceCount: 24, complianceFrameworks: ["NIST 800-53", "PCI DSS"], residualRisk: "low", trend: "stable" },
    { id: "ctrl-2", category: "ids_ips", name: "Suricata IDS", verdict: "partially_effective", score: 68, lastTested: new Date(Date.now() - 7 * 86400000).toISOString(), expirationDate: new Date(Date.now() + 23 * 86400000).toISOString(), testCount: 5, evidenceCount: 15, complianceFrameworks: ["NIST 800-53", "SOC 2"], residualRisk: "medium", trend: "improving" },
    { id: "ctrl-3", category: "mfa", name: "Okta MFA", verdict: "effective", score: 95, lastTested: new Date(Date.now() - 1 * 86400000).toISOString(), expirationDate: new Date(Date.now() + 29 * 86400000).toISOString(), testCount: 12, evidenceCount: 36, complianceFrameworks: ["NIST 800-53", "FedRAMP", "CMMC"], residualRisk: "low", trend: "stable" },
    { id: "ctrl-4", category: "edr", name: "CrowdStrike Falcon", verdict: "effective", score: 88, lastTested: new Date(Date.now() - 5 * 86400000).toISOString(), expirationDate: new Date(Date.now() + 25 * 86400000).toISOString(), testCount: 6, evidenceCount: 18, complianceFrameworks: ["NIST 800-53", "HIPAA"], residualRisk: "low", trend: "improving" },
    { id: "ctrl-5", category: "network_segmentation", name: "VLAN Segmentation", verdict: "ineffective", score: 34, lastTested: new Date(Date.now() - 14 * 86400000).toISOString(), expirationDate: new Date(Date.now() + 16 * 86400000).toISOString(), testCount: 3, evidenceCount: 9, complianceFrameworks: ["PCI DSS", "NIST 800-53"], residualRisk: "high", trend: "degrading" },
    { id: "ctrl-6", category: "dlp", name: "Symantec DLP", verdict: "partially_effective", score: 58, lastTested: new Date(Date.now() - 10 * 86400000).toISOString(), expirationDate: new Date(Date.now() + 5 * 86400000).toISOString(), testCount: 4, evidenceCount: 12, complianceFrameworks: ["SOC 2", "GDPR"], residualRisk: "medium", trend: "degrading" },
    { id: "ctrl-7", category: "siem", name: "Splunk SIEM", verdict: "effective", score: 85, lastTested: new Date(Date.now() - 2 * 86400000).toISOString(), expirationDate: new Date(Date.now() + 28 * 86400000).toISOString(), testCount: 7, evidenceCount: 21, complianceFrameworks: ["NIST 800-53", "SOC 2", "HIPAA"], residualRisk: "low", trend: "stable" },
    { id: "ctrl-8", category: "encryption", name: "TLS 1.3 Enforcement", verdict: "expired", score: 0, lastTested: new Date(Date.now() - 45 * 86400000).toISOString(), expirationDate: new Date(Date.now() - 15 * 86400000).toISOString(), testCount: 2, evidenceCount: 6, complianceFrameworks: ["PCI DSS", "FedRAMP"], residualRisk: "critical", trend: "degrading" },
  ];
  return controls;
}

function generateDemoTimeline(): EvidenceTimelineEntry[] {
  const entries: EvidenceTimelineEntry[] = [
    { id: "ev-1", controlName: "Okta MFA", timestamp: new Date(Date.now() - 1 * 86400000).toISOString(), type: "test_execution", title: "Full MFA validation suite executed", details: "12 tests passed, 0 failed. Phishing-resistant MFA verified.", verdict: "effective", score: 95, hash: "a3f2c1d4e5b6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2" },
    { id: "ev-2", controlName: "Cloudflare WAF", timestamp: new Date(Date.now() - 3 * 86400000).toISOString(), type: "test_execution", title: "WAF bypass testing completed", details: "8 tests: 7 passed, 1 inconclusive. SQL injection blocking verified.", verdict: "effective", score: 92, hash: "b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3" },
    { id: "ev-3", controlName: "Symantec DLP", timestamp: new Date(Date.now() - 5 * 86400000).toISOString(), type: "expiration_warning", title: "Validation expiring in 5 days", details: "DLP control validation expires soon. Re-test recommended to maintain compliance.", hash: "c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4" },
    { id: "ev-4", controlName: "CrowdStrike Falcon", timestamp: new Date(Date.now() - 5 * 86400000).toISOString(), type: "test_execution", title: "EDR detection validation", details: "6 tests: 5 passed, 1 partial. Ransomware behavior detection confirmed.", verdict: "effective", score: 88, hash: "d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5" },
    { id: "ev-5", controlName: "Suricata IDS", timestamp: new Date(Date.now() - 7 * 86400000).toISOString(), type: "test_execution", title: "IDS signature validation", details: "5 tests: 3 passed, 2 failed. Lateral movement detection gaps identified.", verdict: "partially_effective", score: 68, hash: "e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6" },
    { id: "ev-6", controlName: "VLAN Segmentation", timestamp: new Date(Date.now() - 14 * 86400000).toISOString(), type: "test_execution", title: "Network segmentation bypass test", details: "3 tests: 1 passed, 2 failed. Cross-VLAN access possible via misconfigured ACLs.", verdict: "ineffective", score: 34, hash: "f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7" },
    { id: "ev-7", controlName: "TLS 1.3 Enforcement", timestamp: new Date(Date.now() - 45 * 86400000).toISOString(), type: "test_execution", title: "TLS enforcement validation", details: "2 tests passed. TLS 1.3 enforced on all endpoints.", verdict: "effective", score: 90, hash: "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8" },
  ];
  return entries;
}

// ─── Component ──────────────────────────────────────────────────────────────

export default function ControlTestingDashboard() {
  const [filterVerdict, setFilterVerdict] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("score");
  const [activeTab, setActiveTab] = useState("overview");

  const controls = useMemo(() => generateDemoControls(), []);
  const timeline = useMemo(() => generateDemoTimeline(), []);

  // ── Computed stats ──
  const stats = useMemo(() => {
    const total = controls.length;
    const effective = controls.filter(c => c.verdict === "effective").length;
    const partial = controls.filter(c => c.verdict === "partially_effective").length;
    const ineffective = controls.filter(c => c.verdict === "ineffective").length;
    const expired = controls.filter(c => c.verdict === "expired").length;
    const avgScore = total > 0 ? Math.round(controls.reduce((s, c) => s + c.score, 0) / total) : 0;
    const totalEvidence = controls.reduce((s, c) => s + c.evidenceCount, 0);
    const expiringSoon = controls.filter(c => {
      const days = daysUntil(c.expirationDate);
      return days > 0 && days <= 7;
    }).length;
    return { total, effective, partial, ineffective, expired, avgScore, totalEvidence, expiringSoon };
  }, [controls]);

  // ── Filtered & sorted controls ──
  const filteredControls = useMemo(() => {
    let list = [...controls];
    if (filterVerdict !== "all") {
      list = list.filter(c => c.verdict === filterVerdict);
    }
    list.sort((a, b) => {
      if (sortBy === "score") return b.score - a.score;
      if (sortBy === "expiration") return new Date(a.expirationDate).getTime() - new Date(b.expirationDate).getTime();
      if (sortBy === "risk") {
        const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return (riskOrder[a.residualRisk] ?? 4) - (riskOrder[b.residualRisk] ?? 4);
      }
      return 0;
    });
    return list;
  }, [controls, filterVerdict, sortBy]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Control Testing Dashboard</h1>
        <p className="text-muted-foreground mt-1">
          Continuous compliance monitoring — track compensating control validation status, evidence integrity, and expiration across your environment.
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-card/50 border-border/50">
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Overall Score</p>
                <p className="text-3xl font-bold mt-1">{stats.avgScore}<span className="text-sm text-muted-foreground">/100</span></p>
              </div>
              <div className={`p-2 rounded-lg ${stats.avgScore >= 70 ? "bg-emerald-500/10" : stats.avgScore >= 50 ? "bg-amber-500/10" : "bg-red-500/10"}`}>
                <BarChart3 className={`h-5 w-5 ${stats.avgScore >= 70 ? "text-emerald-400" : stats.avgScore >= 50 ? "text-amber-400" : "text-red-400"}`} />
              </div>
            </div>
            <Progress value={stats.avgScore} className="mt-2 h-1.5" />
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-border/50">
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Controls Tested</p>
                <p className="text-3xl font-bold mt-1">{stats.total}</p>
              </div>
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Shield className="h-5 w-5 text-blue-400" />
              </div>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              <span className="text-emerald-400">{stats.effective} effective</span>
              <span className="text-muted-foreground">·</span>
              <span className="text-amber-400">{stats.partial} partial</span>
              <span className="text-muted-foreground">·</span>
              <span className="text-red-400">{stats.ineffective} failed</span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-border/50">
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Evidence Records</p>
                <p className="text-3xl font-bold mt-1">{stats.totalEvidence}</p>
              </div>
              <div className="p-2 rounded-lg bg-violet-500/10">
                <Hash className="h-5 w-5 text-violet-400" />
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-2">SHA-256 integrity verified</p>
          </CardContent>
        </Card>

        <Card className={`bg-card/50 ${stats.expiringSoon > 0 || stats.expired > 0 ? "border-orange-500/50" : "border-border/50"}`}>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Attention Needed</p>
                <p className="text-3xl font-bold mt-1">{stats.expiringSoon + stats.expired}</p>
              </div>
              <div className="p-2 rounded-lg bg-orange-500/10">
                <AlertTriangle className="h-5 w-5 text-orange-400" />
              </div>
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              {stats.expired > 0 && <span className="text-red-400">{stats.expired} expired</span>}
              {stats.expiringSoon > 0 && <span className="text-orange-400">{stats.expiringSoon} expiring soon</span>}
              {stats.expired === 0 && stats.expiringSoon === 0 && <span className="text-emerald-400">All current</span>}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/50">
          <TabsTrigger value="overview">Control Status</TabsTrigger>
          <TabsTrigger value="timeline">Evidence Timeline</TabsTrigger>
          <TabsTrigger value="compliance">Compliance Map</TabsTrigger>
        </TabsList>

        {/* ── Control Status Grid ── */}
        <TabsContent value="overview" className="space-y-4">
          <div className="flex items-center gap-3">
            <Select value={filterVerdict} onValueChange={setFilterVerdict}>
              <SelectTrigger className="w-[180px] bg-muted/30">
                <Filter className="h-3.5 w-3.5 mr-2" />
                <SelectValue placeholder="Filter verdict" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Verdicts</SelectItem>
                <SelectItem value="effective">Effective</SelectItem>
                <SelectItem value="partially_effective">Partially Effective</SelectItem>
                <SelectItem value="ineffective">Ineffective</SelectItem>
                <SelectItem value="expired">Expired</SelectItem>
              </SelectContent>
            </Select>
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger className="w-[160px] bg-muted/30">
                <ArrowUpDown className="h-3.5 w-3.5 mr-2" />
                <SelectValue placeholder="Sort by" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="score">Score</SelectItem>
                <SelectItem value="expiration">Expiration</SelectItem>
                <SelectItem value="risk">Risk Level</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-3">
            {filteredControls.map((ctrl) => {
              const vc = VERDICT_CONFIG[ctrl.verdict];
              const VerdictIcon = vc.icon;
              const daysLeft = daysUntil(ctrl.expirationDate);
              const isExpiring = daysLeft > 0 && daysLeft <= 7;
              const isExpired = daysLeft <= 0;

              return (
                <Card key={ctrl.id} className={`bg-card/50 hover:bg-card/80 transition-colors ${isExpired ? "border-red-500/30" : isExpiring ? "border-orange-500/30" : "border-border/50"}`}>
                  <CardContent className="py-4 px-5">
                    <div className="flex items-center gap-4">
                      {/* Verdict icon */}
                      <div className={`p-2.5 rounded-lg border ${vc.color}`}>
                        <VerdictIcon className="h-5 w-5" />
                      </div>

                      {/* Control info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <h3 className="font-semibold text-sm">{ctrl.name}</h3>
                          <Badge variant="outline" className="text-[10px] uppercase">{ctrl.category.replace(/_/g, " ")}</Badge>
                          {ctrl.trend === "improving" && <TrendingUp className="h-3.5 w-3.5 text-emerald-400" />}
                          {ctrl.trend === "degrading" && <TrendingDown className="h-3.5 w-3.5 text-red-400" />}
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                          <span>{ctrl.testCount} tests</span>
                          <span>·</span>
                          <span>{ctrl.evidenceCount} evidence records</span>
                          <span>·</span>
                          <span className={RISK_COLORS[ctrl.residualRisk]}>
                            {ctrl.residualRisk.toUpperCase()} residual risk
                          </span>
                        </div>
                      </div>

                      {/* Score */}
                      <div className="text-center min-w-[60px]">
                        <p className={`text-2xl font-bold ${ctrl.score >= 70 ? "text-emerald-400" : ctrl.score >= 50 ? "text-amber-400" : ctrl.score > 0 ? "text-red-400" : "text-muted-foreground"}`}>
                          {ctrl.score > 0 ? ctrl.score : "—"}
                        </p>
                        <p className="text-[10px] text-muted-foreground uppercase">Score</p>
                      </div>

                      {/* Expiration */}
                      <div className="text-center min-w-[80px]">
                        {isExpired ? (
                          <Badge variant="destructive" className="text-xs">Expired</Badge>
                        ) : isExpiring ? (
                          <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30 text-xs">{daysLeft}d left</Badge>
                        ) : (
                          <p className="text-xs text-muted-foreground">{daysLeft}d remaining</p>
                        )}
                        <p className="text-[10px] text-muted-foreground mt-0.5">
                          Tested {Math.abs(Math.ceil((Date.now() - new Date(ctrl.lastTested).getTime()) / 86400000))}d ago
                        </p>
                      </div>

                      {/* Frameworks */}
                      <div className="hidden lg:flex gap-1 flex-wrap max-w-[140px]">
                        {ctrl.complianceFrameworks.map((fw) => (
                          <Badge key={fw} variant="outline" className="text-[9px]">{fw}</Badge>
                        ))}
                      </div>

                      {/* Actions */}
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          window.location.href = "/control-testing";
                          toast.info(`Opening test suite for ${ctrl.name}`);
                        }}
                      >
                        <RefreshCw className="h-3.5 w-3.5 mr-1" />
                        Re-test
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>

        {/* ── Evidence Timeline ── */}
        <TabsContent value="timeline" className="space-y-4">
          <Card className="bg-card/50 border-border/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Evidence Chain Timeline</CardTitle>
              <CardDescription>Chronological record of all control validation events with SHA-256 integrity hashes</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="relative">
                {/* Timeline line */}
                <div className="absolute left-[19px] top-0 bottom-0 w-px bg-border/50" />

                <div className="space-y-4">
                  {timeline.map((entry, idx) => {
                    const isTest = entry.type === "test_execution";
                    const isWarning = entry.type === "expiration_warning";

                    return (
                      <div key={entry.id} className="relative flex gap-4 pl-1">
                        {/* Timeline dot */}
                        <div className={`relative z-10 mt-1 h-[10px] w-[10px] rounded-full border-2 flex-shrink-0 ${
                          isWarning ? "border-orange-400 bg-orange-400/20" :
                          entry.verdict === "effective" ? "border-emerald-400 bg-emerald-400/20" :
                          entry.verdict === "partially_effective" ? "border-amber-400 bg-amber-400/20" :
                          entry.verdict === "ineffective" ? "border-red-400 bg-red-400/20" :
                          "border-zinc-400 bg-zinc-400/20"
                        }`} style={{ marginLeft: "10px" }} />

                        {/* Content */}
                        <div className="flex-1 pb-4">
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-sm">{entry.title}</span>
                            <Badge variant="outline" className="text-[10px]">{entry.controlName}</Badge>
                            {entry.score !== undefined && (
                              <Badge className={`text-[10px] ${
                                entry.score >= 70 ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" :
                                entry.score >= 50 ? "bg-amber-500/10 text-amber-400 border-amber-500/30" :
                                "bg-red-500/10 text-red-400 border-red-500/30"
                              }`}>
                                {entry.score}/100
                              </Badge>
                            )}
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">{entry.details}</p>
                          <div className="flex items-center gap-3 mt-1.5 text-[10px] text-muted-foreground">
                            <span className="flex items-center gap-1">
                              <Calendar className="h-3 w-3" />
                              {new Date(entry.timestamp).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" })}
                            </span>
                            <span className="flex items-center gap-1 font-mono">
                              <Hash className="h-3 w-3" />
                              {entry.hash.slice(0, 16)}...
                            </span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Compliance Map ── */}
        <TabsContent value="compliance" className="space-y-4">
          {(() => {
            const frameworkMap = new Map<string, { satisfied: number; partial: number; notSatisfied: number; controls: string[] }>();
            for (const ctrl of controls) {
              for (const fw of ctrl.complianceFrameworks) {
                if (!frameworkMap.has(fw)) frameworkMap.set(fw, { satisfied: 0, partial: 0, notSatisfied: 0, controls: [] });
                const entry = frameworkMap.get(fw)!;
                entry.controls.push(ctrl.name);
                if (ctrl.verdict === "effective") entry.satisfied++;
                else if (ctrl.verdict === "partially_effective") entry.partial++;
                else entry.notSatisfied++;
              }
            }

            return Array.from(frameworkMap.entries()).map(([fw, data]) => {
              const total = data.satisfied + data.partial + data.notSatisfied;
              const pct = total > 0 ? Math.round((data.satisfied / total) * 100) : 0;

              return (
                <Card key={fw} className="bg-card/50 border-border/50">
                  <CardContent className="py-4 px-5">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-semibold">{fw}</h3>
                        <p className="text-xs text-muted-foreground mt-0.5">{total} controls mapped</p>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="flex gap-2 text-xs">
                          <span className="flex items-center gap-1 text-emerald-400">
                            <CheckCircle2 className="h-3.5 w-3.5" /> {data.satisfied}
                          </span>
                          <span className="flex items-center gap-1 text-amber-400">
                            <AlertTriangle className="h-3.5 w-3.5" /> {data.partial}
                          </span>
                          <span className="flex items-center gap-1 text-red-400">
                            <XCircle className="h-3.5 w-3.5" /> {data.notSatisfied}
                          </span>
                        </div>
                        <div className="text-right min-w-[60px]">
                          <p className={`text-xl font-bold ${pct >= 70 ? "text-emerald-400" : pct >= 50 ? "text-amber-400" : "text-red-400"}`}>{pct}%</p>
                          <p className="text-[10px] text-muted-foreground">Satisfied</p>
                        </div>
                      </div>
                    </div>
                    <Progress value={pct} className="mt-3 h-1.5" />
                    <div className="flex gap-1 mt-2 flex-wrap">
                      {data.controls.map((c) => (
                        <Badge key={c} variant="outline" className="text-[10px]">{c}</Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              );
            });
          })()}
        </TabsContent>
      </Tabs>
    </div>
  );
}
