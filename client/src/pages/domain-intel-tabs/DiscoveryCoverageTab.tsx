// @ts-nocheck
import { useState, useEffect, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Streamdown } from "streamdown";
import { toast } from "sonner";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Slider } from "@/components/ui/slider";
import {
  ArrowLeft, Shield, Target, AlertTriangle, Brain, Globe, Server,
  ChevronDown, ChevronUp, Crosshair, Zap, FileText, ExternalLink,
  Activity, Lock, Eye, Network, Loader2, BarChart3, Bug, Skull, Database, Cpu,
  TrendingUp, Fingerprint, Radar, Info, Search, Radio, Scan, Flag, Undo2, MessageSquare,
  Download, FlaskConical, Mail, ShieldAlert, ShieldCheck, ShieldX, CheckCircle2, XCircle, RefreshCw,
  Layers, Play, Pause, Settings2, GitBranch, Link2, Users, Hash, Clock, Unplug, Wifi,
  Workflow, Lightbulb, Route, Telescope, ShieldQuestion, ArrowRightLeft, KeyRound,
  Box, ClipboardCheck, PackageSearch, GitCompareArrows
} from "lucide-react";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";

export default function DiscoveryCoverageTab({ scan, pipeline }: { scan: any; pipeline: any }) {
  const coverage = pipeline?.discoveryCoverage || (scan as any)?.pipelineOutput?.discoveryCoverage;

  // Fallback red team priorities when no coverage data exists yet
  const DEFAULT_PRIORITIES = [
    { id: 1, name: "Domains, Subdomains & DNS Records", shortName: "DNS", weight: 15, covered: false, observationCount: 0, contributingConnectors: [], quality: "none", hasConnectors: true, attackTechniques: ["Zone transfer", "Subdomain takeover", "DNS cache poisoning"] },
    { id: 2, name: "IP Ranges, Netblocks & Hosting Providers", shortName: "IPs", weight: 12, covered: false, observationCount: 0, contributingConnectors: [], quality: "none", hasConnectors: true, attackTechniques: ["Network scanning", "BGP hijacking", "IP spoofing"] },
    { id: 3, name: "Live Hosts & Open Ports/Services", shortName: "Ports", weight: 12, covered: false, observationCount: 0, contributingConnectors: [], quality: "none", hasConnectors: true, attackTechniques: ["Service exploitation", "Banner grabbing", "Protocol attacks"] },
    { id: 4, name: "Web Applications, APIs & Technology Stacks", shortName: "WebApps", weight: 12, covered: false, observationCount: 0, contributingConnectors: [], quality: "none", hasConnectors: true, attackTechniques: ["SQLi", "XSS", "API abuse", "Deserialization"] },
    { id: 5, name: "Employee Names, Emails & Roles", shortName: "People", weight: 10, covered: false, observationCount: 0, contributingConnectors: [], quality: "none", hasConnectors: false, attackTechniques: ["Spear phishing", "Social engineering", "Credential stuffing"] },
    { id: 6, name: "Key Personnel & Social Media OSINT", shortName: "OSINT", weight: 8, covered: false, observationCount: 0, contributingConnectors: [], quality: "none", hasConnectors: false, attackTechniques: ["Whaling", "Pretexting", "Vishing"] },
    { id: 7, name: "Leaked/Breached Credentials & Sensitive Data", shortName: "Breaches", weight: 12, covered: false, observationCount: 0, contributingConnectors: [], quality: "none", hasConnectors: true, attackTechniques: ["Credential stuffing", "Password spraying", "Account takeover"] },
    { id: 8, name: "Cloud Assets & Misconfigurations", shortName: "Cloud", weight: 8, covered: false, observationCount: 0, contributingConnectors: [], quality: "none", hasConnectors: true, attackTechniques: ["S3 bucket access", "SSRF", "Metadata exploitation"] },
    { id: 9, name: "Security Tooling & Defensive Posture", shortName: "Defense", weight: 6, covered: false, observationCount: 0, contributingConnectors: [], quality: "none", hasConnectors: true, attackTechniques: ["WAF bypass", "EDR evasion", "DMARC spoofing"] },
    { id: 10, name: "Code Repositories & Configuration Leaks", shortName: "Code", weight: 5, covered: false, observationCount: 0, contributingConnectors: [], quality: "none", hasConnectors: false, attackTechniques: ["Secret extraction", "Source code analysis", "Config exploitation"] },
  ];

  const priorities = coverage?.priorities || DEFAULT_PRIORITIES;
  const coverageScore = coverage?.coverageScore ?? (scan as any)?.discoveryCoverageScore ?? 0;
  const coverageBand = coverage?.coverageBand ?? (scan as any)?.discoveryCoverageBand ?? "unknown";
  const assessment = coverage?.assessment ?? "No coverage data available. Run a scan to compute discovery coverage.";
  const structuralGaps = coverage?.structuralGaps ?? [];
  const actionableGaps = coverage?.actionableGaps ?? [];

  const bandColor = coverageBand === "comprehensive" ? "text-emerald-400" : coverageBand === "good" ? "text-blue-400" : coverageBand === "partial" ? "text-amber-400" : "text-red-400";
  const bandBorder = coverageBand === "comprehensive" ? "border-emerald-500/30" : coverageBand === "good" ? "border-blue-500/30" : coverageBand === "partial" ? "border-amber-500/30" : "border-red-500/30";

  const qualityColor = (q: string) => {
    switch (q) {
      case "strong": return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
      case "moderate": return "bg-blue-500/20 text-blue-400 border-blue-500/30";
      case "weak": return "bg-amber-500/20 text-amber-400 border-amber-500/30";
      default: return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
    }
  };

  return (
    <div className="space-y-6">
      {/* Page description */}
      <p className="text-sm text-muted-foreground">
        This tab evaluates how well the scan covered the red team's top-10 external discovery priorities. 
        Higher coverage means fewer blind spots for adversaries to exploit during reconnaissance.
      </p>

      {/* Coverage Summary Card */}
      <Card className={bandBorder}>
        <CardContent className="p-6">
          <div className="flex items-start gap-6">
            <div className="text-center min-w-[100px]">
              <p className={`text-5xl font-bold ${bandColor}`}>{coverageScore}%</p>
              <p className="text-xs text-muted-foreground mt-1 capitalize">{coverageBand} Coverage</p>
              <p className="text-[10px] text-muted-foreground">
                {priorities.filter((p: any) => p.covered).length}/{priorities.length} priorities
              </p>
            </div>
            <div className="flex-1 space-y-3">
              <p className="text-sm">{assessment}</p>
              {structuralGaps.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-red-400 mb-1">Structural Gaps (no connectors available):</p>
                  <ul className="text-xs text-muted-foreground space-y-0.5">
                    {structuralGaps.map((g: string, i: number) => (
                      <li key={i} className="flex items-center gap-1.5">
                        <span className="w-1 h-1 rounded-full bg-red-400 shrink-0" />
                        {g}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {actionableGaps.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-amber-400 mb-1">Actionable Gaps (connectors exist but no data found):</p>
                  <ul className="text-xs text-muted-foreground space-y-0.5">
                    {actionableGaps.map((g: string, i: number) => (
                      <li key={i} className="flex items-center gap-1.5">
                        <span className="w-1 h-1 rounded-full bg-amber-400 shrink-0" />
                        {g}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Priority Matrix */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/50 text-xs text-muted-foreground">
                  <th className="text-left p-3 w-8">#</th>
                  <th className="text-left p-3">Discovery Priority</th>
                  <th className="text-center p-3 w-20">Weight</th>
                  <th className="text-center p-3 w-20">Status</th>
                  <th className="text-center p-3 w-20">Quality</th>
                  <th className="text-center p-3 w-24">Observations</th>
                  <th className="text-left p-3">Contributing Sources</th>
                  <th className="text-left p-3">Attack Techniques</th>
                </tr>
              </thead>
              <tbody>
                {priorities.map((p: any) => (
                  <tr key={p.id} className={`border-b border-border/20 ${p.covered ? "" : "opacity-60"}`}>
                    <td className="p-3 font-mono text-xs text-muted-foreground">{p.id}</td>
                    <td className="p-3">
                      <div>
                        <span className="font-medium">{p.name}</span>
                        {!p.hasConnectors && (
                          <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-zinc-500/20 text-zinc-400 border border-zinc-500/30">
                            No Connector
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-3 text-center">
                      <div className="flex items-center gap-1.5 justify-center">
                        <div className="w-12 h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                          <div className="h-full rounded-full bg-blue-500/70" style={{ width: `${(p.weight / 15) * 100}%` }} />
                        </div>
                        <span className="text-xs font-mono">{p.weight}%</span>
                      </div>
                    </td>
                    <td className="p-3 text-center">
                      {p.covered ? (
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                          Covered
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                          Gap
                        </span>
                      )}
                    </td>
                    <td className="p-3 text-center">
                      <span className={`text-xs px-2 py-0.5 rounded-full border capitalize ${qualityColor(p.quality)}`}>
                        {p.quality}
                      </span>
                    </td>
                    <td className="p-3 text-center font-mono text-xs">{p.observationCount}</td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1">
                        {p.contributingConnectors.length > 0 ? p.contributingConnectors.map((c: string) => (
                          <span key={c} className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                            {c}
                          </span>
                        )) : (
                          <span className="text-[10px] text-muted-foreground italic">—</span>
                        )}
                      </div>
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1">
                        {(p.attackTechniques || []).slice(0, 3).map((t: string) => (
                          <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/20">
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Coverage Bar Visualization */}
      <Card>
        <CardContent className="p-4">
          <p className="text-xs font-medium text-muted-foreground mb-3">Weighted Coverage Breakdown</p>
          <div className="flex h-6 rounded-lg overflow-hidden border border-border/30">
            {priorities.map((p: any) => (
              <div
                key={p.id}
                className={`relative group transition-all ${p.covered ? "bg-emerald-500/40" : "bg-zinc-800"}`}
                style={{ width: `${p.weight}%` }}
                title={`${p.shortName}: ${p.weight}% weight — ${p.covered ? "Covered" : "Gap"}`}
              >
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-[9px] font-medium truncate px-0.5">{p.shortName}</span>
                </div>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-4 mt-2 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded bg-emerald-500/40" /> Covered</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded bg-zinc-800 border border-zinc-700" /> Gap</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}


// ─── Email Security Analysis Tab ─────────────────────────────────────────────

