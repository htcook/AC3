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

export default function AccuracyInsightsTab({ scanId }: { scanId: number }) {
  const [activeSection, setActiveSection] = useState<string | null>(null);

  // Fetch accuracy data from the new tRPC endpoints
  const corroboration = trpc.accuracyEngine.corroboration.analyze.useQuery({ scanId }, { enabled: !!scanId, retry: false });
  const temporalScores = trpc.accuracyEngine.temporal.scanScores.useQuery({ scanId }, { enabled: !!scanId, retry: false });
  const attackChains = trpc.accuracyEngine.attackChains.analyze.useQuery({ scanId }, { enabled: !!scanId, retry: false });
  const feedbackSummary = trpc.accuracyEngine.feedback.summary.useQuery(undefined, { retry: false });
  const remediationSummary = trpc.accuracyEngine.remediation.summary.useQuery(undefined, { retry: false });

  const isLoading = corroboration.isLoading || temporalScores.isLoading || attackChains.isLoading;

  return (
    <div className="space-y-6">
      {/* Page Description */}
      <div className="text-sm text-muted-foreground">
        Accuracy insights show how findings are corroborated across sources, scored with temporal urgency, and analyzed for multi-step attack chains. These metrics help prioritize remediation by separating high-confidence, time-sensitive threats from stale or single-source observations.
      </div>

      {/* Summary Cards Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Corroboration Summary */}
        <Card className="border-blue-500/20 bg-blue-500/5 cursor-pointer hover:border-blue-500/40 transition-colors"
          onClick={() => setActiveSection(activeSection === 'corroboration' ? null : 'corroboration')}>
          <CardContent className="p-4 text-center">
            <Fingerprint className="h-5 w-5 text-blue-400 mx-auto mb-2" />
            <p className="text-2xl font-bold text-blue-400">
              {corroboration.isLoading ? '...' : corroboration.data?.stats?.corroborationRate !== undefined ? `${Math.round(corroboration.data.stats.corroborationRate)}%` : '—'}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Corroboration Rate</p>
            <p className="text-[10px] text-muted-foreground/70">
              {corroboration.data?.highConfidence ?? 0} high / {corroboration.data?.mediumConfidence ?? 0} medium
            </p>
          </CardContent>
        </Card>

        {/* Temporal Urgency Summary */}
        <Card className="border-amber-500/20 bg-amber-500/5 cursor-pointer hover:border-amber-500/40 transition-colors"
          onClick={() => setActiveSection(activeSection === 'temporal' ? null : 'temporal')}>
          <CardContent className="p-4 text-center">
            <Activity className="h-5 w-5 text-amber-400 mx-auto mb-2" />
            <p className="text-2xl font-bold text-amber-400">
              {temporalScores.isLoading ? '...' : temporalScores.data?.averageMultiplier !== undefined ? `${temporalScores.data.averageMultiplier}x` : '—'}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Avg Temporal Multiplier</p>
            <p className="text-[10px] text-muted-foreground/70">
              {temporalScores.data?.urgencyDistribution?.immediate ?? 0} immediate / {temporalScores.data?.urgencyDistribution?.urgent ?? 0} urgent
            </p>
          </CardContent>
        </Card>

        {/* Attack Chains Summary */}
        <Card className="border-red-500/20 bg-red-500/5 cursor-pointer hover:border-red-500/40 transition-colors"
          onClick={() => setActiveSection(activeSection === 'chains' ? null : 'chains')}>
          <CardContent className="p-4 text-center">
            <Network className="h-5 w-5 text-red-400 mx-auto mb-2" />
            <p className="text-2xl font-bold text-red-400">
              {attackChains.isLoading ? '...' : attackChains.data?.totalChains ?? '—'}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Attack Chains Found</p>
            <p className="text-[10px] text-muted-foreground/70">
              {attackChains.data?.criticalChains ?? 0} critical / {attackChains.data?.highChains ?? 0} high
            </p>
          </CardContent>
        </Card>

        {/* Exploit Feedback Summary */}
        <Card className="border-purple-500/20 bg-purple-500/5 cursor-pointer hover:border-purple-500/40 transition-colors"
          onClick={() => setActiveSection(activeSection === 'feedback' ? null : 'feedback')}>
          <CardContent className="p-4 text-center">
            <TrendingUp className="h-5 w-5 text-purple-400 mx-auto mb-2" />
            <p className="text-2xl font-bold text-purple-400">
              {feedbackSummary.isLoading ? '...' : feedbackSummary.data?.overallSuccessRate !== undefined ? `${Math.round(feedbackSummary.data.overallSuccessRate)}%` : '—'}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Exploit Success Rate</p>
            <p className="text-[10px] text-muted-foreground/70">
              {feedbackSummary.data?.totalModules ?? 0} modules tracked
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Expanded Detail Sections */}
      {activeSection === 'corroboration' && corroboration.data && (
        <Card className="border-blue-500/30 animate-in fade-in slide-in-from-top-2 duration-200">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Fingerprint className="h-4 w-4 text-blue-400" />
              Cross-Source Corroboration Details
            </CardTitle>
            <CardDescription className="text-xs">
              Findings confirmed by multiple independent sources receive higher confidence scores. High-confidence findings are corroborated by 3+ sources.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Tier Distribution */}
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-center">
                <p className="text-xl font-bold text-emerald-400">{corroboration.data.highConfidence}</p>
                <p className="text-[10px] text-muted-foreground">High Confidence (3+ sources)</p>
              </div>
              <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-center">
                <p className="text-xl font-bold text-amber-400">{corroboration.data.mediumConfidence}</p>
                <p className="text-[10px] text-muted-foreground">Corroborated (2 sources)</p>
              </div>
              <div className="p-3 rounded-lg bg-zinc-500/10 border border-zinc-500/20 text-center">
                <p className="text-xl font-bold text-zinc-400">{corroboration.data.lowConfidence}</p>
                <p className="text-[10px] text-muted-foreground">Unverified (1 source)</p>
              </div>
            </div>

            {/* Top Corroborated Findings */}
            {corroboration.data.findings.length > 0 && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-2">Top Corroborated Findings</p>
                <div className="space-y-1.5 max-h-60 overflow-y-auto">
                  {corroboration.data.findings.slice(0, 15).map((f: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-2 rounded bg-muted/30 text-xs">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono truncate">{f.hostname || f.ip || '—'}</span>
                        {f.service && <Badge variant="outline" className="text-[10px] shrink-0">{f.service}</Badge>}
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <Badge className={`text-[10px] ${f.confidenceTier === 'high-confidence' ? 'bg-emerald-500/20 text-emerald-400' : f.confidenceTier === 'corroborated' ? 'bg-amber-500/20 text-amber-400' : 'bg-zinc-500/20 text-zinc-400'}`}>
                          {f.sourceCount} sources
                        </Badge>
                        <span className="text-muted-foreground">{f.corroborationScore.toFixed(2)}x</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeSection === 'temporal' && temporalScores.data && (
        <Card className="border-amber-500/30 animate-in fade-in slide-in-from-top-2 duration-200">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Activity className="h-4 w-4 text-amber-400" />
              Temporal Decay Scoring
            </CardTitle>
            <CardDescription className="text-xs">
              Scores are adjusted based on exploit maturity, patch availability, KEV listing, and data freshness. A multiplier above 1.0 indicates elevated urgency.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Urgency Distribution */}
            <div className="grid grid-cols-5 gap-2">
              {['immediate', 'urgent', 'elevated', 'standard', 'deferred'].map(level => {
                const count = temporalScores.data?.urgencyDistribution?.[level] ?? 0;
                const colors: Record<string, string> = {
                  immediate: 'bg-red-500/10 border-red-500/20 text-red-400',
                  urgent: 'bg-orange-500/10 border-orange-500/20 text-orange-400',
                  elevated: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
                  standard: 'bg-blue-500/10 border-blue-500/20 text-blue-400',
                  deferred: 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400',
                };
                return (
                  <div key={level} className={`p-2 rounded-lg border text-center ${colors[level]}`}>
                    <p className="text-lg font-bold">{count}</p>
                    <p className="text-[10px] capitalize">{level}</p>
                  </div>
                );
              })}
            </div>

            {/* Score Details */}
            {temporalScores.data.scores.length > 0 && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-2">Score Breakdown (Top 20)</p>
                <div className="space-y-1.5 max-h-60 overflow-y-auto">
                  {temporalScores.data.scores.slice(0, 20).map((s: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-2 rounded bg-muted/30 text-xs">
                      <div className="flex items-center gap-2">
                        <Badge className={`text-[10px] ${RISK_COLORS[s.adjustedSeverity] || RISK_COLORS.medium}`}>
                          {s.adjustedSeverity}
                        </Badge>
                        <span className="font-mono">{s.adjustedScore.toFixed(1)}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`font-semibold ${s.temporalMultiplier > 1.2 ? 'text-red-400' : s.temporalMultiplier > 1.0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                          {s.temporalMultiplier.toFixed(2)}x
                        </span>
                        <Badge variant="outline" className={`text-[10px] capitalize ${s.urgencyLevel === 'immediate' ? 'border-red-500/40 text-red-400' : s.urgencyLevel === 'urgent' ? 'border-orange-500/40 text-orange-400' : ''}`}>
                          {s.urgencyLevel}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeSection === 'chains' && attackChains.data && (
        <Card className="border-red-500/30 animate-in fade-in slide-in-from-top-2 duration-200">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Network className="h-4 w-4 text-red-400" />
              Attack Chain Analysis
            </CardTitle>
            <CardDescription className="text-xs">
              Multi-step exploit chains where individually low-severity findings combine to create critical impact. Chains are matched against known attack patterns.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {attackChains.data.totalChains === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Network className="h-8 w-8 mx-auto mb-2 opacity-40" />
                <p className="text-sm">No attack chains detected in this scan.</p>
                <p className="text-xs mt-1">Chains are identified when multiple findings can be linked into a multi-step exploit path.</p>
              </div>
            ) : (
              <>
                <p className="text-xs text-muted-foreground">{attackChains.data.summary}</p>
                <div className="space-y-3">
                  {attackChains.data.chains.map((chain: any) => (
                    <div key={chain.id} className="p-3 rounded-lg border border-border bg-muted/30">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Badge className={`text-[10px] ${RISK_COLORS[chain.chainSeverity] || RISK_COLORS.medium}`}>
                            {chain.chainSeverity}
                          </Badge>
                          <span className="font-semibold text-sm">{chain.name}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground">{chain.linkCount} steps</span>
                          <Badge variant="outline" className="text-[10px] capitalize">{chain.feasibility}</Badge>
                          <span className="text-xs font-mono font-bold">{chain.chainScore.toFixed(1)}</span>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground">{chain.description}</p>
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {chain.killChainCoverage.map((phase: string) => (
                          <Badge key={phase} variant="secondary" className="text-[10px] capitalize">{phase.replace('_', ' ')}</Badge>
                        ))}
                      </div>
                      <p className="text-[10px] text-red-400/80 mt-1.5">{chain.businessImpact}</p>
                    </div>
                  ))}
                </div>
              </>
            )}

            {/* Available Patterns */}
            {attackChains.data.availablePatterns && (
              <Collapsible>
                <CollapsibleTrigger className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors">
                  <ChevronDown className="h-3 w-3" />
                  {attackChains.data.availablePatterns.length} chain patterns in library
                </CollapsibleTrigger>
                <CollapsibleContent className="mt-2 space-y-1">
                  {attackChains.data.availablePatterns.map((p: any) => (
                    <div key={p.id} className="flex items-center gap-2 text-xs p-1.5 rounded bg-muted/20">
                      <span className="font-mono text-muted-foreground">{p.id}</span>
                      <span>{p.name}</span>
                    </div>
                  ))}
                </CollapsibleContent>
              </Collapsible>
            )}
          </CardContent>
        </Card>
      )}

      {activeSection === 'feedback' && feedbackSummary.data && (
        <Card className="border-purple-500/30 animate-in fade-in slide-in-from-top-2 duration-200">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-purple-400" />
              Exploit Module Feedback Loop
            </CardTitle>
            <CardDescription className="text-xs">
              Tracks exploit module performance over time. Modules with declining success rates are flagged for review or auto-retired.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-4 gap-3">
              <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-center">
                <p className="text-lg font-bold text-emerald-400">{feedbackSummary.data.activeModules}</p>
                <p className="text-[10px] text-muted-foreground">Active</p>
              </div>
              <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-center">
                <p className="text-lg font-bold text-amber-400">{feedbackSummary.data.degradedModules}</p>
                <p className="text-[10px] text-muted-foreground">Degraded</p>
              </div>
              <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-center">
                <p className="text-lg font-bold text-red-400">{feedbackSummary.data.retiredModules}</p>
                <p className="text-[10px] text-muted-foreground">Retired</p>
              </div>
              <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-center">
                <p className="text-lg font-bold text-blue-400">{feedbackSummary.data.needsUpdateModules}</p>
                <p className="text-[10px] text-muted-foreground">Needs Update</p>
              </div>
            </div>

            {/* Trends */}
            {feedbackSummary.data.recentTrends && (
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-emerald-500" />
                  {feedbackSummary.data.recentTrends.improving} improving
                </span>
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-blue-500" />
                  {feedbackSummary.data.recentTrends.stable} stable
                </span>
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-red-500" />
                  {feedbackSummary.data.recentTrends.degrading} degrading
                </span>
              </div>
            )}

            {/* Top Performers */}
            {feedbackSummary.data.topPerformers?.length > 0 && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-2">Top Performing Modules</p>
                <div className="space-y-1.5">
                  {feedbackSummary.data.topPerformers.slice(0, 5).map((m: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-2 rounded bg-muted/30 text-xs">
                      <span className="font-mono truncate">{m.moduleName}</span>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-emerald-400 font-semibold">{m.successRate.toFixed(0)}%</span>
                        <Badge variant="outline" className="text-[10px] capitalize">{m.status}</Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Worst Performers */}
            {feedbackSummary.data.worstPerformers?.length > 0 && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-2">Modules Needing Attention</p>
                <div className="space-y-1.5">
                  {feedbackSummary.data.worstPerformers.slice(0, 5).map((m: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-2 rounded bg-muted/30 text-xs">
                      <span className="font-mono truncate">{m.moduleName}</span>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-red-400 font-semibold">{m.successRate.toFixed(0)}%</span>
                        <Badge variant="outline" className="text-[10px] capitalize">{m.status}</Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Remediation Summary (always visible if data exists) */}
      {remediationSummary.data && remediationSummary.data.totalFindings > 0 && (
        <Card className="border-cyan-500/20">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyan-400" />
              Remediation Verification Status
            </CardTitle>
            <CardDescription className="text-xs">
              Closed-loop verification tracks whether remediated findings are truly fixed by re-running the original exploit.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
              {[
                { label: 'Exploitable', value: remediationSummary.data.exploitable ?? 0, color: 'text-red-400' },
                { label: 'Pending', value: remediationSummary.data.remediationPending ?? 0, color: 'text-amber-400' },
                { label: 'Queued', value: remediationSummary.data.verificationQueued ?? 0, color: 'text-blue-400' },
                { label: 'Verified Fixed', value: remediationSummary.data.verifiedFixed ?? 0, color: 'text-emerald-400' },
                { label: 'Still Vulnerable', value: remediationSummary.data.stillVulnerable ?? 0, color: 'text-red-400' },
                { label: 'Regression', value: remediationSummary.data.regression ?? 0, color: 'text-purple-400' },
              ].map(item => (
                <div key={item.label} className="text-center p-2 rounded bg-muted/30">
                  <p className={`text-lg font-bold ${item.color}`}>{item.value}</p>
                  <p className="text-[10px] text-muted-foreground">{item.label}</p>
                </div>
              ))}
            </div>
            {remediationSummary.data.slaCompliance !== undefined && (
              <div className="mt-3 flex items-center gap-3">
                <span className="text-xs text-muted-foreground">SLA Compliance:</span>
                <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${remediationSummary.data.slaCompliance >= 80 ? 'bg-emerald-500' : remediationSummary.data.slaCompliance >= 50 ? 'bg-amber-500' : 'bg-red-500'}`}
                    style={{ width: `${Math.max(2, remediationSummary.data.slaCompliance)}%` }}
                  />
                </div>
                <span className="text-xs font-bold tabular-nums">{Math.round(remediationSummary.data.slaCompliance)}%</span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Loading State */}
      {isLoading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground mr-2" />
          <span className="text-sm text-muted-foreground">Loading accuracy insights...</span>
        </div>
      )}
    </div>
  );
}


// ─── Discovery Coverage Tab ─────────────────────────────────────────────────
// Shows alignment with red team top-10 discovery methodology priorities

