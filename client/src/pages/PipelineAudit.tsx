import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  ClipboardCheck, Play, Shield, AlertTriangle, CheckCircle2, Clock,
  Layers, ChevronDown, ChevronRight, Target, Lock, Eye, Zap,
  ShieldCheck, Scale, FileText, ArrowUpRight, Loader2, Brain,
  Gavel, BookOpen, ShieldAlert, Fingerprint,
} from "lucide-react";
import { Streamdown } from "streamdown";

// ─── Category metadata ──────────────────────────────────────────────────────
const CATEGORY_META: Record<string, { label: string; icon: any; color: string }> = {
  exploit_chaining: { label: "Exploit Chaining", icon: Zap, color: "text-orange-400" },
  c2_handoff: { label: "C2 Handoff", icon: Target, color: "text-red-400" },
  post_exploitation: { label: "Post-Exploitation", icon: Layers, color: "text-purple-400" },
  opsec: { label: "OPSEC", icon: Eye, color: "text-cyan-400" },
  payload_delivery: { label: "Payload Delivery", icon: Fingerprint, color: "text-amber-400" },
  credential_reuse: { label: "Credential Reuse", icon: Lock, color: "text-blue-400" },
  privilege_escalation: { label: "Privilege Escalation", icon: ArrowUpRight, color: "text-emerald-400" },
  resilience: { label: "Resilience", icon: Shield, color: "text-indigo-400" },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

const EFFORT_COLORS: Record<string, string> = {
  small: "bg-emerald-500/20 text-emerald-400",
  medium: "bg-amber-500/20 text-amber-400",
  large: "bg-red-500/20 text-red-400",
};

export default function PipelineAudit() {
  const [expandedRecs, setExpandedRecs] = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab] = useState("overview");

  const cachedReport = trpc.pipelineAudit.getCachedReport.useQuery();
  const moduleInventory = trpc.pipelineAudit.getModuleInventory.useQuery();
  const generateReport = trpc.pipelineAudit.generateReport.useMutation({
    onSuccess: () => {
      cachedReport.refetch();
    },
  });

  const report = cachedReport.data;

  const toggleRec = (id: string) => {
    setExpandedRecs(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ClipboardCheck className="h-6 w-6 text-orange-400" />
            Exploit Pipeline Audit
          </h1>
          <p className="text-muted-foreground mt-1">
            AI-powered analysis of the exploit pipeline with actionable recommendations for improving engagement success rates
          </p>
        </div>
        <Button
          onClick={() => generateReport.mutate({})}
          disabled={generateReport.isPending}
          className="gap-2"
        >
          {generateReport.isPending ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Analyzing Pipeline...
            </>
          ) : (
            <>
              <Brain className="h-4 w-4" />
              Generate Audit Report
            </>
          )}
        </Button>
      </div>

      {/* Safety & Legal Framework Banner */}
      <Card className="border-emerald-500/30 bg-emerald-500/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-lg flex items-center gap-2">
            <Gavel className="h-5 w-5 text-emerald-400" />
            Safety Guardrails &amp; Legal Compliance Framework
          </CardTitle>
          <CardDescription>
            All exploit pipeline operations are governed by multi-layered safety controls and legal compliance mechanisms
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* ROE Guard */}
            <div className="rounded-lg border border-border/50 bg-card/50 p-4 space-y-2">
              <div className="flex items-center gap-2">
                <Scale className="h-4 w-4 text-amber-400" />
                <span className="font-semibold text-sm">ROE Guard</span>
              </div>
              <p className="text-xs text-muted-foreground">
                All Orange/Red tier operations require a signed, non-expired Rules of Engagement document. Operations are blocked without valid ROE. Scope validation ensures targets are within authorized boundaries.
              </p>
              <div className="flex flex-wrap gap-1 mt-1">
                <Badge variant="outline" className="text-[10px] border-amber-500/30 text-amber-400">Signed ROE Required</Badge>
                <Badge variant="outline" className="text-[10px] border-amber-500/30 text-amber-400">Expiry Enforced</Badge>
                <Badge variant="outline" className="text-[10px] border-amber-500/30 text-amber-400">Scope Locked</Badge>
              </div>
            </div>

            {/* Safety Engine */}
            <div className="rounded-lg border border-border/50 bg-card/50 p-4 space-y-2">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                <span className="font-semibold text-sm">Safety Engine</span>
              </div>
              <p className="text-xs text-muted-foreground">
                Four-tier safety levels (Passive Only, Low Impact, Standard, Full Exploitation) with phase gating, blast radius estimation, and dual-approval requirements for high-impact operations.
              </p>
              <div className="flex flex-wrap gap-1 mt-1">
                <Badge variant="outline" className="text-[10px] border-emerald-500/30 text-emerald-400">Phase Gating</Badge>
                <Badge variant="outline" className="text-[10px] border-emerald-500/30 text-emerald-400">Blast Radius</Badge>
                <Badge variant="outline" className="text-[10px] border-emerald-500/30 text-emerald-400">Dual Approval</Badge>
              </div>
            </div>

            {/* Audit Trail */}
            <div className="rounded-lg border border-border/50 bg-card/50 p-4 space-y-2">
              <div className="flex items-center gap-2">
                <FileText className="h-4 w-4 text-blue-400" />
                <span className="font-semibold text-sm">Offensive Audit Trail</span>
              </div>
              <p className="text-xs text-muted-foreground">
                Every offensive action is logged with operator identity, risk tier, target, tool/module, ROE status, and result. Full provenance chain for forensic review and compliance reporting.
              </p>
              <div className="flex flex-wrap gap-1 mt-1">
                <Badge variant="outline" className="text-[10px] border-blue-500/30 text-blue-400">Operator ID</Badge>
                <Badge variant="outline" className="text-[10px] border-blue-500/30 text-blue-400">Risk Tier</Badge>
                <Badge variant="outline" className="text-[10px] border-blue-500/30 text-blue-400">Full Provenance</Badge>
              </div>
            </div>

            {/* Risk Tier Classification */}
            <div className="rounded-lg border border-border/50 bg-card/50 p-4 space-y-2">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-400" />
                <span className="font-semibold text-sm">Risk Tier Classification</span>
              </div>
              <p className="text-xs text-muted-foreground">
                Operations classified into Yellow (passive), Orange (active probe), and Red (exploitation) tiers. 60+ tools mapped to 4 scan policy tiers with ROE requirements and detection risk ratings.
              </p>
              <div className="flex flex-wrap gap-1 mt-1">
                <Badge variant="outline" className="text-[10px] border-yellow-500/30 text-yellow-400">Yellow: Passive</Badge>
                <Badge variant="outline" className="text-[10px] border-orange-500/30 text-orange-400">Orange: Active</Badge>
                <Badge variant="outline" className="text-[10px] border-red-500/30 text-red-400">Red: Exploit</Badge>
              </div>
            </div>
          </div>

          {/* Legal Compliance Summary */}
          <div className="mt-4 rounded-lg border border-border/50 bg-card/50 p-4">
            <div className="flex items-center gap-2 mb-2">
              <BookOpen className="h-4 w-4 text-violet-400" />
              <span className="font-semibold text-sm">Legal &amp; Compliance Approach</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-muted-foreground">
              <div>
                <p className="font-medium text-foreground mb-1">Pre-Engagement</p>
                <ul className="space-y-1 list-disc list-inside">
                  <li>Signed ROE document required before any active testing</li>
                  <li>Scope boundaries defined and enforced at the platform level</li>
                  <li>Safety level selected per engagement (passive → full exploitation)</li>
                  <li>Caldera preflight validation before C2 operations</li>
                </ul>
              </div>
              <div>
                <p className="font-medium text-foreground mb-1">During Engagement</p>
                <ul className="space-y-1 list-disc list-inside">
                  <li>Every command assessed against safety profile before execution</li>
                  <li>Blast radius estimated for all offensive actions</li>
                  <li>Phase transitions gated by minimum safety level</li>
                  <li>OPSEC risk scoring on every operator action</li>
                </ul>
              </div>
              <div>
                <p className="font-medium text-foreground mb-1">Post-Engagement</p>
                <ul className="space-y-1 list-disc list-inside">
                  <li>Complete audit trail with operator attribution</li>
                  <li>Evidence integrity verification (KSI blockchain)</li>
                  <li>NIST 800-53 control mapping for all findings</li>
                  <li>OSCAL/STIX export for compliance reporting</li>
                </ul>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="recommendations" disabled={!report}>
            Recommendations {report && `(${report.recommendations.length})`}
          </TabsTrigger>
          <TabsTrigger value="priority" disabled={!report}>Priority Matrix</TabsTrigger>
          <TabsTrigger value="architecture">Module Inventory</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          {!report && !generateReport.isPending && (
            <Card>
              <CardContent className="py-12 text-center space-y-4">
                <Brain className="h-12 w-12 mx-auto text-muted-foreground/50" />
                <div>
                  <h3 className="text-lg font-semibold">No Audit Report Generated</h3>
                  <p className="text-muted-foreground text-sm mt-1">
                    Click "Generate Audit Report" to run an AI-powered analysis of your exploit pipeline architecture.
                    The analysis covers exploit chaining, C2 handoff, post-exploitation, OPSEC, payload delivery, and more.
                  </p>
                </div>
              </CardContent>
            </Card>
          )}

          {generateReport.isPending && (
            <Card>
              <CardContent className="py-12 text-center space-y-4">
                <Loader2 className="h-12 w-12 mx-auto text-orange-400 animate-spin" />
                <div>
                  <h3 className="text-lg font-semibold">Analyzing Exploit Pipeline...</h3>
                  <p className="text-muted-foreground text-sm mt-1">
                    The AI is reviewing 24 modules (~15,000 LOC) across 9 architectural layers.
                    This typically takes 30-60 seconds.
                  </p>
                </div>
              </CardContent>
            </Card>
          )}

          {report && (
            <>
              {/* Maturity Score */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card>
                  <CardContent className="pt-6 text-center">
                    <div className="text-4xl font-bold text-orange-400">{report.overallMaturityScore}/10</div>
                    <p className="text-sm text-muted-foreground mt-1">Pipeline Maturity</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-6 text-center">
                    <div className="text-4xl font-bold text-red-400">
                      {report.recommendations.filter(r => r.severity === "critical").length}
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">Critical Findings</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-6 text-center">
                    <div className="text-4xl font-bold text-orange-400">
                      {report.recommendations.filter(r => r.severity === "high").length}
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">High Findings</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-6 text-center">
                    <div className="text-4xl font-bold text-foreground">
                      {report.recommendations.length}
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">Total Recommendations</p>
                  </CardContent>
                </Card>
              </div>

              {/* Executive Summary */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Executive Summary</CardTitle>
                  <CardDescription>
                    Generated {new Date(report.generatedAt).toLocaleString()}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="prose prose-invert max-w-none text-sm">
                    <Streamdown>{report.executiveSummary}</Streamdown>
                  </div>
                </CardContent>
              </Card>

              {/* Category Breakdown */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Findings by Category</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {Object.entries(CATEGORY_META).map(([key, meta]) => {
                      const count = report.recommendations.filter(r => r.category === key).length;
                      const Icon = meta.icon;
                      return (
                        <div key={key} className="rounded-lg border border-border/50 bg-card/50 p-3 flex items-center gap-3">
                          <Icon className={`h-5 w-5 ${meta.color}`} />
                          <div>
                            <div className="text-lg font-bold">{count}</div>
                            <div className="text-xs text-muted-foreground">{meta.label}</div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>

        {/* Recommendations Tab */}
        <TabsContent value="recommendations" className="space-y-3">
          {report?.recommendations.map((rec) => {
            const expanded = expandedRecs.has(rec.id);
            const catMeta = CATEGORY_META[rec.category] || { label: rec.category, icon: AlertTriangle, color: "text-muted-foreground" };
            const CatIcon = catMeta.icon;
            return (
              <Card key={rec.id} className="overflow-hidden">
                <div
                  className="flex items-center gap-3 p-4 cursor-pointer hover:bg-muted/30 transition-colors"
                  onClick={() => toggleRec(rec.id)}
                >
                  {expanded ? <ChevronDown className="h-4 w-4 shrink-0" /> : <ChevronRight className="h-4 w-4 shrink-0" />}
                  <Badge variant="outline" className={`${SEVERITY_COLORS[rec.severity]} text-xs shrink-0`}>
                    {rec.severity.toUpperCase()}
                  </Badge>
                  <CatIcon className={`h-4 w-4 ${catMeta.color} shrink-0`} />
                  <span className="font-medium text-sm">{rec.id}: {rec.title}</span>
                  <div className="ml-auto flex items-center gap-2">
                    <Badge variant="outline" className={`${EFFORT_COLORS[rec.estimatedEffort]} text-[10px]`}>
                      {rec.estimatedEffort} effort
                    </Badge>
                    {rec.mitreTechniques.slice(0, 3).map(t => (
                      <Badge key={t} variant="outline" className="text-[10px] border-violet-500/30 text-violet-400">
                        {t}
                      </Badge>
                    ))}
                  </div>
                </div>

                {expanded && (
                  <div className="px-4 pb-4 space-y-4 border-t border-border/50">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Current State</h4>
                        <p className="text-sm">{rec.currentState}</p>
                      </div>
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Gap Identified</h4>
                        <p className="text-sm text-red-400/90">{rec.gap}</p>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Recommendation</h4>
                      <p className="text-sm">{rec.recommendation}</p>
                    </div>

                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Implementation Steps</h4>
                      <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
                        {rec.implementationSteps.map((step, i) => (
                          <li key={i}>{step}</li>
                        ))}
                      </ol>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Impact on Success Rate</h4>
                        <p className="text-sm text-emerald-400">{rec.impactOnSuccessRate}</p>
                      </div>
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Related Modules</h4>
                        <div className="flex flex-wrap gap-1">
                          {rec.relatedModules.map(m => (
                            <Badge key={m} variant="outline" className="text-[10px]">{m}</Badge>
                          ))}
                        </div>
                      </div>
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">MITRE ATT&amp;CK</h4>
                        <div className="flex flex-wrap gap-1">
                          {rec.mitreTechniques.map(t => (
                            <Badge key={t} variant="outline" className="text-[10px] border-violet-500/30 text-violet-400">{t}</Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </Card>
            );
          })}
        </TabsContent>

        {/* Priority Matrix Tab */}
        <TabsContent value="priority" className="space-y-4">
          {report && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Implementation Priority Matrix</CardTitle>
                <CardDescription>Recommendations ranked by effort-to-impact ratio</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border/50">
                        <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Priority</th>
                        <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Recommendation</th>
                        <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Effort</th>
                        <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Impact</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...report.priorityMatrix]
                        .sort((a, b) => a.priority - b.priority)
                        .map((item, i) => (
                          <tr key={i} className="border-b border-border/30 hover:bg-muted/20">
                            <td className="py-2 px-3">
                              <Badge variant="outline" className={i < 3 ? "bg-red-500/20 text-red-400 border-red-500/30" : ""}>
                                #{item.priority}
                              </Badge>
                            </td>
                            <td className="py-2 px-3 font-medium">{item.recommendation}</td>
                            <td className="py-2 px-3">
                              <Badge variant="outline" className={EFFORT_COLORS[item.effort] || ""}>
                                {item.effort}
                              </Badge>
                            </td>
                            <td className="py-2 px-3">
                              <Badge variant="outline" className={
                                item.impact === "high" ? "bg-emerald-500/20 text-emerald-400" :
                                item.impact === "medium" ? "bg-amber-500/20 text-amber-400" :
                                "bg-blue-500/20 text-blue-400"
                              }>
                                {item.impact}
                              </Badge>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Architecture Tab */}
        <TabsContent value="architecture" className="space-y-4">
          {moduleInventory.data && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card>
                  <CardContent className="pt-6 text-center">
                    <div className="text-3xl font-bold text-orange-400">{moduleInventory.data.totalModules}</div>
                    <p className="text-sm text-muted-foreground">Core Modules</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-6 text-center">
                    <div className="text-3xl font-bold text-foreground">{moduleInventory.data.totalLOC.toLocaleString()}</div>
                    <p className="text-sm text-muted-foreground">Lines of Code</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-6 text-center">
                    <div className="text-3xl font-bold text-cyan-400">{moduleInventory.data.layers.length}</div>
                    <p className="text-sm text-muted-foreground">Architectural Layers</p>
                  </CardContent>
                </Card>
              </div>

              {moduleInventory.data.layers.map((layer) => (
                <Card key={layer.name}>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Layers className="h-4 w-4 text-orange-400" />
                      {layer.name}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {layer.modules.map((mod) => (
                        <div key={mod.name} className="flex items-center justify-between rounded-lg border border-border/30 bg-card/50 px-3 py-2">
                          <div className="flex items-center gap-3">
                            <code className="text-xs font-mono text-orange-400">{mod.name}</code>
                            <span className="text-xs text-muted-foreground">{mod.description}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-[10px]">{mod.loc} LOC</Badge>
                            {"frameworks" in mod && (mod as any).frameworks?.map((fw: string) => (
                              <Badge key={fw} variant="outline" className="text-[10px] border-cyan-500/30 text-cyan-400">{fw}</Badge>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
