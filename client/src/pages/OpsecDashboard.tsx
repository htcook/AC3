import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  ShieldAlert, Activity, AlertTriangle, Eye, Gauge, Flame,
  Shield, Radio, Wifi, Cpu, ChevronRight, Zap, Brain
} from "lucide-react";

/** OPSEC Dashboard — Real-time detection risk scoring, burn detection, and operator guidance.
 *  This page helps red team operators understand the detection risk of every action they take,
 *  track cumulative exposure across the engagement, and receive safer alternatives when risk is high. */

const RISK_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-green-500",
  minimal: "bg-emerald-500",
};

const RISK_TEXT: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
  minimal: "text-emerald-400",
};

const STATUS_COLORS: Record<string, string> = {
  green: "from-emerald-500 to-green-600",
  yellow: "from-yellow-500 to-amber-600",
  red: "from-red-500 to-rose-600",
};

function RiskGauge({ score, level }: { score: number; level: string }) {
  const rotation = (score / 100) * 180 - 90;
  return (
    <div className="relative w-48 h-28 mx-auto">
      <svg viewBox="0 0 200 110" className="w-full h-full">
        <defs>
          <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#10b981" />
            <stop offset="25%" stopColor="#84cc16" />
            <stop offset="50%" stopColor="#eab308" />
            <stop offset="75%" stopColor="#f97316" />
            <stop offset="100%" stopColor="#ef4444" />
          </linearGradient>
        </defs>
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="12" strokeLinecap="round" />
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="url(#gaugeGrad)" strokeWidth="12" strokeLinecap="round"
          strokeDasharray={`${(score / 100) * 251.2} 251.2`} />
        <line x1="100" y1="100" x2="100" y2="30"
          stroke="white" strokeWidth="2" strokeLinecap="round"
          transform={`rotate(${rotation} 100 100)`}
          className="drop-shadow-lg" />
        <circle cx="100" cy="100" r="4" fill="white" />
      </svg>
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 text-center">
        <span className={`text-3xl font-bold ${RISK_TEXT[level] || "text-white"}`}>{score}</span>
        <span className="text-xs text-muted-foreground block uppercase tracking-wider">{level}</span>
      </div>
    </div>
  );
}

function BurnIndicatorCard({ indicator }: { indicator: { id: string; name: string; severity: string; description: string; recommendation: string } }) {
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-red-500/10 border border-red-500/30">
      <Flame className="w-5 h-5 text-red-400 mt-0.5 shrink-0" />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium text-red-300">{indicator.name}</span>
          <Badge variant="destructive" className="text-xs">{indicator.severity}</Badge>
        </div>
        <p className="text-xs text-muted-foreground mt-1">{indicator.description}</p>
        <p className="text-xs text-yellow-400 mt-1">→ {indicator.recommendation}</p>
      </div>
    </div>
  );
}

export default function OpsecDashboard() {
  // Using sonner toast
  const [actionType, setActionType] = useState("port_scan");
  const [actionDetails, setActionDetails] = useState("");
  const [cumulativeExposure, setCumulativeExposure] = useState(0);
  const [scoredActions, setScoredActions] = useState<any[]>([]);

  // Queries
  const { data: riskProfiles } = trpc.opsecRisk.riskProfiles.useQuery();
  const { data: detectionTechs } = trpc.opsecRisk.detectionTechnologies.useQuery();
  const { data: burnIndicatorDefs } = trpc.opsecRisk.burnIndicators.useQuery();

  // Quick score mutation
  const quickScore = trpc.opsecRisk.quickScore.useQuery(
    { actionType, actionDetails: actionDetails || actionType, cumulativeExposure },
    { enabled: false }
  );

  // LLM score mutation
  const llmScore = trpc.opsecRisk.scoreAction.useMutation({
    onSuccess: (data) => {
      setScoredActions(prev => [{ ...data, timestamp: Date.now(), actionType, actionDetails }, ...prev].slice(0, 50));
      setCumulativeExposure(data.cumulativeExposure || cumulativeExposure + data.riskScore * 0.3);
      toast.success(`OPSEC Score — Risk: ${data.riskLevel} (${data.riskScore}/100)`);
    },
  });

  // Engagement status
  const engagementStatus = useMemo(() => {
    if (scoredActions.length === 0) return "green";
    const detected = scoredActions.filter(a => a.burnRisk).length;
    const avgRisk = scoredActions.reduce((s, a) => s + a.riskScore, 0) / scoredActions.length;
    if (detected > 2 || avgRisk > 70) return "red";
    if (detected > 0 || avgRisk > 40) return "yellow";
    return "green";
  }, [scoredActions]);

  const latestScore = scoredActions[0];
  const actionTypeOptions = riskProfiles ? Object.keys(riskProfiles) : [
    "port_scan", "credential_dump", "exploit_attempt", "lateral_movement",
    "c2_callback", "file_exfiltration", "privesc_attempt", "phishing_email",
    "dns_enumeration", "web_scan",
  ];

  const handleQuickScore = () => {
    const details = actionDetails || actionType;
    // Use the deterministic scorer directly
    const result = {
      riskScore: Math.min(100, Math.max(0, (riskProfiles?.[actionType]?.baseScore || 50) + (details.toLowerCase().includes("mimikatz") ? 20 : 0))),
      riskLevel: "medium",
      burnRisk: cumulativeExposure > 70,
      cumulativeExposure: cumulativeExposure + 15,
      mitigations: ["Use living-off-the-land techniques", "Add jitter to timing"],
      detectionSignatures: ["Generic activity signature"],
    };
    if (result.riskScore >= 80) result.riskLevel = "critical";
    else if (result.riskScore >= 60) result.riskLevel = "high";
    else if (result.riskScore >= 40) result.riskLevel = "medium";
    else if (result.riskScore >= 20) result.riskLevel = "low";
    else result.riskLevel = "minimal";
    setScoredActions(prev => [{ ...result, timestamp: Date.now(), actionType, actionDetails }, ...prev].slice(0, 50));
    setCumulativeExposure(result.cumulativeExposure);
  };

  const handleLlmScore = () => {
    llmScore.mutate({ actionType, actionDetails: actionDetails || actionType, cumulativeExposure });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <ShieldAlert className="w-7 h-7 text-orange-400" />
          OPSEC Dashboard
        </h1>
        <p className="text-muted-foreground mt-1">
          Real-time detection risk scoring and operator guidance. Score every action before execution to minimize detection probability and track cumulative exposure across the engagement.
        </p>
      </div>

      {/* Status Bar */}
      <div className={`rounded-xl p-4 bg-gradient-to-r ${STATUS_COLORS[engagementStatus]} text-white flex items-center justify-between`}>
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6" />
          <div>
            <div className="font-bold text-lg">
              Engagement OPSEC: {engagementStatus.toUpperCase()}
            </div>
            <div className="text-sm opacity-90">
              {engagementStatus === "green" && "Low detection risk — continue operations"}
              {engagementStatus === "yellow" && "Moderate exposure — consider operational pause"}
              {engagementStatus === "red" && "High burn risk — recommend infrastructure rotation"}
            </div>
          </div>
        </div>
        <div className="text-right">
          <div className="text-2xl font-bold">{Math.round(cumulativeExposure)}</div>
          <div className="text-xs opacity-80">Cumulative Exposure</div>
        </div>
      </div>

      <Tabs defaultValue="scorer" className="space-y-4">
        <TabsList className="bg-background/50 border">
          <TabsTrigger value="scorer"><Gauge className="w-4 h-4 mr-1" />ACTION SCORER</TabsTrigger>
          <TabsTrigger value="history"><Activity className="w-4 h-4 mr-1" />ACTION LOG</TabsTrigger>
          <TabsTrigger value="detection"><Eye className="w-4 h-4 mr-1" />DETECTION MATRIX</TabsTrigger>
          <TabsTrigger value="burns"><Flame className="w-4 h-4 mr-1" />BURN INDICATORS</TabsTrigger>
        </TabsList>

        {/* Action Scorer Tab */}
        <TabsContent value="scorer" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Score Input */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Zap className="w-4 h-4 text-yellow-400" />
                  Score an Action
                </CardTitle>
                <CardDescription>Select an action type and describe what you plan to do. The engine will calculate detection risk.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Action Type</label>
                    <Select value={actionType} onValueChange={setActionType}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {actionTypeOptions.map(t => (
                          <SelectItem key={t} value={t}>{t.replace(/_/g, " ").toUpperCase()}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Cumulative Exposure</label>
                    <Input type="number" value={cumulativeExposure} onChange={e => setCumulativeExposure(Number(e.target.value))} />
                  </div>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Action Details (optional)</label>
                  <Textarea
                    value={actionDetails}
                    onChange={e => setActionDetails(e.target.value)}
                    placeholder="e.g., Running mimikatz sekurlsa::logonpasswords on DC01..."
                    rows={3}
                  />
                </div>
                <div className="flex gap-2">
                  <Button onClick={handleQuickScore} variant="outline" className="flex-1">
                    <Gauge className="w-4 h-4 mr-1" />Quick Score
                  </Button>
                  <Button onClick={handleLlmScore} className="flex-1 bg-purple-600 hover:bg-purple-700" disabled={llmScore.isPending}>
                    <Brain className="w-4 h-4 mr-1" />
                    {llmScore.isPending ? "Analyzing..." : "LLM Deep Analysis"}
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Risk Gauge */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Current Risk</CardTitle>
              </CardHeader>
              <CardContent>
                {latestScore ? (
                  <div className="space-y-4">
                    <RiskGauge score={latestScore.riskScore} level={latestScore.riskLevel} />
                    {latestScore.burnRisk && (
                      <div className="p-2 rounded bg-red-500/20 border border-red-500/40 text-center">
                        <AlertTriangle className="w-4 h-4 text-red-400 inline mr-1" />
                        <span className="text-red-300 text-sm font-medium">BURN RISK DETECTED</span>
                      </div>
                    )}
                    {latestScore.mitigations?.length > 0 && (
                      <div className="space-y-1">
                        <span className="text-xs text-muted-foreground">Safer Alternatives:</span>
                        {latestScore.mitigations.slice(0, 3).map((m: string, i: number) => (
                          <div key={i} className="text-xs flex items-start gap-1">
                            <ChevronRight className="w-3 h-3 text-green-400 mt-0.5 shrink-0" />
                            <span>{m}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center text-muted-foreground py-8">
                    <Gauge className="w-10 h-10 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">Score an action to see risk</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Risk Profiles Reference */}
          {riskProfiles && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Action Risk Profiles</CardTitle>
                <CardDescription>Base detection risk for common operator actions</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2">
                  {Object.entries(riskProfiles).map(([key, profile]: [string, any]) => (
                    <button
                      key={key}
                      onClick={() => setActionType(key)}
                      className={`p-2 rounded-lg border text-left transition-colors hover:bg-accent/50 ${actionType === key ? "border-primary bg-accent/30" : "border-border/50"}`}
                    >
                      <div className="text-xs font-medium truncate">{key.replace(/_/g, " ")}</div>
                      <div className="flex items-center gap-1 mt-1">
                        <div className={`w-2 h-2 rounded-full ${profile.baseScore >= 80 ? "bg-red-500" : profile.baseScore >= 60 ? "bg-orange-500" : profile.baseScore >= 40 ? "bg-yellow-500" : "bg-green-500"}`} />
                        <span className="text-xs text-muted-foreground">{profile.baseScore}/100</span>
                      </div>
                    </button>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Action Log Tab */}
        <TabsContent value="history" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Activity className="w-4 h-4" />
                Scored Actions ({scoredActions.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {scoredActions.length === 0 ? (
                <div className="text-center text-muted-foreground py-12">
                  <Activity className="w-10 h-10 mx-auto mb-2 opacity-30" />
                  <p>No actions scored yet. Use the Action Scorer to evaluate detection risk.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {scoredActions.map((action, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-card/50 border border-border/50">
                      <div className={`w-3 h-3 rounded-full shrink-0 ${RISK_COLORS[action.riskLevel] || "bg-gray-500"}`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-sm">{action.actionType.replace(/_/g, " ")}</span>
                          <Badge variant="outline" className={`text-xs ${RISK_TEXT[action.riskLevel]}`}>
                            {action.riskScore}/100
                          </Badge>
                          {action.burnRisk && <Badge variant="destructive" className="text-xs">BURN</Badge>}
                        </div>
                        {action.actionDetails && (
                          <p className="text-xs text-muted-foreground truncate mt-0.5">{action.actionDetails}</p>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground shrink-0">
                        {new Date(action.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Detection Matrix Tab */}
        <TabsContent value="detection" className="space-y-4">
          {detectionTechs && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {detectionTechs.map((tech: any) => (
                <Card key={tech.id || tech.name}>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      {tech.category === "edr" && <Cpu className="w-4 h-4 text-blue-400" />}
                      {tech.category === "siem" && <Radio className="w-4 h-4 text-purple-400" />}
                      {tech.category === "ndr" && <Wifi className="w-4 h-4 text-cyan-400" />}
                      {tech.category === "av" && <Shield className="w-4 h-4 text-green-400" />}
                      {tech.category === "ueba" && <Eye className="w-4 h-4 text-yellow-400" />}
                      {tech.name}
                    </CardTitle>
                    <Badge variant="outline" className="text-xs w-fit">{tech.category?.toUpperCase()}</Badge>
                  </CardHeader>
                  <CardContent>
                    <p className="text-xs text-muted-foreground mb-2">{tech.description}</p>
                    {tech.detects && (
                      <div className="space-y-1">
                        <span className="text-xs font-medium">Detects:</span>
                        <div className="flex flex-wrap gap-1">
                          {tech.detects.slice(0, 6).map((d: string, i: number) => (
                            <Badge key={i} variant="secondary" className="text-xs">{d}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {tech.evasionTips && (
                      <div className="mt-2 space-y-1">
                        <span className="text-xs font-medium text-yellow-400">Evasion Tips:</span>
                        {tech.evasionTips.slice(0, 2).map((tip: string, i: number) => (
                          <p key={i} className="text-xs text-muted-foreground">• {tip}</p>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Burn Indicators Tab */}
        <TabsContent value="burns" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Flame className="w-4 h-4 text-red-400" />
                Burn Indicator Reference
              </CardTitle>
              <CardDescription>Signs that your operation may have been detected or compromised</CardDescription>
            </CardHeader>
            <CardContent>
              {burnIndicatorDefs ? (
                <div className="space-y-3">
                  {burnIndicatorDefs.map((indicator: any) => (
                    <BurnIndicatorCard key={indicator.id} indicator={indicator} />
                  ))}
                </div>
              ) : (
                <div className="text-center text-muted-foreground py-8">Loading burn indicators...</div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
