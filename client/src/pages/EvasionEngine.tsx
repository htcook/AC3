// @ts-nocheck
import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import {
  ShieldOff,
  Zap,
  FlaskConical,
  BarChart3,
  Play,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronRight,
  Shield,
  Loader2,
  Copy,
  Terminal,
  Layers,
  Target,
  TrendingUp,
  Info,
  BookOpen,
  Grid3x3,
  Download,
  FileText,
  FileJson,
  Filter,
  ArrowUpDown,
  Activity,
  Crosshair,
  RefreshCw,
  Globe,
  Lock,
  Unlock,
  Clock,
  Eye,
} from "lucide-react";

// ═══════════════════════════════════════════════════════════════════════════════
// TIER 1 — RULE MUTATION TESTING TAB
// ═══════════════════════════════════════════════════════════════════════════════

function MutationTestingTab() {
  const [command, setCommand] = useState("");
  const [detectionPattern, setDetectionPattern] = useState("");
  const [sigmaYaml, setSigmaYaml] = useState("");
  const [mode, setMode] = useState<"pattern" | "sigma">("pattern");
  const [expandedCategories, setExpandedCategories] = useState<Record<string, boolean>>({});

  const patternMutation = trpc.evasionEngine.testRawPattern.useMutation({
    onError: (err: any) => toast.error(`Mutation test failed: ${err.message}`),
  });

  const sigmaMutation = trpc.evasionEngine.testSigmaRule.useMutation({
    onError: (err: any) => toast.error(`Sigma test failed: ${err.message}`),
  });

  const result = mode === "pattern" ? patternMutation.data : sigmaMutation.data;
  const isLoading = patternMutation.isPending || sigmaMutation.isPending;

  const handleTest = () => {
    if (!command.trim()) {
      toast.error("Enter a command to test");
      return;
    }
    if (mode === "pattern") {
      if (!detectionPattern.trim()) {
        toast.error("Enter a detection pattern (regex or keyword)");
        return;
      }
      patternMutation.mutate({ command, pattern: detectionPattern });
    } else {
      if (!sigmaYaml.trim()) {
        toast.error("Enter Sigma rule YAML content");
        return;
      }
      sigmaMutation.mutate({ command, sigmaYaml });
    }
  };

  const variantsByCategory = useMemo(() => {
    if (!result?.variants) return {};
    const grouped: Record<string, any[]> = {};
    for (const v of result.variants) {
      const cat = v.category || "unknown";
      if (!grouped[cat]) grouped[cat] = [];
      grouped[cat].push(v);
    }
    return grouped;
  }, [result]);

  const toggleCategory = (cat: string) => {
    setExpandedCategories((prev) => ({ ...prev, [cat]: !prev[cat] }));
  };

  return (
    <div className="space-y-6">
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base font-display tracking-wider">
            <FlaskConical className="w-4 h-4 text-primary" />
            RULE MUTATION TESTING
          </CardTitle>
          <CardDescription>
            Enter a command and a detection rule/pattern. The engine generates 7+ evasive variants
            and tests whether each one still triggers the rule — exposing blind spots.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">
              COMMAND TO MUTATE
            </label>
            <Textarea
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              placeholder='e.g. powershell.exe -enc SQBFAFgA... or cmd.exe /c whoami'
              className="font-mono text-sm min-h-[80px]"
            />
          </div>

          <div className="flex gap-2">
            <Button
              variant={mode === "pattern" ? "default" : "outline"}
              size="sm"
              onClick={() => setMode("pattern")}
              className="font-display tracking-wider text-xs"
            >
              RAW PATTERN
            </Button>
            <Button
              variant={mode === "sigma" ? "default" : "outline"}
              size="sm"
              onClick={() => setMode("sigma")}
              className="font-display tracking-wider text-xs"
            >
              SIGMA RULE
            </Button>
          </div>

          {mode === "pattern" ? (
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">
                DETECTION PATTERN (regex or keyword)
              </label>
              <Input
                value={detectionPattern}
                onChange={(e) => setDetectionPattern(e.target.value)}
                placeholder="e.g. powershell.*-enc|whoami"
                className="font-mono text-sm"
              />
            </div>
          ) : (
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">
                SIGMA RULE (YAML)
              </label>
              <Textarea
                value={sigmaYaml}
                onChange={(e) => setSigmaYaml(e.target.value)}
                placeholder={`title: Suspicious PowerShell Encoded Command\ndetection:\n  selection:\n    CommandLine|contains:\n      - '-enc'\n      - '-encodedcommand'\n  condition: selection`}
                className="font-mono text-sm min-h-[160px]"
              />
            </div>
          )}

          <Button onClick={handleTest} disabled={isLoading} className="font-display tracking-wider">
            {isLoading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Play className="w-4 h-4 mr-2" />}
            {isLoading ? "TESTING MUTATIONS..." : "RUN MUTATION TEST"}
          </Button>
        </CardContent>
      </Card>

      {result && (
        <div className="space-y-4">
          <Card className="border-border/50">
            <CardContent className="pt-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold font-display">{result.robustnessScore}%</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">ROBUSTNESS</div>
                  <Progress value={result.robustnessScore} className="mt-2 h-1.5" />
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-display text-green-400">{result.detectedCount}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">DETECTED</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-display text-red-400">{result.evadedCount}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">EVADED</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-display">{result.variants?.length || 0}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">TOTAL VARIANTS</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {result.weakestCategories && result.weakestCategories.length > 0 && (
            <Card className="border-red-500/20 bg-red-500/5">
              <CardContent className="pt-6">
                <div className="flex items-center gap-2 mb-3">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  <span className="text-sm font-display tracking-wider text-red-400">WEAKEST CATEGORIES</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {result.weakestCategories.map((cat: string) => (
                    <Badge key={cat} variant="outline" className="border-red-500/30 text-red-400">{cat}</Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {result.hardeningTips && result.hardeningTips.length > 0 && (
            <Card className="border-blue-500/20 bg-blue-500/5">
              <CardContent className="pt-6">
                <div className="flex items-center gap-2 mb-3">
                  <Shield className="w-4 h-4 text-blue-400" />
                  <span className="text-sm font-display tracking-wider text-blue-400">HARDENING RECOMMENDATIONS</span>
                </div>
                <ul className="space-y-1.5">
                  {result.hardeningTips.map((tip: string, i: number) => (
                    <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                      <span className="text-blue-400 mt-0.5">•</span>{tip}
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}

          <Card className="border-border/50">
            <CardHeader>
              <CardTitle className="text-sm font-display tracking-wider">MUTATION VARIANTS BY CATEGORY</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {Object.entries(variantsByCategory).map(([category, variants]) => {
                const evaded = variants.filter((v: any) => !v.detected).length;
                const total = variants.length;
                const isExpanded = expandedCategories[category];
                return (
                  <div key={category} className="border border-border/50 rounded-lg overflow-hidden">
                    <button
                      onClick={() => toggleCategory(category)}
                      className="w-full flex items-center justify-between p-3 hover:bg-secondary/50 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        {isExpanded ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
                        <span className="font-display tracking-wider text-xs uppercase">{category}</span>
                        <Badge variant="outline" className="text-xs">{total} variants</Badge>
                      </div>
                      <div className="flex items-center gap-2">
                        {evaded > 0 && <Badge className="bg-red-500/20 text-red-400 border-red-500/30 text-xs">{evaded} evaded</Badge>}
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-xs">{total - evaded} detected</Badge>
                      </div>
                    </button>
                    {isExpanded && (
                      <div className="border-t border-border/50 divide-y divide-border/30">
                        {variants.map((v: any, i: number) => (
                          <div key={i} className="p-3 flex items-start gap-3">
                            {v.detected ? <CheckCircle2 className="w-4 h-4 text-green-400 mt-0.5 shrink-0" /> : <XCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />}
                            <div className="flex-1 min-w-0">
                              <code className="text-xs font-mono text-foreground/90 break-all block">{v.mutatedCommand}</code>
                              {v.technique && <span className="text-xs text-muted-foreground mt-1 block">Technique: {v.technique}</span>}
                            </div>
                            <Button variant="ghost" size="sm" className="shrink-0" onClick={() => { navigator.clipboard.writeText(v.mutatedCommand); toast.success("Copied"); }}>
                              <Copy className="w-3.5 h-3.5" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIER 2 — PAYLOAD TRANSFORMATION PIPELINE TAB
// ═══════════════════════════════════════════════════════════════════════════════

function PayloadPipelineTab() {
  const [profile, setProfile] = useState("medium");
  const [payloadType, setPayloadType] = useState("exe");
  const [targetOs, setTargetOs] = useState("windows");
  const [targetArch, setTargetArch] = useState("x64");

  const buildMutation = trpc.evasionEngine.buildPipeline.useMutation({
    onError: (err: any) => toast.error(`Pipeline build failed: ${err.message}`),
  });

  const techniquesQuery = trpc.evasionEngine.getAvailableTechniques.useQuery({
    payloadType,
    targetOs,
    targetArch,
  });

  const handleBuild = () => {
    buildMutation.mutate({
      profile: profile as any,
      payloadType: payloadType as any,
      targetOs: targetOs as any,
      targetArch: targetArch as any,
    });
  };

  const pipeline = buildMutation.data;

  return (
    <div className="space-y-6">
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base font-display tracking-wider">
            <Layers className="w-4 h-4 text-primary" />
            PAYLOAD TRANSFORMATION PIPELINE
          </CardTitle>
          <CardDescription>
            Chain ScareCrow → Donut → Freeze to wrap payloads in evasion layers.
            Select a profile to auto-configure the pipeline, or customize individual techniques.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">EVASION PROFILE</label>
              <Select value={profile} onValueChange={setProfile}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None (Baseline)</SelectItem>
                  <SelectItem value="low">Low (Basic)</SelectItem>
                  <SelectItem value="medium">Medium (Standard)</SelectItem>
                  <SelectItem value="high">High (Maximum)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">PAYLOAD TYPE</label>
              <Select value={payloadType} onValueChange={setPayloadType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="exe">EXE</SelectItem>
                  <SelectItem value="dll">DLL</SelectItem>
                  <SelectItem value="shellcode">Shellcode</SelectItem>
                  <SelectItem value="powershell">PowerShell</SelectItem>
                  <SelectItem value="csharp">C# Assembly</SelectItem>
                  <SelectItem value="hta">HTA</SelectItem>
                  <SelectItem value="vba">VBA Macro</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">TARGET OS</label>
              <Select value={targetOs} onValueChange={setTargetOs}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">ARCHITECTURE</label>
              <Select value={targetArch} onValueChange={setTargetArch}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="x64">x64</SelectItem>
                  <SelectItem value="x86">x86</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <Button onClick={handleBuild} disabled={buildMutation.isPending} className="font-display tracking-wider">
            {buildMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Zap className="w-4 h-4 mr-2" />}
            {buildMutation.isPending ? "BUILDING PIPELINE..." : "BUILD PIPELINE"}
          </Button>
        </CardContent>
      </Card>

      {pipeline && (
        <div className="space-y-4">
          <Card className="border-border/50">
            <CardContent className="pt-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold font-display text-primary">{pipeline.pipeline?.stealthRating || "N/A"}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">STEALTH RATING</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-display">{pipeline.pipeline?.steps?.length || 0}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">TRANSFORM STEPS</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-display uppercase">{pipeline.pipeline?.profile || profile}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">EVASION PROFILE</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-display">{pipeline.sessionId ? "SAVED" : "PREVIEW"}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">STATUS</div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-border/50">
            <CardHeader>
              <CardTitle className="text-sm font-display tracking-wider">TRANSFORMATION CHAIN</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {pipeline.pipeline?.steps?.map((step: any, i: number) => (
                  <div key={i} className="flex items-start gap-3">
                    <div className="flex flex-col items-center">
                      <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary font-display text-sm">{i + 1}</div>
                      {i < (pipeline.pipeline?.steps?.length || 0) - 1 && <div className="w-px h-8 bg-border/50 mt-1" />}
                    </div>
                    <div className="flex-1 pb-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-display tracking-wider text-sm uppercase">{step.tool}</span>
                        <Badge variant="outline" className="text-xs">{step.technique || step.category || "transform"}</Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">{step.description || `Apply ${step.tool} transformation`}</p>
                      {step.command && (
                        <div className="mt-2 bg-secondary/50 rounded p-2 flex items-center gap-2">
                          <Terminal className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                          <code className="text-xs font-mono text-foreground/80 break-all">{step.command}</code>
                        </div>
                      )}
                    </div>
                  </div>
                )) || <p className="text-sm text-muted-foreground">No transformation steps for this profile.</p>}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {techniquesQuery.data && techniquesQuery.data.length > 0 && (
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="text-sm font-display tracking-wider">AVAILABLE EVASION TECHNIQUES ({techniquesQuery.data.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {techniquesQuery.data.map((tech: any) => (
                <div key={tech.id} className="border border-border/50 rounded-lg p-3 hover:bg-secondary/30 transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-display tracking-wider text-xs">{tech.name}</span>
                    <Badge variant="outline" className="text-xs">{tech.category}</Badge>
                  </div>
                  <p className="text-xs text-muted-foreground mb-2">{tech.description}</p>
                  <div className="flex items-center gap-2">
                    <Badge className="text-xs bg-primary/20 text-primary border-primary/30">{tech.attackTechnique}</Badge>
                    {tech.implementedBy?.map((tool: string) => (
                      <Badge key={tool} variant="outline" className="text-xs">{tool}</Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIER 3 — EVASION SCORECARD TAB
// ═══════════════════════════════════════════════════════════════════════════════

function EvasionScorecardTab() {
  const [campaignId, setCampaignId] = useState("");
  const [techniques, setTechniques] = useState("");
  const [pipelineProfile, setPipelineProfile] = useState("medium");
  const [includePayloadPipeline, setIncludePayloadPipeline] = useState(true);
  const [mutationCommands, setMutationCommands] = useState("");

  const scorecardMutation = trpc.evasionEngine.generateScorecard.useMutation({
    onError: (err: any) => toast.error(`Scorecard generation failed: ${err.message}`),
  });

  const handleGenerate = () => {
    const techList = techniques.split("\n").map((t) => t.trim()).filter(Boolean);
    if (techList.length === 0) {
      toast.error("Enter at least one ATT&CK technique ID (e.g. T1059.001)");
      return;
    }

    const mutationTests = mutationCommands
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((cmd) => ({ command: cmd, pattern: cmd.split(/\s+/)[0] || cmd }));

    scorecardMutation.mutate({
      campaignId: campaignId || `manual-${Date.now()}`,
      techniques: techList,
      runMutationTests: mutationTests.length > 0 ? mutationTests : undefined,
      pipelineConfig: includePayloadPipeline
        ? {
            profile: pipelineProfile as any,
            payloadType: "exe" as const,
            targetOs: "windows" as const,
            targetArch: "x64" as const,
          }
        : undefined,
    });
  };

  const scorecard = scorecardMutation.data?.scorecard;
  const sessionId = scorecardMutation.data?.sessionId;

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-400";
    if (score >= 60) return "text-yellow-400";
    if (score >= 40) return "text-orange-400";
    return "text-red-400";
  };

  const getBandColor = (band: string) => {
    switch (band) {
      case "ghost": return "bg-green-500/20 text-green-400 border-green-500/30";
      case "stealthy": return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
      case "detectable": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
      case "exposed": return "bg-red-500/20 text-red-400 border-red-500/30";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case "critical": return "text-red-400";
      case "high": return "text-orange-400";
      case "medium": return "text-yellow-400";
      case "low": return "text-green-400";
      default: return "text-muted-foreground";
    }
  };

  return (
    <div className="space-y-6">
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base font-display tracking-wider">
            <BarChart3 className="w-4 h-4 text-primary" />
            EVASION SCORECARD
          </CardTitle>
          <CardDescription>
            Evaluate a campaign's stealth posture by ATT&CK technique. Enter the techniques used —
            the engine assesses detection coverage, mutation robustness, and produces a Campaign Stealth Score.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">CAMPAIGN ID (optional)</label>
            <Input value={campaignId} onChange={(e) => setCampaignId(e.target.value)} placeholder="e.g. op-midnight-2025" className="font-mono text-sm" />
          </div>

          <div>
            <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">ATT&CK TECHNIQUES (one per line)</label>
            <Textarea
              value={techniques}
              onChange={(e) => setTechniques(e.target.value)}
              placeholder={`T1059.001\nT1053.005\nT1003.001\nT1071.001\nT1547.001`}
              className="font-mono text-sm min-h-[120px]"
            />
          </div>

          <div>
            <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">COMMANDS FOR MUTATION TESTING (optional, one per line)</label>
            <Textarea
              value={mutationCommands}
              onChange={(e) => setMutationCommands(e.target.value)}
              placeholder={`powershell.exe -enc SQBFAFgA...\ncmd.exe /c whoami\nnet user /domain`}
              className="font-mono text-sm min-h-[80px]"
            />
          </div>

          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={includePayloadPipeline} onChange={(e) => setIncludePayloadPipeline(e.target.checked)} className="rounded" />
              <span className="text-sm">Include payload pipeline analysis</span>
            </label>
            {includePayloadPipeline && (
              <Select value={pipelineProfile} onValueChange={setPipelineProfile}>
                <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                </SelectContent>
              </Select>
            )}
          </div>

          <Button onClick={handleGenerate} disabled={scorecardMutation.isPending} className="font-display tracking-wider">
            {scorecardMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Target className="w-4 h-4 mr-2" />}
            {scorecardMutation.isPending ? "GENERATING SCORECARD..." : "GENERATE SCORECARD"}
          </Button>
        </CardContent>
      </Card>

      {scorecard && (
        <div className="space-y-4">
          {/* Overall Score */}
          <Card className="border-border/50">
            <CardContent className="pt-6">
              <div className="text-center mb-6">
                <div className={`text-5xl font-bold font-display ${getScoreColor(scorecard.campaignStealthScore)}`}>
                  {scorecard.campaignStealthScore}
                </div>
                <div className="text-xs text-muted-foreground font-display tracking-wider mt-1">CAMPAIGN STEALTH SCORE</div>
                <Badge className={`mt-2 ${getBandColor(scorecard.stealthBand)}`}>
                  {scorecard.stealthBand?.toUpperCase()}
                </Badge>
                {sessionId && <div className="text-xs text-muted-foreground mt-2">Session #{sessionId}</div>}
              </div>

              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="text-center">
                  <div className="text-xl font-bold font-display">{scorecard.detectionCoverage}%</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">DETECTION COVERAGE</div>
                </div>
                <div className="text-center">
                  <div className="text-xl font-bold font-display">{scorecard.evasionSuccessRate}%</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">EVASION SUCCESS</div>
                </div>
                <div className="text-center">
                  <div className="text-xl font-bold font-display">{scorecard.summary.totalTechniques}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">TECHNIQUES</div>
                </div>
                <div className="text-center">
                  <div className="text-xl font-bold font-display text-green-400">{scorecard.summary.detected}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">DETECTED</div>
                </div>
                <div className="text-center">
                  <div className="text-xl font-bold font-display text-red-400">{scorecard.summary.evaded}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">EVADED</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Technique Results */}
          {scorecard.techniqueResults.length > 0 && (
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-sm font-display tracking-wider">TECHNIQUE DETECTION RESULTS</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {scorecard.techniqueResults.map((tr: any) => (
                    <div key={tr.techniqueId} className="border border-border/50 rounded-lg p-3 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {tr.detectionStatus === "detected" ? (
                          <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
                        ) : tr.detectionStatus === "evaded" ? (
                          <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />
                        )}
                        <div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-xs font-mono">{tr.techniqueId}</Badge>
                            <span className="text-sm">{tr.techniqueName}</span>
                          </div>
                          <span className="text-xs text-muted-foreground">{tr.tactic}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {tr.mutationEvasionRate > 0 && (
                          <span className="text-xs text-red-400">{tr.mutationEvasionRate}% mutation evasion</span>
                        )}
                        <Badge className={
                          tr.detectionStatus === "detected" ? "bg-green-500/20 text-green-400 border-green-500/30" :
                          tr.detectionStatus === "evaded" ? "bg-red-500/20 text-red-400 border-red-500/30" :
                          "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                        }>
                          {tr.detectionStatus}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Detection Gaps */}
          {scorecard.detectionGaps.length > 0 && (
            <Card className="border-red-500/20 bg-red-500/5">
              <CardHeader>
                <CardTitle className="text-sm font-display tracking-wider text-red-400 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  DETECTION GAPS ({scorecard.detectionGaps.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {scorecard.detectionGaps.map((gap: any, i: number) => (
                    <div key={i} className="border border-red-500/20 rounded-lg p-3">
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs font-mono">{gap.techniqueId}</Badge>
                          <span className="text-sm">{gap.techniqueName}</span>
                        </div>
                        <Badge className={`text-xs ${getRiskColor(gap.riskLevel)}`}>{gap.riskLevel}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mb-1">{gap.reason}</p>
                      <p className="text-xs text-blue-400">Recommendation: {gap.recommendation}</p>
                      {gap.suggestedRuleTitle && (
                        <p className="text-xs text-muted-foreground mt-1">Suggested rule: "{gap.suggestedRuleTitle}"</p>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Rule Robustness */}
          {scorecard.ruleRobustness.length > 0 && (
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-sm font-display tracking-wider">RULE ROBUSTNESS RATINGS</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {scorecard.ruleRobustness.map((rule: any, i: number) => (
                    <div key={i} className="border border-border/50 rounded-lg p-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm">{rule.ruleTitle}</span>
                        <span className={`text-sm font-bold font-display ${getScoreColor(rule.robustnessScore)}`}>
                          {rule.robustnessScore}%
                        </span>
                      </div>
                      <Progress value={rule.robustnessScore} className="h-1.5" />
                      <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                        <span className="text-green-400">{rule.variantsCaught} caught</span>
                        <span className="text-red-400">{rule.variantsEvaded} evaded</span>
                        <span>{rule.totalVariants} total</span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Purple Team Actions */}
          {scorecard.purpleTeamActions.length > 0 && (
            <Card className="border-primary/20 bg-primary/5">
              <CardHeader>
                <CardTitle className="text-sm font-display tracking-wider text-primary flex items-center gap-2">
                  <TrendingUp className="w-4 h-4" />
                  PURPLE TEAM ACTIONS ({scorecard.purpleTeamActions.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {scorecard.purpleTeamActions.map((action: any, i: number) => (
                    <div key={i} className="border border-primary/20 rounded-lg p-3">
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <span className="text-primary font-bold font-display">P{action.priority}</span>
                          <Badge variant="outline" className="text-xs">{action.type.replace(/_/g, " ")}</Badge>
                          <Badge variant="outline" className="text-xs">{action.effort} effort</Badge>
                        </div>
                      </div>
                      <p className="text-sm text-muted-foreground">{action.description}</p>
                      <div className="flex flex-wrap gap-1 mt-2">
                        {action.techniques.map((t: string) => (
                          <Badge key={t} variant="outline" className="text-xs font-mono">{t}</Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIER 4 — ADAPTIVE EVASION ORCHESTRATOR TAB
// ═══════════════════════════════════════════════════════════════════════════════

function EvasionOrchestratorTab() {
  const [targetUrl, setTargetUrl] = useState("");
  const [c2Command, setC2Command] = useState("");
  const [c2Target, setC2Target] = useState("");
  const [exploitPayload, setExploitPayload] = useState("");
  const [exploitTarget, setExploitTarget] = useState("");
  const [exploitName, setExploitName] = useState("");
  const [activeOp, setActiveOp] = useState<"scan" | "c2" | "exploit">("scan");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const findingsQuery = trpc.evasionEngine.orchestratorFindings.useQuery(undefined, {
    refetchInterval: 10000,
  });

  const probeMutation = trpc.evasionEngine.probeDefenses.useMutation({
    onSuccess: (data) => {
      if (data.wafDetected) {
        toast.warning(`WAF detected: ${data.wafProducts.join(", ")}`);
      } else {
        toast.success("No WAF detected — target appears unprotected");
      }
    },
    onError: (err: any) => toast.error(`Probe failed: ${err.message}`),
  });

  const evasionScanMut = trpc.evasionEngine.evasionScan.useMutation({
    onSuccess: (data) => {
      findingsQuery.refetch();
      if (data.bypassAchieved) {
        toast.success(`WAF bypassed using: ${data.bypassTechnique || "No evasion needed"}`);
      } else {
        toast.error("All evasion techniques blocked — target has robust defenses");
      }
    },
    onError: (err: any) => toast.error(`Evasion scan failed: ${err.message}`),
  });

  const evasionC2Mut = trpc.evasionEngine.evasionC2Task.useMutation({
    onSuccess: (data) => {
      findingsQuery.refetch();
      if (data.bypassAchieved) {
        toast.success(`EDR bypassed using: ${data.bypassTechnique || "No evasion needed"}`);
      } else {
        toast.error("All evasion techniques blocked by EDR");
      }
    },
    onError: (err: any) => toast.error(`Evasion C2 task failed: ${err.message}`),
  });

  const evasionExploitMut = trpc.evasionEngine.evasionExploit.useMutation({
    onSuccess: (data) => {
      findingsQuery.refetch();
      if (data.bypassAchieved) {
        toast.success(`Exploit delivered — bypassed using: ${data.bypassTechnique || "No evasion needed"}`);
      } else {
        toast.error("Exploit blocked by all evasion attempts");
      }
    },
    onError: (err: any) => toast.error(`Evasion exploit failed: ${err.message}`),
  });

  const isRunning = evasionScanMut.isPending || evasionC2Mut.isPending || evasionExploitMut.isPending || probeMutation.isPending;
  const stats = findingsQuery.data?.stats;
  const findings = findingsQuery.data?.findings || [];

  const handleLaunch = () => {
    if (activeOp === "scan") {
      if (!targetUrl.trim()) { toast.error("Enter a target URL"); return; }
      evasionScanMut.mutate({ targetUrl, scanType: "full", scanMode: "active" });
    } else if (activeOp === "c2") {
      if (!c2Command.trim() || !c2Target.trim()) { toast.error("Enter C2 target and command"); return; }
      evasionC2Mut.mutate({ sessionId: 1, sessionTarget: c2Target, taskType: "execute", command: c2Command });
    } else {
      if (!exploitTarget.trim() || !exploitPayload.trim()) { toast.error("Enter exploit target and payload"); return; }
      evasionExploitMut.mutate({ target: exploitTarget, exploitId: "custom", exploitName: exploitName || "Custom Exploit", payload: exploitPayload });
    }
  };

  const resultForDomain = (domain: string) => {
    if (domain === "scan" && evasionScanMut.data) return evasionScanMut.data;
    if (domain === "c2" && evasionC2Mut.data) return evasionC2Mut.data;
    if (domain === "exploit" && evasionExploitMut.data) return evasionExploitMut.data;
    return null;
  };

  const currentResult = resultForDomain(activeOp);

  return (
    <div className="space-y-6">
      {/* Stats Overview */}
      {stats && stats.totalFindings > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Card className="border-border/50">
            <CardContent className="pt-4 pb-3 text-center">
              <div className="text-2xl font-bold font-display">{stats.totalFindings}</div>
              <div className="text-xs text-muted-foreground font-display tracking-wider">TOTAL OPS</div>
            </CardContent>
          </Card>
          <Card className="border-green-500/20">
            <CardContent className="pt-4 pb-3 text-center">
              <div className="text-2xl font-bold font-display text-green-400">{stats.byResult.bypassed}</div>
              <div className="text-xs text-muted-foreground font-display tracking-wider">BYPASSED</div>
            </CardContent>
          </Card>
          <Card className="border-red-500/20">
            <CardContent className="pt-4 pb-3 text-center">
              <div className="text-2xl font-bold font-display text-red-400">{stats.byResult.blocked}</div>
              <div className="text-xs text-muted-foreground font-display tracking-wider">BLOCKED</div>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="pt-4 pb-3 text-center">
              <div className="text-2xl font-bold font-display">{stats.averageEscalationDepth}</div>
              <div className="text-xs text-muted-foreground font-display tracking-wider">AVG DEPTH</div>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="pt-4 pb-3 text-center">
              <div className="text-2xl font-bold font-display">{stats.averageBypassRate}%</div>
              <div className="text-xs text-muted-foreground font-display tracking-wider">BYPASS RATE</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Operation Launcher */}
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base font-display tracking-wider">
            <Target className="w-4 h-4 text-primary" />
            ADAPTIVE EVASION ORCHESTRATOR
          </CardTitle>
          <CardDescription>
            Launch operations with progressive evasion escalation. When blocked, the orchestrator
            automatically steps through increasingly aggressive bypass techniques until it gets through.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Domain selector */}
          <div className="flex gap-2">
            <Button variant={activeOp === "scan" ? "default" : "outline"} size="sm" onClick={() => setActiveOp("scan")} className="font-display tracking-wider text-xs">
              <Shield className="w-3.5 h-3.5 mr-1.5" /> WAF BYPASS SCAN
            </Button>
            <Button variant={activeOp === "c2" ? "default" : "outline"} size="sm" onClick={() => setActiveOp("c2")} className="font-display tracking-wider text-xs">
              <Terminal className="w-3.5 h-3.5 mr-1.5" /> EDR BYPASS C2
            </Button>
            <Button variant={activeOp === "exploit" ? "default" : "outline"} size="sm" onClick={() => setActiveOp("exploit")} className="font-display tracking-wider text-xs">
              <Zap className="w-3.5 h-3.5 mr-1.5" /> EXPLOIT DELIVERY
            </Button>
          </div>

          {/* Scan inputs */}
          {activeOp === "scan" && (
            <div className="space-y-3">
              <div>
                <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">TARGET URL</label>
                <div className="flex gap-2">
                  <Input value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} placeholder="https://target.example.com" className="font-mono text-sm" />
                  <Button variant="outline" size="sm" onClick={() => { if (targetUrl) probeMutation.mutate({ targetUrl }); }} disabled={!targetUrl || probeMutation.isPending} className="font-display tracking-wider text-xs shrink-0">
                    {probeMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
                    PROBE
                  </Button>
                </div>
              </div>
              {probeMutation.data && (
                <div className={`p-3 rounded-lg border text-sm ${probeMutation.data.wafDetected ? "border-amber-500/30 bg-amber-500/5" : "border-green-500/30 bg-green-500/5"}`}>
                  <div className="flex items-center gap-2 mb-1">
                    {probeMutation.data.wafDetected ? <AlertTriangle className="w-4 h-4 text-amber-400" /> : <CheckCircle2 className="w-4 h-4 text-green-400" />}
                    <span className="font-display tracking-wider text-xs">{probeMutation.data.wafDetected ? "WAF DETECTED" : "NO WAF DETECTED"}</span>
                  </div>
                  {probeMutation.data.wafProducts.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {probeMutation.data.wafProducts.map((w: string, i: number) => (
                        <Badge key={i} variant="outline" className="border-amber-500/30 text-amber-400 text-xs">{w}</Badge>
                      ))}
                    </div>
                  )}
                  {probeMutation.data.recommendations.map((r: string, i: number) => (
                    <p key={i} className="text-xs text-muted-foreground mt-1">{r}</p>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* C2 inputs */}
          {activeOp === "c2" && (
            <div className="space-y-3">
              <div>
                <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">C2 SESSION TARGET</label>
                <Input value={c2Target} onChange={(e) => setC2Target(e.target.value)} placeholder="192.168.1.100" className="font-mono text-sm" />
              </div>
              <div>
                <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">COMMAND</label>
                <Textarea value={c2Command} onChange={(e) => setC2Command(e.target.value)} placeholder="whoami /all" className="font-mono text-sm min-h-[80px]" />
              </div>
            </div>
          )}

          {/* Exploit inputs */}
          {activeOp === "exploit" && (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">TARGET</label>
                  <Input value={exploitTarget} onChange={(e) => setExploitTarget(e.target.value)} placeholder="https://target.example.com/vuln" className="font-mono text-sm" />
                </div>
                <div>
                  <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">EXPLOIT NAME</label>
                  <Input value={exploitName} onChange={(e) => setExploitName(e.target.value)} placeholder="CVE-2024-XXXX" className="font-mono text-sm" />
                </div>
              </div>
              <div>
                <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">PAYLOAD</label>
                <Textarea value={exploitPayload} onChange={(e) => setExploitPayload(e.target.value)} placeholder="<script>alert(1)</script>" className="font-mono text-sm min-h-[80px]" />
              </div>
            </div>
          )}

          <Button onClick={handleLaunch} disabled={isRunning} className="font-display tracking-wider">
            {isRunning ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Play className="w-4 h-4 mr-2" />}
            {isRunning ? "ESCALATING EVASION..." : "LAUNCH WITH EVASION"}
          </Button>
        </CardContent>
      </Card>

      {/* Current Operation Result */}
      {currentResult && "evasionFinding" in currentResult && currentResult.evasionFinding && (
        <Card className={`border-${currentResult.bypassAchieved ? "green" : "red"}-500/20`}>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm font-display tracking-wider">
              {currentResult.bypassAchieved ? <CheckCircle2 className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
              {currentResult.bypassAchieved ? "BYPASS ACHIEVED" : "ALL TECHNIQUES BLOCKED"}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Scorecard */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="text-center p-3 bg-secondary/30 rounded-lg">
                <div className="text-lg font-bold font-display">{currentResult.evasionFinding.totalAttempts}</div>
                <div className="text-xs text-muted-foreground">Attempts</div>
              </div>
              <div className="text-center p-3 bg-secondary/30 rounded-lg">
                <div className="text-lg font-bold font-display">{currentResult.evasionFinding.evasionScorecard.escalationDepth}/5</div>
                <div className="text-xs text-muted-foreground">Escalation Depth</div>
              </div>
              <div className="text-center p-3 bg-secondary/30 rounded-lg">
                <div className="text-lg font-bold font-display text-green-400">{currentResult.evasionFinding.evasionScorecard.bypassRate}%</div>
                <div className="text-xs text-muted-foreground">Bypass Rate</div>
              </div>
              <div className="text-center p-3 bg-secondary/30 rounded-lg">
                <div className="text-lg font-bold font-display text-red-400">{currentResult.evasionFinding.evasionScorecard.defenseEffectiveness}%</div>
                <div className="text-xs text-muted-foreground">Defense Effectiveness</div>
              </div>
            </div>

            {/* Successful technique */}
            {currentResult.evasionFinding.successfulTechnique && currentResult.evasionFinding.successfulTechnique.id !== "none" && (
              <div className="p-3 rounded-lg border border-green-500/30 bg-green-500/5">
                <div className="flex items-center gap-2 mb-1">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  <span className="font-display tracking-wider text-xs text-green-400">SUCCESSFUL TECHNIQUE</span>
                  <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-xs">Level {currentResult.evasionFinding.successfulTechnique.escalationLevel}</Badge>
                </div>
                <div className="text-sm font-medium">{currentResult.evasionFinding.successfulTechnique.name}</div>
                <div className="text-xs text-muted-foreground mt-1">{currentResult.evasionFinding.successfulTechnique.description}</div>
              </div>
            )}

            {/* Defenses detected */}
            {currentResult.evasionFinding.defensesDetected.length > 0 && (
              <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/5">
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-4 h-4 text-amber-400" />
                  <span className="font-display tracking-wider text-xs text-amber-400">DEFENSES DETECTED</span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {currentResult.evasionFinding.defensesDetected.map((d: string, i: number) => (
                    <Badge key={i} variant="outline" className="border-amber-500/30 text-amber-400 text-xs">{d}</Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Escalation Timeline */}
            <div>
              <h4 className="font-display tracking-wider text-xs text-muted-foreground mb-3">ESCALATION TIMELINE</h4>
              <div className="space-y-1">
                {currentResult.evasionFinding.attempts.map((attempt: any, i: number) => (
                  <div key={i} className="flex items-center gap-3 p-2 rounded-lg hover:bg-secondary/30 transition-colors">
                    <div className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0" style={{
                      backgroundColor: attempt.result === "bypassed" ? "rgba(34,197,94,0.2)" : attempt.result === "blocked" ? "rgba(239,68,68,0.2)" : "rgba(234,179,8,0.2)",
                      color: attempt.result === "bypassed" ? "#22c55e" : attempt.result === "blocked" ? "#ef4444" : "#eab308",
                    }}>
                      {attempt.attemptNumber}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium truncate">{attempt.techniqueName}</div>
                      <div className="text-xs text-muted-foreground">{attempt.techniqueCategory} • {attempt.latencyMs}ms</div>
                    </div>
                    <Badge variant="outline" className={`text-xs shrink-0 ${
                      attempt.result === "bypassed" ? "border-green-500/30 text-green-400" :
                      attempt.result === "blocked" ? "border-red-500/30 text-red-400" :
                      "border-amber-500/30 text-amber-400"
                    }`}>
                      {attempt.result.toUpperCase()}
                    </Badge>
                    {attempt.blockSignal && (
                      <span className="text-xs text-muted-foreground shrink-0">{attempt.blockSignal}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Recommendations */}
            {currentResult.evasionFinding.recommendations.length > 0 && (
              <div className="p-3 rounded-lg border border-blue-500/30 bg-blue-500/5">
                <div className="flex items-center gap-2 mb-2">
                  <Info className="w-4 h-4 text-blue-400" />
                  <span className="font-display tracking-wider text-xs text-blue-400">RECOMMENDATIONS</span>
                </div>
                {currentResult.evasionFinding.recommendations.map((r: string, i: number) => (
                  <p key={i} className="text-xs text-muted-foreground mt-1">• {r}</p>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Historical Findings */}
      {findings.length > 0 && (
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="text-sm font-display tracking-wider">RECENT EVASION OPERATIONS</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {findings.slice(0, 10).map((f: any) => (
              <div key={f.id} className="border border-border/50 rounded-lg overflow-hidden">
                <button
                  onClick={() => setExpandedFinding(expandedFinding === f.id ? null : f.id)}
                  className="w-full flex items-center justify-between p-3 hover:bg-secondary/30 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    {expandedFinding === f.id ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    <Badge variant="outline" className="text-xs">{f.domain.toUpperCase()}</Badge>
                    <span className="text-sm truncate max-w-[300px]">{f.target}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={`text-xs ${
                      f.finalResult === "bypassed" ? "border-green-500/30 text-green-400" : "border-red-500/30 text-red-400"
                    }`}>
                      {f.finalResult.toUpperCase()}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{f.totalAttempts} attempts</span>
                    <span className="text-xs text-muted-foreground">{new Date(f.completedAt).toLocaleTimeString()}</span>
                  </div>
                </button>
                {expandedFinding === f.id && (
                  <div className="border-t border-border/50 p-3 space-y-3">
                    <div className="grid grid-cols-4 gap-3 text-center">
                      <div><div className="text-sm font-bold">{f.evasionScorecard.totalTechniquesTried}</div><div className="text-xs text-muted-foreground">Tried</div></div>
                      <div><div className="text-sm font-bold text-green-400">{f.evasionScorecard.techniquesBypassed}</div><div className="text-xs text-muted-foreground">Bypassed</div></div>
                      <div><div className="text-sm font-bold text-red-400">{f.evasionScorecard.techniquesBlocked}</div><div className="text-xs text-muted-foreground">Blocked</div></div>
                      <div><div className="text-sm font-bold">{f.evasionScorecard.escalationDepth}/5</div><div className="text-xs text-muted-foreground">Depth</div></div>
                    </div>
                    {f.successfulTechnique && f.successfulTechnique.id !== "none" && (
                      <div className="text-sm"><span className="text-green-400 font-medium">Bypass:</span> {f.successfulTechnique.name} (Level {f.successfulTechnique.escalationLevel})</div>
                    )}
                    {f.defensesDetected.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {f.defensesDetected.map((d: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs border-amber-500/30 text-amber-400">{d}</Badge>
                        ))}
                      </div>
                    )}
                    <div className="space-y-1">
                      {f.attempts.map((a: any, i: number) => (
                        <div key={i} className="flex items-center gap-2 text-xs">
                          <span className={`w-2 h-2 rounded-full shrink-0 ${a.result === "bypassed" ? "bg-green-400" : a.result === "blocked" ? "bg-red-400" : "bg-amber-400"}`} />
                          <span className="text-muted-foreground">#{a.attemptNumber}</span>
                          <span className="truncate">{a.techniqueName}</span>
                          <span className="text-muted-foreground ml-auto">{a.latencyMs}ms</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Top Defenses & Bypass Techniques */}
      {stats && (stats.topDefenses.length > 0 || stats.topBypassTechniques.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {stats.topDefenses.length > 0 && (
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Shield className="w-4 h-4 text-red-400" /> TOP DEFENSES ENCOUNTERED
                </CardTitle>
              </CardHeader>
              <CardContent>
                {stats.topDefenses.map((d: any, i: number) => (
                  <div key={i} className="flex items-center justify-between py-1.5">
                    <span className="text-sm">{d.defense}</span>
                    <Badge variant="outline" className="text-xs">{d.count}x</Badge>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
          {stats.topBypassTechniques.length > 0 && (
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                  <ShieldOff className="w-4 h-4 text-green-400" /> TOP BYPASS TECHNIQUES
                </CardTitle>
              </CardHeader>
              <CardContent>
                {stats.topBypassTechniques.map((t: any, i: number) => (
                  <div key={i} className="flex items-center justify-between py-1.5">
                    <span className="text-sm">{t.technique}</span>
                    <Badge variant="outline" className="text-xs border-green-500/30 text-green-400">{t.count}x</Badge>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVASION PLAYBOOK TAB
// ═══════════════════════════════════════════════════════════════════════════════

function EvasionPlaybookTab() {
  const [domain, setDomain] = useState<string>("all");
  const [onlySuccessful, setOnlySuccessful] = useState(false);
  const [exportFormat, setExportFormat] = useState<"preview" | "markdown" | "json">("preview");

  const queryInput = useMemo(() => ({
    domain: domain === "all" ? undefined : domain as "scanning" | "c2" | "exploit",
    onlySuccessful: onlySuccessful || undefined,
  }), [domain, onlySuccessful]);

  const { data: playbook, isLoading } = trpc.evasionEngine.generatePlaybook.useQuery(queryInput);
  const { data: markdownData } = trpc.evasionEngine.exportPlaybookMarkdown.useQuery(queryInput);
  const { data: jsonData } = trpc.evasionEngine.exportPlaybookJSON.useQuery(queryInput);

  const downloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Downloaded ${filename}`);
  };

  return (
    <div className="space-y-6">
      {/* Controls */}
      <Card className="border-border/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-primary" />
            EVASION PLAYBOOK GENERATOR
          </CardTitle>
          <CardDescription>Compile all evasion findings into a shareable report grouped by target and defense product</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-3 items-end">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Domain Filter</label>
              <Select value={domain} onValueChange={setDomain}>
                <SelectTrigger className="w-[160px] h-8 text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Domains</SelectItem>
                  <SelectItem value="scanning">Scanning</SelectItem>
                  <SelectItem value="c2">C2</SelectItem>
                  <SelectItem value="exploit">Exploit</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="onlySuccess"
                checked={onlySuccessful}
                onChange={(e) => setOnlySuccessful(e.target.checked)}
                className="rounded border-border"
              />
              <label htmlFor="onlySuccess" className="text-xs text-muted-foreground">Successful bypasses only</label>
            </div>
            <div className="ml-auto flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => markdownData && downloadFile(markdownData.markdown, `evasion-playbook-${Date.now()}.md`, "text/markdown")}
                disabled={!markdownData}
                className="text-xs"
              >
                <FileText className="w-3.5 h-3.5 mr-1" />
                Export MD
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => jsonData && downloadFile(jsonData.json, `evasion-playbook-${Date.now()}.json`, "application/json")}
                disabled={!jsonData}
                className="text-xs"
              >
                <FileJson className="w-3.5 h-3.5 mr-1" />
                Export JSON
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-primary" />
          <span className="ml-2 text-sm text-muted-foreground">Generating playbook...</span>
        </div>
      ) : !playbook || playbook.summary.totalFindings === 0 ? (
        <Card className="border-dashed border-border/50">
          <CardContent className="py-12 text-center">
            <BookOpen className="w-10 h-10 mx-auto mb-3 text-muted-foreground/40" />
            <p className="text-sm text-muted-foreground">No evasion findings yet. Run evasion-wrapped operations from the Orchestrator tab to populate the playbook.</p>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Executive Summary */}
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-display tracking-wider">EXECUTIVE SUMMARY</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="text-center p-3 rounded-lg bg-secondary/30">
                  <div className="text-2xl font-bold text-primary">{playbook.summary.totalFindings}</div>
                  <div className="text-xs text-muted-foreground">Total Engagements</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-secondary/30">
                  <div className="text-2xl font-bold">{playbook.summary.totalTargets}</div>
                  <div className="text-xs text-muted-foreground">Targets Tested</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-secondary/30">
                  <div className="text-2xl font-bold">{playbook.summary.totalDefenses}</div>
                  <div className="text-xs text-muted-foreground">Defenses Found</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-secondary/30">
                  <div className={`text-2xl font-bold ${playbook.summary.overallBypassRate >= 50 ? "text-green-400" : "text-amber-400"}`}>
                    {playbook.summary.overallBypassRate}%
                  </div>
                  <div className="text-xs text-muted-foreground">Bypass Rate</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-secondary/30">
                  <div className="text-2xl font-bold">{playbook.summary.avgEscalationDepth}</div>
                  <div className="text-xs text-muted-foreground">Avg Escalation</div>
                </div>
              </div>

              {/* Domain breakdown */}
              <div className="mt-4 grid grid-cols-3 gap-3">
                {Object.entries(playbook.summary.domainBreakdown).map(([dom, stats]) => (
                  <div key={dom} className="flex items-center justify-between p-2 rounded bg-secondary/20">
                    <span className="text-xs font-medium uppercase">{dom}</span>
                    <span className="text-xs text-muted-foreground">
                      {stats.bypassed}/{stats.total} bypassed
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Target Groups */}
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-display tracking-wider">TARGET ANALYSIS</CardTitle>
              <CardDescription>{playbook.targetGroups.length} target(s) analyzed</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {playbook.targetGroups.map((tg) => (
                <div key={tg.target} className="border border-border/30 rounded-lg p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-mono text-sm font-medium">{tg.target}</span>
                      <div className="flex gap-1 mt-1">
                        {tg.domains.map(d => (
                          <Badge key={d} variant="outline" className="text-[10px]">{d}</Badge>
                        ))}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`text-lg font-bold ${tg.overallBypassRate >= 50 ? "text-green-400" : tg.overallBypassRate >= 25 ? "text-amber-400" : "text-red-400"}`}>
                        {tg.overallBypassRate}%
                      </div>
                      <div className="text-xs text-muted-foreground">{tg.successfulBypasses}/{tg.totalEngagements} bypassed</div>
                    </div>
                  </div>

                  {tg.defensesEncountered.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      <span className="text-xs text-muted-foreground mr-1">Defenses:</span>
                      {tg.defensesEncountered.map(d => (
                        <Badge key={d} variant="secondary" className="text-[10px]">{d}</Badge>
                      ))}
                    </div>
                  )}

                  {tg.recommendedApproach && (
                    <div className="bg-green-500/10 border border-green-500/20 rounded p-2">
                      <div className="text-xs font-medium text-green-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" />
                        Recommended: {tg.recommendedApproach.bestTechnique}
                      </div>
                      <div className="text-xs text-muted-foreground mt-0.5">{tg.recommendedApproach.notes}</div>
                    </div>
                  )}

                  {/* Escalation timeline */}
                  <div className="space-y-1">
                    {tg.entries.slice(0, 3).map((entry, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        {entry.successfulTechnique ? (
                          <CheckCircle2 className="w-3 h-3 text-green-400 shrink-0" />
                        ) : (
                          <XCircle className="w-3 h-3 text-red-400 shrink-0" />
                        )}
                        <span className="text-muted-foreground">{entry.operation}</span>
                        <span className="text-muted-foreground/60">→</span>
                        <span className={entry.successfulTechnique ? "text-green-400" : "text-red-400"}>
                          {entry.successfulTechnique ? entry.successfulTechnique.name : "Blocked"}
                        </span>
                        <span className="text-muted-foreground/40 ml-auto">{entry.totalAttempts} attempts</span>
                      </div>
                    ))}
                    {tg.entries.length > 3 && (
                      <div className="text-xs text-muted-foreground/50 pl-5">+{tg.entries.length - 3} more engagements</div>
                    )}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Defense Groups */}
          {playbook.defenseGroups.length > 0 && (
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-display tracking-wider">DEFENSE PRODUCT ANALYSIS</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border/30">
                        <th className="text-left py-2 px-2 font-medium">Defense</th>
                        <th className="text-center py-2 px-2 font-medium">Encountered</th>
                        <th className="text-center py-2 px-2 font-medium">Bypassed</th>
                        <th className="text-center py-2 px-2 font-medium">Bypass Rate</th>
                        <th className="text-center py-2 px-2 font-medium">Risk Level</th>
                        <th className="text-center py-2 px-2 font-medium">Avg Escalation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {playbook.defenseGroups.sort((a, b) => b.bypassRate - a.bypassRate).map(dg => (
                        <tr key={dg.defense} className="border-b border-border/10 hover:bg-secondary/20">
                          <td className="py-2 px-2 font-mono">{dg.defense}</td>
                          <td className="text-center py-2 px-2">{dg.timesEncountered}</td>
                          <td className="text-center py-2 px-2">{dg.timesBypassed}</td>
                          <td className="text-center py-2 px-2">
                            <span className={dg.bypassRate >= 75 ? "text-green-400" : dg.bypassRate >= 50 ? "text-amber-400" : "text-red-400"}>
                              {dg.bypassRate}%
                            </span>
                          </td>
                          <td className="text-center py-2 px-2">
                            <Badge variant={dg.riskLevel === "critical" ? "destructive" : "secondary"} className="text-[10px]">
                              {dg.riskLevel}
                            </Badge>
                          </td>
                          <td className="text-center py-2 px-2">{dg.avgEscalationToBypass}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Technique Effectiveness */}
          {playbook.techniqueEffectiveness.length > 0 && (
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-display tracking-wider">TECHNIQUE EFFECTIVENESS</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {playbook.techniqueEffectiveness.slice(0, 10).map(te => (
                    <div key={te.techniqueId} className="flex items-center gap-3">
                      <div className="w-48 truncate text-xs font-mono">{te.techniqueName}</div>
                      <Badge variant="outline" className="text-[10px] w-24 justify-center">{te.category}</Badge>
                      <div className="flex-1">
                        <div className="h-2 bg-secondary/30 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${te.successRate >= 60 ? "bg-green-500" : te.successRate >= 30 ? "bg-amber-500" : "bg-red-500"}`}
                            style={{ width: `${te.successRate}%` }}
                          />
                        </div>
                      </div>
                      <span className="text-xs w-16 text-right">{te.successRate}% ({te.timesBypassed}/{te.timesUsed})</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* MITRE Mappings */}
          {playbook.mitreMappings.length > 0 && (
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-display tracking-wider">MITRE ATT&CK MAPPINGS</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {playbook.mitreMappings.map(m => (
                    <Badge key={m.mitreId} variant="outline" className="text-xs font-mono">
                      {m.mitreId} — {m.techniqueName} ({m.usageCount}x)
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Recommendations */}
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-display tracking-wider">RECOMMENDATIONS</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {playbook.recommendations.map((rec, i) => (
                  <div key={i} className="flex gap-2 text-xs">
                    <span className="text-primary font-bold shrink-0">{i + 1}.</span>
                    <span className="text-muted-foreground">{rec}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFENSE HEATMAP TAB
// ═══════════════════════════════════════════════════════════════════════════════

function DefenseHeatmapTab() {
  const [domain, setDomain] = useState<string>("all");
  const [minEncounters, setMinEncounters] = useState(1);

  const queryInput = useMemo(() => ({
    domain: domain === "all" ? undefined : domain as "scanning" | "c2" | "exploit",
    minEncounters: minEncounters > 1 ? minEncounters : undefined,
  }), [domain, minEncounters]);

  const { data: heatmap, isLoading } = trpc.evasionEngine.defenseHeatmap.useQuery(queryInput);

  const getCellColor = (intensity: number, encounters: number) => {
    if (encounters === 0) return "bg-secondary/10";
    if (intensity >= 0.75) return "bg-green-500/70";
    if (intensity >= 0.5) return "bg-green-500/40";
    if (intensity >= 0.25) return "bg-amber-500/40";
    return "bg-red-500/40";
  };

  const getCellText = (intensity: number, encounters: number) => {
    if (encounters === 0) return "text-muted-foreground/30";
    if (intensity >= 0.5) return "text-white";
    return "text-foreground";
  };

  return (
    <div className="space-y-6">
      {/* Controls */}
      <Card className="border-border/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
            <Grid3x3 className="w-4 h-4 text-primary" />
            DEFENSE EFFECTIVENESS HEATMAP
          </CardTitle>
          <CardDescription>Visual matrix showing which WAF/EDR products are most/least effective against each evasion technique</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-3 items-end">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Domain Filter</label>
              <Select value={domain} onValueChange={setDomain}>
                <SelectTrigger className="w-[160px] h-8 text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Domains</SelectItem>
                  <SelectItem value="scanning">Scanning</SelectItem>
                  <SelectItem value="c2">C2</SelectItem>
                  <SelectItem value="exploit">Exploit</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Min Encounters</label>
              <Input
                type="number"
                min={1}
                max={50}
                value={minEncounters}
                onChange={(e) => setMinEncounters(parseInt(e.target.value) || 1)}
                className="w-[100px] h-8 text-xs"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-primary" />
          <span className="ml-2 text-sm text-muted-foreground">Generating heatmap...</span>
        </div>
      ) : !heatmap || heatmap.rows.length === 0 ? (
        <Card className="border-dashed border-border/50">
          <CardContent className="py-12 text-center">
            <Grid3x3 className="w-10 h-10 mx-auto mb-3 text-muted-foreground/40" />
            <p className="text-sm text-muted-foreground">No defense data available. Run evasion-wrapped operations against targets with detectable WAF/EDR to populate the heatmap.</p>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card className="border-border/50">
              <CardContent className="py-4 text-center">
                <div className="text-xs text-muted-foreground mb-1">Most Effective Defense</div>
                <div className="font-mono text-sm font-medium">{heatmap.summary.mostEffectiveDefense?.name || "N/A"}</div>
                {heatmap.summary.mostEffectiveDefense && (
                  <div className="text-xs text-green-400">{heatmap.summary.mostEffectiveDefense.bypassRate}% bypass rate</div>
                )}
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="py-4 text-center">
                <div className="text-xs text-muted-foreground mb-1">Weakest Defense</div>
                <div className="font-mono text-sm font-medium">{heatmap.summary.leastEffectiveDefense?.name || "N/A"}</div>
                {heatmap.summary.leastEffectiveDefense && (
                  <div className="text-xs text-red-400">{heatmap.summary.leastEffectiveDefense.bypassRate}% bypass rate</div>
                )}
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="py-4 text-center">
                <div className="text-xs text-muted-foreground mb-1">Best Technique</div>
                <div className="font-mono text-sm font-medium truncate">{heatmap.summary.mostEffectiveTechnique?.name || "N/A"}</div>
                {heatmap.summary.mostEffectiveTechnique && (
                  <div className="text-xs text-green-400">{heatmap.summary.mostEffectiveTechnique.successRate}% success</div>
                )}
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="py-4 text-center">
                <div className="text-xs text-muted-foreground mb-1">Data Points</div>
                <div className="text-2xl font-bold text-primary">{heatmap.summary.totalDataPoints}</div>
              </CardContent>
            </Card>
          </div>

          {/* Heatmap Grid */}
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-display tracking-wider">BYPASS RATE MATRIX</CardTitle>
              <CardDescription>Green = high bypass rate (defense is weak), Red = low bypass rate (defense is strong)</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-[10px]">
                  <thead>
                    <tr>
                      <th className="text-left py-2 px-1 font-medium text-xs sticky left-0 bg-background z-10 min-w-[140px]">Defense \ Technique</th>
                      {heatmap.techniques.map(tech => (
                        <th key={tech} className="py-2 px-1 font-medium text-center min-w-[70px]">
                          <div className="transform -rotate-45 origin-center whitespace-nowrap">{tech.length > 15 ? tech.slice(0, 15) + "..." : tech}</div>
                        </th>
                      ))}
                      <th className="text-center py-2 px-2 font-medium text-xs">Overall</th>
                    </tr>
                  </thead>
                  <tbody>
                    {heatmap.rows.map(row => (
                      <tr key={row.defense} className="border-t border-border/10">
                        <td className="py-1.5 px-1 font-mono font-medium sticky left-0 bg-background z-10">{row.defense}</td>
                        {row.cells.map((cell, ci) => (
                          <td key={ci} className="py-1.5 px-1 text-center">
                            <div
                              className={`rounded px-1 py-0.5 ${getCellColor(cell.intensity, cell.encounters)} ${getCellText(cell.intensity, cell.encounters)}`}
                              title={`${cell.defense} vs ${cell.technique}: ${cell.bypassRate}% bypass (${cell.bypasses}/${cell.encounters})`}
                            >
                              {cell.encounters > 0 ? `${cell.bypassRate}%` : "—"}
                            </div>
                          </td>
                        ))}
                        <td className="py-1.5 px-2 text-center">
                          <span className={`font-bold ${row.overallBypassRate >= 50 ? "text-green-400" : "text-red-400"}`}>
                            {row.overallBypassRate}%
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Legend */}
              <div className="flex items-center gap-4 mt-4 pt-3 border-t border-border/20">
                <span className="text-xs text-muted-foreground">Legend:</span>
                <div className="flex items-center gap-1">
                  <div className="w-4 h-3 rounded bg-red-500/40" />
                  <span className="text-[10px] text-muted-foreground">0-25%</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-4 h-3 rounded bg-amber-500/40" />
                  <span className="text-[10px] text-muted-foreground">25-50%</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-4 h-3 rounded bg-green-500/40" />
                  <span className="text-[10px] text-muted-foreground">50-75%</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-4 h-3 rounded bg-green-500/70" />
                  <span className="text-[10px] text-muted-foreground">75-100%</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-4 h-3 rounded bg-secondary/10" />
                  <span className="text-[10px] text-muted-foreground">No data</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Per-defense detail cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {heatmap.rows.map(row => {
              const activeCells = row.cells.filter(c => c.encounters > 0);
              const bestTech = activeCells.sort((a, b) => b.bypassRate - a.bypassRate)[0];
              const worstTech = activeCells.sort((a, b) => a.bypassRate - b.bypassRate)[0];
              return (
                <Card key={row.defense} className="border-border/30">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-mono text-sm font-medium">{row.defense}</span>
                      <Badge variant={row.overallBypassRate >= 50 ? "destructive" : "secondary"} className="text-[10px]">
                        {row.overallBypassRate}% bypass
                      </Badge>
                    </div>
                    <div className="space-y-1 text-xs">
                      {bestTech && bestTech.bypassRate > 0 && (
                        <div className="flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 text-amber-400" />
                          <span className="text-muted-foreground">Weakest against:</span>
                          <span className="text-amber-400">{bestTech.technique} ({bestTech.bypassRate}%)</span>
                        </div>
                      )}
                      {worstTech && (
                        <div className="flex items-center gap-1">
                          <Shield className="w-3 h-3 text-green-400" />
                          <span className="text-muted-foreground">Strongest against:</span>
                          <span className="text-green-400">{worstTech.technique} ({worstTech.bypassRate}%)</span>
                        </div>
                      )}
                      <div className="text-muted-foreground/60">{row.totalEncounters} total encounters across {activeCells.length} techniques</div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVASION-AWARE VALIDATION TESTING TAB
// ═══════════════════════════════════════════════════════════════════════════════

function EvasionValidationTab() {
  const [target, setTarget] = useState("");
  const [validationType, setValidationType] = useState<"probe" | "verification" | "takeover" | "exploit">("probe");
  const [maxAttempts, setMaxAttempts] = useState(5);
  const [cveFilter, setCveFilter] = useState("");

  const probeScan = trpc.evasionEngine.evasionProbeScan.useMutation({
    onError: (err: any) => toast.error(`Probe scan failed: ${err.message}`),
    onSuccess: () => toast.success("Evasion-aware probe scan complete"),
  });

  const verifySuite = trpc.evasionEngine.evasionVerificationSuite.useMutation({
    onError: (err: any) => toast.error(`Verification failed: ${err.message}`),
    onSuccess: () => toast.success("Evasion-aware verification complete"),
  });

  const detectDef = trpc.evasionEngine.detectDefenses.useMutation({
    onError: (err: any) => toast.error(`Defense detection failed: ${err.message}`),
  });

  const isRunning = probeScan.isPending || verifySuite.isPending;
  const result = validationType === "probe" ? probeScan.data : verifySuite.data;

  const handleRun = () => {
    if (!target.trim()) { toast.error("Enter a target"); return; }
    const cveIds = cveFilter.trim() ? cveFilter.split(",").map(s => s.trim()).filter(Boolean) : undefined;
    if (validationType === "probe") {
      probeScan.mutate({ target, maxAttempts, cveIds });
    } else if (validationType === "verification") {
      verifySuite.mutate({ targetHost: target, maxAttempts, cveIds });
    }
  };

  const handleDetect = () => {
    if (!target.trim()) { toast.error("Enter a target URL"); return; }
    const url = target.startsWith("http") ? target : `https://${target}`;
    detectDef.mutate({ targetUrl: url });
  };

  const severityColor = (level: string) => {
    switch (level) {
      case "critical": return "text-red-400 bg-red-500/10 border-red-500/30";
      case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/30";
      case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
      default: return "text-blue-400 bg-blue-500/10 border-blue-500/30";
    }
  };

  return (
    <div className="space-y-6">
      {/* Config Card */}
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base font-display tracking-wider">
            <Crosshair className="w-4 h-4 text-primary" />
            EVASION-AWARE VALIDATION TESTING
          </CardTitle>
          <CardDescription>
            Run vulnerability probes and verification suites with adaptive evasion bypass.
            When WAF/CDN/EDR/NGFW blocks a test, the engine automatically escalates through
            bypass techniques until it gets through, then records which technique succeeded.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">TARGET HOST / URL</label>
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. vianova.ai or 192.168.1.100"
                className="font-mono text-sm"
              />
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">VALIDATION TYPE</label>
              <Select value={validationType} onValueChange={(v: any) => setValidationType(v)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="probe">Active Probe Scan</SelectItem>
                  <SelectItem value="verification">Verification Suite</SelectItem>
                  <SelectItem value="takeover">Takeover PoC</SelectItem>
                  <SelectItem value="exploit">KEV Exploit Validation</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">CVE FILTER (comma-separated, optional)</label>
              <Input
                value={cveFilter}
                onChange={(e) => setCveFilter(e.target.value)}
                placeholder="e.g. CVE-2024-1234, CVE-2023-5678"
                className="font-mono text-sm"
              />
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-muted-foreground mb-1.5 block">MAX EVASION ATTEMPTS</label>
              <Select value={String(maxAttempts)} onValueChange={(v) => setMaxAttempts(Number(v))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="3">3 (Quick)</SelectItem>
                  <SelectItem value="5">5 (Standard)</SelectItem>
                  <SelectItem value="8">8 (Thorough)</SelectItem>
                  <SelectItem value="10">10 (Maximum)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex gap-3">
            <Button onClick={handleRun} disabled={isRunning} className="font-display tracking-wider">
              {isRunning ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Play className="w-4 h-4 mr-2" />}
              {isRunning ? "RUNNING WITH EVASION..." : "RUN EVASION VALIDATION"}
            </Button>
            <Button variant="outline" onClick={handleDetect} disabled={detectDef.isPending} className="font-display tracking-wider">
              {detectDef.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Eye className="w-4 h-4 mr-2" />}
              DETECT DEFENSES
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Defense Detection Results */}
      {detectDef.data && (
        <Card className={`border-border/50 ${detectDef.data.blocked ? "border-red-500/30 bg-red-500/5" : "border-green-500/30 bg-green-500/5"}`}>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 mb-4">
              {detectDef.data.blocked ? (
                <><Lock className="w-4 h-4 text-red-400" /><span className="text-sm font-display tracking-wider text-red-400">DEFENSES DETECTED</span></>
              ) : (
                <><Unlock className="w-4 h-4 text-green-400" /><span className="text-sm font-display tracking-wider text-green-400">NO ACTIVE BLOCKING</span></>
              )}
              <Badge variant="outline" className="ml-auto">
                HTTP {detectDef.data.statusCode} • {detectDef.data.responseSize} bytes
              </Badge>
            </div>
            {detectDef.data.blocked && (
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-display tracking-wider text-muted-foreground">BLOCK TYPE:</span>
                  <Badge className={severityColor("high")}>{detectDef.data.defenseType || "unknown"}</Badge>
                </div>
                {detectDef.data.defenseName && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-display tracking-wider text-muted-foreground">DEFENSE PRODUCT:</span>
                    <Badge variant="outline">{detectDef.data.defenseName}</Badge>
                  </div>
                )}
                {detectDef.data.confidence && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-display tracking-wider text-muted-foreground">CONFIDENCE:</span>
                    <Progress value={detectDef.data.confidence * 100} className="h-1.5 w-32" />
                    <span className="text-xs">{Math.round(detectDef.data.confidence * 100)}%</span>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Validation Results */}
      {result && (
        <div className="space-y-4">
          {/* Summary Stats */}
          <Card className="border-border/50">
            <CardContent className="pt-6">
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold font-display">{result.summary?.totalProbes || result.summary?.totalChecks || 0}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">TOTAL TESTS</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-display text-green-400">{result.summary?.succeeded || result.summary?.passed || 0}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">SUCCEEDED</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-display text-red-400">{result.summary?.blocked || result.summary?.failed || 0}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">BLOCKED</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-display text-yellow-400">{result.summary?.bypassedViaEvasion || 0}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">BYPASSED VIA EVASION</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-display text-purple-400">{result.summary?.uniqueTechniquesUsed || 0}</div>
                  <div className="text-xs text-muted-foreground font-display tracking-wider">TECHNIQUES USED</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Evasion Findings */}
          {result.evasionFindings && result.evasionFindings.length > 0 && (
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                  <ShieldOff className="w-4 h-4 text-yellow-400" />
                  EVASION BYPASS LOG
                </CardTitle>
                <CardDescription>Techniques that successfully bypassed defenses during validation</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {result.evasionFindings.map((finding: any, i: number) => (
                  <div key={i} className="border border-border/50 rounded-lg p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge className={finding.outcome === "bypassed" ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" : finding.outcome === "blocked" ? "bg-red-500/20 text-red-400 border-red-500/30" : "bg-green-500/20 text-green-400 border-green-500/30"}>
                          {finding.outcome?.toUpperCase() || "UNKNOWN"}
                        </Badge>
                        <span className="text-sm font-display tracking-wider">{finding.target || target}</span>
                      </div>
                      <span className="text-xs text-muted-foreground">
                        Attempt {finding.attemptNumber || i + 1}
                      </span>
                    </div>
                    {finding.defenseName && (
                      <div className="flex items-center gap-2">
                        <Shield className="w-3.5 h-3.5 text-muted-foreground" />
                        <span className="text-xs text-muted-foreground">Defense:</span>
                        <Badge variant="outline" className="text-xs">{finding.defenseName}</Badge>
                      </div>
                    )}
                    {finding.techniqueUsed && (
                      <div className="flex items-center gap-2">
                        <Zap className="w-3.5 h-3.5 text-yellow-400" />
                        <span className="text-xs text-muted-foreground">Bypass technique:</span>
                        <code className="text-xs font-mono bg-secondary/50 px-1.5 py-0.5 rounded">{finding.techniqueUsed}</code>
                      </div>
                    )}
                    {finding.escalationPath && finding.escalationPath.length > 0 && (
                      <div className="mt-2">
                        <span className="text-xs font-display tracking-wider text-muted-foreground block mb-1">ESCALATION PATH:</span>
                        <div className="flex items-center gap-1 flex-wrap">
                          {finding.escalationPath.map((step: string, j: number) => (
                            <span key={j} className="flex items-center gap-1">
                              <Badge variant="outline" className="text-xs">{step}</Badge>
                              {j < finding.escalationPath.length - 1 && <ChevronRight className="w-3 h-3 text-muted-foreground" />}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Individual Probe Results */}
          {result.probes && result.probes.length > 0 && (
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-sm font-display tracking-wider">PROBE RESULTS</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {result.probes.map((probe: any, i: number) => (
                    <div key={i} className="border border-border/50 rounded-lg p-3 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {probe.status === "success" || probe.passed ? (
                          <CheckCircle2 className="w-4 h-4 text-green-400" />
                        ) : probe.evasionBypassed ? (
                          <ShieldOff className="w-4 h-4 text-yellow-400" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-400" />
                        )}
                        <div>
                          <div className="text-sm font-display tracking-wider">{probe.name || probe.probeId || `Probe ${i + 1}`}</div>
                          {probe.cveId && <span className="text-xs text-muted-foreground font-mono">{probe.cveId}</span>}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {probe.evasionBypassed && (
                          <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30 text-xs">
                            Bypassed via {probe.bypassTechnique || "evasion"}
                          </Badge>
                        )}
                        <Badge variant="outline" className="text-xs">
                          {probe.statusCode ? `HTTP ${probe.statusCode}` : probe.status || "unknown"}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Defense Encounters Summary */}
          {result.defensesEncountered && result.defensesEncountered.length > 0 && (
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Shield className="w-4 h-4 text-blue-400" />
                  DEFENSES ENCOUNTERED
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {result.defensesEncountered.map((def: any, i: number) => (
                    <div key={i} className="border border-border/50 rounded-lg p-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-display tracking-wider">{def.product || def.name}</span>
                        <Badge className={def.bypassed ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" : "bg-red-500/20 text-red-400 border-red-500/30"}>
                          {def.bypassed ? "BYPASSED" : "BLOCKED"}
                        </Badge>
                      </div>
                      {def.type && <span className="text-xs text-muted-foreground">Type: {def.type}</span>}
                      {def.bypassTechnique && (
                        <div className="mt-1 flex items-center gap-1">
                          <Zap className="w-3 h-3 text-yellow-400" />
                          <code className="text-xs font-mono">{def.bypassTechnique}</code>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════════════════════════════════════════

export default function EvasionEngine() {
  return (
    <AppShell activePath="/evasion-engine">
      <div className="max-w-7xl mx-auto space-y-6">
        <div>
          <h1 className="text-2xl font-display tracking-wider flex items-center gap-3">
            <ShieldOff className="w-7 h-7 text-primary" />
            EVASION ENGINE
          </h1>
          <p className="text-muted-foreground mt-1">
            Test detection rule robustness, build evasion-wrapped payload pipelines, and generate
            campaign stealth scorecards. The full offensive-defensive feedback loop.
          </p>
        </div>

        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="py-3 flex items-center gap-3">
            <Info className="w-4 h-4 text-primary shrink-0" />
            <p className="text-sm text-muted-foreground">
              <strong className="text-foreground">Purple Team Loop:</strong>{" "}
              Execute campaigns → Correlate SIEM detections → Mutate to find blind spots →
              Harden rules. This engine automates the "Mutate & Harden" step.
            </p>
          </CardContent>
        </Card>

        <Tabs defaultValue="mutations" className="space-y-6">
          <TabsList className="bg-secondary/50 p-1">
            <TabsTrigger value="mutations" className="font-display tracking-wider text-xs data-[state=active]:bg-background">
              <FlaskConical className="w-3.5 h-3.5 mr-1.5" />
              RULE MUTATIONS
            </TabsTrigger>
            <TabsTrigger value="pipeline" className="font-display tracking-wider text-xs data-[state=active]:bg-background">
              <Layers className="w-3.5 h-3.5 mr-1.5" />
              PAYLOAD PIPELINE
            </TabsTrigger>
            <TabsTrigger value="scorecard" className="font-display tracking-wider text-xs data-[state=active]:bg-background">
              <BarChart3 className="w-3.5 h-3.5 mr-1.5" />
              SCORECARD
            </TabsTrigger>
            <TabsTrigger value="orchestrator" className="font-display tracking-wider text-xs data-[state=active]:bg-background">
              <Target className="w-3.5 h-3.5 mr-1.5" />
              ORCHESTRATOR
            </TabsTrigger>
            <TabsTrigger value="playbook" className="font-display tracking-wider text-xs data-[state=active]:bg-background">
              <BookOpen className="w-3.5 h-3.5 mr-1.5" />
              PLAYBOOK
            </TabsTrigger>
            <TabsTrigger value="heatmap" className="font-display tracking-wider text-xs data-[state=active]:bg-background">
              <Grid3x3 className="w-3.5 h-3.5 mr-1.5" />
              DEFENSE HEATMAP
            </TabsTrigger>
            <TabsTrigger value="validation" className="font-display tracking-wider text-xs data-[state=active]:bg-background">
              <Crosshair className="w-3.5 h-3.5 mr-1.5" />
              EVASION VALIDATION
            </TabsTrigger>
          </TabsList>

          <TabsContent value="mutations">
            <MutationTestingTab />
          </TabsContent>
          <TabsContent value="pipeline">
            <PayloadPipelineTab />
          </TabsContent>
          <TabsContent value="scorecard">
            <EvasionScorecardTab />
          </TabsContent>
          <TabsContent value="orchestrator">
            <EvasionOrchestratorTab />
          </TabsContent>
          <TabsContent value="playbook">
            <EvasionPlaybookTab />
          </TabsContent>
          <TabsContent value="heatmap">
            <DefenseHeatmapTab />
          </TabsContent>
          <TabsContent value="validation">
            <EvasionValidationTab />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
