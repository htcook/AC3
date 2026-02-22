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
        </Tabs>
      </div>
    </AppShell>
  );
}
