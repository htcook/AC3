import AppShell from "@/components/AppShell";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  FileCode,
  Brain,
  Target,
  Eye,
  Zap,
  Copy,
  BarChart3,
  Info,
  ChevronDown,
  ChevronRight,
  FileText,
  Download,
} from "lucide-react";

// ─── Sample Rules ───────────────────────────────────────────────────────────

const SAMPLE_RULES: Record<string, { name: string; content: string; technique: string }[]> = {
  sigma: [
    {
      name: "PowerShell Encoded Command",
      technique: "T1059.001",
      content: `title: Suspicious PowerShell Encoded Command
id: 6a7c3e4f-5b2d-4a1e-8c9f-0d3e2f1a5b6c
status: experimental
description: Detects PowerShell execution with encoded commands
author: AceofCloud
date: 2026/02/14
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - '-e '
        Image|endswith: '\\powershell.exe'
    filter:
        ParentImage|endswith:
            - '\\msiexec.exe'
            - '\\sccm\\ccmexec.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate admin scripts using encoding
level: high
tags:
    - attack.execution
    - attack.t1059.001`,
    },
    {
      name: "LSASS Memory Access",
      technique: "T1003.001",
      content: `title: LSASS Memory Access via Process
id: 7b8d4e5f-6c3a-4b2e-9d0f-1e4f3a2b6c7d
status: experimental
description: Detects suspicious access to LSASS process memory
author: AceofCloud
date: 2026/02/14
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1438'
            - '0x143a'
    filter:
        SourceImage|endswith:
            - '\\MsMpEng.exe'
            - '\\csrss.exe'
    condition: selection and not filter
falsepositives:
    - Security products accessing LSASS
level: critical
tags:
    - attack.credential-access
    - attack.t1003.001`,
    },
  ],
  yara: [
    {
      name: "Cobalt Strike Beacon",
      technique: "T1071.001",
      content: `rule CobaltStrike_Beacon_Detection
{
    meta:
        author = "AceofCloud"
        description = "Detects Cobalt Strike beacon patterns"
        date = "2026-02-14"
        reference = "https://attack.mitre.org/techniques/T1071/001/"
        severity = "critical"

    strings:
        $beacon1 = { 4D 5A 90 00 03 00 00 00 }
        $config1 = "sleeptime" ascii wide
        $config2 = "jitter" ascii wide
        $config3 = "publickey" ascii wide
        $pipe = "\\\\.\\pipe\\msagent_" ascii
        $ua = "Mozilla/5.0" ascii

    condition:
        $beacon1 at 0 and
        (2 of ($config*)) and
        ($pipe or $ua) and
        filesize < 1MB
}`,
    },
    {
      name: "Mimikatz Memory Pattern",
      technique: "T1003.001",
      content: `rule Mimikatz_Memory_Detection
{
    meta:
        author = "AceofCloud"
        description = "Detects Mimikatz patterns in memory dumps"
        date = "2026-02-14"
        reference = "https://attack.mitre.org/techniques/T1003/001/"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "sekurlsa::wdigest" ascii wide nocase
        $s3 = "kerberos::golden" ascii wide nocase
        $s4 = "lsadump::sam" ascii wide nocase
        $s5 = "privilege::debug" ascii wide nocase
        $s6 = "token::elevate" ascii wide nocase

    condition:
        3 of them
}`,
    },
  ],
  suricata: [
    {
      name: "C2 Beacon Detection",
      technique: "T1071.001",
      content: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible C2 Beacon - Regular Interval HTTP POST"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/"; http.header; content:"User-Agent: Mozilla/5.0"; threshold:type both, track by_src, count 10, seconds 60; sid:1000001; rev:1; classtype:trojan-activity; reference:url,attack.mitre.org/techniques/T1071/001/;)`,
    },
  ],
  splunk: [
    {
      name: "Suspicious Process Creation",
      technique: "T1059",
      content: `index=windows sourcetype=WinEventLog:Security EventCode=4688
| where match(CommandLine, "(?i)(powershell|cmd|wscript|cscript|mshta|regsvr32|rundll32)")
| where match(CommandLine, "(?i)(-enc|-encodedcommand|downloadstring|invoke-expression|iex|bypass)")
| eval risk_score=case(
    match(CommandLine, "(?i)encodedcommand"), 80,
    match(CommandLine, "(?i)downloadstring"), 90,
    match(CommandLine, "(?i)invoke-expression"), 85,
    1=1, 50)
| where risk_score >= 70
| stats count by Computer, Account_Name, CommandLine, ParentProcessName, risk_score
| sort -risk_score`,
    },
  ],
  kql: [
    {
      name: "Credential Dumping Detection",
      technique: "T1003",
      content: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("procdump.exe", "mimikatz.exe", "nanodump.exe")
    or (FileName == "rundll32.exe" and ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump")
    or (FileName == "powershell.exe" and ProcessCommandLine has_any ("sekurlsa", "lsass", "credential"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc`,
    },
  ],
};

export default function RuleValidator() {
  const [ruleType, setRuleType] = useState<string>("sigma");
  const [ruleContent, setRuleContent] = useState("");
  const [ruleName, setRuleName] = useState("");
  const [techniqueId, setTechniqueId] = useState("");
  const [useLLM, setUseLLM] = useState(true);
  const [validationResult, setValidationResult] = useState<any>(null);
  const [activeTab, setActiveTab] = useState("editor");

  const validateMutation = trpc.calderaProxy.validateRule.useMutation({
    onSuccess: (data) => {
      setValidationResult(data);
      setActiveTab("results");
      toast.success(
        data.valid
          ? `Rule is valid! Effectiveness: ${data.effectivenessScore}%`
          : `Rule has ${data.syntaxErrors.filter((e: any) => e.severity === "error").length} errors`
      );
    },
    onError: (err) => toast.error(`Validation failed: ${err.message}`),
  });

  const handleValidate = () => {
    if (!ruleContent.trim()) {
      toast.error("Please enter a rule to validate");
      return;
    }
    validateMutation.mutate({
      ruleType: ruleType as any,
      ruleContent,
      ruleName: ruleName || undefined,
      techniqueId: techniqueId || undefined,
      useLLM,
    });
  };

  const loadSample = (sample: { name: string; content: string; technique: string }) => {
    setRuleContent(sample.content);
    setRuleName(sample.name);
    setTechniqueId(sample.technique);
    setValidationResult(null);
    toast.success(`Loaded sample: ${sample.name}`);
  };

  const copyRule = () => {
    navigator.clipboard.writeText(ruleContent);
    toast.success("Rule copied to clipboard");
  };

  const exportResults = () => {
    if (!validationResult) return;
    const data = {
      ruleName,
      ruleType,
      techniqueId,
      validation: validationResult,
      exportedAt: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `rule-validation-${ruleName || "result"}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Results exported");
  };

  return (
    <AppShell>
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6" />
            Rule Validation Engine
          </h1>
          <p className="text-muted-foreground mt-1">
            Validate Sigma, YARA, Suricata, Splunk SPL, and KQL detection rules
            before SIEM deployment
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Panel - Editor */}
        <div className="lg:col-span-2">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList>
              <TabsTrigger value="editor">
                <FileCode className="h-4 w-4 mr-1" />
                Editor
              </TabsTrigger>
              <TabsTrigger value="results" disabled={!validationResult}>
                <BarChart3 className="h-4 w-4 mr-1" />
                Results
              </TabsTrigger>
            </TabsList>

            <TabsContent value="editor" className="mt-4 space-y-4">
              {/* Rule Type & Metadata */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">
                    Rule Type
                  </label>
                  <Select value={ruleType} onValueChange={setRuleType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="sigma">Sigma</SelectItem>
                      <SelectItem value="yara">YARA</SelectItem>
                      <SelectItem value="suricata">Suricata</SelectItem>
                      <SelectItem value="splunk">Splunk SPL</SelectItem>
                      <SelectItem value="kql">KQL (Kusto)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">
                    Rule Name
                  </label>
                  <Input
                    placeholder="e.g., PowerShell Encoded Command"
                    value={ruleName}
                    onChange={(e) => setRuleName(e.target.value)}
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">
                    MITRE Technique
                  </label>
                  <Input
                    placeholder="e.g., T1059.001"
                    value={techniqueId}
                    onChange={(e) => setTechniqueId(e.target.value)}
                  />
                </div>
              </div>

              {/* Rule Editor */}
              <div className="relative">
                <Textarea
                  className="font-mono text-sm min-h-[400px] resize-y"
                  placeholder={`Paste your ${ruleType.toUpperCase()} rule here...`}
                  value={ruleContent}
                  onChange={(e) => setRuleContent(e.target.value)}
                />
                <div className="absolute top-2 right-2 flex gap-1">
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 px-2"
                    onClick={copyRule}
                    disabled={!ruleContent}
                  >
                    <Copy className="h-3 w-3" />
                  </Button>
                </div>
              </div>

              {/* Actions */}
              <div className="flex items-center gap-3 flex-wrap">
                <Button
                  onClick={handleValidate}
                  disabled={validateMutation.isPending || !ruleContent.trim()}
                >
                  {validateMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <ShieldCheck className="h-4 w-4 mr-2" />
                  )}
                  Validate Rule
                </Button>
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="useLLM"
                    checked={useLLM}
                    onChange={(e) => setUseLLM(e.target.checked)}
                    className="rounded"
                  />
                  <label htmlFor="useLLM" className="text-sm flex items-center gap-1">
                    <Brain className="h-3 w-3" />
                    LLM Deep Analysis
                  </label>
                </div>
                <span className="text-xs text-muted-foreground">
                  {ruleContent.split("\n").length} lines |{" "}
                  {ruleContent.length} chars
                </span>
              </div>
            </TabsContent>

            <TabsContent value="results" className="mt-4">
              {validationResult && (
                <ValidationResultsView
                  result={validationResult}
                  ruleName={ruleName}
                  ruleType={ruleType}
                  onExport={exportResults}
                />
              )}
            </TabsContent>
          </Tabs>
        </div>

        {/* Right Panel - Samples & Quick Actions */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Sample Rules</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {Object.entries(SAMPLE_RULES).map(([type, samples]) => (
                <div key={type}>
                  <p className="text-xs font-medium text-muted-foreground uppercase mb-1">
                    {type}
                  </p>
                  {samples.map((sample, i) => (
                    <Button
                      key={i}
                      variant="ghost"
                      size="sm"
                      className="w-full justify-start text-xs h-8 mb-1"
                      onClick={() => {
                        setRuleType(type);
                        loadSample(sample);
                      }}
                    >
                      <FileText className="h-3 w-3 mr-2 shrink-0" />
                      <span className="truncate">{sample.name}</span>
                      <Badge variant="outline" className="ml-auto text-xs h-5 shrink-0">
                        {sample.technique}
                      </Badge>
                    </Button>
                  ))}
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Quick Stats */}
          {validationResult && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Quick Summary</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Status</span>
                  {validationResult.valid ? (
                    <Badge className="bg-green-500/10 text-green-500 border-green-500/20">
                      <CheckCircle className="h-3 w-3 mr-1" />
                      Valid
                    </Badge>
                  ) : (
                    <Badge className="bg-red-500/10 text-red-500 border-red-500/20">
                      <XCircle className="h-3 w-3 mr-1" />
                      Invalid
                    </Badge>
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Effectiveness</span>
                  <span className="font-bold">
                    {validationResult.effectivenessScore}%
                  </span>
                </div>
                <Progress
                  value={validationResult.effectivenessScore}
                  className="h-2"
                />
                <div className="flex items-center justify-between">
                  <span className="text-sm">FP Risk</span>
                  <Badge
                    variant={
                      validationResult.falsePositiveRisk === "low"
                        ? "default"
                        : validationResult.falsePositiveRisk === "medium"
                        ? "secondary"
                        : "destructive"
                    }
                  >
                    {validationResult.falsePositiveRisk}
                  </Badge>
                </div>
                <Separator />
                <div className="text-xs space-y-1">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Errors</span>
                    <span className="text-red-500">
                      {validationResult.syntaxErrors.filter(
                        (e: any) => e.severity === "error"
                      ).length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Warnings</span>
                    <span className="text-yellow-500">
                      {validationResult.syntaxErrors.filter(
                        (e: any) => e.severity === "warning"
                      ).length +
                        validationResult.semanticWarnings.length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Suggestions</span>
                    <span>{validationResult.suggestions.length}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Coverage Card */}
          {validationResult?.coverage && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Coverage</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-xs">
                {validationResult.coverage.techniquesCovered.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">Techniques:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {validationResult.coverage.techniquesCovered.map(
                        (t: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {t}
                          </Badge>
                        )
                      )}
                    </div>
                  </div>
                )}
                {validationResult.coverage.platformCompatibility.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">Platforms:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {validationResult.coverage.platformCompatibility.map(
                        (p: string, i: number) => (
                          <Badge key={i} variant="secondary" className="text-xs">
                            {p}
                          </Badge>
                        )
                      )}
                    </div>
                  </div>
                )}
                {validationResult.coverage.dataSourcesRequired.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">Data Sources:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {validationResult.coverage.dataSourcesRequired.map(
                        (d: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {d}
                          </Badge>
                        )
                      )}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
    </AppShell>
  );
}

function ValidationResultsView({
  result,
  ruleName,
  ruleType,
  onExport,
}: {
  result: any;
  ruleName: string;
  ruleType: string;
  onExport: () => void;
}) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(["errors", "warnings", "analysis"])
  );

  const toggleSection = (section: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  };

  const errors = result.syntaxErrors.filter((e: any) => e.severity === "error");
  const warnings = result.syntaxErrors.filter(
    (e: any) => e.severity === "warning"
  );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {result.valid ? (
            <div className="p-2 rounded-lg bg-green-500/10">
              <CheckCircle className="h-6 w-6 text-green-500" />
            </div>
          ) : (
            <div className="p-2 rounded-lg bg-red-500/10">
              <XCircle className="h-6 w-6 text-red-500" />
            </div>
          )}
          <div>
            <h3 className="font-semibold">
              {result.valid ? "Rule is Valid" : "Rule Has Errors"}
            </h3>
            <p className="text-sm text-muted-foreground">
              {ruleName || ruleType.toUpperCase()} | Effectiveness:{" "}
              {result.effectivenessScore}%
            </p>
          </div>
        </div>
        <Button size="sm" variant="outline" onClick={onExport}>
          <Download className="h-4 w-4 mr-1" />
          Export
        </Button>
      </div>

      {/* Effectiveness Gauge */}
      <Card>
        <CardContent className="pt-4 pb-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium">Effectiveness Score</span>
            <span
              className={`text-2xl font-bold ${
                result.effectivenessScore >= 80
                  ? "text-green-500"
                  : result.effectivenessScore >= 60
                  ? "text-yellow-500"
                  : "text-red-500"
              }`}
            >
              {result.effectivenessScore}/100
            </span>
          </div>
          <Progress value={result.effectivenessScore} className="h-2" />
          <div className="flex items-center justify-between mt-2 text-xs text-muted-foreground">
            <span>
              False Positive Risk:{" "}
              <Badge
                variant={
                  result.falsePositiveRisk === "low"
                    ? "default"
                    : result.falsePositiveRisk === "medium"
                    ? "secondary"
                    : "destructive"
                }
                className="text-xs"
              >
                {result.falsePositiveRisk}
              </Badge>
            </span>
            <span>
              {errors.length} errors | {warnings.length} warnings |{" "}
              {result.semanticWarnings.length} semantic issues
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Syntax Errors */}
      {errors.length > 0 && (
        <CollapsibleSection
          title={`Syntax Errors (${errors.length})`}
          icon={<XCircle className="h-4 w-4 text-red-500" />}
          isOpen={expandedSections.has("errors")}
          onToggle={() => toggleSection("errors")}
        >
          <div className="space-y-2">
            {errors.map((err: any, i: number) => (
              <div
                key={i}
                className="flex items-start gap-2 p-2 bg-red-500/5 border border-red-500/20 rounded"
              >
                <XCircle className="h-4 w-4 text-red-500 shrink-0 mt-0.5" />
                <div className="text-sm">
                  <span className="font-mono text-xs text-muted-foreground">
                    Line {err.line}
                    {err.column ? `:${err.column}` : ""}
                  </span>
                  <p>{err.message}</p>
                </div>
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Warnings */}
      {(warnings.length > 0 || result.semanticWarnings.length > 0) && (
        <CollapsibleSection
          title={`Warnings (${warnings.length + result.semanticWarnings.length})`}
          icon={<AlertTriangle className="h-4 w-4 text-yellow-500" />}
          isOpen={expandedSections.has("warnings")}
          onToggle={() => toggleSection("warnings")}
        >
          <div className="space-y-2">
            {warnings.map((w: any, i: number) => (
              <div
                key={`syn-${i}`}
                className="flex items-start gap-2 p-2 bg-yellow-500/5 border border-yellow-500/20 rounded"
              >
                <AlertTriangle className="h-4 w-4 text-yellow-500 shrink-0 mt-0.5" />
                <div className="text-sm">
                  <span className="font-mono text-xs text-muted-foreground">
                    Line {w.line}
                  </span>
                  <p>{w.message}</p>
                </div>
              </div>
            ))}
            {result.semanticWarnings.map((w: any, i: number) => (
              <div
                key={`sem-${i}`}
                className={`flex items-start gap-2 p-2 rounded border ${
                  w.severity === "critical"
                    ? "bg-red-500/5 border-red-500/20"
                    : w.severity === "warning"
                    ? "bg-yellow-500/5 border-yellow-500/20"
                    : "bg-blue-500/5 border-blue-500/20"
                }`}
              >
                {w.severity === "critical" ? (
                  <ShieldAlert className="h-4 w-4 text-red-500 shrink-0 mt-0.5" />
                ) : w.severity === "warning" ? (
                  <AlertTriangle className="h-4 w-4 text-yellow-500 shrink-0 mt-0.5" />
                ) : (
                  <Info className="h-4 w-4 text-blue-500 shrink-0 mt-0.5" />
                )}
                <div className="text-sm">
                  <span className="font-mono text-xs text-muted-foreground">
                    {w.field}
                  </span>
                  <p>{w.message}</p>
                </div>
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* LLM Analysis */}
      {result.llmAnalysis && (
        <CollapsibleSection
          title="AI Analysis"
          icon={<Brain className="h-4 w-4 text-purple-500" />}
          isOpen={expandedSections.has("analysis")}
          onToggle={() => toggleSection("analysis")}
        >
          <div className="space-y-3">
            <p className="text-sm leading-relaxed">{result.llmAnalysis}</p>

            {result.sampleMatches?.length > 0 && (
              <div className="border rounded-lg p-3">
                <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                  <Target className="h-4 w-4" />
                  Sample Data Match Test
                </h4>
                {result.sampleMatches.map((match: any, i: number) => (
                  <div key={i} className="space-y-2">
                    <div className="flex items-center gap-2">
                      {match.matched ? (
                        <Badge className="bg-green-500/10 text-green-500 border-green-500/20">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          Match ({match.confidence}% confidence)
                        </Badge>
                      ) : (
                        <Badge className="bg-red-500/10 text-red-500 border-red-500/20">
                          <XCircle className="h-3 w-3 mr-1" />
                          No Match ({match.confidence}% confidence)
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {match.explanation}
                    </p>
                    {match.matchedFields.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {match.matchedFields.map((f: string, fi: number) => (
                          <Badge key={fi} variant="outline" className="text-xs">
                            {f}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </CollapsibleSection>
      )}

      {/* Suggestions */}
      {result.suggestions.length > 0 && (
        <CollapsibleSection
          title={`Improvement Suggestions (${result.suggestions.length})`}
          icon={<Zap className="h-4 w-4 text-blue-500" />}
          isOpen={expandedSections.has("suggestions")}
          onToggle={() => toggleSection("suggestions")}
        >
          <div className="space-y-2">
            {result.suggestions.map((s: string, i: number) => (
              <div
                key={i}
                className="flex items-start gap-2 p-2 bg-blue-500/5 border border-blue-500/20 rounded"
              >
                <Zap className="h-4 w-4 text-blue-500 shrink-0 mt-0.5" />
                <p className="text-sm">{s}</p>
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}
    </div>
  );
}

function CollapsibleSection({
  title,
  icon,
  isOpen,
  onToggle,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  isOpen: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <div
        className="flex items-center gap-2 p-4 cursor-pointer hover:bg-muted/50"
        onClick={onToggle}
      >
        {isOpen ? (
          <ChevronDown className="h-4 w-4 shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0" />
        )}
        {icon}
        <span className="font-medium text-sm">{title}</span>
      </div>
      {isOpen && <CardContent className="pt-0">{children}</CardContent>}
    </Card>
  );
}
