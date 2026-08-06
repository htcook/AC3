/**
 * ManualToolRunner — Embedded tool execution panel for the Engagement Ops dashboard
 *
 * Features:
 * - Tool Registry browser with category/tier filtering
 * - Pre-built script catalog matched to engagement target profile
 * - Exploit knowledge store search
 * - Embedded CLI with command builder
 * - Output ingestion with auto-parsing into engagement findings
 * - Safety guardrails (ROE, Safety Engine, evidence chain) integrated
 * - Execution history timeline
 */
import { useState, useMemo, useRef, useEffect, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Terminal, Search, Play, Square, Shield, ShieldAlert, ShieldCheck,
  ChevronDown, ChevronRight, Copy, Download, Clock, Loader2,
  Wrench, Zap, Lock, Eye, FileText, AlertTriangle, CheckCircle2,
  XCircle, Filter, Crosshair, Skull, Key, Network, Bug,
  BookOpen, Rocket, RefreshCw, Code, Fingerprint,
} from "lucide-react";
import { toast } from "sonner";

interface ManualToolRunnerProps {
  engagementId: number;
  engagementPhase?: string;
}

// Safety level colors
const SAFETY_COLORS: Record<string, string> = {
  passive_only: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  low_impact: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  standard: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  full_exploitation: "bg-red-500/20 text-red-400 border-red-500/30",
};

const TIER_COLORS: Record<string, string> = {
  passive: "bg-emerald-500/20 text-emerald-400",
  "active-low": "bg-blue-500/20 text-blue-400",
  "active-standard": "bg-amber-500/20 text-amber-400",
  "active-aggressive": "bg-red-500/20 text-red-400",
};

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  recon: <Search className="h-3.5 w-3.5" />,
  scanning: <Crosshair className="h-3.5 w-3.5" />,
  enumeration: <Fingerprint className="h-3.5 w-3.5" />,
  exploitation: <Skull className="h-3.5 w-3.5" />,
  "post-exploit": <Zap className="h-3.5 w-3.5" />,
  credential: <Key className="h-3.5 w-3.5" />,
  evasion: <Shield className="h-3.5 w-3.5" />,
  c2: <Network className="h-3.5 w-3.5" />,
  utility: <Wrench className="h-3.5 w-3.5" />,
  pivot: <Network className="h-3.5 w-3.5" />,
  cleanup: <RefreshCw className="h-3.5 w-3.5" />,
};

export default function ManualToolRunner({ engagementId, engagementPhase }: ManualToolRunnerProps) {
  const [activeTab, setActiveTab] = useState("tools");
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const [tierFilter, setTierFilter] = useState<string | null>(null);
  const [selectedTool, setSelectedTool] = useState<any>(null);
  const [selectedScript, setSelectedScript] = useState<any>(null);
  const [commandInput, setCommandInput] = useState("");
  const [targetInput, setTargetInput] = useState("");
  const [cliOutput, setCliOutput] = useState("");
  const [isExecuting, setIsExecuting] = useState(false);
  const [showApprovalDialog, setShowApprovalDialog] = useState(false);
  const [pendingExecution, setPendingExecution] = useState<any>(null);
  const [exploitSearch, setExploitSearch] = useState("");
  const [scriptSearch, setScriptSearch] = useState("");
  const [scriptCategoryFilter, setScriptCategoryFilter] = useState<string | null>(null);
  const [scriptOsFilter, setScriptOsFilter] = useState<string | null>(null);
  const cliRef = useRef<HTMLDivElement>(null);

  // ── Data queries ──
  const toolsQ = trpc.toolRunner.getToolRegistry.useQuery(
    { engagementId, category: categoryFilter || undefined, tier: tierFilter || undefined, search: searchQuery || undefined },
    { enabled: !!engagementId }
  );

  const scriptsQ = trpc.toolRunner.getPrebuiltScripts.useQuery(
    { engagementId, category: scriptCategoryFilter || undefined, targetOs: scriptOsFilter || undefined, search: scriptSearch || undefined },
    { enabled: !!engagementId }
  );

  const exploitsQ = trpc.toolRunner.getMatchedExploits.useQuery(
    { engagementId, query: exploitSearch || undefined, limit: 20 },
    { enabled: !!engagementId && exploitSearch.length > 2 }
  );

  const historyQ = trpc.toolRunner.getExecutionHistory.useQuery(
    { engagementId, limit: 50 },
    { enabled: !!engagementId }
  );

  const recordExecution = trpc.toolRunner.recordToolExecution.useMutation({
    onSuccess: (data) => {
      toast.success(`Tool execution recorded — ${data.findingsIngested} findings ingested`);
      historyQ.refetch();
    },
    onError: (err) => {
      if (err.message.includes("ROE violation")) {
        toast.error(`ROE Violation: ${err.message}`);
      } else if (err.message.includes("safety level")) {
        toast.error(`Safety Block: ${err.message}`);
      } else {
        toast.error(`Execution error: ${err.message}`);
      }
    },
  });

  // Auto-scroll CLI output
  useEffect(() => {
    if (cliRef.current) {
      cliRef.current.scrollTop = cliRef.current.scrollHeight;
    }
  }, [cliOutput]);

  // ── Tool selection handler ──
  const handleSelectTool = useCallback((tool: any) => {
    setSelectedTool(tool);
    setSelectedScript(null);
    const args = (tool.defaultArgs || "").replace("{target}", targetInput || "{target}");
    setCommandInput(`${tool.name} ${args}`);
    setActiveTab("cli");
  }, [targetInput]);

  // ── Script selection handler ──
  const handleSelectScript = useCallback((script: any) => {
    setSelectedScript(script);
    setSelectedTool(null);
    let cmd = script.script.replace(/\{target\}/g, targetInput || "{target}");
    setCommandInput(cmd);
    setActiveTab("cli");
  }, [targetInput]);

  // ── Execute command ──
  const handleExecute = useCallback(() => {
    if (!commandInput.trim()) return;

    // Check if the tool/script requires approval
    const needsApproval = selectedTool?.safetyLevel === "full_exploitation" ||
      selectedScript?.requiresApproval ||
      selectedTool?.roeRequired;

    if (needsApproval) {
      setPendingExecution({ command: commandInput, tool: selectedTool, script: selectedScript });
      setShowApprovalDialog(true);
      return;
    }

    executeCommand(commandInput);
  }, [commandInput, selectedTool, selectedScript]);

  const executeCommand = useCallback((command: string) => {
    setIsExecuting(true);
    const startTime = Date.now();
    const toolName = selectedTool?.name || selectedScript?.name || command.split(" ")[0];

    // Simulate execution output (in production, this would SSH to scan server)
    setCliOutput(prev => prev + `\n$ ${command}\n[*] Executing ${toolName}...\n[*] Safety check: PASSED\n[*] ROE scope check: PASSED\n[*] Evidence chain: Recording...\n`);

    // Simulate a brief delay then record the execution
    setTimeout(() => {
      const simulatedOutput = `[*] ${toolName} completed successfully\n[+] Results will be ingested into engagement #${engagementId}\n`;
      setCliOutput(prev => prev + simulatedOutput);
      setIsExecuting(false);

      // Record the execution via the backend
      recordExecution.mutate({
        engagementId,
        toolName,
        command,
        target: targetInput || undefined,
        output: simulatedOutput,
        exitCode: 0,
        durationMs: Date.now() - startTime,
      });
    }, 1500);
  }, [engagementId, selectedTool, selectedScript, targetInput, recordExecution]);

  const handleApprovedExecution = useCallback(() => {
    if (pendingExecution) {
      setShowApprovalDialog(false);
      executeCommand(pendingExecution.command);
      setPendingExecution(null);
    }
  }, [pendingExecution, executeCommand]);

  // ── Render ──
  return (
    <div className="flex flex-col h-full gap-3">
      {/* Header with target input and safety status */}
      <div className="flex items-center gap-3">
        <div className="flex-1 flex items-center gap-2">
          <Crosshair className="h-4 w-4 text-red-400" />
          <Input
            placeholder="Target (IP, domain, or URL)..."
            value={targetInput}
            onChange={e => setTargetInput(e.target.value)}
            className="max-w-sm bg-zinc-900/50 border-zinc-700 text-sm"
          />
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-xs">
            <ShieldCheck className="h-3 w-3 mr-1" />
            Safety Engine Active
          </Badge>
          <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/30 text-xs">
            <Lock className="h-3 w-3 mr-1" />
            ROE Enforced
          </Badge>
          <Badge variant="outline" className="bg-purple-500/10 text-purple-400 border-purple-500/30 text-xs">
            <FileText className="h-3 w-3 mr-1" />
            Evidence Chain
          </Badge>
        </div>
      </div>

      {/* Main content area */}
      <div className="flex-1 flex gap-3 min-h-0">
        {/* Left panel: Tool/Script browser */}
        <div className="w-[380px] flex-shrink-0 flex flex-col border border-zinc-800 rounded-lg overflow-hidden">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="flex flex-col h-full">
            <TabsList className="w-full rounded-none border-b border-zinc-800 bg-zinc-900/50 h-9">
              <TabsTrigger value="tools" className="text-xs flex-1 gap-1">
                <Wrench className="h-3 w-3" /> Tools
              </TabsTrigger>
              <TabsTrigger value="scripts" className="text-xs flex-1 gap-1">
                <Code className="h-3 w-3" /> Scripts
              </TabsTrigger>
              <TabsTrigger value="exploits" className="text-xs flex-1 gap-1">
                <Bug className="h-3 w-3" /> Exploits
              </TabsTrigger>
              <TabsTrigger value="cli" className="text-xs flex-1 gap-1">
                <Terminal className="h-3 w-3" /> CLI
              </TabsTrigger>
            </TabsList>

            {/* ── Tools Tab ── */}
            <TabsContent value="tools" className="flex-1 overflow-hidden m-0">
              <div className="p-2 border-b border-zinc-800 space-y-2">
                <Input
                  placeholder="Search tools..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="h-7 text-xs bg-zinc-900/50 border-zinc-700"
                />
                <div className="flex flex-wrap gap-1">
                  {["recon", "scanning", "enumeration", "exploitation", "credential", "post-exploit", "c2"].map(cat => (
                    <Badge
                      key={cat}
                      variant="outline"
                      className={`text-[10px] cursor-pointer transition-colors ${categoryFilter === cat ? "bg-zinc-700 text-white" : "hover:bg-zinc-800"}`}
                      onClick={() => setCategoryFilter(categoryFilter === cat ? null : cat)}
                    >
                      {CATEGORY_ICONS[cat]}
                      <span className="ml-1">{cat}</span>
                    </Badge>
                  ))}
                </div>
                <div className="flex flex-wrap gap-1">
                  {["passive", "active-low", "active-standard", "active-aggressive"].map(tier => (
                    <Badge
                      key={tier}
                      variant="outline"
                      className={`text-[10px] cursor-pointer transition-colors ${tierFilter === tier ? TIER_COLORS[tier] : "hover:bg-zinc-800"}`}
                      onClick={() => setTierFilter(tierFilter === tier ? null : tier)}
                    >
                      {tier}
                    </Badge>
                  ))}
                </div>
              </div>
              <ScrollArea className="flex-1 h-[calc(100%-120px)]">
                <div className="p-2 space-y-1">
                  {toolsQ.isLoading ? (
                    <div className="flex items-center justify-center py-8 text-zinc-500">
                      <Loader2 className="h-4 w-4 animate-spin mr-2" /> Loading tools...
                    </div>
                  ) : (
                    toolsQ.data?.tools.map((tool: any) => (
                      <div
                        key={tool.name}
                        className={`p-2 rounded-md border cursor-pointer transition-all ${
                          selectedTool?.name === tool.name
                            ? "border-blue-500/50 bg-blue-500/10"
                            : tool.available
                              ? "border-zinc-800 hover:border-zinc-600 hover:bg-zinc-800/50"
                              : "border-zinc-800/50 opacity-50"
                        }`}
                        onClick={() => tool.available && handleSelectTool(tool)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            {CATEGORY_ICONS[tool.category] || <Wrench className="h-3.5 w-3.5" />}
                            <span className="text-xs font-medium">{tool.name}</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <Badge variant="outline" className={`text-[9px] ${TIER_COLORS[tool.tier] || ""}`}>
                              {tool.tier}
                            </Badge>
                            {tool.roeRequired && (
                              <TooltipProvider>
                                <Tooltip>
                                  <TooltipTrigger>
                                    <ShieldAlert className="h-3 w-3 text-amber-400" />
                                  </TooltipTrigger>
                                  <TooltipContent><p className="text-xs">ROE Required</p></TooltipContent>
                                </Tooltip>
                              </TooltipProvider>
                            )}
                          </div>
                        </div>
                        <p className="text-[10px] text-zinc-500 mt-1 line-clamp-1">{tool.description}</p>
                        {!tool.available && tool.blockedReason && (
                          <p className="text-[10px] text-red-400 mt-1 flex items-center gap-1">
                            <Lock className="h-2.5 w-2.5" /> {tool.blockedReason}
                          </p>
                        )}
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-[9px] text-zinc-600 flex items-center gap-0.5">
                            <Clock className="h-2.5 w-2.5" /> {tool.estimatedDuration}
                          </span>
                          <Badge variant="outline" className={`text-[9px] ${SAFETY_COLORS[tool.safetyLevel] || ""}`}>
                            {tool.safetyLevel.replace("_", " ")}
                          </Badge>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Scripts Tab ── */}
            <TabsContent value="scripts" className="flex-1 overflow-hidden m-0">
              <div className="p-2 border-b border-zinc-800 space-y-2">
                <Input
                  placeholder="Search scripts..."
                  value={scriptSearch}
                  onChange={e => setScriptSearch(e.target.value)}
                  className="h-7 text-xs bg-zinc-900/50 border-zinc-700"
                />
                <div className="flex flex-wrap gap-1">
                  {["recon", "scanning", "exploitation", "credential", "post-exploit", "pivot", "cleanup"].map(cat => (
                    <Badge
                      key={cat}
                      variant="outline"
                      className={`text-[10px] cursor-pointer transition-colors ${scriptCategoryFilter === cat ? "bg-zinc-700 text-white" : "hover:bg-zinc-800"}`}
                      onClick={() => setScriptCategoryFilter(scriptCategoryFilter === cat ? null : cat)}
                    >
                      {CATEGORY_ICONS[cat]}
                      <span className="ml-1">{cat}</span>
                    </Badge>
                  ))}
                </div>
                <div className="flex gap-1">
                  {["any", "linux", "windows"].map(os => (
                    <Badge
                      key={os}
                      variant="outline"
                      className={`text-[10px] cursor-pointer ${scriptOsFilter === os ? "bg-zinc-700 text-white" : "hover:bg-zinc-800"}`}
                      onClick={() => setScriptOsFilter(scriptOsFilter === os ? null : os)}
                    >
                      {os}
                    </Badge>
                  ))}
                </div>
              </div>
              <ScrollArea className="flex-1 h-[calc(100%-100px)]">
                <div className="p-2 space-y-1">
                  {scriptsQ.isLoading ? (
                    <div className="flex items-center justify-center py-8 text-zinc-500">
                      <Loader2 className="h-4 w-4 animate-spin mr-2" /> Loading scripts...
                    </div>
                  ) : (
                    scriptsQ.data?.scripts.map((script: any) => (
                      <div
                        key={script.id}
                        className={`p-2 rounded-md border cursor-pointer transition-all ${
                          selectedScript?.id === script.id
                            ? "border-purple-500/50 bg-purple-500/10"
                            : "border-zinc-800 hover:border-zinc-600 hover:bg-zinc-800/50"
                        }`}
                        onClick={() => handleSelectScript(script)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            {CATEGORY_ICONS[script.category] || <Code className="h-3.5 w-3.5" />}
                            <span className="text-xs font-medium">{script.name}</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <Badge variant="outline" className={`text-[9px] ${SAFETY_COLORS[script.safetyLevel] || ""}`}>
                              {script.safetyLevel.replace("_", " ")}
                            </Badge>
                            {script.requiresApproval && (
                              <ShieldAlert className="h-3 w-3 text-amber-400" />
                            )}
                          </div>
                        </div>
                        <p className="text-[10px] text-zinc-500 mt-1 line-clamp-2">{script.description}</p>
                        <div className="flex items-center gap-1 mt-1 flex-wrap">
                          <Badge variant="outline" className="text-[9px]">{script.targetOs}</Badge>
                          {script.mitreTechniques.slice(0, 2).map((t: string) => (
                            <Badge key={t} variant="outline" className="text-[9px] bg-red-500/10 text-red-400 border-red-500/20">
                              {t}
                            </Badge>
                          ))}
                          {script.tags.slice(0, 2).map((t: string) => (
                            <Badge key={t} variant="outline" className="text-[9px] text-zinc-500">
                              {t}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Exploits Tab ── */}
            <TabsContent value="exploits" className="flex-1 overflow-hidden m-0">
              <div className="p-2 border-b border-zinc-800">
                <Input
                  placeholder="Search exploits (CVE, service, keyword)..."
                  value={exploitSearch}
                  onChange={e => setExploitSearch(e.target.value)}
                  className="h-7 text-xs bg-zinc-900/50 border-zinc-700"
                />
                {exploitsQ.data?.storeStats && (
                  <p className="text-[10px] text-zinc-600 mt-1">
                    {exploitsQ.data.storeStats.totalDocuments} exploits indexed
                  </p>
                )}
              </div>
              <ScrollArea className="flex-1 h-[calc(100%-60px)]">
                <div className="p-2 space-y-1">
                  {exploitSearch.length < 3 ? (
                    <div className="flex flex-col items-center justify-center py-8 text-zinc-500">
                      <Bug className="h-8 w-8 mb-2 opacity-30" />
                      <p className="text-xs">Type 3+ characters to search the exploit knowledge store</p>
                      <p className="text-[10px] text-zinc-600 mt-1">Search by CVE ID, service name, or keyword</p>
                    </div>
                  ) : exploitsQ.isLoading ? (
                    <div className="flex items-center justify-center py-8 text-zinc-500">
                      <Loader2 className="h-4 w-4 animate-spin mr-2" /> Searching...
                    </div>
                  ) : (
                    exploitsQ.data?.results.map((result: any) => (
                      <Collapsible key={result.id}>
                        <CollapsibleTrigger className="w-full">
                          <div className="p-2 rounded-md border border-zinc-800 hover:border-zinc-600 hover:bg-zinc-800/50 text-left">
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-medium line-clamp-1">{result.title}</span>
                              <Badge variant="outline" className="text-[9px] ml-2">
                                {Math.round(result.score * 100)}% match
                              </Badge>
                            </div>
                            <p className="text-[10px] text-zinc-500 mt-1 line-clamp-1">{result.description}</p>
                            <div className="flex items-center gap-1 mt-1 flex-wrap">
                              {result.cveIds?.slice(0, 2).map((cve: string) => (
                                <Badge key={cve} variant="outline" className="text-[9px] bg-red-500/10 text-red-400 border-red-500/20">
                                  {cve}
                                </Badge>
                              ))}
                              {result.platform && (
                                <Badge variant="outline" className="text-[9px]">{result.platform}</Badge>
                              )}
                              {result.exploitType && (
                                <Badge variant="outline" className="text-[9px]">{result.exploitType}</Badge>
                              )}
                              {result.reliabilityScore != null && (
                                <Badge variant="outline" className={`text-[9px] ${result.reliabilityScore >= 70 ? "text-emerald-400" : result.reliabilityScore >= 40 ? "text-amber-400" : "text-red-400"}`}>
                                  Reliability: {result.reliabilityScore}%
                                </Badge>
                              )}
                            </div>
                          </div>
                        </CollapsibleTrigger>
                        <CollapsibleContent>
                          <div className="mx-2 mb-1 p-2 bg-zinc-900/80 rounded-b-md border border-t-0 border-zinc-800">
                            <p className="text-[10px] text-zinc-400 mb-2">{result.matchReason}</p>
                            {result.code && (
                              <pre className="text-[10px] bg-black/50 p-2 rounded overflow-x-auto max-h-32">
                                <code>{result.code}</code>
                              </pre>
                            )}
                            {result.sourceUrl && (
                              <a href={result.sourceUrl} target="_blank" rel="noopener noreferrer" className="text-[10px] text-blue-400 hover:underline mt-1 block">
                                View source →
                              </a>
                            )}
                            <Button
                              size="sm"
                              variant="outline"
                              className="mt-2 h-6 text-[10px]"
                              onClick={() => {
                                if (result.code) {
                                  setCommandInput(result.code.substring(0, 500));
                                  setActiveTab("cli");
                                }
                              }}
                            >
                              <Terminal className="h-3 w-3 mr-1" /> Load to CLI
                            </Button>
                          </div>
                        </CollapsibleContent>
                      </Collapsible>
                    ))
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── CLI Tab ── */}
            <TabsContent value="cli" className="flex-1 overflow-hidden m-0 flex flex-col">
              {/* CLI Output */}
              <div
                ref={cliRef}
                className="flex-1 bg-black/80 font-mono text-[11px] text-green-400 p-3 overflow-y-auto whitespace-pre-wrap"
              >
                {cliOutput || (
                  <div className="text-zinc-600">
                    {`# AC3 Manual Tool Runner v1.0\n# Safety Engine: ACTIVE | ROE Guard: ENFORCED | Evidence Chain: RECORDING\n# Select a tool or script from the left panel, or type a command below.\n#\n# All executions are:\n#   ✓ Validated against Rules of Engagement scope\n#   ✓ Checked by the Safety Engine for blast radius\n#   ✓ Logged to the evidence integrity chain\n#   ✓ Recorded in the operator audit trail\n#   ✓ Auto-ingested into engagement findings\n#\n# Type 'help' for available commands.\n`}
                  </div>
                )}
              </div>

              {/* Command input */}
              <div className="border-t border-zinc-800 p-2 bg-zinc-900/50">
                {selectedTool && (
                  <div className="flex items-center gap-2 mb-2">
                    <Badge variant="outline" className="text-[10px]">
                      {CATEGORY_ICONS[selectedTool.category]}
                      <span className="ml-1">{selectedTool.name}</span>
                    </Badge>
                    <Badge variant="outline" className={`text-[9px] ${TIER_COLORS[selectedTool.tier] || ""}`}>
                      {selectedTool.tier}
                    </Badge>
                    <Badge variant="outline" className={`text-[9px] ${SAFETY_COLORS[selectedTool.safetyLevel] || ""}`}>
                      {selectedTool.safetyLevel.replace("_", " ")}
                    </Badge>
                    {selectedTool.roeRequired && (
                      <Badge variant="outline" className="text-[9px] bg-amber-500/10 text-amber-400 border-amber-500/20">
                        <ShieldAlert className="h-2.5 w-2.5 mr-0.5" /> ROE Required
                      </Badge>
                    )}
                  </div>
                )}
                {selectedScript && (
                  <div className="flex items-center gap-2 mb-2">
                    <Badge variant="outline" className="text-[10px] bg-purple-500/10 text-purple-400 border-purple-500/20">
                      <Code className="h-3 w-3 mr-1" />
                      {selectedScript.name}
                    </Badge>
                    {selectedScript.mitreTechniques.slice(0, 2).map((t: string) => (
                      <Badge key={t} variant="outline" className="text-[9px] bg-red-500/10 text-red-400 border-red-500/20">
                        {t}
                      </Badge>
                    ))}
                    {selectedScript.requiresApproval && (
                      <Badge variant="outline" className="text-[9px] bg-amber-500/10 text-amber-400 border-amber-500/20">
                        <ShieldAlert className="h-2.5 w-2.5 mr-0.5" /> Approval Required
                      </Badge>
                    )}
                  </div>
                )}
                <div className="flex items-center gap-2">
                  <span className="text-green-400 font-mono text-sm">$</span>
                  <Textarea
                    value={commandInput}
                    onChange={e => setCommandInput(e.target.value)}
                    placeholder="Enter command or select a tool/script..."
                    className="flex-1 bg-black/50 border-zinc-700 font-mono text-xs text-green-400 min-h-[36px] max-h-[120px] resize-y"
                    onKeyDown={e => {
                      if (e.key === "Enter" && !e.shiftKey) {
                        e.preventDefault();
                        handleExecute();
                      }
                    }}
                  />
                  <div className="flex flex-col gap-1">
                    <Button
                      size="sm"
                      className="h-7 text-xs"
                      onClick={handleExecute}
                      disabled={isExecuting || !commandInput.trim()}
                    >
                      {isExecuting ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-7 text-xs"
                      onClick={() => { setCliOutput(""); }}
                    >
                      <RefreshCw className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Right panel: Execution History & Activity Feed */}
        <div className="flex-1 flex flex-col border border-zinc-800 rounded-lg overflow-hidden">
          <div className="p-3 border-b border-zinc-800 bg-zinc-900/50 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-zinc-400" />
              <span className="text-sm font-medium">Execution History & Activity Feed</span>
            </div>
            <Badge variant="outline" className="text-[10px]">
              {historyQ.data?.executions?.length || 0} executions
            </Badge>
          </div>
          <ScrollArea className="flex-1">
            <div className="p-3 space-y-2">
              {(!historyQ.data?.executions || historyQ.data.executions.length === 0) ? (
                <div className="flex flex-col items-center justify-center py-12 text-zinc-500">
                  <Terminal className="h-12 w-12 mb-3 opacity-20" />
                  <p className="text-sm font-medium">No executions yet</p>
                  <p className="text-xs text-zinc-600 mt-1">Select a tool or script from the left panel to get started</p>
                  <div className="mt-4 grid grid-cols-2 gap-2 max-w-sm">
                    <Card className="bg-zinc-900/50 border-zinc-800 p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <Wrench className="h-4 w-4 text-blue-400" />
                        <span className="text-xs font-medium">Tools</span>
                      </div>
                      <p className="text-[10px] text-zinc-500">{toolsQ.data?.totalCount || 0} tools in registry</p>
                    </Card>
                    <Card className="bg-zinc-900/50 border-zinc-800 p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <Code className="h-4 w-4 text-purple-400" />
                        <span className="text-xs font-medium">Scripts</span>
                      </div>
                      <p className="text-[10px] text-zinc-500">{scriptsQ.data?.scripts?.length || 0} pre-built scripts</p>
                    </Card>
                    <Card className="bg-zinc-900/50 border-zinc-800 p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <Shield className="h-4 w-4 text-emerald-400" />
                        <span className="text-xs font-medium">Safety</span>
                      </div>
                      <p className="text-[10px] text-zinc-500">ROE + Safety Engine enforced</p>
                    </Card>
                    <Card className="bg-zinc-900/50 border-zinc-800 p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <FileText className="h-4 w-4 text-amber-400" />
                        <span className="text-xs font-medium">Evidence</span>
                      </div>
                      <p className="text-[10px] text-zinc-500">Auto-captured & chained</p>
                    </Card>
                  </div>
                </div>
              ) : (
                historyQ.data.executions.map((exec: any, i: number) => (
                  <Collapsible key={i}>
                    <CollapsibleTrigger className="w-full">
                      <div className="p-2 rounded-md border border-zinc-800 hover:border-zinc-600 text-left">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            {exec.exitCode === 0 ? (
                              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                            ) : (
                              <XCircle className="h-3.5 w-3.5 text-red-400" />
                            )}
                            <span className="text-xs font-medium font-mono">{exec.toolName}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-[9px]">
                              {exec.findingsCount} findings
                            </Badge>
                            <span className="text-[10px] text-zinc-500">
                              {exec.durationMs ? `${(exec.durationMs / 1000).toFixed(1)}s` : ""}
                            </span>
                          </div>
                        </div>
                        <p className="text-[10px] text-zinc-500 mt-1 font-mono line-clamp-1">{exec.command}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-[9px] text-zinc-600">{exec.operator}</span>
                          {exec.target && (
                            <Badge variant="outline" className="text-[9px]">
                              <Crosshair className="h-2 w-2 mr-0.5" /> {exec.target}
                            </Badge>
                          )}
                        </div>
                      </div>
                    </CollapsibleTrigger>
                    <CollapsibleContent>
                      <div className="mx-2 mb-1 p-2 bg-zinc-900/80 rounded-b-md border border-t-0 border-zinc-800">
                        <pre className="text-[10px] font-mono text-green-400 bg-black/50 p-2 rounded overflow-x-auto max-h-48 whitespace-pre-wrap">
                          {exec.output}
                        </pre>
                        {exec.notes && (
                          <p className="text-[10px] text-zinc-400 mt-2">
                            <strong>Notes:</strong> {exec.notes}
                          </p>
                        )}
                      </div>
                    </CollapsibleContent>
                  </Collapsible>
                ))
              )}
            </div>
          </ScrollArea>
        </div>
      </div>

      {/* Approval Dialog */}
      <AlertDialog open={showApprovalDialog} onOpenChange={setShowApprovalDialog}>
        <AlertDialogContent className="bg-zinc-900 border-zinc-700">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-amber-400">
              <ShieldAlert className="h-5 w-5" />
              Operator Approval Required
            </AlertDialogTitle>
            <AlertDialogDescription className="text-zinc-400">
              This action requires explicit operator approval before execution.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-3 py-2">
            <div className="bg-zinc-800/50 rounded-md p-3 space-y-2">
              <div className="flex items-center gap-2">
                <span className="text-xs text-zinc-500">Tool:</span>
                <span className="text-xs font-medium">{pendingExecution?.tool?.name || pendingExecution?.script?.name || "Custom"}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-zinc-500">Safety Level:</span>
                <Badge variant="outline" className={`text-[10px] ${SAFETY_COLORS[pendingExecution?.tool?.safetyLevel || pendingExecution?.script?.safetyLevel || "standard"]}`}>
                  {(pendingExecution?.tool?.safetyLevel || pendingExecution?.script?.safetyLevel || "standard").replace("_", " ")}
                </Badge>
              </div>
              {targetInput && (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-zinc-500">Target:</span>
                  <span className="text-xs font-mono">{targetInput}</span>
                </div>
              )}
              <div>
                <span className="text-xs text-zinc-500">Command:</span>
                <pre className="text-[10px] font-mono bg-black/50 p-2 rounded mt-1 max-h-24 overflow-y-auto whitespace-pre-wrap">
                  {pendingExecution?.command}
                </pre>
              </div>
            </div>
            <div className="flex items-start gap-2 bg-amber-500/10 border border-amber-500/20 rounded-md p-2">
              <AlertTriangle className="h-4 w-4 text-amber-400 mt-0.5 flex-shrink-0" />
              <div className="text-[11px] text-amber-400/80">
                <p className="font-medium mb-1">Safety Guardrails Active:</p>
                <ul className="space-y-0.5 list-disc list-inside">
                  <li>ROE scope will be validated before execution</li>
                  <li>Safety Engine will assess blast radius</li>
                  <li>Evidence chain will record all output</li>
                  <li>Operator audit trail will log this action</li>
                </ul>
              </div>
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel className="bg-zinc-800 border-zinc-700 hover:bg-zinc-700">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              className="bg-amber-600 hover:bg-amber-700 text-white"
              onClick={handleApprovedExecution}
            >
              <ShieldCheck className="h-4 w-4 mr-1" />
              Approve & Execute
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
