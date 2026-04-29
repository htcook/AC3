/**
 * Bug Bounty Workspace
 * 
 * Full-featured workspace for bug bounty research: paste a program URL, parse scope/policy,
 * document findings, check originality, and format submissions per platform.
 */

import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Bug, Globe, Shield, Target, FileText, Check, X, AlertTriangle,
  Search, Copy, ExternalLink, Sparkles, CheckCircle2, XCircle,
  Clock, Zap, Eye, Send, ArrowRight, Loader2, Info, ChevronDown,
  ChevronRight, Crosshair, Link2, AlertCircle, FileCheck, Clipboard,
  Download, Layers, RefreshCw, Upload, List, Plus, GitBranch, Wrench, Server,
} from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface PolicyROE {
  programName: string;
  platform: string;
  programUrl: string;
  scope: { inScope: ScopeEntry[]; outOfScope: ScopeEntry[] };
  rules: string[];
  rewardRange?: { low: number; high: number; currency: string };
  safeHarbor: boolean;
  responseTimeSla?: { firstResponse: string; triage: string; bountyDecision: string };
  parsedAt: string;
}

interface ScopeEntry {
  type: string;
  value: string;
  eligible: boolean;
  notes?: string;
}

interface ScopeCheckResult {
  target: string;
  inScope: boolean;
  matchedRule?: string;
  reason: string;
}

interface OriginalityResult {
  isOriginal: boolean;
  confidence: number;
  matchedPatterns: string[];
  recommendation: string;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  target: string;
  description: string;
  stepsToReproduce: string;
  impact: string;
  cweId?: string;
  cvssScore?: number;
}

// ─── Component ─────────────────────────────────────────────────────────────────

export default function BugBountyWorkspace() {
  const [activeTab, setActiveTab] = useState('program');
  const [programUrl, setProgramUrl] = useState('');
  const [policy, setPolicy] = useState<PolicyROE | null>(null);
  const [isParsing, setIsParsing] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedPlatform, setSelectedPlatform] = useState('hackerone');
  const [engagementIdInput, setEngagementIdInput] = useState('');
  const [importedFindings, setImportedFindings] = useState<any[]>([]);
  const [parsedPrograms, setParsedPrograms] = useState<Array<{ url: string; policy: PolicyROE }>>([]);
  const [batchUrls, setBatchUrls] = useState('');
  const [isBatchParsing, setIsBatchParsing] = useState(false);

  // tRPC mutations
  const parsePolicy = trpc.vaBugBounty.parseBugBountyPolicy.useMutation();
  const checkScope = trpc.vaBugBounty.checkScope.useMutation();
  const checkOriginality = trpc.vaBugBounty.checkOriginality.useMutation();
  const importEngagementFindings = trpc.vaBugBounty.listEngagementFindingsForBounty.useMutation();
  const refreshPolicy = trpc.vaBugBounty.refreshBugBountyPolicy.useMutation();
  const syncScopeToEngagement = trpc.vaBugBounty.syncScopeToEngagement.useMutation();
  const refreshAllScopes = trpc.vaBugBounty.refreshAllScopes.useMutation();
  const activeEngagements = trpc.vaBugBounty.listActiveEngagements.useQuery();
  const createEngagementFromScope = trpc.vaBugBounty.createEngagementFromScope.useMutation();
  const [isCreatingEngagement, setIsCreatingEngagement] = useState(false);

  const handleImportFromEngagement = async () => {
    const id = parseInt(engagementIdInput);
    if (isNaN(id) || id <= 0) return;
    try {
      const result = await importEngagementFindings.mutateAsync({ engagementId: id });
      setImportedFindings(result.findings || []);
      toast.success(`Imported ${result.findings.length} findings from engagement #${id}`, {
        description: `${result.totalAssets} assets analyzed`,
      });
    } catch (err: any) {
      toast.error('Failed to import findings', { description: err.message });
    }
  };

  const adoptImportedFinding = (imported: any) => {
    const newFinding: Finding = {
      id: `imported-${imported.id || Date.now()}`,
      title: imported.title || 'Imported Finding',
      severity: imported.severity || 'medium',
      target: imported.target || 'unknown',
      description: imported.description || '',
      stepsToReproduce: imported.reproductionSteps?.map((s: any) => `${s.stepNumber}. ${s.action}`).join('\n') || 'Imported from engagement scan — add reproduction steps.',
      impact: imported.impactAnalysis?.technicalImpact || imported.description || '',
      cweId: imported.cweIds?.[0],
    };
    setFindings(prev => [...prev, newFinding]);
    toast.success(`Adopted: ${newFinding.title}`);
  };

  const handleParseProgram = async () => {
    if (!programUrl.trim()) return;
    setIsParsing(true);
    try {
      const result = await parsePolicy.mutateAsync({ programUrl: programUrl.trim() });
      const pol = result as unknown as PolicyROE;
      setPolicy(pol);
      setSelectedPlatform(result.platform || 'hackerone');
      // Track parsed programs for batch refresh
      setParsedPrograms(prev => {
        const existing = prev.findIndex(p => p.url === programUrl.trim());
        if (existing >= 0) {
          const updated = [...prev];
          updated[existing] = { url: programUrl.trim(), policy: pol };
          return updated;
        }
        return [...prev, { url: programUrl.trim(), policy: pol }];
      });
      toast.success('Program parsed successfully', {
        description: `${result.programName} — ${result.scope.inScope.length} in-scope targets`,
      });
      // Notify about auto-created engagement
      const autoEng = (result as any).autoEngagement;
      if (autoEng?.created) {
        toast.success('Engagement auto-created', {
          description: `${autoEng.engagementName || 'New engagement'} — ${autoEng.totalAssetsAdded} assets added`,
          action: {
            label: 'View',
            onClick: () => window.location.href = `/engagements/${autoEng.engagementId}`,
          },
          duration: 8000,
        });
      } else if (autoEng && !autoEng.created && autoEng.engagementId) {
        toast.info('Engagement already exists', {
          description: `Engagement #${autoEng.engagementId} already covers this program`,
          action: {
            label: 'View',
            onClick: () => window.location.href = `/engagements/${autoEng.engagementId}`,
          },
        });
      }
      setActiveTab('scope');
    } catch (err: any) {
      toast.error('Failed to parse program', { description: err.message });
    } finally {
      setIsParsing(false);
    }
  };

  const handleBatchParse = async () => {
    const urls = batchUrls.split('\n').map(u => u.trim()).filter(Boolean);
    if (urls.length === 0) return;
    setIsBatchParsing(true);
    let successCount = 0;
    let errorCount = 0;
    let engagementsCreated = 0;
    for (const url of urls) {
      try {
        const result = await parsePolicy.mutateAsync({ programUrl: url });
        const pol = result as unknown as PolicyROE;
        setParsedPrograms(prev => {
          const existing = prev.findIndex(p => p.url === url);
          if (existing >= 0) {
            const updated = [...prev];
            updated[existing] = { url, policy: pol };
            return updated;
          }
          return [...prev, { url, policy: pol }];
        });
        // Set the last successful one as the active policy
        setPolicy(pol);
        setSelectedPlatform(result.platform || 'hackerone');
        successCount++;
        // Track auto-engagement creation
        const autoEng = (result as any).autoEngagement;
        if (autoEng?.created) engagementsCreated++;
      } catch {
        errorCount++;
      }
    }
    setIsBatchParsing(false);
    toast.success(`Batch parse complete`, {
      description: `${successCount} succeeded, ${errorCount} failed out of ${urls.length} programs${engagementsCreated > 0 ? `. ${engagementsCreated} engagement(s) auto-created.` : ''}`,
    });
    if (engagementsCreated > 0) {
      toast.success(`${engagementsCreated} engagement(s) auto-created`, {
        description: 'Engagements were automatically created for programs with sufficient scope data.',
        duration: 6000,
      });
    }
    if (successCount > 0) setActiveTab('scope');
  };

  const handleRefreshAll = async () => {
    const urls = parsedPrograms.map(p => p.url);
    if (urls.length === 0) {
      toast.error('No programs to refresh');
      return;
    }
    setIsBatchParsing(true);
    try {
      const result = await refreshAllScopes.mutateAsync({ programUrls: urls });
      // Update parsed programs with fresh data from cache
      for (const r of result.results) {
        if (r.status === 'success') {
          // Re-fetch the individual policy to get full data
          try {
            const fresh = await parsePolicy.mutateAsync({ programUrl: r.programUrl });
            const pol = fresh as unknown as PolicyROE;
            setParsedPrograms(prev => {
              const idx = prev.findIndex(p => p.url === r.programUrl);
              if (idx >= 0) {
                const updated = [...prev];
                updated[idx] = { url: r.programUrl, policy: pol };
                return updated;
              }
              return prev;
            });
            // Update active policy if it matches
            if (policy?.programUrl === r.programUrl) setPolicy(pol);
          } catch { /* cache was already refreshed, just couldn't re-read */ }
        }
      }
      toast.success(`Refreshed ${result.successCount} of ${result.total} programs`, {
        description: result.errorCount > 0 ? `${result.errorCount} failed` : 'All scopes up to date',
      });
    } catch (err: any) {
      toast.error('Batch refresh failed', { description: err.message });
    } finally {
      setIsBatchParsing(false);
    }
  };

  const handleRefreshScope = async () => {
    if (!policy?.programUrl) return;
    setIsParsing(true);
    try {
      const result = await refreshPolicy.mutateAsync({ programUrl: policy.programUrl });
      const pol = result as unknown as PolicyROE;
      setPolicy(pol);
      // Update in parsedPrograms too
      setParsedPrograms(prev => {
        const idx = prev.findIndex(p => p.url === policy.programUrl);
        if (idx >= 0) {
          const updated = [...prev];
          updated[idx] = { url: policy.programUrl, policy: pol };
          return updated;
        }
        return prev;
      });
      toast.success('Scope refreshed', {
        description: `${result.programName} — ${result.scope.inScope.length} in-scope targets (fresh data)`,
      });
    } catch (err: any) {
      toast.error('Failed to refresh scope', { description: err.message });
    } finally {
      setIsParsing(false);
    }
  };

  const handleSyncToEngagement = async (engagementId: number) => {
    if (!policy) return;
    try {
      const result = await syncScopeToEngagement.mutateAsync({
        engagementId,
        inScopeTargets: policy.scope.inScope,
        programName: policy.programName,
        programUrl: policy.programUrl,
        platform: policy.platform,
      });
      toast.success(`Synced to Engagement #${engagementId}`, {
        description: `${result.totalDomainsAdded} domains + ${result.totalIpsAdded} IPs added (${result.totalTargets} total targets)${result.skippedTypes > 0 ? ` — ${result.skippedTypes} non-network targets skipped` : ''}`,
      });
    } catch (err: any) {
      toast.error('Failed to sync scope', { description: err.message });
    }
  };

  const handleCreateNewEngagement = async () => {
    if (!policy) return;
    setIsCreatingEngagement(true);
    try {
      const result = await createEngagementFromScope.mutateAsync({
        programName: policy.programName,
        programUrl: policy.programUrl,
        platform: policy.platform,
        inScopeTargets: policy.scope.inScope,
        outOfScopeTargets: policy.scope.outOfScope,
        rules: policy.rules,
        rewardRange: policy.rewardRange,
        safeHarbor: policy.safeHarbor,
      });
      if (result.created && result.engagementId) {
        toast.success(`Engagement Created: ${result.engagementName || 'New Engagement'}`, {
          description: `#${result.engagementId} — ${result.totalAssetsAdded} assets added (including build requirements)`,
          action: {
            label: 'View',
            onClick: () => window.location.href = `/engagements/${result.engagementId}`,
          },
        });
        activeEngagements.refetch();
      } else {
        toast.info('Engagement not created', { description: result.reason || 'Unknown reason' });
      }
    } catch (err: any) {
      toast.error('Failed to create engagement', { description: err.message });
    } finally {
      setIsCreatingEngagement(false);
    }
  };

  return (
    <div className="min-h-screen p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 rounded-lg bg-orange-500/10 border border-orange-500/20">
            <Bug className="h-5 w-5 text-orange-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Bug Bounty Workspace</h1>
            <p className="text-sm text-muted-foreground">
              Parse program policies, verify scope, document findings, check originality, and format platform-ready submissions.
            </p>
          </div>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="mb-6">
          <TabsTrigger value="program" className="gap-1.5">
            <Globe className="h-3.5 w-3.5" />
            Program
          </TabsTrigger>
          <TabsTrigger value="scope" className="gap-1.5" disabled={!policy}>
            <Target className="h-3.5 w-3.5" />
            Scope
          </TabsTrigger>
          <TabsTrigger value="findings" className="gap-1.5" disabled={!policy}>
            <Search className="h-3.5 w-3.5" />
            Findings
          </TabsTrigger>
          <TabsTrigger value="originality" className="gap-1.5" disabled={!policy || findings.length === 0}>
            <Sparkles className="h-3.5 w-3.5" />
            Originality
          </TabsTrigger>
          <TabsTrigger value="submit" className="gap-1.5" disabled={!policy || findings.length === 0}>
            <Send className="h-3.5 w-3.5" />
            Submit
          </TabsTrigger>
          <TabsTrigger value="import" className="gap-1.5">
            <Download className="h-3.5 w-3.5" />
            Import
          </TabsTrigger>
        </TabsList>

        {/* Tab: Program Parser */}
        <TabsContent value="program">
          <ProgramTab
            programUrl={programUrl}
            onUrlChange={setProgramUrl}
            onParse={handleParseProgram}
            isParsing={isParsing}
            policy={policy}
            batchUrls={batchUrls}
            onBatchUrlsChange={setBatchUrls}
            onBatchParse={handleBatchParse}
            isBatchParsing={isBatchParsing}
            parsedPrograms={parsedPrograms}
            onSelectProgram={(p) => { setPolicy(p.policy); setSelectedPlatform(p.policy.platform); setProgramUrl(p.url); }}
          />
        </TabsContent>

        {/* Tab: Scope Checker */}
        <TabsContent value="scope">
          {policy && (
            <ScopeTab
              policy={policy}
              checkScope={checkScope}
              onRefresh={handleRefreshScope}
              isRefreshing={isParsing}
              onSyncToEngagement={handleSyncToEngagement}
              isSyncing={syncScopeToEngagement.isPending}
              engagements={activeEngagements.data || []}
              parsedProgramCount={parsedPrograms.length}
              onRefreshAll={handleRefreshAll}
              isBatchRefreshing={isBatchParsing}
              onCreateNewEngagement={handleCreateNewEngagement}
              isCreatingEngagement={isCreatingEngagement}
            />
          )}
        </TabsContent>

        {/* Tab: Finding Documenter */}
        <TabsContent value="findings">
          {policy && (
            <FindingsTab
              findings={findings}
              onFindingsChange={setFindings}
              policy={policy}
            />
          )}
        </TabsContent>

        {/* Tab: Originality Checker */}
        <TabsContent value="originality">
          {policy && findings.length > 0 && (
            <OriginalityTab findings={findings} checkOriginality={checkOriginality} />
          )}
        </TabsContent>

        {/* Tab: Submission Formatter */}
        <TabsContent value="submit">
          {policy && findings.length > 0 && (
            <SubmitTab
              findings={findings}
              policy={policy}
              platform={selectedPlatform}
              onPlatformChange={setSelectedPlatform}
            />
          )}
        </TabsContent>
        {/* Tab: Import from Engagement */}
        <TabsContent value="import">
          <ImportFromEngagementTab
            engagementIdInput={engagementIdInput}
            onEngagementIdChange={setEngagementIdInput}
            onImport={handleImportFromEngagement}
            isImporting={importEngagementFindings.isPending}
            importedFindings={importedFindings}
            onAdopt={adoptImportedFinding}
            existingFindingIds={new Set(findings.map(f => f.id))}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─── Tab: Program Parser ───────────────────────────────────────────────────────

function ProgramTab({
  programUrl,
  onUrlChange,
  onParse,
  isParsing,
  policy,
  batchUrls,
  onBatchUrlsChange,
  onBatchParse,
  isBatchParsing,
  parsedPrograms,
  onSelectProgram,
}: {
  programUrl: string;
  onUrlChange: (v: string) => void;
  onParse: () => void;
  isParsing: boolean;
  policy: PolicyROE | null;
  batchUrls: string;
  onBatchUrlsChange: (v: string) => void;
  onBatchParse: () => void;
  isBatchParsing: boolean;
  parsedPrograms: Array<{ url: string; policy: PolicyROE }>;
  onSelectProgram: (p: { url: string; policy: PolicyROE }) => void;
}) {
  const [showBatch, setShowBatch] = useState(false);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Globe className="h-4 w-4 text-orange-400" />
            Parse Bug Bounty Program
          </CardTitle>
          <CardDescription>
            Paste a program URL from HackerOne, Bugcrowd, Intigriti, YesWeHack, or OpenBugBounty. The parser extracts scope, rules, reward ranges, and SLA timelines.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Single URL input */}
          <div className="flex gap-2">
            <Input
              placeholder="https://hackerone.com/your-program, https://bugcrowd.com/engagements/your-program, or https://intigriti.com/programs/..."
              value={programUrl}
              onChange={e => onUrlChange(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && onParse()}
              className="flex-1"
            />
            <Button onClick={onParse} disabled={isParsing || !programUrl.trim()} className="gap-2 bg-orange-600 hover:bg-orange-700">
              {isParsing ? (
                <><Loader2 className="h-4 w-4 animate-spin" />Parsing...</>
              ) : (
                <><Search className="h-4 w-4" />Parse</>
              )}
            </Button>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex flex-wrap gap-2">
              {['HackerOne', 'Bugcrowd', 'Intigriti', 'YesWeHack', 'OpenBugBounty', 'Synack', 'Custom'].map(p => (
                <Badge key={p} variant="outline" className="text-[10px]">{p}</Badge>
              ))}
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowBatch(!showBatch)}
              className="gap-1.5 text-xs text-muted-foreground"
            >
              <List className="h-3.5 w-3.5" />
              {showBatch ? 'Hide' : 'Batch'} Parse
            </Button>
          </div>

          {/* Batch URL input */}
          {showBatch && (
            <div className="space-y-3 border-t pt-3">
              <Label className="text-xs text-muted-foreground">Paste multiple program URLs (one per line)</Label>
              <Textarea
                placeholder={"https://hackerone.com/nodejs\nhttps://bugcrowd.com/engagements/tidal-bugbounty\nhttps://www.intigriti.com/programs/amd/amd/detail"}
                value={batchUrls}
                onChange={e => onBatchUrlsChange(e.target.value)}
                rows={5}
                className="font-mono text-xs"
              />
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-muted-foreground">
                  {batchUrls.split('\n').filter(u => u.trim()).length} URLs
                </span>
                <Button
                  onClick={onBatchParse}
                  disabled={isBatchParsing || !batchUrls.trim()}
                  size="sm"
                  className="gap-2 bg-orange-600 hover:bg-orange-700"
                >
                  {isBatchParsing ? (
                    <><Loader2 className="h-3.5 w-3.5 animate-spin" />Parsing All...</>
                  ) : (
                    <><Layers className="h-3.5 w-3.5" />Parse All</>
                  )}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Parsed Programs List */}
      {parsedPrograms.length > 1 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <List className="h-4 w-4 text-orange-400" />
              Parsed Programs ({parsedPrograms.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {parsedPrograms.map((p, i) => (
                <button
                  key={i}
                  onClick={() => onSelectProgram(p)}
                  className={`w-full flex items-center justify-between p-2.5 rounded-md border text-left transition-colors hover:bg-accent/50 ${
                    policy?.programUrl === p.url ? 'border-orange-500/50 bg-orange-500/5' : 'border-border'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <Badge variant="secondary" className="text-[10px] shrink-0">{p.policy.platform}</Badge>
                    <span className="text-sm font-medium truncate">{p.policy.programName}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] text-muted-foreground">
                      {p.policy.scope.inScope.length} in-scope
                    </span>
                    {p.policy.rewardRange && (
                      <Badge className="text-[10px] bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                        {p.policy.rewardRange.currency}{p.policy.rewardRange.high.toLocaleString()}
                      </Badge>
                    )}
                    <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Parsed Policy Summary */}
      {policy && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="h-4 w-4 text-orange-400" />
                <span className="text-sm font-medium">Program Info</span>
              </div>
              <div className="space-y-2 text-xs">
                <div><span className="text-muted-foreground">Name:</span> <span className="font-medium">{policy.programName}</span></div>
                <div><span className="text-muted-foreground">Platform:</span> <Badge variant="secondary" className="text-[10px] ml-1">{policy.platform}</Badge></div>
                <div className="flex items-center gap-1">
                  <span className="text-muted-foreground">Safe Harbor:</span>
                  {policy.safeHarbor ? (
                    <Badge className="text-[10px] bg-emerald-500/10 text-emerald-400 border-emerald-500/30">Yes</Badge>
                  ) : (
                    <Badge className="text-[10px] bg-amber-500/10 text-amber-400 border-amber-500/30">No</Badge>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center gap-2 mb-3">
                <Target className="h-4 w-4 text-orange-400" />
                <span className="text-sm font-medium">Scope</span>
              </div>
              <div className="space-y-2 text-xs">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                  <span>{policy.scope.inScope.length} in-scope targets</span>
                </div>
                <div className="flex items-center gap-2">
                  <XCircle className="h-3 w-3 text-red-400" />
                  <span>{policy.scope.outOfScope.length} out-of-scope exclusions</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center gap-2 mb-3">
                <Zap className="h-4 w-4 text-orange-400" />
                <span className="text-sm font-medium">Rewards</span>
              </div>
              {policy.rewardRange ? (
                <div className="text-xs">
                  <span className="text-2xl font-bold text-orange-400">
                    {policy.rewardRange.currency}{policy.rewardRange.low.toLocaleString()}
                  </span>
                  <span className="text-muted-foreground"> — </span>
                  <span className="text-2xl font-bold text-orange-400">
                    {policy.rewardRange.currency}{policy.rewardRange.high.toLocaleString()}
                  </span>
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">No reward range specified</p>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Rules */}
      {policy && policy.rules.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <FileText className="h-4 w-4 text-orange-400" />
              Program Rules ({policy.rules.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-48">
              <div className="space-y-2">
                {policy.rules.map((rule, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <AlertCircle className="h-3 w-3 text-muted-foreground mt-0.5 flex-shrink-0" />
                    <span>{rule}</span>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      {/* SLA */}
      {policy?.responseTimeSla && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Clock className="h-4 w-4 text-orange-400" />
              Response SLA
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4">
              {Object.entries(policy.responseTimeSla).map(([key, val]) => (
                <div key={key} className="text-center">
                  <p className="text-lg font-bold text-orange-400">{val}</p>
                  <p className="text-[10px] text-muted-foreground capitalize">{key.replace(/([A-Z])/g, ' $1')}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Tab: Scope Checker ────────────────────────────────────────────────────────

function ScopeTab({
  policy,
  checkScope,
  onRefresh,
  isRefreshing,
  onSyncToEngagement,
  isSyncing,
  engagements,
  parsedProgramCount,
  onRefreshAll,
  isBatchRefreshing,
  onCreateNewEngagement,
  isCreatingEngagement,
}: {
  policy: PolicyROE;
  checkScope: any;
  onRefresh: () => void;
  isRefreshing: boolean;
  onSyncToEngagement: (engagementId: number) => void;
  isSyncing: boolean;
  engagements: Array<{ id: number; name: string; engagementType: string; status: string }>;
  parsedProgramCount: number;
  onRefreshAll: () => void;
  isBatchRefreshing: boolean;
  onCreateNewEngagement: () => void;
  isCreatingEngagement: boolean;
}) {
  const [targetToCheck, setTargetToCheck] = useState('');
  const [scopeResults, setScopeResults] = useState<ScopeCheckResult[]>([]);
  const [isChecking, setIsChecking] = useState(false);
  const [showSyncDialog, setShowSyncDialog] = useState(false);

  const handleCheck = async () => {
    if (!targetToCheck.trim()) return;
    setIsChecking(true);
    try {
      const result = await checkScope.mutateAsync({
        target: targetToCheck.trim(),
        policy: policy as any,
      });
      setScopeResults(prev => [result as ScopeCheckResult, ...prev]);
      setTargetToCheck('');
    } catch (err: any) {
      toast.error('Scope check failed', { description: err.message });
    } finally {
      setIsChecking(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Action Bar: Refresh + Sync to Engagement */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={onRefresh}
            disabled={isRefreshing}
            className="gap-1.5"
          >
            {isRefreshing ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}
            Refresh Scope
          </Button>
          {parsedProgramCount > 1 && (
            <Button
              variant="outline"
              size="sm"
              onClick={onRefreshAll}
              disabled={isBatchRefreshing}
              className="gap-1.5"
            >
              {isBatchRefreshing ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Layers className="h-3.5 w-3.5" />
              )}
              Refresh All ({parsedProgramCount})
            </Button>
          )}
          {policy.parsedAt && (
            <span className="text-[10px] text-muted-foreground">
              Last fetched: {new Date(policy.parsedAt).toLocaleString()}
            </span>
          )}
        </div>
        <Dialog open={showSyncDialog} onOpenChange={setShowSyncDialog}>
          <DialogTrigger asChild>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5"
              disabled={policy.scope.inScope.length === 0}
            >
              <Upload className="h-3.5 w-3.5" />
              Sync to Engagement
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Upload className="h-4 w-4 text-orange-400" />
                Sync Scope to Engagement
              </DialogTitle>
              <DialogDescription>
                Add {policy.scope.inScope.length} in-scope targets from <strong>{policy.programName}</strong> as engagement assets.
                All targets will be included — network assets (domains, IPs, URLs) as scan targets, and source code/hardware assets with build-out requirements.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-3 mt-2">
              {/* Create New Engagement button — always shown */}
              <button
                onClick={() => {
                  onCreateNewEngagement();
                  setShowSyncDialog(false);
                }}
                disabled={isCreatingEngagement}
                className="w-full flex items-center justify-between p-3 rounded-lg border border-dashed border-orange-500/40 hover:bg-orange-500/5 transition-colors text-left"
              >
                <div className="flex items-center gap-2">
                  {isCreatingEngagement ? (
                    <Loader2 className="h-4 w-4 animate-spin text-orange-400" />
                  ) : (
                    <Plus className="h-4 w-4 text-orange-400" />
                  )}
                  <div>
                    <p className="text-sm font-medium text-orange-400">Create New Engagement</p>
                    <p className="text-[10px] text-muted-foreground">Auto-generate engagement from parsed scope with all assets</p>
                  </div>
                </div>
                <Sparkles className="h-4 w-4 text-orange-400" />
              </button>
              {engagements.length === 0 ? (
                <p className="text-[10px] text-muted-foreground text-center">No existing engagements — create one above</p>
              ) : (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {engagements.filter(e => e.status !== 'archived' && e.status !== 'completed').map(eng => (
                    <button
                      key={eng.id}
                      onClick={() => {
                        onSyncToEngagement(eng.id);
                        setShowSyncDialog(false);
                      }}
                      disabled={isSyncing}
                      className="w-full flex items-center justify-between p-3 rounded-lg border border-border hover:bg-accent/50 transition-colors text-left"
                    >
                      <div>
                        <p className="text-sm font-medium">{eng.name}</p>
                        <p className="text-[10px] text-muted-foreground">#{eng.id} · {eng.engagementType.replace(/_/g, ' ')} · {eng.status}</p>
                      </div>
                      {isSyncing ? (
                        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                      ) : (
                        <ArrowRight className="h-4 w-4 text-muted-foreground" />
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* In-Scope */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              In-Scope ({policy.scope.inScope.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-80">
              <div className="space-y-2">
                {policy.scope.inScope.map((entry, i) => {
                  const isBuildable = ['source_code', 'hardware', 'downloadable_executables', 'smart_contract'].includes(entry.type.toLowerCase());
                  return (
                    <div key={i} className={`p-2 rounded border ${isBuildable ? 'bg-amber-500/5 border-amber-500/20' : 'bg-emerald-500/5 border-emerald-500/10'}`}>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={`text-[9px] ${isBuildable ? 'border-amber-500/30 text-amber-400' : 'border-emerald-500/30 text-emerald-400'}`}>{entry.type}</Badge>
                        <span className="text-xs font-mono flex-1 min-w-0 truncate">{entry.value}</span>
                        {isBuildable && (
                          <Badge variant="outline" className="text-[8px] border-amber-500/30 text-amber-400 gap-0.5 shrink-0">
                            <Wrench className="h-2.5 w-2.5" />
                            Build Required
                          </Badge>
                        )}
                      </div>
                      {entry.notes && (
                        <p className="text-[10px] text-muted-foreground mt-1 ml-1">{entry.notes}</p>
                      )}
                      {isBuildable && (() => {
                        const val = entry.value.toLowerCase();
                        const isWpRepo = val.includes('wordpress') || val.includes('wp-cli') || val.includes('glotpress') || val.includes('buddypress') || val.includes('bbpress') || val.includes('wordcamp') || val.includes('woocommerce');
                        const isWpPlugin = val.includes('plugin') || val.includes('profiles.wordpress.org') || val.includes('wordpress.org/plugins');
                        const isGithub = val.includes('github.com');
                        const isGitlab = val.includes('gitlab.com');
                        const isBitbucket = val.includes('bitbucket.org');
                        const repoUrl = isGithub || isGitlab || isBitbucket ? entry.value.replace(/\/$/, '') : null;
                        return (
                          <div className="mt-1.5 ml-1 p-2 rounded bg-amber-500/5 border border-amber-500/10 space-y-1.5">
                            <div className="flex items-center gap-1">
                              <Server className="h-2.5 w-2.5 text-amber-400" />
                              <span className="text-[9px] font-medium text-amber-400">
                                {isWpRepo || isWpPlugin ? 'WordPress Local Environment Setup' : 'Local Build Required'}
                              </span>
                            </div>
                            <p className="text-[9px] text-red-400 font-medium">
                              Do NOT test against live production sites. Build and test locally only.
                            </p>
                            {repoUrl && (
                              <div className="space-y-1">
                                <div className="flex items-center gap-1 px-1.5 py-1 rounded bg-black/30 border border-border/20">
                                  <GitBranch className="h-2.5 w-2.5 text-cyan-400 flex-shrink-0" />
                                  <code className="text-[9px] text-cyan-300 font-mono select-all">git clone {repoUrl}.git</code>
                                </div>
                              </div>
                            )}
                            {(isWpRepo || isWpPlugin) && (
                              <div className="space-y-1 pt-1 border-t border-amber-500/10">
                                <span className="text-[9px] font-medium text-amber-300">WordPress Test Environment Options:</span>
                                <div className="space-y-0.5">
                                  <div className="flex items-center gap-1 px-1.5 py-1 rounded bg-black/30 border border-border/20">
                                    <span className="text-[8px] text-purple-400 font-medium shrink-0">wp-env</span>
                                    <code className="text-[9px] text-purple-300 font-mono select-all">npx @wordpress/env start</code>
                                  </div>
                                  <div className="flex items-center gap-1 px-1.5 py-1 rounded bg-black/30 border border-border/20">
                                    <span className="text-[8px] text-blue-400 font-medium shrink-0">Docker</span>
                                    <code className="text-[9px] text-blue-300 font-mono select-all">docker run -d -p 8080:80 -e WORDPRESS_DB_HOST=db wordpress:latest</code>
                                  </div>
                                  <div className="flex items-center gap-1 px-1.5 py-1 rounded bg-black/30 border border-border/20">
                                    <span className="text-[8px] text-green-400 font-medium shrink-0">DDEV</span>
                                    <code className="text-[9px] text-green-300 font-mono select-all">ddev config --project-type=wordpress && ddev start</code>
                                  </div>
                                </div>
                                {isWpPlugin && (
                                  <p className="text-[9px] text-muted-foreground mt-0.5">
                                    For plugins: download the .zip from WordPress.org, install in your local WP instance via Plugins &gt; Add New &gt; Upload.
                                  </p>
                                )}
                                {val.includes('wp-cli') && (
                                  <p className="text-[9px] text-muted-foreground mt-0.5">
                                    WP-CLI: Install via <code className="text-cyan-300">curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar</code> and test commands against your local WP instance.
                                  </p>
                                )}
                                {val.includes('glotpress') && (
                                  <p className="text-[9px] text-muted-foreground mt-0.5">
                                    GlotPress: Clone the repo into <code className="text-cyan-300">wp-content/plugins/</code> of your local WP install, then activate via the admin panel.
                                  </p>
                                )}
                              </div>
                            )}
                            {!isWpRepo && !isWpPlugin && repoUrl && (
                              <p className="text-[9px] text-muted-foreground">
                                Clone the repository, review the README for build instructions, and set up a local test environment before scanning.
                              </p>
                            )}
                            {!isWpRepo && !isWpPlugin && !repoUrl && (
                              <p className="text-[9px] text-muted-foreground">
                                Download the target, build locally per the project's documentation, and test in an isolated environment.
                              </p>
                            )}
                          </div>
                        );
                      })()}
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Out-of-Scope */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-400" />
              Out-of-Scope ({policy.scope.outOfScope.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-64">
              <div className="space-y-2">
                {policy.scope.outOfScope.map((entry, i) => (
                  <div key={i} className="flex items-center gap-2 p-2 rounded bg-red-500/5 border border-red-500/10">
                    <Badge variant="outline" className="text-[9px] border-red-500/30 text-red-400">{entry.type}</Badge>
                    <span className="text-xs font-mono">{entry.value}</span>
                    {entry.notes && <span className="text-[10px] text-muted-foreground ml-auto">{entry.notes}</span>}
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      {/* Scope Checker */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Crosshair className="h-4 w-4 text-orange-400" />
            Check Target Scope
          </CardTitle>
          <CardDescription className="text-xs">
            Verify whether a specific target is in-scope before testing. Supports domains, subdomains, IPs, and URLs.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              placeholder="e.g., api.example.com or 10.0.0.1"
              value={targetToCheck}
              onChange={e => setTargetToCheck(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleCheck()}
              className="flex-1 max-w-md"
            />
            <Button onClick={handleCheck} disabled={isChecking || !targetToCheck.trim()} variant="outline" className="gap-1">
              {isChecking ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              Check
            </Button>
          </div>

          {scopeResults.length > 0 && (
            <div className="space-y-2">
              {scopeResults.map((result, i) => (
                <div
                  key={i}
                  className={`flex items-center gap-3 p-3 rounded-lg border ${
                    result.inScope
                      ? 'bg-emerald-500/5 border-emerald-500/20'
                      : 'bg-red-500/5 border-red-500/20'
                  }`}
                >
                  {result.inScope ? (
                    <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                  ) : (
                    <XCircle className="h-5 w-5 text-red-400" />
                  )}
                  <div className="flex-1">
                    <span className="text-sm font-mono font-medium">{result.target}</span>
                    <p className="text-xs text-muted-foreground">{result.reason}</p>
                    {result.matchedRule && (
                      <p className="text-[10px] text-muted-foreground mt-1">Matched: {result.matchedRule}</p>
                    )}
                  </div>
                  <Badge variant={result.inScope ? 'default' : 'destructive'} className="text-[10px]">
                    {result.inScope ? 'IN SCOPE' : 'OUT OF SCOPE'}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Tab: Finding Documenter ───────────────────────────────────────────────────

function FindingsTab({
  findings,
  onFindingsChange,
  policy,
}: {
  findings: Finding[];
  onFindingsChange: (f: Finding[]) => void;
  policy: PolicyROE;
}) {
  const [isAdding, setIsAdding] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<Partial<Finding>>({
    severity: 'medium',
  });

  const handleSave = () => {
    if (!form.title || !form.target || !form.description || !form.stepsToReproduce || !form.impact) {
      toast.error('Please fill in all required fields');
      return;
    }
    if (editingId) {
      onFindingsChange(findings.map(f => f.id === editingId ? { ...f, ...form } as Finding : f));
      setEditingId(null);
    } else {
      const newFinding: Finding = {
        id: `finding-${Date.now()}`,
        title: form.title!,
        severity: form.severity || 'medium',
        target: form.target!,
        description: form.description!,
        stepsToReproduce: form.stepsToReproduce!,
        impact: form.impact!,
        cweId: form.cweId,
        cvssScore: form.cvssScore,
      };
      onFindingsChange([...findings, newFinding]);
    }
    setForm({ severity: 'medium' });
    setIsAdding(false);
  };

  const handleEdit = (finding: Finding) => {
    setForm(finding);
    setEditingId(finding.id);
    setIsAdding(true);
  };

  const handleDelete = (id: string) => {
    onFindingsChange(findings.filter(f => f.id !== id));
  };

  const severityColor: Record<string, string> = {
    critical: 'bg-red-500/10 text-red-400 border-red-500/30',
    high: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
    medium: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    low: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    informational: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Findings ({findings.length})</h2>
          <p className="text-sm text-muted-foreground">
            Document each vulnerability with reproduction steps, impact, and CWE classification.
          </p>
        </div>
        <Button onClick={() => { setIsAdding(true); setEditingId(null); setForm({ severity: 'medium' }); }} className="gap-1 bg-orange-600 hover:bg-orange-700">
          <Bug className="h-4 w-4" />
          New Finding
        </Button>
      </div>

      {/* Finding Form */}
      {isAdding && (
        <Card className="border-orange-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">{editingId ? 'Edit Finding' : 'New Finding'}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Title *</Label>
                <Input
                  placeholder="e.g., Stored XSS in Comment Field"
                  value={form.title || ''}
                  onChange={e => setForm(p => ({ ...p, title: e.target.value }))}
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-2">
                  <Label>Severity *</Label>
                  <Select value={form.severity || 'medium'} onValueChange={v => setForm(p => ({ ...p, severity: v }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="informational">Informational</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>CWE ID</Label>
                  <Input
                    placeholder="CWE-79"
                    value={form.cweId || ''}
                    onChange={e => setForm(p => ({ ...p, cweId: e.target.value }))}
                  />
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <Label>Target *</Label>
              <Input
                placeholder="e.g., https://api.example.com/v2/comments"
                value={form.target || ''}
                onChange={e => setForm(p => ({ ...p, target: e.target.value }))}
              />
            </div>

            <div className="space-y-2">
              <Label>Description *</Label>
              <Textarea
                placeholder="Describe the vulnerability in detail..."
                value={form.description || ''}
                onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
                rows={3}
              />
            </div>

            <div className="space-y-2">
              <Label>Steps to Reproduce *</Label>
              <Textarea
                placeholder="1. Navigate to...\n2. Enter payload...\n3. Observe..."
                value={form.stepsToReproduce || ''}
                onChange={e => setForm(p => ({ ...p, stepsToReproduce: e.target.value }))}
                rows={4}
              />
            </div>

            <div className="space-y-2">
              <Label>Impact *</Label>
              <Textarea
                placeholder="Describe the security impact and business risk..."
                value={form.impact || ''}
                onChange={e => setForm(p => ({ ...p, impact: e.target.value }))}
                rows={2}
              />
            </div>

            <div className="flex gap-2 justify-end">
              <Button variant="outline" onClick={() => { setIsAdding(false); setEditingId(null); }}>Cancel</Button>
              <Button onClick={handleSave} className="bg-orange-600 hover:bg-orange-700">
                {editingId ? 'Update' : 'Save'} Finding
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Findings List */}
      {findings.length === 0 && !isAdding ? (
        <Card className="border-dashed">
          <CardContent className="py-12 text-center">
            <Bug className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No findings documented yet</p>
            <p className="text-xs text-muted-foreground mt-1">Click "New Finding" to start documenting vulnerabilities</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {findings.map(finding => (
            <Card key={finding.id} className="hover:shadow-sm transition-shadow">
              <CardContent className="pt-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge className={`text-[10px] ${severityColor[finding.severity]}`}>
                        {finding.severity.toUpperCase()}
                      </Badge>
                      <h3 className="text-sm font-medium truncate">{finding.title}</h3>
                      {finding.cweId && <Badge variant="outline" className="text-[9px]">{finding.cweId}</Badge>}
                    </div>
                    <p className="text-xs text-muted-foreground font-mono">{finding.target}</p>
                    <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{finding.description}</p>
                  </div>
                  <div className="flex gap-1 flex-shrink-0">
                    <Button variant="ghost" size="sm" onClick={() => handleEdit(finding)} className="h-7 px-2 text-xs">Edit</Button>
                    <Button variant="ghost" size="sm" onClick={() => handleDelete(finding.id)} className="h-7 px-2 text-xs text-red-400 hover:text-red-300">Delete</Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Tab: Originality Checker ──────────────────────────────────────────────────

function OriginalityTab({
  findings,
  checkOriginality,
}: {
  findings: Finding[];
  checkOriginality: any;
}) {
  const [results, setResults] = useState<Map<string, OriginalityResult>>(new Map());
  const [checking, setChecking] = useState<string | null>(null);

  const handleCheck = async (finding: Finding) => {
    setChecking(finding.id);
    try {
      const result = await checkOriginality.mutateAsync({
        finding: {
          title: finding.title,
          description: finding.description,
          cweId: finding.cweId,
          target: finding.target,
        },
      });
      setResults(prev => new Map(prev).set(finding.id, result as OriginalityResult));
    } catch (err: any) {
      toast.error('Originality check failed', { description: err.message });
    } finally {
      setChecking(null);
    }
  };

  const handleCheckAll = async () => {
    for (const finding of findings) {
      if (!results.has(finding.id)) {
        await handleCheck(finding);
      }
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Originality Verification</h2>
          <p className="text-sm text-muted-foreground">
            Check each finding against known issue patterns and common non-original submissions to avoid duplicates and wasted effort.
          </p>
        </div>
        <Button onClick={handleCheckAll} variant="outline" className="gap-1">
          <Sparkles className="h-4 w-4" />
          Check All
        </Button>
      </div>

      <div className="space-y-3">
        {findings.map(finding => {
          const result = results.get(finding.id);
          const isChecking = checking === finding.id;
          return (
            <Card key={finding.id}>
              <CardContent className="pt-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-medium">{finding.title}</h3>
                    <p className="text-xs text-muted-foreground font-mono">{finding.target}</p>
                  </div>
                  {!result ? (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleCheck(finding)}
                      disabled={isChecking}
                      className="gap-1"
                    >
                      {isChecking ? <Loader2 className="h-3 w-3 animate-spin" /> : <Sparkles className="h-3 w-3" />}
                      Check
                    </Button>
                  ) : (
                    <Badge className={`text-[10px] ${
                      result.isOriginal
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                    }`}>
                      {result.isOriginal ? 'LIKELY ORIGINAL' : 'POSSIBLE DUPLICATE'}
                    </Badge>
                  )}
                </div>
                {result && (
                  <div className="mt-3 p-3 rounded bg-muted/30 border border-border/50 space-y-2">
                    <div className="flex items-center gap-3 text-xs">
                      <span className="text-muted-foreground">Confidence:</span>
                      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${result.isOriginal ? 'bg-emerald-500' : 'bg-amber-500'}`}
                          style={{ width: `${result.confidence * 100}%` }}
                        />
                      </div>
                      <span className="font-mono">{(result.confidence * 100).toFixed(0)}%</span>
                    </div>
                    {result.matchedPatterns.length > 0 && (
                      <div className="text-xs">
                        <span className="text-muted-foreground">Matched patterns:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {result.matchedPatterns.map((p, i) => (
                            <Badge key={i} variant="outline" className="text-[9px]">{p}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    <p className="text-xs text-muted-foreground">{result.recommendation}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

// ─── Tab: Submission Formatter ─────────────────────────────────────────────────

function SubmitTab({
  findings,
  policy,
  platform,
  onPlatformChange,
}: {
  findings: Finding[];
  policy: PolicyROE;
  platform: string;
  onPlatformChange: (p: string) => void;
}) {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(findings[0] || null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const formatSubmission = useCallback((finding: Finding): string => {
    const sections = [];

    // Title
    sections.push(`## ${finding.title}`);
    sections.push('');

    // Metadata
    sections.push(`**Severity:** ${finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)}`);
    if (finding.cweId) sections.push(`**CWE:** ${finding.cweId}`);
    if (finding.cvssScore) sections.push(`**CVSS:** ${finding.cvssScore}`);
    sections.push(`**Target:** \`${finding.target}\``);
    sections.push('');

    // Description
    sections.push('### Description');
    sections.push(finding.description);
    sections.push('');

    // Steps to Reproduce
    sections.push('### Steps to Reproduce');
    sections.push(finding.stepsToReproduce);
    sections.push('');

    // Impact
    sections.push('### Impact');
    sections.push(finding.impact);
    sections.push('');

    // Platform-specific footer
    if (platform === 'hackerone') {
      sections.push('---');
      sections.push(`*Submitted via AC3 Bug Bounty Workspace for ${policy.programName}*`);
    } else if (platform === 'bugcrowd') {
      sections.push('---');
      sections.push(`Program: ${policy.programName}`);
    }

    return sections.join('\n');
  }, [platform, policy.programName]);

  const handleCopy = (finding: Finding) => {
    const text = formatSubmission(finding);
    navigator.clipboard.writeText(text);
    setCopiedId(finding.id);
    toast.success('Copied to clipboard');
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Format & Submit</h2>
          <p className="text-sm text-muted-foreground">
            Generate platform-formatted submission reports for each finding. Copy to clipboard and submit directly on the platform.
          </p>
        </div>
        <Select value={platform} onValueChange={onPlatformChange}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="hackerone">HackerOne</SelectItem>
            <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
            <SelectItem value="intigriti">Intigriti</SelectItem>
            <SelectItem value="synack">Synack</SelectItem>
            <SelectItem value="yeswehack">YesWeHack</SelectItem>
            <SelectItem value="custom">Custom</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Finding Selector */}
        <div className="space-y-2">
          <Label className="text-xs text-muted-foreground">Select Finding</Label>
          <ScrollArea className="max-h-[500px]">
            <div className="space-y-2">
              {findings.map(finding => (
                <Card
                  key={finding.id}
                  className={`cursor-pointer transition-all ${
                    selectedFinding?.id === finding.id
                      ? 'ring-1 ring-orange-500/50 border-orange-500/30'
                      : 'hover:border-muted-foreground/30'
                  }`}
                  onClick={() => setSelectedFinding(finding)}
                >
                  <CardContent className="pt-3 pb-3">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-[9px]">{finding.severity}</Badge>
                      <span className="text-xs font-medium truncate">{finding.title}</span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </ScrollArea>
        </div>

        {/* Formatted Preview */}
        <div className="lg:col-span-2">
          {selectedFinding ? (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <FileCheck className="h-4 w-4 text-orange-400" />
                    Formatted Submission
                    <Badge variant="outline" className="text-[9px]">{platform}</Badge>
                  </CardTitle>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleCopy(selectedFinding)}
                    className="gap-1"
                  >
                    {copiedId === selectedFinding.id ? (
                      <><Check className="h-3 w-3" />Copied</>
                    ) : (
                      <><Copy className="h-3 w-3" />Copy</>
                    )}
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <ScrollArea className="max-h-[400px]">
                  <pre className="text-xs font-mono whitespace-pre-wrap p-4 rounded-lg bg-muted/30 border border-border/50">
                    {formatSubmission(selectedFinding)}
                  </pre>
                </ScrollArea>
              </CardContent>
            </Card>
          ) : (
            <Card className="border-dashed">
              <CardContent className="py-12 text-center">
                <FileText className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">Select a finding to preview the formatted submission</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* Batch Copy */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Batch Export</p>
              <p className="text-xs text-muted-foreground">Copy all {findings.length} findings as a single formatted report</p>
            </div>
            <Button
              variant="outline"
              onClick={() => {
                const all = findings.map(f => formatSubmission(f)).join('\n\n---\n\n');
                navigator.clipboard.writeText(all);
                toast.success(`Copied ${findings.length} findings to clipboard`);
              }}
              className="gap-1"
            >
              <Clipboard className="h-4 w-4" />
              Copy All
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}


// ─── Tab: Import from Engagement ──────────────────────────────────────────────

function ImportFromEngagementTab({
  engagementIdInput,
  onEngagementIdChange,
  onImport,
  isImporting,
  importedFindings,
  onAdopt,
  existingFindingIds,
}: {
  engagementIdInput: string;
  onEngagementIdChange: (v: string) => void;
  onImport: () => void;
  isImporting: boolean;
  importedFindings: any[];
  onAdopt: (f: any) => void;
  existingFindingIds: Set<string>;
}) {
  // Fetch active engagements for the dropdown
  const engagementsQuery = trpc.vaBugBounty.listActiveEngagements.useQuery();
  const engagements = engagementsQuery.data || [];
  const [showManualInput, setShowManualInput] = useState(false);

  const severityColor: Record<string, string> = {
    critical: 'bg-red-500/10 text-red-400 border-red-500/30',
    high: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
    medium: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    low: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    info: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
  };

  const engagementTypeColors: Record<string, string> = {
    pentest: 'bg-red-500/10 text-red-400 border-red-500/30',
    vulnerability_assessment: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    bug_bounty: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    phishing: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    red_team: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    purple_team: 'bg-violet-500/10 text-violet-400 border-violet-500/30',
    tabletop: 'bg-green-500/10 text-green-400 border-green-500/30',
  };

  const handleSelectEngagement = (engId: string) => {
    if (engId === '__manual__') {
      setShowManualInput(true);
      return;
    }
    setShowManualInput(false);
    onEngagementIdChange(engId);
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Download className="h-4 w-4 text-orange-400" />
            Import Findings from Engagement
          </CardTitle>
          <CardDescription>
            Select an active engagement to pull normalized findings. Choose findings to adopt into your
            Bug Bounty workspace, then add reproduction steps and impact analysis for submission.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Engagement Selector Dropdown */}
          <div className="space-y-3">
            <Label className="text-xs font-medium text-muted-foreground">Select Engagement</Label>
            <div className="flex gap-2">
              <Select
                value={engagementIdInput || undefined}
                onValueChange={handleSelectEngagement}
              >
                <SelectTrigger className="flex-1 max-w-md h-9">
                  <SelectValue placeholder={
                    engagementsQuery.isLoading ? "Loading engagements..." : 
                    engagements.length === 0 ? "No engagements found" :
                    "Choose an engagement..."
                  } />
                </SelectTrigger>
                <SelectContent>
                  {engagements.map((eng: any) => (
                    <SelectItem key={eng.id} value={String(eng.id)}>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">#{eng.id}</span>
                        <span className="text-muted-foreground">—</span>
                        <span>{eng.name}</span>
                        {eng.engagementType && (
                          <Badge variant="outline" className={`text-[9px] ml-1 ${engagementTypeColors[eng.engagementType] || 'bg-gray-500/10 text-gray-400'}`}>
                            {eng.engagementType.replace(/_/g, ' ')}
                          </Badge>
                        )}
                        {eng.targetDomain && (
                          <span className="text-[10px] text-muted-foreground ml-1 font-mono">{eng.targetDomain}</span>
                        )}
                      </div>
                    </SelectItem>
                  ))}
                  <SelectItem value="__manual__">
                    <span className="text-muted-foreground">Enter ID manually...</span>
                  </SelectItem>
                </SelectContent>
              </Select>
              <Button onClick={onImport} disabled={isImporting || !engagementIdInput.trim()} className="gap-2 bg-orange-600 hover:bg-orange-700">
                {isImporting ? (
                  <><Loader2 className="h-4 w-4 animate-spin" />Importing...</>
                ) : (
                  <><Download className="h-4 w-4" />Import Findings</>
                )}
              </Button>
            </div>

            {/* Manual ID input fallback */}
            {showManualInput && (
              <div className="flex gap-2 items-center">
                <Input
                  placeholder="Enter engagement ID (e.g., 42)"
                  value={engagementIdInput}
                  onChange={e => onEngagementIdChange(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && onImport()}
                  className="flex-1 max-w-xs h-8 text-sm"
                  autoFocus
                />
                <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={() => setShowManualInput(false)}>
                  Back to dropdown
                </Button>
              </div>
            )}

            {/* Selected engagement info card */}
            {engagementIdInput && !showManualInput && (() => {
              const selected = engagements.find((e: any) => String(e.id) === engagementIdInput);
              if (!selected) return null;
              return (
                <div className="flex items-center gap-3 p-2.5 rounded-lg border border-orange-500/20 bg-orange-500/5 text-xs">
                  <div className="h-8 w-8 rounded-lg bg-orange-500/10 flex items-center justify-center flex-none">
                    <Target className="h-4 w-4 text-orange-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-foreground">{selected.name}</div>
                    <div className="flex items-center gap-2 text-muted-foreground mt-0.5">
                      {selected.clientName && <span>{selected.clientName}</span>}
                      {selected.targetDomain && <span className="font-mono">{selected.targetDomain}</span>}
                      <Badge variant="outline" className={`text-[9px] ${engagementTypeColors[selected.engagementType] || ''}`}>
                        {selected.engagementType?.replace(/_/g, ' ')}
                      </Badge>
                      <Badge variant="outline" className="text-[9px]">
                        {selected.status}
                      </Badge>
                    </div>
                  </div>
                </div>
              );
            })()}
          </div>

          {importedFindings.length > 0 && (
            <div className="text-xs text-muted-foreground">
              {importedFindings.length} findings available for adoption
            </div>
          )}
        </CardContent>
      </Card>

      {/* Imported Findings List */}
      {importedFindings.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Layers className="h-4 w-4 text-orange-400" />
              Engagement Findings ({importedFindings.length})
            </CardTitle>
            <CardDescription className="text-xs">
              Click "Adopt" to add a finding to your workspace. You can then edit reproduction steps and impact before submission.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-[500px]">
              <div className="space-y-2">
                {importedFindings.map((f: any) => {
                  const adopted = existingFindingIds.has(`imported-${f.id}`);
                  return (
                    <div
                      key={f.id}
                      className={`flex items-start gap-3 p-3 rounded-lg border transition-colors ${
                        adopted ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-card/50 border-border/30 hover:bg-card/70'
                      }`}
                    >
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant="outline" className={`${severityColor[f.severity] || severityColor.info} text-[10px]`}>
                            {f.severity}
                          </Badge>
                          {f.corroborationTier && (
                            <Badge variant="outline" className="text-[10px] bg-background/50">
                              {f.corroborationTier.replace(/_/g, ' ')}
                            </Badge>
                          )}
                          <span className="text-sm font-medium text-foreground truncate">{f.title}</span>
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Target className="h-3 w-3" /> {f.target}
                          </span>
                          {f.cveIds?.length > 0 && (
                            <span className="flex items-center gap-1 font-mono">
                              <Shield className="h-3 w-3" /> {f.cveIds.slice(0, 2).join(', ')}
                            </span>
                          )}
                          {f.sourceCount > 1 && (
                            <span className="flex items-center gap-1">
                              <Eye className="h-3 w-3" /> {f.sourceCount} sources
                            </span>
                          )}
                          {f.detectionConfidence != null && (
                            <span className="flex items-center gap-1">
                              <Sparkles className="h-3 w-3" /> {Math.round(f.detectionConfidence * 100)}% conf
                            </span>
                          )}
                        </div>
                        {f.description && (
                          <p className="text-xs text-muted-foreground mt-1.5 line-clamp-2">{f.description}</p>
                        )}
                      </div>
                      <Button
                        variant={adopted ? "secondary" : "outline"}
                        size="sm"
                        className="flex-none h-7 text-xs gap-1"
                        disabled={adopted}
                        onClick={() => onAdopt(f)}
                      >
                        {adopted ? (
                          <><CheckCircle2 className="h-3 w-3 text-emerald-400" />Adopted</>
                        ) : (
                          <><ArrowRight className="h-3 w-3" />Adopt</>
                        )}
                      </Button>
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      {!isImporting && importedFindings.length === 0 && (
        <Card className="border-border/30 bg-card/30">
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <div className="h-12 w-12 rounded-xl bg-orange-500/10 flex items-center justify-center">
              <Download className="h-6 w-6 text-orange-400" />
            </div>
            <p className="text-sm text-muted-foreground text-center max-w-md">
              Enter an engagement ID to import normalized findings. Findings are pulled from the engagement's
              scan results, deduplicated, and presented for adoption into your Bug Bounty workspace.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
