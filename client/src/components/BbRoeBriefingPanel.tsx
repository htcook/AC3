/**
 * BB RoE Operator Briefing Panel
 * Displays program-specific Rules of Engagement for bug bounty engagements.
 * Shows critical rules, identification setup, acceptable/ineligible findings,
 * and allows importing RoE from a program URL.
 */
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Shield, ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink,
  Ban, CheckCircle2, XCircle, Globe, Loader2, Import, Eye,
  Fingerprint, Trash2, Clock, Zap, Info
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface BbRoeBriefingPanelProps {
  engagementId: number;
}

export default function BbRoeBriefingPanel({ engagementId }: BbRoeBriefingPanelProps) {
  const { toast } = useToast();
  const [importUrl, setImportUrl] = useState("");
  const [showImport, setShowImport] = useState(false);

  const briefingQ = trpc.bugBounty.getOperatorBriefing.useQuery({ engagementId });
  const importMut = trpc.bugBounty.importRoeFromUrl.useMutation({
    onSuccess: (data) => {
      toast({
        title: "RoE Imported Successfully",
        description: `Parsed ${data.rulesCount.prohibitedActions} prohibited actions, ${data.rulesCount.eligibleCategories} acceptable categories, ${data.rulesCount.excludedTargets} excluded targets for "${data.programHandle}"`,
      });
      setShowImport(false);
      setImportUrl("");
      briefingQ.refetch();
    },
    onError: (err) => {
      toast({
        title: "Import Failed",
        description: err.message,
        variant: "destructive",
      });
    },
  });

  // Loading state
  if (briefingQ.isLoading) {
    return (
      <Card className="bg-card/50 border-purple-500/30 animate-pulse">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Shield className="h-4 w-4 text-purple-400" /> Loading BB Program Rules...
          </CardTitle>
        </CardHeader>
      </Card>
    );
  }

  // No briefing available (not a BB engagement or no program config)
  if (!briefingQ.data?.briefing) {
    return (
      <Card className="bg-card/50 border-amber-500/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-amber-400" /> Bug Bounty Program Rules
            <Badge variant="outline" className="ml-auto text-[10px] border-amber-500/50 text-amber-400">
              Not Configured
            </Badge>
          </CardTitle>
          <CardDescription className="text-xs">
            No program-specific RoE has been imported for this engagement. Import from a program URL to enable enforcement.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg px-4 py-3">
              <div className="flex items-center gap-2 text-amber-400 text-sm font-medium">
                <AlertTriangle className="h-4 w-4" />
                No Program RoE Loaded
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                This bug bounty engagement is targeting LIVE production assets without program-specific rules loaded.
                Import the program's policy page to enable scan-time enforcement and report filtering.
              </p>
            </div>
            <div className="flex gap-2">
              <Input
                placeholder="https://hackerone.com/program-name?view_policy=true"
                value={importUrl}
                onChange={(e) => setImportUrl(e.target.value)}
                className="text-xs"
              />
              <Button
                size="sm"
                variant="outline"
                className="border-purple-500/30 text-purple-400 hover:bg-purple-500/10 flex-none"
                disabled={!importUrl || importMut.isPending}
                onClick={() => importMut.mutate({ programUrl: importUrl, engagementId })}
              >
                {importMut.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Import className="h-3 w-3" />}
                <span className="ml-1">Import</span>
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  const { briefing, programHandle, subTargetRules, rateLimiting, automatedScannersAllowed, dataHandling } = briefingQ.data;

  return (
    <Card className="bg-card/50 border-purple-500/30">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-purple-400" /> Program RoE: {programHandle?.toUpperCase()}
          <Badge variant="outline" className="ml-auto text-[10px] border-green-500/50 text-green-400">
            <CheckCircle2 className="h-2.5 w-2.5 mr-0.5" /> Enforced
          </Badge>
        </CardTitle>
        <CardDescription className="text-xs flex items-center gap-2">
          <span>Platform: {briefing.platform}</span>
          <span className="text-border">|</span>
          <a href={briefing.policyUrl} target="_blank" rel="noopener noreferrer" className="text-purple-400 hover:underline flex items-center gap-0.5">
            Policy Page <ExternalLink className="h-2.5 w-2.5" />
          </a>
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* ── Critical Rules (MUST FOLLOW) ── */}
        <div>
          <h4 className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Ban className="h-3.5 w-3.5" /> Critical Rules — MUST Follow
          </h4>
          <div className="space-y-1">
            {briefing.criticalRules.map((rule: string, i: number) => (
              <div key={i} className="flex items-start gap-2 text-xs px-2.5 py-1.5 bg-red-500/5 rounded border border-red-500/10">
                <XCircle className="h-3.5 w-3.5 text-red-400 flex-none mt-0.5" />
                <span className="text-foreground/90">{rule.replace(/^❌\s*/, '')}</span>
              </div>
            ))}
          </div>
        </div>

        <Separator className="opacity-30" />

        {/* ── Identification Setup ── */}
        <div>
          <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Fingerprint className="h-3.5 w-3.5" /> Identification Setup
          </h4>
          <div className="space-y-1">
            {briefing.identificationSetup.map((item: string, i: number) => (
              <div key={i} className="flex items-center gap-2 text-xs px-2.5 py-1.5 bg-cyan-500/5 rounded border border-cyan-500/10">
                <Info className="h-3.5 w-3.5 text-cyan-400 flex-none" />
                <code className="text-cyan-300 font-mono text-[11px]">{item}</code>
              </div>
            ))}
          </div>
        </div>

        <Separator className="opacity-30" />

        {/* ── Acceptable Findings (What to Look For) ── */}
        <div>
          <h4 className="text-xs font-semibold text-green-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5" /> Acceptable Findings
          </h4>
          <div className="space-y-1">
            {briefing.targetFindings.map((finding: string, i: number) => (
              <div key={i} className="flex items-start gap-2 text-xs px-2.5 py-1.5 bg-green-500/5 rounded border border-green-500/10">
                <CheckCircle2 className="h-3.5 w-3.5 text-green-400 flex-none mt-0.5" />
                <span className="text-foreground/90">{finding.replace(/^✅\s*/, '')}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Sub-Target Rules (e.g., Penny for Priceline) ── */}
        {subTargetRules && subTargetRules.length > 0 && (
          <>
            <Separator className="opacity-30" />
            <div>
              <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Zap className="h-3.5 w-3.5" /> Sub-Target Specific Rules
              </h4>
              {subTargetRules.map((st: any, i: number) => (
                <div key={i} className="bg-amber-500/5 border border-amber-500/10 rounded-lg p-3 mb-2">
                  <div className="flex items-center gap-2 mb-1.5">
                    <Badge variant="outline" className="text-[10px] border-amber-500/50 text-amber-400">
                      {st.targetName}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground">
                      Assets: {st.assets?.join(', ')}
                    </span>
                  </div>
                  <div className="space-y-0.5">
                    {st.acceptableCategories?.map((cat: any, j: number) => (
                      <div key={j} className="text-[11px] text-foreground/80 flex items-start gap-1.5">
                        <span className="text-amber-400">•</span>
                        <span>{cat.description}{cat.examples?.length ? ` (${cat.examples.join(', ')})` : ''}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        <Separator className="opacity-30" />

        {/* ── Do NOT Submit ── */}
        <div>
          <h4 className="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" /> Do NOT Submit
          </h4>
          <div className="space-y-1">
            {briefing.doNotSubmit.map((item: string, i: number) => (
              <div key={i} className="flex items-start gap-2 text-xs px-2.5 py-1.5 bg-orange-500/5 rounded border border-orange-500/10">
                <Ban className="h-3.5 w-3.5 text-orange-400 flex-none mt-0.5" />
                <span className="text-foreground/90">{item}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Excluded Targets ── */}
        {briefing.excludedTargets && briefing.excludedTargets.length > 0 && (
          <>
            <Separator className="opacity-30" />
            <div>
              <h4 className="text-xs font-semibold text-red-400/80 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Globe className="h-3.5 w-3.5" /> Excluded Targets
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {briefing.excludedTargets.map((target: string, i: number) => (
                  <Badge key={i} variant="outline" className="text-[10px] border-red-500/30 text-red-400 bg-red-500/5">
                    <XCircle className="h-2.5 w-2.5 mr-0.5" /> {target}
                  </Badge>
                ))}
              </div>
            </div>
          </>
        )}

        {/* ── Rate Limiting & Scanner Restrictions ── */}
        {(rateLimiting || !automatedScannersAllowed) && (
          <>
            <Separator className="opacity-30" />
            <div className="grid grid-cols-2 gap-3">
              {rateLimiting && (
                <div className="bg-muted/10 rounded-lg p-2.5 border border-border/30">
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Rate Limits</span>
                  <div className="mt-1 space-y-0.5 text-xs">
                    {rateLimiting.maxRequestsPerSecond && (
                      <div className="flex items-center gap-1.5">
                        <Clock className="h-3 w-3 text-cyan-400" />
                        <span>{rateLimiting.maxRequestsPerSecond} req/sec max</span>
                      </div>
                    )}
                    {rateLimiting.maxConcurrentScans && (
                      <div className="flex items-center gap-1.5">
                        <Zap className="h-3 w-3 text-cyan-400" />
                        <span>{rateLimiting.maxConcurrentScans} concurrent max</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
              {!automatedScannersAllowed && (
                <div className="bg-red-500/5 rounded-lg p-2.5 border border-red-500/20">
                  <span className="text-[10px] text-red-400 uppercase tracking-wider font-semibold">Scanner Restriction</span>
                  <p className="mt-1 text-xs text-foreground/80">
                    Automated scanners are NOT allowed. Manual testing with targeted tools only.
                  </p>
                </div>
              )}
            </div>
          </>
        )}

        {/* ── Data Handling Rules ── */}
        {dataHandling && dataHandling.length > 0 && (
          <>
            <Separator className="opacity-30" />
            <div>
              <h4 className="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Eye className="h-3.5 w-3.5" /> Data Handling Rules
              </h4>
              <div className="space-y-1">
                {dataHandling.map((rule: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs px-2.5 py-1.5 bg-blue-500/5 rounded border border-blue-500/10">
                    <Badge variant="outline" className={`text-[9px] flex-none ${rule.enforcement === 'hard' ? 'border-red-500/50 text-red-400' : 'border-amber-500/50 text-amber-400'}`}>
                      {rule.enforcement}
                    </Badge>
                    <span><strong className="text-blue-300">{rule.dataType}:</strong> {rule.rule}</span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {/* ── Cleanup Actions ── */}
        {briefing.cleanupActions && briefing.cleanupActions.length > 0 && (
          <>
            <Separator className="opacity-30" />
            <div>
              <h4 className="text-xs font-semibold text-teal-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Trash2 className="h-3.5 w-3.5" /> Required Cleanup
              </h4>
              <div className="space-y-1">
                {briefing.cleanupActions.map((action: string, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-xs px-2.5 py-1.5 bg-teal-500/5 rounded border border-teal-500/10">
                    <Trash2 className="h-3 w-3 text-teal-400 flex-none" />
                    <span>{action}</span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        <Separator className="opacity-30" />

        {/* ── Import / Re-import from URL ── */}
        <div className="pt-1">
          {!showImport ? (
            <Button
              size="sm"
              variant="outline"
              className="w-full border-purple-500/30 text-purple-400 hover:bg-purple-500/10 text-xs"
              onClick={() => setShowImport(true)}
            >
              <Import className="h-3 w-3 mr-1.5" />
              Re-import RoE from Program URL
            </Button>
          ) : (
            <div className="flex gap-2">
              <Input
                placeholder="https://hackerone.com/program-name?view_policy=true"
                value={importUrl}
                onChange={(e) => setImportUrl(e.target.value)}
                className="text-xs"
                autoFocus
              />
              <Button
                size="sm"
                variant="outline"
                className="border-purple-500/30 text-purple-400 hover:bg-purple-500/10 flex-none"
                disabled={!importUrl || importMut.isPending}
                onClick={() => importMut.mutate({ programUrl: importUrl, engagementId })}
              >
                {importMut.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Import className="h-3 w-3" />}
                <span className="ml-1">Import</span>
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="flex-none text-muted-foreground"
                onClick={() => { setShowImport(false); setImportUrl(""); }}
              >
                Cancel
              </Button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
