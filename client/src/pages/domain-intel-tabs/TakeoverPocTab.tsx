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

export default function TakeoverPocTab({ scanId }: { scanId: number }) {
  const takeoverQuery = trpc.domainIntel.takeoverDetection.useQuery({ scanId });
  const validateMutation = trpc.domainIntel.validateTakeover.useMutation();
  const [validationResults, setValidationResults] = useState<any>(null);

  const hasCandidates = takeoverQuery.data &&
    ((takeoverQuery.data as any).candidates?.length > 0 ||
     (takeoverQuery.data as any).takeoverCandidates?.length > 0);

  const handleValidate = async () => {
    try {
      const result = await validateMutation.mutateAsync({ scanId });
      setValidationResults(result);
      toast.success(`PoC validation complete: ${result.confirmedCount} confirmed, ${result.likelyCount} likely takeovers`);
    } catch (err: any) {
      toast.error(`Validation failed: ${sanitizeErrorForToast(err)}`);
    }
  };

  if (takeoverQuery.isLoading) return (
    <Card><CardContent className="flex items-center justify-center py-16">
      <Loader2 className="w-6 h-6 animate-spin text-cyan-400 mr-3" />
      <span className="text-muted-foreground">Loading takeover candidates for validation...</span>
    </CardContent></Card>
  );

  if (takeoverQuery.error) return (
    <Card><CardContent className="py-8 text-center">
      <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto mb-2" />
      <p className="text-sm text-muted-foreground">{takeoverQuery.error.message}</p>
    </CardContent></Card>
  );

  const statusColor = (status: string) => {
    switch (status) {
      case "confirmed": return "text-red-400 bg-red-500/10 border-red-500/30";
      case "likely": return "text-orange-400 bg-orange-500/10 border-orange-500/30";
      case "possible": return "text-amber-400 bg-amber-500/10 border-amber-500/30";
      case "unlikely": return "text-emerald-400 bg-emerald-500/10 border-emerald-500/30";
      default: return "text-muted-foreground bg-muted/30 border-border/50";
    }
  };

  const statusIcon = (status: string) => {
    switch (status) {
      case "confirmed": return <XCircle className="w-4 h-4 text-red-400" />;
      case "likely": return <AlertTriangle className="w-4 h-4 text-orange-400" />;
      case "possible": return <Info className="w-4 h-4 text-amber-400" />;
      case "unlikely": return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
      default: return <Info className="w-4 h-4 text-muted-foreground" />;
    }
  };

  const results = validationResults as any;

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Performs active HTTP validation on subdomain takeover candidates by probing the target endpoints for provider-specific error pages, DNS resolution failures, and claimable resource indicators.
      </p>

      {/* Launch Validation */}
      {!validationResults && (
        <Card className="bg-muted/20 border-border/50">
          <CardContent className="py-6 text-center space-y-4">
            {!hasCandidates ? (
              <>
                <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
                <div>
                  <div className="text-sm font-semibold text-emerald-400">No Takeover Candidates</div>
                  <p className="text-xs text-muted-foreground mt-1">No dangling DNS records or takeover candidates were detected in this scan. Active validation is not needed.</p>
                </div>
              </>
            ) : (
              <>
                <Crosshair className="w-10 h-10 text-cyan-400 mx-auto" />
                <div>
                  <div className="text-sm font-semibold">Active Takeover PoC Validation</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    This will make real HTTP requests to each takeover candidate to verify if the subdomain is actually claimable.
                    The validation checks DNS resolution, HTTP response codes, and provider-specific error fingerprints.
                  </p>
                </div>
                <Button
                  onClick={handleValidate}
                  disabled={validateMutation.isPending}
                  className="bg-cyan-600 hover:bg-cyan-700"
                >
                  {validateMutation.isPending ? (
                    <><Loader2 className="w-4 h-4 animate-spin mr-2" /> Validating...</>
                  ) : (
                    <><Play className="w-4 h-4 mr-2" /> Run PoC Validation</>
                  )}
                </Button>
              </>
            )}
          </CardContent>
        </Card>
      )}

      {/* Validation Results */}
      {results && (
        <>
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            <Card className="bg-muted/30 border-border/50">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-cyan-400">{results.totalValidated || 0}</div>
                <div className="text-[11px] text-muted-foreground">Validated</div>
              </CardContent>
            </Card>
            <Card className={`${(results.confirmedCount || 0) > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-muted/30 border-border/50'}`}>
              <CardContent className="p-3 text-center">
                <div className={`text-2xl font-bold ${(results.confirmedCount || 0) > 0 ? 'text-red-400' : 'text-muted-foreground'}`}>{results.confirmedCount || 0}</div>
                <div className="text-[11px] text-muted-foreground">Confirmed</div>
              </CardContent>
            </Card>
            <Card className={`${(results.likelyCount || 0) > 0 ? 'bg-orange-500/10 border-orange-500/30' : 'bg-muted/30 border-border/50'}`}>
              <CardContent className="p-3 text-center">
                <div className={`text-2xl font-bold ${(results.likelyCount || 0) > 0 ? 'text-orange-400' : 'text-muted-foreground'}`}>{results.likelyCount || 0}</div>
                <div className="text-[11px] text-muted-foreground">Likely</div>
              </CardContent>
            </Card>
            <Card className={`${(results.possibleCount || 0) > 0 ? 'bg-amber-500/10 border-amber-500/30' : 'bg-muted/30 border-border/50'}`}>
              <CardContent className="p-3 text-center">
                <div className={`text-2xl font-bold ${(results.possibleCount || 0) > 0 ? 'text-amber-400' : 'text-muted-foreground'}`}>{results.possibleCount || 0}</div>
                <div className="text-[11px] text-muted-foreground">Possible</div>
              </CardContent>
            </Card>
            <Card className="bg-emerald-500/10 border-emerald-500/30">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-emerald-400">{results.unlikelyCount || 0}</div>
                <div className="text-[11px] text-muted-foreground">Unlikely</div>
              </CardContent>
            </Card>
            <Card className="bg-muted/30 border-border/50">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-muted-foreground">{results.errorCount || 0}</div>
                <div className="text-[11px] text-muted-foreground">Errors</div>
              </CardContent>
            </Card>
          </div>

          {/* Summary */}
          {results.summary && (
            <Card className="bg-muted/20">
              <CardContent className="py-3 text-sm text-muted-foreground">{results.summary}</CardContent>
            </Card>
          )}

          {/* Individual Results */}
          {(results.results || []).map((r: any, idx: number) => (
            <Card key={idx} className={`border ${r.validationStatus === 'confirmed' ? 'border-red-500/40' : r.validationStatus === 'likely' ? 'border-orange-500/40' : 'border-border/50'}`}>
              <CardContent className="py-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {statusIcon(r.validationStatus)}
                    <span className="font-mono text-sm font-bold">{r.subdomain}</span>
                    <Badge className={statusColor(r.validationStatus)}>{(r.validationStatus || '').toUpperCase()}</Badge>
                    <Badge variant="outline" className="text-[10px]">{r.service}</Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-muted-foreground">Confidence:</span>
                    <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${r.confidence >= 80 ? 'bg-red-500' : r.confidence >= 50 ? 'bg-orange-500' : 'bg-amber-500'}`}
                        style={{ width: `${r.confidence}%` }}
                      />
                    </div>
                    <span className="text-xs font-mono font-bold">{r.confidence}%</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-muted-foreground">CNAME Target:</span>
                    <span className="ml-1 font-mono">{r.cnameTarget}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">HTTP Status:</span>
                    <span className="ml-1 font-mono">{r.httpStatusCode || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">DNS Resolves:</span>
                    <span className={`ml-1 ${r.dnsResolves ? 'text-emerald-400' : 'text-red-400'}`}>{r.dnsResolves ? 'Yes' : 'No'}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Fingerprint Match:</span>
                    <span className={`ml-1 ${r.responseContainsFingerprint ? 'text-red-400' : 'text-muted-foreground'}`}>
                      {r.responseContainsFingerprint ? `"${r.fingerprintMatched}"` : 'None'}
                    </span>
                  </div>
                </div>

                {r.exploitabilityNote && (
                  <div className={`text-xs p-2 rounded ${r.validationStatus === 'confirmed' ? 'bg-red-500/10 text-red-300' : r.validationStatus === 'likely' ? 'bg-orange-500/10 text-orange-300' : 'bg-muted/30 text-muted-foreground'}`}>
                    {r.exploitabilityNote}
                  </div>
                )}

                {r.responseSnippet && (
                  <Collapsible>
                    <CollapsibleTrigger className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1">
                      <ChevronDown className="w-3 h-3" /> View Response Snippet
                    </CollapsibleTrigger>
                    <CollapsibleContent>
                      <pre className="text-[10px] bg-black/30 p-2 rounded mt-1 overflow-x-auto max-h-32 text-muted-foreground">
                        {r.responseSnippet}
                      </pre>
                    </CollapsibleContent>
                  </Collapsible>
                )}
              </CardContent>
            </Card>
          ))}

          {/* Re-run Button */}
          <div className="flex justify-center">
            <Button variant="outline" size="sm" onClick={handleValidate} disabled={validateMutation.isPending}>
              {validateMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <RefreshCw className="w-4 h-4 mr-2" />}
              Re-run Validation
            </Button>
          </div>
        </>
      )}

      {/* Methodology */}
      <Card className="bg-muted/20">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Info className="w-4 h-4 text-muted-foreground" />
            PoC Validation Methodology
          </CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-muted-foreground space-y-1">
          <p>Active takeover PoC validation performs real HTTP probes against each candidate:</p>
          <ul className="list-disc list-inside space-y-0.5 ml-2">
            <li><strong>DNS Resolution Check</strong> — Verifies if the subdomain and CNAME target resolve to IP addresses</li>
            <li><strong>HTTPS/HTTP Probe</strong> — Makes requests to the subdomain checking for provider-specific error pages</li>
            <li><strong>Fingerprint Matching</strong> — Compares response body against known cloud provider error signatures (e.g., "NoSuchBucket", "There isn't a GitHub Pages site here")</li>
            <li><strong>Confidence Scoring</strong> — Combines DNS, HTTP, and fingerprint signals into a 0-100 confidence score</li>
            <li><strong>Classification</strong> — Confirmed (95%+), Likely (75-94%), Possible (30-74%), Unlikely (&lt;30%)</li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   Web Crawl Results Tab — surfaces raw crawl data (forms, tech, headers, cookies)
   ═══════════════════════════════════════════════════════════════════════════ */

