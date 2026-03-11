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

export default function TakeoverTab({ scanId }: { scanId: number }) {
  const { data, isLoading, error } = trpc.domainIntel.takeoverDetection.useQuery({ scanId });

  if (isLoading) return (
    <Card><CardContent className="flex items-center justify-center py-16">
      <Loader2 className="w-6 h-6 animate-spin text-cyan-400 mr-3" />
      <span className="text-muted-foreground">Checking for dangling DNS records and takeover vulnerabilities...</span>
    </CardContent></Card>
  );

  if (error) return (
    <Card><CardContent className="py-8 text-center">
      <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto mb-2" />
      <p className="text-sm text-muted-foreground">{error.message}</p>
    </CardContent></Card>
  );

  if (!data) return null;

  const d = data as any;
  const candidates = (d.takeoverCandidates || []) as any[];
  const summary = d.summary || {};
  const serviceBreakdown = d.serviceBreakdown || [];

  const criticalCandidates = candidates.filter((c: any) => c.severity === 'critical');
  const highCandidates = candidates.filter((c: any) => c.severity === 'high');
  const mediumCandidates = candidates.filter((c: any) => c.severity === 'medium');

  return (
    <div className="space-y-4">
      {/* Page Purpose */}
      <p className="text-sm text-muted-foreground">
        Detects dangling DNS records (CNAME, A, AAAA) pointing to deprovisioned cloud services that could enable subdomain takeover attacks. Checks for unclaimed S3 buckets, Azure, Heroku, GitHub Pages, and other common cloud providers.
      </p>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="bg-muted/30 border-border/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-cyan-400">{summary.totalSubdomainsChecked || 0}</div>
            <div className="text-[11px] text-muted-foreground">Subdomains Checked</div>
          </CardContent>
        </Card>
        <Card className={`${candidates.length > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-emerald-500/10 border-emerald-500/30'}`}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold ${candidates.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>{candidates.length}</div>
            <div className="text-[11px] text-muted-foreground">Takeover Candidates</div>
          </CardContent>
        </Card>
        <Card className={`${criticalCandidates.length > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-muted/30 border-border/50'}`}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold ${criticalCandidates.length > 0 ? 'text-red-400' : 'text-muted-foreground'}`}>{criticalCandidates.length}</div>
            <div className="text-[11px] text-muted-foreground">Critical</div>
          </CardContent>
        </Card>
        <Card className={`${highCandidates.length > 0 ? 'bg-orange-500/10 border-orange-500/30' : 'bg-muted/30 border-border/50'}`}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold ${highCandidates.length > 0 ? 'text-orange-400' : 'text-muted-foreground'}`}>{highCandidates.length}</div>
            <div className="text-[11px] text-muted-foreground">High</div>
          </CardContent>
        </Card>
        <Card className="bg-muted/30 border-border/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-purple-400">{summary.servicesChecked || 0}</div>
            <div className="text-[11px] text-muted-foreground">Services Checked</div>
          </CardContent>
        </Card>
      </div>

      {/* No Vulnerabilities */}
      {candidates.length === 0 && (
        <Card className="bg-emerald-500/5 border-emerald-500/30">
          <CardContent className="flex items-center justify-center py-8">
            <ShieldCheck className="w-6 h-6 text-emerald-400 mr-3" />
            <span className="text-emerald-300">No subdomain takeover vulnerabilities detected. All DNS records point to active services.</span>
          </CardContent>
        </Card>
      )}

      {/* Takeover Candidates */}
      {candidates.length > 0 && (
        <div className="space-y-3">
          {candidates.map((c: any, i: number) => (
            <Card key={i} className={`${
              c.severity === 'critical' ? 'border-red-500/40 bg-red-500/5' :
              c.severity === 'high' ? 'border-orange-500/40 bg-orange-500/5' :
              'border-amber-500/40 bg-amber-500/5'
            }`}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <ShieldAlert className={`w-5 h-5 ${
                      c.severity === 'critical' ? 'text-red-400' :
                      c.severity === 'high' ? 'text-orange-400' :
                      'text-amber-400'
                    }`} />
                    <div>
                      <span className="font-mono text-sm text-cyan-400">{c.subdomain}</span>
                      <div className="flex items-center gap-2 mt-0.5">
                        <Badge variant="outline" className={`text-[10px] ${
                          c.severity === 'critical' ? 'text-red-400 border-red-500/40' :
                          c.severity === 'high' ? 'text-orange-400 border-orange-500/40' :
                          'text-amber-400 border-amber-500/40'
                        }`}>{c.severity}</Badge>
                        <Badge variant="outline" className="text-[10px] text-purple-400 border-purple-500/40">{c.service}</Badge>
                        <Badge variant="outline" className="text-[10px]">{c.recordType}</Badge>
                      </div>
                    </div>
                  </div>
                  {c.confidence && (
                    <div className="text-right">
                      <div className="text-lg font-bold text-muted-foreground">{c.confidence}%</div>
                      <div className="text-[10px] text-muted-foreground">Confidence</div>
                    </div>
                  )}
                </div>

                {/* DNS Record Details */}
                <div className="mt-3 p-2 rounded bg-muted/20 border border-border/30">
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-muted-foreground">Record Type:</span>
                      <span className="ml-2 font-mono">{c.recordType}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Points To:</span>
                      <span className="ml-2 font-mono text-amber-400">{c.pointsTo}</span>
                    </div>
                    {c.service && (
                      <div>
                        <span className="text-muted-foreground">Service:</span>
                        <span className="ml-2">{c.service}</span>
                      </div>
                    )}
                    {c.reason && (
                      <div className="col-span-2">
                        <span className="text-muted-foreground">Reason:</span>
                        <span className="ml-2">{c.reason}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Evidence */}
                {c.evidence?.length > 0 && (
                  <div className="mt-2">
                    <span className="text-[10px] text-muted-foreground font-medium">Evidence:</span>
                    <ul className="mt-1 space-y-1">
                      {c.evidence.map((e: string, j: number) => (
                        <li key={j} className="text-xs text-muted-foreground flex items-start gap-1.5">
                          <span className="text-amber-400 mt-0.5">•</span> {e}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Remediation */}
                <div className="mt-3 p-2 rounded bg-blue-500/5 border border-blue-500/20">
                  <p className="text-xs text-blue-300">
                    <strong>Remediation:</strong> {c.remediation || `Remove the dangling ${c.recordType} record for ${c.subdomain} or reclaim the ${c.service} resource.`}
                  </p>
                </div>

                {/* MITRE ATT&CK Mapping */}
                {c.mitreAttack && (
                  <div className="mt-2 flex items-center gap-2">
                    <span className="text-[10px] text-muted-foreground">MITRE ATT&CK:</span>
                    <Badge variant="outline" className="text-[10px] font-mono text-cyan-400">{c.mitreAttack}</Badge>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Service Breakdown */}
      {serviceBreakdown.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-400" />
              Service Provider Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {serviceBreakdown.map((s: any, i: number) => (
                <div key={i} className="p-2 rounded-lg bg-muted/20 border border-border/30 text-center">
                  <div className="text-sm font-medium">{s.service}</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {s.total} checked · <span className={s.vulnerable > 0 ? 'text-red-400' : 'text-emerald-400'}>{s.vulnerable} vulnerable</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Methodology */}
      <Card className="bg-muted/20">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Info className="w-4 h-4 text-muted-foreground" />
            Detection Methodology
          </CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-muted-foreground space-y-1">
          <p>The takeover detection engine analyzes DNS records for patterns indicating deprovisioned cloud resources:</p>
          <ul className="list-disc list-inside space-y-0.5 ml-2">
            <li>CNAME records pointing to unclaimed cloud service endpoints (S3, Azure, Heroku, GitHub Pages, Fastly, etc.)</li>
            <li>A/AAAA records resolving to IP ranges of cloud providers with no active HTTP response</li>
            <li>NS delegation to nameservers that no longer exist or respond</li>
            <li>MX records pointing to decommissioned mail services</li>
            <li>Wildcard DNS configurations that may enable mass subdomain takeover</li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════
// CVE-to-Threat-Actor Enrichment Tab
// ═══════════════════════════════════════════════════════════════════════════

