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

export default function EmailSecurityTab({ pipeline, domain }: { pipeline: any; domain: string }) {
  const emailSec = pipeline?.emailSecurityReport || pipeline?.emailSecurity;
  const analyzeMut = trpc.emailSecurity.analyzeDomain.useMutation({
    onSuccess: () => toast.success("Email security analysis complete"),
    onError: (err: any) => toast.error(`Analysis failed: ${err.message}`),
  });

  // Use pipeline data or on-demand analysis result
  const report = analyzeMut.data || emailSec;

  const GRADE_COLORS: Record<string, string> = {
    "A+": "text-emerald-400 bg-emerald-500/20 border-emerald-500/40",
    "A": "text-emerald-400 bg-emerald-500/20 border-emerald-500/40",
    "B": "text-blue-400 bg-blue-500/20 border-blue-500/40",
    "C": "text-yellow-400 bg-yellow-500/20 border-yellow-500/40",
    "D": "text-orange-400 bg-orange-500/20 border-orange-500/40",
    "F": "text-red-400 bg-red-500/20 border-red-500/40",
  };

  const SEVERITY_COLORS: Record<string, string> = {
    critical: "text-red-400 bg-red-500/10 border-red-500/30",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
    low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    info: "text-zinc-400 bg-zinc-500/10 border-zinc-500/30",
  };

  const DIFFICULTY_COLORS: Record<string, string> = {
    trivial: "text-red-400",
    easy: "text-orange-400",
    moderate: "text-yellow-400",
    hard: "text-blue-400",
    very_hard: "text-emerald-400",
  };

  if (!report) {
    return (
      <div className="space-y-6">
        <Card className="border-dashed border-zinc-700">
          <CardContent className="p-8 text-center">
            <Mail className="w-12 h-12 mx-auto mb-4 text-muted-foreground/40" />
            <h3 className="text-lg font-semibold mb-2">Email Security Analysis</h3>
            <p className="text-sm text-muted-foreground mb-4 max-w-md mx-auto">
              Analyze SPF, DKIM, DMARC, and MX records for <strong>{domain}</strong> to identify email security weaknesses
              that can be exploited during phishing operations.
            </p>
            <Button
              onClick={() => analyzeMut.mutate({ domain })}
              disabled={analyzeMut.isPending}
              className="bg-blue-600 hover:bg-blue-700"
            >
              {analyzeMut.isPending ? (
                <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Analyzing...</>
              ) : (
                <><Mail className="w-4 h-4 mr-2" />Analyze Email Security</>
              )}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const allWeaknesses = [
    ...(report.spf?.weaknesses || []).map((w: any) => ({ ...w, protocol: "SPF" })),
    ...(report.dkim?.weaknesses || []).map((w: any) => ({ ...w, protocol: "DKIM" })),
    ...(report.dmarc?.weaknesses || []).map((w: any) => ({ ...w, protocol: "DMARC" })),
    ...(report.mx?.weaknesses || []).map((w: any) => ({ ...w, protocol: "MX" })),
  ];

  return (
    <div className="space-y-6">
      {/* Page description */}
      <p className="text-sm text-muted-foreground">
        Email security posture analysis for <strong>{report.domain || domain}</strong>. Weaknesses identified here
        directly inform phishing campaign difficulty and spoofing viability.
      </p>

      {/* Overall Score Card */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className={`${GRADE_COLORS[report.overallGrade] || "border-zinc-500/30"} border`}>
          <CardContent className="p-6 text-center">
            <p className="text-5xl font-bold">{report.overallGrade || "?"}</p>
            <p className="text-sm mt-1 opacity-80">Overall Grade</p>
            <p className="text-xs mt-2 opacity-60">{report.overallScore}/100</p>
          </CardContent>
        </Card>

        <Card className="border-zinc-800">
          <CardContent className="p-6 text-center">
            <Mail className="w-6 h-6 mx-auto mb-2 text-blue-400" />
            <p className="text-2xl font-bold">{report.totalWeaknesses || 0}</p>
            <p className="text-xs text-muted-foreground mt-1">Total Weaknesses</p>
            {report.criticalWeaknesses > 0 && (
              <p className="text-xs text-red-400 mt-1">{report.criticalWeaknesses} critical</p>
            )}
          </CardContent>
        </Card>

        <Card className="border-zinc-800">
          <CardContent className="p-6 text-center">
            <Target className="w-6 h-6 mx-auto mb-2 text-orange-400" />
            <p className={`text-lg font-bold capitalize ${DIFFICULTY_COLORS[report.phishingDifficultyRating] || "text-zinc-400"}`}>
              {(report.phishingDifficultyRating || "unknown").replace(/_/g, " ")}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Phishing Difficulty</p>
          </CardContent>
        </Card>

        <Card className="border-zinc-800">
          <CardContent className="p-6 text-center">
            <Server className="w-6 h-6 mx-auto mb-2 text-purple-400" />
            <p className="text-lg font-bold text-purple-400">{report.mx?.provider || "Unknown"}</p>
            <p className="text-xs text-muted-foreground mt-1">Mail Provider</p>
            <p className="text-xs text-muted-foreground">{report.mx?.records?.length || 0} MX records</p>
          </CardContent>
        </Card>
      </div>

      {/* Phishing Summary */}
      {report.phishingSummary && (
        <Card className="border-orange-500/20 bg-orange-500/5">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-orange-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="font-semibold text-sm text-orange-400 mb-1">Phishing Operations Assessment</h4>
                <p className="text-sm text-zinc-300">{report.phishingSummary}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Protocol Scores */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* SPF */}
        <Card className="border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              {report.spf?.exists ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : <ShieldX className="w-4 h-4 text-red-400" />}
              SPF
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 mb-2">
              <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all ${(report.spf?.score || 0) >= 80 ? "bg-emerald-500" : (report.spf?.score || 0) >= 50 ? "bg-yellow-500" : "bg-red-500"}`}
                  style={{ width: `${report.spf?.score || 0}%` }} />
              </div>
              <span className="text-xs font-bold">{report.spf?.score || 0}</span>
            </div>
            <p className="text-xs text-muted-foreground">
              {report.spf?.exists ? "Record found" : "No SPF record"}
            </p>
            {report.spf?.weaknesses?.length > 0 && (
              <p className="text-xs text-red-400 mt-1">{report.spf.weaknesses.length} weakness{report.spf.weaknesses.length !== 1 ? "es" : ""}</p>
            )}
          </CardContent>
        </Card>

        {/* DKIM */}
        <Card className="border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              {(report.dkim?.selectorsFound?.length || 0) > 0 ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : <ShieldAlert className="w-4 h-4 text-yellow-400" />}
              DKIM
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 mb-2">
              <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all ${(report.dkim?.score || 0) >= 80 ? "bg-emerald-500" : (report.dkim?.score || 0) >= 50 ? "bg-yellow-500" : "bg-red-500"}`}
                  style={{ width: `${report.dkim?.score || 0}%` }} />
              </div>
              <span className="text-xs font-bold">{report.dkim?.score || 0}</span>
            </div>
            <p className="text-xs text-muted-foreground">
              {(report.dkim?.selectorsFound?.length || 0) > 0
                ? `${report.dkim.selectorsFound.length} selector${report.dkim.selectorsFound.length !== 1 ? "s" : ""} found`
                : "No DKIM selectors found"}
            </p>
            {report.dkim?.weaknesses?.length > 0 && (
              <p className="text-xs text-red-400 mt-1">{report.dkim.weaknesses.length} weakness{report.dkim.weaknesses.length !== 1 ? "es" : ""}</p>
            )}
          </CardContent>
        </Card>

        {/* DMARC */}
        <Card className="border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              {report.dmarc?.exists ? (
                report.dmarc?.policy === "reject" ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : <ShieldAlert className="w-4 h-4 text-yellow-400" />
              ) : <ShieldX className="w-4 h-4 text-red-400" />}
              DMARC
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 mb-2">
              <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all ${(report.dmarc?.score || 0) >= 80 ? "bg-emerald-500" : (report.dmarc?.score || 0) >= 50 ? "bg-yellow-500" : "bg-red-500"}`}
                  style={{ width: `${report.dmarc?.score || 0}%` }} />
              </div>
              <span className="text-xs font-bold">{report.dmarc?.score || 0}</span>
            </div>
            <p className="text-xs text-muted-foreground">
              {report.dmarc?.exists ? `Policy: ${report.dmarc.policy || "none"}` : "No DMARC record"}
            </p>
            {report.dmarc?.weaknesses?.length > 0 && (
              <p className="text-xs text-red-400 mt-1">{report.dmarc.weaknesses.length} weakness{report.dmarc.weaknesses.length !== 1 ? "es" : ""}</p>
            )}
          </CardContent>
        </Card>

        {/* MX */}
        <Card className="border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              {(report.mx?.records?.length || 0) > 0 ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
              MX Records
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {(report.mx?.records || []).slice(0, 3).map((mx: any, i: number) => (
                <div key={i} className="text-xs text-zinc-300 flex items-center gap-1">
                  <span className="text-muted-foreground font-mono">{mx.priority}</span>
                  <span className="truncate">{mx.exchange}</span>
                </div>
              ))}
              {(report.mx?.records?.length || 0) === 0 && (
                <p className="text-xs text-muted-foreground">No MX records found</p>
              )}
            </div>
            {report.mx?.weaknesses?.length > 0 && (
              <p className="text-xs text-red-400 mt-2">{report.mx.weaknesses.length} weakness{report.mx.weaknesses.length !== 1 ? "es" : ""}</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* All Weaknesses */}
      {allWeaknesses.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-orange-400" />
              Identified Weaknesses ({allWeaknesses.length})
            </CardTitle>
            <CardDescription>
              Each weakness represents a potential vector for email spoofing, phishing, or impersonation attacks.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {allWeaknesses
              .sort((a: any, b: any) => {
                const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
              })
              .map((w: any, i: number) => (
                <div key={i} className={`p-4 rounded-lg border ${SEVERITY_COLORS[w.severity] || "border-zinc-700"}`}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge variant="outline" className={`text-[10px] ${SEVERITY_COLORS[w.severity] || ""}`}>
                          {(w.severity || "info").toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="text-[10px] border-zinc-600 text-zinc-400">
                          {w.protocol}
                        </Badge>
                      </div>
                      <h4 className="font-medium text-sm">{w.title}</h4>
                      <p className="text-xs text-muted-foreground mt-1">{w.description}</p>
                    </div>
                  </div>
                  {w.phishingRelevance && (
                    <div className="mt-2 p-2 rounded bg-orange-500/5 border border-orange-500/10">
                      <p className="text-xs text-orange-300 flex items-start gap-1.5">
                        <Target className="w-3 h-3 shrink-0 mt-0.5" />
                        <span><strong>Phishing Relevance:</strong> {w.phishingRelevance}</span>
                      </p>
                    </div>
                  )}
                </div>
              ))}
          </CardContent>
        </Card>
      )}

      {/* DNS Records */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Globe className="w-5 h-5 text-blue-400" />
            Raw DNS Records
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {report.spf?.record && (
            <div>
              <p className="text-xs font-semibold text-zinc-400 uppercase mb-1">SPF Record</p>
              <div className="bg-zinc-900 border border-zinc-800 rounded p-3 font-mono text-xs text-emerald-400 break-all">
                {report.spf.record}
              </div>
            </div>
          )}
          {report.dmarc?.record && (
            <div>
              <p className="text-xs font-semibold text-zinc-400 uppercase mb-1">DMARC Record</p>
              <div className="bg-zinc-900 border border-zinc-800 rounded p-3 font-mono text-xs text-blue-400 break-all">
                {report.dmarc.record}
              </div>
            </div>
          )}
          {!report.spf?.record && !report.dmarc?.record && (
            <p className="text-sm text-muted-foreground text-center py-4">No email authentication DNS records found.</p>
          )}
        </CardContent>
      </Card>

      {/* Recommendations */}
      {report.recommendations && report.recommendations.length > 0 && (
        <Card className="border-blue-500/20">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-blue-400" />
              Recommendations
            </CardTitle>
            <CardDescription>
              Steps the target organization should take to improve their email security posture.
              These are also indicators of what will become harder to exploit if remediated.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {report.recommendations.map((rec: string, i: number) => (
                <li key={i} className="flex items-start gap-2 text-sm">
                  <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">
                    {i + 1}
                  </span>
                  <span className="text-zinc-300">{rec}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {/* Re-analyze button */}
      <div className="flex justify-end">
        <Button
          variant="outline"
          size="sm"
          onClick={() => analyzeMut.mutate({ domain })}
          disabled={analyzeMut.isPending}
        >
          {analyzeMut.isPending ? <Loader2 className="w-4 h-4 mr-1 animate-spin" /> : <RefreshCw className="w-4 h-4 mr-1" />}
          Re-analyze Email Security
        </Button>
      </div>
    </div>
  );
}

/* ─── OSINT Sources Catalog Tab ─── */

