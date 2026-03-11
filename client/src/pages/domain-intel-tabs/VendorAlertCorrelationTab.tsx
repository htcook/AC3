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

export default function VendorAlertCorrelationTab({ correlation, domain }: {
  correlation: {
    correlatedAt: number;
    vendorCount: number;
    totalAlerts: number;
    totalIncidents: number;
    results: Array<{
      vendor: string;
      displayName: string;
      category: string;
      alertCount: number;
      incidentCount: number;
      matchedIOCs: number;
      topAlerts: Array<{ id: string; title: string; severity: string }>;
    }>;
  };
  domain: string;
}) {
  const severityColor = (sev: string) => {
    const s = sev?.toLowerCase() || "";
    if (s === "critical") return "bg-red-500/20 text-red-400 border-red-500/30";
    if (s === "high") return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    if (s === "medium" || s === "warning") return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    if (s === "low" || s === "info") return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  };

  const categoryIcon = (cat: string) => {
    const c = cat?.toLowerCase() || "";
    if (c.includes("edr")) return "🛡️";
    if (c.includes("siem")) return "📊";
    if (c.includes("xdr")) return "🔍";
    if (c.includes("soar")) return "⚙️";
    return "🔗";
  };

  const hasData = correlation.totalAlerts > 0 || correlation.totalIncidents > 0;

  return (
    <div className="space-y-6">
      {/* Summary Banner */}
      <Card className="border-cyan-500/20 bg-gradient-to-r from-cyan-950/30 to-blue-950/30">
        <CardContent className="p-6">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-lg font-semibold text-cyan-300 flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Vendor Alert Correlation
              </h3>
              <p className="text-sm text-zinc-400 mt-1">
                Cross-referenced <span className="text-white font-medium">{domain}</span> against{" "}
                <span className="text-cyan-300 font-medium">{correlation.vendorCount}</span> connected EDR/SIEM/XDR vendor(s)
              </p>
            </div>
            <div className="text-right text-xs text-zinc-500">
              Correlated {new Date(correlation.correlatedAt).toLocaleString()}
            </div>
          </div>

          {/* Summary Stats */}
          <div className="grid grid-cols-4 gap-4 mt-5">
            <div className="bg-zinc-900/50 rounded-lg p-3 text-center border border-zinc-800">
              <div className="text-2xl font-bold text-white">{correlation.vendorCount}</div>
              <div className="text-xs text-zinc-400 mt-1">Vendors Queried</div>
            </div>
            <div className={`rounded-lg p-3 text-center border ${correlation.totalAlerts > 0 ? "bg-red-950/30 border-red-500/30" : "bg-zinc-900/50 border-zinc-800"}`}>
              <div className={`text-2xl font-bold ${correlation.totalAlerts > 0 ? "text-red-400" : "text-zinc-500"}`}>{correlation.totalAlerts}</div>
              <div className="text-xs text-zinc-400 mt-1">Correlated Alerts</div>
            </div>
            <div className={`rounded-lg p-3 text-center border ${correlation.totalIncidents > 0 ? "bg-orange-950/30 border-orange-500/30" : "bg-zinc-900/50 border-zinc-800"}`}>
              <div className={`text-2xl font-bold ${correlation.totalIncidents > 0 ? "text-orange-400" : "text-zinc-500"}`}>{correlation.totalIncidents}</div>
              <div className="text-xs text-zinc-400 mt-1">Correlated Incidents</div>
            </div>
            <div className="bg-zinc-900/50 rounded-lg p-3 text-center border border-zinc-800">
              <div className="text-2xl font-bold text-emerald-400">{correlation.results.filter(r => r.alertCount === 0 && r.incidentCount === 0).length}</div>
              <div className="text-xs text-zinc-400 mt-1">Clean Vendors</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Detection Coverage Assessment */}
      {hasData && (
        <Card className="border-amber-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2 text-amber-300">
              <AlertTriangle className="h-4 w-4" />
              Detection Assessment
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-zinc-300">
              {correlation.totalAlerts > 0 && (
                <>
                  <span className="text-red-400 font-medium">{correlation.totalAlerts} alert(s)</span> were detected across your connected security stack for this domain.
                  This indicates the domain has triggered security detections in your environment.{" "}
                </>
              )}
              {correlation.totalIncidents > 0 && (
                <>
                  <span className="text-orange-400 font-medium">{correlation.totalIncidents} incident(s)</span> have been correlated,
                  suggesting active investigation or automated response may be in progress.{" "}
                </>
              )}
              Review the vendor-specific details below for remediation context.
            </p>
          </CardContent>
        </Card>
      )}

      {!hasData && (
        <Card className="border-emerald-500/20">
          <CardContent className="p-6 text-center">
            <CheckCircle className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
            <h4 className="text-sm font-medium text-emerald-300">No Correlated Alerts</h4>
            <p className="text-xs text-zinc-400 mt-1">
              No alerts or incidents matching <span className="text-white">{domain}</span> were found across your {correlation.vendorCount} connected vendor(s).
              This domain has not triggered any detections in your security stack within the last 30 days.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Per-Vendor Results */}
      <div className="space-y-4">
        <h4 className="text-sm font-medium text-zinc-300">Vendor Breakdown</h4>
        {correlation.results.map((vendor, idx) => (
          <Card key={idx} className={`border ${vendor.alertCount > 0 || vendor.incidentCount > 0 ? "border-amber-500/20" : "border-zinc-800"}`}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2">
                  <span className="text-lg">{categoryIcon(vendor.category)}</span>
                  <span className="text-white">{vendor.displayName}</span>
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-zinc-700 text-zinc-400">
                    {vendor.category}
                  </Badge>
                </CardTitle>
                <div className="flex items-center gap-3 text-xs">
                  <span className={vendor.alertCount > 0 ? "text-red-400 font-medium" : "text-zinc-500"}>
                    {vendor.alertCount} alert{vendor.alertCount !== 1 ? "s" : ""}
                  </span>
                  <span className={vendor.incidentCount > 0 ? "text-orange-400 font-medium" : "text-zinc-500"}>
                    {vendor.incidentCount} incident{vendor.incidentCount !== 1 ? "s" : ""}
                  </span>
                </div>
              </div>
            </CardHeader>

            {vendor.topAlerts.length > 0 && (
              <CardContent className="pt-0">
                <div className="space-y-2">
                  <div className="text-xs text-zinc-500 font-medium uppercase tracking-wider">Top Alerts</div>
                  {vendor.topAlerts.map((alert, aidx) => (
                    <div key={aidx} className="flex items-center gap-3 bg-zinc-900/50 rounded-md px-3 py-2 border border-zinc-800">
                      <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${severityColor(alert.severity)}`}>
                        {alert.severity || "Unknown"}
                      </Badge>
                      <span className="text-sm text-zinc-300 flex-1 truncate">{alert.title}</span>
                      <span className="text-[10px] text-zinc-600 font-mono">{alert.id}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            )}

            {vendor.alertCount === 0 && vendor.incidentCount === 0 && (
              <CardContent className="pt-0">
                <div className="flex items-center gap-2 text-xs text-emerald-400/70">
                  <CheckCircle className="h-3.5 w-3.5" />
                  No domain-related detections in the last 30 days
                </div>
              </CardContent>
            )}
          </Card>
        ))}
      </div>

      {/* Timeline placeholder */}
      <Card className="border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2 text-zinc-400">
            <Clock className="h-4 w-4" />
            Alert Timeline
          </CardTitle>
        </CardHeader>
        <CardContent>
          {hasData ? (
            <div className="space-y-2">
              {correlation.results.flatMap(v =>
                v.topAlerts.map(a => ({
                  ...a,
                  vendor: v.displayName,
                  category: v.category,
                }))
              ).map((alert, tidx) => (
                <div key={tidx} className="flex items-center gap-3 text-xs">
                  <div className="w-2 h-2 rounded-full bg-red-400 shrink-0" />
                  <Badge variant="outline" className={`text-[9px] px-1 py-0 ${severityColor(alert.severity)}`}>
                    {alert.severity}
                  </Badge>
                  <span className="text-zinc-400">{alert.vendor}</span>
                  <span className="text-zinc-300 truncate flex-1">{alert.title}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-zinc-500 text-center py-4">No alerts to display in timeline</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

