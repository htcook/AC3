// @ts-nocheck
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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

export default function OsintSourcesTab() {
  const catalog = trpc.domainIntel.getConnectorCatalog.useQuery();

  const categoryIcons: Record<string, any> = {
    infrastructure: Server,
    dns: Globe,
    certificates: Lock,
    breaches: Skull,
    threat_intel: Shield,
    email: Mail,
    web_archive: Clock,
    attack_surface: Target,
    social: Users,
    reputation: ShieldAlert,
  };

  const categoryLabels: Record<string, string> = {
    infrastructure: "Infrastructure Recon",
    dns: "DNS & Domain Intelligence",
    certificates: "Certificate Transparency",
    breaches: "Breach & Credential Data",
    threat_intel: "Threat Intelligence Feeds",
    email: "Email Discovery",
    web_archive: "Web Archive & History",
    attack_surface: "Attack Surface Mapping",
    social: "Social & Username OSINT",
    reputation: "IP & Domain Reputation",
  };

  if (catalog.isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        <span className="ml-2 text-muted-foreground">Loading connector catalog...</span>
      </div>
    );
  }

  const connectors = catalog.data?.connectors || [];
  const grouped = connectors.reduce((acc: Record<string, any[]>, c: any) => {
    const cat = c.category || "other";
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(c);
    return acc;
  }, {});

  const totalConnectors = connectors.length;
  const configuredCount = connectors.filter((c: any) => c.configured).length;
  const freeCount = connectors.filter((c: any) => !c.requiresApiKey).length;
  const paidCount = connectors.filter((c: any) => c.requiresApiKey).length;

  return (
    <div className="space-y-6">
      {/* Summary Header */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-primary" />
            OSINT Source Catalog
          </CardTitle>
          <CardDescription>
            {totalConnectors} reconnaissance modules across {Object.keys(grouped).length} categories — {configuredCount} configured, {freeCount} free, {paidCount} require API keys
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-3 rounded-lg bg-primary/10 border border-primary/20">
              <div className="text-2xl font-bold text-primary">{totalConnectors}</div>
              <div className="text-xs text-muted-foreground">Total Sources</div>
            </div>
            <div className="text-center p-3 rounded-lg bg-green-500/10 border border-green-500/20">
              <div className="text-2xl font-bold text-green-400">{configuredCount}</div>
              <div className="text-xs text-muted-foreground">Configured</div>
            </div>
            <div className="text-center p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
              <div className="text-2xl font-bold text-blue-400">{freeCount}</div>
              <div className="text-xs text-muted-foreground">Free / No Key</div>
            </div>
            <div className="text-center p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
              <div className="text-2xl font-bold text-amber-400">{paidCount}</div>
              <div className="text-xs text-muted-foreground">Require API Key</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Connectors by Category */}
      {Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b)).map(([category, items]) => {
        const Icon = categoryIcons[category] || Database;
        const label = categoryLabels[category] || category.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
        return (
          <Card key={category}>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Icon className="w-4 h-4 text-muted-foreground" />
                {label}
                <Badge variant="outline" className="ml-auto text-xs">{(items as any[]).length} sources</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {(items as any[]).map((connector: any) => (
                  <div
                    key={connector.id}
                    className={`p-3 rounded-lg border transition-colors ${
                      connector.configured
                        ? "border-green-500/30 bg-green-500/5"
                        : connector.requiresApiKey
                        ? "border-amber-500/20 bg-amber-500/5 opacity-70"
                        : "border-border bg-card"
                    }`}
                  >
                    <div className="flex items-start justify-between mb-1">
                      <span className="font-medium text-sm">{connector.name}</span>
                      <div className="flex items-center gap-1">
                        {connector.configured ? (
                          <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-[10px] px-1.5">
                            <Wifi className="w-3 h-3 mr-0.5" /> Active
                          </Badge>
                        ) : connector.requiresApiKey ? (
                          <Badge variant="outline" className="text-amber-400 border-amber-500/30 text-[10px] px-1.5">
                            <Unplug className="w-3 h-3 mr-0.5" /> Needs Key
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-blue-400 border-blue-500/30 text-[10px] px-1.5">
                            Free
                          </Badge>
                        )}
                      </div>
                    </div>
                    <p className="text-xs text-muted-foreground line-clamp-2">{connector.description}</p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {(connector.entityTypes || []).map((et: string) => (
                        <span key={et} className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                          {et}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

/* ─── Recursive Discovery / Spider Tab ─── */

