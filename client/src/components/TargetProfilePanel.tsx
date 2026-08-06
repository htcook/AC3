/**
 * TargetProfilePanel — Displays context-aware scanner results per asset.
 *
 * Shows WAF/CDN/firewall detection, infrastructure topology, tech fingerprint,
 * evasion profile, and recommended scan strategy for each profiled target.
 * Includes real-time evasion escalation controls when scans are blocked.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX, ShieldOff,
  Globe, Server, Database, Cloud, CloudOff,
  Lock, Unlock, Eye, Fingerprint, Layers, Network,
  ChevronDown, ChevronUp, AlertTriangle, CheckCircle2,
  Zap, Activity, Gauge, Timer, ArrowUpRight,
  Cpu, Code, Monitor, Radio, Wifi, WifiOff,
} from "lucide-react";
import { toast } from "sonner";

// ─── Types ──────────────────────────────────────────────────────────────────

interface TargetProfileData {
  hostname: string;
  ips: string[];
  fingerprint: {
    serverHeader: string | null;
    webServer: string | null;
    appFramework: string | null;
    cms: string | null;
    os: string | null;
    tls: { version: string; cipher: string } | null;
    languages: string[];
    jsFrameworks: string[];
    databases: string[];
    techTags: string[];
    serviceBanners: Record<string, string>;
  };
  waf: {
    detected: boolean;
    vendor: string;
    type: string;
    confidence: number;
    bypassTechniques: string[];
  };
  cdn: {
    detected: boolean;
    provider: string;
    edgeServers: string[];
    originDiscoveryMethods: string[];
  };
  firewall: {
    detected: boolean;
    type: string;
    filteredPorts: number[];
    rateLimiting: { detected: boolean; requestsPerSecond?: number };
  };
  topology: {
    role: string;
    confidence: number;
    backend: string | null;
    services: string[];
  };
  environment: string;
  riskProfile: string;
  evasionProfile: {
    name: string;
    rateLimit: number;
    delayMs: number;
    randomizeOrder: boolean;
    userAgentStrategy: string;
    chunkedTransfer: boolean;
    useHttp2: boolean;
    ipRotation: string;
    encodingTricks?: string[];
    wafBypassPayloads?: string[];
  } | null;
  scanStrategy: {
    name: string;
    riskLevel: string;
    estimatedTimeMinutes: number;
    phases: Array<{
      name: string;
      order: number;
      purpose: string;
      requiresApproval: boolean;
      tools: Array<{ tool: string; purpose: string }>;
    }>;
  } | null;
  profiledAt: number;
  evasionEscalation: {
    currentLevel: number;
    maxLevel: number;
    reason: string;
    action: string;
    escalatedAt: number;
    cooldownUntil: number;
    history: Array<{
      level: number;
      reason: string;
      timestamp: number;
      action: string;
    }>;
    adaptations: Array<{
      type: string;
      description: string;
      applied: boolean;
      appliedAt?: number;
    }>;
  } | null;
}

interface TargetProfilePanelProps {
  engagementId: number;
  isRunning: boolean;
}

// ─── Sub-components ─────────────────────────────────────────────────────────

function WAFBadge({ waf }: { waf: TargetProfileData["waf"] }) {
  if (!waf.detected) {
    return (
      <Badge variant="outline" className="gap-1 text-emerald-400 border-emerald-400/30 bg-emerald-400/5">
        <ShieldOff className="h-3 w-3" /> No WAF
      </Badge>
    );
  }
  const color = waf.confidence >= 80 ? "text-red-400 border-red-400/30 bg-red-400/5" :
    waf.confidence >= 50 ? "text-amber-400 border-amber-400/30 bg-amber-400/5" :
      "text-yellow-400 border-yellow-400/30 bg-yellow-400/5";
  return (
    <Badge variant="outline" className={`gap-1 ${color}`}>
      <ShieldAlert className="h-3 w-3" /> {waf.vendor} ({waf.confidence}%)
    </Badge>
  );
}

function CDNBadge({ cdn }: { cdn: TargetProfileData["cdn"] }) {
  if (!cdn.detected) {
    return (
      <Badge variant="outline" className="gap-1 text-zinc-400 border-zinc-400/30 bg-zinc-400/5">
        <CloudOff className="h-3 w-3" /> No CDN
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="gap-1 text-blue-400 border-blue-400/30 bg-blue-400/5">
      <Cloud className="h-3 w-3" /> {cdn.provider}
    </Badge>
  );
}

function TopologyBadge({ topology }: { topology: TargetProfileData["topology"] }) {
  const roleIcons: Record<string, React.ReactNode> = {
    reverse_proxy: <Layers className="h-3 w-3" />,
    web_server: <Globe className="h-3 w-3" />,
    api_gateway: <Network className="h-3 w-3" />,
    load_balancer: <Activity className="h-3 w-3" />,
    app_server: <Server className="h-3 w-3" />,
    cdn_edge: <Cloud className="h-3 w-3" />,
    waf_appliance: <Shield className="h-3 w-3" />,
  };
  const roleLabels: Record<string, string> = {
    reverse_proxy: "Reverse Proxy",
    web_server: "Web Server",
    api_gateway: "API Gateway",
    load_balancer: "Load Balancer",
    app_server: "App Server",
    cdn_edge: "CDN Edge",
    waf_appliance: "WAF Appliance",
  };
  return (
    <Badge variant="outline" className="gap-1 text-purple-400 border-purple-400/30 bg-purple-400/5">
      {roleIcons[topology.role] || <Server className="h-3 w-3" />}
      {roleLabels[topology.role] || topology.role}
      {topology.confidence > 0 && <span className="text-[10px] opacity-60">({topology.confidence}%)</span>}
    </Badge>
  );
}

function EvasionLevelGauge({ level, maxLevel = 5 }: { level: number; maxLevel?: number }) {
  const colors = ["", "bg-emerald-500", "bg-yellow-500", "bg-amber-500", "bg-orange-500", "bg-red-500"];
  const labels = ["", "Normal", "Cautious", "Moderate", "Aggressive", "Stealth"];
  return (
    <div className="flex items-center gap-2">
      <div className="flex gap-0.5">
        {Array.from({ length: maxLevel }, (_, i) => (
          <div
            key={i}
            className={`h-3 w-5 rounded-sm ${i < level ? colors[level] : "bg-zinc-700/50"}`}
          />
        ))}
      </div>
      <span className="text-xs font-medium text-muted-foreground">
        L{level} — {labels[level] || "Unknown"}
      </span>
    </div>
  );
}

function FingerprintSection({ fingerprint }: { fingerprint: TargetProfileData["fingerprint"] }) {
  const items: Array<{ label: string; value: string | null; icon: React.ReactNode }> = [
    { label: "Web Server", value: fingerprint.webServer, icon: <Globe className="h-3.5 w-3.5 text-blue-400" /> },
    { label: "App Framework", value: fingerprint.appFramework, icon: <Code className="h-3.5 w-3.5 text-purple-400" /> },
    { label: "CMS", value: fingerprint.cms, icon: <Monitor className="h-3.5 w-3.5 text-cyan-400" /> },
    { label: "OS", value: fingerprint.os, icon: <Cpu className="h-3.5 w-3.5 text-amber-400" /> },
  ];

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2">
        {items.map(({ label, value, icon }) => value && (
          <div key={label} className="flex items-center gap-2 p-2 rounded-md bg-zinc-800/50 border border-zinc-700/30">
            {icon}
            <div className="min-w-0">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
              <div className="text-xs font-medium text-foreground truncate">{value}</div>
            </div>
          </div>
        ))}
      </div>

      {fingerprint.tls && (
        <div className="flex items-center gap-2 p-2 rounded-md bg-zinc-800/50 border border-zinc-700/30">
          <Lock className="h-3.5 w-3.5 text-emerald-400" />
          <div className="min-w-0">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">TLS</div>
            <div className="text-xs font-medium text-foreground">{fingerprint.tls.version} — {fingerprint.tls.cipher}</div>
          </div>
        </div>
      )}

      {(fingerprint.languages.length > 0 || fingerprint.jsFrameworks.length > 0 || fingerprint.databases.length > 0) && (
        <div className="flex flex-wrap gap-1">
          {fingerprint.languages.map(l => (
            <Badge key={l} variant="outline" className="text-[10px] text-cyan-300 border-cyan-400/20 bg-cyan-400/5">{l}</Badge>
          ))}
          {fingerprint.jsFrameworks.map(f => (
            <Badge key={f} variant="outline" className="text-[10px] text-yellow-300 border-yellow-400/20 bg-yellow-400/5">{f}</Badge>
          ))}
          {fingerprint.databases.map(d => (
            <Badge key={d} variant="outline" className="text-[10px] text-orange-300 border-orange-400/20 bg-orange-400/5">{d}</Badge>
          ))}
        </div>
      )}

      {fingerprint.techTags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {fingerprint.techTags.slice(0, 12).map(t => (
            <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>
          ))}
          {fingerprint.techTags.length > 12 && (
            <Badge variant="secondary" className="text-[10px]">+{fingerprint.techTags.length - 12} more</Badge>
          )}
        </div>
      )}
    </div>
  );
}

function ScanStrategySection({ strategy }: { strategy: NonNullable<TargetProfileData["scanStrategy"]> }) {
  const [expanded, setExpanded] = useState(false);
  const riskColors: Record<string, string> = {
    low: "text-emerald-400",
    medium: "text-amber-400",
    high: "text-red-400",
  };

  return (
    <Collapsible open={expanded} onOpenChange={setExpanded}>
      <CollapsibleTrigger asChild>
        <button className="w-full flex items-center justify-between p-2 rounded-md bg-zinc-800/50 border border-zinc-700/30 hover:bg-zinc-800/80 transition-colors">
          <div className="flex items-center gap-2">
            <Gauge className="h-3.5 w-3.5 text-cyan-400" />
            <span className="text-xs font-medium">{strategy.name}</span>
            <Badge variant="outline" className={`text-[10px] ${riskColors[strategy.riskLevel] || "text-zinc-400"}`}>
              {strategy.riskLevel} risk
            </Badge>
            <span className="text-[10px] text-muted-foreground">~{strategy.estimatedTimeMinutes}min</span>
          </div>
          {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent className="mt-2 space-y-1.5">
        {strategy.phases.map((phase, i) => (
          <div key={i} className="flex items-start gap-2 p-2 rounded-md bg-zinc-900/50 border border-zinc-700/20">
            <div className="flex-none mt-0.5">
              <div className={`h-5 w-5 rounded-full flex items-center justify-center text-[10px] font-bold ${phase.requiresApproval ? "bg-amber-500/20 text-amber-400 border border-amber-500/30" : "bg-zinc-700/50 text-zinc-400"}`}>
                {phase.order}
              </div>
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">
                <span className="text-xs font-medium">{phase.name}</span>
                {phase.requiresApproval && (
                  <Badge variant="outline" className="text-[9px] text-amber-400 border-amber-400/30">Approval</Badge>
                )}
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">{phase.purpose}</div>
              {phase.tools.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {phase.tools.map((t, j) => (
                    <TooltipProvider key={j}>
                      <Tooltip>
                        <TooltipTrigger>
                          <Badge variant="secondary" className="text-[9px] cursor-help">{t.tool}</Badge>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="max-w-xs">
                          <p className="text-xs">{t.purpose}</p>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
      </CollapsibleContent>
    </Collapsible>
  );
}

function EvasionEscalationSection({
  escalation,
  engagementId,
  hostname,
}: {
  escalation: NonNullable<TargetProfileData["evasionEscalation"]>;
  engagementId: number;
  hostname: string;
}) {
  const [escalateReason, setEscalateReason] = useState<string>("manual");
  const escalateMut = trpc.engagementOps.escalateEvasion.useMutation({
    onSuccess: (data) => {
      toast.success(`Evasion escalated to Level ${data.escalation.currentLevel}`);
    },
    onError: (err) => {
      toast.error(`Escalation failed: ${err.message}`);
    },
  });

  const isCoolingDown = escalation.cooldownUntil > Date.now();
  const cooldownRemaining = isCoolingDown ? Math.ceil((escalation.cooldownUntil - Date.now()) / 1000) : 0;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <EvasionLevelGauge level={escalation.currentLevel} maxLevel={escalation.maxLevel} />
        {isCoolingDown && (
          <Badge variant="outline" className="text-[10px] text-amber-400 border-amber-400/30 gap-1">
            <Timer className="h-3 w-3" /> Cooldown: {cooldownRemaining}s
          </Badge>
        )}
      </div>

      <div className="text-xs text-muted-foreground">{escalation.action}</div>

      {escalation.adaptations.length > 0 && (
        <div className="space-y-1">
          {escalation.adaptations.map((a, i) => (
            <div key={i} className="flex items-center gap-2 text-[10px]">
              {a.applied ? (
                <CheckCircle2 className="h-3 w-3 text-emerald-400 flex-none" />
              ) : (
                <AlertTriangle className="h-3 w-3 text-amber-400 flex-none" />
              )}
              <span className="text-muted-foreground">{a.description}</span>
            </div>
          ))}
        </div>
      )}

      {escalation.history.length > 0 && (
        <Collapsible>
          <CollapsibleTrigger asChild>
            <button className="text-[10px] text-muted-foreground hover:text-foreground flex items-center gap-1">
              <ChevronDown className="h-3 w-3" /> Escalation History ({escalation.history.length})
            </button>
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-1 space-y-1">
            {escalation.history.map((ev, i) => (
              <div key={i} className="flex items-center gap-2 text-[10px] p-1.5 rounded bg-zinc-900/50">
                <Badge variant="outline" className="text-[9px]">L{ev.level}</Badge>
                <span className="text-muted-foreground">{ev.reason}</span>
                <span className="text-muted-foreground ml-auto">{new Date(ev.timestamp).toLocaleTimeString()}</span>
              </div>
            ))}
          </CollapsibleContent>
        </Collapsible>
      )}

      {escalation.currentLevel < escalation.maxLevel && (
        <div className="flex items-center gap-2 pt-1">
          <Select value={escalateReason} onValueChange={setEscalateReason}>
            <SelectTrigger className="h-7 text-xs w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="manual">Manual</SelectItem>
              <SelectItem value="waf_block">WAF Block</SelectItem>
              <SelectItem value="rate_limit">Rate Limit</SelectItem>
              <SelectItem value="connection_reset">Conn Reset</SelectItem>
              <SelectItem value="captcha">CAPTCHA</SelectItem>
              <SelectItem value="ip_ban">IP Ban</SelectItem>
            </SelectContent>
          </Select>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs text-amber-400 border-amber-400/30 hover:bg-amber-400/10"
            disabled={isCoolingDown || escalateMut.isPending}
            onClick={() => {
              escalateMut.mutate({
                engagementId,
                hostname,
                reason: escalateReason as any,
              });
            }}
          >
            <ArrowUpRight className="h-3 w-3 mr-1" />
            Escalate
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────

export default function TargetProfilePanel({ engagementId, isRunning }: TargetProfilePanelProps) {
  const profilesQ = trpc.engagementOps.getTargetProfiles.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: isRunning ? 15000 : 60000 }
  );

  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    fingerprint: true,
    boundary: true,
    topology: true,
    evasion: true,
    strategy: false,
  });

  const profiles = useMemo(() => {
    if (!profilesQ.data?.profiles) return {};
    return profilesQ.data.profiles as Record<string, TargetProfileData>;
  }, [profilesQ.data]);

  const hostnames = useMemo(() => Object.keys(profiles), [profiles]);
  const activeHost = selectedHost || hostnames[0] || null;
  const activeProfile = activeHost ? profiles[activeHost] : null;

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  if (profilesQ.isLoading) {
    return (
      <div className="flex items-center justify-center p-8 text-muted-foreground">
        <Activity className="h-4 w-4 animate-spin mr-2" /> Loading target profiles...
      </div>
    );
  }

  if (!profilesQ.data?.hasProfiles || hostnames.length === 0) {
    return (
      <Card className="bg-zinc-900/50 border-zinc-700/30">
        <CardContent className="p-6">
          <div className="flex flex-col items-center gap-3 text-center">
            <Fingerprint className="h-8 w-8 text-zinc-500" />
            <div>
              <p className="text-sm font-medium text-muted-foreground">No Target Profiles Yet</p>
              <p className="text-xs text-muted-foreground/60 mt-1">
                Target profiles are generated during Active Discovery (Phase A.6) after httpx probing completes.
                Start an active scan to build WAF, CDN, and infrastructure profiles for each asset.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Page description */}
      <p className="text-xs text-muted-foreground">
        Context-aware scanner results showing detected boundary protections, infrastructure topology,
        technology fingerprints, and adaptive evasion profiles for each target asset.
      </p>

      {/* Host selector */}
      {hostnames.length > 1 && (
        <div className="flex flex-wrap gap-1.5">
          {hostnames.map(host => {
            const p = profiles[host];
            return (
              <button
                key={host}
                onClick={() => setSelectedHost(host)}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors border ${
                  host === activeHost
                    ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400"
                    : "bg-zinc-800/50 border-zinc-700/30 text-muted-foreground hover:bg-zinc-800/80"
                }`}
              >
                <Globe className="h-3 w-3" />
                {host}
                {p.waf.detected && <ShieldAlert className="h-3 w-3 text-red-400" />}
                {p.cdn.detected && <Cloud className="h-3 w-3 text-blue-400" />}
              </button>
            );
          })}
        </div>
      )}

      {activeProfile && (
        <div className="space-y-3">
          {/* Summary badges row */}
          <div className="flex flex-wrap gap-2">
            <WAFBadge waf={activeProfile.waf} />
            <CDNBadge cdn={activeProfile.cdn} />
            <TopologyBadge topology={activeProfile.topology} />
            <Badge variant="outline" className="gap-1 text-zinc-400 border-zinc-400/30 bg-zinc-400/5">
              <Gauge className="h-3 w-3" /> {activeProfile.riskProfile}
            </Badge>
            <Badge variant="outline" className="gap-1 text-zinc-400 border-zinc-400/30 bg-zinc-400/5">
              {activeProfile.environment}
            </Badge>
            {activeProfile.profiledAt && (
              <span className="text-[10px] text-muted-foreground/50 self-center ml-auto">
                Profiled {new Date(activeProfile.profiledAt).toLocaleTimeString()}
              </span>
            )}
          </div>

          {/* Fingerprint Section */}
          <Collapsible open={expandedSections.fingerprint} onOpenChange={() => toggleSection("fingerprint")}>
            <CollapsibleTrigger asChild>
              <button className="w-full flex items-center justify-between py-1.5">
                <div className="flex items-center gap-2">
                  <Fingerprint className="h-4 w-4 text-cyan-400" />
                  <span className="text-sm font-semibold">Technology Fingerprint</span>
                </div>
                {expandedSections.fingerprint ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <FingerprintSection fingerprint={activeProfile.fingerprint} />
            </CollapsibleContent>
          </Collapsible>

          <Separator className="bg-zinc-700/30" />

          {/* Boundary Protection Section */}
          <Collapsible open={expandedSections.boundary} onOpenChange={() => toggleSection("boundary")}>
            <CollapsibleTrigger asChild>
              <button className="w-full flex items-center justify-between py-1.5">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-amber-400" />
                  <span className="text-sm font-semibold">Boundary Protection</span>
                  {(activeProfile.waf.detected || activeProfile.cdn.detected || activeProfile.firewall.detected) && (
                    <Badge variant="outline" className="text-[9px] text-amber-400 border-amber-400/30">
                      {[activeProfile.waf.detected && "WAF", activeProfile.cdn.detected && "CDN", activeProfile.firewall.detected && "FW"].filter(Boolean).join(" + ")}
                    </Badge>
                  )}
                </div>
                {expandedSections.boundary ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>
            </CollapsibleTrigger>
            <CollapsibleContent className="space-y-2">
              {/* WAF Detail */}
              {activeProfile.waf.detected && (
                <div className="p-2.5 rounded-md bg-red-500/5 border border-red-500/15">
                  <div className="flex items-center gap-2 mb-1.5">
                    <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
                    <span className="text-xs font-medium text-red-300">WAF: {activeProfile.waf.vendor}</span>
                    <span className="text-[10px] text-muted-foreground">Type: {activeProfile.waf.type}</span>
                    <Progress value={activeProfile.waf.confidence} className="h-1.5 w-16 ml-auto [&>div]:bg-red-400" />
                    <span className="text-[10px] text-muted-foreground">{activeProfile.waf.confidence}%</span>
                  </div>
                  {activeProfile.waf.bypassTechniques.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1">
                      {activeProfile.waf.bypassTechniques.map((t, i) => (
                        <Badge key={i} variant="outline" className="text-[9px] text-red-300 border-red-400/20">{t}</Badge>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* CDN Detail */}
              {activeProfile.cdn.detected && (
                <div className="p-2.5 rounded-md bg-blue-500/5 border border-blue-500/15">
                  <div className="flex items-center gap-2 mb-1.5">
                    <Cloud className="h-3.5 w-3.5 text-blue-400" />
                    <span className="text-xs font-medium text-blue-300">CDN: {activeProfile.cdn.provider}</span>
                  </div>
                  {activeProfile.cdn.originDiscoveryMethods.length > 0 && (
                    <div className="mt-1">
                      <span className="text-[10px] text-muted-foreground">Origin Discovery Methods:</span>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {activeProfile.cdn.originDiscoveryMethods.map((m, i) => (
                          <Badge key={i} variant="outline" className="text-[9px] text-blue-300 border-blue-400/20">{m}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Firewall Detail */}
              {activeProfile.firewall.detected && (
                <div className="p-2.5 rounded-md bg-amber-500/5 border border-amber-500/15">
                  <div className="flex items-center gap-2">
                    <ShieldX className="h-3.5 w-3.5 text-amber-400" />
                    <span className="text-xs font-medium text-amber-300">Firewall: {activeProfile.firewall.type}</span>
                    {activeProfile.firewall.rateLimiting.detected && (
                      <Badge variant="outline" className="text-[9px] text-amber-300 border-amber-400/20">
                        Rate Limited{activeProfile.firewall.rateLimiting.requestsPerSecond ? ` (${activeProfile.firewall.rateLimiting.requestsPerSecond} rps)` : ""}
                      </Badge>
                    )}
                  </div>
                  {activeProfile.firewall.filteredPorts.length > 0 && (
                    <div className="text-[10px] text-muted-foreground mt-1">
                      Filtered ports: {activeProfile.firewall.filteredPorts.slice(0, 10).join(", ")}
                      {activeProfile.firewall.filteredPorts.length > 10 && ` +${activeProfile.firewall.filteredPorts.length - 10} more`}
                    </div>
                  )}
                </div>
              )}

              {!activeProfile.waf.detected && !activeProfile.cdn.detected && !activeProfile.firewall.detected && (
                <div className="flex items-center gap-2 p-2.5 rounded-md bg-emerald-500/5 border border-emerald-500/15">
                  <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                  <span className="text-xs text-emerald-300">No boundary protections detected — direct access to target</span>
                </div>
              )}
            </CollapsibleContent>
          </Collapsible>

          <Separator className="bg-zinc-700/30" />

          {/* Topology Section */}
          <Collapsible open={expandedSections.topology} onOpenChange={() => toggleSection("topology")}>
            <CollapsibleTrigger asChild>
              <button className="w-full flex items-center justify-between py-1.5">
                <div className="flex items-center gap-2">
                  <Layers className="h-4 w-4 text-purple-400" />
                  <span className="text-sm font-semibold">Infrastructure Topology</span>
                </div>
                {expandedSections.topology ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>
            </CollapsibleTrigger>
            <CollapsibleContent className="space-y-2">
              <div className="p-2.5 rounded-md bg-zinc-800/50 border border-zinc-700/30">
                <div className="flex items-center gap-2 mb-2">
                  <TopologyBadge topology={activeProfile.topology} />
                  {activeProfile.topology.backend && (
                    <>
                      <span className="text-muted-foreground text-xs">→</span>
                      <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-400/20">
                        {activeProfile.topology.backend}
                      </Badge>
                    </>
                  )}
                </div>
                {activeProfile.topology.services.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {activeProfile.topology.services.map((s, i) => (
                      <Badge key={i} variant="secondary" className="text-[9px]">{s}</Badge>
                    ))}
                  </div>
                )}
              </div>
            </CollapsibleContent>
          </Collapsible>

          <Separator className="bg-zinc-700/30" />

          {/* Evasion Profile Section */}
          <Collapsible open={expandedSections.evasion} onOpenChange={() => toggleSection("evasion")}>
            <CollapsibleTrigger asChild>
              <button className="w-full flex items-center justify-between py-1.5">
                <div className="flex items-center gap-2">
                  <Eye className="h-4 w-4 text-emerald-400" />
                  <span className="text-sm font-semibold">Evasion Profile</span>
                  {activeProfile.evasionEscalation && (
                    <Badge variant="outline" className={`text-[9px] ${
                      activeProfile.evasionEscalation.currentLevel >= 4 ? "text-red-400 border-red-400/30" :
                      activeProfile.evasionEscalation.currentLevel >= 3 ? "text-amber-400 border-amber-400/30" :
                      "text-emerald-400 border-emerald-400/30"
                    }`}>
                      L{activeProfile.evasionEscalation.currentLevel}
                    </Badge>
                  )}
                </div>
                {expandedSections.evasion ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>
            </CollapsibleTrigger>
            <CollapsibleContent className="space-y-2">
              {activeProfile.evasionProfile && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div className="p-2 rounded-md bg-zinc-800/50 border border-zinc-700/30">
                    <div className="text-[10px] text-muted-foreground">Rate Limit</div>
                    <div className="text-xs font-medium">{activeProfile.evasionProfile.rateLimit} req/s</div>
                  </div>
                  <div className="p-2 rounded-md bg-zinc-800/50 border border-zinc-700/30">
                    <div className="text-[10px] text-muted-foreground">Delay</div>
                    <div className="text-xs font-medium">{activeProfile.evasionProfile.delayMs}ms</div>
                  </div>
                  <div className="p-2 rounded-md bg-zinc-800/50 border border-zinc-700/30">
                    <div className="text-[10px] text-muted-foreground">User-Agent</div>
                    <div className="text-xs font-medium">{activeProfile.evasionProfile.userAgentStrategy}</div>
                  </div>
                  <div className="p-2 rounded-md bg-zinc-800/50 border border-zinc-700/30">
                    <div className="text-[10px] text-muted-foreground">IP Rotation</div>
                    <div className="text-xs font-medium">{activeProfile.evasionProfile.ipRotation}</div>
                  </div>
                </div>
              )}

              {activeProfile.evasionProfile && (
                <div className="flex flex-wrap gap-2 text-[10px]">
                  {activeProfile.evasionProfile.chunkedTransfer && (
                    <Badge variant="outline" className="text-[9px] text-cyan-300 border-cyan-400/20">Chunked Transfer</Badge>
                  )}
                  {activeProfile.evasionProfile.useHttp2 && (
                    <Badge variant="outline" className="text-[9px] text-cyan-300 border-cyan-400/20">HTTP/2</Badge>
                  )}
                  {activeProfile.evasionProfile.randomizeOrder && (
                    <Badge variant="outline" className="text-[9px] text-cyan-300 border-cyan-400/20">Randomized</Badge>
                  )}
                  {(activeProfile.evasionProfile.encodingTricks?.length || 0) > 0 && (
                    <Badge variant="outline" className="text-[9px] text-amber-300 border-amber-400/20">
                      {activeProfile.evasionProfile.encodingTricks!.length} encoding tricks
                    </Badge>
                  )}
                </div>
              )}

              {activeProfile.evasionEscalation && (
                <>
                  <Separator className="bg-zinc-700/30" />
                  <EvasionEscalationSection
                    escalation={activeProfile.evasionEscalation}
                    engagementId={engagementId}
                    hostname={activeProfile.hostname}
                  />
                </>
              )}

              {!activeProfile.evasionEscalation && (
                <div className="flex items-center gap-2 p-2.5 rounded-md bg-zinc-800/50 border border-zinc-700/30">
                  <EvasionLevelGauge level={1} />
                  <span className="text-[10px] text-muted-foreground ml-auto">No escalation triggered yet</span>
                </div>
              )}
            </CollapsibleContent>
          </Collapsible>

          <Separator className="bg-zinc-700/30" />

          {/* Scan Strategy Section */}
          {activeProfile.scanStrategy && (
            <Collapsible open={expandedSections.strategy} onOpenChange={() => toggleSection("strategy")}>
              <CollapsibleTrigger asChild>
                <button className="w-full flex items-center justify-between py-1.5">
                  <div className="flex items-center gap-2">
                    <Zap className="h-4 w-4 text-yellow-400" />
                    <span className="text-sm font-semibold">Recommended Scan Strategy</span>
                    <span className="text-[10px] text-muted-foreground">
                      {activeProfile.scanStrategy.phases.length} phases
                    </span>
                  </div>
                  {expandedSections.strategy ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </button>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <ScanStrategySection strategy={activeProfile.scanStrategy} />
              </CollapsibleContent>
            </Collapsible>
          )}
        </div>
      )}
    </div>
  );
}
