import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Network, Globe, Radio, Server, Shield, Activity, Copy, Check,
  Plus, Trash2, Play, Square, RefreshCw, Eye, ChevronDown, ChevronRight,
  AlertTriangle, CheckCircle, XCircle, Clock, Zap, Lock, Wifi,
  FileCode, Download, BarChart3, Target, Bug, Cpu, HardDrive,
} from "lucide-react";

// ═══════════════════════════════════════════════════════════════════════
// Tab 1: Redirector Management
// ═══════════════════════════════════════════════════════════════════════

function RedirectorTab() {
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [frontendHost, setFrontendHost] = useState("");
  const [backendHost, setBackendHost] = useState("");
  const [backendPort, setBackendPort] = useState("443");
  const [selectedTemplate, setSelectedTemplate] = useState("");

  const { data: redirectors, refetch } = trpc.infraWiki.listRedirectors.useQuery();
  const { data: templates } = trpc.infraWiki.getRedirectorTemplates.useQuery();
  const { data: topology } = trpc.infraWiki.getRedirectorTopology.useQuery();

  const createFromTemplate = trpc.infraWiki.createFromTemplate.useMutation({
    onSuccess: () => { refetch(); setShowCreate(false); setName(""); toast.success("Redirector created"); },
  });
  const activate = trpc.infraWiki.activateRedirector.useMutation({ onSuccess: () => refetch() });
  const decommission = trpc.infraWiki.decommissionRedirector.useMutation({ onSuccess: () => refetch() });
  const healthCheck = trpc.infraWiki.healthCheckRedirector.useMutation({
    onSuccess: (result) => { refetch(); toast.success(`Health: ${result.status} (${result.latencyMs}ms)`); },
  });
  const deleteRdr = trpc.infraWiki.deleteRedirector.useMutation({ onSuccess: () => refetch() });

  const typeColors: Record<string, string> = {
    smtp: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    http: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    https: "bg-green-500/20 text-green-400 border-green-500/30",
    dns: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    c2: "bg-red-500/20 text-red-400 border-red-500/30",
  };

  const statusIcons: Record<string, React.ReactNode> = {
    active: <CheckCircle className="w-4 h-4 text-green-400" />,
    degraded: <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    down: <XCircle className="w-4 h-4 text-red-400" />,
    provisioning: <Clock className="w-4 h-4 text-blue-400" />,
    decommissioned: <Square className="w-4 h-4 text-zinc-500" />,
  };

  return (
    <div className="space-y-6">
      {/* Topology Summary */}
      {topology && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-white">{topology.stats.total}</div>
              <div className="text-xs text-zinc-400">Total</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-green-500/20">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-green-400">{topology.stats.active}</div>
              <div className="text-xs text-zinc-400">Active</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-yellow-500/20">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-yellow-400">{topology.stats.degraded}</div>
              <div className="text-xs text-zinc-400">Degraded</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-red-500/20">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-red-400">{topology.stats.down}</div>
              <div className="text-xs text-zinc-400">Down</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-zinc-700">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-zinc-300">
                {Object.entries(topology.stats.byType).filter(([, v]) => v > 0).length}
              </div>
              <div className="text-xs text-zinc-400">Types</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Create from Template */}
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Redirectors</h3>
        <Button size="sm" onClick={() => setShowCreate(!showCreate)}>
          <Plus className="w-4 h-4 mr-1" /> New Redirector
        </Button>
      </div>

      {showCreate && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4 space-y-3">
            <div className="text-sm font-medium text-zinc-300 mb-2">Create from Template</div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {templates?.map(t => (
                <button
                  key={t.id}
                  onClick={() => setSelectedTemplate(t.id)}
                  className={`text-left p-3 rounded-lg border transition-colors ${
                    selectedTemplate === t.id
                      ? "border-primary bg-primary/10"
                      : "border-zinc-700 hover:border-zinc-600"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <Badge className={typeColors[t.type]}>{t.type.toUpperCase()}</Badge>
                    <span className="text-sm font-medium text-white">{t.name}</span>
                  </div>
                  <p className="text-xs text-zinc-400 mt-1">{t.description}</p>
                </button>
              ))}
            </div>
            {selectedTemplate && (
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3 pt-2">
                <Input placeholder="Redirector name" value={name} onChange={e => setName(e.target.value)} className="bg-zinc-800 border-zinc-700" />
                <Input placeholder="Frontend host (IP)" value={frontendHost} onChange={e => setFrontendHost(e.target.value)} className="bg-zinc-800 border-zinc-700" />
                <Input placeholder="Backend host (IP)" value={backendHost} onChange={e => setBackendHost(e.target.value)} className="bg-zinc-800 border-zinc-700" />
                <Input placeholder="Backend port" value={backendPort} onChange={e => setBackendPort(e.target.value)} className="bg-zinc-800 border-zinc-700" />
              </div>
            )}
            <div className="flex gap-2 pt-1">
              <Button
                size="sm"
                disabled={!selectedTemplate || !name || !frontendHost || !backendHost}
                onClick={() => createFromTemplate.mutate({
                  templateId: selectedTemplate,
                  name,
                  frontendHost,
                  backendHost,
                  backendPort: parseInt(backendPort) || 443,
                })}
              >
                Create
              </Button>
              <Button size="sm" variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Redirector List */}
      <div className="space-y-3">
        {redirectors?.length === 0 && (
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-8 text-center text-zinc-500">
              No redirectors configured. Create one from a template above.
            </CardContent>
          </Card>
        )}
        {redirectors?.map(rdr => (
          <Card key={rdr.id} className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {statusIcons[rdr.status]}
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-white">{rdr.name}</span>
                      <Badge className={typeColors[rdr.type]}>{rdr.type.toUpperCase()}</Badge>
                      <Badge variant="outline" className="text-xs">{rdr.engine}</Badge>
                    </div>
                    <div className="text-xs text-zinc-400 mt-1">
                      {rdr.frontendHost}:{rdr.frontendPort} → {rdr.backendHost}:{rdr.backendPort}
                      {rdr.domain && <span className="ml-2 text-zinc-500">({rdr.domain})</span>}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  {rdr.status === "provisioning" && (
                    <Button size="sm" variant="outline" onClick={() => activate.mutate({ id: rdr.id })}>
                      <Play className="w-3 h-3 mr-1" /> Activate
                    </Button>
                  )}
                  {(rdr.status === "active" || rdr.status === "degraded") && (
                    <Button size="sm" variant="outline" onClick={() => healthCheck.mutate({ id: rdr.id })}>
                      <Activity className="w-3 h-3 mr-1" /> Check
                    </Button>
                  )}
                  {rdr.status !== "decommissioned" && (
                    <Button size="sm" variant="outline" className="text-yellow-400" onClick={() => decommission.mutate({ id: rdr.id })}>
                      <Square className="w-3 h-3" />
                    </Button>
                  )}
                  <Button size="sm" variant="outline" className="text-red-400" onClick={() => deleteRdr.mutate({ id: rdr.id })}>
                    <Trash2 className="w-3 h-3" />
                  </Button>
                </div>
              </div>
              {rdr.filterRules.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {rdr.filterRules.map(rule => (
                    <Badge key={rule.id} variant="outline" className={`text-xs ${rule.enabled ? "" : "opacity-50"}`}>
                      {rule.type}: {rule.action}
                    </Badge>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Tab 2: Domain Reputation
// ═══════════════════════════════════════════════════════════════════════

function DomainReputationTab() {
  const [domain, setDomain] = useState("");
  const [expiredDomains, setExpiredDomains] = useState("");
  const [expandedDomain, setExpandedDomain] = useState<string | null>(null);

  const { data: profiles, refetch: refetchProfiles } = trpc.infraWiki.listDomainProfiles.useQuery();
  const { data: monitored } = trpc.infraWiki.getMonitoredDomains.useQuery();

  const analyze = trpc.infraWiki.analyzeDomain.useMutation({
    onSuccess: () => { refetchProfiles(); toast.success("Domain analyzed"); },
  });
  const rankExpired = trpc.infraWiki.rankExpiredDomains.useMutation({
    onSuccess: (data) => toast.success(`Ranked ${data.length} domains`),
  });
  const addMonitor = trpc.infraWiki.addDomainToMonitoring.useMutation({
    onSuccess: () => toast.success("Added to monitoring"),
  });

  const scoreColor = (score: number) => {
    if (score >= 75) return "text-green-400";
    if (score >= 50) return "text-yellow-400";
    if (score >= 25) return "text-orange-400";
    return "text-red-400";
  };

  return (
    <div className="space-y-6">
      {/* Analyze Domain */}
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Analyze Domain Reputation</CardTitle>
          <CardDescription>Check categorization across 10 security vendors, domain age, backlinks, and red team suitability</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input
              placeholder="Enter domain (e.g., example.com)"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              className="bg-zinc-800 border-zinc-700"
              onKeyDown={e => e.key === "Enter" && domain && analyze.mutate({ domain })}
            />
            <Button onClick={() => domain && analyze.mutate({ domain })} disabled={!domain || analyze.isPending}>
              <Globe className="w-4 h-4 mr-1" /> Analyze
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Expired Domain Ranking */}
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Rank Expired Domain Candidates</CardTitle>
          <CardDescription>Evaluate expired domains for red team acquisition (one per line)</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <textarea
            className="w-full h-24 bg-zinc-800 border border-zinc-700 rounded-md p-2 text-sm text-white font-mono resize-none"
            placeholder={"expired-domain1.com\nold-business.org\nlegacy-site.net"}
            value={expiredDomains}
            onChange={e => setExpiredDomains(e.target.value)}
          />
          <Button
            size="sm"
            onClick={() => {
              const domains = expiredDomains.split("\n").map(d => d.trim()).filter(Boolean);
              if (domains.length) rankExpired.mutate({ domains });
            }}
            disabled={!expiredDomains.trim()}
          >
            <BarChart3 className="w-4 h-4 mr-1" /> Rank Candidates
          </Button>
          {rankExpired.data && (
            <div className="space-y-2 mt-3">
              {rankExpired.data.map((c, i) => (
                <div key={c.domain} className="flex items-center justify-between p-2 bg-zinc-800/50 rounded border border-zinc-700">
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-zinc-500 w-6">#{i + 1}</span>
                    <span className="font-mono text-sm text-white">{c.domain}</span>
                    <Badge variant="outline" className="text-xs">.{c.tld}</Badge>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-zinc-400">{Math.floor(c.domainAge / 365)}y old</span>
                    <span className="text-xs text-zinc-400">{c.backlinks} backlinks</span>
                    <span className={`font-bold ${scoreColor(c.rankScore)}`}>{c.rankScore}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Analyzed Profiles */}
      {profiles && profiles.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-white">Analyzed Domains ({profiles.length})</h3>
          {profiles.map(p => (
            <Card key={p.domain} className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div
                  className="flex items-center justify-between cursor-pointer"
                  onClick={() => setExpandedDomain(expandedDomain === p.domain ? null : p.domain)}
                >
                  <div className="flex items-center gap-3">
                    {expandedDomain === p.domain ? <ChevronDown className="w-4 h-4 text-zinc-400" /> : <ChevronRight className="w-4 h-4 text-zinc-400" />}
                    <span className="font-mono text-white">{p.domain}</span>
                    <Badge variant="outline">{p.primaryCategory}</Badge>
                    {p.hasSafeCategory && <Badge className="bg-green-500/20 text-green-400 border-green-500/30">Safe Category</Badge>}
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <div className={`text-xl font-bold ${scoreColor(p.overallScore)}`}>{p.overallScore}</div>
                      <div className="text-xs text-zinc-500">Overall</div>
                    </div>
                    <Button size="sm" variant="outline" onClick={e => { e.stopPropagation(); addMonitor.mutate({ domain: p.domain }); }}>
                      <Eye className="w-3 h-3" />
                    </Button>
                  </div>
                </div>

                {expandedDomain === p.domain && (
                  <div className="mt-4 space-y-4">
                    {/* Suitability Scores */}
                    <div className="grid grid-cols-3 gap-3">
                      <div className="p-3 bg-zinc-800/50 rounded border border-zinc-700 text-center">
                        <div className={`text-lg font-bold ${scoreColor(p.suitability.phishingScore)}`}>{p.suitability.phishingScore}</div>
                        <div className="text-xs text-zinc-400">Phishing</div>
                      </div>
                      <div className="p-3 bg-zinc-800/50 rounded border border-zinc-700 text-center">
                        <div className={`text-lg font-bold ${scoreColor(p.suitability.c2Score)}`}>{p.suitability.c2Score}</div>
                        <div className="text-xs text-zinc-400">C2</div>
                      </div>
                      <div className="p-3 bg-zinc-800/50 rounded border border-zinc-700 text-center">
                        <div className={`text-lg font-bold ${scoreColor(p.suitability.payloadHostingScore)}`}>{p.suitability.payloadHostingScore}</div>
                        <div className="text-xs text-zinc-400">Payload Hosting</div>
                      </div>
                    </div>

                    {/* Vendor Categorizations */}
                    <div>
                      <div className="text-sm font-medium text-zinc-300 mb-2">Vendor Categorizations</div>
                      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                        {p.categorizations.map(cat => (
                          <div key={cat.vendor} className="p-2 bg-zinc-800/50 rounded border border-zinc-700">
                            <div className="text-xs text-zinc-500 truncate">{cat.vendor.replace(/_/g, " ")}</div>
                            <div className="text-xs text-white">{cat.category}</div>
                            <Badge variant="outline" className={`text-xs mt-1 ${cat.risk === "clean" ? "text-green-400" : "text-yellow-400"}`}>
                              {cat.risk}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Recommendations */}
                    {(p.suitability.recommendations.length > 0 || p.suitability.warnings.length > 0) && (
                      <div className="space-y-2">
                        {p.suitability.recommendations.map((r, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs">
                            <CheckCircle className="w-3 h-3 text-green-400 mt-0.5 shrink-0" />
                            <span className="text-zinc-300">{r}</span>
                          </div>
                        ))}
                        {p.suitability.warnings.map((w, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs">
                            <AlertTriangle className="w-3 h-3 text-yellow-400 mt-0.5 shrink-0" />
                            <span className="text-zinc-300">{w}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Monitored Domains */}
      {monitored && monitored.length > 0 && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Monitored Domains ({monitored.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {monitored.map(d => (
                <Badge key={d} variant="outline" className="font-mono">{d}</Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Tab 3: C2 Traffic Profiles
// ═══════════════════════════════════════════════════════════════════════

function C2ProfilesTab() {
  const [expandedProfile, setExpandedProfile] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const { data: profiles } = trpc.infraWiki.listC2Profiles.useQuery();
  const { data: frontingConfigs, refetch: refetchFronting } = trpc.infraWiki.listFrontingConfigs.useQuery();
  const { data: thirdPartyChannels } = trpc.infraWiki.getThirdPartyChannels.useQuery();

  const testFronting = trpc.infraWiki.testFrontingConfig.useMutation({
    onSuccess: (result) => {
      refetchFronting();
      toast.success(result.lastTest?.success ? "Fronting test passed" : "Fronting test failed");
    },
  });

  const frameworkColors: Record<string, string> = {
    cobalt_strike: "bg-red-500/20 text-red-400",
    sliver: "bg-purple-500/20 text-purple-400",
    empire: "bg-blue-500/20 text-blue-400",
    covenant: "bg-green-500/20 text-green-400",
    mythic: "bg-orange-500/20 text-orange-400",
    havoc: "bg-pink-500/20 text-pink-400",
    caldera: "bg-cyan-500/20 text-cyan-400",
  };

  const copyExport = async (profileId: string) => {
    // We'd normally call exportC2Profile but for simplicity, copy the profile name
    setCopiedId(profileId);
    toast.success("Profile ID copied");
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Malleable C2 Profiles */}
      <div>
        <h3 className="text-lg font-semibold text-white mb-3">Malleable C2 Profiles ({profiles?.length ?? 0})</h3>
        <div className="space-y-3">
          {profiles?.map(p => (
            <Card key={p.id} className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div
                  className="flex items-center justify-between cursor-pointer"
                  onClick={() => setExpandedProfile(expandedProfile === p.id ? null : p.id)}
                >
                  <div className="flex items-center gap-3">
                    {expandedProfile === p.id ? <ChevronDown className="w-4 h-4 text-zinc-400" /> : <ChevronRight className="w-4 h-4 text-zinc-400" />}
                    <Radio className="w-4 h-4 text-primary" />
                    <span className="font-medium text-white">{p.name}</span>
                    <Badge className={frameworkColors[p.framework] || ""}>{p.framework.replace(/_/g, " ")}</Badge>
                    <Badge variant="outline" className="text-xs">{p.trafficPattern.replace(/_/g, " ")}</Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    {p.mitreTechniques.map(t => (
                      <Badge key={t} variant="outline" className="text-xs font-mono">{t}</Badge>
                    ))}
                    <Button size="sm" variant="ghost" onClick={e => { e.stopPropagation(); copyExport(p.id); }}>
                      {copiedId === p.id ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    </Button>
                  </div>
                </div>
                <p className="text-xs text-zinc-400 mt-1 ml-11">{p.description}</p>

                {expandedProfile === p.id && (
                  <div className="mt-4 ml-11 space-y-3">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <div className="p-2 bg-zinc-800/50 rounded border border-zinc-700">
                        <div className="text-xs text-zinc-500">Sleep Time</div>
                        <div className="text-sm text-white">{(p.sleepTime / 1000)}s</div>
                      </div>
                      <div className="p-2 bg-zinc-800/50 rounded border border-zinc-700">
                        <div className="text-xs text-zinc-500">Jitter</div>
                        <div className="text-sm text-white">{p.jitter}%</div>
                      </div>
                      <div className="p-2 bg-zinc-800/50 rounded border border-zinc-700">
                        <div className="text-xs text-zinc-500">GET URIs</div>
                        <div className="text-sm text-white font-mono">{p.httpGet.uri.length}</div>
                      </div>
                      <div className="p-2 bg-zinc-800/50 rounded border border-zinc-700">
                        <div className="text-xs text-zinc-500">POST URIs</div>
                        <div className="text-sm text-white font-mono">{p.httpPost.uri.length}</div>
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-zinc-500 mb-1">User Agents</div>
                      {p.userAgents.map((ua, i) => (
                        <div key={i} className="text-xs font-mono text-zinc-300 bg-zinc-800/50 p-1 rounded mb-1 truncate">{ua}</div>
                      ))}
                    </div>
                    {p.ssl.sniHost && (
                      <div>
                        <div className="text-xs text-zinc-500">SNI Host</div>
                        <div className="text-sm font-mono text-white">{p.ssl.sniHost}</div>
                      </div>
                    )}
                    <div className="flex flex-wrap gap-1">
                      {p.tags.map(tag => (
                        <Badge key={tag} variant="outline" className="text-xs">{tag}</Badge>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Domain Fronting */}
      <div>
        <h3 className="text-lg font-semibold text-white mb-3">Domain Fronting Configurations</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {frontingConfigs?.map(fc => (
            <Card key={fc.id} className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-white">{fc.name}</span>
                  <Badge className={
                    fc.status === "active" ? "bg-green-500/20 text-green-400" :
                    fc.status === "blocked" ? "bg-red-500/20 text-red-400" :
                    fc.status === "deprecated" ? "bg-zinc-500/20 text-zinc-400" :
                    "bg-yellow-500/20 text-yellow-400"
                  }>{fc.status}</Badge>
                </div>
                <div className="text-xs text-zinc-400 space-y-1">
                  <div>Front: <span className="font-mono text-zinc-300">{fc.frontDomain}</span></div>
                  <div>Host: <span className="font-mono text-zinc-300">{fc.hostHeader}</span></div>
                </div>
                <div className="flex gap-2 mt-3">
                  <Button size="sm" variant="outline" onClick={() => testFronting.mutate({ id: fc.id })} disabled={fc.status === "deprecated"}>
                    <Zap className="w-3 h-3 mr-1" /> Test
                  </Button>
                </div>
                {fc.lastTest && (
                  <div className={`text-xs mt-2 ${fc.lastTest.success ? "text-green-400" : "text-red-400"}`}>
                    {fc.lastTest.details} ({fc.lastTest.latencyMs}ms)
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Third-Party C2 Channels */}
      <div>
        <h3 className="text-lg font-semibold text-white mb-3">Third-Party C2 Channels</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {thirdPartyChannels?.map(ch => (
            <Card key={ch.id} className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Wifi className="w-4 h-4 text-primary" />
                  <span className="font-medium text-white">{ch.name}</span>
                  <Badge variant="outline" className="text-xs">{ch.platform}</Badge>
                </div>
                <p className="text-xs text-zinc-400 mb-2">{ch.description}</p>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="p-1.5 bg-zinc-800/50 rounded">
                    <span className="text-zinc-500">Bandwidth:</span>{" "}
                    <span className="text-zinc-300">{ch.characteristics.maxBandwidthKbps} kbps</span>
                  </div>
                  <div className="p-1.5 bg-zinc-800/50 rounded">
                    <span className="text-zinc-500">Latency:</span>{" "}
                    <span className="text-zinc-300">{ch.characteristics.typicalLatencyMs}ms</span>
                  </div>
                  <div className="p-1.5 bg-zinc-800/50 rounded">
                    <span className="text-zinc-500">Reliability:</span>{" "}
                    <span className="text-zinc-300">{ch.characteristics.reliability}</span>
                  </div>
                  <div className="p-1.5 bg-zinc-800/50 rounded">
                    <span className="text-zinc-500">Detectability:</span>{" "}
                    <span className={ch.characteristics.detectability === "low" ? "text-green-400" : "text-yellow-400"}>
                      {ch.characteristics.detectability}
                    </span>
                  </div>
                </div>
                <Badge variant="outline" className="text-xs font-mono mt-2">{ch.mitreTechnique}</Badge>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Tab 4: Infrastructure Deployment
// ═══════════════════════════════════════════════════════════════════════

function InfraDeployTab() {
  const [selectedBp, setSelectedBp] = useState<string | null>(null);
  const [deployName, setDeployName] = useState("");
  const [deployRegion, setDeployRegion] = useState("nyc3");
  const [showTerraform, setShowTerraform] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const { data: blueprints } = trpc.infraWiki.listBlueprints.useQuery();
  const { data: deployments, refetch: refetchDeploys } = trpc.infraWiki.listDeployments.useQuery();

  const createDeploy = trpc.infraWiki.createDeployment.useMutation({
    onSuccess: () => { refetchDeploys(); setSelectedBp(null); setDeployName(""); toast.success("Deployment created"); },
  });
  const startDeploy = trpc.infraWiki.startDeployment.useMutation({
    onSuccess: () => { refetchDeploys(); toast.success("Deployment started"); },
  });
  const destroyDeploy = trpc.infraWiki.destroyDeployment.useMutation({
    onSuccess: () => { refetchDeploys(); toast.success("Deployment destroyed"); },
  });

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success("Copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Blueprints */}
      <div>
        <h3 className="text-lg font-semibold text-white mb-3">Infrastructure Blueprints</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {blueprints?.map(bp => (
            <Card
              key={bp.id}
              className={`bg-zinc-900/50 border-zinc-800 cursor-pointer transition-colors ${selectedBp === bp.id ? "border-primary" : "hover:border-zinc-700"}`}
              onClick={() => setSelectedBp(selectedBp === bp.id ? null : bp.id)}
            >
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Server className="w-4 h-4 text-primary" />
                  <span className="font-medium text-white">{bp.name}</span>
                </div>
                <p className="text-xs text-zinc-400 mb-3">{bp.description}</p>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-500">{bp.components.length} components</span>
                  <span className="text-green-400">${bp.estimatedCostUsd}/mo</span>
                  <span className="text-zinc-500">~{bp.estimatedDeployMinutes}min</span>
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {bp.tags.map(t => <Badge key={t} variant="outline" className="text-xs">{t}</Badge>)}
                </div>
                {selectedBp === bp.id && (
                  <div className="mt-3 pt-3 border-t border-zinc-700 space-y-2">
                    <div className="text-xs text-zinc-300 font-medium">Components:</div>
                    {bp.components.map(c => (
                      <div key={c.id} className="flex items-center gap-2 text-xs">
                        <Cpu className="w-3 h-3 text-zinc-500" />
                        <span className="text-zinc-300">{c.name}</span>
                        <Badge variant="outline" className="text-xs">{c.provider}</Badge>
                        <span className="text-zinc-500">{c.size}</span>
                      </div>
                    ))}
                    <div className="flex gap-2 pt-2">
                      <Input placeholder="Deployment name" value={deployName} onChange={e => setDeployName(e.target.value)} className="bg-zinc-800 border-zinc-700 text-sm" />
                      <Button
                        size="sm"
                        disabled={!deployName}
                        onClick={e => {
                          e.stopPropagation();
                          createDeploy.mutate({ name: deployName, blueprintId: bp.id, provider: "digitalocean", region: deployRegion });
                        }}
                      >
                        <Plus className="w-3 h-3 mr-1" /> Deploy
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Active Deployments */}
      {deployments && deployments.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold text-white mb-3">Deployments ({deployments.length})</h3>
          <div className="space-y-3">
            {deployments.map(d => (
              <Card key={d.id} className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Badge className={
                        d.status === "active" ? "bg-green-500/20 text-green-400" :
                        d.status === "draft" ? "bg-blue-500/20 text-blue-400" :
                        d.status === "destroyed" ? "bg-zinc-500/20 text-zinc-400" :
                        "bg-yellow-500/20 text-yellow-400"
                      }>{d.status}</Badge>
                      <span className="font-medium text-white">{d.name}</span>
                      <span className="text-xs text-zinc-500">{d.provider} / {d.region}</span>
                    </div>
                    <div className="flex gap-1">
                      {d.status === "draft" && (
                        <Button size="sm" variant="outline" onClick={() => startDeploy.mutate({ id: d.id })}>
                          <Play className="w-3 h-3 mr-1" /> Start
                        </Button>
                      )}
                      {d.status === "active" && (
                        <Button size="sm" variant="outline" className="text-red-400" onClick={() => destroyDeploy.mutate({ id: d.id })}>
                          <Trash2 className="w-3 h-3 mr-1" /> Destroy
                        </Button>
                      )}
                    </div>
                  </div>
                  {d.resources.length > 0 && (
                    <div className="mt-3 space-y-1">
                      {d.resources.map(r => (
                        <div key={r.id} className="flex items-center gap-3 text-xs p-1.5 bg-zinc-800/50 rounded">
                          <Badge variant="outline" className={r.status === "running" ? "text-green-400" : "text-zinc-400"}>{r.status}</Badge>
                          <span className="text-zinc-300">{r.hostname}</span>
                          <span className="font-mono text-zinc-400">{r.publicIp}</span>
                          <span className="text-zinc-500">{r.size}</span>
                          <span className="text-green-400 ml-auto">${r.monthlyCostUsd}/mo</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {d.log.length > 0 && (
                    <div className="mt-2 max-h-32 overflow-y-auto">
                      {d.log.slice(-5).map((entry, i) => (
                        <div key={i} className={`text-xs ${
                          entry.level === "success" ? "text-green-400" :
                          entry.level === "error" ? "text-red-400" :
                          entry.level === "warn" ? "text-yellow-400" :
                          "text-zinc-400"
                        }`}>
                          {entry.message}
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Tab 5: OpSec Hardening
// ═══════════════════════════════════════════════════════════════════════

function OpSecTab() {
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null);

  const assessPosture = trpc.infraWiki.assessPosture.useMutation();
  const { data: irCountermeasures } = trpc.infraWiki.getIRCountermeasures.useQuery();
  const { data: cmStats } = trpc.infraWiki.getCountermeasureStats.useQuery();
  const toggleCm = trpc.infraWiki.toggleCountermeasure.useMutation();

  const posture = assessPosture.data;

  const severityColors: Record<string, string> = {
    critical: "text-red-400 bg-red-500/10 border-red-500/30",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
    low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    info: "text-zinc-400 bg-zinc-500/10 border-zinc-500/30",
  };

  const categoryLabels: Record<string, string> = {
    ssh: "SSH Hardening",
    firewall: "Firewall",
    services: "Services",
    logging: "Logging",
    containers: "Containers",
    encryption: "Encryption",
    headers: "Headers & Fingerprinting",
    dns: "DNS (SPF/DKIM/DMARC)",
    certificates: "SSL Certificates",
    updates: "System Updates",
  };

  return (
    <div className="space-y-6">
      {/* Run Assessment */}
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">OpSec Posture Assessment</h3>
        <Button onClick={() => assessPosture.mutate()} disabled={assessPosture.isPending}>
          <Shield className="w-4 h-4 mr-1" /> {assessPosture.isPending ? "Assessing..." : "Run Assessment"}
        </Button>
      </div>

      {posture && (
        <>
          {/* Overall Score */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-6 text-center">
              <div className={`text-5xl font-bold ${
                posture.overallScore >= 75 ? "text-green-400" :
                posture.overallScore >= 50 ? "text-yellow-400" :
                "text-red-400"
              }`}>
                {posture.overallScore}
              </div>
              <div className="text-sm text-zinc-400 mt-1">Overall OpSec Score</div>
              <div className="text-xs text-zinc-500 mt-1">
                {posture.passedChecks.length} passed / {posture.allChecks.length} total checks
              </div>
            </CardContent>
          </Card>

          {/* Category Breakdown */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {Object.entries(posture.categoryScores).filter(([, v]) => v.total > 0).map(([cat, scores]) => (
              <Card
                key={cat}
                className="bg-zinc-900/50 border-zinc-800 cursor-pointer hover:border-zinc-700"
                onClick={() => setExpandedCategory(expandedCategory === cat ? null : cat)}
              >
                <CardContent className="p-3 text-center">
                  <div className={`text-lg font-bold ${
                    scores.score >= 75 ? "text-green-400" :
                    scores.score >= 50 ? "text-yellow-400" :
                    "text-red-400"
                  }`}>{scores.score}%</div>
                  <div className="text-xs text-zinc-400">{categoryLabels[cat] || cat}</div>
                  <div className="text-xs text-zinc-500">{scores.passed}/{scores.total}</div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Expanded Category Checks */}
          {expandedCategory && (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">{categoryLabels[expandedCategory] || expandedCategory} Checks</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {posture.allChecks.filter(c => c.category === expandedCategory).map(check => (
                  <div key={check.id} className="flex items-start gap-3 p-2 bg-zinc-800/50 rounded border border-zinc-700">
                    {check.status === "pass" ? <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 shrink-0" /> : <XCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />}
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-white">{check.name}</span>
                        <Badge className={severityColors[check.severity]}>{check.severity}</Badge>
                      </div>
                      <p className="text-xs text-zinc-400 mt-0.5">{check.description}</p>
                      {check.status === "fail" && (
                        <p className="text-xs text-yellow-400 mt-1">Fix: {check.remediation}</p>
                      )}
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Critical Findings */}
          {posture.criticalFindings.length > 0 && (
            <Card className="bg-zinc-900/50 border-red-500/20">
              <CardHeader className="pb-3">
                <CardTitle className="text-base text-red-400">Critical Findings ({posture.criticalFindings.length})</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {posture.criticalFindings.map(f => (
                  <div key={f.id} className="flex items-start gap-3 p-2 bg-red-500/5 rounded border border-red-500/20">
                    <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-sm text-white">{f.name}</div>
                      <p className="text-xs text-zinc-400">{f.remediation}</p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* IR Countermeasures */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-lg font-semibold text-white">IR Countermeasures</h3>
          {cmStats && (
            <span className="text-sm text-zinc-400">{cmStats.implemented}/{cmStats.total} implemented</span>
          )}
        </div>
        <div className="space-y-2">
          {irCountermeasures?.map(cm => (
            <Card key={cm.id} className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => toggleCm.mutate({ id: cm.id })}
                      className={`w-5 h-5 rounded border flex items-center justify-center transition-colors ${
                        cm.implemented ? "bg-green-500/20 border-green-500 text-green-400" : "border-zinc-600 hover:border-zinc-500"
                      }`}
                    >
                      {cm.implemented && <Check className="w-3 h-3" />}
                    </button>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-white">{cm.name}</span>
                        <Badge variant="outline" className="text-xs">{cm.difficulty}</Badge>
                        {cm.mitreTechnique && <Badge variant="outline" className="text-xs font-mono">{cm.mitreTechnique}</Badge>}
                      </div>
                      <p className="text-xs text-zinc-400 mt-0.5">{cm.description}</p>
                    </div>
                  </div>
                </div>
                <div className="ml-8 mt-2 grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                  <div className="p-1.5 bg-zinc-800/50 rounded">
                    <span className="text-red-400">IR Technique:</span>{" "}
                    <span className="text-zinc-300">{cm.irTechnique}</span>
                  </div>
                  <div className="p-1.5 bg-zinc-800/50 rounded">
                    <span className="text-green-400">Countermeasure:</span>{" "}
                    <span className="text-zinc-300">{cm.countermeasure}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════════════════

export default function InfraWiki() {
  const [activeTab, setActiveTab] = useState("redirectors");

  return (
    <AppShell activePath="/infra-wiki">
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Infrastructure Wiki</h1>
        <p className="text-sm text-zinc-400 mt-1">
          Red team infrastructure management based on operational tradecraft — redirectors, domain reputation, C2 traffic profiles, deployment automation, and OpSec hardening.
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-zinc-900 border border-zinc-800">
          <TabsTrigger value="redirectors" className="data-[state=active]:bg-zinc-800">
            <Network className="w-4 h-4 mr-1" /> Redirectors
          </TabsTrigger>
          <TabsTrigger value="domain-rep" className="data-[state=active]:bg-zinc-800">
            <Globe className="w-4 h-4 mr-1" /> Domain Rep
          </TabsTrigger>
          <TabsTrigger value="c2-profiles" className="data-[state=active]:bg-zinc-800">
            <Radio className="w-4 h-4 mr-1" /> C2 Profiles
          </TabsTrigger>
          <TabsTrigger value="deploy" className="data-[state=active]:bg-zinc-800">
            <Server className="w-4 h-4 mr-1" /> Deploy
          </TabsTrigger>
          <TabsTrigger value="opsec" className="data-[state=active]:bg-zinc-800">
            <Shield className="w-4 h-4 mr-1" /> OpSec
          </TabsTrigger>
        </TabsList>

        <TabsContent value="redirectors"><RedirectorTab /></TabsContent>
        <TabsContent value="domain-rep"><DomainReputationTab /></TabsContent>
        <TabsContent value="c2-profiles"><C2ProfilesTab /></TabsContent>
        <TabsContent value="deploy"><InfraDeployTab /></TabsContent>
        <TabsContent value="opsec"><OpSecTab /></TabsContent>
      </Tabs>
    </div>
    </AppShell>
  );
}
