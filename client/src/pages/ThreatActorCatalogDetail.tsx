import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { safeUpper } from "@/lib/utils-safe";
import { useParams, Link } from "wouter";
import { toast } from "sonner";
import { useState } from "react";
import {
  ArrowLeft,
  Shield,
  Skull,
  AlertTriangle,
  Globe2,
  Key,
  Megaphone,
  Zap,
  Target,
  Clock,
  Crosshair,
  Radio,
  Brain,
  FileText,
  Loader2,
  RefreshCw,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Activity,
  Database,
  Bug,
} from "lucide-react";

const TYPE_CONFIG: Record<string, { icon: typeof Shield; color: string; bg: string; label: string }> = {
  apt: { icon: Shield, color: "text-red-400", bg: "bg-red-500/10 border-red-500/20", label: "APT / Nation-State" },
  ransomware: { icon: Skull, color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20", label: "Ransomware" },
  cybercrime: { icon: AlertTriangle, color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20", label: "Cybercrime" },
  hacktivist: { icon: Globe2, color: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/20", label: "Hacktivist" },
  access_broker: { icon: Key, color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20", label: "Access Broker" },
  influence_ops: { icon: Megaphone, color: "text-pink-400", bg: "bg-pink-500/10 border-pink-500/20", label: "Influence Ops" },
  unknown: { icon: Zap, color: "text-gray-400", bg: "bg-gray-500/10 border-gray-500/20", label: "Unknown" },
};

const THREAT_LEVEL_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-green-400 bg-green-500/10 border-green-500/30",
};

const EVENT_TYPE_COLORS: Record<string, string> = {
  attack: "text-red-400 bg-red-500/10",
  campaign: "text-orange-400 bg-orange-500/10",
  infrastructure_change: "text-blue-400 bg-blue-500/10",
  malware_update: "text-purple-400 bg-purple-500/10",
  law_enforcement: "text-green-400 bg-green-500/10",
  data_leak: "text-amber-400 bg-amber-500/10",
  ttp_evolution: "text-cyan-400 bg-cyan-500/10",
  group_rebrand: "text-pink-400 bg-pink-500/10",
  new_tool: "text-indigo-400 bg-indigo-500/10",
  zero_day: "text-red-500 bg-red-500/15",
};

type TabId = "overview" | "techniques" | "events" | "iocs" | "caldera";

export default function ThreatActorCatalogDetail() {
  const { id } = useParams<{ id: string }>();
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [enriching, setEnriching] = useState(false);

  const { data, isLoading, refetch } = trpc.threatIntel.getActor.useQuery(
    { actorId: id || "" },
    { enabled: !!id }
  );

  const enrichMutation = trpc.threatIntel.enrichActor.useMutation({
    onSuccess: () => {
      toast.success("Actor profile enriched via LLM");
      refetch();
      setEnriching(false);
    },
    onError: (err) => {
      toast.error(`Enrichment failed: ${err.message}`);
      setEnriching(false);
    },
  });

  const handleEnrich = () => {
    if (!data?.actor) return;
    setEnriching(true);
    enrichMutation.mutate({
      actorId: data.actor.actorId,
      actorType: (data.actor.type as any) || "apt",
    });
  };

  if (isLoading) {
    return (
      <AppShell activePath="/threat-catalog">
        <div className="max-w-[1400px] mx-auto space-y-6">
          <div className="animate-pulse space-y-4">
            <div className="h-8 bg-muted rounded w-1/3" />
            <div className="h-4 bg-muted rounded w-2/3" />
            <div className="grid grid-cols-3 gap-4">
              {[1, 2, 3].map(i => <div key={i} className="h-32 bg-muted rounded" />)}
            </div>
          </div>
        </div>
      </AppShell>
    );
  }

  if (!data?.actor) {
    return (
      <AppShell activePath="/threat-catalog">
        <div className="max-w-[1400px] mx-auto text-center py-20">
          <Database className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <h2 className="text-xl font-display tracking-wider mb-2">ACTOR NOT FOUND</h2>
          <p className="text-muted-foreground text-sm mb-4">The requested threat actor does not exist in the catalog.</p>
          <Link href="/threat-catalog" className="text-primary hover:underline text-sm">
            Return to Threat Catalog
          </Link>
        </div>
      </AppShell>
    );
  }

  const { actor, events: rawEvents, iocs: rawIocs, ransomwareProfile } = data;
  const events = rawEvents || [];
  const iocs = rawIocs || [];
  const typeConf = TYPE_CONFIG[actor.type || "unknown"] || TYPE_CONFIG.unknown;
  const TypeIcon = typeConf.icon;
  const aliases: string[] = Array.isArray(actor.aliases) ? actor.aliases : [];
  const sectors: string[] = Array.isArray(actor.targetSectors) ? actor.targetSectors : [];
  const regions: string[] = Array.isArray(actor.targetRegions) ? actor.targetRegions : [];
  const techniques: any[] = Array.isArray(actor.techniques) ? actor.techniques : [];
  const tools: string[] = Array.isArray(actor.tools) ? actor.tools : [];
  const malware: string[] = Array.isArray(actor.malware) ? actor.malware : [];
  const timeline: any[] = Array.isArray(actor.activityTimeline) ? actor.activityTimeline : [];
  const threatLevelClass = THREAT_LEVEL_COLORS[actor.threatLevel || "medium"] || THREAT_LEVEL_COLORS.medium;

  const tabs: { id: TabId; label: string; count?: number }[] = [
    { id: "overview", label: "OVERVIEW" },
    { id: "techniques", label: "TECHNIQUES", count: techniques.length },
    { id: "events", label: "EVENTS", count: events.length },
    { id: "iocs", label: "IOCs", count: iocs.length },
    ...(actor.calderaProfile ? [{ id: "caldera" as TabId, label: "CALDERA" }] : []),
  ];

  return (
    <AppShell activePath="/threat-catalog">
      <div className="max-w-[1400px] mx-auto space-y-6">
        {/* Back Nav */}
        <Link href="/threat-catalog" className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground text-sm transition-colors">
          <ArrowLeft className="w-4 h-4" />
          Back to Threat Catalog
        </Link>

        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <TypeIcon className={`w-8 h-8 ${typeConf.color}`} />
              <h1 className="text-2xl lg:text-3xl font-display tracking-wider">{actor.name}</h1>
            </div>
            <div className="flex items-center gap-2 flex-wrap mb-3">
              <span className={`text-[10px] px-2 py-0.5 border ${typeConf.bg} ${typeConf.color} tracking-wider`}>
                {typeConf.label.toUpperCase()}
              </span>
              {actor.origin && (
                <span className="text-[10px] px-2 py-0.5 bg-secondary text-muted-foreground tracking-wider">
                  {safeUpper(actor.origin)}
                </span>
              )}
              <span className={`text-[10px] px-2 py-0.5 border tracking-wider ${threatLevelClass}`}>
                {safeUpper(actor.threatLevel, "MEDIUM")} THREAT
              </span>
              {actor.sophistication && (
                <span className="text-[10px] px-2 py-0.5 bg-secondary text-muted-foreground tracking-wider">
                  {safeUpper(actor.sophistication)}
                </span>
              )}
              {actor.motivation && (
                <span className="text-[10px] px-2 py-0.5 bg-secondary text-muted-foreground tracking-wider">
                  {safeUpper(actor.motivation)}
                </span>
              )}
            </div>
            {aliases.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-3">
                <span className="text-[10px] text-muted-foreground mr-1">AKA:</span>
                {aliases.map((a: string) => (
                  <span key={a} className="text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground">{a}</span>
                ))}
              </div>
            )}
            {actor.description && (
              <p className="text-sm text-muted-foreground max-w-3xl leading-relaxed">{actor.description}</p>
            )}
          </div>

          {/* Actions */}
          <div className="flex gap-2 shrink-0">
            <button
              onClick={handleEnrich}
              disabled={enriching}
              className="flex items-center gap-2 px-3 py-2 bg-primary/10 border border-primary/20 text-primary text-xs font-display tracking-wider hover:bg-primary/20 transition-colors disabled:opacity-50"
            >
              {enriching ? <Loader2 className="w-3 h-3 animate-spin" /> : <Brain className="w-3 h-3" />}
              LLM ENRICH
            </button>
            <button
              onClick={() => refetch()}
              className="flex items-center gap-2 px-3 py-2 bg-card border border-border text-muted-foreground text-xs font-display tracking-wider hover:text-foreground transition-colors"
            >
              <RefreshCw className="w-3 h-3" />
              REFRESH
            </button>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          <div className="bg-card border border-border p-3">
            <span className="text-[10px] text-muted-foreground tracking-wider">TECHNIQUES</span>
            <p className="text-lg font-display text-primary">{techniques.length}</p>
          </div>
          <div className="bg-card border border-border p-3">
            <span className="text-[10px] text-muted-foreground tracking-wider">TOOLS</span>
            <p className="text-lg font-display text-cyan-400">{tools.length}</p>
          </div>
          <div className="bg-card border border-border p-3">
            <span className="text-[10px] text-muted-foreground tracking-wider">MALWARE</span>
            <p className="text-lg font-display text-amber-400">{malware.length}</p>
          </div>
          <div className="bg-card border border-border p-3">
            <span className="text-[10px] text-muted-foreground tracking-wider">IOCs</span>
            <p className="text-lg font-display text-red-400">{iocs.length}</p>
          </div>
          <div className="bg-card border border-border p-3">
            <span className="text-[10px] text-muted-foreground tracking-wider">EVENTS</span>
            <p className="text-lg font-display text-purple-400">{events.length}</p>
          </div>
          <div className="bg-card border border-border p-3">
            <span className="text-[10px] text-muted-foreground tracking-wider">DATA SOURCE</span>
            <p className="text-xs font-display text-muted-foreground mt-1">{actor.dataSource || "unknown"}</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-border">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-xs font-display tracking-wider border-b-2 transition-colors ${
                activeTab === tab.id
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              {tab.label}
              {tab.count !== undefined && tab.count > 0 && (
                <span className="ml-1.5 text-[10px] text-muted-foreground">({tab.count})</span>
              )}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === "overview" && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Target Sectors */}
            {sectors.length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Target className="w-4 h-4" /> TARGET SECTORS
                </h3>
                <div className="flex flex-wrap gap-2">
                  {sectors.map((s: string) => (
                    <span key={s} className="text-xs px-2 py-1 bg-red-500/10 border border-red-500/20 text-red-400">{s}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Target Regions */}
            {regions.length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Globe2 className="w-4 h-4" /> TARGET REGIONS
                </h3>
                <div className="flex flex-wrap gap-2">
                  {regions.map((r: string) => (
                    <span key={r} className="text-xs px-2 py-1 bg-blue-500/10 border border-blue-500/20 text-blue-400">{r}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Tools */}
            {tools.length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Crosshair className="w-4 h-4" /> TOOLS & SOFTWARE
                </h3>
                <div className="flex flex-wrap gap-2">
                  {tools.map((t: string) => (
                    <span key={t} className="text-xs px-2 py-1 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">{t}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Malware */}
            {malware.length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Bug className="w-4 h-4" /> MALWARE FAMILIES
                </h3>
                <div className="flex flex-wrap gap-2">
                  {malware.map((m: string) => (
                    <span key={m} className="text-xs px-2 py-1 bg-amber-500/10 border border-amber-500/20 text-amber-400">{m}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Ransomware Extension */}
            {ransomwareProfile && (
              <div className="bg-card border border-amber-500/20 p-4 lg:col-span-2">
                <h3 className="text-xs font-display tracking-wider text-amber-400 mb-3 flex items-center gap-2">
                  <Skull className="w-4 h-4" /> RANSOMWARE PROFILE
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-4">
                  <div>
                    <span className="text-[10px] text-muted-foreground">TOTAL VICTIMS</span>
                    <p className="text-lg font-display text-amber-400">{ransomwareProfile.totalVictims || 0}</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-muted-foreground">30D VICTIMS</span>
                    <p className="text-lg font-display text-amber-400">{ransomwareProfile.victims30d || 0}</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-muted-foreground">EXTORTION MODEL</span>
                    <p className="text-xs font-display text-muted-foreground mt-1">{safeUpper(ransomwareProfile.extortionModel)}</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-muted-foreground">TREND</span>
                    <p className="text-xs font-display text-muted-foreground mt-1">{safeUpper(ransomwareProfile.trend)}</p>
                  </div>
                </div>
                {ransomwareProfile.topSectors?.length > 0 && (
                  <div className="mb-3">
                    <span className="text-[10px] text-muted-foreground">TOP SECTORS: </span>
                    {ransomwareProfile.topSectors.map((s: string) => (
                      <span key={s} className="text-[10px] px-1.5 py-0.5 bg-amber-500/10 text-amber-400 mr-1">{s}</span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Activity Timeline */}
            {timeline.length > 0 && (
              <div className="bg-card border border-border p-4 lg:col-span-2">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Clock className="w-4 h-4" /> ACTIVITY TIMELINE
                </h3>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {timeline.slice(0, 20).map((entry: any, i: number) => (
                    <div key={i} className="flex items-start gap-3 text-xs">
                      <span className="text-muted-foreground shrink-0 w-20">{entry.date || "—"}</span>
                      <span className="text-foreground">{entry.event || entry.description || "—"}</span>
                      {entry.source && <span className="text-muted-foreground ml-auto text-[10px]">{entry.source}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Metadata */}
            <div className="bg-card border border-border p-4 lg:col-span-2">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <FileText className="w-4 h-4" /> METADATA
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                <div>
                  <span className="text-muted-foreground">Actor ID</span>
                  <p className="font-mono text-foreground">{actor.actorId}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">STIX ID</span>
                  <p className="font-mono text-foreground truncate">{actor.stixId || "—"}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">First Seen</span>
                  <p className="text-foreground">{actor.firstSeen || "—"}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Last Active</span>
                  <p className="text-foreground">{actor.lastActive || "—"}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Confidence</span>
                  <p className="text-foreground">{actor.confidence ?? "—"}%</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Data Source</span>
                  <p className="text-foreground">{actor.dataSource || "—"}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Created</span>
                  <p className="text-foreground">{actor.createdAt ? new Date(actor.createdAt).toLocaleDateString() : "—"}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Updated</span>
                  <p className="text-foreground">{actor.updatedAt ? new Date(actor.updatedAt).toLocaleDateString() : "—"}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === "techniques" && (
          <div className="bg-card border border-border">
            {techniques.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground text-sm">
                No MITRE ATT&CK techniques mapped. Use LLM Enrich to populate.
              </div>
            ) : (
              <div className="divide-y divide-border">
                <div className="grid grid-cols-12 gap-4 px-4 py-2 text-[10px] text-muted-foreground tracking-wider bg-muted/30">
                  <div className="col-span-2">ID</div>
                  <div className="col-span-4">NAME</div>
                  <div className="col-span-3">TACTIC</div>
                  <div className="col-span-3">DESCRIPTION</div>
                </div>
                {techniques.map((t: any, i: number) => {
                  const techId = typeof t === "string" ? t : t.id;
                  const techName = typeof t === "string" ? t : t.name || t.id;
                  const tactic = typeof t === "string" ? "—" : t.tactic || "—";
                  const desc = typeof t === "string" ? "" : t.description || "";
                  return (
                    <div key={i} className="grid grid-cols-12 gap-4 px-4 py-2.5 text-xs hover:bg-accent/5 transition-colors">
                      <div className="col-span-2 font-mono text-primary">{techId}</div>
                      <div className="col-span-4 text-foreground">{techName}</div>
                      <div className="col-span-3 text-muted-foreground capitalize">{tactic}</div>
                      <div className="col-span-3 text-muted-foreground truncate">{desc}</div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === "events" && (
          <div className="space-y-3">
            {events.length === 0 ? (
              <div className="bg-card border border-border p-8 text-center text-muted-foreground text-sm">
                No events recorded. Events are populated via LLM monitoring sweeps and external feeds.
              </div>
            ) : (
              events.map((evt: any) => {
                const evtColor = EVENT_TYPE_COLORS[evt.eventType] || "text-gray-400 bg-gray-500/10";
                return (
                  <div key={evt.id} className="bg-card border border-border p-4">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] px-2 py-0.5 ${evtColor} tracking-wider`}>
                          {safeUpper(evt.eventType?.replace(/_/g, " "))}
                        </span>
                        <span className={`text-[10px] px-2 py-0.5 border ${THREAT_LEVEL_COLORS[evt.severity || "medium"]} tracking-wider`}>
                          {safeUpper(evt.severity, "MEDIUM")}
                        </span>
                      </div>
                      <span className="text-[10px] text-muted-foreground">
                        {evt.eventDate ? new Date(evt.eventDate).toLocaleDateString() : "—"}
                      </span>
                    </div>
                    <h4 className="text-sm font-display tracking-wider mb-1">{evt.title}</h4>
                    {evt.description && (
                      <p className="text-xs text-muted-foreground mb-2">{evt.description}</p>
                    )}
                    <div className="flex items-center gap-4 text-[10px] text-muted-foreground">
                      {evt.victimName && <span>Victim: {evt.victimName}</span>}
                      {evt.victimSector && <span>Sector: {evt.victimSector}</span>}
                      {evt.source && <span>Source: {evt.source}</span>}
                      {evt.mitreTechniques?.length > 0 && (
                        <span className="text-primary">{evt.mitreTechniques.length} TTPs</span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        )}

        {activeTab === "iocs" && (
          <div className="bg-card border border-border">
            {iocs.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground text-sm">
                No IOCs recorded. IOCs are populated via LLM enrichment and external feeds.
              </div>
            ) : (
              <div className="divide-y divide-border">
                <div className="grid grid-cols-12 gap-4 px-4 py-2 text-[10px] text-muted-foreground tracking-wider bg-muted/30">
                  <div className="col-span-2">TYPE</div>
                  <div className="col-span-4">VALUE</div>
                  <div className="col-span-2">CONFIDENCE</div>
                  <div className="col-span-2">SOURCE</div>
                  <div className="col-span-2">LAST SEEN</div>
                </div>
                {iocs.map((ioc: any) => (
                  <div key={ioc.id} className="grid grid-cols-12 gap-4 px-4 py-2.5 text-xs hover:bg-accent/5 transition-colors">
                    <div className="col-span-2">
                      <span className="text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground">
                        {safeUpper(ioc.type)}
                      </span>
                    </div>
                    <div className="col-span-4 font-mono text-foreground truncate">{ioc.value}</div>
                    <div className="col-span-2 text-muted-foreground capitalize">{ioc.confidence || "—"}</div>
                    <div className="col-span-2 text-muted-foreground">{ioc.source || "—"}</div>
                    <div className="col-span-2 text-muted-foreground">{ioc.lastSeen || "—"}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === "caldera" && actor.calderaProfile && (
          <div className="bg-card border border-cyan-500/20 p-6">
            <h3 className="text-sm font-display tracking-wider text-cyan-400 mb-4 flex items-center gap-2">
              <Activity className="w-5 h-5" /> CALDERA ADVERSARY PROFILE
            </h3>
            <div className="grid grid-cols-2 gap-4 text-xs mb-4">
              <div>
                <span className="text-muted-foreground">Caldera ID</span>
                <p className="font-mono text-foreground">{actor.calderaProfile.id || "—"}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Atomic Ordering</span>
                <p className="text-foreground">{actor.calderaProfile.atomicOrdering?.length || 0} abilities</p>
              </div>
            </div>
            {actor.calderaProfile.objectives && (
              <div>
                <span className="text-[10px] text-muted-foreground tracking-wider">OBJECTIVES</span>
                <p className="text-xs text-foreground mt-1">{JSON.stringify(actor.calderaProfile.objectives)}</p>
              </div>
            )}
          </div>
        )}
      </div>
    </AppShell>
  );
}
