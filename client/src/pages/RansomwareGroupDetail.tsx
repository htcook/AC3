import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { safeUpper } from "@/lib/utils-safe";
import { useParams, Link } from "wouter";
import {
  ArrowLeft, Skull, TrendingUp, TrendingDown, Minus, Flame,
  Users, Target, Globe2, Clock, Shield, Activity, Crosshair,
  AlertTriangle, ExternalLink, Database,
} from "lucide-react";

const TREND_CONFIG: Record<string, { icon: typeof TrendingUp; color: string; label: string }> = {
  surging: { icon: Flame, color: "text-red-500", label: "SURGING" },
  active: { icon: TrendingUp, color: "text-green-400", label: "ACTIVE" },
  declining: { icon: TrendingDown, color: "text-yellow-400", label: "DECLINING" },
  dormant: { icon: Minus, color: "text-gray-500", label: "DORMANT" },
};

const THREAT_LEVEL_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-green-400 bg-green-500/10 border-green-500/30",
};

export default function RansomwareGroupDetail() {
  const { name } = useParams<{ name: string }>();
  const groupName = decodeURIComponent(name || "");

  const { data, isLoading } = trpc.threatIntel.ransomwareDetail.useQuery(
    { groupName },
    { enabled: !!groupName }
  );

  if (isLoading) {
    return (
      <AppShell activePath="/ransomware-groups">
        <div className="max-w-[1400px] mx-auto animate-pulse space-y-4">
          <div className="h-8 bg-muted rounded w-1/3" />
          <div className="h-4 bg-muted rounded w-2/3" />
          <div className="grid grid-cols-4 gap-4">{[1,2,3,4].map(i => <div key={i} className="h-24 bg-muted rounded" />)}</div>
        </div>
      </AppShell>
    );
  }

  if (!data?.group) {
    return (
      <AppShell activePath="/ransomware-groups">
        <div className="max-w-[1400px] mx-auto text-center py-20">
          <Skull className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <h2 className="text-xl font-display tracking-wider mb-2">GROUP NOT FOUND</h2>
          <Link href="/ransomware-groups" className="text-amber-400 hover:underline text-sm">Return to Ransomware Groups</Link>
        </div>
      </AppShell>
    );
  }

  const { group, events, linkedActor } = data;
  const trendConf = TREND_CONFIG[group.trend || "active"] || TREND_CONFIG.active;
  const TrendIcon = trendConf.icon;
  const threatClass = THREAT_LEVEL_COLORS[group.threatLevel || "medium"] || THREAT_LEVEL_COLORS.medium;
  const aliases: string[] = Array.isArray(group.aliases) ? group.aliases : [];
  const sectors: string[] = Array.isArray(group.topSectors) ? group.topSectors : [];
  const countries: string[] = Array.isArray(group.topCountries) ? group.topCountries : [];
  const malware: string[] = Array.isArray(group.associatedMalware) ? group.associatedMalware : [];
  const techniques: string[] = Array.isArray(group.mitreTechniques) ? group.mitreTechniques : [];
  const infra: string[] = Array.isArray(group.knownInfrastructure) ? group.knownInfrastructure : [];
  const attacks: any[] = Array.isArray(group.notableAttacks) ? group.notableAttacks : [];

  return (
    <AppShell activePath="/ransomware-groups">
      <div className="max-w-[1400px] mx-auto space-y-6">
        <Link href="/ransomware-groups" className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground text-sm transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Ransomware Groups
        </Link>

        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Skull className="w-8 h-8 text-amber-400" />
              <h1 className="text-2xl lg:text-3xl font-display tracking-wider">{group.groupName}</h1>
              <TrendIcon className={`w-6 h-6 ${trendConf.color}`} />
            </div>
            <div className="flex items-center gap-2 flex-wrap mb-3">
              <span className={`text-[10px] px-2 py-0.5 ${trendConf.color} tracking-wider`}>{trendConf.label}</span>
              <span className={`text-[10px] px-2 py-0.5 border tracking-wider ${threatClass}`}>{safeUpper(group.threatLevel, "MEDIUM")}</span>
              {group.extortionModel && group.extortionModel !== "unknown" && (
                <span className="text-[10px] px-2 py-0.5 bg-secondary text-muted-foreground tracking-wider">{safeUpper(group.extortionModel)} EXTORTION</span>
              )}
              {group.affiliateProgram && <span className="text-[10px] px-2 py-0.5 bg-purple-500/10 text-purple-400 tracking-wider">RAAS AFFILIATE</span>}
              {group.ransomwareFamily && <span className="text-[10px] px-2 py-0.5 bg-amber-500/10 text-amber-400 tracking-wider">{group.ransomwareFamily}</span>}
            </div>
            {aliases.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-3">
                <span className="text-[10px] text-muted-foreground mr-1">AKA:</span>
                {aliases.map((a: string) => <span key={a} className="text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground">{a}</span>)}
              </div>
            )}
            {group.description && <p className="text-sm text-muted-foreground max-w-3xl leading-relaxed">{group.description}</p>}
          </div>
          {linkedActor && (
            <Link href={`/threat-catalog/${linkedActor.actorId}`}
              className="flex items-center gap-2 px-3 py-2 bg-primary/10 border border-primary/20 text-primary text-xs font-display tracking-wider hover:bg-primary/20 transition-colors shrink-0">
              <Database className="w-3 h-3" /> VIEW IN CATALOG
            </Link>
          )}
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            { label: "ACTIVITY SCORE", value: group.activityScore || 0, color: "text-amber-400" },
            { label: "TOTAL VICTIMS", value: group.totalVictims || 0, color: "text-red-400" },
            { label: "7D VICTIMS", value: group.victims7d || 0, color: "text-orange-400" },
            { label: "30D VICTIMS", value: group.victims30d || 0, color: "text-orange-400" },
            { label: "TECHNIQUES", value: techniques.length, color: "text-primary" },
            { label: "CONFIDENCE", value: `${group.confidence || 0}%`, color: "text-green-400" },
          ].map(s => (
            <div key={s.label} className="bg-card border border-border p-3">
              <span className="text-[10px] text-muted-foreground tracking-wider">{s.label}</span>
              <p className={`text-xl font-display ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Target Sectors */}
          {sectors.length > 0 && (
            <div className="bg-card border border-border p-4">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <Target className="w-4 h-4" /> TOP TARGET SECTORS
              </h3>
              <div className="flex flex-wrap gap-2">
                {sectors.map((s: string) => <span key={s} className="text-xs px-2 py-1 bg-red-500/10 border border-red-500/20 text-red-400">{s}</span>)}
              </div>
            </div>
          )}

          {/* Target Countries */}
          {countries.length > 0 && (
            <div className="bg-card border border-border p-4">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <Globe2 className="w-4 h-4" /> TOP TARGET COUNTRIES
              </h3>
              <div className="flex flex-wrap gap-2">
                {countries.map((c: string) => <span key={c} className="text-xs px-2 py-1 bg-blue-500/10 border border-blue-500/20 text-blue-400">{c}</span>)}
              </div>
            </div>
          )}

          {/* Malware */}
          {malware.length > 0 && (
            <div className="bg-card border border-border p-4">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" /> ASSOCIATED MALWARE
              </h3>
              <div className="flex flex-wrap gap-2">
                {malware.map((m: string) => <span key={m} className="text-xs px-2 py-1 bg-purple-500/10 border border-purple-500/20 text-purple-400">{m}</span>)}
              </div>
            </div>
          )}

          {/* MITRE Techniques */}
          {techniques.length > 0 && (
            <div className="bg-card border border-border p-4">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <Crosshair className="w-4 h-4" /> MITRE ATT&CK TECHNIQUES
              </h3>
              <div className="flex flex-wrap gap-2">
                {techniques.map((t: string) => <span key={t} className="text-xs px-2 py-1 bg-primary/10 border border-primary/20 text-primary font-mono">{t}</span>)}
              </div>
            </div>
          )}

          {/* Infrastructure */}
          {infra.length > 0 && (
            <div className="bg-card border border-border p-4 lg:col-span-2">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <Globe2 className="w-4 h-4" /> KNOWN INFRASTRUCTURE
              </h3>
              <div className="space-y-1">
                {infra.map((url: string, i: number) => (
                  <div key={i} className="text-xs font-mono text-muted-foreground flex items-center gap-2">
                    <ExternalLink className="w-3 h-3 shrink-0" />
                    <span className="truncate">{url}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Notable Attacks */}
          {attacks.length > 0 && (
            <div className="bg-card border border-border p-4 lg:col-span-2">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <Activity className="w-4 h-4" /> NOTABLE ATTACKS
              </h3>
              <div className="space-y-3">
                {attacks.map((a: any, i: number) => (
                  <div key={i} className="border-b border-border/50 pb-2 last:border-0">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-display">{a.victim || a.name || `Attack ${i + 1}`}</span>
                      <span className="text-[10px] text-muted-foreground">{a.date || "—"}</span>
                    </div>
                    {a.description && <p className="text-[11px] text-muted-foreground mt-1">{a.description}</p>}
                    {a.ransom && <span className="text-[10px] text-amber-400">Ransom: {a.ransom}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Victim Events */}
        {events && events.length > 0 && (
          <div className="bg-card border border-border p-4">
            <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
              <Users className="w-4 h-4" /> RECENT VICTIM EVENTS ({events.length})
            </h3>
            <div className="divide-y divide-border max-h-96 overflow-y-auto">
              {events.map((evt: any) => (
                <div key={evt.id} className="py-2 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="text-foreground font-display truncate">{evt.victimName}</span>
                    {evt.country && <span className="text-[10px] px-1.5 py-0.5 bg-blue-500/10 text-blue-400 shrink-0">{evt.country}</span>}
                    {evt.sector && <span className="text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground shrink-0">{evt.sector}</span>}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {evt.verified && <span className="text-[10px] text-green-400">VERIFIED</span>}
                    <span className="text-muted-foreground">{evt.publishedAt ? new Date(evt.publishedAt).toLocaleDateString() : "—"}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Metadata */}
        <div className="bg-card border border-border p-4">
          <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3">METADATA</h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
            <div><span className="text-muted-foreground">First Seen</span><p>{group.firstSeen || "—"}</p></div>
            <div><span className="text-muted-foreground">Last Active</span><p>{group.lastActive || "—"}</p></div>
            <div><span className="text-muted-foreground">Data Source</span><p>{group.dataSource || "—"}</p></div>
            <div><span className="text-muted-foreground">Last Enriched</span><p>{group.lastEnriched ? new Date(group.lastEnriched).toLocaleDateString() : "—"}</p></div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
