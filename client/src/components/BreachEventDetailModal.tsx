/**
 * BreachEventDetailModal — Rich detail view for breach events.
 * Shows threat actor profile, IOCs, MITRE ATT&CK techniques, related events,
 * and ransomware group profile when available.
 */
import { trpc } from "@/lib/trpc";
import { useState } from "react";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Skull, Shield, AlertTriangle, Database, FileWarning, Globe, Building2,
  Calendar, ExternalLink, Target, Fingerprint, Network, Crosshair,
  TrendingUp, Clock, Eye, Copy, Check, ChevronRight, Loader2,
  Siren, Lock, Bug, Layers, Server,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

// ─── Types ───────────────────────────────────────────────────────────────

interface BreachEventDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  eventId: number | null;
  eventType: "ransomware" | "data_leak" | "unauthorized_access" | "incident" | null;
}

// ─── Helpers ─────────────────────────────────────────────────────────────

function severityBadge(severity: string | null | undefined) {
  const s = severity?.toLowerCase();
  const config: Record<string, { color: string; label: string }> = {
    critical: { color: "bg-red-500/20 text-red-400 border-red-500/50", label: "CRITICAL" },
    high: { color: "bg-orange-500/20 text-orange-400 border-orange-500/50", label: "HIGH" },
    medium: { color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/50", label: "MEDIUM" },
    low: { color: "bg-blue-500/20 text-blue-400 border-blue-500/50", label: "LOW" },
    info: { color: "bg-zinc-500/20 text-zinc-400 border-zinc-500/50", label: "INFO" },
  };
  const c = config[s || ""] || config.info!;
  return (
    <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${c.color}`}>
      {c.label}
    </Badge>
  );
}

function typeIcon(type: string) {
  switch (type) {
    case "ransomware": return <Skull className="h-5 w-5 text-red-400" />;
    case "data_leak": return <Database className="h-5 w-5 text-yellow-400" />;
    case "unauthorized_access": return <Lock className="h-5 w-5 text-purple-400" />;
    case "incident": return <AlertTriangle className="h-5 w-5 text-amber-400" />;
    default: return <Shield className="h-5 w-5 text-zinc-400" />;
  }
}

function typeLabel(type: string) {
  switch (type) {
    case "ransomware": return "Ransomware Attack";
    case "data_leak": return "Data Leak";
    case "unauthorized_access": return "Unauthorized Access";
    case "incident": return "Incident Report";
    default: return type;
  }
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      className="p-0.5 hover:bg-zinc-700 rounded transition-colors"
      title="Copy to clipboard"
    >
      {copied ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3 text-muted-foreground" />}
    </button>
  );
}

// ─── Component ───────────────────────────────────────────────────────────

export default function BreachEventDetailModal({
  open, onOpenChange, eventId, eventType,
}: BreachEventDetailModalProps) {
  const [tab, setTab] = useState("overview");

  const { data, isLoading } = trpc.darkwebIntel.getBreachEventDetail.useQuery(
    { eventId: eventId!, eventType: eventType! },
    { enabled: open && eventId !== null && eventType !== null },
  );

  const event = data?.event;
  const actor = data?.actor;
  const actorIocs = data?.actorIocs || [];
  const ransomwareProfile = data?.ransomwareProfile;
  const relatedEvents = data?.relatedEvents || [];

  // Collect all MITRE techniques from various sources
  const allTechniques: Array<{ id: string; name?: string; tactic?: string }> = [];
  if (actor?.techniques) {
    actor.techniques.forEach((t: any) => {
      if (typeof t === "string") allTechniques.push({ id: t });
      else if (t?.id) allTechniques.push(t);
    });
  }
  if (event?.mitreTechniques) {
    event.mitreTechniques.forEach((t: any) => {
      if (typeof t === "string" && !allTechniques.find(x => x.id === t)) allTechniques.push({ id: t });
      else if (t?.id && !allTechniques.find(x => x.id === t.id)) allTechniques.push(t);
    });
  }
  if (event?.ttpsExtracted) {
    event.ttpsExtracted.forEach((t: any) => {
      if (t?.techniqueId && !allTechniques.find(x => x.id === t.techniqueId)) {
        allTechniques.push({ id: t.techniqueId, name: t.techniqueName, tactic: t.tactic });
      }
    });
  }
  if (ransomwareProfile?.mitreTechniques) {
    ransomwareProfile.mitreTechniques.forEach((t: any) => {
      const id = typeof t === "string" ? t : t?.id;
      if (id && !allTechniques.find(x => x.id === id)) allTechniques.push(typeof t === "string" ? { id: t } : t);
    });
  }

  // Collect all IOCs from various sources
  const allIocs: Array<{ type: string; value: string; source?: string; confidence?: string }> = [];
  actorIocs.forEach((ioc: any) => {
    allIocs.push({ type: ioc.type, value: ioc.value, source: ioc.source, confidence: ioc.confidence });
  });
  if (event?.iocsExtracted) {
    event.iocsExtracted.forEach((ioc: any) => {
      if (ioc?.value && !allIocs.find(x => x.value === ioc.value)) {
        allIocs.push({ type: ioc.type, value: ioc.value, source: "incident_report" });
      }
    });
  }
  if (event?.iocValue && !allIocs.find(x => x.value === event.iocValue)) {
    allIocs.push({ type: event.iocType || "unknown", value: event.iocValue, source: event.source });
  }
  // Add IOCs from related events
  relatedEvents.forEach((re: any) => {
    (re.iocs || []).forEach((ioc: any) => {
      if (ioc?.value && !allIocs.find(x => x.value === ioc.value)) {
        allIocs.push({ type: ioc.type, value: ioc.value, source: re.source });
      }
    });
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto bg-zinc-950 border-zinc-800 p-0">
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
            <span className="ml-3 text-muted-foreground">Loading event details...</span>
          </div>
        ) : !event ? (
          <div className="flex items-center justify-center py-20">
            <AlertTriangle className="h-8 w-8 text-muted-foreground mr-3" />
            <span className="text-muted-foreground">Event not found or data unavailable.</span>
          </div>
        ) : (
          <>
            {/* Header */}
            <div className="p-6 pb-4 border-b border-zinc-800">
              <div className="flex items-start gap-3">
                {typeIcon(event.type)}
                <div className="flex-1 min-w-0">
                  <DialogHeader>
                    <DialogTitle className="text-lg font-bold text-white leading-tight">
                      {event.title}
                    </DialogTitle>
                  </DialogHeader>
                  <div className="flex items-center gap-2 mt-2 flex-wrap">
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-zinc-600 text-zinc-300">
                      {typeLabel(event.type)}
                    </Badge>
                    {severityBadge(event.severity)}
                    {event.source && (
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-zinc-700 text-zinc-400">
                        {event.source}
                      </Badge>
                    )}
                    {event.publishedAt && (
                      <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                        <Calendar className="h-3 w-3" />
                        {new Date(event.publishedAt).toLocaleDateString()}
                      </span>
                    )}
                    {event.sourceUrl && (
                      <a
                        href={event.sourceUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[10px] text-blue-400 hover:text-blue-300 flex items-center gap-1"
                      >
                        <ExternalLink className="h-3 w-3" /> Source
                      </a>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Tabs */}
            <Tabs value={tab} onValueChange={setTab} className="px-6 pt-4">
              <TabsList className="bg-zinc-900/50 mb-4">
                <TabsTrigger value="overview">Overview</TabsTrigger>
                {allTechniques.length > 0 && <TabsTrigger value="mitre">ATT&CK ({allTechniques.length})</TabsTrigger>}
                {allIocs.length > 0 && <TabsTrigger value="iocs">IOCs ({allIocs.length})</TabsTrigger>}
                {relatedEvents.length > 0 && <TabsTrigger value="timeline">Timeline ({relatedEvents.length})</TabsTrigger>}
              </TabsList>

              {/* ── Overview Tab ── */}
              <TabsContent value="overview" className="space-y-4 pb-6">
                {/* Description */}
                {event.description && (
                  <div className="bg-zinc-900/50 border border-zinc-800 p-4 rounded-sm">
                    <p className="text-sm text-zinc-300 leading-relaxed">{event.description}</p>
                  </div>
                )}

                {/* Victim / Target Info */}
                {(event.victimName || event.victimSector || event.victimCountry || event.country || event.sector) && (
                  <div className="bg-zinc-900/50 border border-zinc-800 p-4 rounded-sm">
                    <h4 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                      <Target className="h-3.5 w-3.5" /> TARGET INFORMATION
                    </h4>
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      {(event.victimName || event.groupName) && (
                        <div>
                          <span className="text-muted-foreground text-xs">Victim</span>
                          <p className="text-white">{event.victimName || "—"}</p>
                        </div>
                      )}
                      {(event.victimSector || event.sector) && (() => {
                        const sectorStr = String(event.victimSector || event.sector);
                        const sectors = sectorStr.split(/,\s*/).filter(Boolean);
                        return (
                          <div>
                            <span className="text-muted-foreground text-xs">Sector{sectors.length > 1 ? "s" : ""}</span>
                            <div className="flex flex-wrap gap-1 mt-0.5">
                              {sectors.map((s: string, i: number) => (
                                <span key={i} className="text-xs px-1.5 py-0.5 bg-orange-500/10 border border-orange-500/20 text-orange-300 flex items-center gap-1">
                                  {i === 0 && <Building2 className="h-3 w-3" />}{s.trim()}
                                </span>
                              ))}
                            </div>
                          </div>
                        );
                      })()}
                      {(event.victimCountry || event.country) && (
                        <div>
                          <span className="text-muted-foreground text-xs">Country</span>
                          <p className="text-white flex items-center gap-1">
                            <Globe className="h-3 w-3 text-muted-foreground" />
                            {event.victimCountry || event.country}
                          </p>
                        </div>
                      )}
                      {event.incidentType && (
                        <div>
                          <span className="text-muted-foreground text-xs">Incident Type</span>
                          <p className="text-white capitalize">{event.incidentType}</p>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Threat Actor Profile */}
                {actor && (
                  <div className="bg-zinc-900/50 border border-red-500/20 p-4 rounded-sm">
                    <h4 className="text-xs font-display tracking-wider text-red-400 mb-3 flex items-center gap-2">
                      <Skull className="h-3.5 w-3.5" /> THREAT ACTOR PROFILE
                    </h4>
                    <div className="space-y-3">
                      <div className="flex items-center gap-3">
                        <span className="text-lg font-bold text-white">{actor.name}</span>
                        {actor.type && (
                          <Badge variant="outline" className="text-[10px] border-red-500/50 text-red-400 uppercase">
                            {actor.type}
                          </Badge>
                        )}
                        {actor.threatLevel && severityBadge(actor.threatLevel)}
                        {actor.sophistication && (
                          <Badge variant="outline" className="text-[10px] border-purple-500/50 text-purple-400">
                            {actor.sophistication}
                          </Badge>
                        )}
                      </div>
                      {actor.aliases?.length > 0 && (
                        <div className="text-xs text-muted-foreground">
                          Also known as: {actor.aliases.join(", ")}
                        </div>
                      )}
                      {actor.description && (
                        <p className="text-sm text-zinc-300 leading-relaxed">{actor.description}</p>
                      )}
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                        {actor.origin && (
                          <div>
                            <span className="text-muted-foreground">Origin</span>
                            <p className="text-white flex items-center gap-1"><Globe className="h-3 w-3" /> {actor.origin}</p>
                          </div>
                        )}
                        {actor.motivation && (
                          <div>
                            <span className="text-muted-foreground">Motivation</span>
                            <p className="text-white capitalize">{actor.motivation}</p>
                          </div>
                        )}
                        {actor.firstSeen && (
                          <div>
                            <span className="text-muted-foreground">First Seen</span>
                            <p className="text-white">{actor.firstSeen}</p>
                          </div>
                        )}
                        {actor.lastActive && (
                          <div>
                            <span className="text-muted-foreground">Last Active</span>
                            <p className="text-white">{actor.lastActive}</p>
                          </div>
                        )}
                      </div>
                      {actor.targetSectors?.length > 0 && (
                        <div>
                          <span className="text-xs text-muted-foreground">Target Sectors</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {actor.targetSectors.map((s: string) => (
                              <Badge key={s} variant="outline" className="text-[9px] border-zinc-700 text-zinc-300">{s}</Badge>
                            ))}
                          </div>
                        </div>
                      )}
                      {actor.tools?.length > 0 && (
                        <div>
                          <span className="text-xs text-muted-foreground">Tools & Malware</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {[...actor.tools, ...(actor.malware || [])].map((t: string) => (
                              <Badge key={t} variant="outline" className="text-[9px] border-cyan-500/30 text-cyan-400">{t}</Badge>
                            ))}
                          </div>
                        </div>
                      )}
                      {actor.confidence && (
                        <div className="text-[10px] text-muted-foreground flex items-center gap-1">
                          <Eye className="h-3 w-3" /> Confidence: {actor.confidence}% · Source: {actor.dataSource || "osint"}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Ransomware Group Profile */}
                {ransomwareProfile && (
                  <div className="bg-zinc-900/50 border border-orange-500/20 p-4 rounded-sm">
                    <h4 className="text-xs font-display tracking-wider text-orange-400 mb-3 flex items-center gap-2">
                      <Siren className="h-3.5 w-3.5" /> RANSOMWARE GROUP PROFILE
                    </h4>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="bg-zinc-800/50 p-2 text-center rounded-sm">
                        <div className="text-xl font-bold text-orange-400">{ransomwareProfile.activityScore || 0}</div>
                        <div className="text-[9px] text-muted-foreground">Activity Score</div>
                      </div>
                      <div className="bg-zinc-800/50 p-2 text-center rounded-sm">
                        <div className="text-xl font-bold text-red-400">{ransomwareProfile.totalVictims || 0}</div>
                        <div className="text-[9px] text-muted-foreground">Total Victims</div>
                      </div>
                      <div className="bg-zinc-800/50 p-2 text-center rounded-sm">
                        <div className="text-xl font-bold text-yellow-400">{ransomwareProfile.victims30d || 0}</div>
                        <div className="text-[9px] text-muted-foreground">Last 30 Days</div>
                      </div>
                      <div className="bg-zinc-800/50 p-2 text-center rounded-sm">
                        <div className="text-xl font-bold text-white capitalize">{ransomwareProfile.trend || "unknown"}</div>
                        <div className="text-[9px] text-muted-foreground">Trend</div>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3 mt-3 text-xs">
                      {ransomwareProfile.ransomwareFamily && (
                        <div>
                          <span className="text-muted-foreground">Ransomware Family</span>
                          <p className="text-white">{ransomwareProfile.ransomwareFamily}</p>
                        </div>
                      )}
                      {ransomwareProfile.extortionModel && (
                        <div>
                          <span className="text-muted-foreground">Extortion Model</span>
                          <p className="text-white capitalize">{ransomwareProfile.extortionModel}</p>
                        </div>
                      )}
                    </div>
                    {ransomwareProfile.topSectors?.length > 0 && (
                      <div className="mt-3">
                        <span className="text-xs text-muted-foreground">Top Target Sectors</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {ransomwareProfile.topSectors.map((s: string) => (
                            <Badge key={s} variant="outline" className="text-[9px] border-orange-500/30 text-orange-300">{s}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {ransomwareProfile.knownInfrastructure?.length > 0 && (
                      <div className="mt-3">
                        <span className="text-xs text-muted-foreground">Known Infrastructure</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {ransomwareProfile.knownInfrastructure.map((s: string) => (
                            <Badge key={s} variant="outline" className="text-[9px] border-zinc-700 text-zinc-400 font-mono">{s}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Attack Narrative (for incident reports) */}
                {event.attackNarrative && (
                  <div className="bg-zinc-900/50 border border-zinc-800 p-4 rounded-sm">
                    <h4 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                      <Layers className="h-3.5 w-3.5" /> ATTACK NARRATIVE
                    </h4>
                    <p className="text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap">{event.attackNarrative}</p>
                  </div>
                )}

                {/* Lessons Learned */}
                {event.lessonsLearned && (
                  <div className="bg-zinc-900/50 border border-green-500/20 p-4 rounded-sm">
                    <h4 className="text-xs font-display tracking-wider text-green-400 mb-3 flex items-center gap-2">
                      <Shield className="h-3.5 w-3.5" /> LESSONS LEARNED
                    </h4>
                    <p className="text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap">{event.lessonsLearned}</p>
                  </div>
                )}

                {/* Quick IOC / Technique summary if not enough for separate tabs */}
                {allTechniques.length > 0 && allTechniques.length <= 5 && (
                  <div className="bg-zinc-900/50 border border-zinc-800 p-4 rounded-sm">
                    <h4 className="text-xs font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-2">
                      <Crosshair className="h-3.5 w-3.5" /> MITRE ATT&CK TECHNIQUES
                    </h4>
                    <div className="flex flex-wrap gap-1">
                      {allTechniques.map(t => (
                        <a
                          key={t.id}
                          href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[10px] font-mono px-1.5 py-0.5 bg-primary/10 text-primary border border-primary/30 hover:bg-primary/20 transition-colors"
                        >
                          {t.id}{t.name ? ` — ${t.name}` : ""}
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {allIocs.length > 0 && allIocs.length <= 5 && (
                  <div className="bg-zinc-900/50 border border-zinc-800 p-4 rounded-sm">
                    <h4 className="text-xs font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-2">
                      <Fingerprint className="h-3.5 w-3.5" /> INDICATORS OF COMPROMISE
                    </h4>
                    <div className="space-y-1">
                      {allIocs.map((ioc, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs">
                          <Badge variant="outline" className="text-[9px] border-zinc-700 text-zinc-400 uppercase w-16 justify-center">
                            {ioc.type}
                          </Badge>
                          <code className="text-zinc-300 font-mono text-[11px] truncate flex-1">{ioc.value}</code>
                          <CopyButton text={ioc.value} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </TabsContent>

              {/* ── MITRE ATT&CK Tab ── */}
              {allTechniques.length > 0 && (
                <TabsContent value="mitre" className="space-y-3 pb-6">
                  <div className="text-xs text-muted-foreground mb-2">
                    {allTechniques.length} techniques mapped from threat actor profile, event data, and ransomware group intelligence.
                  </div>
                  <div className="space-y-1">
                    {allTechniques.map(t => (
                      <a
                        key={t.id}
                        href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-3 p-2 bg-zinc-900/50 border border-zinc-800 hover:border-primary/30 transition-colors group"
                      >
                        <span className="font-mono text-sm text-primary font-medium w-20 shrink-0">{t.id}</span>
                        <span className="text-sm text-zinc-300 flex-1 truncate">
                          {t.name || "—"}
                        </span>
                        {t.tactic && (
                          <Badge variant="outline" className="text-[9px] border-zinc-700 text-zinc-400 capitalize shrink-0">
                            {t.tactic}
                          </Badge>
                        )}
                        <ExternalLink className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                      </a>
                    ))}
                  </div>
                </TabsContent>
              )}

              {/* ── IOCs Tab ── */}
              {allIocs.length > 0 && (
                <TabsContent value="iocs" className="space-y-3 pb-6">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-muted-foreground">
                      {allIocs.length} indicators from threat actor database, event data, and related intelligence.
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs"
                      onClick={() => {
                        const text = allIocs.map(i => `${i.type}\t${i.value}`).join("\n");
                        navigator.clipboard.writeText(text);
                        toast.success("IOCs copied to clipboard");
                      }}
                    >
                      <Copy className="h-3 w-3 mr-1" /> Copy All
                    </Button>
                  </div>
                  <div className="space-y-1 max-h-[400px] overflow-y-auto">
                    {allIocs.map((ioc, i) => (
                      <div key={i} className="flex items-center gap-2 p-2 bg-zinc-900/50 border border-zinc-800 text-xs">
                        <Badge variant="outline" className="text-[9px] border-zinc-700 text-zinc-400 uppercase w-16 justify-center shrink-0">
                          {ioc.type}
                        </Badge>
                        <code className="text-zinc-300 font-mono text-[11px] truncate flex-1 min-w-0">{ioc.value}</code>
                        {ioc.confidence && (
                          <Badge variant="outline" className="text-[9px] border-zinc-700 text-zinc-500 shrink-0">
                            {ioc.confidence}
                          </Badge>
                        )}
                        {ioc.source && (
                          <span className="text-[9px] text-zinc-600 shrink-0">{ioc.source}</span>
                        )}
                        <CopyButton text={ioc.value} />
                      </div>
                    ))}
                  </div>
                </TabsContent>
              )}

              {/* ── Timeline Tab ── */}
              {relatedEvents.length > 0 && (
                <TabsContent value="timeline" className="space-y-3 pb-6">
                  <div className="text-xs text-muted-foreground mb-2">
                    {relatedEvents.length} related events for this threat actor.
                  </div>
                  <div className="space-y-1">
                    {relatedEvents.map((re: any) => (
                      <div key={re.id} className="flex items-start gap-3 p-3 bg-zinc-900/50 border border-zinc-800">
                        <div className="w-1 h-full min-h-[40px] bg-zinc-700 shrink-0 rounded-full" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-medium text-white truncate">{re.title}</span>
                            {re.severity && severityBadge(re.severity)}
                            <Badge variant="outline" className="text-[9px] border-zinc-700 text-zinc-400 capitalize">
                              {re.eventType?.replace("_", " ")}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                            {re.eventDate && (
                              <span className="flex items-center gap-1">
                                <Calendar className="h-2.5 w-2.5" />
                                {new Date(re.eventDate).toLocaleDateString()}
                              </span>
                            )}
                            {re.victimName && (
                              <span className="flex items-center gap-1">
                                <Target className="h-2.5 w-2.5" /> {re.victimName}
                              </span>
                            )}
                            {re.victimSector && (() => {
                              const sectors = String(re.victimSector).split(/,\s*/).filter(Boolean);
                              return sectors.map((s: string, i: number) => (
                                <span key={i} className="flex items-center gap-1">
                                  {i === 0 && <Building2 className="h-2.5 w-2.5" />}{s.trim()}
                                </span>
                              ));
                            })()}
                            {re.victimCountry && (
                              <span className="flex items-center gap-1">
                                <Globe className="h-2.5 w-2.5" /> {re.victimCountry}
                              </span>
                            )}
                            {re.source && (
                              <span>{re.source}</span>
                            )}
                            {re.sourceUrl && (
                              <a
                                href={re.sourceUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-blue-400 hover:text-blue-300 flex items-center gap-1"
                              >
                                <ExternalLink className="h-2.5 w-2.5" /> Source
                              </a>
                            )}
                          </div>
                          {re.mitreTechniques?.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1.5">
                              {re.mitreTechniques.slice(0, 5).map((t: any) => {
                                const id = typeof t === "string" ? t : t?.id;
                                return (
                                  <span key={id} className="text-[9px] font-mono px-1 py-0.5 bg-primary/10 text-primary border border-primary/30">
                                    {id}
                                  </span>
                                );
                              })}
                              {re.mitreTechniques.length > 5 && (
                                <span className="text-[9px] text-muted-foreground">+{re.mitreTechniques.length - 5} more</span>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>
              )}
            </Tabs>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
