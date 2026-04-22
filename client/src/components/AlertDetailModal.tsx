/**
 * AlertDetailModal — Rich detail view for escalation alerts.
 * Shows threat actor profile, victim info, timeline, IOCs, MITRE techniques,
 * related events, ransomware profile, and access broker listings.
 */
import { trpc } from "@/lib/trpc";
import { safeUpper } from "@/lib/utils-safe";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  AlertTriangle, Shield, Skull, Clock, Globe2, Crosshair, Eye,
  Zap, Bug, Key, ExternalLink, Users, Network, Loader2,
  MapPin, Target, Fingerprint, Swords, FileText, TrendingUp,
} from "lucide-react";

interface AlertDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  eventId: number | null;
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/40",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/40",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/40",
};

const ACTOR_TYPE_BADGE: Record<string, string> = {
  apt: "bg-red-500/15 text-red-400 border-red-500/30",
  ransomware: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  cybercrime: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  hacktivist: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  access_broker: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  influence_ops: "bg-pink-500/15 text-pink-400 border-pink-500/30",
};

const THREAT_LEVEL_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-blue-400",
};

function formatDate(d: string | Date | null | undefined): string {
  if (!d) return "—";
  const date = typeof d === "string" ? new Date(d) : d;
  return date.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function timeAgo(dateStr: string | null | undefined): string {
  if (!dateStr) return "";
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;
  const hours = Math.floor(diff / (1000 * 60 * 60));
  if (hours < 1) return "< 1h ago";
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  if (days < 30) return `${Math.floor(days / 7)}w ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

export default function AlertDetailModal({ open, onOpenChange, eventId }: AlertDetailModalProps) {
  const { data, isLoading, error } = trpc.darkwebIntel.alertDetail.useQuery(
    { eventId: eventId! },
    { enabled: !!eventId && open }
  );

  const event = data?.event;
  const actor = data?.actor;
  const relatedEvents = data?.relatedEvents || [];
  const actorIocs = data?.actorIocs || [];
  const feedIocs = (data as any)?.feedIocs || [];
  const totalIocCount = actorIocs.length + feedIocs.length;
  const ransomwareProfile = data?.ransomwareProfile;
  const brokerListings = data?.brokerListings || [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[90vh] p-0 bg-background border-border overflow-hidden">
        <DialogHeader className="px-6 pt-5 pb-3 border-b border-border bg-card">
          <div className="flex items-center gap-3">
            <div className={`p-2 border ${SEVERITY_BADGE[event?.severity || "high"] || SEVERITY_BADGE.high}`}>
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div className="flex-1 min-w-0">
              <DialogTitle className="text-base font-display tracking-wider leading-tight">
                {event?.title || "Loading..."}
              </DialogTitle>
              <DialogDescription className="text-xs text-muted-foreground mt-1 flex items-center gap-2 flex-wrap">
                {event?.severity && (
                  <span className={`px-1.5 py-0.5 text-[9px] font-display tracking-wider border ${SEVERITY_BADGE[event.severity]}`}>
                    {safeUpper(event.severity)}
                  </span>
                )}
                {event?.eventType && (
                  <span className="px-1.5 py-0.5 text-[9px] font-display tracking-wider bg-muted border border-border">
                    {safeUpper(event.eventType.replace(/_/g, " "))}
                  </span>
                )}
                {event?.eventDate && (
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" /> {formatDate(event.eventDate)}
                  </span>
                )}
                {event?.source && (
                  <span className="flex items-center gap-1">
                    <Globe2 className="w-3 h-3" /> {event.source}
                  </span>
                )}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <ScrollArea className="max-h-[calc(90vh-100px)]">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
              <span className="ml-3 text-sm text-muted-foreground">Loading alert intelligence...</span>
            </div>
          ) : error ? (
            <div className="text-center py-16 text-red-400 text-sm">
              Failed to load alert details: {error.message}
            </div>
          ) : !data ? (
            <div className="text-center py-16 text-muted-foreground text-sm">
              Alert not found.
            </div>
          ) : (
            <Tabs defaultValue="overview" className="w-full">
              <TabsList className="w-full justify-start rounded-none border-b border-border bg-card px-6 h-auto py-0">
                <TabsTrigger value="overview" className="font-display tracking-wider text-[11px] rounded-none border-b-2 border-transparent data-[state=active]:border-primary py-2.5">
                  OVERVIEW
                </TabsTrigger>
                {actor && (
                  <TabsTrigger value="actor" className="font-display tracking-wider text-[11px] rounded-none border-b-2 border-transparent data-[state=active]:border-red-400 py-2.5">
                    THREAT ACTOR
                  </TabsTrigger>
                )}
                {totalIocCount > 0 && (
                  <TabsTrigger value="iocs" className="font-display tracking-wider text-[11px] rounded-none border-b-2 border-transparent data-[state=active]:border-amber-400 py-2.5">
                    IOCs ({totalIocCount})
                  </TabsTrigger>
                )}
                {relatedEvents.length > 0 && (
                  <TabsTrigger value="related" className="font-display tracking-wider text-[11px] rounded-none border-b-2 border-transparent data-[state=active]:border-cyan-400 py-2.5">
                    RELATED ({relatedEvents.length})
                  </TabsTrigger>
                )}
              </TabsList>

              {/* ── OVERVIEW TAB ── */}
              <TabsContent value="overview" className="px-6 py-4 space-y-5 mt-0">
                {/* Event description */}
                {event?.description && (
                  <div>
                    <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-2">DESCRIPTION</h4>
                    <p className="text-sm text-foreground/90 leading-relaxed">{event.description}</p>
                  </div>
                )}

                {/* Victim Information */}
                {(event?.victimName || event?.victimSector || event?.victimCountry) && (
                  <div className="bg-card border border-border p-4">
                    <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-3 flex items-center gap-2">
                      <Target className="w-3.5 h-3.5 text-red-400" /> VICTIM INFORMATION
                    </h4>
                    <div className="grid grid-cols-3 gap-4">
                      {event.victimName && (
                        <div>
                          <div className="text-[9px] text-muted-foreground tracking-wider mb-0.5">ORGANIZATION</div>
                          <div className="text-sm font-medium">{event.victimName}</div>
                        </div>
                      )}
                      {event.victimSector && (
                        <div>
                          <div className="text-[9px] text-muted-foreground tracking-wider mb-0.5">SECTOR{String(event.victimSector).includes(",") ? "S" : ""}</div>
                          <div className="flex flex-wrap gap-1">
                            {String(event.victimSector).split(/,\s*/).filter(Boolean).map((s: string, i: number) => (
                              <span key={i} className="text-xs px-1.5 py-0.5 bg-orange-500/10 border border-orange-500/20 text-orange-300">{s.trim()}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {event.victimCountry && (
                        <div>
                          <div className="text-[9px] text-muted-foreground tracking-wider mb-0.5">COUNTRY</div>
                          <div className="text-sm flex items-center gap-1"><MapPin className="w-3 h-3 text-muted-foreground" />{event.victimCountry}</div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Threat Actor Summary Card */}
                {actor && (
                  <div className="bg-card border border-border p-4">
                    <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-3 flex items-center gap-2">
                      <Skull className="w-3.5 h-3.5 text-red-400" /> THREAT ACTOR
                    </h4>
                    <div className="flex items-start gap-4">
                      <div className={`p-3 border ${ACTOR_TYPE_BADGE[actor.type || ""] || "bg-muted border-border"}`}>
                        <Skull className="w-6 h-6" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-display tracking-wider">{actor.name}</span>
                          {actor.type && (
                            <span className={`text-[9px] px-1.5 py-0.5 border font-display tracking-wider ${ACTOR_TYPE_BADGE[actor.type] || "bg-muted border-border text-muted-foreground"}`}>
                              {safeUpper(actor.type.replace(/_/g, " "))}
                            </span>
                          )}
                          {actor.threatLevel && (
                            <span className={`text-[9px] font-display tracking-wider ${THREAT_LEVEL_COLORS[actor.threatLevel] || "text-muted-foreground"}`}>
                              {safeUpper(actor.threatLevel)} THREAT
                            </span>
                          )}
                        </div>
                        {actor.aliases && actor.aliases.length > 0 && (
                          <div className="text-[10px] text-muted-foreground mt-1">
                            AKA: {actor.aliases.slice(0, 5).join(", ")}
                            {actor.aliases.length > 5 && ` +${actor.aliases.length - 5} more`}
                          </div>
                        )}
                        {actor.description && (
                          <p className="text-xs text-muted-foreground mt-2 leading-relaxed line-clamp-3">{actor.description}</p>
                        )}
                        <div className="flex flex-wrap gap-2 mt-2">
                          {actor.origin && (
                            <span className="text-[9px] px-1.5 py-0.5 bg-muted border border-border text-muted-foreground">
                              <Globe2 className="w-2.5 h-2.5 inline mr-1" />{actor.origin}
                            </span>
                          )}
                          {actor.motivation && (
                            <span className="text-[9px] px-1.5 py-0.5 bg-muted border border-border text-muted-foreground">
                              {actor.motivation}
                            </span>
                          )}
                          {actor.sophistication && (
                            <span className="text-[9px] px-1.5 py-0.5 bg-muted border border-border text-muted-foreground">
                              <Fingerprint className="w-2.5 h-2.5 inline mr-1" />{actor.sophistication}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* MITRE Techniques */}
                {event?.mitreTechniques && event.mitreTechniques.length > 0 && (
                  <div>
                    <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-2 flex items-center gap-2">
                      <Crosshair className="w-3.5 h-3.5 text-primary" /> MITRE ATT&CK TECHNIQUES
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {event.mitreTechniques.map((t: any) => {
                        const tid = typeof t === "string" ? t : t.id || t.technique_id || "";
                        const tname = typeof t === "string" ? "" : t.name || "";
                        return (
                          <a
                            key={tid}
                            href={`https://attack.mitre.org/techniques/${tid.replace(/\./g, "/")}/`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[10px] font-mono px-2 py-1 bg-primary/10 text-primary border border-primary/30 hover:bg-primary/20 transition-colors flex items-center gap-1"
                          >
                            {tid}{tname && ` — ${tname}`}
                            <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* IOCs from event */}
                {event?.iocs && event.iocs.length > 0 && (
                  <div>
                    <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-2 flex items-center gap-2">
                      <Bug className="w-3.5 h-3.5 text-amber-400" /> EVENT IOCs
                    </h4>
                    <div className="space-y-1">
                      {event.iocs.slice(0, 10).map((ioc: any, i: number) => (
                        <div key={i} className="flex items-center gap-2 text-xs bg-card border border-border px-3 py-1.5">
                          <span className="text-[9px] px-1.5 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/30 font-display tracking-wider shrink-0">
                            {safeUpper(typeof ioc === "string" ? "INDICATOR" : ioc.type || "IOC")}
                          </span>
                          <span className="font-mono text-muted-foreground truncate">
                            {typeof ioc === "string" ? ioc : ioc.value || ioc.indicator || JSON.stringify(ioc)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Ransomware Profile */}
                {ransomwareProfile && (
                  <div className="bg-red-500/5 border border-red-500/20 p-4">
                    <h4 className="text-[10px] font-display tracking-widest text-red-400 mb-3 flex items-center gap-2">
                      <Skull className="w-3.5 h-3.5" /> RANSOMWARE PROFILE
                    </h4>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="text-center">
                        <div className="text-lg font-display text-red-400">{ransomwareProfile.totalVictims ?? 0}</div>
                        <div className="text-[9px] tracking-wider text-muted-foreground">TOTAL VICTIMS</div>
                      </div>
                      <div className="text-center">
                        <div className="text-lg font-display text-orange-400">{ransomwareProfile.victims30d ?? 0}</div>
                        <div className="text-[9px] tracking-wider text-muted-foreground">LAST 30 DAYS</div>
                      </div>
                      <div className="text-center">
                        <div className="text-lg font-display text-amber-400">{ransomwareProfile.victims7d ?? 0}</div>
                        <div className="text-[9px] tracking-wider text-muted-foreground">LAST 7 DAYS</div>
                      </div>
                      <div className="text-center">
                        <div className={`text-lg font-display ${THREAT_LEVEL_COLORS[ransomwareProfile.threatLevel || ""] || "text-muted-foreground"}`}>
                          {safeUpper(ransomwareProfile.threatLevel || "—")}
                        </div>
                        <div className="text-[9px] tracking-wider text-muted-foreground">THREAT LEVEL</div>
                      </div>
                    </div>
                    {ransomwareProfile.extortionModel && (
                      <div className="mt-3 text-xs text-muted-foreground">
                        <span className="text-[9px] tracking-wider text-red-400 mr-2">EXTORTION MODEL:</span>
                        {ransomwareProfile.extortionModel}
                      </div>
                    )}
                    {ransomwareProfile.ransomwareFamily && (
                      <div className="mt-1 text-xs text-muted-foreground">
                        <span className="text-[9px] tracking-wider text-red-400 mr-2">FAMILY:</span>
                        {ransomwareProfile.ransomwareFamily}
                      </div>
                    )}
                  </div>
                )}

                {/* Access Broker Listings */}
                {brokerListings.length > 0 && (
                  <div className="bg-orange-500/5 border border-orange-500/20 p-4">
                    <h4 className="text-[10px] font-display tracking-widest text-orange-400 mb-3 flex items-center gap-2">
                      <Key className="w-3.5 h-3.5" /> LINKED ACCESS BROKER LISTINGS
                    </h4>
                    <div className="space-y-2">
                      {brokerListings.map((listing: any, i: number) => (
                        <div key={i} className="flex items-center justify-between text-xs border border-orange-500/20 px-3 py-2">
                          <div className="flex items-center gap-2">
                            <span className="font-display text-orange-400">{listing.brokerName || listing.brokerId}</span>
                            {listing.accessType && (
                              <span className="text-[9px] px-1.5 py-0.5 bg-muted border border-border">{listing.accessType}</span>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            {listing.victimSector && (
                              <div className="flex flex-wrap gap-0.5">
                                {String(listing.victimSector).split(/,\s*/).filter(Boolean).map((s: string, i: number) => (
                                  <span key={i} className="text-[9px] px-1 py-0.5 bg-orange-500/10 border border-orange-500/20 text-orange-300">{s.trim()}</span>
                                ))}
                              </div>
                            )}
                            {listing.askingPrice && (
                              <span className="text-green-400 font-mono">${listing.askingPrice}</span>
                            )}
                            <span className={`text-[9px] px-1.5 py-0.5 border ${
                              listing.status === "active" ? "text-green-400 border-green-500/30 bg-green-500/10" : "text-muted-foreground border-border"
                            }`}>{safeUpper(listing.status || "—")}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Source link */}
                {event?.sourceUrl && (
                  <div className="pt-2 border-t border-border">
                    <a
                      href={event.sourceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-primary hover:underline flex items-center gap-1"
                    >
                      <ExternalLink className="w-3 h-3" /> View Original Source
                    </a>
                  </div>
                )}
              </TabsContent>

              {/* ── THREAT ACTOR TAB ── */}
              {actor && (
                <TabsContent value="actor" className="px-6 py-4 space-y-5 mt-0">
                  {/* Full actor profile */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-3">
                      <div>
                        <div className="text-[9px] text-muted-foreground tracking-wider mb-0.5">ACTOR ID</div>
                        <div className="text-sm font-mono">{actor.actorId}</div>
                      </div>
                      <div>
                        <div className="text-[9px] text-muted-foreground tracking-wider mb-0.5">TYPE</div>
                        <div className="text-sm">{actor.type?.replace(/_/g, " ") || "—"}</div>
                      </div>
                      <div>
                        <div className="text-[9px] text-muted-foreground tracking-wider mb-0.5">ORIGIN</div>
                        <div className="text-sm">{actor.origin || "—"}</div>
                      </div>
                      <div>
                        <div className="text-[9px] text-muted-foreground tracking-wider mb-0.5">MOTIVATION</div>
                        <div className="text-sm">{actor.motivation || "—"}</div>
                      </div>
                    </div>
                    <div className="space-y-3">
                      <div>
                        <div className="text-[9px] text-muted-foreground tracking-wider mb-0.5">FIRST SEEN</div>
                        <div className="text-sm">{formatDate(actor.firstSeen)}</div>
                      </div>
                      <div>
                        <div className="text-[9px] text-muted-foreground tracking-wider mb-0.5">LAST ACTIVE</div>
                        <div className="text-sm">{formatDate(actor.lastActive)}</div>
                      </div>
                      <div>
                        <div className="text-[9px] text-muted-foreground tracking-wider mb-0.5">SOPHISTICATION</div>
                        <div className="text-sm">{actor.sophistication || "—"}</div>
                      </div>
                      <div>
                        <div className="text-[9px] text-muted-foreground tracking-wider mb-0.5">CONFIDENCE</div>
                        <div className="text-sm">{actor.confidence != null ? `${actor.confidence}%` : "—"}</div>
                      </div>
                    </div>
                  </div>

                  {/* Description */}
                  {actor.description && (
                    <div>
                      <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-2">DESCRIPTION</h4>
                      <p className="text-xs text-muted-foreground leading-relaxed">{actor.description}</p>
                    </div>
                  )}

                  {/* Target Sectors */}
                  {actor.targetSectors && actor.targetSectors.length > 0 && (
                    <div>
                      <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-2 flex items-center gap-2">
                        <Target className="w-3 h-3 text-red-400" /> TARGET SECTORS
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                        {actor.targetSectors.map((s: string) => (
                          <span key={s} className="text-[10px] px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/20">{s}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Target Regions */}
                  {actor.targetRegions && actor.targetRegions.length > 0 && (
                    <div>
                      <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-2 flex items-center gap-2">
                        <MapPin className="w-3 h-3 text-blue-400" /> TARGET REGIONS
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                        {actor.targetRegions.map((r: string) => (
                          <span key={r} className="text-[10px] px-2 py-1 bg-blue-500/10 text-blue-400 border border-blue-500/20">{r}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Tools & Malware */}
                  {((actor.tools && actor.tools.length > 0) || (actor.malware && actor.malware.length > 0)) && (
                    <div>
                      <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-2 flex items-center gap-2">
                        <Swords className="w-3 h-3 text-purple-400" /> TOOLS & MALWARE
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                        {(actor.tools || []).map((t: string) => (
                          <span key={t} className="text-[10px] px-2 py-1 bg-purple-500/10 text-purple-400 border border-purple-500/20 font-mono">{t}</span>
                        ))}
                        {(actor.malware || []).map((m: string) => (
                          <span key={m} className="text-[10px] px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/20 font-mono">{m}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Techniques */}
                  {actor.techniques && actor.techniques.length > 0 && (
                    <div>
                      <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-2 flex items-center gap-2">
                        <Crosshair className="w-3 h-3 text-primary" /> KNOWN TECHNIQUES ({actor.techniques.length})
                      </h4>
                      <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
                        {actor.techniques.map((t: any) => {
                          const tid = typeof t === "string" ? t : t.id || t.technique_id || "";
                          return (
                            <span key={tid} className="text-[9px] font-mono px-1.5 py-0.5 bg-primary/10 text-primary border border-primary/30">
                              {tid}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Data source */}
                  {actor.dataSource && (
                    <div className="text-[10px] text-muted-foreground pt-2 border-t border-border">
                      Source: {actor.dataSource}
                    </div>
                  )}
                </TabsContent>
              )}

              {/* ── IOCs TAB ── */}
              {totalIocCount > 0 && (
                <TabsContent value="iocs" className="px-6 py-4 space-y-4 mt-0">
                  {actorIocs.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-[10px] font-display tracking-widest text-muted-foreground flex items-center gap-2">
                        <Bug className="w-3.5 h-3.5 text-amber-400" /> ACTOR IOCs ({actorIocs.length})
                      </h4>
                      <div className="space-y-1.5">
                        {actorIocs.map((ioc: any, i: number) => (
                          <div key={`actor-${i}`} className="flex items-start gap-3 bg-card border border-border px-3 py-2">
                            <span className="text-[9px] px-1.5 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/30 font-display tracking-wider shrink-0 mt-0.5">
                              {safeUpper(ioc.type || "IOC")}
                            </span>
                            <div className="flex-1 min-w-0">
                              <div className="font-mono text-xs text-foreground break-all">{ioc.value}</div>
                              {ioc.description && <div className="text-[10px] text-muted-foreground mt-0.5">{ioc.description}</div>}
                              <div className="flex items-center gap-3 mt-1 text-[9px] text-muted-foreground">
                                {ioc.firstSeen && <span>First: {formatDate(ioc.firstSeen)}</span>}
                                {ioc.lastSeen && <span>Last: {formatDate(ioc.lastSeen)}</span>}
                                {ioc.confidence != null && <span>Conf: {ioc.confidence}%</span>}
                                {ioc.source && <span>Src: {ioc.source}</span>}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {feedIocs.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-[10px] font-display tracking-widest text-muted-foreground flex items-center gap-2">
                        <Network className="w-3.5 h-3.5 text-purple-400" /> CORRELATED FEED IOCs ({feedIocs.length})
                      </h4>
                      <div className="space-y-1.5">
                        {feedIocs.map((ioc: any, i: number) => (
                          <div key={`feed-${i}`} className="flex items-start gap-3 bg-card border border-purple-500/20 px-3 py-2">
                            <span className="text-[9px] px-1.5 py-0.5 bg-purple-500/10 text-purple-400 border border-purple-500/30 font-display tracking-wider shrink-0 mt-0.5">
                              {safeUpper(ioc.iocType || "IOC")}
                            </span>
                            <div className="flex-1 min-w-0">
                              <div className="font-mono text-xs text-foreground break-all">{ioc.iocValue}</div>
                              <div className="flex items-center gap-3 mt-1 text-[9px] text-muted-foreground">
                                {ioc.threatType && <span className="text-red-400">{ioc.threatType}</span>}
                                {ioc.malwareFamily && <span className="text-amber-400">{ioc.malwareFamily}</span>}
                                {ioc.confidence != null && <span>Conf: {ioc.confidence}%</span>}
                                {ioc.source && <span>Src: {ioc.source}</span>}
                                {ioc.firstSeen && <span>First: {formatDate(ioc.firstSeen)}</span>}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </TabsContent>
              )}

              {/* ── RELATED EVENTS TAB ── */}
              {relatedEvents.length > 0 && (
                <TabsContent value="related" className="px-6 py-4 space-y-3 mt-0">
                  <h4 className="text-[10px] font-display tracking-widest text-muted-foreground flex items-center gap-2">
                    <TrendingUp className="w-3.5 h-3.5 text-cyan-400" /> RELATED EVENTS BY SAME ACTOR
                  </h4>
                  <div className="space-y-1.5">
                    {relatedEvents.map((re: any) => (
                      <div key={re.id} className="flex items-center gap-3 bg-card border border-border px-3 py-2 text-xs">
                        <span className={`px-1.5 py-0.5 text-[9px] font-display tracking-wider border ${SEVERITY_BADGE[re.severity] || "bg-muted border-border text-muted-foreground"}`}>
                          {safeUpper(re.severity || "—")}
                        </span>
                        <span className="px-1.5 py-0.5 text-[9px] bg-muted border border-border text-muted-foreground font-display tracking-wider">
                          {safeUpper(re.eventType?.replace(/_/g, " ") || "—")}
                        </span>
                        <span className="flex-1 truncate">{re.title || re.victimName || "Event"}</span>
                        {re.victimCountry && <span className="text-muted-foreground shrink-0">{re.victimCountry}</span>}
                        <span className="text-muted-foreground shrink-0">{formatDate(re.eventDate)}</span>
                      </div>
                    ))}
                  </div>
                </TabsContent>
              )}
            </Tabs>
          )}
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}
