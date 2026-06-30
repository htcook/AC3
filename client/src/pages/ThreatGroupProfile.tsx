/**
 * Threat Group Profile Page
 * 
 * Deep-dive into a single threat group: TTPs, tools, attack history,
 * IOCs, FedRAMP supply chain exposure, and related groups.
 * Accessible from Executive Dashboard threat group matches.
 */

import { useState, useMemo } from "react";
import { useRoute, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import {
  Shield, Globe, Target, Crosshair, AlertTriangle, ChevronLeft,
  Calendar, MapPin, Users, Cpu, Lock, Eye, FileText, ExternalLink,
  ChevronRight, Layers, Zap, ShieldAlert, Building2, Server,
  Activity, Hash, Clock
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";

const THREAT_COLORS = {
  critical: { text: "text-red-500", bg: "bg-red-500/10", border: "border-red-500/30", badge: "destructive" as const },
  high: { text: "text-orange-500", bg: "bg-orange-500/10", border: "border-orange-500/30", badge: "default" as const },
  medium: { text: "text-yellow-500", bg: "bg-yellow-500/10", border: "border-yellow-500/30", badge: "secondary" as const },
  low: { text: "text-emerald-500", bg: "bg-emerald-500/10", border: "border-emerald-500/30", badge: "outline" as const },
};

const TYPE_LABELS: Record<string, string> = {
  apt: "Advanced Persistent Threat",
  ransomware: "Ransomware Group",
  cybercrime: "Cybercrime Organization",
  hacktivist: "Hacktivist Group",
};

export default function ThreatGroupProfile() {
  const [, params] = useRoute("/threat-group/:id");
  const [, navigate] = useLocation();
  const groupId = params?.id || "";

  const profileInput = useMemo(() => ({ groupId }), [groupId]);
  const { data: profile, isLoading } = trpc.threatIntelMatching.groupProfile.useQuery(profileInput);

  if (isLoading) {
    return (
      <div className="flex flex-col gap-6 p-6 max-w-[1400px] mx-auto">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-[200px]" />
        <Skeleton className="h-[400px]" />
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 p-12">
        <ShieldAlert className="w-12 h-12 text-muted-foreground" />
        <h2 className="text-xl font-semibold">Threat Group Not Found</h2>
        <p className="text-muted-foreground">The group "{groupId}" was not found in the knowledge base.</p>
        <Button variant="outline" onClick={() => navigate("/executive-dashboard")}>
          <ChevronLeft className="w-4 h-4 mr-1" /> Back to Dashboard
        </Button>
      </div>
    );
  }

  const g = profile.group;
  const colors = THREAT_COLORS[g.threatLevel as keyof typeof THREAT_COLORS] || THREAT_COLORS.medium;

  return (
    <div className="flex flex-col gap-6 p-6 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate("/executive-dashboard")}>
            <ChevronLeft className="w-5 h-5" />
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold">{g.name}</h1>
              <Badge variant={colors.badge} className="text-xs uppercase">{g.threatLevel}</Badge>
              <Badge variant="outline" className="text-xs">{g.type.toUpperCase()}</Badge>
              {g.active && <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 text-xs">Active</Badge>}
            </div>
            <p className="text-sm text-muted-foreground mt-1">
              {TYPE_LABELS[g.type] || g.type} — Origin: {g.origin}
              {g.mitreGroupId && <span className="ml-2 font-mono text-xs">({g.mitreGroupId})</span>}
            </p>
            {g.aliases.length > 0 && (
              <p className="text-xs text-muted-foreground mt-1">
                Also known as: {g.aliases.join(", ")}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className={`${colors.bg} ${colors.border}`}>
          <CardContent className="p-4 text-center">
            <Crosshair className={`w-5 h-5 mx-auto mb-1 ${colors.text}`} />
            <div className={`text-2xl font-bold tabular-nums ${colors.text}`}>{g.ttps.length}</div>
            <div className="text-xs text-muted-foreground">Known TTPs</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <Cpu className="w-5 h-5 mx-auto mb-1 text-primary" />
            <div className="text-2xl font-bold tabular-nums">{g.tools.length}</div>
            <div className="text-xs text-muted-foreground">Tools Used</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <AlertTriangle className="w-5 h-5 mx-auto mb-1 text-orange-500" />
            <div className="text-2xl font-bold tabular-nums">{g.exploitedCVEs.length}</div>
            <div className="text-xs text-muted-foreground">Exploited CVEs</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <Building2 className="w-5 h-5 mx-auto mb-1 text-blue-500" />
            <div className="text-2xl font-bold tabular-nums">{profile.fedrampExposure.length}</div>
            <div className="text-xs text-muted-foreground">FedRAMP Exposures</div>
          </CardContent>
        </Card>
      </div>

      {/* Description */}
      {g.description && (
        <Card>
          <CardContent className="p-4">
            <p className="text-sm leading-relaxed">{g.description}</p>
            {g.motivation && (
              <p className="text-sm text-muted-foreground mt-2">
                <strong>Motivation:</strong> {g.motivation}
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Tabbed Detail Sections */}
      <Tabs defaultValue="ttps" className="w-full">
        <TabsList className="w-full justify-start bg-muted/30 p-1 flex-wrap">
          <TabsTrigger value="ttps" className="gap-1.5">
            <Crosshair className="w-4 h-4" /> TTPs
          </TabsTrigger>
          <TabsTrigger value="tools" className="gap-1.5">
            <Cpu className="w-4 h-4" /> Tools
          </TabsTrigger>
          <TabsTrigger value="cves" className="gap-1.5">
            <AlertTriangle className="w-4 h-4" /> CVEs
          </TabsTrigger>
          <TabsTrigger value="history" className="gap-1.5">
            <Calendar className="w-4 h-4" /> Attack History
          </TabsTrigger>
          <TabsTrigger value="fedramp" className="gap-1.5">
            <Building2 className="w-4 h-4" /> FedRAMP Exposure
          </TabsTrigger>
          <TabsTrigger value="defense" className="gap-1.5">
            <Shield className="w-4 h-4" /> Defense
          </TabsTrigger>
        </TabsList>

        {/* TTPs Tab */}
        <TabsContent value="ttps" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">MITRE ATT&CK Techniques ({g.ttps.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border/50">
                      <th className="text-left py-2 px-3 text-xs text-muted-foreground font-medium">Technique</th>
                      <th className="text-left py-2 px-3 text-xs text-muted-foreground font-medium">Tactic</th>
                      <th className="text-center py-2 px-3 text-xs text-muted-foreground font-medium">Frequency</th>
                      <th className="text-left py-2 px-3 text-xs text-muted-foreground font-medium">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {g.ttps.map((ttp, i) => (
                      <tr key={i} className="border-b border-border/20 hover:bg-muted/20">
                        <td className="py-2 px-3">
                          <span className="font-mono text-xs text-primary">{ttp.techniqueId}</span>
                          <span className="ml-2 text-sm">{ttp.techniqueName}</span>
                        </td>
                        <td className="py-2 px-3">
                          <Badge variant="outline" className="text-xs capitalize">{ttp.tactic}</Badge>
                        </td>
                        <td className="py-2 px-3 text-center">
                          <Badge variant={ttp.frequency === "primary" ? "destructive" : ttp.frequency === "secondary" ? "default" : "secondary"} className="text-xs">
                            {ttp.frequency}
                          </Badge>
                        </td>
                        <td className="py-2 px-3 text-xs text-muted-foreground max-w-[300px] truncate">{ttp.description}</td>
                      </tr>
                    ))}
                    {g.ttps.length === 0 && (
                      <tr><td colSpan={4} className="py-8 text-center text-muted-foreground">No TTPs recorded</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tools Tab */}
        <TabsContent value="tools" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Tools & Malware ({g.tools.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {g.tools.map((tool, i) => (
                  <div key={i} className="p-3 rounded-lg bg-muted/30 border hover:border-primary/30 transition-colors">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-sm">{tool.name}</span>
                      <Badge variant="outline" className="text-xs capitalize">{tool.category}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">{tool.description}</p>
                  </div>
                ))}
                {g.tools.length === 0 && (
                  <p className="text-muted-foreground text-sm col-span-2 text-center py-8">No tools recorded</p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* CVEs Tab */}
        <TabsContent value="cves" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Exploited CVEs ({g.exploitedCVEs.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {g.exploitedCVEs.map((cve, i) => (
                  <Badge key={i} variant="outline" className="font-mono text-xs hover:bg-primary/10 cursor-pointer">
                    {cve}
                  </Badge>
                ))}
                {g.exploitedCVEs.length === 0 && (
                  <p className="text-muted-foreground text-sm w-full text-center py-8">No exploited CVEs recorded</p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Attack History Tab */}
        <TabsContent value="history" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Attack History ({profile.attackHistory.length} events)</CardTitle>
            </CardHeader>
            <CardContent>
              {profile.attackHistory.length === 0 ? (
                <p className="text-muted-foreground text-sm text-center py-8">No attack history events recorded in database</p>
              ) : (
                <div className="flex flex-col gap-4">
                  {profile.attackHistory.map((event) => (
                    <div key={event.id} className="p-4 rounded-lg bg-muted/30 border">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h4 className="font-medium text-sm">{event.title}</h4>
                          <div className="flex items-center gap-2 mt-1">
                            <Badge variant="outline" className="text-xs capitalize">{event.eventType}</Badge>
                            {event.severity && <Badge variant={event.severity === "critical" ? "destructive" : "secondary"} className="text-xs">{event.severity}</Badge>}
                          </div>
                        </div>
                        {event.eventDate && (
                          <span className="text-xs text-muted-foreground flex items-center gap-1">
                            <Calendar className="w-3 h-3" /> {event.eventDate}
                          </span>
                        )}
                      </div>
                      {event.description && <p className="text-xs text-muted-foreground mt-1">{event.description}</p>}
                      <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                        {event.victimName && <span><Target className="w-3 h-3 inline mr-1" />{event.victimName}</span>}
                        {event.victimSector && <span><Building2 className="w-3 h-3 inline mr-1" />{event.victimSector}</span>}
                        {event.victimCountry && <span><Globe className="w-3 h-3 inline mr-1" />{event.victimCountry}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* FedRAMP Exposure Tab */}
        <TabsContent value="fedramp" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Building2 className="w-4 h-4 text-blue-500" />
                FedRAMP Supply Chain Exposure ({profile.fedrampExposure.length} providers at risk)
              </CardTitle>
            </CardHeader>
            <CardContent>
              {profile.fedrampExposure.length === 0 ? (
                <p className="text-muted-foreground text-sm text-center py-8">No FedRAMP supply chain exposure identified</p>
              ) : (
                <div className="flex flex-col gap-3">
                  {profile.fedrampExposure.map((exp, i) => {
                    const riskColors = THREAT_COLORS[exp.riskLevel as keyof typeof THREAT_COLORS] || THREAT_COLORS.medium;
                    return (
                      <div key={i} className={`p-4 rounded-lg border ${riskColors.bg} ${riskColors.border}`}>
                        <div className="flex items-start justify-between mb-2">
                          <div>
                            <h4 className="font-medium text-sm">{exp.provider.name}</h4>
                            <div className="flex items-center gap-2 mt-1">
                              <Badge variant="outline" className="text-xs">{exp.provider.serviceModel}</Badge>
                              <Badge variant="outline" className="text-xs">{exp.provider.impactLevel} Impact</Badge>
                              <Badge variant="outline" className="text-xs">{exp.provider.category}</Badge>
                            </div>
                          </div>
                          <Badge variant={riskColors.badge} className="text-xs uppercase">{exp.riskLevel} risk</Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-2">{exp.exposureReason}</p>
                        {exp.mitigations.length > 0 && (
                          <div className="mt-3">
                            <span className="text-xs font-medium">Recommended Mitigations:</span>
                            <ul className="mt-1 text-xs text-muted-foreground list-disc list-inside">
                              {exp.mitigations.slice(0, 4).map((m, j) => (
                                <li key={j}>{m}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Defense Tab */}
        <TabsContent value="defense" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Initial Access Methods</CardTitle>
              </CardHeader>
              <CardContent>
                {g.initialAccessMethods.length === 0 ? (
                  <p className="text-muted-foreground text-sm text-center py-4">No initial access methods recorded</p>
                ) : (
                  <div className="flex flex-col gap-2">
                    {g.initialAccessMethods.map((m, i) => (
                      <div key={i} className="flex items-center gap-2 p-2 rounded bg-muted/30">
                        <Zap className="w-3 h-3 text-orange-500 shrink-0" />
                        <span className="text-sm">{m}</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Defense Recommendations</CardTitle>
              </CardHeader>
              <CardContent>
                {g.defenseRecommendations.length === 0 ? (
                  <p className="text-muted-foreground text-sm text-center py-4">No defense recommendations available</p>
                ) : (
                  <div className="flex flex-col gap-2">
                    {g.defenseRecommendations.map((rec, i) => (
                      <div key={i} className="p-3 rounded-lg bg-muted/30 border">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge variant={rec.priority === "critical" ? "destructive" : rec.priority === "high" ? "default" : "secondary"} className="text-xs">{rec.priority}</Badge>
                          <Badge variant="outline" className="text-xs capitalize">{rec.category}</Badge>
                        </div>
                        <p className="text-sm">{rec.recommendation}</p>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Target Info */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Target Sectors</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {g.targetSectors.map((s, i) => (
                    <Badge key={i} variant="outline" className="text-xs capitalize">{s}</Badge>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Target Regions</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {g.targetRegions.map((r, i) => (
                    <Badge key={i} variant="outline" className="text-xs">{r}</Badge>
                  ))}
                  {g.targetRegions.length === 0 && (
                    <p className="text-muted-foreground text-sm">No specific regions recorded</p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      {/* Related Groups */}
      {profile.relatedGroups.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Users className="w-4 h-4" /> Related Threat Groups
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              {profile.relatedGroups.map((rg, i) => (
                <Button
                  key={i}
                  variant="outline"
                  size="sm"
                  className="gap-2"
                  onClick={() => navigate(`/threat-group/${rg.id}`)}
                >
                  {rg.name}
                  <span className="text-xs text-muted-foreground">({rg.relationship})</span>
                  <ChevronRight className="w-3 h-3" />
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
