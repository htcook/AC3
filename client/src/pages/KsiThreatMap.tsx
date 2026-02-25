import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Shield, Target, Crosshair, Users, Zap, AlertTriangle, ChevronRight, ExternalLink } from "lucide-react";

const TACTIC_COLORS: Record<string, string> = {
  "Reconnaissance": "bg-slate-500",
  "Resource Development": "bg-gray-500",
  "Initial Access": "bg-red-600",
  "Execution": "bg-orange-500",
  "Persistence": "bg-amber-600",
  "Privilege Escalation": "bg-yellow-600",
  "Defense Evasion": "bg-lime-600",
  "Credential Access": "bg-emerald-600",
  "Discovery": "bg-teal-500",
  "Lateral Movement": "bg-cyan-600",
  "Collection": "bg-sky-500",
  "Command and Control": "bg-blue-600",
  "Exfiltration": "bg-indigo-600",
  "Impact": "bg-purple-600",
};

const ORIGIN_FLAGS: Record<string, string> = {
  "Russia": "🇷🇺",
  "China": "🇨🇳",
  "North Korea": "🇰🇵",
  "Iran": "🇮🇷",
  "US/UK": "🇺🇸",
};

export default function KsiThreatMap() {
  const [selectedKsi, setSelectedKsi] = useState<string | null>(null);

  const { data: coverage } = trpc.ksiThreatMap.getThreatCoverageMatrix.useQuery();
  const { data: exploitSummary } = trpc.ksiThreatMap.getExploitCoverageSummary.useQuery();
  const { data: threatGroups } = trpc.ksiThreatMap.getThreatGroupMappings.useQuery();
  const { data: ksiReport } = trpc.ksiThreatMap.getKsiThreatReport.useQuery(
    { ksiId: selectedKsi! },
    { enabled: !!selectedKsi }
  );
  const { data: ksiExploits } = trpc.ksiThreatMap.getExploitsForKsi.useQuery(
    { ksiId: selectedKsi! },
    { enabled: !!selectedKsi }
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">KSI Threat Map</h1>
        <p className="text-muted-foreground">
          Map FedRAMP 20x KSIs to MITRE ATT&CK techniques, threat groups, and available exploits for validation testing
        </p>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>KSIs Mapped</CardDescription>
            <CardTitle className="text-2xl">{coverage?.summary.totalKsisWithTtps ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>ATT&CK Techniques</CardDescription>
            <CardTitle className="text-2xl text-red-500">{coverage?.summary.totalTechniques ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Threat Groups</CardDescription>
            <CardTitle className="text-2xl text-amber-500">{coverage?.summary.totalThreatGroups ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Exploits Available</CardDescription>
            <CardTitle className="text-2xl text-emerald-500">{exploitSummary?.totalExploitsWithMitre ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Atomic Tests</CardDescription>
            <CardTitle className="text-2xl text-blue-500">{exploitSummary?.totalAtomicTests ?? 0}</CardTitle>
          </CardHeader>
        </Card>
      </div>

      <Tabs defaultValue="matrix" className="space-y-4">
        <TabsList>
          <TabsTrigger value="matrix">Coverage Matrix</TabsTrigger>
          <TabsTrigger value="threats">Threat Groups</TabsTrigger>
          <TabsTrigger value="exploits">Exploit Coverage</TabsTrigger>
          <TabsTrigger value="tactics">Tactic Distribution</TabsTrigger>
        </TabsList>

        {/* Coverage Matrix Tab */}
        <TabsContent value="matrix" className="space-y-3">
          {coverage?.matrix.map((item) => (
            <Card
              key={item.ksiId}
              className="cursor-pointer hover:border-primary/50 transition-colors"
              onClick={() => setSelectedKsi(item.ksiId)}
            >
              <CardContent className="p-4">
                <div className="flex items-center gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="font-mono text-xs">{item.ksiId}</Badge>
                      <span className="font-medium truncate">{item.ksiTitle}</span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {item.techniques.map((t) => (
                        <Badge key={t.id} className={`text-[10px] text-white ${TACTIC_COLORS[t.tactic] || "bg-gray-500"}`}>
                          {t.id}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-center">
                      <div className="text-xs text-muted-foreground">Techniques</div>
                      <div className="font-bold text-lg">{item.techniqueCount}</div>
                    </div>
                    <div className="text-center">
                      <div className="text-xs text-muted-foreground">Groups</div>
                      <div className="font-bold text-lg text-amber-500">{item.threatGroupCount}</div>
                    </div>
                    <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  </div>
                </div>
                {item.threatGroups.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2 pt-2 border-t">
                    {item.threatGroups.map((g) => (
                      <Badge key={g.groupId} variant="secondary" className="text-[10px]">
                        {ORIGIN_FLAGS[g.origin] || "🌐"} {g.groupName}
                      </Badge>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        {/* Threat Groups Tab */}
        <TabsContent value="threats" className="space-y-3">
          {threatGroups?.map((group) => (
            <Card key={group.groupId}>
              <CardContent className="p-4">
                <div className="flex items-center gap-4">
                  <span className="text-3xl">{ORIGIN_FLAGS[group.origin] || "🌐"}</span>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-lg">{group.groupName}</div>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Badge variant={group.type === "apt" ? "destructive" : group.type === "ransomware" ? "default" : "secondary"}>
                        {group.type.toUpperCase()}
                      </Badge>
                      <span>Origin: {group.origin}</span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {group.ksiIds.map((id) => (
                        <Badge
                          key={id}
                          variant="outline"
                          className="text-[10px] cursor-pointer hover:bg-primary/10"
                          onClick={() => setSelectedKsi(id)}
                        >
                          {id}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div className="text-center shrink-0">
                    <div className="text-xs text-muted-foreground">KSIs Defended</div>
                    <div className="font-bold text-2xl">{group.ksiIds.length}</div>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1 mt-2 pt-2 border-t">
                  <span className="text-xs text-muted-foreground mr-1">Primary TTPs:</span>
                  {group.primaryTechniques.map((t) => (
                    <Badge key={t} variant="secondary" className="text-[10px] font-mono">{t}</Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        {/* Exploit Coverage Tab */}
        <TabsContent value="exploits" className="space-y-3">
          <div className="grid grid-cols-2 gap-4 mb-4">
            <Card className="border-emerald-500/30">
              <CardHeader className="pb-2">
                <CardDescription>KSIs with Validation Tools</CardDescription>
                <CardTitle className="text-3xl text-emerald-500">{exploitSummary?.ksisWithExploits ?? 0}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="border-amber-500/30">
              <CardHeader className="pb-2">
                <CardDescription>KSIs Without Tools</CardDescription>
                <CardTitle className="text-3xl text-amber-500">{exploitSummary?.ksisWithoutExploits ?? 0}</CardTitle>
              </CardHeader>
            </Card>
          </div>
          {exploitSummary?.ksiExploitCoverage.map((item) => (
            <div
              key={item.ksiId}
              className="flex items-center gap-3 p-3 rounded-lg border hover:bg-accent/50 transition-colors cursor-pointer"
              onClick={() => setSelectedKsi(item.ksiId)}
            >
              {item.hasValidationTools ? (
                <Shield className="h-5 w-5 text-emerald-500 shrink-0" />
              ) : (
                <AlertTriangle className="h-5 w-5 text-amber-500 shrink-0" />
              )}
              <Badge variant="outline" className="font-mono text-xs shrink-0">{item.ksiId}</Badge>
              <span className="flex-1 text-sm">{item.techniqueCount} techniques</span>
              <div className="flex items-center gap-4 shrink-0">
                <div className="flex items-center gap-1">
                  <Crosshair className="h-3 w-3 text-red-500" />
                  <span className="text-sm font-mono">{item.exploitCount}</span>
                </div>
                <div className="flex items-center gap-1">
                  <Zap className="h-3 w-3 text-blue-500" />
                  <span className="text-sm font-mono">{item.atomicTestCount}</span>
                </div>
              </div>
            </div>
          ))}
        </TabsContent>

        {/* Tactic Distribution Tab */}
        <TabsContent value="tactics" className="space-y-3">
          <Card>
            <CardHeader>
              <CardTitle>MITRE ATT&CK Tactic Distribution</CardTitle>
              <CardDescription>How KSI defenses map across the ATT&CK kill chain</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {coverage?.summary.tacticDistribution.map((t) => (
                  <div key={t.tactic} className="flex items-center gap-3">
                    <span className="text-sm w-48 truncate">{t.tactic}</span>
                    <div className="flex-1 bg-muted rounded-full h-4 overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${TACTIC_COLORS[t.tactic] || "bg-gray-500"}`}
                        style={{ width: `${Math.min(100, (t.count / Math.max(...(coverage?.summary.tacticDistribution.map(x => x.count) || [1]))) * 100)}%` }}
                      />
                    </div>
                    <span className="text-sm font-mono w-8 text-right">{t.count}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* KSI Detail Dialog */}
      <Dialog open={!!selectedKsi} onOpenChange={(open) => !open && setSelectedKsi(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Target className="h-5 w-5" />
              {ksiReport?.ksiTitle || selectedKsi}
            </DialogTitle>
          </DialogHeader>
          {ksiReport && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 flex-wrap">
                <Badge variant="outline" className="font-mono">{ksiReport.ksiId}</Badge>
                <Badge>{ksiReport.themeCode}</Badge>
                <Badge variant={ksiReport.coverageStatus === "implemented" ? "default" : "secondary"}>
                  {ksiReport.coverageStatus}
                </Badge>
                {ksiReport.validationReady && (
                  <Badge className="bg-emerald-500 text-white">Validation Ready</Badge>
                )}
              </div>

              {ksiReport.description && (
                <p className="text-sm text-muted-foreground">{ksiReport.description}</p>
              )}

              <div className="grid grid-cols-3 gap-3">
                <Card>
                  <CardHeader className="p-3">
                    <CardDescription className="text-xs">Risk Score</CardDescription>
                    <CardTitle className={`text-2xl ${ksiReport.riskScore >= 70 ? "text-red-500" : ksiReport.riskScore >= 40 ? "text-amber-500" : "text-emerald-500"}`}>
                      {ksiReport.riskScore}/100
                    </CardTitle>
                  </CardHeader>
                </Card>
                <Card>
                  <CardHeader className="p-3">
                    <CardDescription className="text-xs">Exploits</CardDescription>
                    <CardTitle className="text-2xl">{ksiReport.exploitCount}</CardTitle>
                  </CardHeader>
                </Card>
                <Card>
                  <CardHeader className="p-3">
                    <CardDescription className="text-xs">Atomic Tests</CardDescription>
                    <CardTitle className="text-2xl">{ksiReport.atomicTestCount}</CardTitle>
                  </CardHeader>
                </Card>
              </div>

              {/* Techniques */}
              <div>
                <h4 className="font-medium mb-2 flex items-center gap-2">
                  <Crosshair className="h-4 w-4" /> ATT&CK Techniques
                </h4>
                <div className="space-y-1">
                  {ksiReport.techniques.map((t) => (
                    <div key={t.id} className="flex items-center gap-2 text-sm p-1.5 rounded bg-muted/50">
                      <Badge className={`text-[10px] text-white ${TACTIC_COLORS[t.tactic] || "bg-gray-500"}`}>{t.tactic}</Badge>
                      <span className="font-mono text-xs">{t.id}</span>
                      <span>{t.name}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Threat Groups */}
              {ksiReport.threatGroups.length > 0 && (
                <div>
                  <h4 className="font-medium mb-2 flex items-center gap-2">
                    <Users className="h-4 w-4" /> Threat Groups Defended Against
                  </h4>
                  <div className="space-y-1">
                    {ksiReport.threatGroups.map((g) => (
                      <div key={g.groupId} className="flex items-center gap-2 text-sm p-1.5 rounded bg-muted/50">
                        <span>{ORIGIN_FLAGS[g.origin] || "🌐"}</span>
                        <span className="font-medium">{g.groupName}</span>
                        <Badge variant={g.type === "apt" ? "destructive" : "secondary"} className="text-[10px]">{g.type}</Badge>
                        <span className="text-xs text-muted-foreground ml-auto">
                          {g.overlappingTechniques.length} overlapping TTPs
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Matching Exploits */}
              {ksiExploits && ksiExploits.exploits.length > 0 && (
                <div>
                  <h4 className="font-medium mb-2 flex items-center gap-2">
                    <Zap className="h-4 w-4" /> Available Exploits for Validation
                  </h4>
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {ksiExploits.exploits.slice(0, 15).map((e: any) => (
                      <div key={e.id} className="flex items-center gap-2 text-sm p-1.5 rounded bg-muted/50">
                        <Badge variant="destructive" className="text-[10px]">{e.severity || "N/A"}</Badge>
                        <span className="font-mono text-xs">{e.mitreId}</span>
                        <span className="truncate flex-1">{e.name}</span>
                        {e.cvssScore && <span className="text-xs font-mono">{e.cvssScore}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Matching Atomic Tests */}
              {ksiExploits && ksiExploits.atomicTests.length > 0 && (
                <div>
                  <h4 className="font-medium mb-2 flex items-center gap-2">
                    <Target className="h-4 w-4" /> Atomic Red Team Tests
                  </h4>
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {ksiExploits.atomicTests.slice(0, 15).map((t: any) => (
                      <div key={t.id} className="flex items-center gap-2 text-sm p-1.5 rounded bg-muted/50">
                        <span className="font-mono text-xs">{t.techniqueId}</span>
                        <span className="truncate flex-1">{t.testName}</span>
                        <Badge variant="outline" className="text-[10px]">{t.executorType}</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
