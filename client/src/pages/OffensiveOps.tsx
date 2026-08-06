import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";

// ─── Attack Chain Synthesis Tab ──────────────────────────────────────────────

function ChainSynthesisTab() {
  const { toast } = useToast();
  const [sectors, setSectors] = useState("");
  const [technologies, setTechnologies] = useState("");
  const [segments, setSegments] = useState<{ name: string; technologies: string; connectivity: string }[]>([
    { name: "DMZ", technologies: "nginx, apache", connectivity: "internet_facing" },
  ]);
  const [objective, setObjective] = useState("full_compromise");
  const [stealthRequired, setStealthRequired] = useState(false);
  const [actorEmulation, setActorEmulation] = useState("");
  const [result, setResult] = useState<any>(null);

  const synthesize = trpc.offensiveOps.synthesizeChain.useMutation({
    onSuccess: (data) => {
      setResult(data);
      toast({ title: "Chain Synthesized", description: `Generated ${data.steps?.length || 0}-step attack chain` });
    },
    onError: (err) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const addSegment = () => setSegments([...segments, { name: "", technologies: "", connectivity: "internal" }]);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Environment Profile</CardTitle>
          <CardDescription>Define the target environment for chain synthesis</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Target Sectors (comma-separated)</Label>
              <Input value={sectors} onChange={e => setSectors(e.target.value)} placeholder="water, energy, manufacturing" />
            </div>
            <div>
              <Label>Technologies (comma-separated)</Label>
              <Input value={technologies} onChange={e => setTechnologies(e.target.value)} placeholder="plc, scada, windows_ad, vpn" />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <Label>Network Segments</Label>
              <Button variant="outline" size="sm" onClick={addSegment}>+ Add Segment</Button>
            </div>
            {segments.map((seg, i) => (
              <div key={i} className="grid grid-cols-3 gap-2 mb-2">
                <Input value={seg.name} onChange={e => { const s = [...segments]; s[i].name = e.target.value; setSegments(s); }} placeholder="Segment name" />
                <Input value={seg.technologies} onChange={e => { const s = [...segments]; s[i].technologies = e.target.value; setSegments(s); }} placeholder="Technologies" />
                <Select value={seg.connectivity} onValueChange={v => { const s = [...segments]; s[i].connectivity = v; setSegments(s); }}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="internet_facing">Internet Facing</SelectItem>
                    <SelectItem value="dmz">DMZ</SelectItem>
                    <SelectItem value="internal">Internal</SelectItem>
                    <SelectItem value="air_gapped">Air Gapped</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            ))}
          </div>

          <Separator />

          <div className="grid grid-cols-3 gap-4">
            <div>
              <Label>Objective</Label>
              <Select value={objective} onValueChange={setObjective}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="full_compromise">Full Compromise</SelectItem>
                  <SelectItem value="data_exfil">Data Exfiltration</SelectItem>
                  <SelectItem value="disruption">Disruption</SelectItem>
                  <SelectItem value="persistence">Persistence</SelectItem>
                  <SelectItem value="lateral_movement">Lateral Movement</SelectItem>
                  <SelectItem value="privilege_escalation">Privilege Escalation</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Actor Emulation (optional)</Label>
              <Input value={actorEmulation} onChange={e => setActorEmulation(e.target.value)} placeholder="e.g., cyberav3ngers" />
            </div>
            <div className="flex items-center gap-2 pt-6">
              <Switch checked={stealthRequired} onCheckedChange={setStealthRequired} />
              <Label>Stealth Required</Label>
            </div>
          </div>

          <Button
            className="w-full"
            onClick={() => synthesize.mutate({
              environment: {
                targetSectors: sectors.split(",").map(s => s.trim()).filter(Boolean),
                technologies: technologies.split(",").map(t => t.trim()).filter(Boolean),
                networkSegments: segments.map(s => ({
                  name: s.name,
                  technologies: s.technologies.split(",").map(t => t.trim()).filter(Boolean),
                  connectivity: s.connectivity as any,
                })),
              },
              constraints: {
                maxSteps: 8,
                stealthRequired,
                targetObjective: objective as any,
                actorEmulation: actorEmulation || undefined,
              },
            })}
            disabled={synthesize.isPending}
          >
            {synthesize.isPending ? "Synthesizing..." : "Synthesize Attack Chain"}
          </Button>
        </CardContent>
      </Card>

      {result && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              Generated Chain
              <Badge variant={result.riskLevel === "critical" ? "destructive" : "secondary"}>
                {result.riskLevel || "high"}
              </Badge>
            </CardTitle>
            <CardDescription>
              {result.steps?.length || 0} steps | Confidence: {result.confidence || "N/A"}% | Estimated Duration: {result.estimatedDuration || "N/A"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {result.steps?.map((step: any, i: number) => (
                <div key={i} className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg">
                  <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary/10 text-primary flex items-center justify-center font-bold text-sm">
                    {i + 1}
                  </div>
                  <div className="flex-1">
                    <div className="font-medium">{step.technique || step.name}</div>
                    <div className="text-sm text-muted-foreground">{step.description}</div>
                    {step.mitreTechnique && (
                      <Badge variant="outline" className="mt-1 text-xs">{step.mitreTechnique}</Badge>
                    )}
                  </div>
                  <Badge variant={step.complexity === "low" ? "secondary" : step.complexity === "high" ? "destructive" : "default"}>
                    {step.complexity || "medium"}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Exploit Validation Tab ──────────────────────────────────────────────────

function ValidationTab() {
  const { toast } = useToast();
  const [exploitId, setExploitId] = useState("");
  const [targetHost, setTargetHost] = useState("");
  const [targetPort, setTargetPort] = useState("");
  const [techType, setTechType] = useState("web_application");
  const [validationMode, setValidationMode] = useState("active");
  const [captureEvidence, setCaptureEvidence] = useState(true);
  const [result, setResult] = useState<any>(null);

  const validate = trpc.offensiveOps.executeValidation.useMutation({
    onSuccess: (data) => {
      setResult(data);
      toast({ title: "Validation Complete", description: `Status: ${data.status}` });
    },
    onError: (err) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const { data: history } = trpc.offensiveOps.getValidationHistory.useQuery({ limit: 20 });
  const { data: adapters } = trpc.offensiveOps.getAdapters.useQuery();

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Execute Validation</CardTitle>
            <CardDescription>Run exploit validation with raw evidence capture</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label>Exploit ID</Label>
              <Input value={exploitId} onChange={e => setExploitId(e.target.value)} placeholder="exploit_cve_2024_..." />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <Label>Target Host</Label>
                <Input value={targetHost} onChange={e => setTargetHost(e.target.value)} placeholder="192.168.1.100" />
              </div>
              <div>
                <Label>Port</Label>
                <Input value={targetPort} onChange={e => setTargetPort(e.target.value)} placeholder="443" />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <Label>Tech Type</Label>
                <Select value={techType} onValueChange={setTechType}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="plc_ics">PLC/ICS</SelectItem>
                    <SelectItem value="web_application">Web Application</SelectItem>
                    <SelectItem value="network_infrastructure">Network Infrastructure</SelectItem>
                    <SelectItem value="cloud_saas">Cloud/SaaS</SelectItem>
                    <SelectItem value="active_directory">Active Directory</SelectItem>
                    <SelectItem value="endpoint">Endpoint</SelectItem>
                    <SelectItem value="iot_embedded">IoT/Embedded</SelectItem>
                    <SelectItem value="mobile">Mobile</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Mode</Label>
                <Select value={validationMode} onValueChange={setValidationMode}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="passive">Passive</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="destructive">Destructive</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={captureEvidence} onCheckedChange={setCaptureEvidence} />
              <Label>Capture Raw Evidence</Label>
            </div>
            <Button
              className="w-full"
              onClick={() => validate.mutate({
                exploitId,
                targetHost,
                targetPort: targetPort ? parseInt(targetPort) : undefined,
                techType: techType as any,
                validationMode: validationMode as any,
                captureEvidence,
              })}
              disabled={validate.isPending || !exploitId || !targetHost}
            >
              {validate.isPending ? "Validating..." : "Execute Validation"}
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Adapter Registry</CardTitle>
            <CardDescription>Pluggable validation adapters by tech type</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {adapters?.map((adapter: any) => (
                <div key={adapter.techType} className="flex items-center justify-between p-2 bg-muted/50 rounded">
                  <div>
                    <div className="font-medium text-sm">{adapter.name}</div>
                    <div className="text-xs text-muted-foreground">{adapter.techType}</div>
                  </div>
                  <Badge variant={adapter.status === "active" ? "default" : "secondary"}>
                    {adapter.status || "active"}
                  </Badge>
                </div>
              )) || <div className="text-sm text-muted-foreground">Loading adapters...</div>}
            </div>
          </CardContent>
        </Card>
      </div>

      {result && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              Validation Result
              <Badge variant={result.status === "confirmed" ? "default" : result.status === "failed" ? "destructive" : "secondary"}>
                {result.status}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div className="p-3 bg-muted/50 rounded">
                <div className="text-xs text-muted-foreground">Duration</div>
                <div className="font-bold">{result.duration || "N/A"}ms</div>
              </div>
              <div className="p-3 bg-muted/50 rounded">
                <div className="text-xs text-muted-foreground">Evidence Artifacts</div>
                <div className="font-bold">{result.evidence?.length || 0}</div>
              </div>
              <div className="p-3 bg-muted/50 rounded">
                <div className="text-xs text-muted-foreground">Confidence</div>
                <div className="font-bold">{result.confidence || "N/A"}%</div>
              </div>
            </div>
            {result.evidence && result.evidence.length > 0 && (
              <div>
                <h4 className="font-medium mb-2">Raw Evidence Captured</h4>
                <div className="space-y-2">
                  {result.evidence.map((ev: any, i: number) => (
                    <div key={i} className="p-2 bg-muted/30 rounded text-sm font-mono">
                      <Badge variant="outline" className="mr-2">{ev.type}</Badge>
                      {ev.summary || ev.description}
                      {ev.sizeBytes && <span className="text-muted-foreground ml-2">({(ev.sizeBytes / 1024).toFixed(1)} KB)</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {history && history.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Validation History</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {history.map((h: any, i: number) => (
                <div key={i} className="flex items-center justify-between p-2 border-b last:border-0">
                  <div>
                    <span className="font-mono text-sm">{h.exploitId}</span>
                    <span className="text-muted-foreground text-xs ml-2">→ {h.target}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={h.status === "confirmed" ? "default" : h.status === "failed" ? "destructive" : "secondary"}>
                      {h.status}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{h.evidence?.length || 0} artifacts</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Predictive Targeting Tab ────────────────────────────────────────────────

function PredictiveTargetingTab() {
  const { data: landscape } = trpc.offensiveOps.getPredictiveLandscape.useQuery();
  const { data: momentum } = trpc.offensiveOps.getCampaignMomentum.useQuery();

  return (
    <div className="space-y-6">
      {landscape && (
        <>
          <div className="grid grid-cols-3 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base">Highest Risk Actors</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {landscape.highestRiskActors?.map((actor: any, i: number) => (
                    <div key={i} className="flex items-center justify-between">
                      <div className="text-sm font-medium truncate max-w-[150px]">{actor.actorName}</div>
                      <Badge variant={actor.activeThreatLevel > 70 ? "destructive" : "secondary"}>
                        {actor.activeThreatLevel}%
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base">Emerging Targets</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {landscape.emergingTargets?.slice(0, 5).map((target: any, i: number) => (
                    <div key={i} className="flex items-center justify-between">
                      <div className="text-sm">{target.technology}</div>
                      <div className="flex items-center gap-1">
                        <span className="text-xs text-muted-foreground">{target.actorsInterested} actors</span>
                        <Badge variant="outline">{target.riskScore}</Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base">Time Horizon</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <div className="text-xs font-medium text-destructive mb-1">Next 7 Days</div>
                  {landscape.timeHorizon?.next7days?.map((item: string, i: number) => (
                    <div key={i} className="text-xs text-muted-foreground">{item}</div>
                  ))}
                </div>
                <div>
                  <div className="text-xs font-medium text-yellow-500 mb-1">Next 30 Days</div>
                  {landscape.timeHorizon?.next30days?.map((item: string, i: number) => (
                    <div key={i} className="text-xs text-muted-foreground">{item}</div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Sector Risk Matrix</CardTitle>
              <CardDescription>Sectors ranked by predicted targeting intensity</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3">
                {landscape.sectorRiskMatrix?.map((sector: any, i: number) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-muted/50 rounded">
                    <div>
                      <div className="font-medium text-sm capitalize">{sector.sector.replace(/_/g, " ")}</div>
                      <div className="text-xs text-muted-foreground">{sector.primaryThreats?.slice(0, 2).join(", ")}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${sector.overallRisk > 70 ? "bg-destructive" : sector.overallRisk > 40 ? "bg-yellow-500" : "bg-green-500"}`}
                          style={{ width: `${sector.overallRisk}%` }}
                        />
                      </div>
                      <span className="text-sm font-bold w-8">{sector.overallRisk}</span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {momentum && momentum.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Campaign Momentum</CardTitle>
            <CardDescription>Active threat actor campaign velocity and trajectory</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {momentum.map((m: any, i: number) => (
                <div key={i} className="p-4 border rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-medium">{m.actorName}</div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">{m.activeCampaigns} campaigns</Badge>
                      <Badge variant={m.momentumConfidence > 60 ? "destructive" : "secondary"}>
                        {m.momentumConfidence}% confidence
                      </Badge>
                    </div>
                  </div>
                  <div className="grid grid-cols-4 gap-3 text-sm">
                    <div>
                      <div className="text-xs text-muted-foreground">Vulns/Week</div>
                      <div className="font-bold">{m.newVulnsPerWeek}</div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">Dev Velocity</div>
                      <div className="font-bold">{m.exploitDevVelocity} days</div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">Expansion Rate</div>
                      <div className="font-bold">{m.campaignExpansionRate?.toFixed(1)}/week</div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">Data Freshness</div>
                      <div className="font-bold">{m.dataFreshness}h ago</div>
                    </div>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {m.targetingTechnologies?.map((tech: string, j: number) => (
                      <Badge key={j} variant="outline" className="text-xs">{tech}</Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function OffensiveOps() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Offensive Operations</h1>
        <p className="text-muted-foreground">
          Attack chain synthesis, exploit validation with evidence capture, and predictive vulnerability targeting
        </p>
      </div>

      <Tabs defaultValue="chain-synthesis">
        <TabsList>
          <TabsTrigger value="chain-synthesis">Chain Synthesis</TabsTrigger>
          <TabsTrigger value="validation">Exploit Validation</TabsTrigger>
          <TabsTrigger value="predictive">Predictive Targeting</TabsTrigger>
        </TabsList>

        <TabsContent value="chain-synthesis">
          <ChainSynthesisTab />
        </TabsContent>

        <TabsContent value="validation">
          <ValidationTab />
        </TabsContent>

        <TabsContent value="predictive">
          <PredictiveTargetingTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
