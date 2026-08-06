import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";

export default function ActorGenome() {
  const [activeTab, setActiveTab] = useState("profiles");
  const [selectedActor, setSelectedActor] = useState<string | null>(null);
  const [compareActor1, setCompareActor1] = useState<string>("");
  const [compareActor2, setCompareActor2] = useState<string>("");
  const [showScoreDialog, setShowScoreDialog] = useState(false);

  // Queries
  const profilesQuery = trpc.actorGenome.listProfiles.useQuery();
  const campaignsQuery = trpc.actorGenome.listCampaigns.useQuery();
  const presetsQuery = trpc.actorGenome.getWeightPresets.useQuery();
  const completenessQuery = trpc.actorGenome.profileCompleteness.useQuery();

  // Selected actor detail
  const actorDetailQuery = trpc.actorGenome.getProfile.useQuery(
    { actorId: selectedActor || "" },
    { enabled: !!selectedActor }
  );
  const tradecraftQuery = trpc.actorGenome.getTradecraft.useQuery(
    { actorId: selectedActor || "" },
    { enabled: !!selectedActor }
  );
  const temporalQuery = trpc.actorGenome.getTemporalAnalysis.useQuery(
    { actorId: selectedActor || "" },
    { enabled: !!selectedActor }
  );

  // Compare query
  const compareQuery = trpc.actorGenome.compareActors.useQuery(
    { actorId1: compareActor1, actorId2: compareActor2 },
    { enabled: !!compareActor1 && !!compareActor2 && compareActor1 !== compareActor2 }
  );

  // Score mutation
  const scoreMutation = trpc.actorGenome.scoreIncident.useMutation();

  const profiles = profilesQuery.data || [];
  const campaigns = campaignsQuery.data || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Actor Genome Engine</h1>
          <p className="text-muted-foreground mt-1">
            Behavioral attribution scoring with explainable evidence chains
          </p>
        </div>
        <div className="flex gap-2">
          <Dialog open={showScoreDialog} onOpenChange={setShowScoreDialog}>
            <DialogTrigger asChild>
              <Button variant="default" className="gap-2">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
                Score Incident
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Score Incident Against Actor Profiles</DialogTitle>
              </DialogHeader>
              <IncidentScoreForm onScore={(data) => {
                scoreMutation.mutate(data);
              }} isLoading={scoreMutation.isPending} result={scoreMutation.data} />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="profiles">Actor DNA</TabsTrigger>
          <TabsTrigger value="campaigns">Campaigns</TabsTrigger>
          <TabsTrigger value="compare">Compare</TabsTrigger>
          <TabsTrigger value="temporal">Temporal</TabsTrigger>
          <TabsTrigger value="completeness">Coverage</TabsTrigger>
          <TabsTrigger value="falseFlag">False Flag</TabsTrigger>
        </TabsList>

        {/* Actor DNA Profiles Tab */}
        <TabsContent value="profiles" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Profile List */}
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">Threat Actor Profiles</h3>
              <ScrollArea className="h-[600px]">
                <div className="space-y-2 pr-3">
                  {profiles.map((profile) => (
                    <Card
                      key={profile.actorId}
                      className={`cursor-pointer transition-colors hover:border-primary/50 ${selectedActor === profile.actorId ? "border-primary bg-primary/5" : ""}`}
                      onClick={() => setSelectedActor(profile.actorId)}
                    >
                      <CardContent className="p-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="font-medium text-sm">{profile.name}</p>
                            <p className="text-xs text-muted-foreground">{profile.origin}</p>
                          </div>
                          <div className="text-right">
                            <Badge variant={
                              profile.sophistication === "nation-state" ? "destructive" :
                              profile.sophistication === "advanced" ? "default" : "secondary"
                            } className="text-xs">
                              {profile.sophistication}
                            </Badge>
                            <p className="text-xs text-muted-foreground mt-1">
                              {Math.round(profile.profileCompleteness * 100)}% complete
                            </p>
                          </div>
                        </div>
                        <div className="mt-2">
                          <Progress value={profile.profileCompleteness * 100} className="h-1" />
                        </div>
                        <div className="mt-2 flex flex-wrap gap-1">
                          {profile.aliases.slice(0, 3).map((alias) => (
                            <Badge key={alias} variant="outline" className="text-xs py-0">
                              {alias}
                            </Badge>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </div>

            {/* Actor Detail */}
            <div className="lg:col-span-2">
              {selectedActor && actorDetailQuery.data ? (
                <ActorDetailView
                  actor={actorDetailQuery.data}
                  tradecraft={tradecraftQuery.data}
                  temporal={temporalQuery.data}
                />
              ) : (
                <Card className="h-[600px] flex items-center justify-center">
                  <CardContent className="text-center text-muted-foreground">
                    <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" className="mx-auto mb-4 opacity-50"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
                    <p className="text-lg font-medium">Select an actor profile</p>
                    <p className="text-sm mt-1">Click on a threat actor to view their behavioral DNA profile</p>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        </TabsContent>

        {/* Campaigns Tab */}
        <TabsContent value="campaigns" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {campaigns.map((campaign) => (
              <Card key={campaign.id}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">{campaign.name}</CardTitle>
                  <CardDescription className="text-xs">
                    {campaign.actorName} • {new Date(campaign.startDate).toLocaleDateString()} – {campaign.endDate ? new Date(campaign.endDate).toLocaleDateString() : "Ongoing"}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex flex-wrap gap-1">
                    {campaign.targetSectors.map((sector: string) => (
                      <Badge key={sector} variant="outline" className="text-xs">{sector}</Badge>
                    ))}
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {campaign.targetCountries.map((country: string) => (
                      <Badge key={country} variant="secondary" className="text-xs">{country}</Badge>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">{campaign.description}</p>
                  <div className="text-xs">
                    <span className="font-medium">Key techniques: </span>
                    {campaign.techniques.slice(0, 4).join(", ")}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Compare Tab */}
        <TabsContent value="compare" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Genome Comparison</CardTitle>
              <CardDescription>Compare behavioral DNA between two threat actors</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <Select value={compareActor1} onValueChange={setCompareActor1}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select first actor" />
                  </SelectTrigger>
                  <SelectContent>
                    {profiles.map((p) => (
                      <SelectItem key={p.actorId} value={p.actorId}>{p.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={compareActor2} onValueChange={setCompareActor2}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select second actor" />
                  </SelectTrigger>
                  <SelectContent>
                    {profiles.map((p) => (
                      <SelectItem key={p.actorId} value={p.actorId}>{p.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {compareQuery.data && (
                <div className="space-y-4 mt-6">
                  <div className="flex items-center justify-between p-4 bg-muted rounded-lg">
                    <div>
                      <p className="text-sm font-medium">Overall Similarity</p>
                      <p className="text-3xl font-bold">{Math.round(compareQuery.data.overallSimilarity * 100)}%</p>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-medium">Relationship</p>
                      <Badge variant={
                        compareQuery.data.overallSimilarity > 0.7 ? "destructive" :
                        compareQuery.data.overallSimilarity > 0.4 ? "default" : "secondary"
                      }>
                        {compareQuery.data.overallSimilarity > 0.7 ? "Highly Similar" :
                         compareQuery.data.overallSimilarity > 0.4 ? "Moderate Overlap" : "Distinct"}
                      </Badge>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    {compareQuery.data.dimensionScores.map((dim: any) => (
                      <div key={dim.dimension} className="flex items-center justify-between p-2 border rounded">
                        <span className="text-sm">{dim.dimension}</span>
                        <div className="flex items-center gap-2">
                          <Progress value={dim.similarity * 100} className="w-20 h-2" />
                          <span className="text-xs font-mono">{Math.round(dim.similarity * 100)}%</span>
                        </div>
                      </div>
                    ))}
                  </div>

                  {compareQuery.data.sharedElements.length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold mb-2">Shared Behavioral Elements</h4>
                      <div className="flex flex-wrap gap-1">
                        {compareQuery.data.sharedElements.map((elem: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs">{elem}</Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {compareQuery.data.distinctElements.length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold mb-2">Distinguishing Elements</h4>
                      <div className="flex flex-wrap gap-1">
                        {compareQuery.data.distinctElements.map((elem: string, i: number) => (
                          <Badge key={i} variant="secondary" className="text-xs">{elem}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Temporal Tab */}
        <TabsContent value="temporal" className="space-y-4">
          {selectedActor && temporalQuery.data ? (
            <TemporalAnalysisView data={temporalQuery.data} actorName={actorDetailQuery.data?.name || ""} />
          ) : (
            <Card className="p-8 text-center text-muted-foreground">
              <p>Select an actor from the DNA tab to view temporal analysis</p>
            </Card>
          )}
        </TabsContent>

        {/* Coverage Tab */}
        <TabsContent value="completeness" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {completenessQuery.data?.map((item: any) => (
              <Card key={item.actorId}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-2">
                    <p className="font-medium text-sm">{item.name}</p>
                    <span className="text-sm font-mono">{Math.round(item.completeness * 100)}%</span>
                  </div>
                  <Progress value={item.completeness * 100} className="h-2 mb-3" />
                  <div className="space-y-1">
                    {item.dimensions.map((dim: any) => (
                      <div key={dim.name} className="flex items-center justify-between text-xs">
                        <span className="text-muted-foreground">{dim.name}</span>
                        <div className="flex items-center gap-1">
                          <div className={`w-2 h-2 rounded-full ${dim.filled ? "bg-green-500" : "bg-red-400"}`} />
                          <span>{dim.filled ? "Populated" : "Gap"}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* False Flag Detection Tab */}
        <TabsContent value="falseFlag" className="space-y-4">
          <FalseFlagAnalysisPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─── False Flag Analysis Panel ───────────────────────────────────────────────────

function FalseFlagAnalysisPanel() {
  const [incidentTitle, setIncidentTitle] = useState("");
  const [claimedActor, setClaimedActor] = useState("");
  const [victimSector, setVictimSector] = useState("");
  const [victimCountry, setVictimCountry] = useState("");
  const [techniques, setTechniques] = useState("");
  const [malware, setMalware] = useState("");
  const [tools, setTools] = useState("");
  const [c2Methods, setC2Methods] = useState("");
  const [initialAccess, setInitialAccess] = useState("");
  const [dwellTime, setDwellTime] = useState("");
  const [propagandaText, setPropagandaText] = useState("");
  const [operatingHours, setOperatingHours] = useState("");
  const [compileTimestamps, setCompileTimestamps] = useState("");
  const [geopoliticalContext, setGeopoliticalContext] = useState("");

  const falseFlagMutation = trpc.actorGenome.analyzeFalseFlag.useMutation();
  const result = falseFlagMutation.data;

  const handleAnalyze = () => {
    falseFlagMutation.mutate({
      id: `ff-${Date.now()}`,
      title: incidentTitle,
      claimedActor: claimedActor || null,
      attributedActor: null,
      timestamp: Date.now(),
      victimSector,
      victimCountry,
      techniques: techniques.split(",").map(s => s.trim()).filter(Boolean),
      malwareObserved: malware.split(",").map(s => s.trim()).filter(Boolean),
      toolsUsed: tools.split(",").map(s => s.trim()).filter(Boolean),
      c2Methods: c2Methods.split(",").map(s => s.trim()).filter(Boolean),
      initialAccess: initialAccess.split(",").map(s => s.trim()).filter(Boolean),
      sourceIps: [],
      domains: [],
      jarmHashes: [],
      ja3Hashes: [],
      tlsCerts: [],
      asnNumbers: [],
      dwellTimeDays: dwellTime ? parseInt(dwellTime) : null,
      propagandaText: propagandaText || null,
      operatingHoursUtc: operatingHours ? operatingHours.split(",").map(s => parseInt(s.trim())).filter(n => !isNaN(n)) : undefined,
      compileTimestamps: compileTimestamps ? compileTimestamps.split(",").map(s => parseInt(s.trim())).filter(n => !isNaN(n)) : undefined,
      publicClaims: [],
      relatedAdvisories: [],
      geopoliticalContext: geopoliticalContext || undefined,
    });
  };

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case "likely_authentic": return "bg-green-500/10 text-green-500 border-green-500/30";
      case "suspicious": return "bg-yellow-500/10 text-yellow-500 border-yellow-500/30";
      case "probable_false_flag": return "bg-orange-500/10 text-orange-500 border-orange-500/30";
      case "confirmed_deception": return "bg-red-500/10 text-red-500 border-red-500/30";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getCategoryLabel = (cat: string) => {
    const labels: Record<string, string> = {
      planted_iocs: "Planted IOCs",
      borrowed_ttps: "Borrowed TTPs",
      timezone_spoofing: "Timezone Spoofing",
      linguistic_deception: "Linguistic Deception",
      infrastructure_age: "Infrastructure Age",
      tooling_inconsistency: "Tooling Inconsistency",
      geopolitical_mismatch: "Geopolitical Mismatch",
      operational_security_anomaly: "OpSec Anomaly",
      claim_behavior_divergence: "Claim Divergence",
    };
    return labels[cat] || cat;
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <span className="text-red-500">⚠</span> False Flag Detection Engine
          </CardTitle>
          <CardDescription>
            Analyze incidents for deliberate misdirection: planted IOCs, borrowed TTPs, timezone spoofing,
            linguistic deception, and geopolitical motivation mismatches.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Incident Title</label>
              <Input value={incidentTitle} onChange={e => setIncidentTitle(e.target.value)} placeholder="e.g., Minnesota Water Utility PLC Attack" />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Claimed/Attributed Actor</label>
              <Input value={claimedActor} onChange={e => setClaimedActor(e.target.value)} placeholder="e.g., CyberAv3ngers, Handala" />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Victim Sector</label>
              <Input value={victimSector} onChange={e => setVictimSector(e.target.value)} placeholder="e.g., water, energy, finance" />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Victim Country</label>
              <Input value={victimCountry} onChange={e => setVictimCountry(e.target.value)} placeholder="e.g., US, IL, UA" />
            </div>
          </div>

          <Separator />

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Techniques (comma-separated)</label>
              <Textarea value={techniques} onChange={e => setTechniques(e.target.value)} placeholder="T0883, T0855, T0821, T1059" rows={2} />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Malware Observed (comma-separated)</label>
              <Textarea value={malware} onChange={e => setMalware(e.target.value)} placeholder="IOCONTROL, Industroyer2" rows={2} />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Tools Used (comma-separated)</label>
              <Textarea value={tools} onChange={e => setTools(e.target.value)} placeholder="Mimikatz, Impacket, web_shells" rows={2} />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">C2 Methods (comma-separated)</label>
              <Textarea value={c2Methods} onChange={e => setC2Methods(e.target.value)} placeholder="direct_plc_access, tor_hidden_service" rows={2} />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Initial Access (comma-separated)</label>
              <Textarea value={initialAccess} onChange={e => setInitialAccess(e.target.value)} placeholder="default_credentials, spearphishing" rows={2} />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Dwell Time (days)</label>
              <Input value={dwellTime} onChange={e => setDwellTime(e.target.value)} placeholder="e.g., 45" type="number" />
            </div>
          </div>

          <Separator />

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Operating Hours UTC (comma-separated)</label>
              <Input value={operatingHours} onChange={e => setOperatingHours(e.target.value)} placeholder="4, 5, 6, 7, 8, 9, 10, 11, 12, 13" />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Compile Timestamps (epoch ms, comma-separated)</label>
              <Input value={compileTimestamps} onChange={e => setCompileTimestamps(e.target.value)} placeholder="1722345600000, 1722432000000" />
            </div>
            <div className="col-span-2 space-y-2">
              <label className="text-sm font-medium">Propaganda / Ransom Note Text</label>
              <Textarea value={propagandaText} onChange={e => setPropagandaText(e.target.value)} placeholder="Any text left by the attacker..." rows={2} />
            </div>
            <div className="col-span-2 space-y-2">
              <label className="text-sm font-medium">Geopolitical Context</label>
              <Textarea value={geopoliticalContext} onChange={e => setGeopoliticalContext(e.target.value)} placeholder="Describe the geopolitical situation at the time of the attack..." rows={2} />
            </div>
          </div>

          <Button onClick={handleAnalyze} disabled={!incidentTitle || !victimSector || !victimCountry || falseFlagMutation.isPending} className="w-full">
            {falseFlagMutation.isPending ? "Analyzing for Deception..." : "Run False Flag Analysis"}
          </Button>
        </CardContent>
      </Card>

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Verdict Card */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Analysis Result</CardTitle>
                <Badge className={getVerdictColor(result.verdict)}>
                  {result.verdict.replace(/_/g, " ").toUpperCase()}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <div className="text-4xl font-bold">{result.overallProbability}%</div>
                <div className="flex-1">
                  <p className="text-sm text-muted-foreground">False Flag Probability</p>
                  <Progress value={result.overallProbability} className="h-3 mt-1" />
                </div>
              </div>

              {result.likelyTrueActor && (
                <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/30">
                  <p className="text-sm font-semibold text-orange-500">Likely True Actor: {result.likelyTrueActor}</p>
                  <p className="text-xs text-muted-foreground">Confidence: {result.likelyTrueActorConfidence}%</p>
                </div>
              )}

              {result.intendedScapegoat && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30">
                  <p className="text-sm font-semibold text-red-500">Intended Scapegoat: {result.intendedScapegoat}</p>
                </div>
              )}

              <div className="p-3 rounded-lg bg-muted">
                <p className="text-sm">{result.deceptionNarrative}</p>
              </div>
            </CardContent>
          </Card>

          {/* Category Scores */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Detection Category Scores</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-3">
                {Object.entries(result.categoryScores).map(([cat, score]) => (
                  <div key={cat} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span>{getCategoryLabel(cat)}</span>
                      <span className="font-mono">{score as number}%</span>
                    </div>
                    <Progress value={score as number} className="h-2" />
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Indicators */}
          {result.indicators.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Deception Indicators ({result.indicators.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px]">
                  <div className="space-y-3">
                    {result.indicators.map((ind: any, i: number) => (
                      <div key={i} className="p-3 rounded-lg border">
                        <div className="flex items-center justify-between mb-1">
                          <Badge variant="outline" className="text-xs">{getCategoryLabel(ind.category)}</Badge>
                          <Badge className={ind.confidence === "high" ? "bg-red-500/10 text-red-500" : ind.confidence === "medium" ? "bg-yellow-500/10 text-yellow-500" : "bg-blue-500/10 text-blue-500"}>
                            {ind.confidence}
                          </Badge>
                        </div>
                        <p className="text-sm font-medium mt-1">{ind.signal}</p>
                        <p className="text-xs text-muted-foreground mt-1">{ind.description}</p>
                        <div className="mt-2">
                          <p className="text-xs font-semibold">Evidence:</p>
                          {ind.evidence.map((e: string, j: number) => (
                            <p key={j} className="text-xs text-muted-foreground">• {e}</p>
                          ))}
                        </div>
                        {ind.mitigatingFactors && ind.mitigatingFactors.length > 0 && (
                          <div className="mt-2">
                            <p className="text-xs font-semibold text-green-600">Mitigating Factors:</p>
                            {ind.mitigatingFactors.map((m: string, j: number) => (
                              <p key={j} className="text-xs text-green-600/70">• {m}</p>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          )}

          {/* Recommendations */}
          {result.recommendations.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Analyst Recommendations</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {result.recommendations.map((rec: string, i: number) => (
                    <div key={i} className="flex items-start gap-2">
                      <span className="text-sm font-mono text-muted-foreground">{i + 1}.</span>
                      <p className="text-sm">{rec}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Actor Detail View ────────────────────────────────────────────────────────

function ActorDetailView({ actor, tradecraft, temporal }: { actor: any; tradecraft: any; temporal: any }) {
  return (
    <ScrollArea className="h-[600px]">
      <div className="space-y-4 pr-3">
        {/* Header */}
        <Card>
          <CardContent className="p-4">
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-xl font-bold">{actor.name}</h2>
                <p className="text-sm text-muted-foreground">{actor.aliases.join(" / ")}</p>
              </div>
              <Badge variant="destructive">{actor.sophistication}</Badge>
            </div>
            <Separator className="my-3" />
            <div className="grid grid-cols-3 gap-4 text-sm">
              <div>
                <p className="text-muted-foreground">Origin</p>
                <p className="font-medium">{actor.origin}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Motivation</p>
                <p className="font-medium">{actor.motivation}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Active Since</p>
                <p className="font-medium">{new Date(actor.firstSeen).toLocaleDateString()}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Three-Layer Attribution */}
        {actor.attribution && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Three-Layer Attribution</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-3 p-2 bg-red-500/10 rounded">
                <Badge variant="destructive" className="text-xs">Sponsor</Badge>
                <div>
                  <p className="text-sm font-medium">{actor.attribution.sponsor.entity}</p>
                  <p className="text-xs text-muted-foreground">Confidence: {Math.round(actor.attribution.sponsor.confidence * 100)}%</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-2 bg-orange-500/10 rounded">
                <Badge className="text-xs bg-orange-600">Operator</Badge>
                <div>
                  <p className="text-sm font-medium">{actor.attribution.operator.entity}</p>
                  <p className="text-xs text-muted-foreground">Confidence: {Math.round(actor.attribution.operator.confidence * 100)}%</p>
                </div>
              </div>
              {actor.attribution.personas.map((p: any, i: number) => (
                <div key={i} className="flex items-center gap-3 p-2 bg-blue-500/10 rounded">
                  <Badge variant="secondary" className="text-xs">Persona</Badge>
                  <div>
                    <p className="text-sm font-medium">{p.entity}</p>
                    <p className="text-xs text-muted-foreground">Confidence: {Math.round(p.confidence * 100)}%</p>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        )}

        {/* Genome Features */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Behavioral DNA ({actor.genome?.length || 0} features)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {actor.genome?.slice(0, 15).map((feature: any, i: number) => (
                <div key={i} className="flex items-center justify-between text-xs border-b pb-1">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs py-0">{feature.category}</Badge>
                    <span>{feature.value}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Progress value={feature.weight * 100} className="w-16 h-1.5" />
                    <span className="font-mono w-8 text-right">{Math.round(feature.weight * 100)}%</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Tradecraft Fingerprints */}
        {tradecraft && tradecraft.length > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Tradecraft Fingerprints</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {tradecraft.map((fp: any, i: number) => (
                  <div key={i} className="p-2 border rounded">
                    <div className="flex items-center justify-between mb-1">
                      <p className="text-sm font-medium">{fp.name}</p>
                      <Badge variant={fp.confidence > 0.8 ? "destructive" : "default"} className="text-xs">
                        {Math.round(fp.confidence * 100)}% confidence
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mb-2">{fp.description}</p>
                    <div className="flex flex-wrap gap-1">
                      {fp.sequence.map((step: string, j: number) => (
                        <span key={j} className="text-xs bg-muted px-1.5 py-0.5 rounded">
                          {j + 1}. {step}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Campaigns */}
        {actor.campaigns && actor.campaigns.length > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Known Campaigns ({actor.campaigns.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {actor.campaigns.map((c: any, i: number) => (
                  <div key={i} className="flex items-center justify-between p-2 border rounded text-xs">
                    <div>
                      <p className="font-medium">{c.name}</p>
                      <p className="text-muted-foreground">{c.targetSectors.join(", ")}</p>
                    </div>
                    <div className="text-right">
                      <p>{new Date(c.startDate).getFullYear()}</p>
                      <p className="text-muted-foreground">{c.targetCountries.join(", ")}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </ScrollArea>
  );
}

// ─── Temporal Analysis View ───────────────────────────────────────────────────

function TemporalAnalysisView({ data, actorName }: { data: any; actorName: string }) {
  if (!data) return null;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* UTC Offset */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Estimated Operating Timezone</CardTitle>
          <CardDescription>{actorName}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-4">
            <p className="text-4xl font-bold">UTC{data.primaryUtcOffset >= 0 ? "+" : ""}{data.primaryUtcOffset}</p>
            {data.secondaryUtcOffset && (
              <p className="text-sm text-muted-foreground mt-1">Secondary: UTC{data.secondaryUtcOffset >= 0 ? "+" : ""}{data.secondaryUtcOffset}</p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Hourly Distribution */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Activity Distribution (Local Time)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-end gap-0.5 h-24">
            {data.hourlyDistribution.map((val: number, hour: number) => (
              <div
                key={hour}
                className="flex-1 bg-primary/70 rounded-t transition-all"
                style={{ height: `${val * 100}%`, minHeight: val > 0 ? "2px" : "0" }}
                title={`${hour}:00 — ${Math.round(val * 100)}%`}
              />
            ))}
          </div>
          <div className="flex justify-between text-xs text-muted-foreground mt-1">
            <span>00:00</span>
            <span>06:00</span>
            <span>12:00</span>
            <span>18:00</span>
            <span>23:00</span>
          </div>
        </CardContent>
      </Card>

      {/* Campaign Cadence */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Campaign Cadence</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Avg Interval</span>
              <span className="font-medium">{data.avgCampaignIntervalDays} days</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Avg Duration</span>
              <span className="font-medium">{data.avgCampaignDurationDays} days</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Holiday Correlation */}
      {data.holidayCorrelation && data.holidayCorrelation.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Holiday Correlation</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {data.holidayCorrelation.map((h: any, i: number) => (
                <div key={i} className="flex items-center justify-between text-xs p-2 border rounded">
                  <div>
                    <p className="font-medium">{h.holiday}</p>
                    <p className="text-muted-foreground">{h.country}</p>
                  </div>
                  <Badge variant={h.activityDuringHoliday < 0.3 ? "secondary" : "default"}>
                    {h.activityDuringHoliday < 0.3 ? "Avoids" : h.activityDuringHoliday > 1.5 ? "Spikes" : "Normal"}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Geopolitical Triggers */}
      {data.geopoliticalTriggers && data.geopoliticalTriggers.length > 0 && (
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Geopolitical Triggers</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {data.geopoliticalTriggers.map((g: any, i: number) => (
                <div key={i} className="flex items-center justify-between text-xs p-2 border rounded">
                  <div>
                    <p className="font-medium">{g.event}</p>
                    <p className="text-muted-foreground">Response delay: {g.responseDelayHours}h</p>
                  </div>
                  <Badge variant={g.activitySpike ? "destructive" : "secondary"}>
                    {g.activitySpike ? "Activity Spike" : "No Spike"}
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

// ─── Incident Score Form ──────────────────────────────────────────────────────

function IncidentScoreForm({ onScore, isLoading, result }: { onScore: (data: any) => void; isLoading: boolean; result: any }) {
  const [formData, setFormData] = useState({
    id: `incident-${Date.now()}`,
    title: "",
    timestamp: Date.now(),
    victimSector: "",
    victimCountry: "",
    techniques: "",
    malwareObserved: "",
    toolsUsed: "",
    initialAccess: "",
    impactType: "disruption",
    sourceIps: "",
    domains: "",
    plcVendors: "",
    icsProtocols: "",
    safetySystemTargeted: false,
    plcLogicChanged: false,
    credentialReuse: false,
    propagandaLeft: false,
    dwellTimeDays: "",
  });

  const handleSubmit = () => {
    onScore({
      ...formData,
      timestamp: Date.now(),
      techniques: formData.techniques.split(",").map(s => s.trim()).filter(Boolean),
      malwareObserved: formData.malwareObserved.split(",").map(s => s.trim()).filter(Boolean),
      toolsUsed: formData.toolsUsed.split(",").map(s => s.trim()).filter(Boolean),
      initialAccess: formData.initialAccess.split(",").map(s => s.trim()).filter(Boolean),
      sourceIps: formData.sourceIps.split(",").map(s => s.trim()).filter(Boolean),
      domains: formData.domains.split(",").map(s => s.trim()).filter(Boolean),
      plcVendors: formData.plcVendors.split(",").map(s => s.trim()).filter(Boolean),
      icsProtocols: formData.icsProtocols.split(",").map(s => s.trim()).filter(Boolean),
      dwellTimeDays: formData.dwellTimeDays ? parseInt(formData.dwellTimeDays) : null,
      victimTechnology: [],
      persistenceMethods: [],
      c2Methods: [],
      lateralMovement: [],
      exfiltrationMethods: [],
      jarmHashes: [],
      ja3Hashes: [],
      tlsCerts: [],
      asnNumbers: [],
      hmiModified: false,
      propagandaText: null,
      operatingHoursUtc: null,
      publicClaims: [],
      relatedAdvisories: [],
    });
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs font-medium">Incident Title</label>
          <Input value={formData.title} onChange={(e) => setFormData({ ...formData, title: e.target.value })} placeholder="e.g., Water Plant PLC Compromise" />
        </div>
        <div>
          <label className="text-xs font-medium">Impact Type</label>
          <Select value={formData.impactType} onValueChange={(v) => setFormData({ ...formData, impactType: v })}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="disruption">Disruption</SelectItem>
              <SelectItem value="destruction">Destruction</SelectItem>
              <SelectItem value="espionage">Espionage</SelectItem>
              <SelectItem value="ransomware">Ransomware</SelectItem>
              <SelectItem value="sabotage">Sabotage</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-xs font-medium">Victim Sector</label>
          <Input value={formData.victimSector} onChange={(e) => setFormData({ ...formData, victimSector: e.target.value })} placeholder="e.g., water, energy" />
        </div>
        <div>
          <label className="text-xs font-medium">Victim Country</label>
          <Input value={formData.victimCountry} onChange={(e) => setFormData({ ...formData, victimCountry: e.target.value })} placeholder="e.g., US, IL" />
        </div>
      </div>

      <div>
        <label className="text-xs font-medium">MITRE Techniques (comma-separated)</label>
        <Textarea value={formData.techniques} onChange={(e) => setFormData({ ...formData, techniques: e.target.value })} placeholder="T1190, T1078, T0855" rows={2} />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs font-medium">Malware Observed</label>
          <Input value={formData.malwareObserved} onChange={(e) => setFormData({ ...formData, malwareObserved: e.target.value })} placeholder="IOCONTROL, FrostyGoop" />
        </div>
        <div>
          <label className="text-xs font-medium">Initial Access Methods</label>
          <Input value={formData.initialAccess} onChange={(e) => setFormData({ ...formData, initialAccess: e.target.value })} placeholder="default-credentials, exposed-hmi" />
        </div>
        <div>
          <label className="text-xs font-medium">PLC Vendors</label>
          <Input value={formData.plcVendors} onChange={(e) => setFormData({ ...formData, plcVendors: e.target.value })} placeholder="Unitronics, Rockwell" />
        </div>
        <div>
          <label className="text-xs font-medium">ICS Protocols</label>
          <Input value={formData.icsProtocols} onChange={(e) => setFormData({ ...formData, icsProtocols: e.target.value })} placeholder="Modbus, PCOM, EtherNet/IP" />
        </div>
      </div>

      <div className="grid grid-cols-4 gap-3">
        <label className="flex items-center gap-2 text-xs">
          <input type="checkbox" checked={formData.safetySystemTargeted} onChange={(e) => setFormData({ ...formData, safetySystemTargeted: e.target.checked })} />
          Safety System Targeted
        </label>
        <label className="flex items-center gap-2 text-xs">
          <input type="checkbox" checked={formData.plcLogicChanged} onChange={(e) => setFormData({ ...formData, plcLogicChanged: e.target.checked })} />
          PLC Logic Changed
        </label>
        <label className="flex items-center gap-2 text-xs">
          <input type="checkbox" checked={formData.credentialReuse} onChange={(e) => setFormData({ ...formData, credentialReuse: e.target.checked })} />
          Credential Reuse
        </label>
        <label className="flex items-center gap-2 text-xs">
          <input type="checkbox" checked={formData.propagandaLeft} onChange={(e) => setFormData({ ...formData, propagandaLeft: e.target.checked })} />
          Propaganda Left
        </label>
      </div>

      <Button onClick={handleSubmit} disabled={isLoading || !formData.title} className="w-full">
        {isLoading ? "Scoring..." : "Score Against All Actors"}
      </Button>

      {/* Results */}
      {result && (
        <div className="space-y-3 mt-4 p-4 bg-muted rounded-lg">
          <h4 className="font-semibold text-sm">Attribution Results</h4>

          {/* Top Candidate */}
          <div className="p-3 border rounded bg-background">
            <div className="flex items-center justify-between mb-2">
              <div>
                <p className="font-bold">{result.topCandidate.actorName}</p>
                <p className="text-xs text-muted-foreground">Top Match</p>
              </div>
              <div className="text-right">
                <p className="text-2xl font-bold text-primary">{Math.round(result.topCandidate.overallScore)}%</p>
                <Badge variant={
                  result.topCandidate.overallScore >= 70 ? "destructive" :
                  result.topCandidate.overallScore >= 50 ? "default" : "secondary"
                }>
                  {result.topCandidate.overallScore >= 70 ? "High Confidence" :
                   result.topCandidate.overallScore >= 50 ? "Moderate" : "Low Confidence"}
                </Badge>
              </div>
            </div>

            {/* Evidence Chain */}
            {result.topCandidate.evidenceChain && (
              <div className="mt-3 space-y-1">
                <p className="text-xs font-semibold">Evidence Chain:</p>
                {result.topCandidate.evidenceChain.slice(0, 8).map((ev: any, i: number) => (
                  <div key={i} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1">
                      <span className={ev.points > 0 ? "text-green-600" : "text-red-500"}>
                        {ev.points > 0 ? "+" : ""}{ev.points.toFixed(1)}
                      </span>
                      <span className="text-muted-foreground">{ev.category}:</span>
                      <span>{ev.evidence}</span>
                    </div>
                    <Badge variant="outline" className="text-xs py-0">{ev.explanation}</Badge>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Other Candidates */}
          {result.allScores && result.allScores.slice(1).map((score: any, i: number) => (
            <div key={i} className="flex items-center justify-between p-2 border rounded text-sm">
              <span>{score.actorName}</span>
              <div className="flex items-center gap-2">
                <Progress value={score.overallScore} className="w-20 h-2" />
                <span className="font-mono text-xs">{Math.round(score.overallScore)}%</span>
              </div>
            </div>
          ))}

          {/* Conflicting Indicators */}
          {result.conflictingIndicators && result.conflictingIndicators.length > 0 && (
            <div className="mt-3">
              <p className="text-xs font-semibold text-orange-600">Conflicting Indicators:</p>
              {result.conflictingIndicators.map((ci: any, i: number) => (
                <p key={i} className="text-xs text-muted-foreground">• {ci}</p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
