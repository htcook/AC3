import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { toast } from "sonner";
import { useLocation } from "wouter";
import {
  Shield, AlertTriangle, Activity, Cpu, Eye, RefreshCw, Zap, Target,
  Globe, ChevronRight, Bug, Skull, Factory, Database, ExternalLink,
  Biohazard, Wrench, GitBranch, Radio, Search, Filter, BookOpen,
  Rocket, Play, ArrowRight,
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── Protocol & Vendor Constants ────────────────────────────────────────────
const ICS_PROTOCOLS = [
  "modbus", "dnp3", "s7comm", "bacnet", "ethernet/ip", "opc ua", "opc da",
  "iec104", "iec61850", "profinet", "codesys", "tristation", "mqtt", "m-bus",
];

const ICS_VENDORS = [
  "Siemens", "Schneider Electric", "Rockwell", "ABB", "Honeywell",
  "OMRON", "Emerson", "GE", "Yokogawa", "Mitsubishi",
];

// ─── Main Component ─────────────────────────────────────────────────────────
export default function IcsIntelligence() {
  const [activeTab, setActiveTab] = useState("malware");
  const [showEngagementDialog, setShowEngagementDialog] = useState(false);
  const [selectedActorForEngagement, setSelectedActorForEngagement] = useState<any>(null);

  const handleStartEngagement = (actor?: any) => {
    setSelectedActorForEngagement(actor || null);
    setShowEngagementDialog(true);
  };

  return (
    <AppShell>
    <div className="space-y-6 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Biohazard className="w-6 h-6 text-red-400" />
            ICS/SCADA Threat Intelligence
          </h1>
          <p className="text-muted-foreground mt-1">
            Curated intelligence on ICS-targeting malware families, capable threat actors, open-source assessment tools, and live CISA advisories. Auto-enriched daily from government and vendor feeds.
          </p>
        </div>
        <Button
          onClick={() => handleStartEngagement()}
          className="gap-2 bg-green-600 hover:bg-green-700 text-white shrink-0"
        >
          <Rocket className="w-4 h-4" />
          Start ICS Engagement
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-4 w-full max-w-3xl">
          <TabsTrigger value="malware" className="flex items-center gap-1">
            <Skull className="w-3.5 h-3.5" /> Malware Families
          </TabsTrigger>
          <TabsTrigger value="actors" className="flex items-center gap-1">
            <Target className="w-3.5 h-3.5" /> ICS Actors
          </TabsTrigger>
          <TabsTrigger value="tools" className="flex items-center gap-1">
            <Wrench className="w-3.5 h-3.5" /> Open-Source Tools
          </TabsTrigger>
          <TabsTrigger value="advisories" className="flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5" /> Live Advisories
          </TabsTrigger>
        </TabsList>

        <TabsContent value="malware" className="space-y-6">
          <MalwareFamiliesTab onStartEngagement={handleStartEngagement} />
        </TabsContent>
        <TabsContent value="actors" className="space-y-6">
          <IcsActorsTab onStartEngagement={handleStartEngagement} />
        </TabsContent>
        <TabsContent value="tools" className="space-y-6">
          <OpenSourceToolsTab />
        </TabsContent>
        <TabsContent value="advisories" className="space-y-6">
          <LiveAdvisoriesTab />
        </TabsContent>
      </Tabs>

      {/* Start ICS Engagement Dialog */}
      <StartIcsEngagementDialog
        open={showEngagementDialog}
        onClose={() => setShowEngagementDialog(false)}
        selectedActor={selectedActorForEngagement}
      />
    </div>
    </AppShell>
  );
}

// ─── Malware Families Tab ───────────────────────────────────────────────────
function MalwareFamiliesTab({ onStartEngagement }: { onStartEngagement: (actor?: any) => void }) {
  const { data: malware, isLoading } = trpc.icsOtSecurity.getIcsMalwareFamilies.useQuery();
  const [search, setSearch] = useState("");
  const [selectedSector, setSelectedSector] = useState("all");
  const [selectedProtocol, setSelectedProtocol] = useState("all");
  const [selectedVendor, setSelectedVendor] = useState("all");

  const filtered = useMemo(() => {
    if (!malware) return [];
    return malware.filter(m => {
      const matchesSearch = !search ||
        m.name.toLowerCase().includes(search.toLowerCase()) ||
        m.aliases.some(a => a.toLowerCase().includes(search.toLowerCase())) ||
        m.attribution.toLowerCase().includes(search.toLowerCase());
      const matchesSector = selectedSector === "all" ||
        m.targetedSectors.some(s => s.toLowerCase().includes(selectedSector.toLowerCase()));
      const matchesProtocol = selectedProtocol === "all" ||
        m.targetedProtocols.some(p => p.toLowerCase().includes(selectedProtocol.toLowerCase()));
      const matchesVendor = selectedVendor === "all" ||
        m.targetedVendors.some(v => v.toLowerCase().includes(selectedVendor.toLowerCase()));
      return matchesSearch && matchesSector && matchesProtocol && matchesVendor;
    });
  }, [malware, search, selectedSector, selectedProtocol, selectedVendor]);

  const sectors = useMemo(() => {
    if (!malware) return [];
    const all = malware.flatMap(m => m.targetedSectors);
    return [...new Set(all)].sort();
  }, [malware]);

  const activeProtocols = useMemo(() => {
    if (!malware) return [];
    const all = malware.flatMap(m => m.targetedProtocols);
    return [...new Set(all)].sort();
  }, [malware]);

  const activeVendors = useMemo(() => {
    if (!malware) return [];
    const all = malware.flatMap(m => m.targetedVendors);
    return [...new Set(all)].sort();
  }, [malware]);

  if (isLoading) {
    return <div className="text-center py-12 text-muted-foreground">Loading ICS malware knowledge base...</div>;
  }

  return (
    <>
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Skull className="w-5 h-5 text-red-400" />
            ICS Malware Knowledge Base
          </h2>
          <p className="text-sm text-muted-foreground">
            {malware?.length || 0} documented ICS-specific malware families with attribution, targeted protocols, and MITRE ATT&CK for ICS mapping
          </p>
        </div>
      </div>

      <div className="flex gap-3 flex-wrap">
        <Input
          placeholder="Search by name, alias, or attribution..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-sm"
        />
        <Select value={selectedProtocol} onValueChange={setSelectedProtocol}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Protocol" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Protocols</SelectItem>
            {activeProtocols.map(p => (
              <SelectItem key={p} value={p}>{p.toUpperCase()}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={selectedVendor} onValueChange={setSelectedVendor}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Vendor" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Vendors</SelectItem>
            {activeVendors.map(v => (
              <SelectItem key={v} value={v}>{v}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={selectedSector} onValueChange={setSelectedSector}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Sector" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Sectors</SelectItem>
            {sectors.map(s => (
              <SelectItem key={s} value={s}>{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        {(selectedProtocol !== "all" || selectedVendor !== "all" || selectedSector !== "all") && (
          <Button variant="ghost" size="sm" onClick={() => { setSelectedProtocol("all"); setSelectedVendor("all"); setSelectedSector("all"); }}>
            Clear Filters
          </Button>
        )}
      </div>

      {/* Active filter badges */}
      {(selectedProtocol !== "all" || selectedVendor !== "all" || selectedSector !== "all") && (
        <div className="flex gap-2 flex-wrap">
          {selectedProtocol !== "all" && (
            <Badge variant="outline" className="bg-purple-500/10 text-purple-400 border-purple-500/20">
              <Radio className="w-3 h-3 mr-1" /> Protocol: {selectedProtocol.toUpperCase()}
            </Badge>
          )}
          {selectedVendor !== "all" && (
            <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/20">
              <Factory className="w-3 h-3 mr-1" /> Vendor: {selectedVendor}
            </Badge>
          )}
          {selectedSector !== "all" && (
            <Badge variant="outline" className="bg-orange-500/10 text-orange-400 border-orange-500/20">
              <Globe className="w-3 h-3 mr-1" /> Sector: {selectedSector}
            </Badge>
          )}
          <Badge variant="outline" className="bg-zinc-800 text-zinc-300 border-zinc-700">
            {filtered.length} results
          </Badge>
        </div>
      )}

      <div className="space-y-4">
        {filtered.map((m) => (
          <Card key={m.name} className="bg-card/50 border-border/50 hover:border-red-500/20 transition-colors">
            <CardContent className="p-5">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-base font-semibold text-red-400">{m.name}</h3>
                    <Badge variant="outline" className="text-xs bg-zinc-800/50 border-zinc-700">
                      {m.year}
                    </Badge>
                    {m.aliases.length > 0 && (
                      <span className="text-xs text-muted-foreground">
                        aka {m.aliases.slice(0, 3).join(", ")}
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground mb-3">{m.description}</p>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                    <div>
                      <span className="text-muted-foreground font-medium block mb-1">Attribution</span>
                      <span className="text-amber-400">{m.attribution}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground font-medium block mb-1">Targeted Vendors</span>
                      <div className="flex flex-wrap gap-1">
                        {m.targetedVendors.map(v => (
                          <Badge key={v} variant="outline" className="text-[10px] bg-blue-500/10 text-blue-400 border-blue-500/20">
                            {v}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <div>
                      <span className="text-muted-foreground font-medium block mb-1">Targeted Protocols</span>
                      <div className="flex flex-wrap gap-1">
                        {m.targetedProtocols.map(p => (
                          <Badge key={p} variant="outline" className="text-[10px] bg-purple-500/10 text-purple-400 border-purple-500/20">
                            {p}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="mt-3 flex items-center gap-2 flex-wrap">
                    {m.targetedSectors.map(s => (
                      <Badge key={s} variant="outline" className="text-[10px] bg-orange-500/10 text-orange-400 border-orange-500/20">
                        <Factory className="w-3 h-3 mr-1" />{s}
                      </Badge>
                    ))}
                    {m.mitreIcsTechniques.slice(0, 4).map(t => (
                      <Badge key={t} variant="outline" className="text-[10px] font-mono bg-zinc-800 text-zinc-300 border-zinc-700">
                        {t}
                      </Badge>
                    ))}
                    {m.mitreIcsTechniques.length > 4 && (
                      <span className="text-[10px] text-muted-foreground">+{m.mitreIcsTechniques.length - 4} more</span>
                    )}
                  </div>
                </div>
                <Button
                  size="sm"
                  variant="ghost"
                  className="text-green-400 hover:text-green-300 hover:bg-green-500/10 shrink-0 ml-3"
                  onClick={() => onStartEngagement({ name: m.attribution, techniques: m.mitreIcsTechniques, protocols: m.targetedProtocols, vendors: m.targetedVendors })}
                  title="Start ICS engagement emulating this malware"
                >
                  <Rocket className="w-4 h-4" />
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </>
  );
}

// ─── ICS-Capable Actors Tab ─────────────────────────────────────────────────
function IcsActorsTab({ onStartEngagement }: { onStartEngagement: (actor?: any) => void }) {
  const { data: actors, isLoading, refetch } = trpc.icsOtSecurity.getIcsCapableActors.useQuery();
  const [search, setSearch] = useState("");
  const [selectedOrigin, setSelectedOrigin] = useState("all");

  const origins = useMemo(() => {
    if (!actors) return [];
    const all = actors.map((a: any) => a.origin).filter(Boolean);
    return [...new Set(all)].sort();
  }, [actors]);

  const filtered = useMemo(() => {
    if (!actors) return [];
    return actors.filter((a: any) => {
      const q = search.toLowerCase();
      const matchesSearch = !search ||
        a.name.toLowerCase().includes(q) ||
        a.origin?.toLowerCase().includes(q) ||
        (a.aliases as string[] || []).some((al: string) => al.toLowerCase().includes(q));
      const matchesOrigin = selectedOrigin === "all" || a.origin === selectedOrigin;
      return matchesSearch && matchesOrigin;
    });
  }, [actors, search, selectedOrigin]);

  if (isLoading) {
    return <div className="text-center py-12 text-muted-foreground">Loading ICS-capable threat actors...</div>;
  }

  return (
    <>
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Target className="w-5 h-5 text-amber-400" />
            ICS/SCADA-Capable Threat Actors
          </h2>
          <p className="text-sm text-muted-foreground">
            {actors?.length || 0} threat actors auto-tagged with ICS/SCADA capability based on TTPs, malware usage, and advisory mentions
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => refetch()}>
          <RefreshCw className="w-4 h-4 mr-1" /> Refresh
        </Button>
      </div>

      <div className="flex gap-3 flex-wrap">
        <Input
          placeholder="Search by name, alias, or origin..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-sm"
        />
        <Select value={selectedOrigin} onValueChange={setSelectedOrigin}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Origin" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Origins</SelectItem>
            {origins.map(o => (
              <SelectItem key={o} value={o}>{o}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {filtered.length === 0 ? (
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-12 text-center">
            <Target className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-40" />
            <p className="text-muted-foreground">No ICS-capable actors found.</p>
            <p className="text-sm text-muted-foreground mt-1">
              Run the daily threat intel pipeline to auto-tag actors with ICS/SCADA capabilities.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filtered.map((actor: any) => (
            <Card key={actor.actorId} className="bg-card/50 border-border/50 hover:border-amber-500/20 transition-colors">
              <CardContent className="p-4">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <h3 className="font-semibold text-amber-400">{actor.name}</h3>
                    {actor.aliases && (actor.aliases as string[]).length > 0 && (
                      <p className="text-xs text-muted-foreground">
                        aka {(actor.aliases as string[]).slice(0, 3).join(", ")}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={`text-[10px] ${
                      actor.threatLevel === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                      actor.threatLevel === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                      actor.threatLevel === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                      'bg-green-500/20 text-green-400 border-green-500/30'
                    }`}>
                      {actor.threatLevel?.toUpperCase()}
                    </Badge>
                    <Badge variant="outline" className="text-[10px] bg-zinc-800 text-zinc-300 border-zinc-700">
                      {actor.actorType}
                    </Badge>
                  </div>
                </div>
                <div className="text-xs space-y-1">
                  {actor.origin && (
                    <div className="flex items-center gap-1">
                      <Globe className="w-3 h-3 text-muted-foreground" />
                      <span className="text-muted-foreground">Origin:</span>
                      <span>{actor.origin}</span>
                    </div>
                  )}
                  {actor.sophistication && (
                    <div className="flex items-center gap-1">
                      <Shield className="w-3 h-3 text-muted-foreground" />
                      <span className="text-muted-foreground">Sophistication:</span>
                      <span className="capitalize">{actor.sophistication}</span>
                    </div>
                  )}
                  {actor.lastActive && (
                    <div className="flex items-center gap-1">
                      <Activity className="w-3 h-3 text-muted-foreground" />
                      <span className="text-muted-foreground">Last Active:</span>
                      <span>{actor.lastActive}</span>
                    </div>
                  )}
                </div>
                {actor.targetSectors && (actor.targetSectors as string[]).length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {(actor.targetSectors as string[]).slice(0, 5).map((s: string) => (
                      <Badge key={s} variant="outline" className="text-[10px] bg-orange-500/10 text-orange-400 border-orange-500/20">
                        {s}
                      </Badge>
                    ))}
                  </div>
                )}
                <div className="mt-3 flex justify-end">
                  <Button
                    size="sm"
                    variant="ghost"
                    className="text-green-400 hover:text-green-300 hover:bg-green-500/10 gap-1 text-xs"
                    onClick={() => onStartEngagement(actor)}
                  >
                    <Rocket className="w-3.5 h-3.5" /> Emulate Actor
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}

// ─── Open-Source Tools Tab ───────────────────────────────────────────────────
function OpenSourceToolsTab() {
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [selectedProtocol, setSelectedProtocol] = useState("all");
  const { data: categories } = trpc.icsOtSecurity.getIcsToolCategories.useQuery();
  const { data: protocols } = trpc.icsOtSecurity.getIcsToolProtocols.useQuery();
  const { data: tools, isLoading } = trpc.icsOtSecurity.getIcsTools.useQuery(
    {
      category: selectedCategory !== "all" ? selectedCategory : undefined,
      protocol: selectedProtocol !== "all" ? selectedProtocol : undefined,
    }
  );

  const categoryIcons: Record<string, React.ReactNode> = {
    honeypot: <Eye className="w-4 h-4 text-yellow-400" />,
    assessment: <Bug className="w-4 h-4 text-red-400" />,
    monitoring: <Activity className="w-4 h-4 text-blue-400" />,
    simulation: <Cpu className="w-4 h-4 text-purple-400" />,
    framework: <Wrench className="w-4 h-4 text-green-400" />,
    protocol_analysis: <Radio className="w-4 h-4 text-cyan-400" />,
    forensics: <Search className="w-4 h-4 text-orange-400" />,
  };

  if (isLoading) {
    return <div className="text-center py-12 text-muted-foreground">Loading ICS tool catalog...</div>;
  }

  return (
    <>
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Wrench className="w-5 h-5 text-green-400" />
            Open-Source ICS/SCADA Tools
          </h2>
          <p className="text-sm text-muted-foreground">
            {tools?.length || 0} curated open-source tools for ICS security assessment, monitoring, and research. Select tools for OT engagements.
          </p>
        </div>
      </div>

      <div className="flex gap-3 flex-wrap">
        <Select value={selectedCategory} onValueChange={setSelectedCategory}>
          <SelectTrigger className="w-52">
            <SelectValue placeholder="Filter by category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            {categories?.map(c => (
              <SelectItem key={c.value} value={c.value}>
                {c.label} ({c.count})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={selectedProtocol} onValueChange={setSelectedProtocol}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Filter by protocol" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Protocols</SelectItem>
            {protocols?.map(p => (
              <SelectItem key={p} value={p}>{p.toUpperCase()}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        {(selectedCategory !== "all" || selectedProtocol !== "all") && (
          <Button variant="ghost" size="sm" onClick={() => { setSelectedCategory("all"); setSelectedProtocol("all"); }}>
            Clear Filters
          </Button>
        )}
      </div>

      {/* Active filter badges */}
      {(selectedCategory !== "all" || selectedProtocol !== "all") && (
        <div className="flex gap-2 flex-wrap">
          {selectedProtocol !== "all" && (
            <Badge variant="outline" className="bg-purple-500/10 text-purple-400 border-purple-500/20">
              <Radio className="w-3 h-3 mr-1" /> Protocol: {selectedProtocol.toUpperCase()}
            </Badge>
          )}
          {selectedCategory !== "all" && (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/20">
              <Wrench className="w-3 h-3 mr-1" /> Category: {selectedCategory.replace(/_/g, ' ')}
            </Badge>
          )}
          <Badge variant="outline" className="bg-zinc-800 text-zinc-300 border-zinc-700">
            {tools?.length || 0} results
          </Badge>
        </div>
      )}

      {/* Category summary cards */}
      {selectedCategory === "all" && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2">
          {categories?.map(c => (
            <Card
              key={c.value}
              className={`bg-card/50 border-border/50 cursor-pointer hover:border-green-500/30 transition-colors ${selectedCategory === c.value ? 'border-green-500/50' : ''}`}
              onClick={() => setSelectedCategory(c.value)}
            >
              <CardContent className="p-3 text-center">
                <div className="flex justify-center mb-1">{categoryIcons[c.value]}</div>
                <p className="text-xs font-medium">{c.label}</p>
                <p className="text-lg font-bold text-green-400">{c.count}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {tools?.map((tool) => (
          <Card key={tool.name} className="bg-card/50 border-border/50 hover:border-green-500/20 transition-colors">
            <CardContent className="p-4">
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  {categoryIcons[tool.category]}
                  <h3 className="font-semibold">{tool.name}</h3>
                </div>
                <a
                  href={tool.githubUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-muted-foreground hover:text-green-400 transition-colors"
                >
                  <ExternalLink className="w-4 h-4" />
                </a>
              </div>
              <p className="text-sm text-muted-foreground mb-3">{tool.description}</p>
              <div className="text-xs space-y-2">
                <div>
                  <span className="text-muted-foreground font-medium">Use Case: </span>
                  <span>{tool.useCase}</span>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant="outline" className="text-[10px] bg-zinc-800 text-zinc-300 border-zinc-700">
                    {tool.license}
                  </Badge>
                  <Badge variant="outline" className="text-[10px] bg-green-500/10 text-green-400 border-green-500/20">
                    {tool.category.replace(/_/g, ' ')}
                  </Badge>
                  {tool.protocols.slice(0, 4).map(p => (
                    <Badge key={p} variant="outline" className="text-[10px] bg-purple-500/10 text-purple-400 border-purple-500/20">
                      {p}
                    </Badge>
                  ))}
                  {tool.protocols.length > 4 && (
                    <span className="text-[10px] text-muted-foreground">+{tool.protocols.length - 4}</span>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </>
  );
}

// ─── Live Advisories Tab ────────────────────────────────────────────────────
function LiveAdvisoriesTab() {
  const [vendor, setVendor] = useState("");
  const [safetyFilter, setSafetyFilter] = useState("all");
  const [protocolFilter, setProtocolFilter] = useState("all");
  const { data: advisories, isLoading, refetch } = trpc.icsOtSecurity.getRecentIcsAdvisories.useQuery({
    limit: 100,
    vendor: vendor || undefined,
    safetyImpact: safetyFilter !== "all" ? safetyFilter : undefined,
  });

  const filteredAdvisories = useMemo(() => {
    if (!advisories || protocolFilter === "all") return advisories || [];
    // Filter advisories by protocol mention in title/product
    return advisories.filter((adv: any) => {
      const text = `${adv.iceTitle || ''} ${adv.iceAffectedProduct || ''}`.toLowerCase();
      return text.includes(protocolFilter.toLowerCase());
    });
  }, [advisories, protocolFilter]);

  if (isLoading) {
    return <div className="text-center py-12 text-muted-foreground">Loading ICS advisories...</div>;
  }

  return (
    <>
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            Live ICS Advisories
          </h2>
          <p className="text-sm text-muted-foreground">
            {advisories?.length || 0} ICS-CERT advisories from CISA, Siemens ProductCERT, Dragos, and vendor feeds. Auto-ingested daily.
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => refetch()}>
          <RefreshCw className="w-4 h-4 mr-1" /> Refresh
        </Button>
      </div>

      <div className="flex gap-3 flex-wrap">
        <Input
          placeholder="Filter by vendor (Siemens, Schneider, Rockwell...)"
          value={vendor}
          onChange={(e) => setVendor(e.target.value)}
          className="max-w-sm"
        />
        <Select value={safetyFilter} onValueChange={setSafetyFilter}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Safety Impact" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Safety Levels</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <Select value={protocolFilter} onValueChange={setProtocolFilter}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Protocol" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Protocols</SelectItem>
            {ICS_PROTOCOLS.map(p => (
              <SelectItem key={p} value={p}>{p.toUpperCase()}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {(!filteredAdvisories || filteredAdvisories.length === 0) ? (
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-12 text-center">
            <AlertTriangle className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-40" />
            <p className="text-muted-foreground">No ICS advisories loaded yet.</p>
            <p className="text-sm text-muted-foreground mt-1">
              Advisories are auto-ingested from CISA ICS-CERT, Siemens ProductCERT, Dragos, and vendor feeds during the daily pipeline run.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {filteredAdvisories.map((adv: any) => (
            <Card key={adv.id} className="bg-card/50 border-border/50 hover:border-amber-500/20 transition-colors">
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      {adv.iceCveId && (
                        <Badge variant="outline" className="text-xs font-mono bg-red-500/10 text-red-400 border-red-500/20">
                          {adv.iceCveId}
                        </Badge>
                      )}
                      {adv.iceIcsCertAdvisoryId && (
                        <Badge variant="outline" className="text-xs font-mono bg-amber-500/10 text-amber-400 border-amber-500/20">
                          {adv.iceIcsCertAdvisoryId}
                        </Badge>
                      )}
                      <span className="text-sm font-medium">{adv.iceTitle}</span>
                    </div>
                    <div className="flex items-center gap-2 mt-2 flex-wrap">
                      {adv.iceAffectedVendor && (
                        <Badge variant="outline" className="text-[10px] bg-blue-500/10 text-blue-400 border-blue-500/20">
                          {adv.iceAffectedVendor}
                        </Badge>
                      )}
                      {adv.iceAffectedProduct && (
                        <Badge variant="outline" className="text-[10px] bg-zinc-800 text-zinc-300 border-zinc-700">
                          {adv.iceAffectedProduct}
                        </Badge>
                      )}
                      {adv.iceCvssScore && (
                        <Badge variant="outline" className={`text-[10px] ${
                          adv.iceCvssScore >= 9 ? "bg-red-500/20 text-red-400 border-red-500/30" :
                          adv.iceCvssScore >= 7 ? "bg-orange-500/20 text-orange-400 border-orange-500/30" :
                          "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                        }`}>
                          CVSS {adv.iceCvssScore}
                        </Badge>
                      )}
                      {adv.iceSafetyImpact && adv.iceSafetyImpact !== "none" && (
                        <Badge variant="outline" className="text-[10px] bg-red-600/20 text-red-400 border-red-600/30">
                          Safety: {adv.iceSafetyImpact}
                        </Badge>
                      )}
                      {adv.icePhysicalImpact === 1 && (
                        <Badge variant="outline" className="text-[10px] bg-red-700/20 text-red-300 border-red-700/30">
                          Physical Impact
                        </Badge>
                      )}
                      {adv.iceExploitAvailable === 1 && (
                        <Badge variant="outline" className="text-[10px] bg-red-500/10 text-red-400 border-red-500/20">
                          <Zap className="w-3 h-3 mr-1" /> Exploit Available
                        </Badge>
                      )}
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground whitespace-nowrap ml-4">
                    {adv.icePublishedDate ? new Date(adv.icePublishedDate).toLocaleDateString() : ""}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}

// ─── Start ICS Engagement Dialog ────────────────────────────────────────────
function StartIcsEngagementDialog({
  open,
  onClose,
  selectedActor,
}: {
  open: boolean;
  onClose: () => void;
  selectedActor: any;
}) {
  const [, navigate] = useLocation();
  const [selectedTemplate, setSelectedTemplate] = useState("ics_ot_assessment");
  const [targetProtocols, setTargetProtocols] = useState<string[]>([]);
  const [targetVendors, setTargetVendors] = useState<string[]>([]);

  // Pre-fill from selected actor/malware
  useMemo(() => {
    if (selectedActor?.protocols) {
      setTargetProtocols(selectedActor.protocols);
    }
    if (selectedActor?.vendors) {
      setTargetVendors(selectedActor.vendors);
    }
    if (selectedActor?.techniques?.some((t: string) => t.startsWith("T08"))) {
      setSelectedTemplate("ics_adversary_emulation");
    }
  }, [selectedActor]);

  const toggleProtocol = (p: string) => {
    setTargetProtocols(prev =>
      prev.includes(p) ? prev.filter(x => x !== p) : [...prev, p]
    );
  };

  const toggleVendor = (v: string) => {
    setTargetVendors(prev =>
      prev.includes(v) ? prev.filter(x => x !== v) : [...prev, v]
    );
  };

  const handleLaunch = () => {
    // Navigate to engagement automation with pre-filled ICS template
    const params = new URLSearchParams({
      template: selectedTemplate,
      protocols: targetProtocols.join(","),
      vendors: targetVendors.join(","),
      ...(selectedActor?.name ? { actor: selectedActor.name } : {}),
    });
    toast.success("Navigating to engagement planner with ICS configuration...");
    navigate(`/engagement-automation?${params.toString()}`);
    onClose();
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Rocket className="w-5 h-5 text-green-400" />
            Start ICS/OT Engagement
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-5">
          {selectedActor && (
            <div className="p-3 rounded-md bg-amber-500/10 border border-amber-500/20">
              <p className="text-sm font-medium text-amber-400">
                Emulating: {selectedActor.name}
              </p>
              {selectedActor.techniques && (
                <p className="text-xs text-muted-foreground mt-1">
                  {selectedActor.techniques.length} MITRE ICS techniques pre-loaded
                </p>
              )}
            </div>
          )}

          <div className="space-y-2">
            <label className="text-sm font-medium">Engagement Template</label>
            <Select value={selectedTemplate} onValueChange={setSelectedTemplate}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ics_ot_assessment">ICS/OT Security Assessment</SelectItem>
                <SelectItem value="ics_adversary_emulation">ICS Adversary Emulation</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Target Protocols</label>
            <div className="flex flex-wrap gap-2">
              {ICS_PROTOCOLS.map(p => (
                <Badge
                  key={p}
                  variant="outline"
                  className={`cursor-pointer text-xs transition-colors ${
                    targetProtocols.includes(p)
                      ? 'bg-purple-500/20 text-purple-400 border-purple-500/40'
                      : 'bg-zinc-800/50 text-zinc-400 border-zinc-700 hover:border-purple-500/30'
                  }`}
                  onClick={() => toggleProtocol(p)}
                >
                  {p.toUpperCase()}
                </Badge>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Target Vendors</label>
            <div className="flex flex-wrap gap-2">
              {ICS_VENDORS.map(v => (
                <Badge
                  key={v}
                  variant="outline"
                  className={`cursor-pointer text-xs transition-colors ${
                    targetVendors.includes(v)
                      ? 'bg-blue-500/20 text-blue-400 border-blue-500/40'
                      : 'bg-zinc-800/50 text-zinc-400 border-zinc-700 hover:border-blue-500/30'
                  }`}
                  onClick={() => toggleVendor(v)}
                >
                  {v}
                </Badge>
              ))}
            </div>
          </div>

          {targetProtocols.length > 0 && (
            <div className="p-2 rounded bg-green-500/5 border border-green-500/20">
              <p className="text-xs text-green-400">
                <Zap className="w-3 h-3 inline mr-1" />
                {targetProtocols.length} protocols + {targetVendors.length} vendors selected.
                Tool recommendations will auto-populate in the engagement wizard.
              </p>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleLaunch} className="gap-2 bg-green-600 hover:bg-green-700">
            <ArrowRight className="w-4 h-4" />
            Launch Engagement
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
