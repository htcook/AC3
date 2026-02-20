import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import {
  Search, Shield, Zap, Upload, CheckCircle2, ChevronDown, ChevronRight,
  Terminal, Copy, Filter, Layers, Target, Eye, Lock, Move, Trash2,
  Database, Bug, ArrowUpRight, Crosshair, Package, AlertTriangle,
} from "lucide-react";
import {
  RANSOMWARE_PROFILES,
  getAllAbilities,
  getAllIOCs,
  type CalderaAbilityDef,
  type RansomwareIOC,
  type RansomwareAbilityProfile,
} from "@/data/ransomware-abilities";

const TACTIC_CONFIG: Record<string, { icon: React.ComponentType<{className?: string}>, color: string, label: string }> = {
  'discovery': { icon: Search, color: 'bg-blue-500/20 text-blue-400 border-blue-500/30', label: 'Discovery' },
  'execution': { icon: Zap, color: 'bg-red-500/20 text-red-400 border-red-500/30', label: 'Execution' },
  'credential-access': { icon: Lock, color: 'bg-amber-500/20 text-amber-400 border-amber-500/30', label: 'Credential Access' },
  'lateral-movement': { icon: Move, color: 'bg-purple-500/20 text-purple-400 border-purple-500/30', label: 'Lateral Movement' },
  'persistence': { icon: Database, color: 'bg-green-500/20 text-green-400 border-green-500/30', label: 'Persistence' },
  'defense-evasion': { icon: Eye, color: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30', label: 'Defense Evasion' },
  'exfiltration': { icon: ArrowUpRight, color: 'bg-orange-500/20 text-orange-400 border-orange-500/30', label: 'Exfiltration' },
  'impact': { icon: Trash2, color: 'bg-rose-500/20 text-rose-400 border-rose-500/30', label: 'Impact' },
  'initial-access': { icon: Crosshair, color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', label: 'Initial Access' },
  'collection': { icon: Package, color: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30', label: 'Collection' },
  'command-and-control': { icon: Terminal, color: 'bg-pink-500/20 text-pink-400 border-pink-500/30', label: 'Command & Control' },
};

function TacticBadge({ tactic }: { tactic: string }) {
  const config = TACTIC_CONFIG[tactic] || { icon: Bug, color: 'bg-gray-500/20 text-gray-400 border-gray-500/30', label: tactic };
  const Icon = config.icon;
  return (
    <Badge variant="outline" className={`${config.color} text-xs`}>
      <Icon className="w-3 h-3 mr-1" />
      {config.label}
    </Badge>
  );
}

function AbilityCard({ ability, group, selected, onToggle }: {
  ability: CalderaAbilityDef;
  group: string;
  selected: boolean;
  onToggle: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const platforms = Object.keys(ability.platforms);

  return (
    <Card className={`border transition-all ${selected ? 'border-cyan-500 bg-cyan-500/5' : 'border-border/50 hover:border-border'}`}>
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <button
            onClick={onToggle}
            className={`mt-1 w-5 h-5 rounded border flex items-center justify-center shrink-0 transition-colors ${
              selected ? 'bg-cyan-500 border-cyan-500' : 'border-muted-foreground/30 hover:border-cyan-500'
            }`}
          >
            {selected && <CheckCircle2 className="w-3.5 h-3.5 text-white" />}
          </button>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <span className="font-mono text-xs text-muted-foreground">{ability.ability_id}</span>
              <TacticBadge tactic={ability.tactic} />
              <Badge variant="outline" className="text-xs bg-muted/50">{group}</Badge>
            </div>
            <h4 className="font-semibold text-sm mb-1">{ability.name}</h4>
            <p className="text-xs text-muted-foreground line-clamp-2">{ability.description}</p>
            <div className="flex items-center gap-2 mt-2">
              <Badge variant="outline" className="text-xs font-mono">{ability.technique_id}</Badge>
              <span className="text-xs text-muted-foreground">{ability.technique_name}</span>
              <div className="ml-auto flex gap-1">
                {platforms.map(p => (
                  <Badge key={p} variant="secondary" className="text-[10px]">{p}</Badge>
                ))}
              </div>
            </div>
            {expanded && (
              <div className="mt-3 space-y-2">
                {Object.entries(ability.platforms).map(([platform, executors]) =>
                  Object.entries(executors).map(([executor, config]) => (
                    <div key={`${platform}-${executor}`} className="bg-black/30 rounded p-3 border border-border/30">
                      <div className="flex items-center gap-2 mb-2">
                        <Terminal className="w-3 h-3 text-green-400" />
                        <span className="text-xs font-mono text-green-400">{platform}/{executor}</span>
                        <button
                          onClick={() => { navigator.clipboard.writeText(config.command); toast.success("Command copied"); }}
                          className="ml-auto text-muted-foreground hover:text-foreground"
                        >
                          <Copy className="w-3 h-3" />
                        </button>
                      </div>
                      <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap break-all">{config.command}</pre>
                      {config.cleanup && (
                        <div className="mt-2 pt-2 border-t border-border/20">
                          <span className="text-[10px] text-amber-400">Cleanup:</span>
                          <pre className="text-xs font-mono text-muted-foreground/70 whitespace-pre-wrap">{config.cleanup}</pre>
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}
            <button
              onClick={() => setExpanded(!expanded)}
              className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 mt-2"
            >
              {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
              {expanded ? 'Hide commands' : 'Show commands'}
            </button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function IOCCard({ ioc, group }: { ioc: RansomwareIOC; group: string }) {
  const typeColors: Record<string, string> = {
    hash_sha256: 'text-red-400', hash_md5: 'text-red-400',
    domain: 'text-blue-400', ip: 'text-green-400', url: 'text-purple-400',
    email: 'text-amber-400', filename: 'text-cyan-400',
    registry: 'text-orange-400', mutex: 'text-pink-400', user_agent: 'text-indigo-400',
  };
  const confColors: Record<string, string> = {
    high: 'bg-red-500/20 text-red-400', medium: 'bg-amber-500/20 text-amber-400', low: 'bg-gray-500/20 text-gray-400',
  };

  return (
    <div className="flex items-start gap-3 p-3 rounded border border-border/30 bg-card/50 hover:bg-card/80 transition-colors">
      <AlertTriangle className={`w-4 h-4 mt-0.5 shrink-0 ${typeColors[ioc.type] || 'text-muted-foreground'}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <Badge variant="outline" className="text-[10px] font-mono">{ioc.type.replace('_', ' ')}</Badge>
          <Badge className={`text-[10px] ${confColors[ioc.confidence]}`}>{ioc.confidence}</Badge>
          <Badge variant="outline" className="text-[10px] bg-muted/50">{group}</Badge>
        </div>
        <p className="text-xs font-mono break-all text-foreground/90">{ioc.value}</p>
        <p className="text-xs text-muted-foreground mt-1">{ioc.description}</p>
        {(ioc.firstSeen || ioc.lastSeen) && (
          <div className="flex gap-3 mt-1 text-[10px] text-muted-foreground">
            {ioc.firstSeen && <span>First: {ioc.firstSeen}</span>}
            {ioc.lastSeen && <span>Last: {ioc.lastSeen}</span>}
          </div>
        )}
      </div>
      <button
        onClick={() => { navigator.clipboard.writeText(ioc.value); toast.success("IOC copied"); }}
        className="text-muted-foreground hover:text-foreground shrink-0"
      >
        <Copy className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

export default function AbilitiesLibrary() {
  const [search, setSearch] = useState("");
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [selectedGroup, setSelectedGroup] = useState<string | null>(null);
  const [selectedAbilities, setSelectedAbilities] = useState<Set<string>>(new Set());
  const [viewMode, setViewMode] = useState<'tactic' | 'group' | 'flat'>('tactic');

  const deployMutation = trpc.calderaProxy.deployRansomwareProfile.useMutation({
    onSuccess: (data) => toast.success(`Deployed ${data.abilitiesDeployed} abilities to the emulation framework`),
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const deployGroup = (groupId: string) => {
    const profile = RANSOMWARE_PROFILES.find(p => p.groupId === groupId);
    if (!profile) return;
    deployMutation.mutate({
      groupId: profile.groupId,
      groupName: profile.groupName,
      adversaryId: profile.adversaryId,
      description: profile.description,
      abilities: profile.abilities.map(a => ({
        ability_id: a.ability_id,
        name: a.name,
        description: a.description,
        tactic: a.tactic,
        technique_id: a.technique_id,
        technique_name: a.technique_name,
        platforms: a.platforms,
      })),
    });
  };

  const allAbilities = useMemo(() => getAllAbilities(), []);
  const allIOCs = useMemo(() => getAllIOCs(), []);

  const filteredAbilities = useMemo(() => {
    let result = allAbilities;
    if (selectedTactic) result = result.filter(a => a.tactic === selectedTactic);
    if (selectedGroup) {
      const profile = RANSOMWARE_PROFILES.find(p => p.groupId === selectedGroup);
      if (profile) {
        const abilityIds = new Set(profile.abilities.map(a => a.ability_id));
        result = result.filter(a => abilityIds.has(a.ability_id));
      }
    }
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(a =>
        a.name.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        a.technique_id.toLowerCase().includes(q) ||
        a.technique_name.toLowerCase().includes(q) ||
        a.ability_id.toLowerCase().includes(q)
      );
    }
    return result;
  }, [allAbilities, selectedTactic, selectedGroup, search]);

  const filteredIOCs = useMemo(() => {
    let result = allIOCs;
    if (selectedGroup) {
      const profile = RANSOMWARE_PROFILES.find(p => p.groupId === selectedGroup);
      if (profile) {
        const iocValues = new Set(profile.iocs.map(i => i.value));
        result = result.filter(i => iocValues.has(i.value));
      }
    }
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(i =>
        i.value.toLowerCase().includes(q) ||
        i.description.toLowerCase().includes(q) ||
        i.type.toLowerCase().includes(q)
      );
    }
    return result;
  }, [allIOCs, selectedGroup, search]);

  const getGroupForAbility = (abilityId: string): string => {
    for (const p of RANSOMWARE_PROFILES) {
      if (p.abilities.some(a => a.ability_id === abilityId)) return p.groupName;
    }
    return 'Unknown';
  };

  const getGroupForIOC = (iocValue: string): string => {
    for (const p of RANSOMWARE_PROFILES) {
      if (p.iocs.some(i => i.value === iocValue)) return p.groupName;
    }
    return 'Unknown';
  };

  const tacticGroups = useMemo(() => {
    const groups: Record<string, CalderaAbilityDef[]> = {};
    for (const a of filteredAbilities) {
      if (!groups[a.tactic]) groups[a.tactic] = [];
      groups[a.tactic].push(a);
    }
    return Object.entries(groups).sort((a, b) => b[1].length - a[1].length);
  }, [filteredAbilities]);

  const groupGroups = useMemo(() => {
    const groups: Record<string, CalderaAbilityDef[]> = {};
    for (const a of filteredAbilities) {
      const g = getGroupForAbility(a.ability_id);
      if (!groups[g]) groups[g] = [];
      groups[g].push(a);
    }
    return Object.entries(groups).sort((a, b) => b[1].length - a[1].length);
  }, [filteredAbilities]);

  const toggleAbility = (id: string) => {
    setSelectedAbilities(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    setSelectedAbilities(new Set(filteredAbilities.map(a => a.ability_id)));
  };

  const clearSelection = () => setSelectedAbilities(new Set());

  const deploySelected = () => {
    if (selectedAbilities.size === 0) { toast.error("No abilities selected"); return; }
    // Find which groups have selected abilities
    const groupsToDeployArr: string[] = [];
    Array.from(selectedAbilities).forEach(id => {
      for (const p of RANSOMWARE_PROFILES) {
        if (p.abilities.some(a => a.ability_id === id) && !groupsToDeployArr.includes(p.groupId)) {
          groupsToDeployArr.push(p.groupId);
        }
      }
    });
    groupsToDeployArr.forEach(groupId => {
      deployGroup(groupId);
    });
  };

  const tactics = useMemo(() => {
    const t = new Set(allAbilities.map(a => a.tactic));
    return Array.from(t).sort();
  }, [allAbilities]);

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
              <Layers className="w-7 h-7 text-cyan-400" />
              Abilities Library
            </h1>
            <p className="text-muted-foreground mt-1">
              Searchable catalog of {allAbilities.length} adversary abilities and {allIOCs.length} IOCs across {RANSOMWARE_PROFILES.length} ransomware groups
            </p>
          </div>
          <div className="flex gap-2">
            {selectedAbilities.size > 0 && (
              <>
                <Badge variant="outline" className="text-sm px-3 py-1">
                  {selectedAbilities.size} selected
                </Badge>
                <Button variant="outline" size="sm" onClick={clearSelection}>Clear</Button>
                <Button size="sm" onClick={deploySelected} disabled={deployMutation.isPending} className="bg-cyan-600 hover:bg-cyan-700">
                  <Upload className="w-4 h-4 mr-1" />
                  Deploy to the emulation framework
                </Button>
              </>
            )}
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2 sm:gap-3">
          {[
            { label: 'Total Abilities', value: allAbilities.length, icon: Zap, color: 'text-cyan-400' },
            { label: 'Total IOCs', value: allIOCs.length, icon: AlertTriangle, color: 'text-red-400' },
            { label: 'Groups', value: RANSOMWARE_PROFILES.length, icon: Shield, color: 'text-purple-400' },
            { label: 'Tactics', value: tactics.length, icon: Target, color: 'text-amber-400' },
            { label: 'Techniques', value: new Set(allAbilities.map(a => a.technique_id)).size, icon: Crosshair, color: 'text-green-400' },
          ].map(s => (
            <Card key={s.label} className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <s.icon className={`w-8 h-8 ${s.color}`} />
                <div>
                  <p className="text-2xl font-bold">{s.value}</p>
                  <p className="text-xs text-muted-foreground">{s.label}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Filters */}
        <Card className="border-border/50">
          <CardContent className="p-4">
            <div className="flex flex-wrap gap-3 items-center">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search abilities, techniques, IOCs..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9"
                />
              </div>
              <div className="flex gap-2 items-center">
                <Filter className="w-4 h-4 text-muted-foreground" />
                <select
                  value={selectedTactic || ''}
                  onChange={(e) => setSelectedTactic(e.target.value || null)}
                  className="bg-background border rounded px-3 py-2 text-sm"
                >
                  <option value="">All Tactics</option>
                  {tactics.map(t => (
                    <option key={t} value={t}>{TACTIC_CONFIG[t]?.label || t}</option>
                  ))}
                </select>
                <select
                  value={selectedGroup || ''}
                  onChange={(e) => setSelectedGroup(e.target.value || null)}
                  className="bg-background border rounded px-3 py-2 text-sm"
                >
                  <option value="">All Groups</option>
                  {RANSOMWARE_PROFILES.map(p => (
                    <option key={p.groupId} value={p.groupId}>{p.groupName}</option>
                  ))}
                </select>
              </div>
              <Button variant="outline" size="sm" onClick={selectAll}>Select All ({filteredAbilities.length})</Button>
            </div>
          </CardContent>
        </Card>

        {/* Main Content */}
        <Tabs defaultValue="abilities">
          <TabsList>
            <TabsTrigger value="abilities">Abilities ({filteredAbilities.length})</TabsTrigger>
            <TabsTrigger value="iocs">IOCs ({filteredIOCs.length})</TabsTrigger>
            <TabsTrigger value="groups">Groups ({RANSOMWARE_PROFILES.length})</TabsTrigger>
          </TabsList>

          <TabsContent value="abilities" className="mt-4">
            <div className="flex gap-2 mb-4">
              {(['tactic', 'group', 'flat'] as const).map(mode => (
                <Button
                  key={mode}
                  variant={viewMode === mode ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setViewMode(mode)}
                >
                  {mode === 'tactic' ? 'By Tactic' : mode === 'group' ? 'By Group' : 'Flat List'}
                </Button>
              ))}
            </div>

            {viewMode === 'flat' ? (
              <div className="space-y-3">
                {filteredAbilities.map(a => (
                  <AbilityCard
                    key={a.ability_id}
                    ability={a}
                    group={getGroupForAbility(a.ability_id)}
                    selected={selectedAbilities.has(a.ability_id)}
                    onToggle={() => toggleAbility(a.ability_id)}
                  />
                ))}
              </div>
            ) : (
              <div className="space-y-6">
                {(viewMode === 'tactic' ? tacticGroups : groupGroups).map(([key, abilities]) => (
                  <TacticSection
                    key={key}
                    title={viewMode === 'tactic' ? (TACTIC_CONFIG[key]?.label || key) : key}
                    count={abilities.length}
                    tactic={viewMode === 'tactic' ? key : undefined}
                  >
                    {abilities.map(a => (
                      <AbilityCard
                        key={a.ability_id}
                        ability={a}
                        group={getGroupForAbility(a.ability_id)}
                        selected={selectedAbilities.has(a.ability_id)}
                        onToggle={() => toggleAbility(a.ability_id)}
                      />
                    ))}
                  </TacticSection>
                ))}
              </div>
            )}
          </TabsContent>

          <TabsContent value="iocs" className="mt-4">
            <div className="space-y-2">
              {filteredIOCs.map((ioc, i) => (
                <IOCCard key={`${ioc.value}-${i}`} ioc={ioc} group={getGroupForIOC(ioc.value)} />
              ))}
              {filteredIOCs.length === 0 && (
                <div className="text-center py-12 text-muted-foreground">
                  <AlertTriangle className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No IOCs match your filters</p>
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="groups" className="mt-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 sm:gap-4">
              {RANSOMWARE_PROFILES.map(profile => (
                <GroupCard
                  key={profile.groupId}
                  profile={profile}
                  onDeploy={() => deployGroup(profile.groupId)}
                  deploying={deployMutation.isPending}
                />
              ))}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}

function TacticSection({ title, count, tactic, children }: {
  title: string; count: number; tactic?: string; children: React.ReactNode;
}) {
  const [expanded, setExpanded] = useState(true);
  const config = tactic ? TACTIC_CONFIG[tactic] : null;
  const Icon = config?.icon || Layers;

  return (
    <div>
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 w-full text-left mb-3 group"
      >
        {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        <Icon className={`w-5 h-5 ${config ? '' : 'text-muted-foreground'}`} />
        <span className="font-semibold">{title}</span>
        <Badge variant="secondary" className="text-xs">{count}</Badge>
      </button>
      {expanded && <div className="space-y-3 ml-6">{children}</div>}
    </div>
  );
}

function GroupCard({ profile, onDeploy, deploying }: {
  profile: RansomwareAbilityProfile; onDeploy: () => void; deploying: boolean;
}) {
  return (
    <Card className="border-border/50 hover:border-cyan-500/30 transition-colors">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg flex items-center gap-2">
          <Shield className="w-5 h-5 text-red-400" />
          {profile.groupName}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground line-clamp-3">{profile.description}</p>
        <div className="flex flex-wrap gap-1">
          {profile.killChainPhases.map(phase => (
            <TacticBadge key={phase} tactic={phase} />
          ))}
        </div>
        <div className="grid grid-cols-2 gap-2 text-center">
          <div className="bg-muted/30 rounded p-2">
            <p className="text-lg font-bold">{profile.abilities.length}</p>
            <p className="text-[10px] text-muted-foreground">Abilities</p>
          </div>
          <div className="bg-muted/30 rounded p-2">
            <p className="text-lg font-bold">{profile.iocs.length}</p>
            <p className="text-[10px] text-muted-foreground">IOCs</p>
          </div>
        </div>
        <Button
          className="w-full bg-cyan-600 hover:bg-cyan-700"
          size="sm"
          onClick={(e) => { e.stopPropagation(); onDeploy(); }}
          disabled={deploying}
        >
          <Upload className="w-4 h-4 mr-1" />
          Deploy All to the emulation framework
        </Button>
      </CardContent>
    </Card>
  );
}
