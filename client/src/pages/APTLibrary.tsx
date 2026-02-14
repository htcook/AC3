import { Link, useLocation } from "wouter";
import { useState, useMemo } from "react";
import {
  Cloud, Activity, Key, Target, Cpu, Zap, Users, FileText, BookOpen, Fish,
  Menu, X, LogOut, ChevronRight, Shield, AlertTriangle, Crosshair, Globe2,
  ArrowRight, ExternalLink, Search, Download, Copy, Check,
  Briefcase, Clock, Filter, Brain,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { APT_SCENARIOS, NAVIGATOR_LAYERS, STIX_BUNDLE, type APTScenario } from "@/data/apt-scenarios";
import { RANSOMWARE_PROFILES } from "@/data/ransomware-abilities";
import { trpc } from "@/lib/trpc";

import AppShell from "@/components/AppShell";
// MITRE ATT&CK Tactic ordering for the heatmap
const TACTICS = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact"
];

export default function APTLibrary() {
  const [, navigate] = useLocation();
  const [selectedAPT, setSelectedAPT] = useState<APTScenario>(APT_SCENARIOS[0]);
  const [searchTerm, setSearchTerm] = useState("");
  const [showStix, setShowStix] = useState(false);
  const [copied, setCopied] = useState(false);
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const [sectorFilter, setSectorFilter] = useState<string>("all");

  const deployToCaldera = trpc.calderaProxy.deployRansomwareProfile.useMutation({
    onSuccess: (data) => {
      toast.success(`Deployed ${data.abilitiesDeployed} abilities to Caldera${data.adversaryCreated ? ' with adversary profile' : ''}`);
      if (data.abilitiesFailed > 0) {
        toast.warning(`${data.abilitiesFailed} abilities failed to deploy`);
      }
    },
    onError: (err) => {
      toast.error(`Deployment failed: ${err.message}`);
    },
  });

  const allSectors = useMemo(() => {
    const sectors = new Set<string>();
    APT_SCENARIOS.forEach(s => s.targetSectors.forEach(sec => sectors.add(sec)));
    return Array.from(sectors).sort();
  }, []);

  const filteredScenarios = APT_SCENARIOS.filter(s => {
    const matchesSearch = s.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.alias.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.origin.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = typeFilter === "all" || s.type === typeFilter;
    const matchesLevel = levelFilter === "all" || s.threatLevel === levelFilter;
    const matchesSector = sectorFilter === "all" || s.targetSectors.includes(sectorFilter);
    return matchesSearch && matchesType && matchesLevel && matchesSector;
  });

  const copyJSON = (data: object, label: string) => {
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    toast.success(`${label} copied to clipboard`);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadJSON = (data: object, filename: string) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Downloaded ${filename}`);
  };

  const navigatorLayer = NAVIGATOR_LAYERS[selectedAPT.id as keyof typeof NAVIGATOR_LAYERS];

  return (
    <AppShell activePath="/apt-library">
{/* Sidebar */}
<header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4 flex items-center justify-between">
            <div>
              <h1 className="font-display text-3xl md:text-2xl sm:text-3xl lg:text-4xl">APT SCENARIO LIBRARY</h1>
              <p className="text-sm text-muted-foreground">Nation-state adversary profiles with ATT&CK mappings and Caldera simulation profiles for authorized government red team engagements.</p>
            </div>
          </div>
          <div className="w-full h-1 bg-red-500" />
        </header>

        <div className="p-6 space-y-8">

          {/* Search + Filters + APT Selector Cards */}
          <section>
            <div className="relative mb-4">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search APT groups by name, alias, or origin..."
                className="w-full pl-10 pr-4 py-3 bg-card border-2 border-border font-display text-sm tracking-wider focus:outline-none focus:border-red-500/50 transition-colors"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
            <div className="flex flex-wrap gap-3 mb-4">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-muted-foreground" />
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="bg-card border border-border px-3 py-1.5 text-xs font-display tracking-wider focus:outline-none focus:border-red-500/50"
                >
                  <option value="all">ALL TYPES</option>
                  <option value="Nation-State APT">NATION-STATE</option>
                  <option value="Cybercrime">CYBERCRIME</option>
                  <option value="Ransomware">RANSOMWARE</option>
                  <option value="Hybrid">HYBRID</option>
                  <option value="Hacktivist">HACKTIVIST</option>
                </select>
              </div>
              <select
                value={levelFilter}
                onChange={(e) => setLevelFilter(e.target.value)}
                className="bg-card border border-border px-3 py-1.5 text-xs font-display tracking-wider focus:outline-none focus:border-red-500/50"
              >
                <option value="all">ALL LEVELS</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
              <select
                value={sectorFilter}
                onChange={(e) => setSectorFilter(e.target.value)}
                className="bg-card border border-border px-3 py-1.5 text-xs font-display tracking-wider focus:outline-none focus:border-red-500/50"
              >
                <option value="all">ALL SECTORS</option>
                {allSectors.map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
              </select>
              <span className="text-xs text-muted-foreground self-center ml-auto">{filteredScenarios.length} of {APT_SCENARIOS.length} actors</span>
            </div>

            <div className="grid grid-cols-2 lg:grid-cols-2 sm:grid-cols-2 lg:grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {filteredScenarios.map((apt) => (
                <button
                  key={apt.id}
                  onClick={() => setSelectedAPT(apt)}
                  className={`bg-card border-2 p-5 text-left transition-all ${
                    selectedAPT.id === apt.id
                      ? `${apt.borderColor} ring-1 ring-current`
                      : 'border-border hover:border-muted-foreground'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className={`font-display text-2xl ${apt.color}`}>{apt.name}</div>
                    <span className={`px-1.5 py-0.5 text-[9px] font-display tracking-wider ${
                      apt.threatLevel === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                      apt.threatLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                      apt.threatLevel === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                      'bg-green-500/20 text-green-400 border border-green-500/30'
                    }`}>{apt.threatLevel}</span>
                  </div>
                  <div className="text-xs text-muted-foreground mb-1">{apt.alias}</div>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-[10px] tracking-wider text-muted-foreground">{apt.origin}</span>
                    <span className={`text-[9px] px-1 py-0.5 ${apt.color} bg-current/10 border border-current/20`}>{apt.type.toUpperCase()}</span>
                  </div>
                  <div className="flex flex-wrap gap-1 mb-2">
                    {apt.targetSectors.slice(0, 3).map(s => (
                      <span key={s} className="text-[9px] px-1 py-0.5 bg-secondary text-muted-foreground">{s}</span>
                    ))}
                    {apt.targetSectors.length > 3 && <span className="text-[9px] text-muted-foreground">+{apt.targetSectors.length - 3}</span>}
                  </div>
                  <div className="text-xs text-muted-foreground">{apt.techniques.length} techniques</div>
                </button>
              ))}
            </div>
          </section>

          <div className="w-full h-0.5 bg-red-500/50" />

          {/* Selected APT Detail */}
          <section>
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className={`w-6 h-6 ${selectedAPT.color}`} />
              <h2 className="font-display text-2xl">{selectedAPT.name} — {selectedAPT.alias.split(" / ")[0].toUpperCase()}</h2>
            </div>

            <div className="grid md:grid-cols-2 gap-4 mb-6">
              {/* Overview */}
              <div className={`bg-card border-2 ${selectedAPT.borderColor} p-5`}>
                <h3 className={`font-display text-lg mb-3 ${selectedAPT.color}`}>OVERVIEW</h3>
                <p className="text-sm text-muted-foreground leading-relaxed mb-4">{selectedAPT.description}</p>
                <div className="bg-secondary/50 p-3">
                  <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">OBJECTIVE</p>
                  <p className="text-sm">{selectedAPT.objective}</p>
                </div>
              </div>

              {/* ATT&CK Technique Heatmap */}
              <div className={`bg-card border-2 ${selectedAPT.borderColor} p-5`}>
                <div className="flex items-center justify-between mb-3">
                  <h3 className={`font-display text-lg ${selectedAPT.color}`}>ATT&CK TECHNIQUE MAP</h3>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className={`text-xs border-current ${selectedAPT.color}`}
                      onClick={() => copyJSON(navigatorLayer, "Navigator Layer")}
                    >
                      {copied ? <Check className="w-3 h-3 mr-1" /> : <Copy className="w-3 h-3 mr-1" />}
                      COPY
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className={`text-xs border-current ${selectedAPT.color}`}
                      onClick={() => downloadJSON(navigatorLayer, `${selectedAPT.id}_navigator_layer.json`)}
                    >
                      <Download className="w-3 h-3 mr-1" />
                      EXPORT
                    </Button>
                  </div>
                </div>
                {/* Tactic-based heatmap */}
                <div className="space-y-1">
                  {TACTICS.map((tactic) => {
                    const matchingTechniques = selectedAPT.techniques.filter(t => t.tactic.includes(tactic));
                    const isActive = matchingTechniques.length > 0;
                    return (
                      <div key={tactic} className="flex items-center gap-2">
                        <div className={`w-32 text-[10px] tracking-wider truncate ${isActive ? selectedAPT.color : 'text-muted-foreground/30'}`}>
                          {tactic.toUpperCase()}
                        </div>
                        <div className="flex-1 h-6 relative">
                          <div className={`absolute inset-0 ${isActive ? 'bg-current opacity-20' : 'bg-secondary/30'}`}
                            style={{ color: isActive ? undefined : undefined }}
                          />
                          {isActive && (
                            <div className={`absolute inset-0 flex items-center px-2 ${selectedAPT.color}`}>
                              {matchingTechniques.map(t => (
                                <span key={t.id} className="text-[10px] font-display tracking-wider mr-3">
                                  {t.id}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                        <div className={`w-6 h-6 flex items-center justify-center text-[10px] font-display ${
                          isActive ? `${selectedAPT.color} bg-current/10` : 'text-muted-foreground/20'
                        }`}>
                          {matchingTechniques.length || '—'}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Activity Timeline + Sector Targeting */}
            <div className="grid md:grid-cols-2 gap-4 mb-6">
              <div className={`bg-card border-2 ${selectedAPT.borderColor} p-5`}>
                <h3 className={`font-display text-lg mb-3 ${selectedAPT.color} flex items-center gap-2`}>
                  <Clock className="w-5 h-5" />
                  RECENT ACTIVITY
                </h3>
                {selectedAPT.recentActivity.length > 0 ? (
                  <div className="space-y-3">
                    {selectedAPT.recentActivity.map((act, i) => (
                      <div key={i} className="flex gap-3">
                        <div className="flex flex-col items-center">
                          <div className={`w-3 h-3 rounded-full ${selectedAPT.color} bg-current`} />
                          {i < selectedAPT.recentActivity.length - 1 && <div className="w-0.5 flex-1 bg-border mt-1" />}
                        </div>
                        <div className="flex-1 pb-3">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-xs font-display tracking-wider text-muted-foreground">{act.date}</span>
                            <span className={`text-[9px] px-1 py-0.5 ${selectedAPT.color} bg-current/10 border border-current/20`}>{act.source}</span>
                          </div>
                          <p className="text-sm">{act.event}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No recent activity recorded.</p>
                )}
              </div>
              <div className={`bg-card border-2 ${selectedAPT.borderColor} p-5`}>
                <h3 className={`font-display text-lg mb-3 ${selectedAPT.color} flex items-center gap-2`}>
                  <Target className="w-5 h-5" />
                  TARGET SECTORS & PROFILE
                </h3>
                <div className="space-y-4">
                  <div>
                    <p className="text-xs font-display tracking-wider text-muted-foreground mb-2">THREAT CLASSIFICATION</p>
                    <div className="flex flex-wrap gap-2">
                      <span className={`px-2 py-1 text-xs font-display tracking-wider ${selectedAPT.color} bg-current/10 border border-current/20`}>{selectedAPT.type.toUpperCase()}</span>
                      <span className={`px-2 py-1 text-xs font-display tracking-wider ${
                        selectedAPT.threatLevel === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                        selectedAPT.threatLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                        'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                      }`}>{selectedAPT.threatLevel}</span>
                    </div>
                  </div>
                  <div>
                    <p className="text-xs font-display tracking-wider text-muted-foreground mb-2">TARGET SECTORS</p>
                    <div className="flex flex-wrap gap-2">
                      {selectedAPT.targetSectors.map(s => (
                        <span key={s} className="px-2 py-1 text-xs bg-secondary">{s}</span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs font-display tracking-wider text-muted-foreground mb-2">CAMPAIGN DESIGN</p>
                    <Button
                      variant="outline"
                      size="sm"
                      className={`w-full font-display tracking-wider border-current ${selectedAPT.color}`}
                      onClick={() => navigate(`/domain-intel`)}
                    >
                      <Brain className="w-4 h-4 mr-2" />
                      USE FOR DOMAIN INTEL PIPELINE
                    </Button>
                  </div>
                </div>
              </div>
            </div>

            {/* Technique Details Table */}
            <div className={`bg-card border-2 ${selectedAPT.borderColor} overflow-hidden mb-6`}>
              <div className="px-5 py-3 border-b border-border">
                <h3 className={`font-display text-lg ${selectedAPT.color}`}>TECHNIQUE DETAILS</h3>
              </div>
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border bg-secondary/50">
                    <th className="text-left text-xs font-display tracking-wider text-muted-foreground px-5 py-3">ID</th>
                    <th className="text-left text-xs font-display tracking-wider text-muted-foreground px-5 py-3">TECHNIQUE</th>
                    <th className="text-left text-xs font-display tracking-wider text-muted-foreground px-5 py-3">TACTIC</th>
                    <th className="text-left text-xs font-display tracking-wider text-muted-foreground px-5 py-3">DESCRIPTION</th>
                    <th className="text-center text-xs font-display tracking-wider text-muted-foreground px-5 py-3">MITRE</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedAPT.techniques.map((tech) => (
                    <tr key={tech.id} className="border-b border-border/30 hover:bg-secondary/30 transition-colors">
                      <td className={`px-5 py-3 font-display text-sm ${selectedAPT.color}`}>{tech.id}</td>
                      <td className="px-5 py-3 text-sm font-medium">{tech.name}</td>
                      <td className="px-5 py-3">
                        <span className={`px-2 py-0.5 text-[10px] font-display tracking-wider ${selectedAPT.color} bg-current/10 border border-current/20`}>
                          {tech.tactic.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-xs text-muted-foreground max-w-md">{tech.description}</td>
                      <td className="px-5 py-3 text-center">
                        <a
                          href={`https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className={`${selectedAPT.color} hover:underline`}
                        >
                          <ExternalLink className="w-4 h-4 mx-auto" />
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Caldera Profile + STIX */}
            <div className="grid md:grid-cols-2 gap-4">
              {/* Caldera Adversary Profile */}
              <div className={`bg-card border-2 ${selectedAPT.borderColor} p-5`}>
                <div className="flex items-center justify-between mb-3">
                  <h3 className={`font-display text-lg ${selectedAPT.color}`}>CALDERA PROFILE</h3>
                  {selectedAPT.calderaProfile && (
                    <Button
                      variant="outline"
                      size="sm"
                      className={`text-xs border-current ${selectedAPT.color}`}
                      onClick={() => copyJSON(selectedAPT.calderaProfile!, "Caldera Profile")}
                    >
                      <Copy className="w-3 h-3 mr-1" />COPY YAML
                    </Button>
                  )}
                </div>
                {selectedAPT.calderaProfile ? (
                  <div>
                    <div className="bg-secondary/50 p-3 mb-3">
                      <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">PROFILE ID</p>
                      <p className="text-sm font-mono">{selectedAPT.calderaProfile.id}</p>
                    </div>
                    <p className="text-xs font-display tracking-wider text-muted-foreground mb-2">ATOMIC ORDERING</p>
                    <div className="space-y-2">
                      {selectedAPT.calderaProfile.atomicOrdering.map((step, i) => (
                        <div key={step} className="flex items-center gap-3">
                          <div className={`w-8 h-8 flex items-center justify-center font-display text-sm ${selectedAPT.color} bg-current/10 border border-current/20`}>
                            {i + 1}
                          </div>
                          <div className="flex-1 bg-secondary/50 px-3 py-2">
                            <span className="text-sm font-mono">{step}</span>
                          </div>
                          {i < selectedAPT.calderaProfile!.atomicOrdering.length - 1 && (
                            <ArrowRight className={`w-4 h-4 ${selectedAPT.color} opacity-50`} />
                          )}
                        </div>
                      ))}
                    </div>
                    <div className="mt-4 space-y-2">
                      <Button
                        variant="outline"
                        size="sm"
                        className={`w-full font-display tracking-wider border-current ${selectedAPT.color}`}
                        onClick={() => {
                          const profile = RANSOMWARE_PROFILES.find(r => r.groupId === selectedAPT.id);
                          if (profile) {
                            deployToCaldera.mutate({
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
                          } else {
                            toast.info('No Caldera abilities defined for this group yet.');
                          }
                        }}
                        disabled={deployToCaldera.isPending}
                      >
                        {deployToCaldera.isPending ? (
                          <><Cpu className="w-4 h-4 mr-2 animate-spin" />DEPLOYING...</>
                        ) : (
                          <><Zap className="w-4 h-4 mr-2" />DEPLOY ABILITIES TO CALDERA</>
                        )}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className={`w-full font-display tracking-wider border-current ${selectedAPT.color}`}
                        onClick={() => navigate(`/template-generator?actor=${selectedAPT.id}`)}
                      >
                        <Fish className="w-4 h-4 mr-2" />GENERATE PHISHING TEMPLATE
                      </Button>
                      <a href="https://caldera.aceofcloud.io/#/adversaries" target="_blank" rel="noopener noreferrer">
                        <Button variant="outline" size="sm" className={`w-full font-display tracking-wider border-current ${selectedAPT.color}`}>
                          <Crosshair className="w-4 h-4 mr-2" />
                          LAUNCH IN CALDERA
                        </Button>
                      </a>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Shield className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">No Caldera profile available for this APT group.</p>
                    <p className="text-xs mt-1">Create a custom profile based on the techniques above.</p>
                  </div>
                )}
              </div>

              {/* STIX 2.1 Bundle */}
              <div className={`bg-card border-2 ${selectedAPT.borderColor} p-5`}>
                <div className="flex items-center justify-between mb-3">
                  <h3 className={`font-display text-lg ${selectedAPT.color}`}>STIX 2.1 INTELLIGENCE</h3>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className={`text-xs border-current ${selectedAPT.color}`}
                      onClick={() => setShowStix(!showStix)}
                    >
                      {showStix ? 'HIDE' : 'VIEW'} BUNDLE
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className={`text-xs border-current ${selectedAPT.color}`}
                      onClick={() => downloadJSON(STIX_BUNDLE, "gov_redteam_stix_bundle.json")}
                    >
                      <Download className="w-3 h-3 mr-1" />EXPORT
                    </Button>
                  </div>
                </div>

                <div className="space-y-3 mb-4">
                  {STIX_BUNDLE.objects.map((obj) => (
                    <div key={obj.id} className="flex items-center gap-3 bg-secondary/50 p-3">
                      <div className={`px-2 py-0.5 text-[10px] font-display tracking-wider ${selectedAPT.color} bg-current/10 border border-current/20`}>
                        {obj.type.toUpperCase()}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{obj.name}</p>
                        <p className="text-xs text-muted-foreground font-mono truncate">{obj.id}</p>
                      </div>
                    </div>
                  ))}
                </div>

                {showStix && (
                  <div className="bg-black/50 p-4 overflow-auto max-h-64 border border-border">
                    <pre className="text-xs text-green-400 font-mono whitespace-pre">
                      {JSON.stringify(STIX_BUNDLE, null, 2)}
                    </pre>
                  </div>
                )}

                <div className="mt-4 bg-secondary/30 p-3">
                  <p className="text-xs text-muted-foreground">
                    <span className="font-display tracking-wider">BUNDLE ID:</span> {STIX_BUNDLE.id}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    <span className="font-display tracking-wider">OBJECTS:</span> {STIX_BUNDLE.objects.length} ({STIX_BUNDLE.objects.map(o => o.type).filter((v, i, a) => a.indexOf(v) === i).join(', ')})
                  </p>
                </div>
              </div>
            </div>
          </section>

        </div>
    </AppShell>
  );
}

