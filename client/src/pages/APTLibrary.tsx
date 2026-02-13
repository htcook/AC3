import { Link, useLocation } from "wouter";
import { useState } from "react";
import {
  Cloud, Activity, Key, Target, Cpu, Zap, Users, FileText, BookOpen, Fish,
  Menu, X, LogOut, ChevronRight, Shield, AlertTriangle, Crosshair, Globe2,
  ArrowRight, ExternalLink, Search, Download, Copy, Check
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { APT_SCENARIOS, NAVIGATOR_LAYERS, STIX_BUNDLE, type APTScenario } from "@/data/apt-scenarios";

// MITRE ATT&CK Tactic ordering for the heatmap
const TACTICS = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact"
];

export default function APTLibrary() {
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedAPT, setSelectedAPT] = useState<APTScenario>(APT_SCENARIOS[0]);
  const [searchTerm, setSearchTerm] = useState("");
  const [showStix, setShowStix] = useState(false);
  const [copied, setCopied] = useState(false);

  const filteredScenarios = APT_SCENARIOS.filter(s =>
    s.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    s.alias.toLowerCase().includes(searchTerm.toLowerCase()) ||
    s.origin.toLowerCase().includes(searchTerm.toLowerCase())
  );

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
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-card border-r border-border transform transition-transform duration-200 lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex flex-col h-full">
          <div className="p-6 border-b border-border">
            <Link href="/" className="flex items-center gap-3">
              <Cloud className="w-8 h-8 text-primary" />
              <div className="flex flex-col">
                <span className="font-display text-xl tracking-wider">ACE OF CLOUD</span>
                <span className="text-xs text-muted-foreground tracking-widest">C3 — <span className="text-primary/70">CYBER CAMPAIGN COMMAND</span></span>
              </div>
            </Link>
          </div>
          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity />} label="DASHBOARD" />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" />
            <NavItem href="/agents" icon={<Cpu />} label="AGENTS" />
            <NavItem href="/campaigns" icon={<Zap />} label="CAMPAIGNS" />
            <NavItem href="/gophish" icon={<Fish />} label="GOPHISH" />
            <NavItem href="/team" icon={<Users />} label="TEAM" />
            <NavItem href="/activity" icon={<FileText />} label="ACTIVITY" />
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">THREAT INTEL</p>
              <NavItem href="/apt-library" icon={<Shield />} label="APT SCENARIOS" active />
              <NavItem href="/compliance" icon={<FileText />} label="COMPLIANCE" />
              <NavItem href="/infra-reference" icon={<Globe2 />} label="INFRASTRUCTURE" />
            </div>
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">GUIDES</p>
              <NavItem href="/guide/gophish" icon={<BookOpen />} label="GOPHISH GUIDE" />
              <NavItem href="/guide/caldera" icon={<BookOpen />} label="CALDERA GUIDE" />
              <NavItem href="/templates" icon={<FileText />} label="TEMPLATE LIBRARY" />
            </div>
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">REPORTS</p>
              <NavItem href="/reports/security" icon={<FileText />} label="SECURITY REPORT" />
            </div>
          </nav>
          <div className="p-4 border-t border-border">
            <Link href="/">
              <Button variant="outline" size="sm" className="w-full font-display tracking-wider">
                <LogOut className="w-4 h-4 mr-2" />EXIT
              </Button>
            </Link>
          </div>
        </div>
      </aside>

      <button className="fixed top-4 left-4 z-50 lg:hidden p-2 bg-card border border-border" onClick={() => setSidebarOpen(!sidebarOpen)}>
        {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      {/* Main Content */}
      <main className="flex-1 lg:ml-64">
        <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4 flex items-center justify-between">
            <div>
              <h1 className="font-display text-3xl md:text-4xl">APT SCENARIO LIBRARY</h1>
              <p className="text-sm text-muted-foreground">Nation-state adversary profiles with ATT&CK mappings and Caldera simulation profiles for authorized government red team engagements.</p>
            </div>
          </div>
          <div className="w-full h-1 bg-red-500" />
        </header>

        <div className="p-6 space-y-8">

          {/* Search + APT Selector Cards */}
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

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
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
                  <div className={`font-display text-2xl mb-1 ${apt.color}`}>{apt.name}</div>
                  <div className="text-xs text-muted-foreground mb-2">{apt.alias}</div>
                  <div className="text-[10px] tracking-wider text-muted-foreground">{apt.origin}</div>
                  <div className="text-xs mt-2 text-muted-foreground">{apt.techniques.length} techniques</div>
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
                    <div className="mt-4">
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
      </main>

      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/50 z-40 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}
    </div>
  );
}

function NavItem({ href, icon, label, active }: { href: string; icon: React.ReactNode; label: string; active?: boolean }) {
  return (
    <Link href={href}>
      <div className={`flex items-center gap-3 px-4 py-3 font-display tracking-wider text-sm transition-colors ${active ? 'bg-primary/20 text-primary border-l-2 border-primary' : 'hover:bg-secondary'}`}>
        {icon}
        {label}
      </div>
    </Link>
  );
}
