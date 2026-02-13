import { Button } from "@/components/ui/button";
import { Link, useLocation, useParams } from "wouter";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { 
  Cloud, 
  Activity, 
  Key,
  Users,
  LogOut,
  Menu,
  X,
  Target,
  FileText,
  Crosshair,
  ChevronRight,
  Zap,
  Cpu,
  ExternalLink,
  Play,
  Pause,
  CheckCircle,
  Clock,
  Shield,
  AlertTriangle,
  ArrowLeft,
  Copy,
  Filter,
  Search
} from "lucide-react";
import { useState, useEffect, useMemo } from "react";

// MITRE ATT&CK Tactic order and colors
const TACTIC_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact'
];

const TACTIC_COLORS: Record<string, string> = {
  'reconnaissance': 'bg-purple-500/20 text-purple-400 border-purple-500',
  'resource-development': 'bg-indigo-500/20 text-indigo-400 border-indigo-500',
  'initial-access': 'bg-red-500/20 text-red-400 border-red-500',
  'execution': 'bg-orange-500/20 text-orange-400 border-orange-500',
  'persistence': 'bg-yellow-500/20 text-yellow-400 border-yellow-500',
  'privilege-escalation': 'bg-amber-500/20 text-amber-400 border-amber-500',
  'defense-evasion': 'bg-green-500/20 text-green-400 border-green-500',
  'credential-access': 'bg-teal-500/20 text-teal-400 border-teal-500',
  'discovery': 'bg-cyan-500/20 text-cyan-400 border-cyan-500',
  'lateral-movement': 'bg-blue-500/20 text-blue-400 border-blue-500',
  'collection': 'bg-sky-500/20 text-sky-400 border-sky-500',
  'command-and-control': 'bg-violet-500/20 text-violet-400 border-violet-500',
  'exfiltration': 'bg-pink-500/20 text-pink-400 border-pink-500',
  'impact': 'bg-rose-500/20 text-rose-400 border-rose-500',
};

const STATUS_STYLES: Record<string, { bg: string; text: string; icon: React.ReactNode }> = {
  paused: { bg: 'bg-yellow-500/20 border-yellow-500', text: 'text-yellow-400', icon: <Pause className="w-4 h-4" /> },
  running: { bg: 'bg-green-500/20 border-green-500', text: 'text-green-400', icon: <Play className="w-4 h-4" /> },
  finished: { bg: 'bg-blue-500/20 border-blue-500', text: 'text-blue-400', icon: <CheckCircle className="w-4 h-4" /> },
  cleanup: { bg: 'bg-orange-500/20 border-orange-500', text: 'text-orange-400', icon: <AlertTriangle className="w-4 h-4" /> },
};

export default function OperationDetail() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);

  // Fetch operations and abilities
  const { data: operations, isLoading: opsLoading } = trpc.calderaProxy.getOperations.useQuery();
  const { data: allAbilities, isLoading: abilitiesLoading } = trpc.calderaProxy.getAbilities.useQuery();

  // Find the specific operation
  const operation = useMemo(() => {
    if (!operations) return null;
    return operations.find((op: any) => op.id === params.id);
  }, [operations, params.id]);

  // Get adversary abilities
  const adversaryAbilities = useMemo(() => {
    if (!operation || !allAbilities) return [];
    const atomicOrdering = operation.adversary?.atomic_ordering || [];
    const abilityMap = new Map(allAbilities.map((a: any) => [a.ability_id, a]));
    return atomicOrdering.map((id: string) => abilityMap.get(id)).filter(Boolean);
  }, [operation, allAbilities]);

  // Filter abilities
  const filteredAbilities = useMemo(() => {
    let filtered = adversaryAbilities;
    
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter((a: any) => 
        a.name?.toLowerCase().includes(term) ||
        a.technique_id?.toLowerCase().includes(term) ||
        a.description?.toLowerCase().includes(term)
      );
    }
    
    if (selectedTactic) {
      filtered = filtered.filter((a: any) => a.tactic === selectedTactic);
    }
    
    return filtered;
  }, [adversaryAbilities, searchTerm, selectedTactic]);

  // Group abilities by tactic
  const abilitiesByTactic = useMemo(() => {
    const grouped: Record<string, any[]> = {};
    adversaryAbilities.forEach((ability: any) => {
      const tactic = ability.tactic || 'unknown';
      if (!grouped[tactic]) grouped[tactic] = [];
      grouped[tactic].push(ability);
    });
    return grouped;
  }, [adversaryAbilities]);

  // Get unique tactics in order
  const tactics = useMemo(() => {
    const tacticSet = new Set(adversaryAbilities.map((a: any) => a.tactic || 'unknown'));
    return TACTIC_ORDER.filter(t => tacticSet.has(t));
  }, [adversaryAbilities]);

  const handleCopyAbilityId = (id: string) => {
    navigator.clipboard.writeText(id);
    toast.success('Ability ID copied to clipboard');
  };

  const handleOpenInCaldera = () => {
    window.open(`https://caldera.aceofcloud.io/operations/${params.id}`, '_blank');
  };

  if (opsLoading || abilitiesLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-muted-foreground">Loading operation details...</p>
        </div>
      </div>
    );
  }

  if (!operation) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
          <h2 className="font-display text-2xl mb-2">Operation Not Found</h2>
          <p className="text-muted-foreground mb-4">The operation you're looking for doesn't exist.</p>
          <Link href="/campaigns">
            <Button variant="outline">
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Campaigns
            </Button>
          </Link>
        </div>
      </div>
    );
  }

  const statusStyle = STATUS_STYLES[operation.state] || STATUS_STYLES.paused;

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
            <NavItem href="/campaigns" icon={<Crosshair />} label="CAMPAIGNS" active />
            <NavItem href="/team" icon={<Users />} label="TEAM" />
            <NavItem href="/activity" icon={<FileText />} label="ACTIVITY" />
          </nav>

          <div className="p-4 border-t border-border">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 bg-primary/20 flex items-center justify-center">
                <span className="font-display text-primary">A</span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">Admin</p>
                <p className="text-xs text-muted-foreground uppercase">ADMIN</p>
              </div>
            </div>
            <Link href="/login">
              <Button variant="outline" size="sm" className="w-full font-display tracking-wider">
                <LogOut className="w-4 h-4 mr-2" />EXIT
              </Button>
            </Link>
          </div>
        </div>
      </aside>

      <button
        className="fixed top-4 left-4 z-50 lg:hidden p-2 bg-card border border-border"
        onClick={() => setSidebarOpen(!sidebarOpen)}
      >
        {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      <main className="flex-1 lg:ml-64">
        <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4">
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
              <Link href="/campaigns" className="hover:text-primary">Campaigns</Link>
              <ChevronRight className="w-4 h-4" />
              <span className="text-foreground">{operation.name}</span>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="font-display text-3xl md:text-4xl">{operation.name}</h1>
                  <span className={`px-3 py-1 text-sm font-display border ${statusStyle.bg} ${statusStyle.text} flex items-center gap-2`}>
                    {statusStyle.icon}
                    {operation.state.toUpperCase()}
                  </span>
                </div>
                <p className="text-sm text-muted-foreground mt-1">
                  Adversary: {operation.adversary?.name || 'None'} • {adversaryAbilities.length} Abilities
                </p>
              </div>
              <Button 
                className="font-display tracking-wider bg-primary hover:bg-primary/90"
                onClick={handleOpenInCaldera}
              >
                <ExternalLink className="w-4 h-4 mr-2" />
                OPEN IN CALDERA
              </Button>
            </div>
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-6">
          {/* Operation Summary */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-card border-2 border-border p-4">
              <div className="flex items-center gap-2 text-muted-foreground mb-2">
                <Target className="w-4 h-4" />
                <span className="text-xs uppercase">Adversary</span>
              </div>
              <p className="font-display text-lg">{operation.adversary?.name || 'None'}</p>
            </div>
            <div className="bg-card border-2 border-border p-4">
              <div className="flex items-center gap-2 text-muted-foreground mb-2">
                <Zap className="w-4 h-4" />
                <span className="text-xs uppercase">Total Abilities</span>
              </div>
              <p className="font-display text-3xl text-primary">{adversaryAbilities.length}</p>
            </div>
            <div className="bg-card border-2 border-border p-4">
              <div className="flex items-center gap-2 text-muted-foreground mb-2">
                <Shield className="w-4 h-4" />
                <span className="text-xs uppercase">Tactics Covered</span>
              </div>
              <p className="font-display text-3xl text-primary">{tactics.length}</p>
            </div>
            <div className="bg-card border-2 border-border p-4">
              <div className="flex items-center gap-2 text-muted-foreground mb-2">
                <Cpu className="w-4 h-4" />
                <span className="text-xs uppercase">Agents</span>
              </div>
              <p className="font-display text-3xl text-primary">{operation.host_group?.length || 0}</p>
            </div>
          </div>

          {/* MITRE ATT&CK Coverage */}
          <div className="bg-card border-2 border-border p-6">
            <h2 className="font-display text-xl mb-4">MITRE ATT&CK COVERAGE</h2>
            <div className="flex flex-wrap gap-2">
              {tactics.map(tactic => {
                const count = abilitiesByTactic[tactic]?.length || 0;
                const colorClass = TACTIC_COLORS[tactic] || 'bg-gray-500/20 text-gray-400 border-gray-500';
                const isSelected = selectedTactic === tactic;
                return (
                  <button
                    key={tactic}
                    onClick={() => setSelectedTactic(isSelected ? null : tactic)}
                    className={`px-3 py-2 text-sm font-display border transition-all ${colorClass} ${isSelected ? 'ring-2 ring-white' : 'hover:opacity-80'}`}
                  >
                    {tactic.replace(/-/g, ' ').toUpperCase()} ({count})
                  </button>
                );
              })}
            </div>
            {selectedTactic && (
              <button 
                onClick={() => setSelectedTactic(null)}
                className="mt-3 text-sm text-muted-foreground hover:text-foreground"
              >
                Clear filter
              </button>
            )}
          </div>

          {/* Search and Filter */}
          <div className="flex gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search abilities by name, technique ID, or description..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-3 bg-card border-2 border-border focus:border-primary outline-none font-display"
              />
            </div>
          </div>

          {/* Abilities List */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="font-display text-xl">
                ABILITIES ({filteredAbilities.length})
              </h2>
            </div>

            {filteredAbilities.length === 0 ? (
              <div className="bg-card border-2 border-border p-8 text-center">
                <AlertTriangle className="w-8 h-8 text-yellow-500 mx-auto mb-3" />
                <p className="text-muted-foreground">No abilities match your search criteria.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {filteredAbilities.map((ability: any, index: number) => {
                  const tacticColor = TACTIC_COLORS[ability.tactic] || 'bg-gray-500/20 text-gray-400 border-gray-500';
                  return (
                    <div 
                      key={ability.ability_id}
                      className="bg-card border-2 border-border hover:border-primary/50 transition-colors p-4"
                    >
                      <div className="flex items-start gap-4">
                        <div className="w-8 h-8 bg-primary/20 flex items-center justify-center flex-shrink-0">
                          <span className="font-display text-primary text-sm">{index + 1}</span>
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-2">
                            <h3 className="font-display text-lg">{ability.name}</h3>
                            <span className={`px-2 py-0.5 text-xs font-display border ${tacticColor}`}>
                              {ability.tactic?.replace(/-/g, ' ').toUpperCase()}
                            </span>
                            {ability.technique_id && (
                              <span className="px-2 py-0.5 text-xs font-mono bg-secondary text-muted-foreground">
                                {ability.technique_id}
                              </span>
                            )}
                          </div>
                          {ability.description && (
                            <p className="text-sm text-muted-foreground mb-2 line-clamp-2">
                              {ability.description}
                            </p>
                          )}
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            {ability.technique_name && (
                              <span className="flex items-center gap-1">
                                <Target className="w-3 h-3" />
                                {ability.technique_name}
                              </span>
                            )}
                            {ability.executors?.[0]?.platform && (
                              <span className="flex items-center gap-1">
                                <Cpu className="w-3 h-3" />
                                {ability.executors[0].platform}
                              </span>
                            )}
                          </div>
                        </div>
                        <button
                          onClick={() => handleCopyAbilityId(ability.ability_id)}
                          className="p-2 hover:bg-secondary transition-colors"
                          title="Copy Ability ID"
                        >
                          <Copy className="w-4 h-4 text-muted-foreground" />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
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
