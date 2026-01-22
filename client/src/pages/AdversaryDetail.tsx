import { Button } from "@/components/ui/button";
import { Link, useLocation, useParams } from "wouter";
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
  ChevronLeft,
  ExternalLink,
  Zap,
  Code,
  Terminal,
  Cpu,
  RefreshCw,
  Shield,
  AlertTriangle,
  Copy,
  Check
} from "lucide-react";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";

// MITRE ATT&CK tactic order for proper display
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

// Tactic display names
const TACTIC_NAMES: Record<string, string> = {
  'reconnaissance': 'Reconnaissance',
  'resource-development': 'Resource Development',
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Movement',
  'collection': 'Collection',
  'command-and-control': 'Command & Control',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact'
};

// Tactic colors for visual distinction
const TACTIC_COLORS: Record<string, string> = {
  'reconnaissance': 'bg-blue-500/20 text-blue-400 border-blue-500/50',
  'resource-development': 'bg-indigo-500/20 text-indigo-400 border-indigo-500/50',
  'initial-access': 'bg-red-500/20 text-red-400 border-red-500/50',
  'execution': 'bg-orange-500/20 text-orange-400 border-orange-500/50',
  'persistence': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
  'privilege-escalation': 'bg-amber-500/20 text-amber-400 border-amber-500/50',
  'defense-evasion': 'bg-green-500/20 text-green-400 border-green-500/50',
  'credential-access': 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50',
  'discovery': 'bg-teal-500/20 text-teal-400 border-teal-500/50',
  'lateral-movement': 'bg-cyan-500/20 text-cyan-400 border-cyan-500/50',
  'collection': 'bg-sky-500/20 text-sky-400 border-sky-500/50',
  'command-and-control': 'bg-violet-500/20 text-violet-400 border-violet-500/50',
  'exfiltration': 'bg-purple-500/20 text-purple-400 border-purple-500/50',
  'impact': 'bg-pink-500/20 text-pink-400 border-pink-500/50'
};

interface Ability {
  ability_id: string;
  name: string;
  description: string;
  tactic: string;
  technique_id: string;
  technique_name: string;
  platforms: Record<string, Record<string, any>>;
  executors?: any[];
}

export default function AdversaryDetail() {
  const [, navigate] = useLocation();
  const params = useParams<{ id: string }>();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [expandedAbility, setExpandedAbility] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Fetch adversary details from Caldera
  const { data: adversary, isLoading: adversaryLoading, error: adversaryError } = 
    trpc.calderaProxy.getAdversary.useQuery(
      { adversaryId: params.id || '' },
      { enabled: !!params.id }
    );

  // Fetch all abilities to get details for the adversary's abilities
  const { data: allAbilities, isLoading: abilitiesLoading } = 
    trpc.calderaProxy.getAbilities.useQuery();

  // Map adversary's atomic_ordering to full ability details
  const adversaryAbilities = useMemo(() => {
    if (!adversary?.atomic_ordering || !allAbilities) return [];
    
    const abilityMap = new Map(allAbilities.map((a: Ability) => [a.ability_id, a]));
    return adversary.atomic_ordering
      .map((abilityId: string) => abilityMap.get(abilityId))
      .filter(Boolean) as Ability[];
  }, [adversary, allAbilities]);

  // Get unique tactics from abilities, sorted by MITRE order
  const tactics = useMemo(() => {
    const tacticSet = new Set(adversaryAbilities.map(a => a.tactic));
    return TACTIC_ORDER.filter(t => tacticSet.has(t));
  }, [adversaryAbilities]);

  // Filter abilities by selected tactic
  const filteredAbilities = useMemo(() => {
    if (!selectedTactic) return adversaryAbilities;
    return adversaryAbilities.filter(a => a.tactic === selectedTactic);
  }, [adversaryAbilities, selectedTactic]);

  // Group abilities by tactic for display
  const abilitiesByTactic = useMemo(() => {
    const grouped: Record<string, Ability[]> = {};
    adversaryAbilities.forEach(ability => {
      const tactic = ability.tactic || 'unknown';
      if (!grouped[tactic]) grouped[tactic] = [];
      grouped[tactic].push(ability);
    });
    return grouped;
  }, [adversaryAbilities]);

  const isLoading = adversaryLoading || abilitiesLoading;

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    toast.success('Copied to clipboard');
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Determine MITRE group ID from adversary name
  const getMitreGroupId = (name: string): string | null => {
    const groupMappings: Record<string, string> = {
      'APT28': 'G0007',
      'APT29': 'G0016',
      'APT41': 'G0096',
      'APT3': 'G0022',
      'APT32': 'G0050',
      'APT33': 'G0064',
      'APT38': 'G0082',
      'APT39': 'G0087',
      'Lazarus': 'G0032',
      'FIN7': 'G0046',
      'FIN8': 'G0061',
      'Cobalt': 'G0080',
      'Turla': 'G0010',
      'Sandworm': 'G0034',
      'Kimsuky': 'G0094',
      'MuddyWater': 'G0069',
      'OilRig': 'G0049',
      'Wizard Spider': 'G0102',
      'Carbanak': 'G0008',
    };
    
    for (const [key, value] of Object.entries(groupMappings)) {
      if (name.toLowerCase().includes(key.toLowerCase())) {
        return value;
      }
    }
    return null;
  };

  const mitreGroupId = adversary ? getMitreGroupId(adversary.name || '') : null;

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
                <span className="text-xs text-muted-foreground">Caldera Command</span>
              </div>
            </Link>
          </div>

          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity />} label="DASHBOARD" />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" active />
            <NavItem href="/agents" icon={<Cpu />} label="AGENTS" />
            <NavItem href="/campaigns" icon={<Zap />} label="CAMPAIGNS" />
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
            <Link href="/"><Button variant="outline" size="sm" className="w-full font-display tracking-wider"><LogOut className="w-4 h-4 mr-2" />EXIT</Button></Link>
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
            <Link href="/adversaries" className="inline-flex items-center gap-2 text-muted-foreground hover:text-white mb-2">
              <ChevronLeft className="w-4 h-4" />
              <span className="text-sm">Back to Adversaries</span>
            </Link>
            {isLoading ? (
              <div className="h-10 w-64 bg-muted animate-pulse rounded" />
            ) : adversaryError ? (
              <h1 className="font-display text-3xl md:text-4xl text-destructive">ERROR LOADING ADVERSARY</h1>
            ) : (
              <h1 className="font-display text-3xl md:text-4xl text-primary">{adversary?.name || 'Unknown Adversary'}</h1>
            )}
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <RefreshCw className="w-8 h-8 animate-spin text-primary" />
            <span className="ml-3 text-muted-foreground">Loading adversary profile...</span>
          </div>
        ) : adversaryError ? (
          <div className="p-6">
            <div className="bg-destructive/10 border border-destructive p-6 text-center">
              <AlertTriangle className="w-12 h-12 mx-auto text-destructive mb-4" />
              <p className="text-lg font-display mb-2">FAILED TO LOAD ADVERSARY</p>
              <p className="text-muted-foreground mb-4">Could not fetch adversary details from Caldera server.</p>
              <Button onClick={() => navigate('/adversaries')} variant="outline">
                <ChevronLeft className="w-4 h-4 mr-2" />
                Return to Adversaries
              </Button>
            </div>
          </div>
        ) : !adversary ? (
          <div className="p-6">
            <div className="bg-card border-2 border-border p-6 text-center">
              <Target className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-lg font-display mb-2">ADVERSARY NOT FOUND</p>
              <p className="text-muted-foreground mb-4">The requested adversary profile does not exist.</p>
              <Button onClick={() => navigate('/adversaries')} variant="outline">
                <ChevronLeft className="w-4 h-4 mr-2" />
                Return to Adversaries
              </Button>
            </div>
          </div>
        ) : (
          <div className="p-6 space-y-8">
            {/* Overview Section */}
            <section className="bg-card border-2 border-border p-6">
              <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-6">
                <div className="flex-1">
                  <p className="text-lg text-muted-foreground mb-6">
                    {adversary.description || 'No description available for this adversary profile.'}
                  </p>
                  
                  {/* Stats Row */}
                  <div className="flex flex-wrap gap-6 items-center mb-6">
                    <div className="flex items-center gap-2">
                      <Zap className="w-5 h-5 text-primary" />
                      <span className="font-display text-xl">{adversaryAbilities.length}</span>
                      <span className="text-muted-foreground">ABILITIES</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Shield className="w-5 h-5 text-primary" />
                      <span className="font-display text-xl">{tactics.length}</span>
                      <span className="text-muted-foreground">TACTICS</span>
                    </div>
                    {mitreGroupId && (
                      <a 
                        href={`https://attack.mitre.org/groups/${mitreGroupId}/`} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 text-primary hover:underline"
                      >
                        <ExternalLink className="w-4 h-4" />
                        <span className="font-display">MITRE {mitreGroupId}</span>
                      </a>
                    )}
                  </div>

                  {/* Adversary ID */}
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-muted-foreground">Adversary ID:</span>
                    <code className="bg-muted px-2 py-1 rounded font-mono text-xs">{adversary.adversary_id}</code>
                    <button 
                      onClick={() => copyToClipboard(adversary.adversary_id, 'adversary-id')}
                      className="p-1 hover:bg-muted rounded"
                    >
                      {copiedId === 'adversary-id' ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4 text-muted-foreground" />}
                    </button>
                  </div>
                </div>

                {/* Quick Actions */}
                <div className="flex flex-col gap-2">
                  <Button 
                    variant="default" 
                    className="font-display tracking-wider"
                    onClick={() => window.open(`http://137.184.7.224:8888/#/adversaries`, '_blank')}
                  >
                    <ExternalLink className="w-4 h-4 mr-2" />
                    OPEN IN CALDERA
                  </Button>
                  {mitreGroupId && (
                    <Button 
                      variant="outline" 
                      className="font-display tracking-wider"
                      onClick={() => window.open(`https://attack.mitre.org/groups/${mitreGroupId}/`, '_blank')}
                    >
                      <Shield className="w-4 h-4 mr-2" />
                      VIEW MITRE ATT&CK
                    </Button>
                  )}
                </div>
              </div>
            </section>

            {/* Tactic Filter */}
            {tactics.length > 0 && (
              <section>
                <h2 className="font-display text-xl mb-4">FILTER BY TACTIC</h2>
                <div className="flex flex-wrap gap-2">
                  <Button
                    variant={selectedTactic === null ? "default" : "outline"}
                    size="sm"
                    className="font-display tracking-wider"
                    onClick={() => setSelectedTactic(null)}
                  >
                    ALL ({adversaryAbilities.length})
                  </Button>
                  {tactics.map(tactic => (
                    <Button
                      key={tactic}
                      variant={selectedTactic === tactic ? "default" : "outline"}
                      size="sm"
                      className={`font-display tracking-wider ${selectedTactic !== tactic ? TACTIC_COLORS[tactic] || '' : ''}`}
                      onClick={() => setSelectedTactic(tactic)}
                    >
                      {TACTIC_NAMES[tactic] || tactic.toUpperCase()} ({abilitiesByTactic[tactic]?.length || 0})
                    </Button>
                  ))}
                </div>
              </section>
            )}

            {/* Abilities List */}
            <section>
              <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
                <Zap className="w-6 h-6 text-primary" />
                ABILITIES ({filteredAbilities.length})
              </h2>
              
              {filteredAbilities.length === 0 ? (
                <div className="bg-card border-2 border-border p-8 text-center">
                  <Code className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                  <p className="text-lg font-display mb-2">NO ABILITIES FOUND</p>
                  <p className="text-muted-foreground">
                    {selectedTactic 
                      ? `No abilities found for the ${TACTIC_NAMES[selectedTactic] || selectedTactic} tactic.`
                      : 'This adversary profile has no abilities configured.'}
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {filteredAbilities.map((ability, index) => (
                    <AbilityCard 
                      key={ability.ability_id} 
                      ability={ability} 
                      index={index + 1}
                      expanded={expandedAbility === ability.ability_id}
                      onToggle={() => setExpandedAbility(
                        expandedAbility === ability.ability_id ? null : ability.ability_id
                      )}
                      onCopy={copyToClipboard}
                      copiedId={copiedId}
                    />
                  ))}
                </div>
              )}
            </section>

            {/* Tactic Coverage Matrix */}
            {adversaryAbilities.length > 0 && (
              <section>
                <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
                  <Shield className="w-6 h-6 text-primary" />
                  MITRE ATT&CK COVERAGE
                </h2>
                <div className="bg-card border-2 border-border p-6 overflow-x-auto">
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
                    {TACTIC_ORDER.map(tactic => {
                      const count = abilitiesByTactic[tactic]?.length || 0;
                      const hasAbilities = count > 0;
                      return (
                        <div 
                          key={tactic}
                          className={`p-3 border text-center cursor-pointer transition-all ${
                            hasAbilities 
                              ? `${TACTIC_COLORS[tactic]} hover:opacity-80` 
                              : 'bg-muted/30 border-border text-muted-foreground'
                          }`}
                          onClick={() => hasAbilities && setSelectedTactic(tactic)}
                        >
                          <div className="text-xs font-display tracking-wider mb-1">
                            {TACTIC_NAMES[tactic]?.toUpperCase() || tactic.toUpperCase()}
                          </div>
                          <div className="text-2xl font-display">{count}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </section>
            )}
          </div>
        )}
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

interface AbilityCardProps {
  ability: Ability;
  index: number;
  expanded: boolean;
  onToggle: () => void;
  onCopy: (text: string, id: string) => void;
  copiedId: string | null;
}

function AbilityCard({ ability, index, expanded, onToggle, onCopy, copiedId }: AbilityCardProps) {
  const tacticColor = TACTIC_COLORS[ability.tactic] || 'bg-gray-500/20 text-gray-400 border-gray-500/50';
  
  // Get platforms
  const platforms = ability.platforms ? Object.keys(ability.platforms) : [];
  
  // Get executor commands if available
  const executors = ability.executors || [];
  const hasCommands = executors.length > 0 || (ability.platforms && Object.keys(ability.platforms).length > 0);

  return (
    <div className={`bg-card border-2 ${expanded ? 'border-primary' : 'border-border'} transition-colors`}>
      <div 
        className="p-4 cursor-pointer hover:bg-muted/30 transition-colors"
        onClick={onToggle}
      >
        <div className="flex items-start gap-4">
          <div className="w-8 h-8 bg-primary/20 flex items-center justify-center shrink-0">
            <span className="font-display text-primary text-sm">{index}</span>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <h3 className="font-display text-lg">{ability.name}</h3>
              {ability.technique_id && (
                <a 
                  href={`https://attack.mitre.org/techniques/${ability.technique_id.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs bg-primary/20 text-primary px-2 py-0.5 font-mono hover:bg-primary/30"
                  onClick={(e) => e.stopPropagation()}
                >
                  {ability.technique_id}
                </a>
              )}
            </div>
            <p className="text-sm text-muted-foreground mb-2 line-clamp-2">
              {ability.description || 'No description available'}
            </p>
            <div className="flex items-center gap-3 flex-wrap">
              <span className={`text-xs px-2 py-0.5 border font-display tracking-wider ${tacticColor}`}>
                {TACTIC_NAMES[ability.tactic] || ability.tactic}
              </span>
              {platforms.map(platform => (
                <span key={platform} className="text-xs bg-muted px-2 py-0.5 font-mono">
                  {platform}
                </span>
              ))}
            </div>
          </div>
          <Terminal className={`w-5 h-5 shrink-0 transition-transform ${expanded ? 'rotate-180 text-primary' : 'text-muted-foreground'}`} />
        </div>
      </div>
      
      {expanded && (
        <div className="border-t border-border p-4 bg-muted/20">
          <div className="space-y-4">
            {/* Full Description */}
            <div>
              <h4 className="text-xs font-display tracking-wider text-muted-foreground mb-2">DESCRIPTION</h4>
              <p className="text-sm">{ability.description || 'No description available'}</p>
            </div>

            {/* Ability ID */}
            <div>
              <h4 className="text-xs font-display tracking-wider text-muted-foreground mb-2">ABILITY ID</h4>
              <div className="flex items-center gap-2">
                <code className="bg-muted px-2 py-1 rounded font-mono text-xs flex-1 overflow-x-auto">
                  {ability.ability_id}
                </code>
                <button 
                  onClick={(e) => { e.stopPropagation(); onCopy(ability.ability_id, ability.ability_id); }}
                  className="p-1 hover:bg-muted rounded"
                >
                  {copiedId === ability.ability_id ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4 text-muted-foreground" />}
                </button>
              </div>
            </div>

            {/* Technique Info */}
            {ability.technique_id && (
              <div>
                <h4 className="text-xs font-display tracking-wider text-muted-foreground mb-2">MITRE TECHNIQUE</h4>
                <a 
                  href={`https://attack.mitre.org/techniques/${ability.technique_id.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 text-primary hover:underline"
                >
                  <span className="font-mono">{ability.technique_id}</span>
                  {ability.technique_name && <span>- {ability.technique_name}</span>}
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            )}

            {/* Platform Commands */}
            {hasCommands && ability.platforms && (
              <div>
                <h4 className="text-xs font-display tracking-wider text-muted-foreground mb-2">EXECUTORS</h4>
                <div className="space-y-2">
                  {Object.entries(ability.platforms).map(([platform, executors]) => (
                    <div key={platform}>
                      {Object.entries(executors as Record<string, any>).map(([executor, details]) => (
                        <div key={`${platform}-${executor}`} className="bg-background border border-border p-3">
                          <div className="flex items-center gap-2 mb-2">
                            <span className="text-xs bg-primary/20 text-primary px-2 py-0.5 font-display">{platform}</span>
                            <span className="text-xs bg-muted px-2 py-0.5 font-mono">{executor}</span>
                          </div>
                          {details?.command && (
                            <div className="relative">
                              <pre className="text-xs font-mono bg-muted p-2 overflow-x-auto whitespace-pre-wrap break-all">
                                {details.command}
                              </pre>
                              <button 
                                onClick={(e) => { e.stopPropagation(); onCopy(details.command, `${ability.ability_id}-${platform}-${executor}`); }}
                                className="absolute top-1 right-1 p-1 hover:bg-background rounded"
                              >
                                {copiedId === `${ability.ability_id}-${platform}-${executor}` 
                                  ? <Check className="w-3 h-3 text-green-500" /> 
                                  : <Copy className="w-3 h-3 text-muted-foreground" />}
                              </button>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
