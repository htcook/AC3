import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Link, useLocation, useParams } from "wouter";
import { 
  Shield, 
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
  Terminal
} from "lucide-react";
import { useState, useEffect } from "react";

// APT29 VCD Enhanced Campaign abilities
const APT29_VCD_ABILITIES = [
  { id: 1, technique: 'T1580', tactic: 'Reconnaissance', name: 'Cloud Infrastructure Discovery', description: 'Enumerate VCD API endpoints and version information' },
  { id: 2, technique: 'T1589.001', tactic: 'Reconnaissance', name: 'Gather Victim Identity - Credentials', description: 'OSINT gathering for VCD admin credentials' },
  { id: 3, technique: 'T1590.004', tactic: 'Reconnaissance', name: 'IP Address Discovery', description: 'Identify VCD management interfaces' },
  { id: 4, technique: 'T1591.004', tactic: 'Reconnaissance', name: 'Network Topology Discovery', description: 'Map VCD organization structure' },
  { id: 5, technique: 'T1566.002', tactic: 'Initial Access', name: 'Spearphishing Link', description: 'Phishing campaign targeting VCD administrators' },
  { id: 6, technique: 'T1190', tactic: 'Initial Access', name: 'Exploit Public-Facing Application', description: 'CVE-2023-34060 VCD authentication bypass' },
  { id: 7, technique: 'T1078.004', tactic: 'Initial Access', name: 'Valid Cloud Accounts', description: 'Use compromised VCD credentials' },
  { id: 8, technique: 'T1199', tactic: 'Initial Access', name: 'Trusted Relationship', description: 'Abuse VCD provider-tenant trust' },
  { id: 9, technique: 'T1059.009', tactic: 'Execution', name: 'Cloud API Execution', description: 'Execute commands via VCD REST API' },
  { id: 10, technique: 'T1059.001', tactic: 'Execution', name: 'PowerShell in vApp', description: 'Execute PowerShell in deployed VMs' },
  { id: 11, technique: 'T1106', tactic: 'Execution', name: 'Native API', description: 'Direct VCD API calls for VM manipulation' },
  { id: 12, technique: 'T1098.001', tactic: 'Persistence', name: 'Additional Cloud Credentials', description: 'Create backdoor VCD admin account' },
  { id: 13, technique: 'T1136.003', tactic: 'Persistence', name: 'Create Cloud Account', description: 'Add service account with elevated privileges' },
  { id: 14, technique: 'T1546', tactic: 'Persistence', name: 'Event Triggered Execution', description: 'VCD event subscription for persistence' },
  { id: 15, technique: 'T1078.004', tactic: 'Persistence', name: 'Valid Cloud Accounts', description: 'Maintain access via legitimate credentials' },
  { id: 16, technique: 'T1548', tactic: 'Privilege Escalation', name: 'Abuse Elevation Control', description: 'Escalate to VCD System Organization' },
  { id: 17, technique: 'T1078.004', tactic: 'Privilege Escalation', name: 'Provider Admin Escalation', description: 'Elevate to provider administrator role' },
  { id: 18, technique: 'T1134', tactic: 'Privilege Escalation', name: 'Access Token Manipulation', description: 'Forge VCD API tokens' },
  { id: 19, technique: 'T1562.001', tactic: 'Defense Evasion', name: 'Disable Audit Logging', description: 'Disable VCD audit and event logging' },
  { id: 20, technique: 'T1070.001', tactic: 'Defense Evasion', name: 'Clear Event Logs', description: 'Remove VCD event history' },
  { id: 21, technique: 'T1070.006', tactic: 'Defense Evasion', name: 'Timestomping', description: 'Modify VCD object timestamps' },
  { id: 22, technique: 'T1550.001', tactic: 'Defense Evasion', name: 'Application Access Token', description: 'Use stolen API tokens' },
  { id: 23, technique: 'T1552.001', tactic: 'Credential Access', name: 'Credentials in Files', description: 'Extract VCD configuration files' },
  { id: 24, technique: 'T1552.004', tactic: 'Credential Access', name: 'Private Keys', description: 'Extract SSL/TLS private keys' },
  { id: 25, technique: 'T1110.003', tactic: 'Credential Access', name: 'Password Spraying', description: 'Spray common passwords against VCD' },
  { id: 26, technique: 'T1606.002', tactic: 'Credential Access', name: 'SAML Token Forgery', description: 'Golden SAML attack on VCD SSO' },
  { id: 27, technique: 'T1087.004', tactic: 'Discovery', name: 'Cloud Account Discovery', description: 'Enumerate VCD organizations and users' },
  { id: 28, technique: 'T1580', tactic: 'Discovery', name: 'Cloud Infrastructure Discovery', description: 'Map VCD vApps and VMs' },
  { id: 29, technique: 'T1526', tactic: 'Discovery', name: 'Cloud Service Discovery', description: 'Identify VCD services and capabilities' },
  { id: 30, technique: 'T1538', tactic: 'Discovery', name: 'Cloud Service Dashboard', description: 'Access VCD management console' },
  { id: 31, technique: 'T1482', tactic: 'Discovery', name: 'Domain Trust Discovery', description: 'Map VCD federation trusts' },
  { id: 32, technique: 'T1021.001', tactic: 'Lateral Movement', name: 'Remote Desktop Protocol', description: 'RDP to VCD-hosted VMs' },
  { id: 33, technique: 'T1550.001', tactic: 'Lateral Movement', name: 'API Token Abuse', description: 'Pivot using VCD API tokens' },
  { id: 34, technique: 'T1021', tactic: 'Lateral Movement', name: 'Cross-Org Movement', description: 'Move between VCD organizations' },
  { id: 35, technique: 'T1560.001', tactic: 'Collection', name: 'Archive via Utility', description: 'Compress VCD configuration data' },
  { id: 36, technique: 'T1530', tactic: 'Collection', name: 'Data from Cloud Storage', description: 'Access VCD catalog and storage' },
  { id: 37, technique: 'T1213', tactic: 'Collection', name: 'Data from Information Repositories', description: 'Export vApp templates' },
  { id: 38, technique: 'T1074.002', tactic: 'Collection', name: 'Remote Data Staging', description: 'Stage data in VCD storage' },
  { id: 39, technique: 'T1071.001', tactic: 'Command and Control', name: 'Web Protocols', description: 'HTTPS C2 beacon' },
  { id: 40, technique: 'T1568', tactic: 'Command and Control', name: 'Dynamic Resolution', description: 'DNS-based C2 resolution' },
  { id: 41, technique: 'T1102', tactic: 'Command and Control', name: 'Web Service', description: 'Use legitimate cloud services for C2' },
  { id: 42, technique: 'T1041', tactic: 'Exfiltration', name: 'Exfiltration Over C2', description: 'Exfiltrate via HTTPS C2 channel' },
  { id: 43, technique: 'T1048.002', tactic: 'Exfiltration', name: 'Exfiltration Over Asymmetric Encrypted', description: 'Encrypted data exfiltration' },
  { id: 44, technique: 'T1567.002', tactic: 'Exfiltration', name: 'Exfiltration to Cloud Storage', description: 'Upload to attacker cloud storage' },
  { id: 45, technique: 'T1485', tactic: 'Impact', name: 'Data Destruction', description: 'Delete VCD resources (optional)' },
  { id: 46, technique: 'T1489', tactic: 'Impact', name: 'Service Stop', description: 'Disrupt VCD services (optional)' },
];

const ADVERSARY_DATA: Record<string, any> = {
  'apt29-vcd-enhanced': {
    name: 'APT29_VCD_Cloud_Compromise_Enhanced',
    description: 'Enhanced APT29 emulation campaign specifically designed for VMware Cloud Director (VCD) environments. This campaign includes 46 abilities covering the full attack lifecycle from reconnaissance through exfiltration, with authentic APT29 tradecraft adapted for cloud infrastructure.',
    abilities: APT29_VCD_ABILITIES,
    tags: ['APT29', 'Cloud', 'VCD', 'Russia'],
    mitreid: 'G0016',
  },
  'apt29-vcd': {
    name: 'APT29_VCD_Cloud_Compromise',
    description: 'Original APT29 VCD campaign with 11 core abilities for VMware Cloud Director environments.',
    abilities: APT29_VCD_ABILITIES.slice(0, 11),
    tags: ['APT29', 'Cloud'],
    mitreid: 'G0016',
  },
};

export default function AdversaryDetail() {
  const { user, logout, isAuthenticated, loading: authLoading } = useAuth();
  const [, navigate] = useLocation();
  const params = useParams<{ id: string }>();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);

  const adversary = ADVERSARY_DATA[params.id || ''] || {
    name: 'Unknown Adversary',
    description: 'Adversary profile not found',
    abilities: [],
    tags: [],
  };

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate('/');
    }
  }, [authLoading, isAuthenticated, navigate]);

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  // Get unique tactics
  const tactics = Array.from(new Set(adversary.abilities.map((a: any) => a.tactic))) as string[];

  // Filter abilities by tactic
  const filteredAbilities = selectedTactic
    ? adversary.abilities.filter((a: any) => a.tactic === selectedTactic)
    : adversary.abilities;

  if (authLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-primary border-t-transparent animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-card border-r border-border transform transition-transform duration-200 lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex flex-col h-full">
          <div className="p-6 border-b border-border">
            <Link href="/" className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-primary" />
              <span className="font-display text-xl tracking-wider">CALDERA</span>
            </Link>
          </div>

          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity />} label="DASHBOARD" />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" active />
            <NavItem href="/team" icon={<Users />} label="TEAM" />
            <NavItem href="/activity" icon={<FileText />} label="ACTIVITY" />
          </nav>

          <div className="p-4 border-t border-border">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 bg-primary/20 flex items-center justify-center">
                <span className="font-display text-primary">{user?.name?.[0] || 'U'}</span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{user?.name || 'User'}</p>
                <p className="text-xs text-muted-foreground uppercase">{user?.role || 'viewer'}</p>
              </div>
            </div>
            <Button variant="outline" size="sm" className="w-full font-display tracking-wider" onClick={handleLogout}>
              <LogOut className="w-4 h-4 mr-2" />
              LOGOUT
            </Button>
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
            <h1 className="font-display text-3xl md:text-4xl text-primary">{adversary.name}</h1>
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">
          {/* Overview */}
          <section className="bg-card border-2 border-border p-6">
            <p className="text-lg text-muted-foreground mb-6">{adversary.description}</p>
            <div className="flex flex-wrap gap-4 items-center">
              <div className="flex items-center gap-2">
                <Zap className="w-5 h-5 text-primary" />
                <span className="font-display">{adversary.abilities.length} ABILITIES</span>
              </div>
              <div className="flex items-center gap-2">
                <Target className="w-5 h-5 text-primary" />
                <span className="font-display">{tactics.length} TACTICS</span>
              </div>
              {adversary.mitreid && (
                <a 
                  href={`https://attack.mitre.org/groups/${adversary.mitreid}/`} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-primary hover:underline"
                >
                  <ExternalLink className="w-4 h-4" />
                  <span className="font-display">MITRE ATT&CK</span>
                </a>
              )}
            </div>
            <div className="flex flex-wrap gap-2 mt-4">
              {adversary.tags.map((tag: string) => (
                <span key={tag} className="px-3 py-1 bg-secondary text-xs font-display tracking-wider">{tag}</span>
              ))}
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* Tactic Filter */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setSelectedTactic(null)}
              className={`px-3 py-2 text-xs font-display tracking-wider border-2 transition-colors ${!selectedTactic ? 'bg-primary border-primary' : 'border-border hover:border-primary'}`}
            >
              ALL TACTICS
            </button>
            {tactics.map((tactic: string) => (
              <button
                key={tactic}
                onClick={() => setSelectedTactic(selectedTactic === tactic ? null : tactic)}
                className={`px-3 py-2 text-xs font-display tracking-wider border-2 transition-colors ${selectedTactic === tactic ? 'bg-primary border-primary' : 'border-border hover:border-primary'}`}
              >
                {tactic.toUpperCase()}
              </button>
            ))}
          </div>

          {/* Abilities Table */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <Code className="w-6 h-6 text-primary" />
              ABILITIES ({filteredAbilities.length})
            </h2>
            <div className="bg-card border-2 border-border overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border bg-secondary/50">
                      <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">TECHNIQUE</th>
                      <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">TACTIC</th>
                      <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">NAME</th>
                      <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground hidden lg:table-cell">DESCRIPTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAbilities.map((ability: any, index: number) => (
                      <tr key={ability.id} className={`border-b border-border/50 hover:bg-secondary/30 ${index % 2 === 0 ? '' : 'bg-secondary/10'}`}>
                        <td className="px-4 py-3">
                          <a 
                            href={`https://attack.mitre.org/techniques/${ability.technique.replace('.', '/')}/`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-mono text-primary hover:underline"
                          >
                            {ability.technique}
                          </a>
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-1 bg-secondary text-xs">{ability.tactic}</span>
                        </td>
                        <td className="px-4 py-3 font-medium">{ability.name}</td>
                        <td className="px-4 py-3 text-sm text-muted-foreground hidden lg:table-cell">{ability.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
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
