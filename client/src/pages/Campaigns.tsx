import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
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
  Plus,
  Play,
  Pause,
  CheckCircle,
  Clock,
  Crosshair,
  ChevronRight,
  Zap,
  Cpu,
  ExternalLink
} from "lucide-react";
import { useState, useEffect } from "react";

// Hardcoded Caldera operations for standalone deployment
const CALDERA_OPERATIONS = [
  {
    id: 'apt29-vcd',
    name: 'APT29 VCD Cloud Compromise',
    description: 'Enhanced campaign for VMware Cloud Director environments with authentic APT29 TTPs.',
    status: 'active',
    adversaryName: 'APT29_VCD_Cloud_Compromise_Enhanced',
    targetEnvironment: 'VMware Cloud Director (VCD)',
    abilities: 46,
    createdAt: '2025-01-15',
    tags: ['CLOUD', 'VCD', 'EXFILTRATION'],
  },
  {
    id: 'crowdstrike-bypass',
    name: 'CrowdStrike Falcon Bypass',
    description: 'Defense evasion operation for testing CrowdStrike Falcon-protected endpoints.',
    status: 'ready',
    adversaryName: 'Databank_CrowdStrike_Bypass',
    targetEnvironment: 'Windows Endpoints with CrowdStrike',
    abilities: 12,
    createdAt: '2025-01-20',
    tags: ['EDR BYPASS', 'T1562.001', 'STEALTH'],
  },
  {
    id: 'apt28-phishing',
    name: 'APT28 Spear Phishing Campaign',
    description: 'Simulated spear phishing campaign using APT28 techniques for email security testing.',
    status: 'draft',
    adversaryName: 'APT28',
    targetEnvironment: 'Email Infrastructure',
    abilities: 50,
    createdAt: '2025-01-18',
    tags: ['PHISHING', 'INITIAL ACCESS', 'T1566'],
  },
  {
    id: 'lazarus-financial',
    name: 'Lazarus Financial Sector Attack',
    description: 'Financial sector targeted attack simulation based on Lazarus Group TTPs.',
    status: 'draft',
    adversaryName: 'Lazarus Group',
    targetEnvironment: 'Financial Systems',
    abilities: 50,
    createdAt: '2025-01-10',
    tags: ['FINANCIAL', 'SWIFT', 'LATERAL MOVEMENT'],
  },
];

const STATUS_STYLES: Record<string, { bg: string; text: string; icon: React.ReactNode }> = {
  draft: { bg: 'bg-gray-500/20 border-gray-500', text: 'text-gray-400', icon: <FileText className="w-4 h-4" /> },
  ready: { bg: 'bg-blue-500/20 border-blue-500', text: 'text-blue-400', icon: <CheckCircle className="w-4 h-4" /> },
  active: { bg: 'bg-green-500/20 border-green-500', text: 'text-green-400', icon: <Play className="w-4 h-4" /> },
  paused: { bg: 'bg-yellow-500/20 border-yellow-500', text: 'text-yellow-400', icon: <Pause className="w-4 h-4" /> },
  completed: { bg: 'bg-primary/20 border-primary', text: 'text-primary', icon: <CheckCircle className="w-4 h-4" /> },
};

export default function Campaigns() {
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [campaigns] = useState(CALDERA_OPERATIONS);

  const handleOpenCaldera = () => {
    window.open('https://137.184.7.224:8888', '_blank');
  };

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
            <Link href="/login"><Button variant="outline" size="sm" className="w-full font-display tracking-wider"><LogOut className="w-4 h-4 mr-2" />EXIT</Button></Link>
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
          <div className="px-6 py-4 flex items-center justify-between">
            <div>
              <h1 className="font-display text-3xl md:text-4xl">CAMPAIGNS</h1>
              <p className="text-sm text-muted-foreground">Red team exercise campaigns and operations</p>
            </div>
            <Button 
              className="font-display tracking-wider bg-primary hover:bg-primary/90"
              onClick={handleOpenCaldera}
            >
              <ExternalLink className="w-4 h-4 mr-2" />
              OPEN CALDERA
            </Button>
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">
          {/* Info Banner */}
          <div className="bg-blue-500/10 border-2 border-blue-500/30 p-4">
            <p className="text-sm text-blue-400">
              <strong>Note:</strong> Campaigns are managed directly in Caldera. Click "Open Caldera" to create and manage operations.
              The campaigns below are pre-configured for your red team exercises.
            </p>
          </div>

          {/* Campaign List */}
          <div className="grid gap-4">
            {campaigns.map((campaign) => {
              const statusStyle = STATUS_STYLES[campaign.status] || STATUS_STYLES.draft;
              return (
                <div key={campaign.id} className="bg-card border-2 border-border hover:border-primary transition-colors p-6 cursor-pointer" onClick={handleOpenCaldera}>
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-2">
                        <Crosshair className="w-5 h-5 text-primary" />
                        <h3 className="font-display text-xl truncate">{campaign.name}</h3>
                        <span className={`px-2 py-1 text-xs font-display border ${statusStyle.bg} ${statusStyle.text} flex items-center gap-1`}>
                          {statusStyle.icon}
                          {campaign.status.toUpperCase()}
                        </span>
                        <span className="px-2 py-1 text-xs font-display bg-primary/20 text-primary border border-primary">
                          {campaign.abilities} ABILITIES
                        </span>
                      </div>
                      {campaign.description && (
                        <p className="text-sm text-muted-foreground mb-3 line-clamp-2">{campaign.description}</p>
                      )}
                      <div className="flex flex-wrap gap-2 mb-3">
                        {campaign.tags.map((tag) => (
                          <span key={tag} className="px-2 py-1 text-xs bg-secondary text-muted-foreground">
                            {tag}
                          </span>
                        ))}
                      </div>
                      <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                        {campaign.adversaryName && (
                          <span className="flex items-center gap-1">
                            <Target className="w-3 h-3" />
                            {campaign.adversaryName}
                          </span>
                        )}
                        {campaign.targetEnvironment && (
                          <span className="flex items-center gap-1">
                            <Zap className="w-3 h-3" />
                            {campaign.targetEnvironment}
                          </span>
                        )}
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {campaign.createdAt}
                        </span>
                      </div>
                    </div>
                    <ExternalLink className="w-5 h-5 text-muted-foreground" />
                  </div>
                </div>
              );
            })}
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
