import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { 
  Activity, 
  Terminal, 
  Users, 
  Key,
  ExternalLink,
  RefreshCw,
  Server,
  Cpu,
  HardDrive,
  Clock,
  Copy,
  LogOut,
  Menu,
  X,
  ChevronRight,
  Zap,
  Target,
  FileText,
  Cloud
} from "lucide-react";
import { useState, useEffect } from "react";

// Default server config for the DigitalOcean deployment
const DEFAULT_SERVER = {
  id: 1,
  name: "Caldera Production",
  ipAddress: "137.184.7.224",
  httpsUrl: "https://137.184.7.224",
  httpUrl: "http://137.184.7.224:8888",
  region: "San Francisco (sfo3)",
  dropletSize: "s-2vcpu-4gb",
  status: "online" as const,
};

export default function Dashboard() {
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [serverStatus, setServerStatus] = useState<'online' | 'offline' | 'checking'>('checking');

  // Live stats from DigitalOcean Caldera API via server proxy
  const { data: stats, refetch: refetchStats } = trpc.calderaProxy.getStats.useQuery(undefined, {
    refetchInterval: 30000,
  });

  const calderaStats = stats || {
    totalAdversaries: 0,
    totalAbilities: 0,
    activeOperations: 0,
    totalAgents: 0,
  };

  // Check server health via server proxy
  const { data: healthData } = trpc.calderaProxy.checkHealth.useQuery(undefined, {
    refetchInterval: 30000,
  });

  useEffect(() => {
    if (healthData !== undefined) {
      setServerStatus(healthData ? 'online' : 'offline');
    }
  }, [healthData]);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-card border-r border-border transform transition-transform duration-200 lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="p-6 border-b border-border">
            <Link href="/" className="flex items-center gap-3">
              <Cloud className="w-8 h-8 text-primary" />
              <div className="flex flex-col">
                <span className="font-display text-xl tracking-wider">ACE OF CLOUD</span>
                <span className="text-xs text-muted-foreground">Caldera Command</span>
              </div>
            </Link>
          </div>

          {/* Navigation */}
          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity />} label="DASHBOARD" active />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" />
            <NavItem href="/agents" icon={<Cpu />} label="AGENTS" />
            <NavItem href="/campaigns" icon={<Zap />} label="CAMPAIGNS" />
            <NavItem href="/team" icon={<Users />} label="TEAM" />
            <NavItem href="/activity" icon={<FileText />} label="ACTIVITY" />
          </nav>

          {/* User Info */}
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
            <Link href="/">
              <Button variant="outline" size="sm" className="w-full font-display tracking-wider">
                <LogOut className="w-4 h-4 mr-2" />
                EXIT
              </Button>
            </Link>
          </div>
        </div>
      </aside>

      {/* Mobile sidebar toggle */}
      <button
        className="fixed top-4 left-4 z-50 lg:hidden p-2 bg-card border border-border"
        onClick={() => setSidebarOpen(!sidebarOpen)}
      >
        {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      {/* Main Content */}
      <main className="flex-1 lg:ml-64">
        {/* Header */}
        <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4 flex items-center justify-between">
            <div>
              <h1 className="font-display text-3xl md:text-4xl">COMMAND CENTER</h1>
              <p className="text-sm text-muted-foreground">Server Management Dashboard</p>
            </div>
            <div className="flex items-center gap-4">
              <a href={DEFAULT_SERVER.httpUrl} target="_blank" rel="noopener noreferrer">
                <Button variant="outline" className="font-display tracking-wider border-2">
                  <ExternalLink className="w-4 h-4 mr-2" />
                  CALDERA UI
                </Button>
              </a>
            </div>
          </div>
          {/* Red Divider */}
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">
          {/* Server Status Card */}
          <section>
            <h2 className="font-display text-2xl mb-4">SERVER STATUS</h2>
            <div className="bg-card border-2 border-border p-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div className="flex items-center gap-4">
                  <div className={`w-4 h-4 ${serverStatus === 'online' ? 'bg-green-500' : serverStatus === 'offline' ? 'bg-red-500' : 'bg-yellow-500 animate-pulse'}`} />
                  <div>
                    <h3 className="font-display text-xl">{DEFAULT_SERVER.name}</h3>
                    <p className="text-muted-foreground">{DEFAULT_SERVER.ipAddress}</p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-4">
                  <StatusBadge icon={<Server />} label="REGION" value={DEFAULT_SERVER.region} />
                  <StatusBadge icon={<Cpu />} label="SIZE" value={DEFAULT_SERVER.dropletSize} />
                  <StatusBadge icon={<Clock />} label="STATUS" value={serverStatus.toUpperCase()} />
                </div>
              </div>
            </div>
          </section>

          {/* Red Divider */}
          <div className="w-full h-0.5 bg-primary" />

          {/* Statistics Grid */}
          <section>
            <h2 className="font-display text-2xl mb-4">CALDERA STATISTICS</h2>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard value={calderaStats.totalAdversaries.toString()} label="ADVERSARIES" />
              <StatCard value={calderaStats.totalAbilities.toString()} label="ABILITIES" />
              <StatCard value={calderaStats.activeOperations.toString()} label="OPERATIONS" />
              <StatCard value={calderaStats.totalAgents.toString()} label="AGENTS" />
            </div>
          </section>

          {/* Red Divider */}
          <div className="w-full h-0.5 bg-primary" />

          {/* Quick Actions */}
          <section>
            <h2 className="font-display text-2xl mb-4">QUICK ACTIONS</h2>
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
              <QuickAction
                icon={<ExternalLink />}
                label="OPEN CALDERA"
                onClick={() => window.open(DEFAULT_SERVER.httpUrl, '_blank')}
              />
              <QuickAction
                icon={<Terminal />}
                label="COPY SSH"
                onClick={() => copyToClipboard(`ssh -i ~/.ssh/caldera_do_key root@${DEFAULT_SERVER.ipAddress}`, 'SSH command')}
              />
              <QuickAction
                icon={<Key />}
                label="VIEW CREDENTIALS"
                onClick={() => navigate('/credentials')}
              />
              <QuickAction
                icon={<Target />}
                label="BROWSE ADVERSARIES"
                onClick={() => navigate('/adversaries')}
              />
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4 mt-4">
              <QuickAction
                icon={<Cpu />}
                label="DEPLOY AGENTS"
                onClick={() => navigate('/agents/deploy')}
              />
              <QuickAction
                icon={<Activity />}
                label="MONITOR OPERATIONS"
                onClick={() => navigate('/operations/monitor')}
              />
              <QuickAction
                icon={<FileText />}
                label="GENERATE REPORT"
                onClick={() => navigate('/reports/generate')}
              />
              <QuickAction
                icon={<RefreshCw />}
                label="REFRESH DATA"
                onClick={() => refetchStats()}
              />
            </div>
          </section>

          {/* Red Divider */}
          <div className="w-full h-0.5 bg-primary" />

          {/* Featured Campaigns - Custom Operations */}
          <section>
            <h2 className="font-display text-2xl mb-4">ACTIVE OPERATIONS</h2>
            <div className="grid md:grid-cols-3 gap-4 mb-8">
              {/* Databank Complete - Merged Operation */}
              <div className="bg-card border-2 border-emerald-500 p-5 hover:border-emerald-500/80 transition-colors md:col-span-2">
                <div className="flex items-center gap-2 mb-3">
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-500 text-xs font-display tracking-wider border border-emerald-500">COMPLETE</span>
                  <span className="text-xs text-muted-foreground">59 ABILITIES</span>
                  <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 text-[10px] font-display tracking-wider">MERGED</span>
                </div>
                <h3 className="font-display text-xl text-emerald-500 mb-2">DATABANK COMPLETE RED TEAM EXERCISE</h3>
                <p className="text-sm text-muted-foreground mb-3">
                  Comprehensive adversary profile combining APT29 VCD Cloud Compromise with CrowdStrike Falcon bypass defense evasion. Full attack lifecycle from initial access through exfiltration with EDR evasion.
                </p>
                <div className="flex flex-wrap gap-1 mb-4">
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-xs border border-emerald-500/30">APT29</span>
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-xs border border-emerald-500/30">VCD</span>
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-xs border border-emerald-500/30">CROWDSTRIKE BYPASS</span>
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-xs border border-emerald-500/30">DEFENSE EVASION</span>
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-xs border border-emerald-500/30">CLOUD</span>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <Link href="/adversaries/Databank_Complete_APT29_VCD_CrowdStrike">
                    <Button size="sm" className="w-full font-display tracking-wider bg-emerald-500 hover:bg-emerald-500/90 text-black">
                      VIEW PROFILE
                    </Button>
                  </Link>
                  <a href="http://137.184.7.224:8888/#/operations" target="_blank" rel="noopener noreferrer">
                    <Button size="sm" variant="outline" className="w-full font-display tracking-wider border-emerald-500 text-emerald-500 hover:bg-emerald-500/10">
                      OPEN IN CALDERA
                    </Button>
                  </a>
                </div>
              </div>

              {/* APT29 VCD Campaign */}
              <div className="bg-card border-2 border-primary p-5 hover:border-primary/80 transition-colors">
                <div className="flex items-center gap-2 mb-3">
                  <span className="px-2 py-0.5 bg-primary/20 text-primary text-xs font-display tracking-wider border border-primary">ACTIVE</span>
                  <span className="text-xs text-muted-foreground">48 ABILITIES</span>
                </div>
                <h3 className="font-display text-lg text-primary mb-2">APT29 VCD ENHANCED</h3>
                <p className="text-sm text-muted-foreground mb-3">
                  VMware Cloud Director campaign with authentic APT29 TTPs.
                </p>
                <div className="flex flex-wrap gap-1 mb-4">
                  <span className="px-2 py-0.5 bg-secondary text-xs">CLOUD</span>
                  <span className="px-2 py-0.5 bg-secondary text-xs">VCD</span>
                </div>
                <Link href="/adversaries/APT29_VCD_Cloud_Compromise_Enhanced">
                  <Button size="sm" className="w-full font-display tracking-wider bg-primary hover:bg-primary/90">
                    VIEW DETAILS
                  </Button>
                </Link>
              </div>

              {/* CrowdStrike Falcon Bypass */}
              <div className="bg-card border-2 border-yellow-500 p-5 hover:border-yellow-500/80 transition-colors">
                <div className="flex items-center gap-2 mb-3">
                  <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-500 text-xs font-display tracking-wider border border-yellow-500">EDR</span>
                  <span className="text-xs text-muted-foreground">12 ABILITIES</span>
                </div>
                <h3 className="font-display text-lg text-yellow-500 mb-2">CROWDSTRIKE BYPASS</h3>
                <p className="text-sm text-muted-foreground mb-3">
                  Defense evasion for CrowdStrike Falcon-protected endpoints.
                </p>
                <div className="flex flex-wrap gap-1 mb-4">
                  <span className="px-2 py-0.5 bg-yellow-500/20 text-xs border border-yellow-500/30">T1562.001</span>
                  <span className="px-2 py-0.5 bg-yellow-500/20 text-xs border border-yellow-500/30">STEALTH</span>
                </div>
                <Link href="/adversaries/Databank_CrowdStrike_Bypass">
                  <Button size="sm" className="w-full font-display tracking-wider bg-yellow-500 hover:bg-yellow-500/90 text-black">
                    VIEW DETAILS
                  </Button>
                </Link>
              </div>

              {/* Operation Status Card */}
              <div className="bg-card border-2 border-border p-5 md:col-span-2">
                <h3 className="font-display text-lg mb-3">OPERATION STATUS</h3>
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="text-2xl font-display text-emerald-500">3</div>
                    <div className="text-xs text-muted-foreground">OPERATIONS</div>
                  </div>
                  <div>
                    <div className="text-2xl font-display text-primary">119</div>
                    <div className="text-xs text-muted-foreground">TOTAL ABILITIES</div>
                  </div>
                  <div>
                    <div className="text-2xl font-display text-yellow-500">PAUSED</div>
                    <div className="text-xs text-muted-foreground">AWAITING AGENTS</div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* APT Threat Actor Library */}
          <section>
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-display text-2xl">APT THREAT ACTOR LIBRARY</h2>
              <Link href="/adversaries">
                <Button variant="outline" size="sm" className="font-display tracking-wider">
                  VIEW ALL <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </Link>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
              {/* APT29 */}
              <a href="http://137.184.7.224:8888/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-blue-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-blue-500 mb-1">APT29</div>
                <div className="text-xs text-muted-foreground mb-2">COZY BEAR</div>
                <div className="text-xs text-blue-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">Russia • G0016</div>
              </a>
              {/* APT28 */}
              <a href="http://137.184.7.224:8888/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-red-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-red-500 mb-1">APT28</div>
                <div className="text-xs text-muted-foreground mb-2">FANCY BEAR</div>
                <div className="text-xs text-red-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">Russia • G0007</div>
              </a>
              {/* APT41 */}
              <a href="http://137.184.7.224:8888/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-orange-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-orange-500 mb-1">APT41</div>
                <div className="text-xs text-muted-foreground mb-2">DOUBLE DRAGON</div>
                <div className="text-xs text-orange-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">China • G0096</div>
              </a>
              {/* Lazarus */}
              <a href="http://137.184.7.224:8888/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-purple-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-purple-500 mb-1">LAZARUS</div>
                <div className="text-xs text-muted-foreground mb-2">HIDDEN COBRA</div>
                <div className="text-xs text-purple-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">N. Korea • G0032</div>
              </a>
              {/* FIN7 */}
              <a href="http://137.184.7.224:8888/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-green-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-green-500 mb-1">FIN7</div>
                <div className="text-xs text-muted-foreground mb-2">CARBANAK</div>
                <div className="text-xs text-green-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">Financial • G0046</div>
              </a>
              {/* Cobalt Group */}
              <a href="http://137.184.7.224:8888/#/adversaries" target="_blank" rel="noopener noreferrer" className="bg-card border-2 border-border hover:border-cyan-500 p-4 text-center transition-colors group">
                <div className="text-3xl font-display text-cyan-500 mb-1">COBALT</div>
                <div className="text-xs text-muted-foreground mb-2">COBALT GROUP</div>
                <div className="text-xs text-cyan-500">50 ABILITIES</div>
                <div className="text-[10px] text-muted-foreground mt-1">Financial • G0080</div>
              </a>
            </div>
          </section>
        </div>
      </main>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
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

function StatusBadge({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2 px-4 py-2 bg-secondary">
      <span className="text-muted-foreground">{icon}</span>
      <div>
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-sm font-medium">{value}</p>
      </div>
    </div>
  );
}

function StatCard({ value, label }: { value: string; label: string }) {
  return (
    <div className="bg-card border-2 border-border p-6 text-center hover:border-primary transition-colors">
      <div className="font-display text-5xl md:text-6xl text-white mb-2">{value}</div>
      <div className="text-xs tracking-widest text-muted-foreground">{label}</div>
    </div>
  );
}

function QuickAction({ icon, label, onClick }: { icon: React.ReactNode; label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center justify-center gap-3 bg-card border-2 border-border p-4 font-display tracking-wider hover:border-primary hover:text-primary transition-colors"
    >
      {icon}
      {label}
    </button>
  );
}
