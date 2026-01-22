import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { 
  Shield, 
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
  FileText
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
  const { user, logout, isAuthenticated, loading: authLoading } = useAuth();
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [serverStatus, setServerStatus] = useState<'online' | 'offline' | 'checking'>('checking');

  // Redirect if not authenticated
  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate('/');
    }
  }, [authLoading, isAuthenticated, navigate]);

  // Live stats from DigitalOcean Caldera API
  const [stats, setStats] = useState({
    totalAdversaries: 0,
    totalAbilities: 0,
    activeOperations: 0,
    totalAgents: 0,
  });

  // Fetch live stats from Caldera API
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [adversaries, abilities, operations, agents] = await Promise.all([
          fetch(`${DEFAULT_SERVER.httpUrl}/api/v2/adversaries`, { headers: { 'KEY': 'ADMIN123' } }).then(r => r.json()).catch(() => []),
          fetch(`${DEFAULT_SERVER.httpUrl}/api/v2/abilities`, { headers: { 'KEY': 'ADMIN123' } }).then(r => r.json()).catch(() => []),
          fetch(`${DEFAULT_SERVER.httpUrl}/api/v2/operations`, { headers: { 'KEY': 'ADMIN123' } }).then(r => r.json()).catch(() => []),
          fetch(`${DEFAULT_SERVER.httpUrl}/api/v2/agents`, { headers: { 'KEY': 'ADMIN123' } }).then(r => r.json()).catch(() => []),
        ]);
        setStats({
          totalAdversaries: Array.isArray(adversaries) ? adversaries.length : 0,
          totalAbilities: Array.isArray(abilities) ? abilities.length : 0,
          activeOperations: Array.isArray(operations) ? operations.filter((o: any) => o.state === 'running').length : 0,
          totalAgents: Array.isArray(agents) ? agents.length : 0,
        });
      } catch (error) {
        console.error('Failed to fetch Caldera stats:', error);
      }
    };
    fetchStats();
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, []);

  // Check server health on mount
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await fetch(`${DEFAULT_SERVER.httpUrl}/api/v2/health`, {
          signal: AbortSignal.timeout(5000),
        }).catch(() => null);
        setServerStatus(response?.ok ? 'online' : 'offline');
      } catch {
        setServerStatus('offline');
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  if (authLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <RefreshCw className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-card border-r border-border transform transition-transform duration-200 lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="p-6 border-b border-border">
            <Link href="/" className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-primary" />
              <span className="font-display text-xl tracking-wider">CALDERA</span>
            </Link>
          </div>

          {/* Navigation */}
          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity />} label="DASHBOARD" active />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" />
            <NavItem href="/team" icon={<Users />} label="TEAM" />
            <NavItem href="/activity" icon={<FileText />} label="ACTIVITY" />
          </nav>

          {/* User Info */}
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
              <a href={DEFAULT_SERVER.httpsUrl} target="_blank" rel="noopener noreferrer">
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
              <StatCard value={stats.totalAdversaries.toString()} label="ADVERSARIES" />
              <StatCard value={stats.totalAbilities.toString()} label="ABILITIES" />
              <StatCard value={stats.activeOperations.toString()} label="OPERATIONS" />
              <StatCard value={stats.totalAgents.toString()} label="AGENTS" />
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
                onClick={() => window.open(DEFAULT_SERVER.httpsUrl, '_blank')}
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
          </section>

          {/* Red Divider */}
          <div className="w-full h-0.5 bg-primary" />

          {/* APT29 Campaign Highlight */}
          <section>
            <h2 className="font-display text-2xl mb-4">FEATURED CAMPAIGN</h2>
            <div className="bg-card border-2 border-primary p-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h3 className="font-display text-3xl text-primary mb-2">APT29 VCD CLOUD COMPROMISE</h3>
                  <p className="text-muted-foreground mb-4">
                    Enhanced campaign with 46 abilities tailored for VMware Cloud Director environments.
                    Covers reconnaissance through exfiltration with authentic APT29 TTPs.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <span className="px-3 py-1 bg-secondary text-xs font-display tracking-wider">RECONNAISSANCE</span>
                    <span className="px-3 py-1 bg-secondary text-xs font-display tracking-wider">INITIAL ACCESS</span>
                    <span className="px-3 py-1 bg-secondary text-xs font-display tracking-wider">PERSISTENCE</span>
                    <span className="px-3 py-1 bg-secondary text-xs font-display tracking-wider">EXFILTRATION</span>
                  </div>
                </div>
                <Link href="/adversaries">
                  <Button className="font-display tracking-wider bg-primary hover:bg-primary/90">
                    VIEW CAMPAIGN
                    <ChevronRight className="w-4 h-4 ml-2" />
                  </Button>
                </Link>
              </div>
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
