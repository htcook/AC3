import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { 
  Cloud, 
  Activity, 
  Key,
  Users,
  Copy,
  Eye,
  EyeOff,
  LogOut,
  Menu,
  X,
  Target,
  FileText,
  Terminal,
  Lock,
  ExternalLink,
  Zap
} from "lucide-react";
import { useState, useEffect } from "react";

// Credentials data - DigitalOcean Caldera Server
const CREDENTIALS = {
  adminLogin: {
    username: 'admin',
    password: 'PVYedK$BUAYzyXaAegdEl2Dz',
  },
  redApiKey: 'ADMIN123',
  blueApiKey: 'BLUEADMIN123',
  sshCommand: 'ssh -i ~/.ssh/caldera_do_key root@137.184.7.224',
  serverUrl: 'https://137.184.7.224',
  httpUrl: 'http://137.184.7.224:8888',
};

export default function Credentials() {
  const { user, logout, isAuthenticated, loading: authLoading } = useAuth();
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate('/');
    }
  }, [authLoading, isAuthenticated, navigate]);

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  const togglePassword = (key: string) => {
    setShowPasswords(prev => ({ ...prev, [key]: !prev[key] }));
  };

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
              <Cloud className="w-8 h-8 text-primary" />
              <div className="flex flex-col">
                <span className="font-display text-xl tracking-wider">ACE OF CLOUD</span>
                <span className="text-xs text-muted-foreground">Caldera Command</span>
              </div>
            </Link>
          </div>

          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity />} label="DASHBOARD" />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" active />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" />
            <NavItem href="/campaigns" icon={<Zap />} label="CAMPAIGNS" />
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
            <h1 className="font-display text-3xl md:text-4xl">CREDENTIALS</h1>
            <p className="text-sm text-muted-foreground">Secure access credentials for Caldera server</p>
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">
          {/* Admin Login */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <Lock className="w-6 h-6 text-primary" />
              ADMIN LOGIN
            </h2>
            <div className="bg-card border-2 border-border p-6 space-y-4">
              <CredentialRow
                label="USERNAME"
                value={CREDENTIALS.adminLogin.username}
                onCopy={() => copyToClipboard(CREDENTIALS.adminLogin.username, 'Username')}
              />
              <CredentialRow
                label="PASSWORD"
                value={CREDENTIALS.adminLogin.password}
                isSecret
                show={showPasswords['password']}
                onToggle={() => togglePassword('password')}
                onCopy={() => copyToClipboard(CREDENTIALS.adminLogin.password, 'Password')}
              />
              <div className="pt-4">
                <a href={CREDENTIALS.serverUrl} target="_blank" rel="noopener noreferrer">
                  <Button className="font-display tracking-wider bg-primary hover:bg-primary/90">
                    <ExternalLink className="w-4 h-4 mr-2" />
                    OPEN CALDERA LOGIN
                  </Button>
                </a>
              </div>
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* API Keys */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <Key className="w-6 h-6 text-primary" />
              API KEYS
            </h2>
            <div className="grid md:grid-cols-2 gap-4">
              <div className="bg-card border-2 border-border p-6">
                <h3 className="font-display text-lg mb-4 text-red-500">RED TEAM API KEY</h3>
                <CredentialRow
                  label="API KEY"
                  value={CREDENTIALS.redApiKey}
                  isSecret
                  show={showPasswords['redApi']}
                  onToggle={() => togglePassword('redApi')}
                  onCopy={() => copyToClipboard(CREDENTIALS.redApiKey, 'Red Team API Key')}
                />
              </div>
              <div className="bg-card border-2 border-border p-6">
                <h3 className="font-display text-lg mb-4 text-blue-500">BLUE TEAM API KEY</h3>
                <CredentialRow
                  label="API KEY"
                  value={CREDENTIALS.blueApiKey}
                  isSecret
                  show={showPasswords['blueApi']}
                  onToggle={() => togglePassword('blueApi')}
                  onCopy={() => copyToClipboard(CREDENTIALS.blueApiKey, 'Blue Team API Key')}
                />
              </div>
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* SSH Access */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <Terminal className="w-6 h-6 text-primary" />
              SSH ACCESS
            </h2>
            <div className="bg-card border-2 border-border p-6">
              <CredentialRow
                label="SSH COMMAND"
                value={CREDENTIALS.sshCommand}
                onCopy={() => copyToClipboard(CREDENTIALS.sshCommand, 'SSH Command')}
                mono
              />
              <p className="mt-4 text-sm text-muted-foreground">
                Note: SSH key is stored at <code className="bg-secondary px-2 py-1">~/.ssh/caldera_do_key</code>
              </p>
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* Server URLs */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <ExternalLink className="w-6 h-6 text-primary" />
              SERVER URLS
            </h2>
            <div className="bg-card border-2 border-border p-6 space-y-4">
              <CredentialRow
                label="HTTPS URL"
                value={CREDENTIALS.serverUrl}
                onCopy={() => copyToClipboard(CREDENTIALS.serverUrl, 'HTTPS URL')}
                mono
              />
              <CredentialRow
                label="HTTP URL"
                value={CREDENTIALS.httpUrl}
                onCopy={() => copyToClipboard(CREDENTIALS.httpUrl, 'HTTP URL')}
                mono
              />
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

function CredentialRow({ 
  label, 
  value, 
  isSecret, 
  show, 
  onToggle, 
  onCopy,
  mono 
}: { 
  label: string; 
  value: string; 
  isSecret?: boolean; 
  show?: boolean; 
  onToggle?: () => void; 
  onCopy: () => void;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col md:flex-row md:items-center gap-2 md:gap-4">
      <span className="text-xs tracking-widest text-muted-foreground w-32 shrink-0">{label}</span>
      <div className="flex-1 flex items-center gap-2 bg-secondary px-4 py-3">
        <code className={`flex-1 text-sm ${mono ? 'font-mono' : ''} ${isSecret && !show ? 'tracking-widest' : ''}`}>
          {isSecret && !show ? '••••••••••••••••' : value}
        </code>
        {isSecret && onToggle && (
          <button onClick={onToggle} className="text-muted-foreground hover:text-white transition-colors">
            {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        )}
        <button onClick={onCopy} className="text-muted-foreground hover:text-primary transition-colors">
          <Copy className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
