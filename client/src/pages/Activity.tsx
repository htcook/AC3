import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
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
  Clock,
  Server,
  UserCheck,
  Settings,
  AlertTriangle,
  CheckCircle
} from "lucide-react";
import { useState, useEffect } from "react";

// Sample activity data - in production this would come from the API
const ACTIVITY_LOGS = [
  { id: 1, action: 'server_health_check', user: 'System', details: 'Automated health check completed - Server online', timestamp: '2026-01-22T11:00:00Z', type: 'success' },
  { id: 2, action: 'user_login', user: 'Admin User', details: 'User logged in from 192.168.1.100', timestamp: '2026-01-22T10:30:00Z', type: 'info' },
  { id: 3, action: 'credential_viewed', user: 'Admin User', details: 'Viewed Red Team API Key', timestamp: '2026-01-22T10:25:00Z', type: 'info' },
  { id: 4, action: 'adversary_accessed', user: 'Red Team Lead', details: 'Accessed APT29_VCD_Cloud_Compromise_Enhanced', timestamp: '2026-01-21T14:45:00Z', type: 'info' },
  { id: 5, action: 'server_created', user: 'Admin User', details: 'Created server: Caldera Production', timestamp: '2026-01-21T09:00:00Z', type: 'success' },
  { id: 6, action: 'credential_created', user: 'Admin User', details: 'Added admin_login credential', timestamp: '2026-01-21T09:05:00Z', type: 'success' },
  { id: 7, action: 'role_updated', user: 'Admin User', details: 'Updated user 2 role to user', timestamp: '2026-01-20T16:30:00Z', type: 'warning' },
  { id: 8, action: 'server_health_check', user: 'System', details: 'Automated health check completed - Server online', timestamp: '2026-01-20T11:00:00Z', type: 'success' },
  { id: 9, action: 'user_login', user: 'Security Analyst', details: 'User logged in from 10.0.0.50', timestamp: '2026-01-20T09:15:00Z', type: 'info' },
  { id: 10, action: 'adversary_accessed', user: 'Security Analyst', details: 'Accessed Lazarus Group profile', timestamp: '2026-01-20T09:20:00Z', type: 'info' },
];

const ACTION_ICONS: Record<string, React.ReactNode> = {
  server_health_check: <Server className="w-4 h-4" />,
  user_login: <UserCheck className="w-4 h-4" />,
  credential_viewed: <Key className="w-4 h-4" />,
  credential_created: <Key className="w-4 h-4" />,
  adversary_accessed: <Target className="w-4 h-4" />,
  server_created: <Server className="w-4 h-4" />,
  role_updated: <Settings className="w-4 h-4" />,
};

const TYPE_STYLES: Record<string, { bg: string; icon: React.ReactNode }> = {
  success: { bg: 'bg-green-500/20 border-green-500/50', icon: <CheckCircle className="w-4 h-4 text-green-500" /> },
  warning: { bg: 'bg-yellow-500/20 border-yellow-500/50', icon: <AlertTriangle className="w-4 h-4 text-yellow-500" /> },
  info: { bg: 'bg-blue-500/20 border-blue-500/50', icon: <Activity className="w-4 h-4 text-blue-500" /> },
  error: { bg: 'bg-red-500/20 border-red-500/50', icon: <AlertTriangle className="w-4 h-4 text-red-500" /> },
};

export default function ActivityPage() {
  const { user, logout, isAuthenticated, loading: authLoading } = useAuth();
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [filter, setFilter] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate('/');
    }
  }, [authLoading, isAuthenticated, navigate]);

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  const formatFullDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const filteredLogs = filter
    ? ACTIVITY_LOGS.filter(log => log.type === filter)
    : ACTIVITY_LOGS;

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
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" />
            <NavItem href="/team" icon={<Users />} label="TEAM" />
            <NavItem href="/activity" icon={<FileText />} label="ACTIVITY" active />
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
            <h1 className="font-display text-3xl md:text-4xl">ACTIVITY LOG</h1>
            <p className="text-sm text-muted-foreground">Audit trail and system events</p>
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">
          {/* Filter Buttons */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setFilter(null)}
              className={`px-3 py-2 text-xs font-display tracking-wider border-2 transition-colors ${!filter ? 'bg-primary border-primary' : 'border-border hover:border-primary'}`}
            >
              ALL
            </button>
            <button
              onClick={() => setFilter(filter === 'success' ? null : 'success')}
              className={`px-3 py-2 text-xs font-display tracking-wider border-2 transition-colors ${filter === 'success' ? 'bg-green-500/20 border-green-500' : 'border-border hover:border-green-500'}`}
            >
              SUCCESS
            </button>
            <button
              onClick={() => setFilter(filter === 'info' ? null : 'info')}
              className={`px-3 py-2 text-xs font-display tracking-wider border-2 transition-colors ${filter === 'info' ? 'bg-blue-500/20 border-blue-500' : 'border-border hover:border-blue-500'}`}
            >
              INFO
            </button>
            <button
              onClick={() => setFilter(filter === 'warning' ? null : 'warning')}
              className={`px-3 py-2 text-xs font-display tracking-wider border-2 transition-colors ${filter === 'warning' ? 'bg-yellow-500/20 border-yellow-500' : 'border-border hover:border-yellow-500'}`}
            >
              WARNING
            </button>
          </div>

          {/* Activity Timeline */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <Clock className="w-6 h-6 text-primary" />
              RECENT ACTIVITY ({filteredLogs.length})
            </h2>
            <div className="space-y-4">
              {filteredLogs.map((log) => {
                const typeStyle = TYPE_STYLES[log.type] || TYPE_STYLES.info;
                const actionIcon = ACTION_ICONS[log.action] || <Activity className="w-4 h-4" />;
                
                return (
                  <div 
                    key={log.id} 
                    className={`bg-card border-2 ${typeStyle.bg} p-4 flex items-start gap-4`}
                  >
                    <div className="flex-shrink-0 w-10 h-10 bg-secondary flex items-center justify-center">
                      {actionIcon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        {typeStyle.icon}
                        <span className="font-display text-sm">
                          {log.action.replace(/_/g, ' ').toUpperCase()}
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground mb-2">{log.details}</p>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Users className="w-3 h-3" />
                          {log.user}
                        </span>
                        <span className="flex items-center gap-1" title={formatFullDate(log.timestamp)}>
                          <Clock className="w-3 h-3" />
                          {formatDate(log.timestamp)}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {filteredLogs.length === 0 && (
            <div className="text-center py-12">
              <FileText className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">No activity logs found</p>
            </div>
          )}
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
