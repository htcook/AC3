import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
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
  Clock,
  Server,
  UserCheck,
  Settings,
  AlertTriangle,
  CheckCircle,
  Zap,
  Cpu,
  Briefcase,
} from "lucide-react";
import { useState, useEffect } from "react";

import AppShell from "@/components/AppShell";
// Activity logs - populated from real platform events
const ACTIVITY_LOGS: { id: number; action: string; user: string; details: string; timestamp: string; type: string }[] = [];

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
  const [, navigate] = useLocation();
  const [filter, setFilter] = useState<string | null>(null);

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

  return (
    <AppShell activePath="/activity">
{/* Sidebar */}
<header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4">
            <h1 className="font-display text-3xl md:text-2xl sm:text-3xl lg:text-4xl">ACTIVITY LOG</h1>
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
    </AppShell>
  );
}

