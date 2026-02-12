import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
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
  UserPlus,
  Crown,
  Eye,
  User,
  Zap,
  Cpu
} from "lucide-react";
import { useState, useEffect } from "react";

// Sample team data - in production this would come from the API
const TEAM_MEMBERS = [
  { id: 1, name: 'Admin User', email: 'admin@example.com', role: 'admin', lastSignedIn: '2026-01-22T10:30:00Z' },
  { id: 2, name: 'Red Team Lead', email: 'redteam@example.com', role: 'user', lastSignedIn: '2026-01-21T14:45:00Z' },
  { id: 3, name: 'Security Analyst', email: 'analyst@example.com', role: 'viewer', lastSignedIn: '2026-01-20T09:15:00Z' },
];

const ROLE_INFO = {
  admin: { icon: Crown, label: 'Administrator', description: 'Full access to all features including credential management and team administration', color: 'text-primary' },
  user: { icon: User, label: 'User', description: 'Can view credentials, run operations, and access adversary profiles', color: 'text-blue-500' },
  viewer: { icon: Eye, label: 'Viewer', description: 'Read-only access to dashboard and statistics', color: 'text-muted-foreground' },
};

export default function Team() {
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const handleRoleChange = (userId: number, newRole: string) => {
    toast.info('Role management requires admin privileges');
  };

  const isAdmin = true; // Admin access for standalone deployment

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
                <span className="text-xs text-muted-foreground">Ace Strike</span>
              </div>
            </Link>
          </div>

          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity />} label="DASHBOARD" />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" />
            <NavItem href="/agents" icon={<Cpu />} label="AGENTS" />
            <NavItem href="/campaigns" icon={<Zap />} label="CAMPAIGNS" />
            <NavItem href="/team" icon={<Users />} label="TEAM" active />
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
          <div className="px-6 py-4 flex items-center justify-between">
            <div>
              <h1 className="font-display text-3xl md:text-4xl">TEAM</h1>
              <p className="text-sm text-muted-foreground">Manage team access and permissions</p>
            </div>
            {isAdmin && (
              <Button className="font-display tracking-wider bg-primary hover:bg-primary/90">
                <UserPlus className="w-4 h-4 mr-2" />
                INVITE
              </Button>
            )}
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">
          {/* Role Legend */}
          <section>
            <h2 className="font-display text-2xl mb-4">ACCESS LEVELS</h2>
            <div className="grid md:grid-cols-3 gap-4">
              {Object.entries(ROLE_INFO).map(([role, info]) => {
                const Icon = info.icon;
                return (
                  <div key={role} className="bg-card border-2 border-border p-4">
                    <div className="flex items-center gap-3 mb-2">
                      <Icon className={`w-5 h-5 ${info.color}`} />
                      <span className="font-display">{info.label.toUpperCase()}</span>
                    </div>
                    <p className="text-sm text-muted-foreground">{info.description}</p>
                  </div>
                );
              })}
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* Team Members */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <Users className="w-6 h-6 text-primary" />
              TEAM MEMBERS ({TEAM_MEMBERS.length})
            </h2>
            <div className="bg-card border-2 border-border overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border bg-secondary/50">
                      <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">USER</th>
                      <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">EMAIL</th>
                      <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">ROLE</th>
                      <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">LAST ACTIVE</th>
                      {isAdmin && <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">ACTIONS</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {TEAM_MEMBERS.map((member, index) => {
                      const roleInfo = ROLE_INFO[member.role as keyof typeof ROLE_INFO];
                      const RoleIcon = roleInfo.icon;
                      return (
                        <tr key={member.id} className={`border-b border-border/50 hover:bg-secondary/30 ${index % 2 === 0 ? '' : 'bg-secondary/10'}`}>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-3">
                              <div className="w-8 h-8 bg-secondary flex items-center justify-center">
                                <span className="font-display text-sm">{member.name[0]}</span>
                              </div>
                              <span className="font-medium">{member.name}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-muted-foreground">{member.email}</td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <RoleIcon className={`w-4 h-4 ${roleInfo.color}`} />
                              <span className="text-sm">{roleInfo.label}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-sm text-muted-foreground">{formatDate(member.lastSignedIn)}</td>
                          {isAdmin && (
                            <td className="px-4 py-3">
                              <select 
                                className="bg-secondary border border-border px-2 py-1 text-sm"
                                value={member.role}
                                onChange={(e) => handleRoleChange(member.id, e.target.value)}
                              >
                                <option value="admin">Admin</option>
                                <option value="user">User</option>
                                <option value="viewer">Viewer</option>
                              </select>
                            </td>
                          )}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </section>

          {!isAdmin && (
            <div className="bg-card border-2 border-border p-6 text-center">
              <Cloud className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">Contact an administrator to modify team permissions</p>
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
