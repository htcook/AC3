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
  Cpu,
  Briefcase,
} from "lucide-react";
import { useState, useEffect } from "react";

import AppShell from "@/components/AppShell";
// Team members - populated from user management API
const TEAM_MEMBERS: { id: number; name: string; email: string; role: string; lastSignedIn: string }[] = [];

const ROLE_INFO = {
  admin: { icon: Crown, label: 'Administrator', description: 'Full access to all features including credential management and team administration', color: 'text-primary' },
  user: { icon: User, label: 'User', description: 'Can view credentials, run operations, and access adversary profiles', color: 'text-blue-500' },
  viewer: { icon: Eye, label: 'Viewer', description: 'Read-only access to dashboard and statistics', color: 'text-muted-foreground' },
};

export default function Team() {
  const [, navigate] = useLocation();

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
    <AppShell activePath="/team">
{/* Sidebar */}
<header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4 flex items-center justify-between">
            <div>
              <h1 className="font-display text-3xl md:text-2xl sm:text-3xl lg:text-4xl">TEAM</h1>
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
                      <span className="font-display">{(info.label || '').toUpperCase()}</span>
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
    </AppShell>
  );
}

