import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Server, Users, Shield, ArrowRight, Activity, Database,
  AlertTriangle, CheckCircle2, Settings, HardDrive, Cpu, Wifi
} from "lucide-react";

function HealthIndicator({ label, status, detail }: { label: string; status: "healthy" | "warning" | "error"; detail: string }) {
  const colors = { healthy: "bg-emerald-500", warning: "bg-amber-500", error: "bg-red-500" };
  return (
    <div className="flex items-center gap-3 p-3 bg-secondary/30 rounded-lg">
      <div className={`w-3 h-3 rounded-full ${colors[status]} shrink-0`} />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-display tracking-wider">{label}</p>
        <p className="text-[10px] text-muted-foreground">{detail}</p>
      </div>
      <span className={`text-[9px] font-display tracking-widest px-2 py-0.5 rounded-full ${
        status === "healthy" ? "bg-emerald-500/20 text-emerald-400" :
        status === "warning" ? "bg-amber-500/20 text-amber-400" : "bg-red-500/20 text-red-400"
      }`}>{status.toUpperCase()}</span>
    </div>
  );
}

export default function AdminHome() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display tracking-wider font-bold">ADMIN DASHBOARD</h1>
        <p className="text-sm text-muted-foreground mt-1">System health, user management, and platform configuration</p>
      </div>

      {/* System Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "TOTAL USERS", value: "24", icon: Users, color: "bg-blue-500/80" },
          { label: "ACTIVE SERVERS", value: "5", icon: Server, color: "bg-emerald-500/80" },
          { label: "API CALLS TODAY", value: "12.4K", icon: Activity, color: "bg-purple-500/80" },
          { label: "SYSTEM ALERTS", value: "2", icon: AlertTriangle, color: "bg-amber-500/80" },
        ].map((stat) => (
          <Card key={stat.label}>
            <CardContent className="p-4">
              <div className={`w-8 h-8 rounded ${stat.color} flex items-center justify-center mb-2`}>
                <stat.icon className="w-4 h-4 text-white" />
              </div>
              <p className="text-2xl font-display font-bold">{stat.value}</p>
              <p className="text-[10px] font-display tracking-widest text-muted-foreground mt-1">{stat.label}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* System Health + User Management */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-400" /> SYSTEM HEALTH
              </CardTitle>
              <Link href="/error-dashboard">
                <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                  DETAILS <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            <HealthIndicator label="Caldera C2 Server" status="healthy" detail="v4.2.0 — 3 active agents" />
            <HealthIndicator label="Database" status="healthy" detail="TiDB — 2.1GB used, 98.7% uptime" />
            <HealthIndicator label="GoPhish Server" status="healthy" detail="v0.12.1 — 2 active campaigns" />
            <HealthIndicator label="ZAP Proxy" status="warning" detail="High memory usage (87%)" />
            <HealthIndicator label="Nuclei Engine" status="healthy" detail="v3.1.0 — 8,400 templates loaded" />
            <HealthIndicator label="SOCKS Proxy Chain" status="healthy" detail="3 active tunnels" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Users className="w-4 h-4 text-blue-400" /> USER MANAGEMENT
              </CardTitle>
              <Link href="/team">
                <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                  MANAGE <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-3 gap-3 mb-3">
              {[
                { role: "Operators", count: 8, color: "text-red-400" },
                { role: "Analysts", count: 6, color: "text-purple-400" },
                { role: "Executives", count: 4, color: "text-amber-400" },
              ].map((r) => (
                <div key={r.role} className="text-center p-2 bg-secondary/30 rounded">
                  <p className={`text-lg font-display font-bold ${r.color}`}>{r.count}</p>
                  <p className="text-[9px] font-display tracking-widest text-muted-foreground">{r.role.toUpperCase()}</p>
                </div>
              ))}
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-display tracking-widest text-muted-foreground">RECENT LOGINS</p>
              {[
                { name: "John Doe", role: "operator", time: "2 min ago", status: "online" },
                { name: "Sarah Kim", role: "analyst", time: "15 min ago", status: "online" },
                { name: "Mike Ross", role: "operator", time: "1 hr ago", status: "idle" },
                { name: "CEO", role: "executive", time: "3 hrs ago", status: "offline" },
              ].map((user) => (
                <div key={user.name} className="flex items-center gap-3 p-2 rounded hover:bg-secondary/30 transition-colors">
                  <div className={`w-2 h-2 rounded-full ${
                    user.status === "online" ? "bg-emerald-500" : user.status === "idle" ? "bg-amber-500" : "bg-gray-500"
                  }`} />
                  <span className="text-xs flex-1">{user.name}</span>
                  <span className="text-[9px] font-display tracking-widest text-muted-foreground">{user.role}</span>
                  <span className="text-[10px] text-muted-foreground">{user.time}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Admin Actions */}
      <div>
        <h2 className="text-sm font-display tracking-widest text-muted-foreground mb-3">ADMIN TOOLS</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {[
            { href: "/servers", icon: Server, label: "SERVER MANAGEMENT", desc: "Configure C2, proxy, and scanner servers", color: "bg-blue-500/80" },
            { href: "/team", icon: Users, label: "USER & ROLES", desc: "Manage users, roles, and permissions", color: "bg-purple-500/80" },
            { href: "/audit-log", icon: Shield, label: "AUDIT LOG", desc: "Review all platform activity", color: "bg-amber-500/80" },
            { href: "/vendor-integrations", icon: Wifi, label: "INTEGRATIONS", desc: "API keys, webhooks, and connectors", color: "bg-emerald-500/80" },
            { href: "/error-dashboard", icon: AlertTriangle, label: "ERROR DASHBOARD", desc: "System errors and diagnostics", color: "bg-red-500/80" },
            { href: "/tenants", icon: Database, label: "TENANTS", desc: "Multi-tenant configuration", color: "bg-cyan-500/80" },
          ].map((tool) => (
            <Link key={tool.href} href={tool.href}>
              <Card className="group cursor-pointer hover:border-primary/30 transition-all duration-200 hover:shadow-lg hover:shadow-primary/5">
                <CardContent className="p-4 flex items-center gap-4">
                  <div className={`w-10 h-10 rounded-lg ${tool.color} flex items-center justify-center shrink-0`}>
                    <tool.icon className="w-5 h-5 text-white" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-display tracking-wider font-medium">{tool.label}</p>
                    <p className="text-xs text-muted-foreground">{tool.desc}</p>
                  </div>
                  <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors shrink-0" />
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
