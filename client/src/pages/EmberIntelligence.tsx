import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Brain, ChevronLeft, RefreshCw, Network, Key, Shield,
  Globe, Server, Eye, AlertTriangle, Clock, Flame
} from "lucide-react";
import { Link } from "wouter";

const INTEL_TYPE_COLORS: Record<string, string> = {
  network_map: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  credential: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  vulnerability: "bg-red-500/20 text-red-400 border-red-500/30",
  service_discovery: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  file_discovery: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  process_list: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  security_product: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  lateral_path: "bg-violet-500/20 text-violet-400 border-violet-500/30",
};

const INTEL_TYPE_ICONS: Record<string, React.ReactNode> = {
  network_map: <Network className="w-4 h-4" />,
  credential: <Key className="w-4 h-4" />,
  vulnerability: <AlertTriangle className="w-4 h-4" />,
  service_discovery: <Server className="w-4 h-4" />,
  file_discovery: <Eye className="w-4 h-4" />,
  process_list: <Globe className="w-4 h-4" />,
  security_product: <Shield className="w-4 h-4" />,
  lateral_path: <Network className="w-4 h-4" />,
};

export default function EmberIntelligence() {
  const [typeFilter, setTypeFilter] = useState("all");
  const dashboardQuery = trpc.ember.getDashboard.useQuery(undefined, { refetchInterval: 10000 });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link href="/ember">
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <ChevronLeft className="w-4 h-4" />
            </Button>
          </Link>
          <div className="p-2 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30">
            <Brain className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Intelligence Feed</h1>
            <p className="text-sm text-muted-foreground">Aggregated intelligence from all deployed agents</p>
          </div>
        </div>
        <Button variant="outline" size="icon" onClick={() => dashboardQuery.refetch()}>
          <RefreshCw className="w-4 h-4" />
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-cyan-400">{dashboardQuery.data?.totalIntel ?? 0}</p>
            <p className="text-xs text-muted-foreground">Total Intel Items</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-amber-400">0</p>
            <p className="text-xs text-muted-foreground">Credentials Found</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-red-400">0</p>
            <p className="text-xs text-muted-foreground">Vulnerabilities</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-blue-400">0</p>
            <p className="text-xs text-muted-foreground">Network Nodes</p>
          </CardContent>
        </Card>
      </div>

      {/* Intelligence Types */}
      <Card className="bg-card/50 border-border/50">
        <CardHeader>
          <CardTitle className="text-base">Intelligence Categories</CardTitle>
          <CardDescription>Types of intelligence automatically collected by Ember agents</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              { type: "network_map", name: "Network Mapping", desc: "Discovered hosts, subnets, routes, and network topology" },
              { type: "credential", name: "Credentials", desc: "Harvested credentials, tokens, API keys, and session data" },
              { type: "vulnerability", name: "Vulnerabilities", desc: "Identified vulnerabilities, misconfigurations, and weaknesses" },
              { type: "service_discovery", name: "Service Discovery", desc: "Running services, versions, and exposed ports" },
              { type: "file_discovery", name: "File Discovery", desc: "Sensitive files, configuration data, and documents" },
              { type: "process_list", name: "Process Intelligence", desc: "Running processes, loaded modules, and scheduled tasks" },
              { type: "security_product", name: "Security Products", desc: "Detected AV, EDR, SIEM agents, and security controls" },
              { type: "lateral_path", name: "Lateral Paths", desc: "Identified paths for lateral movement between hosts" },
            ].map((item) => (
              <Card key={item.type} className="bg-muted/20 border-border/30 hover:border-cyan-500/30 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <div className={`p-1.5 rounded-md ${INTEL_TYPE_COLORS[item.type]}`}>
                      {INTEL_TYPE_ICONS[item.type]}
                    </div>
                    <span className="text-sm font-medium text-foreground">{item.name}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{item.desc}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Empty State */}
      <Card className="bg-card/30 border-border/30">
        <CardContent className="p-12 text-center">
          <Brain className="w-16 h-16 text-cyan-400/20 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-foreground mb-2">Intelligence Feed Empty</h3>
          <p className="text-sm text-muted-foreground mb-4">
            Deploy agents and execute reconnaissance tasks to populate the intelligence feed.
            Agents automatically share discovered intelligence with the swarm.
          </p>
          <Link href="/ember/deploy">
            <Button className="bg-amber-600 hover:bg-amber-700 text-white">
              <Flame className="w-4 h-4 mr-2" /> Deploy Agent
            </Button>
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}
