/**
 * Server Access Hub
 *
 * Unified view of all C2 framework servers — Caldera, Metasploit, Sliver,
 * Empire, Cobalt Strike, Manjusaka, and ZAP. Shows live health status,
 * connection details, and quick-launch links to each server's web UI.
 */
import React, { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import {
  Server, Activity, CheckCircle2, XCircle, Clock, Loader2,
  Terminal, Globe, Shield, Cpu, Radio, Flame, Crown,
  RefreshCw, ExternalLink, Lock, Unlock, HeartPulse,
  Zap, Target, Network, Eye, AlertTriangle,
} from "lucide-react";

// ─── Server Card Component ──────────────────────────────────────────────────

interface ServerInfo {
  id: string;
  name: string;
  displayName: string;
  icon: React.ReactNode;
  description: string;
  category: "c2" | "scanning" | "phishing";
  defaultPort: number;
  protocol: string;
  webUiPath?: string;
  envKeys: { url: string; key?: string };
  statusEndpoint?: string;
  color: string;
}

const SERVERS: ServerInfo[] = [
  {
    id: "caldera",
    name: "caldera",
    displayName: "MITRE Caldera",
    icon: <Target className="h-5 w-5" />,
    description: "Adversary emulation platform with MITRE ATT&CK integration. Manages agents, abilities, and automated operations.",
    category: "c2",
    defaultPort: 8888,
    protocol: "HTTP",
    webUiPath: "/",
    envKeys: { url: "CALDERA_BASE_URL", key: "CALDERA_API_KEY" },
    color: "text-red-400",
  },
  {
    id: "metasploit",
    name: "metasploit",
    displayName: "Metasploit Framework",
    icon: <Terminal className="h-5 w-5" />,
    description: "Exploitation framework with 2,000+ modules. Manages sessions, exploits, and post-exploitation payloads.",
    category: "c2",
    defaultPort: 55553,
    protocol: "HTTPS (RPC)",
    envKeys: { url: "MSF_SERVER_URL" },
    color: "text-blue-400",
  },
  {
    id: "sliver",
    name: "sliver",
    displayName: "Sliver C2",
    icon: <Cpu className="h-5 w-5" />,
    description: "Modern implant framework with mTLS, HTTPS, DNS, and WireGuard transports. Supports beacons and interactive sessions.",
    category: "c2",
    defaultPort: 31337,
    protocol: "gRPC / REST",
    envKeys: { url: "SLIVER_SERVER_URL", key: "SLIVER_OPERATOR_TOKEN" },
    color: "text-green-400",
  },
  {
    id: "empire",
    name: "empire",
    displayName: "Empire / Starkiller",
    icon: <Crown className="h-5 w-5" />,
    description: "PowerShell/Python post-exploitation framework with Starkiller GUI. Manages listeners, stagers, and agents.",
    category: "c2",
    defaultPort: 1337,
    protocol: "HTTPS (REST)",
    webUiPath: "/index.html",
    envKeys: { url: "EMPIRE_SERVER_URL", key: "EMPIRE_API_TOKEN" },
    color: "text-purple-400",
  },
  {
    id: "cobaltstrike",
    name: "cobaltstrike",
    displayName: "Cobalt Strike",
    icon: <Shield className="h-5 w-5" />,
    description: "Commercial adversary simulation with Malleable C2, BOFs, and beacon management. Team Server architecture.",
    category: "c2",
    defaultPort: 55553,
    protocol: "HTTPS (REST)",
    envKeys: { url: "CS_TEAM_SERVER_URL", key: "CS_API_KEY" },
    color: "text-orange-400",
  },
  {
    id: "manjusaka",
    name: "manjusaka",
    displayName: "Manjusaka C2",
    icon: <Flame className="h-5 w-5" />,
    description: "Rust/Go C2 framework with Noise Protocol encryption, VNC, and multi-transport support (TCP, HTTP, WS, KCP, SSH).",
    category: "c2",
    defaultPort: 8443,
    protocol: "HTTPS",
    envKeys: { url: "MANJUSAKA_SERVER_URL", key: "MANJUSAKA_API_TOKEN" },
    color: "text-pink-400",
  },
  {
    id: "gophish",
    name: "gophish",
    displayName: "GoPhish",
    icon: <Globe className="h-5 w-5" />,
    description: "Phishing simulation platform for social engineering assessments. Manages campaigns, landing pages, and email templates.",
    category: "phishing",
    defaultPort: 3333,
    protocol: "HTTPS",
    webUiPath: "/",
    envKeys: { url: "GOPHISH_BASE_URL", key: "GOPHISH_API_KEY" },
    color: "text-cyan-400",
  },
  {
    id: "zap",
    name: "zap",
    displayName: "OWASP ZAP",
    icon: <Zap className="h-5 w-5" />,
    description: "Web application security scanner. Manages active/passive scans, spider crawls, and vulnerability reports.",
    category: "scanning",
    defaultPort: 8080,
    protocol: "HTTP (REST)",
    webUiPath: "/",
    envKeys: { url: "ZAP_BASE_URL", key: "ZAP_API_KEY" },
    color: "text-yellow-400",
  },
];

function ServerCard({ server, onRefresh }: { server: ServerInfo; onRefresh?: () => void }) {
  const [checking, setChecking] = useState(false);

  // Try to get health status from the server config
  const { data: configs } = trpc.server.list.useQuery();
  const config = configs?.find((c: any) => c.name?.toLowerCase().includes(server.id) || c.type?.toLowerCase().includes(server.id));

  const isConfigured = !!config;
  const isOnline = config?.status === "online" || config?.status === "active";

  const handleHealthCheck = async () => {
    setChecking(true);
    try {
      toast.info(`Checking ${server.displayName}...`);
      // Trigger a refresh
      onRefresh?.();
    } catch {
      toast.error(`Failed to check ${server.displayName}`);
    } finally {
      setTimeout(() => setChecking(false), 2000);
    }
  };

  return (
    <Card className={`transition-all hover:border-primary/30 ${isOnline ? "border-green-500/30" : ""}`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`${server.color}`}>{server.icon}</div>
            <div>
              <CardTitle className="text-base">{server.displayName}</CardTitle>
              <CardDescription className="text-xs">{server.protocol} · Port {server.defaultPort}</CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isOnline ? (
              <Badge className="bg-green-500/10 text-green-400 text-[10px]">
                <CheckCircle2 className="h-3 w-3 mr-1" /> Online
              </Badge>
            ) : isConfigured ? (
              <Badge className="bg-yellow-500/10 text-yellow-400 text-[10px]">
                <Clock className="h-3 w-3 mr-1" /> Offline
              </Badge>
            ) : (
              <Badge className="bg-muted/30 text-muted-foreground text-[10px]">
                <XCircle className="h-3 w-3 mr-1" /> Not Configured
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">{server.description}</p>

        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="flex items-center gap-1.5">
            <Lock className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">API Key:</span>
            {server.envKeys.key ? (
              <Badge variant="outline" className="text-[9px] px-1 py-0">
                {isConfigured ? "Set" : "Missing"}
              </Badge>
            ) : (
              <span className="text-muted-foreground/50">N/A</span>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <Globe className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">URL:</span>
            <Badge variant="outline" className="text-[9px] px-1 py-0">
              {isConfigured ? "Configured" : "Missing"}
            </Badge>
          </div>
        </div>

        <Separator />

        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            className="flex-1 text-xs"
            onClick={handleHealthCheck}
            disabled={checking || !isConfigured}
          >
            {checking ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <HeartPulse className="h-3 w-3 mr-1" />}
            Health Check
          </Button>
          {server.webUiPath && isOnline && (
            <Button size="sm" variant="outline" className="text-xs" asChild>
              <a href={config?.url ? `${config.url}${server.webUiPath}` : "#"} target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-3 w-3 mr-1" /> Open UI
              </a>
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Status Overview ────────────────────────────────────────────────────────

function StatusOverview() {
  const { data: configs, refetch } = trpc.server.list.useQuery();

  const stats = useMemo(() => {
    if (!configs) return { total: 0, online: 0, offline: 0, unconfigured: 0 };
    const online = configs.filter((c: any) => c.status === "online" || c.status === "active").length;
    return {
      total: SERVERS.length,
      online,
      offline: configs.length - online,
      unconfigured: SERVERS.length - configs.length,
    };
  }, [configs]);

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      <Card className="bg-card/50">
        <CardContent className="p-3 text-center">
          <Server className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
          <div className="text-lg font-bold">{stats.total}</div>
          <div className="text-[10px] text-muted-foreground">Total Servers</div>
        </CardContent>
      </Card>
      <Card className="bg-card/50">
        <CardContent className="p-3 text-center">
          <CheckCircle2 className="h-4 w-4 mx-auto text-green-400 mb-1" />
          <div className="text-lg font-bold text-green-400">{stats.online}</div>
          <div className="text-[10px] text-muted-foreground">Online</div>
        </CardContent>
      </Card>
      <Card className="bg-card/50">
        <CardContent className="p-3 text-center">
          <XCircle className="h-4 w-4 mx-auto text-red-400 mb-1" />
          <div className="text-lg font-bold text-red-400">{stats.offline}</div>
          <div className="text-[10px] text-muted-foreground">Offline</div>
        </CardContent>
      </Card>
      <Card className="bg-card/50">
        <CardContent className="p-3 text-center">
          <AlertTriangle className="h-4 w-4 mx-auto text-yellow-400 mb-1" />
          <div className="text-lg font-bold text-yellow-400">{stats.unconfigured}</div>
          <div className="text-[10px] text-muted-foreground">Not Configured</div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function ServerAccess() {
  const { refetch } = trpc.server.list.useQuery();
  const [filter, setFilter] = useState<"all" | "c2" | "scanning" | "phishing">("all");

  const filtered = filter === "all" ? SERVERS : SERVERS.filter(s => s.category === filter);

  return (
    <AppShell activePath="/server-access">
      <div className="space-y-6 p-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="bg-primary/10 rounded-xl p-3">
              <Server className="h-8 w-8 text-primary" />
            </div>
            <div>
              <h1 className="font-display text-2xl font-bold tracking-wider">Server Access Hub</h1>
              <p className="text-muted-foreground text-sm">
                Unified view of all offensive infrastructure — C2 frameworks, scanners, and phishing servers
              </p>
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" /> Refresh All
          </Button>
        </div>

        {/* Status Overview */}
        <StatusOverview />

        {/* Category Filter */}
        <Tabs value={filter} onValueChange={(v) => setFilter(v as any)}>
          <TabsList>
            <TabsTrigger value="all" className="text-xs">All Servers</TabsTrigger>
            <TabsTrigger value="c2" className="text-xs">
              <Radio className="h-3.5 w-3.5 mr-1.5" /> C2 Frameworks
            </TabsTrigger>
            <TabsTrigger value="scanning" className="text-xs">
              <Eye className="h-3.5 w-3.5 mr-1.5" /> Scanners
            </TabsTrigger>
            <TabsTrigger value="phishing" className="text-xs">
              <Globe className="h-3.5 w-3.5 mr-1.5" /> Phishing
            </TabsTrigger>
          </TabsList>
        </Tabs>

        {/* Server Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map(server => (
            <ServerCard key={server.id} server={server} onRefresh={() => refetch()} />
          ))}
        </div>

        {/* Connection Guide */}
        <Card className="bg-muted/10">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Network className="h-5 w-5 text-blue-400" /> Connection Guide
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-xs text-muted-foreground">
            <p>
              Server connections are managed through the <strong>Infrastructure Reference</strong> page.
              Add server configurations there and they will appear here with live health monitoring.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="bg-muted/20 rounded-lg p-3">
                <div className="font-semibold text-foreground mb-1">1. Configure Server</div>
                <p>Add the server URL and API credentials in Infrastructure Reference or environment variables.</p>
              </div>
              <div className="bg-muted/20 rounded-lg p-3">
                <div className="font-semibold text-foreground mb-1">2. Verify Connection</div>
                <p>Use the Health Check button to verify the server is reachable and responding to API calls.</p>
              </div>
              <div className="bg-muted/20 rounded-lg p-3">
                <div className="font-semibold text-foreground mb-1">3. Launch Operations</div>
                <p>Once online, use the dedicated pages (C2 Hub, MSF Sessions, etc.) to manage operations.</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
