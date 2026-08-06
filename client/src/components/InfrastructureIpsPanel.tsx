/**
 * InfrastructureIpsPanel — Client Whitelisting Panel
 *
 * Displays all platform infrastructure IPs that clients need to whitelist
 * in their firewalls before a pentest/red team engagement begins.
 * Supports copy-to-clipboard for easy sharing.
 */
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import {
  Server, Copy, RefreshCw, CheckCircle2, XCircle, Loader2,
  Shield, Globe, Network, Radio, Scan, AlertTriangle, Clock,
} from "lucide-react";

interface InfraIp {
  role: string;
  ip: string;
  port: number | string;
  protocol: string;
  description: string;
  healthy: boolean | null;
  source: string;
}

export function InfrastructureIpsPanel({ engagementId }: { engagementId?: number }) {
  const [copied, setCopied] = useState(false);

  const platformIpsQ = trpc.liveInfra.platformIps.useQuery(undefined, {
    staleTime: 60_000,
    refetchInterval: 5 * 60_000, // Auto-refresh every 5 min
  });

  const scanInfoQ = trpc.liveInfra.scanServerInfo.useQuery(undefined, {
    staleTime: 60_000,
  });

  const rediscoverMutation = trpc.liveInfra.forceRediscoverScanServer.useMutation({
    onSuccess: (data) => {
      toast.success(`Scan server rediscovered: ${data.ip}`);
      platformIpsQ.refetch();
      scanInfoQ.refetch();
    },
    onError: (err) => toast.error(`Rediscovery failed: ${err.message}`),
  });

  const ips = platformIpsQ.data || [];

  const copyAllIps = () => {
    const lines = ips.map(
      (ip) => `${ip.role}: ${ip.ip}:${ip.port} (${ip.protocol})`
    );
    const header = engagementId
      ? `# AC3 Platform Source IPs — Engagement #${engagementId}`
      : "# AC3 Platform Source IPs";
    const text = [
      header,
      `# Generated: ${new Date().toISOString()}`,
      "",
      "Please whitelist the following IPs in your firewall/IDS/WAF:",
      "",
      ...lines,
      "",
      "# All traffic from these IPs is authorized testing activity.",
    ].join("\n");

    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      toast.success("Infrastructure IPs copied to clipboard");
      setTimeout(() => setCopied(false), 3000);
    });
  };

  const copyIpOnly = (ip: string) => {
    navigator.clipboard.writeText(ip).then(() => {
      toast.success(`Copied: ${ip}`);
    });
  };

  const getRoleIcon = (role: string) => {
    if (role.includes("Scan")) return <Scan className="h-4 w-4" />;
    if (role.includes("Metasploit") || role.includes("C2") || role.includes("Caldera")) return <Radio className="h-4 w-4" />;
    if (role.includes("Phishing") || role.includes("GoPhish") || role.includes("Evilginx")) return <Shield className="h-4 w-4" />;
    if (role.includes("ZAP")) return <Globe className="h-4 w-4" />;
    if (role.includes("Platform") || role.includes("ECS")) return <Server className="h-4 w-4" />;
    return <Network className="h-4 w-4" />;
  };

  const getHealthBadge = (healthy: boolean | null) => {
    if (healthy === null) return <Badge variant="outline" className="text-xs text-muted-foreground"><Clock className="h-3 w-3 mr-1" />Unknown</Badge>;
    if (healthy) return <Badge className="text-xs bg-emerald-500/20 text-emerald-400 border-emerald-500/30"><CheckCircle2 className="h-3 w-3 mr-1" />Healthy</Badge>;
    return <Badge className="text-xs bg-red-500/20 text-red-400 border-red-500/30"><XCircle className="h-3 w-3 mr-1" />Unhealthy</Badge>;
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Server className="h-5 w-5 text-blue-400" />
            Infrastructure Source IPs
          </h3>
          <p className="text-sm text-muted-foreground mt-1">
            Share these IPs with clients for firewall whitelisting before engagement begins.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => rediscoverMutation.mutate()}
            disabled={rediscoverMutation.isPending}
          >
            {rediscoverMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1" />
            ) : (
              <RefreshCw className="h-4 w-4 mr-1" />
            )}
            Rediscover
          </Button>
          <Button
            size="sm"
            onClick={copyAllIps}
            disabled={ips.length === 0}
          >
            {copied ? (
              <CheckCircle2 className="h-4 w-4 mr-1" />
            ) : (
              <Copy className="h-4 w-4 mr-1" />
            )}
            {copied ? "Copied!" : "Copy All"}
          </Button>
        </div>
      </div>

      {/* Scan Server Discovery Status */}
      {scanInfoQ.data && (
        <Card className="border-blue-500/20 bg-blue-500/5">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded bg-blue-500/10">
                  <Scan className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-sm font-medium">
                    ScanForge Auto-Discovery: <span className="text-blue-400">{scanInfoQ.data.ip || "Not discovered"}</span>
                  </p>
                  <p className="text-xs text-muted-foreground">
                    Source: {scanInfoQ.data.source === "ec2-discovery" ? "EC2 DescribeInstances" : "Static ENV fallback"}
                    {scanInfoQ.data.instanceName && ` • Instance: ${scanInfoQ.data.instanceName}`}
                    {scanInfoQ.data.lastDiscovered > 0 && ` • Last discovered: ${new Date(scanInfoQ.data.lastDiscovered).toLocaleTimeString()}`}
                  </p>
                </div>
              </div>
              {getHealthBadge(scanInfoQ.data.healthy)}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Loading State */}
      {platformIpsQ.isLoading && (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          <span className="ml-2 text-sm text-muted-foreground">Discovering infrastructure IPs...</span>
        </div>
      )}

      {/* IP List */}
      {ips.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">
              Whitelist Requirements ({ips.length} source{ips.length !== 1 ? "s" : ""})
            </CardTitle>
            <CardDescription>
              All traffic from these IPs during the engagement window is authorized testing activity.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border">
              {ips.map((ip, idx) => (
                <div key={idx} className="flex items-center justify-between px-4 py-3 hover:bg-muted/50 transition-colors">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="text-muted-foreground flex-shrink-0">
                      {getRoleIcon(ip.role)}
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium truncate">{ip.role}</span>
                        <Badge variant="outline" className="text-xs flex-shrink-0">{ip.protocol}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground truncate">{ip.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0 ml-4">
                    {getHealthBadge(ip.healthy)}
                    <code className="text-sm font-mono bg-muted px-2 py-1 rounded">
                      {ip.ip}:{ip.port}
                    </code>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0"
                      onClick={() => copyIpOnly(ip.ip)}
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Empty State */}
      {!platformIpsQ.isLoading && ips.length === 0 && (
        <Card className="border-dashed">
          <CardContent className="p-8 text-center">
            <AlertTriangle className="h-8 w-8 text-amber-400 mx-auto mb-3" />
            <p className="text-sm font-medium">No Infrastructure IPs Configured</p>
            <p className="text-xs text-muted-foreground mt-1">
              Configure SCAN_SERVER_HOST, MSF_RPC_HOST, or CALDERA_BASE_URL environment variables
              to populate this panel.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Client Instructions */}
      <Card className="border-amber-500/20 bg-amber-500/5">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-400 flex-shrink-0 mt-0.5" />
            <div className="text-sm">
              <p className="font-medium text-amber-400">Client Instructions</p>
              <p className="text-muted-foreground mt-1">
                Provide these IPs to the client's SOC/IT team before the engagement begins.
                They should whitelist these in their firewall, IDS/IPS, and WAF to prevent
                blocking of authorized testing traffic. IPs are auto-discovered and may change
                if infrastructure is restarted.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export default InfrastructureIpsPanel;
