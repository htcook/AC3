import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Server, Wifi, WifiOff, RefreshCw, Activity, HardDrive,
  MemoryStick, Clock, Wrench, CheckCircle2, XCircle, Zap,
  Terminal, Shield
} from "lucide-react";
import AppShell from "@/components/AppShell";

function parseDiskInfo(raw: string | null) {
  if (!raw) return null;
  const lines = raw.split("\n").filter(l => l.trim());
  if (lines.length < 2) return null;
  const parts = lines[1].split(/\s+/);
  return { filesystem: parts[0], size: parts[1], used: parts[2], avail: parts[3], usePercent: parts[4] };
}

function parseMemInfo(raw: string | null) {
  if (!raw) return null;
  const lines = raw.split("\n").filter(l => l.trim());
  const memLine = lines.find(l => l.startsWith("Mem:"));
  if (!memLine) return null;
  const parts = memLine.split(/\s+/);
  return { total: parts[1], used: parts[2], free: parts[3], shared: parts[4], buffCache: parts[5], available: parts[6] };
}

export default function ScanServerHealth() {
  const healthQ = trpc.scanServer.health.useQuery(undefined, { refetchInterval: 30000 });
  const toolVersionsQ = trpc.scanServer.toolVersions.useQuery(undefined, { enabled: healthQ.data?.status === "online" });
  const pingMut = trpc.scanServer.ping.useMutation();
  const [showRawDisk, setShowRawDisk] = useState(false);
  const [showRawMem, setShowRawMem] = useState(false);

  const health = healthQ.data;
  const disk = parseDiskInfo(health?.disk ?? null);
  const mem = parseMemInfo(health?.memory ?? null);

  const statusColor = health?.status === "online" ? "text-emerald-400" : health?.status === "offline" ? "text-red-400" : "text-yellow-400";
  const statusBg = health?.status === "online" ? "bg-emerald-500/10 border-emerald-500/30" : health?.status === "offline" ? "bg-red-500/10 border-red-500/30" : "bg-yellow-500/10 border-yellow-500/30";

  return (
    <AppShell activePath="/scan-server">
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Server className="h-7 w-7 text-cyan-400" />
            Scan Server Health
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Monitor your dedicated scan server — connection status, installed tools, and resource usage
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => pingMut.mutate()}
            disabled={pingMut.isPending || health?.status !== "online"}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
          >
            <Zap className="h-4 w-4 mr-1" />
            {pingMut.isPending ? "Pinging..." : "Ping"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => { healthQ.refetch(); toolVersionsQ.refetch(); }}
            disabled={healthQ.isRefetching}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
          >
            <RefreshCw className={`h-4 w-4 mr-1 ${healthQ.isRefetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Ping result */}
      {pingMut.data && (
        <div className={`rounded-lg border px-4 py-3 text-sm ${pingMut.data.success ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300" : "bg-red-500/10 border-red-500/30 text-red-300"}`}>
          {pingMut.data.success
            ? `Ping successful — ${pingMut.data.latencyMs}ms round trip`
            : `Ping failed — ${pingMut.data.output}`}
        </div>
      )}

      {/* Loading state */}
      {healthQ.isLoading && (
        <div className="flex items-center justify-center py-20">
          <RefreshCw className="h-8 w-8 animate-spin text-cyan-400" />
          <span className="ml-3 text-zinc-400">Connecting to scan server...</span>
        </div>
      )}

      {health && (
        <>
          {/* Status Banner */}
          <Card className={`border ${statusBg}`}>
            <CardContent className="py-4 flex items-center justify-between">
              <div className="flex items-center gap-4">
                {health.status === "online" ? (
                  <Wifi className={`h-8 w-8 ${statusColor}`} />
                ) : (
                  <WifiOff className={`h-8 w-8 ${statusColor}`} />
                )}
                <div>
                  <div className={`text-lg font-semibold ${statusColor}`}>
                    {health.status === "online" ? "Online" : health.status === "offline" ? "Offline" : "Unconfigured"}
                  </div>
                  <div className="text-sm text-zinc-400">
                    {health.host ? `Host: ${health.host}` : "No host configured"}
                  </div>
                </div>
              </div>
              {health.uptime && (
                <div className="text-right">
                  <div className="text-xs text-zinc-500 uppercase tracking-wider">Uptime</div>
                  <div className="text-sm text-zinc-300 font-mono">{health.uptime}</div>
                </div>
              )}
            </CardContent>
          </Card>

          {health.error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              <strong>Error:</strong> {health.error}
            </div>
          )}

          {/* Resource Usage */}
          {health.status === "online" && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Disk Usage */}
              <Card className="border-zinc-800 bg-zinc-900/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                    <HardDrive className="h-4 w-4 text-blue-400" />
                    Disk Usage
                    <button onClick={() => setShowRawDisk(!showRawDisk)} className="ml-auto text-xs text-zinc-500 hover:text-zinc-300">
                      {showRawDisk ? "Parsed" : "Raw"}
                    </button>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {showRawDisk ? (
                    <pre className="text-xs font-mono text-zinc-400 whitespace-pre overflow-x-auto">{health.disk || "N/A"}</pre>
                  ) : disk ? (
                    <div className="space-y-3">
                      <div className="flex justify-between text-sm">
                        <span className="text-zinc-400">Used</span>
                        <span className="text-zinc-200 font-mono">{disk.used} / {disk.size}</span>
                      </div>
                      <div className="w-full bg-zinc-800 rounded-full h-3">
                        <div
                          className="bg-blue-500 h-3 rounded-full transition-all"
                          style={{ width: disk.usePercent }}
                        />
                      </div>
                      <div className="flex justify-between text-xs text-zinc-500">
                        <span>{disk.usePercent} used</span>
                        <span>{disk.avail} available</span>
                      </div>
                    </div>
                  ) : (
                    <span className="text-zinc-500 text-sm">No disk data</span>
                  )}
                </CardContent>
              </Card>

              {/* Memory Usage */}
              <Card className="border-zinc-800 bg-zinc-900/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                    <MemoryStick className="h-4 w-4 text-purple-400" />
                    Memory Usage
                    <button onClick={() => setShowRawMem(!showRawMem)} className="ml-auto text-xs text-zinc-500 hover:text-zinc-300">
                      {showRawMem ? "Parsed" : "Raw"}
                    </button>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {showRawMem ? (
                    <pre className="text-xs font-mono text-zinc-400 whitespace-pre overflow-x-auto">{health.memory || "N/A"}</pre>
                  ) : mem ? (
                    <div className="space-y-3">
                      <div className="flex justify-between text-sm">
                        <span className="text-zinc-400">Used</span>
                        <span className="text-zinc-200 font-mono">{mem.used} / {mem.total}</span>
                      </div>
                      <div className="w-full bg-zinc-800 rounded-full h-3">
                        <div
                          className="bg-purple-500 h-3 rounded-full transition-all"
                          style={{ width: `${Math.round((parseFloat(mem.used) / parseFloat(mem.total)) * 100)}%` }}
                        />
                      </div>
                      <div className="flex justify-between text-xs text-zinc-500">
                        <span>{mem.available} available</span>
                        <span>{mem.free} free</span>
                      </div>
                    </div>
                  ) : (
                    <span className="text-zinc-500 text-sm">No memory data</span>
                  )}
                </CardContent>
              </Card>
            </div>
          )}

          {/* Installed Tools */}
          {health.status === "online" && (
            <Card className="border-zinc-800 bg-zinc-900/50">
              <CardHeader>
                <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                  <Wrench className="h-4 w-4 text-amber-400" />
                  Installed Tools
                  <Badge variant="outline" className="ml-2 text-xs border-zinc-700 text-zinc-400">
                    {toolVersionsQ.data?.length ?? health.tools?.length ?? 0} tools
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {toolVersionsQ.isLoading ? (
                  <div className="flex items-center gap-2 text-zinc-400 text-sm">
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    Checking tool versions...
                  </div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {(toolVersionsQ.data || []).map((tool) => (
                      <div
                        key={tool.name}
                        className={`flex items-center gap-3 rounded-lg border px-3 py-2 ${
                          tool.installed
                            ? "border-zinc-700/50 bg-zinc-800/30"
                            : "border-red-500/20 bg-red-500/5"
                        }`}
                      >
                        {tool.installed ? (
                          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                        ) : (
                          <XCircle className="h-4 w-4 text-red-400 shrink-0" />
                        )}
                        <div className="min-w-0">
                          <div className="text-sm font-medium text-zinc-200">{tool.name}</div>
                          <div className="text-xs text-zinc-500 truncate font-mono">{tool.version}</div>
                        </div>
                        <ToolCategoryBadge name={tool.name} />
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
    </AppShell>
  );
}

function ToolCategoryBadge({ name }: { name: string }) {
  const categories: Record<string, { label: string; color: string }> = {
    nmap: { label: "Recon", color: "text-cyan-400 border-cyan-500/30" },
    nuclei: { label: "Vuln", color: "text-red-400 border-red-500/30" },
    nikto: { label: "Web", color: "text-orange-400 border-orange-500/30" },
    hydra: { label: "Creds", color: "text-yellow-400 border-yellow-500/30" },
    httpx: { label: "Web", color: "text-orange-400 border-orange-500/30" },
    subfinder: { label: "Recon", color: "text-cyan-400 border-cyan-500/30" },
    gobuster: { label: "Web", color: "text-orange-400 border-orange-500/30" },
    sqlmap: { label: "Exploit", color: "text-red-400 border-red-500/30" },
    enum4linux: { label: "Enum", color: "text-blue-400 border-blue-500/30" },
    smbclient: { label: "Enum", color: "text-blue-400 border-blue-500/30" },
    ldapsearch: { label: "Enum", color: "text-blue-400 border-blue-500/30" },
    dig: { label: "DNS", color: "text-teal-400 border-teal-500/30" },
    whois: { label: "OSINT", color: "text-indigo-400 border-indigo-500/30" },
  };
  const cat = categories[name];
  if (!cat) return null;
  return (
      <span className={`ml-auto text-[10px] font-medium uppercase tracking-wider border rounded px-1.5 py-0.5 ${cat.color}`}>
      {cat.label}
    </span>
  );
}
