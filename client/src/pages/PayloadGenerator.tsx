import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Package,
  Play,
  Download,
  Trash2,
  Copy,
  RefreshCw,
  Terminal,
  Shield,
  Loader2,
  CheckCircle2,
  XCircle,
  Clock,
  FileCode,
  Eye,
} from "lucide-react";
import ROEWarningBanner from "@/components/ROEWarningBanner";
import AppShell from "@/components/AppShell";

// ─── Common payload presets ─────────────────────────────────────────────────

const PRESETS = [
  {
    name: "Windows Meterpreter (Reverse TCP)",
    payload: "windows/meterpreter/reverse_tcp",
    format: "exe",
    arch: "x86",
    platform: "windows",
  },
  {
    name: "Windows x64 Meterpreter (Reverse HTTPS)",
    payload: "windows/x64/meterpreter/reverse_https",
    format: "exe",
    arch: "x64",
    platform: "windows",
  },
  {
    name: "Linux Meterpreter (Reverse TCP)",
    payload: "linux/x64/meterpreter/reverse_tcp",
    format: "elf",
    arch: "x64",
    platform: "linux",
  },
  {
    name: "Android Meterpreter",
    payload: "android/meterpreter/reverse_tcp",
    format: "apk",
    arch: "",
    platform: "android",
  },
  {
    name: "Python Meterpreter",
    payload: "python/meterpreter/reverse_tcp",
    format: "py",
    arch: "",
    platform: "python",
  },
  {
    name: "PowerShell Reverse Shell",
    payload: "windows/x64/meterpreter/reverse_tcp",
    format: "ps1",
    arch: "x64",
    platform: "windows",
  },
  {
    name: "macOS Meterpreter",
    payload: "osx/x64/meterpreter/reverse_tcp",
    format: "macho",
    arch: "x64",
    platform: "osx",
  },
  {
    name: "PHP Meterpreter",
    payload: "php/meterpreter/reverse_tcp",
    format: "php",
    arch: "",
    platform: "php",
  },
];

const FORMATS = [
  "exe", "elf", "apk", "ps1", "py", "raw", "dll", "macho",
  "msi", "vba", "war", "asp", "aspx", "jsp", "php", "bash",
  "sh", "pl", "rb", "c", "csharp", "powershell",
];

const ENCODERS = [
  { value: "none", label: "None (no encoding)" },
  { value: "x86/shikata_ga_nai", label: "x86/shikata_ga_nai (Polymorphic XOR)" },
  { value: "x64/xor", label: "x64/xor" },
  { value: "x64/xor_dynamic", label: "x64/xor_dynamic" },
  { value: "x86/countdown", label: "x86/countdown" },
  { value: "x86/fnstenv_mov", label: "x86/fnstenv_mov" },
  { value: "cmd/powershell_base64", label: "cmd/powershell_base64" },
  { value: "php/base64", label: "php/base64" },
];

export default function PayloadGenerator() {
  // ─── Server selection ─────────────────────────────────────────────────────
  const serversQuery = trpc.metasploit.listServers.useQuery();
  const onlineServers = useMemo(
    () => (serversQuery.data || []).filter((s: any) => s.status === "online"),
    [serversQuery.data]
  );

  const [serverId, setServerId] = useState<number | null>(null);

  // ─── Form state ───────────────────────────────────────────────────────────
  const [name, setName] = useState("");
  const [payload, setPayload] = useState("windows/meterpreter/reverse_tcp");
  const [format, setFormat] = useState("exe");
  const [lhost, setLhost] = useState("");
  const [lport, setLport] = useState(4444);
  const [encoder, setEncoder] = useState("none");
  const [iterations, setIterations] = useState(1);
  const [arch, setArch] = useState("x86");
  const [platform, setPlatform] = useState("windows");

  // ─── Queries ──────────────────────────────────────────────────────────────
  const payloadsQuery = trpc.payloadGenerator.list.useQuery(
    serverId ? { serverId, limit: 50 } : { limit: 50 },
    { refetchInterval: 5000 }
  );

  const previewQuery = trpc.payloadGenerator.previewCommand.useQuery(
    {
      payload,
      format,
      lhost: lhost || "0.0.0.0",
      lport,
      encoder: encoder !== "none" ? encoder : undefined,
      iterations: iterations > 1 ? iterations : undefined,
      arch: arch || undefined,
      platform: platform || undefined,
    },
    { enabled: !!payload && !!format }
  );

  // ─── Mutations ────────────────────────────────────────────────────────────
  const generateMut = trpc.payloadGenerator.generate.useMutation({
    onSuccess: (data) => {
      toast.success(`Payload generation started (ID: ${data.payloadId})`);
      payloadsQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const deleteMut = trpc.payloadGenerator.delete.useMutation({
    onSuccess: () => {
      toast.success("Payload deleted");
      payloadsQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  // ─── Detail dialog ────────────────────────────────────────────────────────
  const [detailId, setDetailId] = useState<number | null>(null);
  const detailQuery = trpc.payloadGenerator.getStatus.useQuery(
    { payloadId: detailId! },
    { enabled: !!detailId, refetchInterval: detailId ? 3000 : false }
  );

  // ─── Handlers ─────────────────────────────────────────────────────────────
  const handleGenerate = () => {
    if (!serverId) {
      toast.error("Select an MSF server first");
      return;
    }
    if (!lhost) {
      toast.error("LHOST is required");
      return;
    }
    generateMut.mutate({
      serverId,
      name: name || `${payload.split("/").pop()}_${format}`,
      payload,
      format,
      lhost,
      lport,
      encoder: encoder !== "none" ? encoder : undefined,
      iterations: iterations > 1 ? iterations : undefined,
      arch: arch || undefined,
      platform: platform || undefined,
    });
  };

  const applyPreset = (preset: (typeof PRESETS)[number]) => {
    setPayload(preset.payload);
    setFormat(preset.format);
    setArch(preset.arch);
    setPlatform(preset.platform);
    setName(preset.name);
  };

  const copyCommand = () => {
    if (previewQuery.data?.command) {
      navigator.clipboard.writeText(previewQuery.data.command);
      toast.success("Command copied to clipboard");
    }
  };

  const statusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <CheckCircle2 className="h-4 w-4 text-green-400" />;
      case "failed":
        return <XCircle className="h-4 w-4 text-red-400" />;
      case "generating":
        return <Loader2 className="h-4 w-4 text-yellow-400 animate-spin" />;
      default:
        return <Clock className="h-4 w-4 text-zinc-400" />;
    }
  };

  const formatBytes = (bytes: number | null) => {
    if (!bytes) return "—";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <AppShell activePath="/payload-generator">
      <div className="space-y-6">
      {/* ROE Warning Banner */}
      <ROEWarningBanner riskTier="red" operationName="Payload Generation" />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Package className="h-6 w-6 text-purple-400" />
            Payload Generator
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Generate custom payloads via msfvenom on your MSF servers
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => payloadsQuery.refetch()}
        >
          <RefreshCw className="h-4 w-4 mr-1" />
          Refresh
        </Button>
      </div>

      {/* Server Selection */}
      <Card className="border-zinc-800 bg-zinc-900/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-400">
            Target MSF Server
          </CardTitle>
        </CardHeader>
        <CardContent>
          {onlineServers.length === 0 ? (
            <p className="text-sm text-zinc-500">
              No online MSF servers. Go to Exploit Servers to connect one.
            </p>
          ) : (
            <Select
              value={serverId ? String(serverId) : ""}
              onValueChange={(v) => setServerId(Number(v))}
            >
              <SelectTrigger className="w-full max-w-md">
                <SelectValue placeholder="Select an MSF server..." />
              </SelectTrigger>
              <SelectContent>
                {onlineServers.map((s: any) => (
                  <SelectItem key={s.id} value={String(s.id)}>
                    {s.name} ({s.ipAddress})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Generator Form */}
        <div className="lg:col-span-2 space-y-4">
          {/* Quick Presets */}
          <Card className="border-zinc-800 bg-zinc-900/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-zinc-400">
                Quick Presets
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {PRESETS.map((p) => (
                  <Button
                    key={p.name}
                    variant="outline"
                    size="sm"
                    className="text-xs"
                    onClick={() => applyPreset(p)}
                  >
                    {p.name}
                  </Button>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Payload Configuration */}
          <Card className="border-zinc-800 bg-zinc-900/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-zinc-400">
                Payload Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Name</Label>
                  <Input
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="My payload"
                    className="bg-zinc-800/50"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Payload Type</Label>
                  <Input
                    value={payload}
                    onChange={(e) => setPayload(e.target.value)}
                    placeholder="windows/meterpreter/reverse_tcp"
                    className="bg-zinc-800/50 font-mono text-sm"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="space-y-2">
                  <Label>LHOST</Label>
                  <Input
                    value={lhost}
                    onChange={(e) => setLhost(e.target.value)}
                    placeholder="10.0.0.1"
                    className="bg-zinc-800/50 font-mono text-sm"
                  />
                </div>
                <div className="space-y-2">
                  <Label>LPORT</Label>
                  <Input
                    type="number"
                    value={lport}
                    onChange={(e) => setLport(Number(e.target.value))}
                    className="bg-zinc-800/50 font-mono text-sm"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Format</Label>
                  <Select value={format} onValueChange={setFormat}>
                    <SelectTrigger className="bg-zinc-800/50">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {FORMATS.map((f) => (
                        <SelectItem key={f} value={f}>
                          {f}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Architecture</Label>
                  <Select value={arch} onValueChange={setArch}>
                    <SelectTrigger className="bg-zinc-800/50">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="x86">x86</SelectItem>
                      <SelectItem value="x64">x64</SelectItem>
                      <SelectItem value="armle">armle</SelectItem>
                      <SelectItem value="aarch64">aarch64</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label>Platform</Label>
                  <Select value={platform} onValueChange={setPlatform}>
                    <SelectTrigger className="bg-zinc-800/50">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {["windows", "linux", "osx", "android", "java", "php", "python", "ruby"].map(
                        (p) => (
                          <SelectItem key={p} value={p}>
                            {p}
                          </SelectItem>
                        )
                      )}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Encoder</Label>
                  <Select value={encoder} onValueChange={setEncoder}>
                    <SelectTrigger className="bg-zinc-800/50">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {ENCODERS.map((e) => (
                        <SelectItem key={e.value} value={e.value}>
                          {e.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Iterations</Label>
                  <Input
                    type="number"
                    value={iterations}
                    onChange={(e) =>
                      setIterations(Math.max(1, Math.min(20, Number(e.target.value))))
                    }
                    min={1}
                    max={20}
                    className="bg-zinc-800/50"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Command Preview */}
          <Card className="border-zinc-800 bg-zinc-900/50">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-zinc-400 flex items-center gap-2">
                  <Terminal className="h-4 w-4" />
                  Command Preview
                </CardTitle>
                <Button variant="ghost" size="sm" onClick={copyCommand}>
                  <Copy className="h-3 w-3 mr-1" />
                  Copy
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <pre className="bg-black/50 rounded-lg p-3 text-xs font-mono text-green-400 overflow-x-auto whitespace-pre-wrap break-all">
                {previewQuery.data?.command || "Loading..."}
              </pre>
            </CardContent>
          </Card>

          {/* Generate Button */}
          <Button
            className="w-full"
            size="lg"
            onClick={handleGenerate}
            disabled={!serverId || !lhost || generateMut.isPending}
          >
            {generateMut.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Play className="h-4 w-4 mr-2" />
            )}
            Generate Payload
          </Button>
        </div>

        {/* Right: Info Panel */}
        <div className="space-y-4">
          <Card className="border-zinc-800 bg-zinc-900/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-zinc-400 flex items-center gap-2">
                <Shield className="h-4 w-4" />
                About msfvenom
              </CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-zinc-400 space-y-2">
              <p>
                msfvenom is the Metasploit payload generator and encoder. It
                combines msfpayload and msfencode into a single tool.
              </p>
              <p>
                Payloads are generated on the remote MSF server via SSH tunnel,
                then downloaded and stored in S3 for easy access.
              </p>
              <div className="border-t border-zinc-800 pt-2 mt-2">
                <p className="font-medium text-zinc-300 mb-1">Common Use Cases:</p>
                <ul className="space-y-1 list-disc list-inside">
                  <li>Reverse shells for penetration testing</li>
                  <li>Encoded payloads for AV evasion testing</li>
                  <li>Platform-specific implants</li>
                  <li>Web application payloads (PHP, JSP, WAR)</li>
                </ul>
              </div>
            </CardContent>
          </Card>

          <Card className="border-zinc-800 bg-zinc-900/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-zinc-400">
                Stats
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3">
                <div className="text-center p-2 bg-zinc-800/30 rounded">
                  <div className="text-lg font-bold text-purple-400">
                    {payloadsQuery.data?.length || 0}
                  </div>
                  <div className="text-xs text-zinc-500">Total</div>
                </div>
                <div className="text-center p-2 bg-zinc-800/30 rounded">
                  <div className="text-lg font-bold text-green-400">
                    {payloadsQuery.data?.filter((p: any) => p.status === "completed").length || 0}
                  </div>
                  <div className="text-xs text-zinc-500">Completed</div>
                </div>
                <div className="text-center p-2 bg-zinc-800/30 rounded">
                  <div className="text-lg font-bold text-yellow-400">
                    {payloadsQuery.data?.filter((p: any) => p.status === "generating").length || 0}
                  </div>
                  <div className="text-xs text-zinc-500">Generating</div>
                </div>
                <div className="text-center p-2 bg-zinc-800/30 rounded">
                  <div className="text-lg font-bold text-red-400">
                    {payloadsQuery.data?.filter((p: any) => p.status === "failed").length || 0}
                  </div>
                  <div className="text-xs text-zinc-500">Failed</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Payload History */}
      <Card className="border-zinc-800 bg-zinc-900/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileCode className="h-5 w-5 text-purple-400" />
            Generated Payloads
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!payloadsQuery.data || payloadsQuery.data.length === 0 ? (
            <div className="text-center py-8 text-zinc-500">
              <Package className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p>No payloads generated yet</p>
              <p className="text-xs mt-1">
                Configure and generate your first payload above
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800">
                    <TableHead>Status</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Payload</TableHead>
                    <TableHead>Format</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {payloadsQuery.data.map((p: any) => (
                    <TableRow key={p.id} className="border-zinc-800">
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          {statusIcon(p.status)}
                          <span className="text-xs capitalize">{p.status}</span>
                        </div>
                      </TableCell>
                      <TableCell className="font-medium text-sm">
                        {p.name}
                      </TableCell>
                      <TableCell>
                        <code className="text-xs bg-zinc-800 px-1.5 py-0.5 rounded">
                          {p.payload}
                        </code>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-xs">
                          {p.format}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {p.lhost}:{p.lport}
                      </TableCell>
                      <TableCell className="text-xs text-zinc-400">
                        {formatBytes(p.fileSize)}
                      </TableCell>
                      <TableCell className="text-xs text-zinc-400">
                        {new Date(p.createdAt).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setDetailId(p.id)}
                          >
                            <Eye className="h-3 w-3" />
                          </Button>
                          {p.status === "completed" && p.fileUrl && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => window.open(p.fileUrl, "_blank")}
                            >
                              <Download className="h-3 w-3" />
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-red-400 hover:text-red-300"
                            onClick={() => {
                              if (confirm("Delete this payload?")) {
                                deleteMut.mutate({ payloadId: p.id });
                              }
                            }}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Detail Dialog */}
      <Dialog open={!!detailId} onOpenChange={(open) => !open && setDetailId(null)}>
        <DialogContent className="max-w-2xl bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Package className="h-5 w-5 text-purple-400" />
              Payload Details
            </DialogTitle>
          </DialogHeader>
          {detailQuery.data && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-zinc-500">Status:</span>{" "}
                  <span className="flex items-center gap-1 inline-flex">
                    {statusIcon(detailQuery.data.status)}
                    <span className="capitalize">{detailQuery.data.status}</span>
                  </span>
                </div>
                <div>
                  <span className="text-zinc-500">Name:</span>{" "}
                  {detailQuery.data.name}
                </div>
                <div>
                  <span className="text-zinc-500">Payload:</span>{" "}
                  <code className="text-xs bg-zinc-800 px-1 rounded">
                    {detailQuery.data.payload}
                  </code>
                </div>
                <div>
                  <span className="text-zinc-500">Format:</span>{" "}
                  <Badge variant="outline">{detailQuery.data.format}</Badge>
                </div>
                <div>
                  <span className="text-zinc-500">Target:</span>{" "}
                  <span className="font-mono">
                    {detailQuery.data.lhost}:{detailQuery.data.lport}
                  </span>
                </div>
                <div>
                  <span className="text-zinc-500">Encoder:</span>{" "}
                  {detailQuery.data.encoder || "None"}
                </div>
                {detailQuery.data.arch && (
                  <div>
                    <span className="text-zinc-500">Arch:</span>{" "}
                    {detailQuery.data.arch}
                  </div>
                )}
                {detailQuery.data.platform && (
                  <div>
                    <span className="text-zinc-500">Platform:</span>{" "}
                    {detailQuery.data.platform}
                  </div>
                )}
                {detailQuery.data.fileSize && (
                  <div>
                    <span className="text-zinc-500">Size:</span>{" "}
                    {formatBytes(detailQuery.data.fileSize)}
                  </div>
                )}
                {detailQuery.data.fileSha256 && (
                  <div className="col-span-2">
                    <span className="text-zinc-500">SHA256:</span>{" "}
                    <code className="text-xs bg-zinc-800 px-1 rounded break-all">
                      {detailQuery.data.fileSha256}
                    </code>
                  </div>
                )}
              </div>

              {detailQuery.data.msfvenomCommand && (
                <div>
                  <Label className="text-zinc-500 text-xs">Command</Label>
                  <pre className="bg-black/50 rounded p-2 text-xs font-mono text-green-400 mt-1 whitespace-pre-wrap break-all">
                    {detailQuery.data.msfvenomCommand}
                  </pre>
                </div>
              )}

              {detailQuery.data.errorMessage && (
                <div>
                  <Label className="text-red-400 text-xs">Error</Label>
                  <pre className="bg-red-950/30 border border-red-900/50 rounded p-2 text-xs font-mono text-red-300 mt-1 whitespace-pre-wrap">
                    {detailQuery.data.errorMessage}
                  </pre>
                </div>
              )}

              {detailQuery.data.status === "completed" && detailQuery.data.fileUrl && (
                <Button
                  className="w-full"
                  onClick={() => window.open(detailQuery.data!.fileUrl!, "_blank")}
                >
                  <Download className="h-4 w-4 mr-2" />
                  Download Payload
                </Button>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
    </AppShell>
  );
}
