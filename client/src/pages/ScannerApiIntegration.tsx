"use client";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loader2, Plug, CheckCircle2, XCircle, Download, RefreshCw, Server, Shield } from "lucide-react";
import AppShell from "@/components/AppShell";

type ScannerType = "nessus" | "tenable_io" | "qualys" | "rapid7";

interface ConnectionConfig {
  type: ScannerType;
  baseUrl: string;
  apiKey?: string;
  apiSecret?: string;
  username?: string;
  password?: string;
  accessKey?: string;
  secretKey?: string;
}

const SCANNER_INFO: Record<ScannerType, { label: string; description: string; authFields: string[] }> = {
  nessus: {
    label: "Nessus Professional",
    description: "On-premise Nessus scanner. Requires Access Key and Secret Key from API Keys settings.",
    authFields: ["accessKey", "secretKey"],
  },
  tenable_io: {
    label: "Tenable.io",
    description: "Cloud-based Tenable Vulnerability Management. Generate API keys from Settings > My Account.",
    authFields: ["accessKey", "secretKey"],
  },
  qualys: {
    label: "Qualys VMDR",
    description: "Qualys Vulnerability Management. Uses username/password authentication.",
    authFields: ["username", "password"],
  },
  rapid7: {
    label: "Rapid7 InsightVM",
    description: "Rapid7 InsightVM / Nexpose. Requires API key from Administration > API Keys.",
    authFields: ["apiKey"],
  },
};

const ScannerApiIntegration = () => {
  const [scannerType, setScannerType] = useState<ScannerType>("nessus");
  const [baseUrl, setBaseUrl] = useState("");
  const [accessKey, setAccessKey] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [connectionStatus, setConnectionStatus] = useState<any>(null);
  const [remoteScans, setRemoteScans] = useState<any[]>([]);
  const [pullingId, setPullingId] = useState<string | null>(null);

  const validateMutation = trpc.vulnScanner.validateScannerConnection.useMutation({
    onSuccess: (data) => {
      setConnectionStatus(data);
      if (data.connected) {
        toast.success(`Connected to ${SCANNER_INFO[scannerType].label}${data.scannerVersion ? ` v${data.scannerVersion}` : ""}`);
      } else {
        toast.error(`Connection failed: ${data.error}`);
      }
    },
    onError: (err) => toast.error(`Connection error: ${err.message}`),
  });

  const listScansMutation = trpc.vulnScanner.listRemoteScans.useMutation({
    onSuccess: (data) => {
      setRemoteScans(data);
      if (data.length === 0) toast.info("No scans found on the remote scanner");
      else toast.success(`Found ${data.length} scans`);
    },
    onError: (err) => toast.error(`Failed to list scans: ${err.message}`),
  });

  const pullScanMutation = trpc.vulnScanner.pullRemoteScan.useMutation({
    onSuccess: (data) => {
      setPullingId(null);
      toast.success(`Imported ${data.totalVulns} vulnerabilities across ${data.totalHosts} hosts. ${data.corroboration.corroborated} findings corroborated.`);
    },
    onError: (err) => {
      setPullingId(null);
      toast.error(`Failed to pull scan: ${err.message}`);
    },
  });

  const getCredentials = (): ConnectionConfig => ({
    type: scannerType,
    baseUrl: baseUrl.replace(/\/$/, ""),
    ...(scannerType === "nessus" || scannerType === "tenable_io" ? { accessKey, secretKey } : {}),
    ...(scannerType === "qualys" ? { username, password } : {}),
    ...(scannerType === "rapid7" ? { apiKey } : {}),
  });

  const handleConnect = () => {
    if (!baseUrl) { toast.error("Base URL is required"); return; }
    validateMutation.mutate(getCredentials());
  };

  const handleListScans = () => {
    if (!connectionStatus?.connected) { toast.error("Connect to scanner first"); return; }
    listScansMutation.mutate(getCredentials());
  };

  const handlePullScan = (scanId: string) => {
    setPullingId(scanId);
    pullScanMutation.mutate({ ...getCredentials(), scanId });
  };

  const info = SCANNER_INFO[scannerType];

  return (
    <AppShell activePath="/scanner-api">
      <div className="space-y-6">
      {/* Connection Configuration */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Plug className="w-5 h-5 text-primary" />
            <CardTitle>Scanner Connection</CardTitle>
          </div>
          <CardDescription>
            Connect to your vulnerability scanner to pull authenticated scan results directly into the platform.
            This satisfies FedRAMP RA-5(5) requirements for credentialed scanning.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Scanner Type</Label>
              <Select value={scannerType} onValueChange={(v) => { setScannerType(v as ScannerType); setConnectionStatus(null); setRemoteScans([]); }}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="nessus">Nessus Professional</SelectItem>
                  <SelectItem value="tenable_io">Tenable.io</SelectItem>
                  <SelectItem value="qualys">Qualys VMDR</SelectItem>
                  <SelectItem value="rapid7">Rapid7 InsightVM</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">{info.description}</p>
            </div>

            <div className="space-y-2">
              <Label>Base URL</Label>
              <Input
                placeholder={scannerType === "tenable_io" ? "https://cloud.tenable.com" : scannerType === "qualys" ? "https://qualysapi.qualys.com" : "https://scanner.example.com:8834"}
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
              />
            </div>
          </div>

          {/* Auth fields based on scanner type */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(scannerType === "nessus" || scannerType === "tenable_io") && (
              <>
                <div className="space-y-2">
                  <Label>Access Key</Label>
                  <Input type="password" placeholder="Access Key" value={accessKey} onChange={(e) => setAccessKey(e.target.value)} />
                </div>
                <div className="space-y-2">
                  <Label>Secret Key</Label>
                  <Input type="password" placeholder="Secret Key" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} />
                </div>
              </>
            )}
            {scannerType === "qualys" && (
              <>
                <div className="space-y-2">
                  <Label>Username</Label>
                  <Input placeholder="Qualys username" value={username} onChange={(e) => setUsername(e.target.value)} />
                </div>
                <div className="space-y-2">
                  <Label>Password</Label>
                  <Input type="password" placeholder="Qualys password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
              </>
            )}
            {scannerType === "rapid7" && (
              <div className="space-y-2">
                <Label>API Key</Label>
                <Input type="password" placeholder="InsightVM API key" value={apiKey} onChange={(e) => setApiKey(e.target.value)} />
              </div>
            )}
          </div>

          <div className="flex items-center gap-3">
            <Button onClick={handleConnect} disabled={validateMutation.isPending}>
              {validateMutation.isPending ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Connecting...</> : <><Plug className="w-4 h-4 mr-2" /> Test Connection</>}
            </Button>
            {connectionStatus && (
              <div className="flex items-center gap-2">
                {connectionStatus.connected ? (
                  <Badge className="bg-green-600 text-white"><CheckCircle2 className="w-3 h-3 mr-1" /> Connected{connectionStatus.scannerVersion ? ` (v${connectionStatus.scannerVersion})` : ""}</Badge>
                ) : (
                  <Badge variant="destructive"><XCircle className="w-3 h-3 mr-1" /> {connectionStatus.error}</Badge>
                )}
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Remote Scans */}
      {connectionStatus?.connected && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-primary" />
                <CardTitle>Available Scans</CardTitle>
              </div>
              <Button variant="outline" size="sm" onClick={handleListScans} disabled={listScansMutation.isPending}>
                {listScansMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4 mr-1" />}
                {listScansMutation.isPending ? "Loading..." : "Refresh"}
              </Button>
            </div>
            <CardDescription>
              Select a scan to pull its results into the platform. Findings will be auto-corroborated against existing data.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {remoteScans.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Server className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>Click "Refresh" to load available scans from the remote scanner</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Scan Name</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Date</TableHead>
                    <TableHead>Hosts</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {remoteScans.map((scan) => (
                    <TableRow key={scan.scanId}>
                      <TableCell className="font-medium">{scan.name}</TableCell>
                      <TableCell>
                        <Badge variant={scan.status === "completed" ? "default" : "outline"}>
                          {scan.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {scan.startTime ? new Date(scan.startTime).toLocaleDateString() : "—"}
                      </TableCell>
                      <TableCell>{scan.hostCount ?? scan.vulnCount ?? "—"}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handlePullScan(scan.scanId)}
                          disabled={pullingId === scan.scanId || pullScanMutation.isPending}
                        >
                          {pullingId === scan.scanId ? (
                            <><Loader2 className="w-3 h-3 mr-1 animate-spin" /> Pulling...</>
                          ) : (
                            <><Download className="w-3 h-3 mr-1" /> Import</>
                          )}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {/* FedRAMP Compliance Note */}
      <Card className="border-blue-500/30 bg-blue-500/5">
        <CardContent className="pt-6">
          <div className="flex items-start gap-3">
            <Shield className="w-5 h-5 text-blue-500 mt-0.5 shrink-0" />
            <div>
              <p className="font-semibold text-sm">FedRAMP Authenticated Scanning Requirement</p>
              <p className="text-xs text-muted-foreground mt-1">
                FedRAMP RA-5(5) requires credentialed vulnerability scanning for Moderate and High baselines.
                Connect your Nessus, Qualys, or Rapid7 scanner to import authenticated scan results that satisfy
                this control. Imported findings are automatically corroborated against other scan sources to reduce
                false positives and strengthen your POA&M evidence.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
    </AppShell>
  );
};

export default ScannerApiIntegration;
