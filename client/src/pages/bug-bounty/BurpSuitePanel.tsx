import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import {
  Loader2,
  CheckCircle2,
  XCircle,
  Key,
  Eye,
  EyeOff,
  Trash2,
  RefreshCw,
  Download,
  ExternalLink,
  Shield,
  Unplug,
  Globe,
  AlertTriangle,
} from "lucide-react";
import { BurpSuiteIcon } from "@/components/PlatformIcons";

interface BurpSuitePanelProps {
  credentials: any[];
  onRefreshCredentials: () => void;
}

export function BurpSuitePanel({
  credentials,
  onRefreshCredentials,
}: BurpSuitePanelProps) {
  const [showConnectDialog, setShowConnectDialog] = useState(false);
  const [showImportDialog, setShowImportDialog] = useState(false);
  const [edition, setEdition] = useState<"professional" | "enterprise">("professional");
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:1337");
  const [apiKey, setApiKey] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [importScanId, setImportScanId] = useState("");
  const [importCredId, setImportCredId] = useState<number | null>(null);
  const [importHandle, setImportHandle] = useState("");

  const burpCreds = useMemo(
    () =>
      credentials.filter(
        (c: any) =>
          c.platform === "burpsuite_pro" || c.platform === "burpsuite_enterprise"
      ),
    [credentials]
  );

  // Mutations
  const addCredential = trpc.platformCredentials.add.useMutation({
    onSuccess: () => {
      toast.success("Burp Suite connection saved");
      setShowConnectDialog(false);
      resetForm();
      onRefreshCredentials();
    },
    onError: (e: any) => toast.error(e.message),
  });

  const verifyConnection = trpc.bugBounty.verifyBurpConnection.useMutation({
    onSuccess: (result: any) => {
      if (result.connected) {
        toast.success(result.message || "Connected to Burp Suite");
      } else {
        toast.error(result.message || "Connection failed");
      }
      setVerifying(false);
    },
    onError: (e: any) => {
      toast.error(`Verification failed: ${e.message}`);
      setVerifying(false);
    },
  });

  const deleteCredential = trpc.platformCredentials.delete.useMutation({
    onSuccess: () => {
      toast.success("Burp Suite connection removed");
      onRefreshCredentials();
    },
    onError: (e: any) => toast.error(e.message),
  });

  const verifyCredential = trpc.platformCredentials.verify.useMutation({
    onSuccess: (result: any) => {
      if (result.valid) toast.success(result.message);
      else toast.error(result.message);
      onRefreshCredentials();
    },
    onError: (e: any) => toast.error(e.message),
  });

  const importIssues = trpc.bugBounty.importBurpIssues.useMutation({
    onSuccess: (data: any) => {
      toast.success(
        `Imported ${data.imported} issues from Burp Suite scan ${data.scanId}`
      );
      setShowImportDialog(false);
      setImportScanId("");
      setImportCredId(null);
    },
    onError: (e: any) => toast.error(`Import failed: ${e.message}`),
  });

  const resetForm = () => {
    setEdition("professional");
    setBaseUrl("http://127.0.0.1:1337");
    setApiKey("");
    setDisplayName("");
    setShowApiKey(false);
  };

  const handleVerifyAndSave = () => {
    setVerifying(true);
    verifyConnection.mutate(
      { edition, baseUrl, apiKey },
      {
        onSuccess: (result: any) => {
          // Save regardless of verification result — user may be offline
          addCredential.mutate({
            platform: edition === "enterprise" ? "burpsuite_enterprise" : "burpsuite_pro",
            displayName: displayName || `Burp Suite ${edition === "enterprise" ? "Enterprise" : "Professional"}`,
            apiKey,
            baseUrl,
          });
        },
        onError: () => {
          // Still save the credential
          addCredential.mutate({
            platform: edition === "enterprise" ? "burpsuite_enterprise" : "burpsuite_pro",
            displayName: displayName || `Burp Suite ${edition === "enterprise" ? "Enterprise" : "Professional"}`,
            apiKey,
            baseUrl,
          });
        },
      }
    );
  };

  return (
    <>
      {/* Burp Suite Section Header */}
      <Card className="bg-zinc-900/50 border-zinc-800 border-orange-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg border border-orange-500/30 bg-orange-500/10 flex items-center justify-center">
                <BurpSuiteIcon className="text-orange-400" size={22} />
              </div>
              <div>
                <CardTitle className="text-base">Burp Suite Integration</CardTitle>
                <CardDescription className="text-xs">
                  Connect Burp Suite Professional or Enterprise to import scan
                  results and issues
                </CardDescription>
              </div>
            </div>
            <div className="flex gap-2">
              {burpCreds.length > 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  className="text-xs border-orange-500/30 text-orange-400 hover:bg-orange-500/10"
                  onClick={() => {
                    setImportCredId(burpCreds[0]?.id);
                    setShowImportDialog(true);
                  }}
                >
                  <Download className="h-3.5 w-3.5 mr-1" />
                  Import Scan
                </Button>
              )}
              <Button
                size="sm"
                onClick={() => setShowConnectDialog(true)}
                className="bg-orange-600 hover:bg-orange-700"
              >
                <Key className="h-3.5 w-3.5 mr-1" />
                Connect Burp Suite
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {burpCreds.length > 0 ? (
            <div className="space-y-2">
              {burpCreds.map((cred: any) => (
                <div
                  key={cred.id}
                  className="flex items-center justify-between p-3 bg-zinc-800/50 rounded-lg border border-zinc-700/50"
                >
                  <div className="flex items-center gap-3">
                    <BurpSuiteIcon
                      className={
                        cred.platform === "burpsuite_enterprise"
                          ? "text-orange-600"
                          : "text-orange-400"
                      }
                      size={18}
                    />
                    <div>
                      <p className="text-sm font-medium">{cred.displayName}</p>
                      <p className="text-xs text-muted-foreground">
                        {cred.platform === "burpsuite_enterprise"
                          ? "Enterprise/DAST"
                          : "Professional"}{" "}
                        {cred.baseUrl && `• ${cred.baseUrl}`}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {cred.syncStatus === "success" && (
                      <Badge className="bg-emerald-500/20 text-emerald-400 text-xs">
                        Verified
                      </Badge>
                    )}
                    {cred.syncStatus === "failed" && (
                      <Badge className="bg-red-500/20 text-red-400 text-xs">
                        Failed
                      </Badge>
                    )}
                    {(cred.syncStatus === "idle" || !cred.syncStatus) && (
                      <Badge className="bg-zinc-500/20 text-zinc-400 text-xs">
                        Unverified
                      </Badge>
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-xs h-7"
                      onClick={() => verifyCredential.mutate({ id: cred.id })}
                      disabled={verifyCredential.isPending}
                    >
                      {verifyCredential.isPending ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <RefreshCw className="h-3 w-3" />
                      )}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-xs h-7 border-orange-500/30 text-orange-400 hover:bg-orange-500/10"
                      onClick={() => {
                        setImportCredId(cred.id);
                        setShowImportDialog(true);
                      }}
                    >
                      <Download className="h-3 w-3 mr-1" />
                      Import
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-xs h-7 text-red-400 hover:text-red-300"
                      onClick={() => {
                        if (confirm("Remove this Burp Suite connection?"))
                          deleteCredential.mutate({ id: cred.id });
                      }}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-6">
              <Unplug className="h-8 w-8 mx-auto mb-2 text-zinc-600" />
              <p className="text-sm text-muted-foreground mb-1">
                No Burp Suite connections configured
              </p>
              <p className="text-xs text-muted-foreground mb-3">
                Connect your Burp Suite Professional or Enterprise instance to
                import scan findings
              </p>
              <div className="flex justify-center gap-2">
                <a
                  href="https://portswigger.net/burp/documentation/desktop/settings/suite/rest-api"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                >
                  <ExternalLink className="h-3 w-3" />
                  Pro REST API Docs
                </a>
                <a
                  href="https://portswigger.net/burp/documentation/dast/user-guide/api-documentation/rest"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                >
                  <ExternalLink className="h-3 w-3" />
                  Enterprise API Docs
                </a>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ─── Connect Dialog ─── */}
      <Dialog open={showConnectDialog} onOpenChange={setShowConnectDialog}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <BurpSuiteIcon className="text-orange-400" size={20} />
              Connect Burp Suite
            </DialogTitle>
            <DialogDescription>
              Connect your Burp Suite instance to import scan results and
              vulnerability findings into the platform.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <Label>Edition</Label>
              <Select
                value={edition}
                onValueChange={(v) => {
                  setEdition(v as "professional" | "enterprise");
                  if (v === "professional") setBaseUrl("http://127.0.0.1:1337");
                  else setBaseUrl("");
                }}
              >
                <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="professional">
                    Burp Suite Professional
                  </SelectItem>
                  <SelectItem value="enterprise">
                    Burp Suite Enterprise / DAST
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label>Display Name</Label>
              <Input
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder={`Burp Suite ${edition === "enterprise" ? "Enterprise" : "Professional"}`}
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>

            <div>
              <Label>
                {edition === "professional" ? "REST API Base URL" : "Server URL"}
              </Label>
              <Input
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder={
                  edition === "professional"
                    ? "http://127.0.0.1:1337"
                    : "https://burp-enterprise.example.com"
                }
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
              <p className="text-xs text-muted-foreground mt-1">
                {edition === "professional"
                  ? "Enable the REST API in Burp Suite: Settings → Suite → REST API. Default port is 1337."
                  : "The base URL of your Burp Suite Enterprise/DAST server."}
              </p>
            </div>

            <div>
              <Label>API Key</Label>
              <div className="relative">
                <Input
                  type={showApiKey ? "text" : "password"}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder={
                    edition === "professional"
                      ? "Your REST API key from Burp Suite settings"
                      : "API key from Burp Suite DAST settings"
                  }
                  className="bg-zinc-800 border-zinc-700 mt-1 pr-10"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0"
                  onClick={() => setShowApiKey(!showApiKey)}
                >
                  {showApiKey ? (
                    <EyeOff className="h-3.5 w-3.5" />
                  ) : (
                    <Eye className="h-3.5 w-3.5" />
                  )}
                </Button>
              </div>
            </div>

            {/* Setup instructions */}
            <Card className="bg-zinc-800/30 border-zinc-700/50">
              <CardContent className="py-3 px-4">
                <p className="text-xs font-medium mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                  Setup Instructions
                </p>
                {edition === "professional" ? (
                  <ol className="text-xs text-muted-foreground space-y-1 list-decimal list-inside">
                    <li>
                      Open Burp Suite Professional → Settings → Suite → REST API
                    </li>
                    <li>Check "Service running" to enable the API</li>
                    <li>
                      Set "API key" — copy it here. Optionally restrict to
                      specific IP.
                    </li>
                    <li>
                      Default URL is http://127.0.0.1:1337. Adjust if you
                      changed the port.
                    </li>
                    <li>
                      For remote access, ensure the port is accessible from this
                      server.
                    </li>
                  </ol>
                ) : (
                  <ol className="text-xs text-muted-foreground space-y-1 list-decimal list-inside">
                    <li>
                      Log into Burp Suite Enterprise/DAST → Settings → API
                    </li>
                    <li>Create an API user with appropriate permissions</li>
                    <li>Copy the API key and server URL</li>
                    <li>
                      The GraphQL API endpoint is at /graphql/v1 (auto-appended)
                    </li>
                  </ol>
                )}
              </CardContent>
            </Card>
          </div>

          <DialogFooter className="gap-2">
            <Button
              variant="outline"
              onClick={() => setShowConnectDialog(false)}
            >
              Cancel
            </Button>
            <Button
              onClick={handleVerifyAndSave}
              disabled={!apiKey || !baseUrl || addCredential.isPending || verifying}
              className="bg-orange-600 hover:bg-orange-700"
            >
              {verifying || addCredential.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Shield className="h-4 w-4 mr-1" />
              )}
              {verifying
                ? "Verifying..."
                : addCredential.isPending
                  ? "Saving..."
                  : "Verify & Save"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ─── Import Scan Dialog ─── */}
      <Dialog open={showImportDialog} onOpenChange={setShowImportDialog}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Download className="h-5 w-5 text-orange-400" />
              Import Burp Suite Scan
            </DialogTitle>
            <DialogDescription>
              Import vulnerability findings from a specific Burp Suite scan into
              the bug bounty findings database.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {burpCreds.length > 1 && (
              <div>
                <Label>Connection</Label>
                <Select
                  value={String(importCredId || "")}
                  onValueChange={(v) => setImportCredId(Number(v))}
                >
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1">
                    <SelectValue placeholder="Select connection" />
                  </SelectTrigger>
                  <SelectContent>
                    {burpCreds.map((c: any) => (
                      <SelectItem key={c.id} value={String(c.id)}>
                        {c.displayName}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            <div>
              <Label>Scan ID / Task ID</Label>
              <Input
                value={importScanId}
                onChange={(e) => setImportScanId(e.target.value)}
                placeholder="Enter the scan or task ID"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
              <p className="text-xs text-muted-foreground mt-1">
                For Burp Pro: use the scan task number. For Enterprise: use the
                scan ID from the dashboard.
              </p>
            </div>

            <div>
              <Label>Engagement Handle (optional)</Label>
              <Input
                value={importHandle}
                onChange={(e) => setImportHandle(e.target.value)}
                placeholder="Link to an engagement handle"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
          </div>

          <DialogFooter className="gap-2">
            <Button
              variant="outline"
              onClick={() => setShowImportDialog(false)}
            >
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (!importCredId || !importScanId) {
                  toast.error("Select a connection and enter a scan ID");
                  return;
                }
                importIssues.mutate({
                  credentialId: importCredId,
                  scanId: importScanId,
                  engagementHandle: importHandle || undefined,
                });
              }}
              disabled={importIssues.isPending || !importScanId || !importCredId}
              className="bg-orange-600 hover:bg-orange-700"
            >
              {importIssues.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Download className="h-4 w-4 mr-1" />
              )}
              {importIssues.isPending ? "Importing..." : "Import Issues"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
