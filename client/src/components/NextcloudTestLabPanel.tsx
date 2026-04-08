import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import {
  Server, Download, Copy, CheckCircle2, AlertTriangle,
  Shield, Database, Mail, Key, Search, Video,
  HardDrive, Users, FileCode, Terminal, ExternalLink,
  ChevronDown, ChevronRight, Globe, Package,
} from "lucide-react";

interface Props {
  engagementId: number;
  engagementName?: string;
}

const TIER_NAMES: Record<number, string> = {
  1: "Security & Auth",
  2: "Collaboration",
  3: "PIM & Productivity",
  4: "Files & Storage",
  5: "Search & Indexing",
  6: "System & Admin",
  7: "Workflow",
  8: "UI & Misc",
  9: "Libraries",
};

const TIER_COLORS: Record<number, string> = {
  1: "bg-red-500/10 text-red-400 border-red-500/20",
  2: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  3: "bg-green-500/10 text-green-400 border-green-500/20",
  4: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  5: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  6: "bg-gray-500/10 text-gray-400 border-gray-500/20",
  7: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  8: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  9: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
};

export function NextcloudTestLabPanel({ engagementId, engagementName }: Props) {
  const { toast } = useToast();
  const [scanServerHost, setScanServerHost] = useState("");
  const [hostPort, setHostPort] = useState("8443");
  const [selectedVersion, setSelectedVersion] = useState("30.0.6");
  const [services, setServices] = useState({
    enableCollabora: true,
    enableClamAV: true,
    enableLDAP: true,
    enableKeycloak: true,
    enableElasticsearch: true,
    enableMinIO: true,
    enableMailhog: true,
    enableCoturn: true,
  });
  const [expandedTiers, setExpandedTiers] = useState<Set<number>>(new Set([1, 2]));
  const [copiedFile, setCopiedFile] = useState<string | null>(null);
  const [testLabUrl, setTestLabUrl] = useState("");

  const configInput = useMemo(() => ({
    nextcloudVersion: selectedVersion,
    hostPort: parseInt(hostPort) || 8443,
    scanServerHost: scanServerHost || undefined,
    ...services,
  }), [selectedVersion, hostPort, scanServerHost, services]);

  const { data: labConfig, isLoading } = trpc.bugBounty.getTestLabConfig.useQuery(configInput);

  const downloadFiles = trpc.bugBounty.downloadTestLabFiles.useMutation({
    onSuccess: (data) => {
      // Create a zip-like download of all files
      for (const file of data.files) {
        const blob = new Blob([file.content], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = file.name;
        a.click();
        URL.revokeObjectURL(url);
      }
      toast({ title: "Files Downloaded", description: `${data.files.length} files downloaded` });
    },
    onError: (err) => {
      toast({ title: "Download Failed", description: err.message, variant: "destructive" });
    },
  });

  const updateTarget = trpc.bugBounty.updateEngagementTestTarget.useMutation({
    onSuccess: (data) => {
      toast({ title: "Target Updated", description: `Engagement target set to ${data.targetDomain}` });
    },
    onError: (err) => {
      toast({ title: "Update Failed", description: err.message, variant: "destructive" });
    },
  });

  const copyToClipboard = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedFile(label);
    setTimeout(() => setCopiedFile(null), 2000);
    toast({ title: "Copied", description: `${label} copied to clipboard` });
  };

  const toggleTier = (tier: number) => {
    setExpandedTiers(prev => {
      const next = new Set(prev);
      if (next.has(tier)) next.delete(tier);
      else next.add(tier);
      return next;
    });
  };

  if (isLoading) {
    return (
      <Card className="border-orange-500/20 bg-orange-500/5">
        <CardContent className="p-6">
          <div className="flex items-center gap-3 text-orange-400">
            <Server className="h-5 w-5 animate-pulse" />
            <span>Loading test lab configuration...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!labConfig) return null;

  const appsByTier = labConfig.bountyEligibleApps.reduce((acc, app) => {
    if (!acc[app.tier]) acc[app.tier] = [];
    acc[app.tier].push(app);
    return acc;
  }, {} as Record<number, typeof labConfig.bountyEligibleApps>);

  return (
    <div className="space-y-4">
      {/* Header */}
      <Card className="border-orange-500/20 bg-gradient-to-r from-orange-500/5 to-red-500/5">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-500/10">
                <Server className="h-5 w-5 text-orange-400" />
              </div>
              <div>
                <CardTitle className="text-lg">Nextcloud Bug Bounty Test Lab</CardTitle>
                <CardDescription>
                  Self-hosted Nextcloud {selectedVersion} with {labConfig.appCount} bounty-eligible apps
                </CardDescription>
              </div>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => downloadFiles.mutate({
                  scanServerHost: scanServerHost || undefined,
                  nextcloudVersion: selectedVersion,
                  hostPort: parseInt(hostPort) || 8443,
                })}
                disabled={downloadFiles.isPending}
              >
                <Download className="h-4 w-4 mr-1" />
                {downloadFiles.isPending ? "Downloading..." : "Download All Scripts"}
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      <Tabs defaultValue="config" className="space-y-4">
        <TabsList className="bg-muted/50">
          <TabsTrigger value="config">Configuration</TabsTrigger>
          <TabsTrigger value="scripts">Deploy Scripts</TabsTrigger>
          <TabsTrigger value="apps">Scope Apps ({labConfig.appCount})</TabsTrigger>
          <TabsTrigger value="credentials">Test Credentials</TabsTrigger>
          <TabsTrigger value="compliance">Compliance Rules</TabsTrigger>
        </TabsList>

        {/* ── Configuration Tab ── */}
        <TabsContent value="config" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Version & Network */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Server Settings</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Nextcloud Version</Label>
                  <Select value={selectedVersion} onValueChange={setSelectedVersion}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {labConfig.supportedVersions.map(v => (
                        <SelectItem key={v} value={v}>{v}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Host Port</Label>
                  <Input
                    type="number"
                    value={hostPort}
                    onChange={e => setHostPort(e.target.value)}
                    placeholder="8443"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Scan Server Host (for remote deployment)</Label>
                  <Input
                    value={scanServerHost}
                    onChange={e => setScanServerHost(e.target.value)}
                    placeholder="e.g., 192.168.1.100 or your-server.com"
                  />
                  <p className="text-xs text-muted-foreground">
                    Leave empty for localhost deployment
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Services Toggle */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Supporting Services</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {[
                  { key: "enableCollabora", label: "Collabora Online", icon: FileCode, desc: "Office document editing" },
                  { key: "enableClamAV", label: "ClamAV", icon: Shield, desc: "Antivirus scanning" },
                  { key: "enableLDAP", label: "OpenLDAP", icon: Users, desc: "LDAP authentication" },
                  { key: "enableKeycloak", label: "Keycloak", icon: Key, desc: "OIDC/SAML IdP" },
                  { key: "enableElasticsearch", label: "Elasticsearch", icon: Search, desc: "Full text search" },
                  { key: "enableMinIO", label: "MinIO", icon: HardDrive, desc: "S3 object storage" },
                  { key: "enableMailhog", label: "Mailhog", icon: Mail, desc: "SMTP testing" },
                  { key: "enableCoturn", label: "Coturn", icon: Video, desc: "TURN server for Talk" },
                ].map(svc => (
                  <div key={svc.key} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <svc.icon className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <span className="text-sm font-medium">{svc.label}</span>
                        <span className="text-xs text-muted-foreground ml-2">{svc.desc}</span>
                      </div>
                    </div>
                    <Switch
                      checked={services[svc.key as keyof typeof services]}
                      onCheckedChange={v => setServices(prev => ({ ...prev, [svc.key]: v }))}
                    />
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Update Engagement Target */}
          <Card className="border-blue-500/20">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Globe className="h-4 w-4 text-blue-400" />
                Point Engagement to Test Lab
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2">
                <Input
                  value={testLabUrl}
                  onChange={e => setTestLabUrl(e.target.value)}
                  placeholder={`http://${scanServerHost || 'localhost'}:${hostPort}`}
                  className="flex-1"
                />
                <Button
                  onClick={() => updateTarget.mutate({
                    engagementId,
                    testLabUrl: testLabUrl || `http://${scanServerHost || 'localhost'}:${hostPort}`,
                    scanServerHost: scanServerHost || undefined,
                  })}
                  disabled={updateTarget.isPending}
                  size="sm"
                >
                  {updateTarget.isPending ? "Updating..." : "Update Target"}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                This updates the engagement's target domain and logs a timeline event.
              </p>
            </CardContent>
          </Card>

          {/* Service Endpoints */}
          {labConfig.labInfo && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Service Endpoints</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {labConfig.labInfo.services.map(svc => (
                    <div key={svc.name} className="flex items-center justify-between p-2 rounded bg-muted/30">
                      <div>
                        <span className="text-sm font-medium">{svc.name}</span>
                        <span className="text-xs text-muted-foreground ml-2">{svc.description}</span>
                      </div>
                      <code className="text-xs bg-muted px-2 py-0.5 rounded">{svc.url}</code>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── Deploy Scripts Tab ── */}
        <TabsContent value="scripts" className="space-y-4">
          {[
            { label: "Docker Compose", content: labConfig.dockerCompose, icon: Database },
            { label: "Full Deploy Script", content: labConfig.fullDeployScript, icon: Terminal },
            { label: "Install Apps", content: labConfig.installAppsScript, icon: Package },
            { label: "Provision Users", content: labConfig.provisionUsersScript, icon: Users },
            { label: "Configure Services", content: labConfig.configureScript, icon: Server },
            { label: "Status Check", content: labConfig.statusScript, icon: CheckCircle2 },
            { label: "Teardown", content: labConfig.teardownScript, icon: AlertTriangle },
          ].map(script => (
            <Card key={script.label}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <script.icon className="h-4 w-4 text-muted-foreground" />
                    {script.label}
                  </CardTitle>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => copyToClipboard(script.content, script.label)}
                  >
                    {copiedFile === script.label ? (
                      <><CheckCircle2 className="h-3 w-3 mr-1 text-green-400" /> Copied</>
                    ) : (
                      <><Copy className="h-3 w-3 mr-1" /> Copy</>
                    )}
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <pre className="text-xs bg-muted/30 p-3 rounded-lg overflow-x-auto max-h-48 overflow-y-auto font-mono">
                  {script.content.substring(0, 2000)}
                  {script.content.length > 2000 && "\n\n... (truncated, copy for full content)"}
                </pre>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        {/* ── Scope Apps Tab ── */}
        <TabsContent value="apps" className="space-y-3">
          <Card className="border-dashed">
            <CardContent className="p-4">
              <div className="flex items-center gap-4 text-sm">
                <Badge variant="outline">{labConfig.appCount} installable apps</Badge>
                <Badge variant="outline">{labConfig.bountyEligibleApps.length} total in scope</Badge>
                <Badge variant="outline">8 tiers by priority</Badge>
              </div>
            </CardContent>
          </Card>

          {Object.entries(appsByTier)
            .sort(([a], [b]) => Number(a) - Number(b))
            .map(([tier, apps]) => {
              const tierNum = Number(tier);
              const isExpanded = expandedTiers.has(tierNum);
              return (
                <Card key={tier}>
                  <CardHeader
                    className="pb-2 cursor-pointer hover:bg-muted/30 transition-colors"
                    onClick={() => toggleTier(tierNum)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                        <Badge className={TIER_COLORS[tierNum] || ""} variant="outline">
                          Tier {tier}
                        </Badge>
                        <span className="text-sm font-medium">{TIER_NAMES[tierNum] || "Other"}</span>
                        <span className="text-xs text-muted-foreground">({apps.length} apps)</span>
                      </div>
                    </div>
                  </CardHeader>
                  {isExpanded && (
                    <CardContent className="pt-0">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-1">
                        {apps.map(app => (
                          <div key={app.name} className="flex items-center justify-between p-1.5 rounded hover:bg-muted/30">
                            <div className="flex items-center gap-2">
                              <Package className="h-3 w-3 text-muted-foreground" />
                              <span className="text-sm font-mono">{app.name}</span>
                              <span className="text-xs text-muted-foreground">{app.description}</span>
                            </div>
                            <a
                              href={`https://github.com/${app.repo}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs text-blue-400 hover:underline flex items-center gap-1"
                            >
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  )}
                </Card>
              );
            })}
        </TabsContent>

        {/* ── Credentials Tab ── */}
        <TabsContent value="credentials" className="space-y-4">
          {labConfig.labInfo && (
            <>
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium">Admin Credentials</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-4 p-3 bg-muted/30 rounded-lg">
                    <Key className="h-5 w-5 text-yellow-400" />
                    <div>
                      <div className="text-sm">
                        <span className="text-muted-foreground">Username:</span>{" "}
                        <code className="font-mono">{labConfig.labInfo.adminCredentials.user}</code>
                      </div>
                      <div className="text-sm">
                        <span className="text-muted-foreground">Password:</span>{" "}
                        <code className="font-mono">{labConfig.labInfo.adminCredentials.password}</code>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="ml-auto"
                      onClick={() => copyToClipboard(
                        `${labConfig.labInfo.adminCredentials.user}:${labConfig.labInfo.adminCredentials.password}`,
                        "Admin Credentials"
                      )}
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium">Test Users</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-1">
                    {labConfig.labInfo.testUsers.map(user => (
                      <div key={user.username} className="flex items-center justify-between p-2 rounded hover:bg-muted/30">
                        <div className="flex items-center gap-3">
                          <Users className="h-4 w-4 text-muted-foreground" />
                          <code className="text-sm font-mono">{user.username}</code>
                          <span className="text-xs text-muted-foreground">{user.role}</span>
                        </div>
                        <code className="text-xs bg-muted px-2 py-0.5 rounded">{user.password}</code>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>

        {/* ── Compliance Tab ── */}
        <TabsContent value="compliance" className="space-y-4">
          <Card className="border-red-500/20">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-red-400" />
                HackerOne Program Rules
              </CardTitle>
              <CardDescription>
                These rules MUST be followed for all testing under the Nextcloud bug bounty program
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {labConfig.labInfo?.complianceNotes.map((note, i) => (
                  <div key={i} className="flex items-start gap-2 p-2 rounded bg-muted/30">
                    <Shield className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
                    <span className="text-sm">{note}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Reward Structure</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                  { severity: "Critical", amount: "$10,000", color: "text-red-400" },
                  { severity: "High", amount: "$4,000", color: "text-orange-400" },
                  { severity: "Medium", amount: "$1,500", color: "text-yellow-400" },
                  { severity: "Low", amount: "$500", color: "text-blue-400" },
                ].map(r => (
                  <div key={r.severity} className="text-center p-3 rounded-lg bg-muted/30">
                    <div className={`text-lg font-bold ${r.color}`}>{r.amount}</div>
                    <div className="text-xs text-muted-foreground">{r.severity}</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
