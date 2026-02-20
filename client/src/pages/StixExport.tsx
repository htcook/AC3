import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Download, FileJson, Shield, Bug, Crosshair,
  Server, Database, Copy,
  AlertTriangle, Loader2,
  Package, Eye
} from "lucide-react";

interface ExportResult {
  bundle: any;
  stats: {
    totalObjects: number;
    byType: Record<string, number>;
    bundleSize: number;
    generatedAt: string;
  };
  [key: string]: any;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function StixExport() {
  const [exportResult, setExportResult] = useState<ExportResult | null>(null);
  const [showPreview, setShowPreview] = useState(false);

  // Filters
  const [actorType, setActorType] = useState("all");
  const [actorThreatLevel, setActorThreatLevel] = useState("all");
  const [actorLimit, setActorLimit] = useState(100);
  const [iocSource, setIocSource] = useState("all");
  const [iocSeverity, setIocSeverity] = useState("all");
  const [iocLimit, setIocLimit] = useState(200);
  const [vulnSeverity, setVulnSeverity] = useState("all");
  const [vulnLimit, setVulnLimit] = useState(200);
  const [campaignStatus, setCampaignStatus] = useState("all");

  const statsQuery = trpc.stixExport.stats.useQuery();

  const exportActors = trpc.stixExport.exportThreatActors.useMutation({
    onSuccess: (data) => {
      setExportResult(data);
      setShowPreview(true);
      toast.success(`STIX Bundle: ${data.stats.totalObjects} objects (${data.exportedActors} actors, ${data.exportedIocs} IOCs)`);
    },
    onError: (err) => toast.error(`Export Failed: ${err.message}`),
  });

  const exportIocs = trpc.stixExport.exportIocFeed.useMutation({
    onSuccess: (data) => {
      setExportResult(data);
      setShowPreview(true);
      toast.success(`STIX Bundle: ${data.stats.totalObjects} objects from ${data.exportedEntries} feed entries`);
    },
    onError: (err) => toast.error(`Export Failed: ${err.message}`),
  });

  const exportVulns = trpc.stixExport.exportVulnerabilities.useMutation({
    onSuccess: (data) => {
      setExportResult(data);
      setShowPreview(true);
      toast.success(`STIX Bundle: ${data.stats.totalObjects} objects (${data.exportedExploits} exploits, ${data.exportedKev} KEV)`);
    },
    onError: (err) => toast.error(`Export Failed: ${err.message}`),
  });

  const exportCampaigns = trpc.stixExport.exportCampaigns.useMutation({
    onSuccess: (data) => {
      setExportResult(data);
      setShowPreview(true);
      toast.success(`STIX Bundle: ${data.stats.totalObjects} objects from ${data.exportedCampaigns} campaigns`);
    },
    onError: (err) => toast.error(`Export Failed: ${err.message}`),
  });

  const exportAll = trpc.stixExport.exportAll.useMutation({
    onSuccess: (data) => {
      setExportResult(data);
      setShowPreview(true);
      toast.success(`Complete STIX Bundle: ${data.stats.totalObjects} objects across all collections`);
    },
    onError: (err) => toast.error(`Export Failed: ${err.message}`),
  });

  const isExporting = exportActors.isPending || exportIocs.isPending || exportVulns.isPending || exportCampaigns.isPending || exportAll.isPending;

  function downloadBundle() {
    if (!exportResult?.bundle) return;
    const json = JSON.stringify(exportResult.bundle, null, 2);
    const blob = new Blob([json], { type: "application/stix+json;version=2.1" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ace-c3-stix-bundle-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("STIX bundle saved as JSON");
  }

  function copyBundle() {
    if (!exportResult?.bundle) return;
    navigator.clipboard.writeText(JSON.stringify(exportResult.bundle, null, 2));
    toast.success("STIX bundle copied to clipboard");
  }

  const stats = statsQuery.data;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight flex items-center gap-3">
            <FileJson className="h-7 w-7 sm:h-8 sm:w-8 text-cyan-400" />
            STIX/TAXII Export
          </h1>
          <p className="text-muted-foreground mt-1 text-sm sm:text-base">
            Export threat intelligence as STIX 2.1 bundles for ISACs, SOC teams, and partner organizations
          </p>
        </div>
        <Button
          onClick={() => exportAll.mutate({ maxActors: 50, maxIocs: 100, maxExploits: 50, maxEngagements: 20 })}
          disabled={isExporting}
          className="bg-cyan-600 hover:bg-cyan-700"
        >
          {exportAll.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Package className="h-4 w-4 mr-2" />}
          Export All Intelligence
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <StatCard icon={<Shield className="h-4 w-4 text-red-400" />} label="Threat Actors" value={stats?.dataCounts.threatActors} />
        <StatCard icon={<AlertTriangle className="h-4 w-4 text-amber-400" />} label="IOCs" value={stats?.dataCounts.iocs} />
        <StatCard icon={<Database className="h-4 w-4 text-blue-400" />} label="Feed Entries" value={stats?.dataCounts.feedEntries} />
        <StatCard icon={<Crosshair className="h-4 w-4 text-green-400" />} label="Engagements" value={stats?.dataCounts.engagements} />
        <StatCard icon={<Bug className="h-4 w-4 text-purple-400" />} label="Exploits" value={stats?.dataCounts.exploits} />
      </div>

      {/* Main Tabs */}
      <Tabs defaultValue="collections" className="space-y-4">
        <TabsList className="flex flex-wrap h-auto gap-1">
          <TabsTrigger value="collections" className="text-xs sm:text-sm">Collections</TabsTrigger>
          <TabsTrigger value="actors" className="text-xs sm:text-sm">Threat Actors</TabsTrigger>
          <TabsTrigger value="iocs" className="text-xs sm:text-sm">IOC Feed</TabsTrigger>
          <TabsTrigger value="vulns" className="text-xs sm:text-sm">Vulnerabilities</TabsTrigger>
          <TabsTrigger value="campaigns" className="text-xs sm:text-sm">Campaigns</TabsTrigger>
          <TabsTrigger value="taxii" className="text-xs sm:text-sm">TAXII API</TabsTrigger>
        </TabsList>

        {/* Collections Tab */}
        <TabsContent value="collections" className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {stats?.collections?.map((col: any) => (
              <Card key={col.id} className="bg-card/50 border-border/50 hover:border-cyan-500/30 transition-colors">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Server className="h-4 w-4 text-cyan-400" />
                    {col.title}
                  </CardTitle>
                  <CardDescription className="text-xs">{col.description}</CardDescription>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="flex items-center gap-2 mt-2">
                    <Badge variant="outline" className="text-[10px]">{col.can_read ? "READ" : "NO READ"}</Badge>
                    <Badge variant="outline" className="text-[10px]">{col.media_types[0]}</Badge>
                  </div>
                </CardContent>
              </Card>
            )) ?? (
              <div className="col-span-full text-center text-muted-foreground py-8">Loading collections...</div>
            )}
          </div>
        </TabsContent>

        {/* Threat Actors Export Tab */}
        <TabsContent value="actors" className="space-y-4">
          <Card className="bg-card/50 border-border/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Shield className="h-5 w-5 text-red-400" />
                Export Threat Actors
              </CardTitle>
              <CardDescription>Generate STIX 2.1 Intrusion Set objects from threat actor profiles with associated attack patterns, malware, and tools</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Actor Type</label>
                  <Select value={actorType} onValueChange={setActorType}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Types</SelectItem>
                      <SelectItem value="apt">APT</SelectItem>
                      <SelectItem value="cybercrime">Cybercrime</SelectItem>
                      <SelectItem value="ransomware">Ransomware</SelectItem>
                      <SelectItem value="hacktivist">Hacktivist</SelectItem>
                      <SelectItem value="access_broker">Access Broker</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Threat Level</label>
                  <Select value={actorThreatLevel} onValueChange={setActorThreatLevel}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Levels</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Max Results</label>
                  <Select value={String(actorLimit)} onValueChange={(v) => setActorLimit(Number(v))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="25">25</SelectItem>
                      <SelectItem value="50">50</SelectItem>
                      <SelectItem value="100">100</SelectItem>
                      <SelectItem value="200">200</SelectItem>
                      <SelectItem value="500">500</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <Button
                onClick={() => exportActors.mutate({ type: actorType, threatLevel: actorThreatLevel, limit: actorLimit, search: "" })}
                disabled={isExporting}
                className="w-full sm:w-auto"
              >
                {exportActors.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Download className="h-4 w-4 mr-2" />}
                Generate STIX Bundle
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* IOC Feed Export Tab */}
        <TabsContent value="iocs" className="space-y-4">
          <Card className="bg-card/50 border-border/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-amber-400" />
                Export IOC Feed
              </CardTitle>
              <CardDescription>Generate STIX 2.1 Indicator objects from IOC feeds (threat intelligence feeds, malware indicators, KEV)</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Feed Source</label>
                  <Select value={iocSource} onValueChange={setIocSource}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Sources</SelectItem>
                      <SelectItem value="cisa_kev">KEV</SelectItem>
                      <SelectItem value="abusech_urlhaus">URLhaus Feed</SelectItem>
                      <SelectItem value="abusech_malwarebazaar">MalwareBazaar Feed</SelectItem>
                      <SelectItem value="abusech_threatfox">Malware Indicator Feed</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Severity</label>
                  <Select value={iocSeverity} onValueChange={setIocSeverity}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Severities</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Max Results</label>
                  <Select value={String(iocLimit)} onValueChange={(v) => setIocLimit(Number(v))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="50">50</SelectItem>
                      <SelectItem value="100">100</SelectItem>
                      <SelectItem value="200">200</SelectItem>
                      <SelectItem value="500">500</SelectItem>
                      <SelectItem value="1000">1000</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <Button
                onClick={() => exportIocs.mutate({ feedSource: iocSource, severity: iocSeverity, limit: iocLimit, search: "" })}
                disabled={isExporting}
                className="w-full sm:w-auto"
              >
                {exportIocs.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Download className="h-4 w-4 mr-2" />}
                Generate STIX Bundle
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Vulnerabilities Export Tab */}
        <TabsContent value="vulns" className="space-y-4">
          <Card className="bg-card/50 border-border/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Bug className="h-5 w-5 text-purple-400" />
                Export Vulnerabilities
              </CardTitle>
              <CardDescription>Generate STIX 2.1 Vulnerability and Attack Pattern objects from exploit catalog and known exploited vulnerabilities (KEV)</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Severity</label>
                  <Select value={vulnSeverity} onValueChange={setVulnSeverity}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Severities</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Max Results</label>
                  <Select value={String(vulnLimit)} onValueChange={(v) => setVulnLimit(Number(v))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="50">50</SelectItem>
                      <SelectItem value="100">100</SelectItem>
                      <SelectItem value="200">200</SelectItem>
                      <SelectItem value="500">500</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <Button
                onClick={() => exportVulns.mutate({ severity: vulnSeverity, limit: vulnLimit, source: "all" })}
                disabled={isExporting}
                className="w-full sm:w-auto"
              >
                {exportVulns.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Download className="h-4 w-4 mr-2" />}
                Generate STIX Bundle
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Campaigns Export Tab */}
        <TabsContent value="campaigns" className="space-y-4">
          <Card className="bg-card/50 border-border/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Crosshair className="h-5 w-5 text-green-400" />
                Export Campaigns
              </CardTitle>
              <CardDescription>Generate STIX 2.1 Campaign objects from red team engagements</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Status</label>
                  <Select value={campaignStatus} onValueChange={setCampaignStatus}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Statuses</SelectItem>
                      <SelectItem value="planning">Planning</SelectItem>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="completed">Completed</SelectItem>
                      <SelectItem value="archived">Archived</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <Button
                onClick={() => exportCampaigns.mutate({ status: campaignStatus, limit: 50 })}
                disabled={isExporting}
                className="w-full sm:w-auto"
              >
                {exportCampaigns.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Download className="h-4 w-4 mr-2" />}
                Generate STIX Bundle
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* TAXII API Tab */}
        <TabsContent value="taxii" className="space-y-4">
          <Card className="bg-card/50 border-border/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Server className="h-5 w-5 text-cyan-400" />
                TAXII 2.1 API
              </CardTitle>
              <CardDescription>
                TAXII (Trusted Automated eXchange of Intelligence Information) endpoints for automated intel sharing.
                Compatible with OpenCTI, MISP, ThreatConnect, and other TAXII clients.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3">
                <TaxiiEndpoint
                  method="GET"
                  path="/api/trpc/stixExport.taxiiDiscovery"
                  description="TAXII Discovery — returns server info and API roots"
                />
                <TaxiiEndpoint
                  method="GET"
                  path="/api/trpc/stixExport.taxiiApiRoot"
                  description="API Root — returns supported versions and content limits"
                />
                <TaxiiEndpoint
                  method="GET"
                  path="/api/trpc/stixExport.taxiiCollections"
                  description="Collections — lists all available intelligence collections"
                />
                <TaxiiEndpoint
                  method="GET"
                  path={`/api/trpc/stixExport.taxiiGetCollection?input={"collectionId":"ace-c3-threat-actors"}`}
                  description="Get Collection — returns metadata for a specific collection"
                />
                <TaxiiEndpoint
                  method="GET"
                  path={`/api/trpc/stixExport.taxiiGetObjects?input={"collectionId":"ace-c3-all","limit":50}`}
                  description="Get Objects — returns STIX objects from a collection (requires auth)"
                />
              </div>

              <div className="mt-6 p-4 bg-muted/30 rounded-lg border border-border/50">
                <h4 className="text-sm font-semibold mb-2">Integration Example</h4>
                <pre className="text-xs text-muted-foreground overflow-x-auto whitespace-pre-wrap">
{`# Fetch STIX bundle from Ace C3 TAXII endpoint
curl -H "Content-Type: application/taxii+json;version=2.1" \\
     -H "Authorization: Bearer <your-session-token>" \\
     "/api/trpc/stixExport.taxiiGetObjects?input={\\"collectionId\\":\\"ace-c3-all\\",\\"limit\\":100}"

# Import into OpenCTI
# Configure a TAXII connector pointing to the Ace C3 API root`}
                </pre>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Export Result Preview */}
      {showPreview && exportResult && (
        <Card className="bg-card/50 border-cyan-500/30">
          <CardHeader>
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <CardTitle className="text-lg flex items-center gap-2">
                <Eye className="h-5 w-5 text-cyan-400" />
                Export Result
              </CardTitle>
              <div className="flex gap-2 flex-wrap">
                <Button size="sm" variant="outline" onClick={copyBundle}>
                  <Copy className="h-3 w-3 mr-1" /> Copy JSON
                </Button>
                <Button size="sm" onClick={downloadBundle} className="bg-cyan-600 hover:bg-cyan-700">
                  <Download className="h-3 w-3 mr-1" /> Download .json
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Stats Summary */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 bg-muted/30 rounded-lg">
                <p className="text-xs text-muted-foreground">Total Objects</p>
                <p className="text-xl font-bold">{exportResult.stats.totalObjects}</p>
              </div>
              <div className="p-3 bg-muted/30 rounded-lg">
                <p className="text-xs text-muted-foreground">Bundle Size</p>
                <p className="text-xl font-bold">{formatBytes(exportResult.stats.bundleSize)}</p>
              </div>
              <div className="p-3 bg-muted/30 rounded-lg">
                <p className="text-xs text-muted-foreground">Object Types</p>
                <p className="text-xl font-bold">{Object.keys(exportResult.stats.byType).length}</p>
              </div>
              <div className="p-3 bg-muted/30 rounded-lg">
                <p className="text-xs text-muted-foreground">Generated</p>
                <p className="text-sm font-medium">{new Date(exportResult.stats.generatedAt).toLocaleTimeString()}</p>
              </div>
            </div>

            {/* Type Breakdown */}
            <div className="flex flex-wrap gap-2">
              {Object.entries(exportResult.stats.byType).map(([type, count]) => (
                <Badge key={type} variant="outline" className="text-xs">
                  {type}: {count as number}
                </Badge>
              ))}
            </div>

            {/* JSON Preview */}
            <div className="relative">
              <pre className="text-xs text-muted-foreground bg-muted/20 p-4 rounded-lg overflow-x-auto max-h-96 overflow-y-auto border border-border/30">
                {JSON.stringify(exportResult.bundle, null, 2).slice(0, 5000)}
                {JSON.stringify(exportResult.bundle, null, 2).length > 5000 && "\n\n... (truncated — download for full bundle)"}
              </pre>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ icon, label, value }: { icon: React.ReactNode; label: string; value?: number | null }) {
  return (
    <Card className="bg-card/50 border-border/50">
      <CardContent className="p-3 sm:p-4">
        <div className="flex items-center gap-2 mb-1">
          {icon}
          <span className="text-xs text-muted-foreground">{label}</span>
        </div>
        <p className="text-xl sm:text-2xl font-bold">{value ?? "—"}</p>
      </CardContent>
    </Card>
  );
}

function TaxiiEndpoint({ method, path, description }: { method: string; path: string; description: string }) {
  return (
    <div className="p-3 bg-muted/20 rounded-lg border border-border/30">
      <div className="flex items-start gap-2">
        <Badge className="bg-green-600/20 text-green-400 border-green-500/30 text-[10px] shrink-0">{method}</Badge>
        <div className="min-w-0">
          <code className="text-xs text-cyan-300 break-all">{path}</code>
          <p className="text-xs text-muted-foreground mt-1">{description}</p>
        </div>
      </div>
    </div>
  );
}
