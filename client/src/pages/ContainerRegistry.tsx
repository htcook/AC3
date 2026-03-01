/**
 * Container Registry Management Page
 *
 * Allows users to:
 * - Add Docker/ECR/ACR/GCR/Harbor/etc. registry credentials
 * - Browse repositories and tags
 * - Scan container images for vulnerabilities
 * - View scan results with severity breakdown
 */

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  Box, Plus, Trash2, RefreshCw, Shield, AlertTriangle,
  CheckCircle, XCircle, Package, Layers, Eye, Scan,
  Server, Cloud, Lock, Loader2, ChevronRight, ExternalLink,
} from "lucide-react";

// ─── Registry Type Config ───────────────────────────────────────────

const REGISTRY_TYPES = [
  { value: "docker_hub", label: "Docker Hub", icon: "🐳", fields: ["username", "password"] },
  { value: "ecr", label: "AWS ECR", icon: "☁️", fields: ["awsAccessKeyId", "awsSecretAccessKey", "awsRegion", "awsAccountId"] },
  { value: "acr", label: "Azure ACR", icon: "☁️", fields: ["username", "password", "customUrl"] },
  { value: "gcr", label: "Google GCR", icon: "☁️", fields: ["gcpServiceAccountJson", "gcpProjectId"] },
  { value: "ghcr", label: "GitHub GHCR", icon: "🐙", fields: ["token"] },
  { value: "quay", label: "Quay.io", icon: "🔴", fields: ["username", "password"] },
  { value: "harbor", label: "Harbor", icon: "⚓", fields: ["username", "password", "customUrl"] },
  { value: "artifactory", label: "JFrog Artifactory", icon: "🐸", fields: ["username", "password", "customUrl"] },
  { value: "nexus", label: "Sonatype Nexus", icon: "📦", fields: ["username", "password", "customUrl"] },
  { value: "gitlab", label: "GitLab Registry", icon: "🦊", fields: ["username", "token", "customUrl"] },
  { value: "custom", label: "Custom Registry", icon: "🔧", fields: ["username", "password", "customUrl"] },
] as const;

const FIELD_LABELS: Record<string, string> = {
  username: "Username",
  password: "Password / Access Token",
  token: "Personal Access Token",
  awsAccessKeyId: "AWS Access Key ID",
  awsSecretAccessKey: "AWS Secret Access Key",
  awsRegion: "AWS Region",
  awsAccountId: "AWS Account ID",
  azureTenantId: "Azure Tenant ID",
  azureClientId: "Azure Client ID",
  azureClientSecret: "Azure Client Secret",
  azureSubscriptionId: "Azure Subscription ID",
  gcpServiceAccountJson: "GCP Service Account JSON",
  gcpProjectId: "GCP Project ID",
  customUrl: "Registry URL",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  negligible: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

// ─── Add Registry Dialog ────────────────────────────────────────────

function AddRegistryDialog({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false);
  const [registryType, setRegistryType] = useState<string>("docker_hub");
  const [name, setName] = useState("");
  const [authFields, setAuthFields] = useState<Record<string, string>>({});
  const addRegistry = trpc.containerRegistry.addRegistry.useMutation({
    onSuccess: (data) => {
      if (data.success) toast.success(`Registry Added: ${data.message}`);
      else toast.error(`Registry Added (Connection Failed): ${data.message}`);
      setOpen(false);
      setName("");
      setAuthFields({});
      onSuccess();
    },
    onError: (err) => {
      toast.error(err.message);
    },
  });

  const selectedType = REGISTRY_TYPES.find(t => t.value === registryType);
  const fields = selectedType?.fields || [];

  const handleSubmit = () => {
    if (!name.trim()) {
      toast.error("Registry name is required");
      return;
    }

    addRegistry.mutate({
      registryType: registryType as any,
      name: name.trim(),
      registryUrl: authFields.customUrl || "",
      authConfig: authFields,
    });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="gap-2">
          <Plus className="h-4 w-4" />
          Add Registry
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Server className="h-5 w-5 text-cyan-400" />
            Add Container Registry
          </DialogTitle>
          <DialogDescription>
            Connect a container registry to scan private images for vulnerabilities.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 mt-4">
          <div>
            <Label>Registry Type</Label>
            <Select value={registryType} onValueChange={(v) => { setRegistryType(v); setAuthFields({}); }}>
              <SelectTrigger className="mt-1">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {REGISTRY_TYPES.map(t => (
                  <SelectItem key={t.value} value={t.value}>
                    <span className="flex items-center gap-2">
                      <span>{t.icon}</span>
                      <span>{t.label}</span>
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div>
            <Label>Display Name</Label>
            <Input
              className="mt-1"
              placeholder="e.g., Production ECR, Staging Harbor"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          {fields.map(field => (
            <div key={field}>
              <Label>{FIELD_LABELS[field] || field}</Label>
              {field === "gcpServiceAccountJson" ? (
                <Textarea
                  className="mt-1 font-mono text-xs"
                  placeholder='{"type": "service_account", ...}'
                  rows={4}
                  value={authFields[field] || ""}
                  onChange={(e) => setAuthFields(prev => ({ ...prev, [field]: e.target.value }))}
                />
              ) : (
                <Input
                  className="mt-1"
                  type={field.includes("secret") || field.includes("password") || field === "token" ? "password" : "text"}
                  placeholder={field === "awsRegion" ? "us-east-1" : field === "customUrl" ? "https://registry.example.com" : ""}
                  value={authFields[field] || ""}
                  onChange={(e) => setAuthFields(prev => ({ ...prev, [field]: e.target.value }))}
                />
              )}
            </div>
          ))}

          <Button
            className="w-full gap-2"
            onClick={handleSubmit}
            disabled={addRegistry.isPending}
          >
            {addRegistry.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Lock className="h-4 w-4" />
            )}
            {addRegistry.isPending ? "Connecting..." : "Test & Save Credentials"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Registry Card ──────────────────────────────────────────────────

function RegistryCard({
  registry,
  onRefresh,
  onSelect,
}: {
  registry: any;
  onRefresh: () => void;
  onSelect: (id: number) => void;
}) {
  const testConnection = trpc.containerRegistry.testConnection.useMutation({
    onSuccess: (result) => {
      if (result.success) toast.success(`Connection OK: ${result.message}`);
      else toast.error(`Connection Failed: ${result.message}`);
      onRefresh();
    },
  });

  const deleteRegistry = trpc.containerRegistry.deleteRegistry.useMutation({
    onSuccess: () => {
      toast.success("Registry Removed");
      onRefresh();
    },
  });

  const typeConfig = REGISTRY_TYPES.find(t => t.value === registry.registryType);

  return (
    <Card
      className="cursor-pointer hover:border-cyan-500/50 transition-colors"
      onClick={() => onSelect(registry.id)}
    >
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="text-2xl">{typeConfig?.icon || "📦"}</div>
            <div>
              <h3 className="font-semibold text-sm">{registry.name}</h3>
              <p className="text-xs text-muted-foreground mt-0.5">
                {typeConfig?.label || registry.registryType}
              </p>
              {registry.registryUrl && (
                <p className="text-xs text-muted-foreground/70 font-mono mt-0.5 truncate max-w-[200px]">
                  {registry.registryUrl}
                </p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-1">
            <Badge
              variant="outline"
              className={
                registry.status === "active"
                  ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                  : registry.status === "error"
                  ? "bg-red-500/20 text-red-400 border-red-500/30"
                  : "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
              }
            >
              {registry.status === "active" ? (
                <CheckCircle className="h-3 w-3 mr-1" />
              ) : registry.status === "error" ? (
                <XCircle className="h-3 w-3 mr-1" />
              ) : (
                <RefreshCw className="h-3 w-3 mr-1" />
              )}
              {registry.status}
            </Badge>
          </div>
        </div>

        <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Package className="h-3 w-3" />
            {registry.repoCount || 0} repos
          </span>
          <span className="flex items-center gap-1">
            <Scan className="h-3 w-3" />
            {registry.imageCount || 0} scans
          </span>
          {registry.lastValidated && (
            <span>
              Validated {new Date(registry.lastValidated).toLocaleDateString()}
            </span>
          )}
        </div>

        {registry.lastError && (
          <p className="text-xs text-red-400 mt-2 truncate">{registry.lastError}</p>
        )}

        <div className="flex items-center gap-2 mt-3" onClick={(e) => e.stopPropagation()}>
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs gap-1"
            onClick={() => testConnection.mutate({ registryId: registry.id })}
            disabled={testConnection.isPending}
          >
            {testConnection.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
            Test
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs gap-1"
            onClick={() => onSelect(registry.id)}
          >
            <Eye className="h-3 w-3" />
            Browse
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs gap-1 text-red-400 hover:text-red-300"
            onClick={() => {
              if (confirm("Remove this registry?")) {
                deleteRegistry.mutate({ registryId: registry.id });
              }
            }}
          >
            <Trash2 className="h-3 w-3" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Repository Browser ─────────────────────────────────────────────

function RepositoryBrowser({
  registryId,
  onBack,
}: {
  registryId: number;
  onBack: () => void;
}) {
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
  const [scanningTag, setScanningTag] = useState<string | null>(null);
  const repos = trpc.containerRegistry.listRepos.useQuery({ registryId });
  const tags = trpc.containerRegistry.listTags.useQuery(
    { registryId, repository: selectedRepo! },
    { enabled: !!selectedRepo }
  );

  const scanImage = trpc.containerRegistry.scanImage.useMutation({
    onSuccess: (result) => {
      setScanningTag(null);
      if (result.criticalCount > 0) toast.error(`Scan Complete: ${result.totalVulnerabilities} vulns (${result.criticalCount} critical)`);
      else if (result.totalVulnerabilities > 0) toast.warning(`Scan Complete: ${result.totalVulnerabilities} vulnerabilities found`);
      else toast.success("Scan Complete — Clean image");
    },
    onError: (err) => {
      setScanningTag(null);
      toast.error(`Scan Failed: ${err.message}`);
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" onClick={onBack} className="gap-1">
          ← Back
        </Button>
        {selectedRepo && (
          <>
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
            <Button variant="ghost" size="sm" onClick={() => setSelectedRepo(null)}>
              Repositories
            </Button>
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-mono">{selectedRepo}</span>
          </>
        )}
      </div>

      {!selectedRepo ? (
        // Repository list
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
            Repositories ({repos.data?.length || 0})
          </h3>
          {repos.isLoading ? (
            <div className="flex items-center gap-2 text-muted-foreground py-8 justify-center">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading repositories...
            </div>
          ) : repos.data?.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Package className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No repositories found or catalog access restricted.</p>
              <p className="text-xs mt-1">Try entering a repository name manually.</p>
            </div>
          ) : (
            <div className="grid gap-2">
              {repos.data?.map((repo) => (
                <Card
                  key={repo.fullName}
                  className="cursor-pointer hover:border-cyan-500/50 transition-colors"
                  onClick={() => setSelectedRepo(repo.fullName)}
                >
                  <CardContent className="p-3 flex items-center justify-between">
                    <div>
                      <p className="font-mono text-sm">{repo.fullName}</p>
                      {repo.description && (
                        <p className="text-xs text-muted-foreground mt-0.5">{repo.description}</p>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {repo.isPrivate && (
                        <Badge variant="outline" className="text-xs">
                          <Lock className="h-3 w-3 mr-1" />
                          Private
                        </Badge>
                      )}
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {/* Manual repo entry */}
          <Card className="border-dashed">
            <CardContent className="p-3">
              <ManualRepoEntry
                onSelect={(repo) => setSelectedRepo(repo)}
              />
            </CardContent>
          </Card>
        </div>
      ) : (
        // Tag list
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
            Tags for {selectedRepo}
          </h3>
          {tags.isLoading ? (
            <div className="flex items-center gap-2 text-muted-foreground py-8 justify-center">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading tags...
            </div>
          ) : tags.data?.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Layers className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No tags found.</p>
            </div>
          ) : (
            <div className="grid gap-2">
              {tags.data?.map((tag) => (
                <Card key={tag.name}>
                  <CardContent className="p-3 flex items-center justify-between">
                    <div>
                      <p className="font-mono text-sm">{tag.name}</p>
                      <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                        {tag.digest && <span className="font-mono">{tag.digest.slice(0, 19)}</span>}
                        {tag.size && <span>{(tag.size / 1024 / 1024).toFixed(1)} MB</span>}
                        {tag.lastModified && <span>{new Date(tag.lastModified).toLocaleDateString()}</span>}
                      </div>
                    </div>
                    <Button
                      size="sm"
                      className="gap-1"
                      disabled={scanImage.isPending && scanningTag === tag.name}
                      onClick={() => {
                        setScanningTag(tag.name);
                        scanImage.mutate({
                          registryId,
                          repository: selectedRepo,
                          tag: tag.name,
                          enrichNvd: false,
                        });
                      }}
                    >
                      {scanImage.isPending && scanningTag === tag.name ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <Scan className="h-3 w-3" />
                      )}
                      Scan
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ManualRepoEntry({ onSelect }: { onSelect: (repo: string) => void }) {
  const [repo, setRepo] = useState("");
  return (
    <div className="flex items-center gap-2">
      <Input
        placeholder="Enter repository name (e.g., library/nginx)"
        value={repo}
        onChange={(e) => setRepo(e.target.value)}
        className="text-sm"
        onKeyDown={(e) => {
          if (e.key === "Enter" && repo.trim()) onSelect(repo.trim());
        }}
      />
      <Button
        variant="outline"
        size="sm"
        disabled={!repo.trim()}
        onClick={() => onSelect(repo.trim())}
      >
        Browse
      </Button>
    </div>
  );
}

// ─── Scan Results View ──────────────────────────────────────────────

function ScanResultsView() {
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const scans = trpc.containerRegistry.listScans.useQuery({});
  const scanDetail = trpc.containerRegistry.getScan.useQuery(
    { scanId: selectedScanId! },
    { enabled: !!selectedScanId }
  );

  if (selectedScanId && scanDetail.data) {
    const scan = scanDetail.data;
    const vulns = (scan.vulnerabilities as any[]) || [];
    const packages = (scan.packages as any[]) || [];
    const compliance = (scan.complianceIssues as any[]) || [];
    const layers = (scan.layers as any[]) || [];

    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" onClick={() => setSelectedScanId(null)} className="gap-1">
          ← Back to Scans
        </Button>

        {/* Summary */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-lg flex items-center gap-2">
              <Shield className="h-5 w-5 text-cyan-400" />
              {scan.repository}:{scan.tag}
            </CardTitle>
            <CardDescription>
              {scan.digest?.slice(0, 19)} · {scan.architecture}/{scan.os} · {scan.scanDurationMs}ms
              {scan.baseImage && ` · Base: ${scan.baseImage}`}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
              {[
                { label: "Critical", count: scan.criticalCount, color: "text-red-400" },
                { label: "High", count: scan.highCount, color: "text-orange-400" },
                { label: "Medium", count: scan.mediumCount, color: "text-yellow-400" },
                { label: "Low", count: scan.lowCount, color: "text-blue-400" },
                { label: "Fixable", count: scan.fixedAvailable, color: "text-emerald-400" },
                { label: "Packages", count: packages.length, color: "text-purple-400" },
              ].map(({ label, count, color }) => (
                <div key={label} className="text-center p-2 rounded-lg bg-muted/30">
                  <div className={`text-2xl font-bold ${color}`}>{count}</div>
                  <div className="text-xs text-muted-foreground">{label}</div>
                </div>
              ))}
            </div>

            {scan.malwareDetected && (
              <div className="mt-3 p-2 rounded bg-red-500/20 border border-red-500/30 text-red-400 text-sm flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" />
                Malware detected in image
              </div>
            )}
            {(scan.secretsDetected || 0) > 0 && (
              <div className="mt-2 p-2 rounded bg-orange-500/20 border border-orange-500/30 text-orange-400 text-sm flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" />
                {scan.secretsDetected} potential secrets detected
              </div>
            )}
          </CardContent>
        </Card>

        {/* Vulnerabilities */}
        {vulns.length > 0 && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Vulnerabilities ({vulns.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-[400px] overflow-y-auto">
                {vulns.sort((a, b) => {
                  const order = { critical: 0, high: 1, medium: 2, low: 3, negligible: 4 };
                  return (order[a.severity as keyof typeof order] || 4) - (order[b.severity as keyof typeof order] || 4);
                }).map((v: any, i: number) => (
                  <div key={i} className="flex items-start justify-between p-2 rounded bg-muted/20 border border-border/50">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={SEVERITY_COLORS[v.severity] || ""}>
                          {v.severity}
                        </Badge>
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${v.cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-mono text-sm text-cyan-400 hover:underline flex items-center gap-1"
                        >
                          {v.cveId}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                        {v.cvssScore && (
                          <span className="text-xs text-muted-foreground">CVSS {v.cvssScore}</span>
                        )}
                      </div>
                      {v.title && <p className="text-xs text-muted-foreground mt-1">{v.title}</p>}
                      <div className="flex items-center gap-3 text-xs mt-1">
                        <span className="text-muted-foreground">
                          <Package className="h-3 w-3 inline mr-1" />
                          {v.packageName} {v.installedVersion}
                        </span>
                        {v.fixedVersion && (
                          <span className="text-emerald-400">
                            Fix: {v.fixedVersion}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Compliance */}
        {compliance.length > 0 && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">
                Compliance Checks ({compliance.filter((c: any) => c.status === "pass").length}/{compliance.length} passed)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-1">
                {compliance.map((c: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 p-2 rounded bg-muted/20">
                    {c.status === "pass" ? (
                      <CheckCircle className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
                    )}
                    <div>
                      <p className="text-xs font-medium">{c.check}</p>
                      <p className="text-xs text-muted-foreground">{c.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Layers */}
        {layers.length > 0 && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Image Layers ({layers.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-1 max-h-[300px] overflow-y-auto">
                {layers.map((l: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 p-2 rounded bg-muted/20 text-xs">
                    <Layers className="h-3 w-3 text-muted-foreground mt-0.5 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <span className="text-muted-foreground">{(l.size / 1024 / 1024).toFixed(1)} MB</span>
                      {l.command && (
                        <p className="font-mono text-xs text-muted-foreground/70 truncate mt-0.5">{l.command}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    );
  }

  // Scan list
  return (
    <div className="space-y-3">
      {scans.isLoading ? (
        <div className="flex items-center gap-2 text-muted-foreground py-8 justify-center">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading scan history...
        </div>
      ) : scans.data?.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          <Scan className="h-10 w-10 mx-auto mb-3 opacity-50" />
          <p className="font-medium">No scans yet</p>
          <p className="text-sm mt-1">Add a registry and scan an image to see results here.</p>
        </div>
      ) : (
        scans.data?.map((scan) => (
          <Card
            key={scan.id}
            className="cursor-pointer hover:border-cyan-500/50 transition-colors"
            onClick={() => setSelectedScanId(scan.id)}
          >
            <CardContent className="p-4">
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-mono text-sm font-medium">{scan.repository}:{scan.tag}</p>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground mt-1">
                    {scan.digest && <span className="font-mono">{scan.digest.slice(0, 19)}</span>}
                    {scan.architecture && <span>{scan.architecture}/{scan.os}</span>}
                    <span>{new Date(scan.createdAt).toLocaleString()}</span>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  {scan.criticalCount! > 0 && (
                    <Badge variant="outline" className={SEVERITY_COLORS.critical}>
                      {scan.criticalCount} C
                    </Badge>
                  )}
                  {scan.highCount! > 0 && (
                    <Badge variant="outline" className={SEVERITY_COLORS.high}>
                      {scan.highCount} H
                    </Badge>
                  )}
                  {scan.mediumCount! > 0 && (
                    <Badge variant="outline" className={SEVERITY_COLORS.medium}>
                      {scan.mediumCount} M
                    </Badge>
                  )}
                  {scan.lowCount! > 0 && (
                    <Badge variant="outline" className={SEVERITY_COLORS.low}>
                      {scan.lowCount} L
                    </Badge>
                  )}
                  {scan.totalVulnerabilities === 0 && (
                    <Badge variant="outline" className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
                      Clean
                    </Badge>
                  )}
                </div>
              </div>
              {scan.malwareDetected && (
                <div className="mt-2 text-xs text-red-400 flex items-center gap-1">
                  <AlertTriangle className="h-3 w-3" />
                  Malware detected
                </div>
              )}
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────

export default function ContainerRegistry() {
  const [selectedRegistryId, setSelectedRegistryId] = useState<number | null>(null);
  const registries = trpc.containerRegistry.listRegistries.useQuery();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <Box className="h-6 w-6 text-cyan-400" />
            Container Registry Scanner
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Connect private registries to scan container images for vulnerabilities, misconfigurations, and secrets.
          </p>
        </div>
        <AddRegistryDialog onSuccess={() => registries.refetch()} />
      </div>

      <Tabs defaultValue="registries">
        <TabsList>
          <TabsTrigger value="registries" className="gap-1">
            <Server className="h-4 w-4" />
            Registries
          </TabsTrigger>
          <TabsTrigger value="scans" className="gap-1">
            <Scan className="h-4 w-4" />
            Scan History
          </TabsTrigger>
        </TabsList>

        <TabsContent value="registries" className="mt-4">
          {selectedRegistryId ? (
            <RepositoryBrowser
              registryId={selectedRegistryId}
              onBack={() => setSelectedRegistryId(null)}
            />
          ) : (
            <div className="space-y-4">
              {registries.isLoading ? (
                <div className="flex items-center gap-2 text-muted-foreground py-8 justify-center">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Loading registries...
                </div>
              ) : registries.data?.length === 0 ? (
                <Card className="border-dashed">
                  <CardContent className="py-12 text-center">
                    <Cloud className="h-10 w-10 mx-auto mb-3 text-muted-foreground/50" />
                    <h3 className="font-medium">No registries connected</h3>
                    <p className="text-sm text-muted-foreground mt-1 max-w-md mx-auto">
                      Add a Docker Hub, AWS ECR, Azure ACR, Google GCR, or other container registry
                      to scan private images for vulnerabilities.
                    </p>
                  </CardContent>
                </Card>
              ) : (
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {registries.data?.map((reg) => (
                    <RegistryCard
                      key={reg.id}
                      registry={reg}
                      onRefresh={() => registries.refetch()}
                      onSelect={setSelectedRegistryId}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </TabsContent>

        <TabsContent value="scans" className="mt-4">
          <ScanResultsView />
        </TabsContent>
      </Tabs>
    </div>
  );
}
