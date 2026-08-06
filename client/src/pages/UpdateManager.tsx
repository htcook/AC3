import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import {
  ArrowUpCircle,
  Package,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Plus,
  Download,
  History,
  FileText,
  Rocket,
} from "lucide-react";

// ─── Publish Version Dialog ─────────────────────────────────────────────────

function PublishVersionDialog({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false);
  const [version, setVersion] = useState("");
  const [changelog, setChangelog] = useState("");
  const [downloadUrl, setDownloadUrl] = useState("");
  const [migrationScript, setMigrationScript] = useState("");
  const [isBreaking, setIsBreaking] = useState(false);
  const [isRequired, setIsRequired] = useState(false);
  const { toast } = useToast();

  const publishMutation = trpc.licenseAdmin.publishVersion.useMutation({
    onSuccess: () => {
      toast({ title: "Version Published", description: `Version ${version} published to stable channel.` });
      setOpen(false);
      setVersion("");
      setChangelog("");
      setDownloadUrl("");
      setMigrationScript("");
      setIsBreaking(false);
      setIsRequired(false);
      onSuccess();
    },
    onError: (err) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="gap-2">
          <Plus className="h-4 w-4" />
          Publish Version
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Publish New Version</DialogTitle>
          <DialogDescription>
            Create a new release that customer deployments can update to.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          <div className="grid gap-2">
            <Label htmlFor="version">Version *</Label>
            <Input id="version" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="2.5.0" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="changelog">Changelog *</Label>
            <Textarea
              id="changelog"
              value={changelog}
              onChange={(e) => setChangelog(e.target.value)}
              placeholder="## What's New&#10;- Feature A&#10;- Bug fix B&#10;&#10;## Breaking Changes&#10;- None"
              rows={6}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="downloadUrl">Download URL</Label>
            <Input id="downloadUrl" value={downloadUrl} onChange={(e) => setDownloadUrl(e.target.value)} placeholder="https://releases.aceofcloud.com/ac3/v2.5.0.tar.gz" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="migration">Migration SQL (optional)</Label>
            <Textarea
              id="migration"
              value={migrationScript}
              onChange={(e) => setMigrationScript(e.target.value)}
              placeholder="ALTER TABLE ... ADD COLUMN ...;"
              rows={3}
              className="font-mono text-xs"
            />
          </div>
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <Switch checked={isBreaking} onCheckedChange={setIsBreaking} />
              <Label className="text-sm">Breaking Change</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={isRequired} onCheckedChange={setIsRequired} />
              <Label className="text-sm">Required Update</Label>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button
            onClick={() => publishMutation.mutate({
              version,
              changelog,
              downloadUrl: downloadUrl || undefined,
              migrationScript: migrationScript || undefined,
              isBreaking,
              isRequired,
            })}
            disabled={!version || !changelog || publishMutation.isPending}
          >
            {publishMutation.isPending ? "Publishing..." : "Publish"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────

export default function UpdateManager() {
  const { toast } = useToast();

  const versionQuery = trpc.licenseAdmin.getCurrentVersion.useQuery();
  const updateCheckQuery = trpc.licenseAdmin.checkForUpdates.useQuery();
  const changelogQuery = trpc.licenseAdmin.getChangelog.useQuery({ limit: 20 });
  const historyQuery = trpc.licenseAdmin.getUpdateHistory.useQuery();

  const currentVersion = versionQuery.data?.version ?? "...";
  const updateCheck = updateCheckQuery.data;
  const changelog = changelogQuery.data ?? [];
  const history = historyQuery.data ?? [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ArrowUpCircle className="h-6 w-6 text-primary" />
            Update Manager
          </h1>
          <p className="text-muted-foreground mt-1">
            Publish versions, manage updates, and track deployment history
          </p>
        </div>
        <PublishVersionDialog onSuccess={() => { changelogQuery.refetch(); updateCheckQuery.refetch(); }} />
      </div>

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Package className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold font-mono">{currentVersion}</p>
                <p className="text-xs text-muted-foreground">Current Version</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${updateCheck?.updateAvailable ? "bg-amber-500/10" : "bg-emerald-500/10"}`}>
                {updateCheck?.updateAvailable ? (
                  <AlertTriangle className="h-5 w-5 text-amber-400" />
                ) : (
                  <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                )}
              </div>
              <div>
                <p className="text-lg font-bold">
                  {updateCheck?.updateAvailable
                    ? `${updateCheck.updates.length} update${updateCheck.updates.length > 1 ? "s" : ""}`
                    : "Up to date"}
                </p>
                <p className="text-xs text-muted-foreground">
                  Latest: {updateCheck?.latestVersion ?? currentVersion}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Rocket className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{changelog.length}</p>
                <p className="text-xs text-muted-foreground">Published Releases</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="changelog">
        <TabsList>
          <TabsTrigger value="changelog" className="gap-1">
            <FileText className="h-3.5 w-3.5" /> Changelog
          </TabsTrigger>
          <TabsTrigger value="history" className="gap-1">
            <History className="h-3.5 w-3.5" /> Update History
          </TabsTrigger>
        </TabsList>

        {/* Changelog Tab */}
        <TabsContent value="changelog" className="space-y-4">
          {changelog.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                No versions published yet. Click "Publish Version" to create the first release.
              </CardContent>
            </Card>
          ) : (
            changelog.map((v) => (
              <Card key={v.version}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <CardTitle className="text-lg font-mono">v{v.version}</CardTitle>
                      <div className="flex gap-2">
                        {v.isBreaking && (
                          <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30 text-xs">
                            Breaking
                          </Badge>
                        )}
                        {v.isRequired && (
                          <Badge variant="outline" className="bg-amber-500/20 text-amber-400 border-amber-500/30 text-xs">
                            Required
                          </Badge>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">
                        {new Date(v.releaseDate).toLocaleDateString()}
                      </span>
                      {v.downloadUrl && (
                        <Button variant="ghost" size="sm" className="gap-1 text-xs" asChild>
                          <a href={v.downloadUrl} target="_blank" rel="noopener noreferrer">
                            <Download className="h-3 w-3" /> Download
                          </a>
                        </Button>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="prose prose-sm prose-invert max-w-none">
                    <pre className="whitespace-pre-wrap text-sm text-muted-foreground bg-muted/30 p-3 rounded-lg">
                      {v.changelog}
                    </pre>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        {/* Update History Tab */}
        <TabsContent value="history">
          <Card>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border/50">
                      <th className="text-left p-3 font-medium text-muted-foreground">Organization</th>
                      <th className="text-left p-3 font-medium text-muted-foreground">From</th>
                      <th className="text-left p-3 font-medium text-muted-foreground">To</th>
                      <th className="text-left p-3 font-medium text-muted-foreground">Status</th>
                      <th className="text-left p-3 font-medium text-muted-foreground">Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.length === 0 && (
                      <tr>
                        <td colSpan={5} className="text-center py-12 text-muted-foreground">
                          No update history yet.
                        </td>
                      </tr>
                    )}
                    {history.map((h: any) => (
                      <tr key={h.id} className="border-b border-border/30 hover:bg-muted/30">
                        <td className="p-3 font-medium">{h.orgId}</td>
                        <td className="p-3 font-mono text-xs">{h.fromVersion}</td>
                        <td className="p-3 font-mono text-xs">{h.toVersion}</td>
                        <td className="p-3">
                          <Badge
                            variant="outline"
                            className={
                              h.status === "completed"
                                ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                                : h.status === "failed"
                                ? "bg-red-500/20 text-red-400 border-red-500/30"
                                : "bg-blue-500/20 text-blue-400 border-blue-500/30"
                            }
                          >
                            {h.status === "completed" && <CheckCircle2 className="h-3 w-3 mr-1" />}
                            {h.status === "failed" && <XCircle className="h-3 w-3 mr-1" />}
                            {h.status === "in_progress" && <Clock className="h-3 w-3 mr-1" />}
                            {h.status}
                          </Badge>
                        </td>
                        <td className="p-3 text-muted-foreground text-xs">
                          {new Date(h.startedAt).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
