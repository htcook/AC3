import { useState, useCallback, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import {
  Upload, FileJson, FileArchive, AlertTriangle, CheckCircle2,
  Users, Shield, Monitor, Globe, FolderTree, Crosshair,
  Loader2, Trash2, Eye, Import, Info,
} from "lucide-react";

interface FileEntry {
  file: File;
  name: string;
  size: number;
  type: "json" | "zip";
}

export default function BloodHoundImport() {
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [environmentName, setEnvironmentName] = useState("BloodHound Import");
  const [previewResult, setPreviewResult] = useState<any>(null);
  const [importResult, setImportResult] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [phase, setPhase] = useState<"upload" | "preview" | "importing" | "complete">("upload");

  const info = trpc.bloodhoundImport.getInfo.useQuery();
  const previewMutation = trpc.bloodhoundImport.preview.useMutation();
  const importMutation = trpc.bloodhoundImport.import.useMutation();

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const dropped = Array.from(e.dataTransfer.files);
    addFiles(dropped);
  }, []);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      addFiles(Array.from(e.target.files));
    }
  }, []);

  function addFiles(newFiles: File[]) {
    const entries: FileEntry[] = newFiles
      .filter(f => f.name.endsWith(".json") || f.name.endsWith(".zip"))
      .map(f => ({
        file: f,
        name: f.name,
        size: f.size,
        type: f.name.endsWith(".zip") ? "zip" as const : "json" as const,
      }));
    if (entries.length === 0) {
      toast.error("Only .json and .zip files are supported");
      return;
    }
    setFiles(prev => [...prev, ...entries]);
    setPreviewResult(null);
    setImportResult(null);
    setPhase("upload");
  }

  function removeFile(index: number) {
    setFiles(prev => prev.filter((_, i) => i !== index));
    setPreviewResult(null);
  }

  async function readFilesAsBase64(): Promise<{ filename: string; data: string }[]> {
    return Promise.all(
      files.map(entry =>
        new Promise<{ filename: string; data: string }>((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => {
            const base64 = (reader.result as string).split(",")[1];
            resolve({ filename: entry.name, data: base64 });
          };
          reader.onerror = reject;
          reader.readAsDataURL(entry.file);
        })
      )
    );
  }

  async function handlePreview() {
    if (files.length === 0) return;
    setIsLoading(true);
    try {
      const fileData = await readFilesAsBase64();
      const result = await previewMutation.mutateAsync({ files: fileData });
      setPreviewResult(result);
      setPhase("preview");
      toast.success(`Preview complete: ${result.nodes.length} objects, ${result.edges.length} relationships`);
    } catch (e: any) {
      toast.error(`Preview failed: ${e.message}`);
    } finally {
      setIsLoading(false);
    }
  }

  async function handleImport() {
    if (files.length === 0) return;
    setIsLoading(true);
    setPhase("importing");
    try {
      const fileData = await readFilesAsBase64();
      const result = await importMutation.mutateAsync({
        environmentName,
        files: fileData,
      });
      setImportResult(result);
      setPhase("complete");
      toast.success(`Imported ${result.importedObjects} objects into "${environmentName}"`);
    } catch (e: any) {
      toast.error(`Import failed: ${e.message}`);
      setPhase("preview");
    } finally {
      setIsLoading(false);
    }
  }

  const totalSize = useMemo(() => {
    const bytes = files.reduce((sum, f) => sum + f.size, 0);
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
  }, [files]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Crosshair className="h-6 w-6 text-red-500" />
            BloodHound Data Import
          </h1>
          <p className="text-muted-foreground mt-1">
            Import SharpHound collection data to populate the AD Attack Path Graph
          </p>
        </div>
        {phase === "complete" && (
          <Button
            variant="outline"
            onClick={() => {
              setFiles([]);
              setPreviewResult(null);
              setImportResult(null);
              setPhase("upload");
            }}
          >
            New Import
          </Button>
        )}
      </div>

      {/* Instructions Card */}
      <Card className="border-blue-500/20 bg-blue-500/5">
        <CardContent className="pt-4 pb-4">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-blue-500 mt-0.5 shrink-0" />
            <div className="text-sm space-y-1">
              <p className="font-medium text-blue-400">How to collect data</p>
              <p className="text-muted-foreground">
                Run <code className="bg-muted px-1.5 py-0.5 rounded text-xs font-mono">SharpHound.exe --CollectionMethods All</code> on
                a domain-joined machine, then upload the resulting ZIP file below. Individual JSON files are also supported.
              </p>
              <p className="text-muted-foreground">
                Supports SharpHound v4 and v5 formats. Maximum 20 files, 50MB each.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs value={phase === "complete" ? "results" : phase === "preview" || phase === "importing" ? "preview" : "upload"}>
        <TabsList>
          <TabsTrigger value="upload" onClick={() => phase !== "importing" && setPhase("upload")}>
            <Upload className="h-4 w-4 mr-1.5" /> Upload Files
          </TabsTrigger>
          <TabsTrigger value="preview" disabled={!previewResult}>
            <Eye className="h-4 w-4 mr-1.5" /> Preview
          </TabsTrigger>
          <TabsTrigger value="results" disabled={!importResult}>
            <CheckCircle2 className="h-4 w-4 mr-1.5" /> Results
          </TabsTrigger>
        </TabsList>

        {/* Upload Tab */}
        <TabsContent value="upload" className="space-y-4">
          {/* Drop Zone */}
          <Card
            className="border-dashed border-2 hover:border-primary/50 transition-colors cursor-pointer"
            onDragOver={e => e.preventDefault()}
            onDrop={handleFileDrop}
          >
            <CardContent className="flex flex-col items-center justify-center py-12">
              <div className="rounded-full bg-muted p-4 mb-4">
                <Upload className="h-8 w-8 text-muted-foreground" />
              </div>
              <p className="text-lg font-medium mb-1">Drop SharpHound files here</p>
              <p className="text-sm text-muted-foreground mb-4">
                ZIP archives or individual JSON collection files
              </p>
              <Label htmlFor="file-input">
                <Button variant="outline" asChild>
                  <span>Browse Files</span>
                </Button>
              </Label>
              <input
                id="file-input"
                type="file"
                multiple
                accept=".json,.zip"
                onChange={handleFileSelect}
                className="hidden"
              />
            </CardContent>
          </Card>

          {/* File List */}
          {files.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base">
                    Selected Files ({files.length})
                  </CardTitle>
                  <span className="text-sm text-muted-foreground">{totalSize}</span>
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                {files.map((entry, i) => (
                  <div key={i} className="flex items-center justify-between py-2 px-3 bg-muted/50 rounded-lg">
                    <div className="flex items-center gap-3">
                      {entry.type === "zip" ? (
                        <FileArchive className="h-5 w-5 text-amber-500" />
                      ) : (
                        <FileJson className="h-5 w-5 text-blue-500" />
                      )}
                      <div>
                        <p className="text-sm font-medium">{entry.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {entry.size < 1048576
                            ? `${(entry.size / 1024).toFixed(1)} KB`
                            : `${(entry.size / 1048576).toFixed(1)} MB`}
                        </p>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      onClick={() => removeFile(i)}
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                ))}

                <div className="pt-3 flex items-center gap-3">
                  <div className="flex-1">
                    <Label className="text-xs text-muted-foreground">Environment Name</Label>
                    <Input
                      value={environmentName}
                      onChange={e => setEnvironmentName(e.target.value)}
                      placeholder="e.g., CORP.LOCAL"
                      className="mt-1"
                    />
                  </div>
                  <Button
                    onClick={handlePreview}
                    disabled={isLoading || files.length === 0}
                    className="mt-5"
                  >
                    {isLoading ? (
                      <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />
                    ) : (
                      <Eye className="h-4 w-4 mr-1.5" />
                    )}
                    Preview
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Preview Tab */}
        <TabsContent value="preview" className="space-y-4">
          {previewResult && (
            <>
              {/* Stats Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                <StatCard icon={Users} label="Users" value={previewResult.stats.totalUsers} color="blue" />
                <StatCard icon={Shield} label="Groups" value={previewResult.stats.totalGroups} color="green" />
                <StatCard icon={Monitor} label="Computers" value={previewResult.stats.totalComputers} color="purple" />
                <StatCard icon={Globe} label="Domains" value={previewResult.stats.totalDomains} color="amber" />
                <StatCard icon={FolderTree} label="GPOs" value={previewResult.stats.totalGPOs} color="cyan" />
                <StatCard icon={FolderTree} label="OUs" value={previewResult.stats.totalOUs} color="slate" />
              </div>

              {/* Security Findings */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Security Findings</CardTitle>
                  <CardDescription>Attack surface indicators detected in the collection</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="p-3 bg-red-500/10 rounded-lg border border-red-500/20">
                      <p className="text-2xl font-bold text-red-400">{previewResult.stats.highValueTargets}</p>
                      <p className="text-xs text-muted-foreground">High-Value Targets</p>
                    </div>
                    <div className="p-3 bg-amber-500/10 rounded-lg border border-amber-500/20">
                      <p className="text-2xl font-bold text-amber-400">{previewResult.stats.kerberoastableUsers}</p>
                      <p className="text-xs text-muted-foreground">Kerberoastable Users</p>
                    </div>
                    <div className="p-3 bg-orange-500/10 rounded-lg border border-orange-500/20">
                      <p className="text-2xl font-bold text-orange-400">{previewResult.stats.asrepRoastableUsers}</p>
                      <p className="text-xs text-muted-foreground">AS-REP Roastable</p>
                    </div>
                    <div className="p-3 bg-purple-500/10 rounded-lg border border-purple-500/20">
                      <p className="text-2xl font-bold text-purple-400">{previewResult.stats.unconstrainedDelegation}</p>
                      <p className="text-xs text-muted-foreground">Unconstrained Delegation</p>
                    </div>
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-4">
                    <div className="p-3 bg-muted/50 rounded-lg">
                      <p className="text-lg font-bold">{previewResult.nodes.length}</p>
                      <p className="text-xs text-muted-foreground">Total Graph Nodes</p>
                    </div>
                    <div className="p-3 bg-muted/50 rounded-lg">
                      <p className="text-lg font-bold">{previewResult.edges.length}</p>
                      <p className="text-xs text-muted-foreground">Total Relationships</p>
                    </div>
                  </div>

                  {previewResult.stats.totalACEs > 0 && (
                    <p className="mt-3 text-sm text-muted-foreground">
                      {previewResult.stats.totalACEs} ACEs processed into attack edges
                    </p>
                  )}
                </CardContent>
              </Card>

              {/* Parse Errors */}
              {previewResult.stats.parseErrors.length > 0 && (
                <Card className="border-amber-500/20">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-amber-500" />
                      Parse Warnings ({previewResult.stats.parseErrors.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {previewResult.stats.parseErrors.map((err: string, i: number) => (
                        <p key={i} className="text-xs text-amber-400 font-mono">{err}</p>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Import Button */}
              <div className="flex justify-end gap-3">
                <Button variant="outline" onClick={() => setPhase("upload")}>
                  Back to Upload
                </Button>
                <Button
                  onClick={handleImport}
                  disabled={isLoading || previewResult.nodes.length === 0}
                  className="bg-red-600 hover:bg-red-700"
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />
                      Importing...
                    </>
                  ) : (
                    <>
                      <Import className="h-4 w-4 mr-1.5" />
                      Import {previewResult.nodes.length} Objects
                    </>
                  )}
                </Button>
              </div>

              {/* Import Progress */}
              {phase === "importing" && (
                <Card>
                  <CardContent className="py-6">
                    <div className="flex items-center gap-3 mb-3">
                      <Loader2 className="h-5 w-5 animate-spin text-primary" />
                      <p className="font-medium">Importing into AD Attack Path Graph...</p>
                    </div>
                    <Progress value={65} className="h-2" />
                    <p className="text-sm text-muted-foreground mt-2">
                      Processing nodes and building relationships...
                    </p>
                  </CardContent>
                </Card>
              )}
            </>
          )}
        </TabsContent>

        {/* Results Tab */}
        <TabsContent value="results" className="space-y-4">
          {importResult && (
            <>
              <Card className="border-green-500/20 bg-green-500/5">
                <CardContent className="pt-6 pb-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="rounded-full bg-green-500/20 p-2">
                      <CheckCircle2 className="h-6 w-6 text-green-500" />
                    </div>
                    <div>
                      <p className="text-lg font-bold">Import Complete</p>
                      <p className="text-sm text-muted-foreground">
                        Data imported into environment "{importResult.environmentName}"
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="p-3 bg-background rounded-lg">
                      <p className="text-2xl font-bold">{importResult.importedObjects}</p>
                      <p className="text-xs text-muted-foreground">Objects Imported</p>
                    </div>
                    <div className="p-3 bg-background rounded-lg">
                      <p className="text-2xl font-bold">{importResult.totalNodes}</p>
                      <p className="text-xs text-muted-foreground">Graph Nodes</p>
                    </div>
                    <div className="p-3 bg-background rounded-lg">
                      <p className="text-2xl font-bold">{importResult.totalEdges}</p>
                      <p className="text-xs text-muted-foreground">Relationships</p>
                    </div>
                    <div className="p-3 bg-background rounded-lg">
                      <p className="text-2xl font-bold">{importResult.stats.highValueTargets}</p>
                      <p className="text-xs text-muted-foreground">High-Value Targets</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Next Steps */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Next Steps</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg">
                    <Badge variant="outline" className="mt-0.5">1</Badge>
                    <div>
                      <p className="text-sm font-medium">View Attack Paths</p>
                      <p className="text-xs text-muted-foreground">
                        Navigate to AD Attack Path Graph to visualize escalation paths from the imported data
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg">
                    <Badge variant="outline" className="mt-0.5">2</Badge>
                    <div>
                      <p className="text-sm font-medium">Run AD Attack Simulation</p>
                      <p className="text-xs text-muted-foreground">
                        Use the imported objects to simulate Kerberoasting, AS-REP Roasting, and other AD attacks
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg">
                    <Badge variant="outline" className="mt-0.5">3</Badge>
                    <div>
                      <p className="text-sm font-medium">Generate Report</p>
                      <p className="text-xs text-muted-foreground">
                        Include the AD attack path findings in your Executive Report
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, color }: {
  icon: any;
  label: string;
  value: number;
  color: string;
}) {
  const colorClasses: Record<string, string> = {
    blue: "text-blue-500 bg-blue-500/10 border-blue-500/20",
    green: "text-green-500 bg-green-500/10 border-green-500/20",
    purple: "text-purple-500 bg-purple-500/10 border-purple-500/20",
    amber: "text-amber-500 bg-amber-500/10 border-amber-500/20",
    cyan: "text-cyan-500 bg-cyan-500/10 border-cyan-500/20",
    slate: "text-slate-400 bg-slate-500/10 border-slate-500/20",
  };
  return (
    <div className={`p-3 rounded-lg border ${colorClasses[color] || colorClasses.slate}`}>
      <Icon className={`h-5 w-5 mb-1 ${colorClasses[color]?.split(" ")[0]}`} />
      <p className="text-xl font-bold">{value}</p>
      <p className="text-xs text-muted-foreground">{label}</p>
    </div>
  );
}
