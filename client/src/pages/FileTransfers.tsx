import { useState, useRef, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { toast } from "sonner";
import {
  Upload,
  Download,
  FolderOpen,
  File,
  Folder,
  Trash2,
  ExternalLink,
  RefreshCw,
  HardDrive,
  ArrowUpDown,
  Loader2,
  CheckCircle,
  XCircle,
  Clock,
  FileText,
  Image,
  Archive,
  Code,
  Music,
  Video,
  BarChart3,
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── File Icon Helper ────────────────────────────────────────────────────────

function getFileIcon(fileName: string) {
  const ext = fileName.split(".").pop()?.toLowerCase() || "";
  if (["jpg", "jpeg", "png", "gif", "bmp", "svg", "webp"].includes(ext)) return Image;
  if (["zip", "tar", "gz", "rar", "7z", "bz2"].includes(ext)) return Archive;
  if (["js", "ts", "py", "rb", "c", "cpp", "h", "java", "go", "rs", "sh", "bat", "ps1"].includes(ext)) return Code;
  if (["mp3", "wav", "ogg", "flac", "aac"].includes(ext)) return Music;
  if (["mp4", "avi", "mkv", "mov", "wmv"].includes(ext)) return Video;
  if (["txt", "md", "log", "csv", "json", "xml", "yaml", "yml", "conf", "ini"].includes(ext)) return FileText;
  return File;
}

function formatBytes(bytes: number | null | undefined): string {
  if (!bytes) return "0 B";
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
}

// ─── Remote File Browser ─────────────────────────────────────────────────────

function RemoteFileBrowser({
  open,
  onOpenChange,
  serverId,
  sessionId,
  onSelectFile,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  serverId: number;
  sessionId: string;
  onSelectFile: (path: string) => void;
}) {
  const [currentPath, setCurrentPath] = useState(".");
  const browseMutation = trpc.fileTransfers.browseRemoteDir.useMutation();

  const handleBrowse = (path: string) => {
    setCurrentPath(path);
    browseMutation.mutate({ serverId, sessionId, path });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl bg-zinc-900 border-zinc-700">
        <DialogHeader>
          <DialogTitle className="text-white flex items-center gap-2">
            <FolderOpen className="h-5 w-5 text-amber-400" />
            Remote File Browser
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Input
              value={currentPath}
              onChange={(e) => setCurrentPath(e.target.value)}
              className="bg-zinc-800 border-zinc-700 font-mono text-sm"
              placeholder="Enter path..."
            />
            <Button
              size="sm"
              onClick={() => handleBrowse(currentPath)}
              disabled={browseMutation.isPending}
            >
              {browseMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            </Button>
          </div>

          {!browseMutation.data && !browseMutation.isPending && (
            <div className="text-center py-8">
              <FolderOpen className="h-12 w-12 text-zinc-600 mx-auto mb-3" />
              <p className="text-sm text-zinc-400">Click refresh to browse the remote filesystem</p>
            </div>
          )}

          {browseMutation.data && (
            <div className="max-h-[400px] overflow-y-auto space-y-1">
              {/* Parent directory */}
              <div
                className="flex items-center gap-2 p-2 rounded hover:bg-zinc-800 cursor-pointer"
                onClick={() => {
                  const parent = currentPath.split("/").slice(0, -1).join("/") || "/";
                  handleBrowse(parent);
                }}
              >
                <Folder className="h-4 w-4 text-amber-400" />
                <span className="text-sm text-zinc-300">..</span>
              </div>

              {browseMutation.data.entries.map((entry, idx) => {
                const FileIcon = entry.type === "directory" ? Folder : getFileIcon(entry.name);
                const fullPath = `${currentPath === "." ? "" : currentPath}/${entry.name}`;

                return (
                  <div
                    key={idx}
                    className="flex items-center gap-2 p-2 rounded hover:bg-zinc-800 cursor-pointer group"
                    onClick={() => {
                      if (entry.type === "directory") {
                        handleBrowse(fullPath);
                      }
                    }}
                  >
                    <FileIcon className={`h-4 w-4 ${entry.type === "directory" ? "text-amber-400" : "text-zinc-400"}`} />
                    <span className="text-sm text-zinc-300 flex-1">{entry.name}</span>
                    <span className="text-xs text-zinc-500">{entry.type === "file" ? formatBytes(parseInt(entry.size)) : ""}</span>
                    <span className="text-xs text-zinc-600">{entry.modified}</span>
                    {entry.type === "file" && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="opacity-0 group-hover:opacity-100 text-xs text-red-400"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFile(fullPath);
                          onOpenChange(false);
                        }}
                      >
                        <Download className="h-3 w-3 mr-1" /> Download
                      </Button>
                    )}
                  </div>
                );
              })}

              {browseMutation.data.entries.length === 0 && (
                <div className="text-center py-4">
                  <p className="text-sm text-zinc-500">Directory is empty</p>
                </div>
              )}
            </div>
          )}

          {/* Raw output toggle */}
          {browseMutation.data?.rawOutput && (
            <details className="text-xs">
              <summary className="text-zinc-500 cursor-pointer">Raw output</summary>
              <pre className="mt-1 p-2 bg-zinc-800 rounded text-zinc-400 font-mono overflow-x-auto max-h-32">
                {browseMutation.data.rawOutput}
              </pre>
            </details>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function FileTransfers() {
  const utils = trpc.useUtils();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dirFilter, setDirFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [browserOpen, setBrowserOpen] = useState(false);
  const [selectedServerId, setSelectedServerId] = useState<number | null>(null);
  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [downloadPath, setDownloadPath] = useState("");
  const [uploadPath, setUploadPath] = useState("");
  const [uploadFile, setUploadFile] = useState<{ name: string; content: string; size: number } | null>(null);

  const { data: transfers, isLoading } = trpc.fileTransfers.listTransfers.useQuery(
    {
      direction: dirFilter !== "all" ? dirFilter as any : undefined,
      status: statusFilter !== "all" ? statusFilter as any : undefined,
    },
    { refetchInterval: 5000 }
  );

  const { data: stats } = trpc.fileTransfers.getStats.useQuery();

  const { data: servers } = trpc.metasploit.listServers.useQuery();
  const onlineServers = useMemo(() => servers?.filter((s: any) => s.msfStatus === "online") || [], [servers]);

  const downloadMutation = trpc.fileTransfers.downloadFromTarget.useMutation({
    onSuccess: (data) => {
      toast.success(`Download started (Transfer #${data.transferId})`);
      utils.fileTransfers.listTransfers.invalidate();
      setDownloadPath("");
    },
    onError: (err) => toast.error(err.message),
  });

  const uploadMutation = trpc.fileTransfers.uploadToTarget.useMutation({
    onSuccess: (data) => {
      toast.success(`Upload started (Transfer #${data.transferId})`);
      utils.fileTransfers.listTransfers.invalidate();
      setUploadFile(null);
      setUploadPath("");
    },
    onError: (err) => toast.error(err.message),
  });

  const deleteMutation = trpc.fileTransfers.deleteTransfer.useMutation({
    onSuccess: () => {
      toast.success("Transfer record deleted");
      utils.fileTransfers.listTransfers.invalidate();
      utils.fileTransfers.getStats.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) {
      toast.error("File too large (max 10MB)");
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const base64 = (reader.result as string).split(",")[1];
      setUploadFile({ name: file.name, content: base64, size: file.size });
    };
    reader.readAsDataURL(file);
  };

  const handleDownload = () => {
    if (!selectedServerId || !selectedSessionId || !downloadPath) {
      toast.error("Select server, session, and enter remote path");
      return;
    }
    downloadMutation.mutate({
      serverId: selectedServerId,
      sessionId: selectedSessionId,
      remotePath: downloadPath,
    });
  };

  const handleUpload = () => {
    if (!selectedServerId || !selectedSessionId || !uploadPath || !uploadFile) {
      toast.error("Select server, session, enter remote path, and choose a file");
      return;
    }
    uploadMutation.mutate({
      serverId: selectedServerId,
      sessionId: selectedSessionId,
      remotePath: uploadPath,
      fileContent: uploadFile.content,
      fileName: uploadFile.name,
    });
  };

  return (
    <AppShell activePath="/file-transfers">
      <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <ArrowUpDown className="h-6 w-6 text-red-500" />
          File Transfers
        </h1>
        <p className="text-zinc-400 text-sm mt-1">
          Upload and download files to/from compromised targets via Meterpreter
        </p>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Card className="bg-zinc-800/50 border-zinc-700">
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold text-white">{stats.total}</p>
              <p className="text-xs text-zinc-500">Total</p>
            </CardContent>
          </Card>
          <Card className="bg-zinc-800/50 border-zinc-700">
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold text-blue-400">{stats.uploads}</p>
              <p className="text-xs text-zinc-500">Uploads</p>
            </CardContent>
          </Card>
          <Card className="bg-zinc-800/50 border-zinc-700">
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold text-green-400">{stats.downloads}</p>
              <p className="text-xs text-zinc-500">Downloads</p>
            </CardContent>
          </Card>
          <Card className="bg-zinc-800/50 border-zinc-700">
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold text-red-400">{stats.failed}</p>
              <p className="text-xs text-zinc-500">Failed</p>
            </CardContent>
          </Card>
          <Card className="bg-zinc-800/50 border-zinc-700">
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold text-amber-400">{formatBytes(stats.totalSize)}</p>
              <p className="text-xs text-zinc-500">Total Size</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Transfer Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Download from Target */}
        <Card className="bg-zinc-800/50 border-zinc-700">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-white flex items-center gap-2">
              <Download className="h-4 w-4 text-green-400" />
              Download from Target
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <Label className="text-xs">Server</Label>
                <Select
                  value={selectedServerId?.toString() || ""}
                  onValueChange={(v) => setSelectedServerId(parseInt(v))}
                >
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 text-sm">
                    <SelectValue placeholder="Select server" />
                  </SelectTrigger>
                  <SelectContent>
                    {onlineServers.map((s: any) => (
                      <SelectItem key={s.id} value={s.id.toString()}>
                        {s.name} ({s.ipAddress})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Session ID</Label>
                <Input
                  value={selectedSessionId}
                  onChange={(e) => setSelectedSessionId(e.target.value)}
                  placeholder="e.g., 1"
                  className="bg-zinc-800 border-zinc-700 text-sm"
                />
              </div>
            </div>
            <div>
              <Label className="text-xs">Remote File Path</Label>
              <div className="flex gap-2">
                <Input
                  value={downloadPath}
                  onChange={(e) => setDownloadPath(e.target.value)}
                  placeholder="/etc/passwd or C:\Users\..."
                  className="bg-zinc-800 border-zinc-700 text-sm font-mono flex-1"
                />
                <Button
                  variant="outline"
                  size="sm"
                  className="border-zinc-700"
                  onClick={() => setBrowserOpen(true)}
                  disabled={!selectedServerId || !selectedSessionId}
                >
                  <FolderOpen className="h-4 w-4" />
                </Button>
              </div>
            </div>
            <Button
              className="w-full bg-green-600 hover:bg-green-700"
              onClick={handleDownload}
              disabled={downloadMutation.isPending || !downloadPath}
            >
              {downloadMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Download className="h-4 w-4 mr-2" />
              )}
              Download File
            </Button>
          </CardContent>
        </Card>

        {/* Upload to Target */}
        <Card className="bg-zinc-800/50 border-zinc-700">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-white flex items-center gap-2">
              <Upload className="h-4 w-4 text-blue-400" />
              Upload to Target
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Label className="text-xs">Local File</Label>
              <div
                className="border-2 border-dashed border-zinc-700 rounded-lg p-4 text-center cursor-pointer hover:border-zinc-500 transition-colors"
                onClick={() => fileInputRef.current?.click()}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  className="hidden"
                  onChange={handleFileSelect}
                />
                {uploadFile ? (
                  <div className="flex items-center justify-center gap-2">
                    <File className="h-5 w-5 text-blue-400" />
                    <span className="text-sm text-white">{uploadFile.name}</span>
                    <span className="text-xs text-zinc-500">({formatBytes(uploadFile.size)})</span>
                  </div>
                ) : (
                  <div>
                    <Upload className="h-8 w-8 text-zinc-500 mx-auto mb-1" />
                    <p className="text-sm text-zinc-400">Click to select file (max 10MB)</p>
                  </div>
                )}
              </div>
            </div>
            <div>
              <Label className="text-xs">Remote Destination Path</Label>
              <Input
                value={uploadPath}
                onChange={(e) => setUploadPath(e.target.value)}
                placeholder="/tmp/payload.exe or C:\Temp\..."
                className="bg-zinc-800 border-zinc-700 text-sm font-mono"
              />
            </div>
            <Button
              className="w-full bg-blue-600 hover:bg-blue-700"
              onClick={handleUpload}
              disabled={uploadMutation.isPending || !uploadFile || !uploadPath}
            >
              {uploadMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Upload className="h-4 w-4 mr-2" />
              )}
              Upload File
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Transfer History */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <HardDrive className="h-5 w-5 text-zinc-400" />
            Transfer History
          </h2>
          <div className="flex items-center gap-2">
            <Select value={dirFilter} onValueChange={setDirFilter}>
              <SelectTrigger className="w-32 bg-zinc-800 border-zinc-700 text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="upload">Uploads</SelectItem>
                <SelectItem value="download">Downloads</SelectItem>
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-32 bg-zinc-800 border-zinc-700 text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {isLoading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <Card key={i} className="bg-zinc-800/50 border-zinc-700 animate-pulse">
                <CardContent className="p-4 h-16" />
              </Card>
            ))}
          </div>
        ) : !transfers?.length ? (
          <Card className="bg-zinc-800/50 border-zinc-700">
            <CardContent className="p-12 text-center">
              <ArrowUpDown className="h-12 w-12 text-zinc-600 mx-auto mb-3" />
              <h3 className="text-lg font-medium text-zinc-400">No Transfers Yet</h3>
              <p className="text-sm text-zinc-500 mt-1">
                Use the controls above to upload or download files from target systems.
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-2">
            {transfers.map((transfer) => {
              const FileIcon = getFileIcon(transfer.fileName);
              const isDownload = transfer.direction === "download";

              return (
                <Card key={transfer.id} className="bg-zinc-800/50 border-zinc-700 hover:border-zinc-600 transition-colors">
                  <CardContent className="p-3 flex items-center gap-3">
                    {/* Direction icon */}
                    <div className={`p-2 rounded-lg ${isDownload ? "bg-green-500/10" : "bg-blue-500/10"}`}>
                      {isDownload ? (
                        <Download className="h-4 w-4 text-green-400" />
                      ) : (
                        <Upload className="h-4 w-4 text-blue-400" />
                      )}
                    </div>

                    {/* File info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <FileIcon className="h-4 w-4 text-zinc-400" />
                        <span className="text-sm font-medium text-white truncate">{transfer.fileName}</span>
                        <Badge
                          variant="outline"
                          className={
                            transfer.status === "completed" ? "text-green-400 border-green-400/30" :
                            transfer.status === "in_progress" ? "text-blue-400 border-blue-400/30 animate-pulse" :
                            transfer.status === "failed" ? "text-red-400 border-red-400/30" :
                            "text-zinc-400 border-zinc-600"
                          }
                        >
                          {transfer.status === "in_progress" && <Loader2 className="h-3 w-3 animate-spin mr-1" />}
                          {transfer.status === "completed" && <CheckCircle className="h-3 w-3 mr-1" />}
                          {transfer.status === "failed" && <XCircle className="h-3 w-3 mr-1" />}
                          {transfer.status}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-3 text-xs text-zinc-500 mt-1">
                        <span className="font-mono truncate max-w-[300px]">{transfer.remotePath}</span>
                        <span>Server {transfer.serverId}</span>
                        <span>Session {transfer.sessionId}</span>
                        {transfer.fileSize && <span>{formatBytes(transfer.fileSize)}</span>}
                      </div>
                      {transfer.errorMessage && (
                        <p className="text-xs text-red-400 mt-1">{transfer.errorMessage}</p>
                      )}
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-1">
                      <span className="text-xs text-zinc-600">
                        {new Date(transfer.createdAt).toLocaleString()}
                      </span>
                      {transfer.s3Url && transfer.status === "completed" && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-green-400"
                          onClick={() => window.open(transfer.s3Url!, "_blank")}
                        >
                          <ExternalLink className="h-3 w-3" />
                        </Button>
                      )}
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="ghost" size="sm" className="text-red-400">
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Delete Transfer Record?</AlertDialogTitle>
                            <AlertDialogDescription>
                              This will remove the transfer record. The S3 file will remain.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              className="bg-red-600 hover:bg-red-700"
                              onClick={() => deleteMutation.mutate({ id: transfer.id })}
                            >
                              Delete
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </div>

      {/* Remote File Browser Dialog */}
      {selectedServerId && selectedSessionId && (
        <RemoteFileBrowser
          open={browserOpen}
          onOpenChange={setBrowserOpen}
          serverId={selectedServerId}
          sessionId={selectedSessionId}
          onSelectFile={(path) => setDownloadPath(path)}
        />
      )}
    </div>
    </AppShell>
  );
}
