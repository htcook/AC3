import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import {
  FileText, Plus, Search, Shield, Clock, Hash,
  Download, Trash2, Eye, CheckCircle, AlertTriangle,
  Camera, Terminal, Globe, HardDrive
} from "lucide-react";

const EVIDENCE_TYPES = [
  { value: "screenshot", label: "Screenshot", icon: Camera },
  { value: "command_log", label: "Command Log", icon: Terminal },
  { value: "network_capture", label: "Network Capture", icon: Globe },
  { value: "file_artifact", label: "File Artifact", icon: HardDrive },
  { value: "memory_dump", label: "Memory Dump", icon: HardDrive },
  { value: "report", label: "Report", icon: FileText },
  { value: "other", label: "Other", icon: FileText },
];

const CLASSIFICATIONS = [
  { value: "unclassified", label: "Unclassified", color: "bg-green-500/20 text-green-400" },
  { value: "confidential", label: "Confidential", color: "bg-yellow-500/20 text-yellow-400" },
  { value: "secret", label: "Secret", color: "bg-orange-500/20 text-orange-400" },
  { value: "top_secret", label: "Top Secret", color: "bg-red-500/20 text-red-400" },
];

export default function EvidenceCollection() {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [selectedEvidence, setSelectedEvidence] = useState<string | null>(null);

  // Form state
  const [newTitle, setNewTitle] = useState("");
  const [newType, setNewType] = useState("screenshot");
  const [newDescription, setNewDescription] = useState("");
  const [newClassification, setNewClassification] = useState("confidential");
  const [newNotes, setNewNotes] = useState("");

  const searchInput = useMemo(() => ({
    search: search || undefined,
    type: typeFilter || undefined,
  }), [search, typeFilter]);

  const { data: evidence, isLoading, refetch } = trpc.evidence.list.useQuery(searchInput);
  const { data: stats } = trpc.evidence.stats.useQuery();
  const { data: selectedItem } = trpc.evidence.get.useQuery(
    { evidenceId: selectedEvidence! },
    { enabled: !!selectedEvidence }
  );

  const createMutation = trpc.evidence.create.useMutation({
    onSuccess: () => {
      toast.success("Evidence item added with chain of custody entry");
      setShowCreateDialog(false);
      setNewTitle("");
      setNewDescription("");
      setNewNotes("");
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const verifyMutation = trpc.evidence.verifyHash.useMutation({
    onSuccess: (data) => {
      if (data.verified) {
        toast.success(`Hash Verified - SHA-256: ${data.hash}`);
      } else {
        toast.error(`Verification Failed: ${data.reason}`);
      }
    },
  });

  const deleteMutation = trpc.evidence.delete.useMutation({
    onSuccess: () => {
      toast.success("Evidence deleted");
      setSelectedEvidence(null);
      refetch();
    },
  });

  const getTypeIcon = (type: string) => {
    const t = EVIDENCE_TYPES.find(et => et.value === type);
    return t ? t.icon : FileText;
  };

  const getClassColor = (cls: string | null) => {
    const c = CLASSIFICATIONS.find(cl => cl.value === cls);
    return c?.color || "bg-zinc-500/20 text-zinc-400";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6 text-cyan-400" />
            Evidence Collection
          </h1>
          <p className="text-muted-foreground mt-1">
            Forensic evidence management with chain of custody tracking
          </p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              Collect Evidence
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Collect New Evidence</DialogTitle>
              <DialogDescription>Add a new evidence item with classification and metadata</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div>
                <Label>Title</Label>
                <Input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="Evidence title..." />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Type</Label>
                  <Select value={newType} onValueChange={setNewType}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {EVIDENCE_TYPES.map(t => (
                        <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Classification</Label>
                  <Select value={newClassification} onValueChange={setNewClassification}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {CLASSIFICATIONS.map(c => (
                        <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div>
                <Label>Description</Label>
                <Textarea value={newDescription} onChange={(e) => setNewDescription(e.target.value)} placeholder="Describe the evidence..." />
              </div>
              <div>
                <Label>Notes</Label>
                <Textarea value={newNotes} onChange={(e) => setNewNotes(e.target.value)} placeholder="Additional notes..." rows={2} />
              </div>
            </div>
            <DialogFooter>
              <Button
                onClick={() => createMutation.mutate({
                  title: newTitle,
                  type: newType,
                  description: newDescription,
                  classification: newClassification,
                  notes: newNotes,
                })}
                disabled={!newTitle || createMutation.isPending}
              >
                {createMutation.isPending ? "Creating..." : "Collect Evidence"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold">{stats?.total ?? 0}</div>
            <div className="text-xs text-muted-foreground">Total Evidence</div>
          </CardContent>
        </Card>
        {stats?.byType?.slice(0, 3).map((t: any) => (
          <Card key={t.type}>
            <CardContent className="pt-4 pb-4">
              <div className="text-2xl font-bold">{t.count}</div>
              <div className="text-xs text-muted-foreground capitalize">{t.type?.replace(/_/g, " ")}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Search & Filter */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input placeholder="Search evidence..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All Types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            {EVIDENCE_TYPES.map(t => (
              <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Evidence List + Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* List */}
        <div className="lg:col-span-1 space-y-3 max-h-[600px] overflow-y-auto">
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading...</div>
          ) : !evidence?.items?.length ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                <Shield className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p>No evidence collected yet</p>
              </CardContent>
            </Card>
          ) : (
            evidence.items.map((item: any) => {
              const TypeIcon = getTypeIcon(item.type);
              return (
                <Card
                  key={item.evidenceId}
                  className={`cursor-pointer transition-colors hover:border-cyan-500/50 ${
                    selectedEvidence === item.evidenceId ? "border-cyan-500" : ""
                  }`}
                  onClick={() => setSelectedEvidence(item.evidenceId)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-start gap-3">
                      <TypeIcon className="h-5 w-5 text-cyan-400 mt-0.5 shrink-0" />
                      <div className="flex-1 min-w-0">
                        <h3 className="font-semibold text-sm truncate">{item.title}</h3>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="outline" className="text-[10px]">{item.type}</Badge>
                          <Badge className={`text-[10px] ${getClassColor(item.classification)}`}>
                            {item.classification}
                          </Badge>
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {new Date(item.createdAt).toLocaleDateString()}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })
          )}
        </div>

        {/* Detail Panel */}
        <div className="lg:col-span-2">
          {selectedItem ? (
            <Card>
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle>{selectedItem.title}</CardTitle>
                    <CardDescription>{selectedItem.description}</CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-1"
                      onClick={() => verifyMutation.mutate({ evidenceId: selectedItem.evidenceId })}
                      disabled={verifyMutation.isPending}
                    >
                      <Hash className="h-3 w-3" />
                      Verify Hash
                    </Button>
                    {selectedItem.fileUrl && (
                      <Button size="sm" variant="outline" className="gap-1" asChild>
                        <a href={selectedItem.fileUrl} target="_blank" rel="noopener noreferrer">
                          <Download className="h-3 w-3" />
                          Download
                        </a>
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => deleteMutation.mutate({ evidenceId: selectedItem.evidenceId })}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Metadata */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Type:</span>{" "}
                    <span className="capitalize">{selectedItem.type?.replace(/_/g, " ")}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Classification:</span>{" "}
                    <Badge className={`text-[10px] ${getClassColor(selectedItem.classification)}`}>
                      {selectedItem.classification}
                    </Badge>
                  </div>
                  {selectedItem.sha256Hash && (
                    <div className="col-span-2">
                      <span className="text-muted-foreground">SHA-256:</span>{" "}
                      <code className="text-xs bg-zinc-800 px-2 py-0.5 rounded">{selectedItem.sha256Hash}</code>
                    </div>
                  )}
                  {selectedItem.fileName && (
                    <div>
                      <span className="text-muted-foreground">File:</span> {selectedItem.fileName}
                    </div>
                  )}
                  {selectedItem.fileSize && (
                    <div>
                      <span className="text-muted-foreground">Size:</span>{" "}
                      {(selectedItem.fileSize / 1024).toFixed(1)} KB
                    </div>
                  )}
                </div>

                {selectedItem.notes && (
                  <div className="rounded-lg border p-3 bg-zinc-900/50">
                    <h4 className="text-sm font-semibold mb-1">Notes</h4>
                    <p className="text-sm text-muted-foreground">{selectedItem.notes}</p>
                  </div>
                )}

                {/* Chain of Custody */}
                <div>
                  <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                    <Clock className="h-4 w-4 text-cyan-400" />
                    Chain of Custody
                  </h4>
                  <div className="space-y-2">
                    {selectedItem.custodyLog?.map((entry: any, idx: number) => (
                      <div key={idx} className="flex items-start gap-3 text-sm border-l-2 border-cyan-500/30 pl-3 py-1">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-[10px]">{entry.action}</Badge>
                            <span className="text-muted-foreground">by {entry.performedBy}</span>
                          </div>
                          {entry.details && (
                            <p className="text-xs text-muted-foreground mt-0.5">{entry.details}</p>
                          )}
                        </div>
                        <span className="text-xs text-muted-foreground whitespace-nowrap">
                          {new Date(entry.performedAt).toLocaleString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="py-16 text-center text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-4 opacity-30" />
                <p className="text-lg">Select evidence to view details</p>
                <p className="text-sm mt-1">Including chain of custody and hash verification</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
