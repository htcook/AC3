import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  FileOutput, Download, Plus, Loader2, RefreshCw, FileJson,
  FileText, ClipboardList, CheckCircle2, XCircle, Clock, Hash
} from "lucide-react";

const DOC_TYPES = [
  { id: "ssp", name: "System Security Plan (SSP)", icon: FileText, description: "Comprehensive security plan documenting KSI implementations" },
  { id: "sar", name: "Security Assessment Report (SAR)", icon: ClipboardList, description: "Assessment findings with evidence observations" },
  { id: "poam", name: "Plan of Action & Milestones (POA&M)", icon: Clock, description: "Remediation plan for failing or unimplemented KSIs" },
] as const;

export default function OscalExport() {
  
  const [showGenerateDialog, setShowGenerateDialog] = useState(false);
  const [showPreviewDialog, setShowPreviewDialog] = useState(false);
  const [previewData, setPreviewData] = useState<any>(null);
  const [generating, setGenerating] = useState(false);

  const [newExport, setNewExport] = useState({
    documentType: "ssp" as "ssp" | "sar" | "poam",
    title: "",
    description: "",
    outputFormat: "json" as "json" | "xml" | "yaml",
  });

  const utils = trpc.useUtils();
  const exportsQuery = trpc.oscalExport.listExports.useQuery();
  const statsQuery = trpc.oscalExport.getStats.useQuery();
  const docTypesQuery = trpc.oscalExport.getDocumentTypes.useQuery();

  const generateMutation = trpc.oscalExport.generate.useMutation({
    onSuccess: (data) => {
      toast.success(`OSCAL Document Generated: ${data.documentType.toUpperCase()} — ${(data.documentSize / 1024).toFixed(1)} KB`);
      setShowGenerateDialog(false);
      setPreviewData(data);
      setShowPreviewDialog(true);
      utils.oscalExport.listExports.invalidate();
      utils.oscalExport.getStats.invalidate();
      setNewExport({ documentType: "ssp", title: "", description: "", outputFormat: "json" });
      setGenerating(false);
    },
    onError: (err) => {
      toast.error("Generation Failed: " + err.message);
      setGenerating(false);
    },
  });

  const handleGenerate = () => {
    setGenerating(true);
    generateMutation.mutate(newExport);
  };

  const handleDownload = (data: any) => {
    const json = JSON.stringify(data.document, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `oscal-${data.documentType}-${data.exportId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exports = exportsQuery.data || [];
  const stats = statsQuery.data;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <FileOutput className="h-7 w-7 text-blue-500" />
            OSCAL Export Engine
          </h1>
          <p className="text-muted-foreground mt-1">
            Generate machine-readable OSCAL v1.1.2 compliance documents for FedRAMP 20x
          </p>
        </div>
        <div className="flex gap-2">
          <Dialog open={showGenerateDialog} onOpenChange={setShowGenerateDialog}>
            <DialogTrigger asChild>
              <Button size="sm"><Plus className="h-4 w-4 mr-1" /> Generate Document</Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Generate OSCAL Document</DialogTitle>
                <DialogDescription>Create a machine-readable compliance document from your KSI data</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Document Type</Label>
                  <div className="grid grid-cols-1 gap-2 mt-2">
                    {DOC_TYPES.map(dt => (
                      <button
                        key={dt.id}
                        className={`flex items-start gap-3 p-3 rounded-lg border text-left transition-colors ${
                          newExport.documentType === dt.id ? "border-blue-500 bg-blue-500/10" : "border-border hover:bg-muted/50"
                        }`}
                        onClick={() => setNewExport(p => ({ ...p, documentType: dt.id }))}
                      >
                        <dt.icon className={`h-5 w-5 mt-0.5 ${newExport.documentType === dt.id ? "text-blue-500" : "text-muted-foreground"}`} />
                        <div>
                          <div className="text-sm font-medium">{dt.name}</div>
                          <div className="text-xs text-muted-foreground">{dt.description}</div>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <Label>Title</Label>
                  <Input
                    value={newExport.title}
                    onChange={(e) => setNewExport(p => ({ ...p, title: e.target.value }))}
                    placeholder={`ACE C3 ${newExport.documentType.toUpperCase()} — FedRAMP 20x`}
                  />
                </div>
                <div>
                  <Label>Description (optional)</Label>
                  <Textarea
                    value={newExport.description}
                    onChange={(e) => setNewExport(p => ({ ...p, description: e.target.value }))}
                    placeholder="Additional context for this export..."
                  />
                </div>
                <div>
                  <Label>Output Format</Label>
                  <Select value={newExport.outputFormat} onValueChange={(v) => setNewExport(p => ({ ...p, outputFormat: v as any }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="xml">XML (coming soon)</SelectItem>
                      <SelectItem value="yaml">YAML (coming soon)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <Button onClick={handleGenerate} disabled={!newExport.title || generating}>
                  {generating ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <FileOutput className="h-4 w-4 mr-1" />}
                  Generate
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
          <Button variant="outline" size="sm" onClick={() => { exportsQuery.refetch(); statsQuery.refetch(); }}>
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="text-xs text-muted-foreground uppercase">Total Exports</div>
            <div className="text-2xl font-bold mt-1">{stats?.totalExports || 0}</div>
          </CardContent>
        </Card>
        {stats?.byType?.map((t: any) => (
          <Card key={t.type}>
            <CardContent className="pt-4 pb-3">
              <div className="text-xs text-muted-foreground uppercase">{t.type.toUpperCase()}</div>
              <div className="text-2xl font-bold mt-1">{t.count}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Document Type Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {DOC_TYPES.map(dt => (
          <Card key={dt.id} className="hover:border-blue-500/30 transition-colors cursor-pointer" onClick={() => {
            setNewExport(p => ({ ...p, documentType: dt.id, title: `ACE C3 ${dt.id.toUpperCase()} — FedRAMP 20x` }));
            setShowGenerateDialog(true);
          }}>
            <CardContent className="pt-5 pb-4">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg bg-blue-500/10">
                  <dt.icon className="h-5 w-5 text-blue-500" />
                </div>
                <div>
                  <div className="font-medium text-sm">{dt.name}</div>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">{dt.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Export History */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Export History</CardTitle>
          <CardDescription>Previously generated OSCAL documents</CardDescription>
        </CardHeader>
        <CardContent>
          {exports.length > 0 ? (
            <div className="space-y-2">
              {exports.map((exp: any) => (
                <div key={exp.exportId} className="flex items-center justify-between py-3 border-b last:border-0">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-xs uppercase">{exp.documentType}</Badge>
                      <span className="text-sm font-medium">{exp.title}</span>
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                      <span>OSCAL v{exp.oscalVersion}</span>
                      <span>·</span>
                      <span>{exp.outputFormat.toUpperCase()}</span>
                      <span>·</span>
                      <span>{new Date(exp.createdAt).toLocaleString()}</span>
                      {exp.outputHash && (
                        <>
                          <span>·</span>
                          <span className="font-mono flex items-center gap-1">
                            <Hash className="h-3 w-3" />
                            {exp.outputHash.slice(0, 16)}...
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={
                      exp.status === "complete" ? "default" :
                      exp.status === "failed" ? "destructive" :
                      exp.status === "generating" ? "secondary" :
                      "outline"
                    }>
                      {exp.status === "complete" && <CheckCircle2 className="h-3 w-3 mr-1" />}
                      {exp.status === "failed" && <XCircle className="h-3 w-3 mr-1" />}
                      {exp.status === "generating" && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                      {exp.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <FileJson className="h-10 w-10 mx-auto mb-3 opacity-40" />
              <p className="font-medium">No exports yet</p>
              <p className="text-sm mt-1">Generate your first OSCAL document above</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Preview Dialog */}
      <Dialog open={showPreviewDialog} onOpenChange={setShowPreviewDialog}>
        <DialogContent className="max-w-3xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle>OSCAL Document Preview</DialogTitle>
            <DialogDescription>
              {previewData?.documentType?.toUpperCase()} — {previewData?.exportId}
              {previewData?.outputHash && ` — SHA-256: ${previewData.outputHash.slice(0, 24)}...`}
            </DialogDescription>
          </DialogHeader>
          <div className="overflow-auto max-h-[60vh] bg-muted/30 rounded-lg p-4">
            <pre className="text-xs font-mono whitespace-pre-wrap">
              {previewData?.document ? JSON.stringify(previewData.document, null, 2).slice(0, 10000) : "No data"}
              {previewData?.document && JSON.stringify(previewData.document, null, 2).length > 10000 && "\n\n... (truncated for preview)"}
            </pre>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowPreviewDialog(false)}>Close</Button>
            {previewData && (
              <Button onClick={() => handleDownload(previewData)}>
                <Download className="h-4 w-4 mr-1" />
                Download JSON
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
