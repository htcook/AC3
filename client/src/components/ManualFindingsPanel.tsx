import { useState, useRef, useCallback, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Plus, Upload, FileText, Image, Terminal, Code, Globe, Paperclip,
  Trash2, Eye, AlertTriangle, Shield, ChevronDown, ChevronUp,
  CheckCircle2, XCircle, Clock, Edit2, Save, X
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface ManualEvidence {
  type: string;
  name: string;
  mimeType: string;
  url?: string;
  textContent?: string;
  caption?: string;
}

interface ManualFinding {
  id: string;
  asset: string;
  title: string;
  severity: string;
  cvss?: number;
  cve?: string;
  cwe?: string;
  description: string;
  stepsToReproduce?: string;
  impact?: string;
  remediation?: string;
  category: string;
  tags: string[];
  submittedBy: string;
  submittedAt: number;
  status: string;
  notes?: string;
  evidence: ManualEvidence[];
}

interface ManualFindingsPanelProps {
  engagementId: string;
  assets: Array<{ hostname: string; ip?: string }>;
}

const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "Informational"];
const CATEGORY_OPTIONS = [
  "Authentication", "Authorization", "Injection", "XSS", "CSRF", "SSRF",
  "File Upload", "Information Disclosure", "Cryptography", "Configuration",
  "Business Logic", "API Security", "Network", "Privilege Escalation",
  "Remote Code Execution", "Denial of Service", "Other"
];
const EVIDENCE_TYPES = [
  { value: "screenshot", label: "Screenshot", icon: Image },
  { value: "terminal_output", label: "Terminal Output", icon: Terminal },
  { value: "http_request_response", label: "HTTP Request/Response", icon: Globe },
  { value: "exploit_code", label: "Exploit Code", icon: Code },
  { value: "tool_output", label: "Tool Output", icon: FileText },
  { value: "notes", label: "Notes", icon: FileText },
  { value: "pcap", label: "PCAP Capture", icon: Paperclip },
  { value: "video", label: "Video Recording", icon: Paperclip },
  { value: "document", label: "Document", icon: FileText },
];

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "bg-red-500/20 text-red-400 border-red-500/30",
  High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  Medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  Low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  Informational: "bg-slate-500/20 text-slate-400 border-slate-500/30",
};

const STATUS_ICONS: Record<string, any> = {
  draft: Clock,
  submitted: CheckCircle2,
  verified: Shield,
  rejected: XCircle,
};

export default function ManualFindingsPanel({ engagementId, assets }: ManualFindingsPanelProps) {
  const { toast } = useToast();
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [editingId, setEditingId] = useState<string | null>(null);

  // Form state
  const [formData, setFormData] = useState({
    title: "",
    asset: "",
    severity: "Medium",
    cvss: "",
    cve: "",
    cwe: "",
    description: "",
    stepsToReproduce: "",
    impact: "",
    remediation: "",
    category: "Other",
    tags: "",
    notes: "",
  });
  const [evidenceItems, setEvidenceItems] = useState<Array<{
    type: string;
    name: string;
    textContent?: string;
    caption?: string;
    file?: File;
  }>>([]);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Queries
  const findingsQ = trpc.engagementOps.listManualFindings.useQuery(
    { engagementId },
    { refetchInterval: 15000 }
  );

  // Mutations
  const submitMutation = trpc.engagementOps.submitManualFinding.useMutation({
    onSuccess: () => {
      toast({ title: "Finding submitted", description: "Manual finding added to engagement." });
      findingsQ.refetch();
      resetForm();
      setShowCreateDialog(false);
    },
    onError: (err) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const updateMutation = trpc.engagementOps.updateManualFinding.useMutation({
    onSuccess: () => {
      toast({ title: "Finding updated" });
      findingsQ.refetch();
      setEditingId(null);
    },
    onError: (err) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const deleteMutation = trpc.engagementOps.deleteManualFinding.useMutation({
    onSuccess: () => {
      toast({ title: "Finding deleted" });
      findingsQ.refetch();
    },
    onError: (err) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const uploadMutation = trpc.engagementOps.uploadManualEvidence.useMutation();

  const resetForm = useCallback(() => {
    setFormData({
      title: "", asset: "", severity: "Medium", cvss: "", cve: "", cwe: "",
      description: "", stepsToReproduce: "", impact: "", remediation: "",
      category: "Other", tags: "", notes: "",
    });
    setEvidenceItems([]);
  }, []);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files) return;
    for (const file of Array.from(files)) {
      const isText = file.type.startsWith("text/") || file.name.endsWith(".txt") ||
                     file.name.endsWith(".log") || file.name.endsWith(".py") ||
                     file.name.endsWith(".sh") || file.name.endsWith(".json") ||
                     file.name.endsWith(".xml") || file.name.endsWith(".html") ||
                     file.name.endsWith(".md") || file.name.endsWith(".csv");
      const isImage = file.type.startsWith("image/");
      const type = isImage ? "screenshot" : isText ? "tool_output" : "document";
      setEvidenceItems(prev => [...prev, { type, name: file.name, file, caption: "" }]);
    }
    e.target.value = "";
  }, []);

  const addTextEvidence = useCallback((type: string) => {
    setEvidenceItems(prev => [...prev, {
      type,
      name: type === "terminal_output" ? "Terminal Output" :
            type === "http_request_response" ? "HTTP Request/Response" :
            type === "exploit_code" ? "Exploit Code" :
            type === "notes" ? "Notes" : "Evidence",
      textContent: "",
      caption: "",
    }]);
  }, []);

  const handleSubmit = useCallback(async () => {
    if (!formData.title || !formData.asset || !formData.description) {
      toast({ title: "Missing fields", description: "Title, asset, and description are required.", variant: "destructive" });
      return;
    }

    // Upload file evidence first
    const processedEvidence: ManualEvidence[] = [];
    for (const item of evidenceItems) {
      if (item.file) {
        try {
          const reader = new FileReader();
          const base64 = await new Promise<string>((resolve, reject) => {
            reader.onload = () => resolve((reader.result as string).split(",")[1]);
            reader.onerror = reject;
            reader.readAsDataURL(item.file!);
          });
          const result = await uploadMutation.mutateAsync({
            engagementId,
            fileName: item.file.name,
            mimeType: item.file.type || "application/octet-stream",
            base64Data: base64,
          });
          processedEvidence.push({
            type: item.type,
            name: item.name,
            mimeType: item.file.type || "application/octet-stream",
            url: result.url,
            caption: item.caption,
          });
        } catch (err: any) {
          toast({ title: "Upload failed", description: `Failed to upload ${item.name}: ${err.message}`, variant: "destructive" });
          return;
        }
      } else if (item.textContent) {
        processedEvidence.push({
          type: item.type,
          name: item.name,
          mimeType: "text/plain",
          textContent: item.textContent,
          caption: item.caption,
        });
      }
    }

    submitMutation.mutate({
      engagementId,
      title: formData.title,
      asset: formData.asset,
      severity: formData.severity,
      cvss: formData.cvss ? parseFloat(formData.cvss) : undefined,
      cve: formData.cve || undefined,
      cwe: formData.cwe || undefined,
      description: formData.description,
      stepsToReproduce: formData.stepsToReproduce || undefined,
      impact: formData.impact || undefined,
      remediation: formData.remediation || undefined,
      category: formData.category,
      tags: formData.tags ? formData.tags.split(",").map(t => t.trim()).filter(Boolean) : [],
      notes: formData.notes || undefined,
      evidence: processedEvidence,
    });
  }, [formData, evidenceItems, engagementId, submitMutation, uploadMutation, toast]);

  const findings = useMemo(() => {
    let list = (findingsQ.data?.findings || []) as ManualFinding[];
    if (filterSeverity !== "all") list = list.filter(f => f.severity === filterSeverity);
    if (filterStatus !== "all") list = list.filter(f => f.status === filterStatus);
    return list.sort((a, b) => {
      const sevOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };
      return (sevOrder[a.severity as keyof typeof sevOrder] ?? 5) - (sevOrder[b.severity as keyof typeof sevOrder] ?? 5);
    });
  }, [findingsQ.data, filterSeverity, filterStatus]);

  const stats = useMemo(() => {
    const all = (findingsQ.data?.findings || []) as ManualFinding[];
    return {
      total: all.length,
      critical: all.filter(f => f.severity === "Critical").length,
      high: all.filter(f => f.severity === "High").length,
      medium: all.filter(f => f.severity === "Medium").length,
      low: all.filter(f => f.severity === "Low").length,
      info: all.filter(f => f.severity === "Informational").length,
      verified: all.filter(f => f.status === "verified").length,
    };
  }, [findingsQ.data]);

  return (
    <div className="space-y-4">
      {/* Stats Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-zinc-100">{stats.total}</div>
            <div className="text-xs text-zinc-500">Total</div>
          </CardContent>
        </Card>
        {[
          { label: "Critical", count: stats.critical, color: "text-red-400" },
          { label: "High", count: stats.high, color: "text-orange-400" },
          { label: "Medium", count: stats.medium, color: "text-yellow-400" },
          { label: "Low", count: stats.low, color: "text-blue-400" },
          { label: "Info", count: stats.info, color: "text-slate-400" },
          { label: "Verified", count: stats.verified, color: "text-green-400" },
        ].map(s => (
          <Card key={s.label} className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-3 text-center">
              <div className={`text-2xl font-bold ${s.color}`}>{s.count}</div>
              <div className="text-xs text-zinc-500">{s.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2">
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-1.5">
              <Plus className="h-4 w-4" /> Submit Finding
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Submit Manual Finding</DialogTitle>
              <DialogDescription>
                Submit a finding from manual testing. Include evidence such as screenshots, terminal output, or HTTP request/response pairs.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              {/* Basic Info */}
              <div className="grid grid-cols-2 gap-3">
                <div className="col-span-2">
                  <label className="text-xs text-zinc-400 mb-1 block">Title *</label>
                  <Input
                    placeholder="e.g., SQL Injection in Login Form"
                    value={formData.title}
                    onChange={e => setFormData(p => ({ ...p, title: e.target.value }))}
                  />
                </div>
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">Target Asset *</label>
                  <Select value={formData.asset} onValueChange={v => setFormData(p => ({ ...p, asset: v }))}>
                    <SelectTrigger><SelectValue placeholder="Select asset" /></SelectTrigger>
                    <SelectContent>
                      {assets.map(a => (
                        <SelectItem key={a.hostname} value={a.hostname}>
                          {a.hostname}{a.ip ? ` (${a.ip})` : ""}
                        </SelectItem>
                      ))}
                      <SelectItem value="__custom__">Custom...</SelectItem>
                    </SelectContent>
                  </Select>
                  {formData.asset === "__custom__" && (
                    <Input
                      className="mt-1"
                      placeholder="Enter hostname or IP"
                      onChange={e => setFormData(p => ({ ...p, asset: e.target.value }))}
                    />
                  )}
                </div>
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">Severity</label>
                  <Select value={formData.severity} onValueChange={v => setFormData(p => ({ ...p, severity: v }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {SEVERITY_OPTIONS.map(s => (
                        <SelectItem key={s} value={s}>{s}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">Category</label>
                  <Select value={formData.category} onValueChange={v => setFormData(p => ({ ...p, category: v }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {CATEGORY_OPTIONS.map(c => (
                        <SelectItem key={c} value={c}>{c}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">CVSS Score</label>
                  <Input
                    type="number" min="0" max="10" step="0.1"
                    placeholder="e.g., 9.8"
                    value={formData.cvss}
                    onChange={e => setFormData(p => ({ ...p, cvss: e.target.value }))}
                  />
                </div>
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">CVE ID</label>
                  <Input
                    placeholder="e.g., CVE-2024-1234"
                    value={formData.cve}
                    onChange={e => setFormData(p => ({ ...p, cve: e.target.value }))}
                  />
                </div>
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">CWE ID</label>
                  <Input
                    placeholder="e.g., CWE-89"
                    value={formData.cwe}
                    onChange={e => setFormData(p => ({ ...p, cwe: e.target.value }))}
                  />
                </div>
              </div>

              {/* Description */}
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">Description *</label>
                <Textarea
                  rows={3}
                  placeholder="Describe the vulnerability, how it was discovered, and its context..."
                  value={formData.description}
                  onChange={e => setFormData(p => ({ ...p, description: e.target.value }))}
                />
              </div>

              {/* Steps to Reproduce */}
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">Steps to Reproduce</label>
                <Textarea
                  rows={4}
                  placeholder={"1. Navigate to /login\n2. Enter ' OR 1=1-- in username field\n3. Submit the form\n4. Observe SQL error in response"}
                  value={formData.stepsToReproduce}
                  onChange={e => setFormData(p => ({ ...p, stepsToReproduce: e.target.value }))}
                />
              </div>

              {/* Impact & Remediation */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">Impact</label>
                  <Textarea
                    rows={2}
                    placeholder="What can an attacker achieve?"
                    value={formData.impact}
                    onChange={e => setFormData(p => ({ ...p, impact: e.target.value }))}
                  />
                </div>
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">Remediation</label>
                  <Textarea
                    rows={2}
                    placeholder="How should this be fixed?"
                    value={formData.remediation}
                    onChange={e => setFormData(p => ({ ...p, remediation: e.target.value }))}
                  />
                </div>
              </div>

              {/* Tags */}
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">Tags (comma-separated)</label>
                <Input
                  placeholder="e.g., owasp-top10, manual, authenticated"
                  value={formData.tags}
                  onChange={e => setFormData(p => ({ ...p, tags: e.target.value }))}
                />
              </div>

              {/* Notes */}
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">Operator Notes</label>
                <Textarea
                  rows={2}
                  placeholder="Internal notes for the team..."
                  value={formData.notes}
                  onChange={e => setFormData(p => ({ ...p, notes: e.target.value }))}
                />
              </div>

              {/* Evidence Section */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm font-medium text-zinc-300">Evidence Attachments</label>
                  <div className="flex gap-1">
                    <Button variant="outline" size="sm" className="gap-1 text-xs" onClick={() => fileInputRef.current?.click()}>
                      <Upload className="h-3 w-3" /> Upload File
                    </Button>
                    <input ref={fileInputRef} type="file" multiple className="hidden" onChange={handleFileSelect}
                      accept="image/*,.txt,.log,.py,.sh,.json,.xml,.html,.md,.csv,.pcap,.pcapng,.mp4,.webm,.pdf,.doc,.docx" />
                    <Button variant="outline" size="sm" className="gap-1 text-xs" onClick={() => addTextEvidence("terminal_output")}>
                      <Terminal className="h-3 w-3" /> Terminal
                    </Button>
                    <Button variant="outline" size="sm" className="gap-1 text-xs" onClick={() => addTextEvidence("http_request_response")}>
                      <Globe className="h-3 w-3" /> HTTP
                    </Button>
                    <Button variant="outline" size="sm" className="gap-1 text-xs" onClick={() => addTextEvidence("exploit_code")}>
                      <Code className="h-3 w-3" /> Code
                    </Button>
                  </div>
                </div>

                {evidenceItems.length === 0 && (
                  <div className="border border-dashed border-zinc-700 rounded-lg p-6 text-center text-zinc-500 text-sm">
                    <Upload className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    Drag & drop files or use the buttons above to add evidence
                  </div>
                )}

                {evidenceItems.map((item, idx) => (
                  <Card key={idx} className="bg-zinc-900/50 border-zinc-800 mb-2">
                    <CardContent className="p-3">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          {(() => {
                            const EvidenceIcon = EVIDENCE_TYPES.find(t => t.value === item.type)?.icon || FileText;
                            return <EvidenceIcon className="h-4 w-4 text-zinc-400" />;
                          })()}
                          <span className="text-sm font-medium text-zinc-300">{item.name}</span>
                          <Badge variant="outline" className="text-xs">{item.type.replace(/_/g, " ")}</Badge>
                        </div>
                        <Button variant="ghost" size="sm" onClick={() => setEvidenceItems(p => p.filter((_, i) => i !== idx))}>
                          <Trash2 className="h-3 w-3 text-red-400" />
                        </Button>
                      </div>
                      {item.file && (
                        <div className="text-xs text-zinc-500">
                          {item.file.name} ({(item.file.size / 1024).toFixed(1)} KB)
                        </div>
                      )}
                      {!item.file && (
                        <Textarea
                          rows={4}
                          className="font-mono text-xs"
                          placeholder={
                            item.type === "terminal_output" ? "$ sqlmap -u 'http://target/login' --dbs\n[*] available databases [3]:\n[*] information_schema\n[*] mysql\n[*] webapp_db" :
                            item.type === "http_request_response" ? "POST /api/login HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"username\": \"admin' OR 1=1--\", \"password\": \"test\"}\n\n---\n\nHTTP/1.1 200 OK\n{\"token\": \"eyJ...\"}" :
                            item.type === "exploit_code" ? "import requests\n\nurl = 'http://target.com/api/login'\npayload = {\"username\": \"admin' OR 1=1--\"}\nresp = requests.post(url, json=payload)\nprint(resp.json())" :
                            "Paste evidence content here..."
                          }
                          value={item.textContent || ""}
                          onChange={e => setEvidenceItems(p => p.map((x, i) => i === idx ? { ...x, textContent: e.target.value } : x))}
                        />
                      )}
                      <Input
                        className="mt-2"
                        placeholder="Caption (optional)"
                        value={item.caption || ""}
                        onChange={e => setEvidenceItems(p => p.map((x, i) => i === idx ? { ...x, caption: e.target.value } : x))}
                      />
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>

            <DialogFooter className="mt-4">
              <Button variant="outline" onClick={() => { resetForm(); setShowCreateDialog(false); }}>Cancel</Button>
              <Button onClick={handleSubmit} disabled={submitMutation.isPending || uploadMutation.isPending}>
                {submitMutation.isPending ? "Submitting..." : "Submit Finding"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <Select value={filterSeverity} onValueChange={setFilterSeverity}>
          <SelectTrigger className="w-[130px] h-8 text-xs"><SelectValue placeholder="Severity" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            {SEVERITY_OPTIONS.map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>

        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="w-[120px] h-8 text-xs"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="draft">Draft</SelectItem>
            <SelectItem value="submitted">Submitted</SelectItem>
            <SelectItem value="verified">Verified</SelectItem>
            <SelectItem value="rejected">Rejected</SelectItem>
          </SelectContent>
        </Select>

        <div className="ml-auto text-xs text-zinc-500">
          {findings.length} finding{findings.length !== 1 ? "s" : ""}
          {findings.length !== (findingsQ.data?.findings?.length || 0) && ` (filtered from ${findingsQ.data?.findings?.length || 0})`}
        </div>
      </div>

      {/* Findings List */}
      {findingsQ.isLoading ? (
        <div className="text-center text-zinc-500 py-8">Loading manual findings...</div>
      ) : findings.length === 0 ? (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-8 text-center">
            <AlertTriangle className="h-10 w-10 mx-auto mb-3 text-zinc-600" />
            <p className="text-zinc-400 mb-1">No manual findings yet</p>
            <p className="text-xs text-zinc-600">Submit findings from manual testing to include them in the engagement report.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {findings.map(f => {
            const isExpanded = expandedFinding === f.id;
            const StatusIcon = STATUS_ICONS[f.status] || Clock;
            return (
              <Card key={f.id} className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors">
                <CardContent className="p-0">
                  {/* Header row */}
                  <div
                    className="flex items-center gap-3 p-3 cursor-pointer"
                    onClick={() => setExpandedFinding(isExpanded ? null : f.id)}
                  >
                    <Badge className={`${SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.Informational} text-xs shrink-0`}>
                      {f.severity}
                    </Badge>
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm text-zinc-200 truncate">{f.title}</div>
                      <div className="text-xs text-zinc-500 flex items-center gap-2 mt-0.5">
                        <span>{f.asset}</span>
                        <span>·</span>
                        <span>{f.category}</span>
                        <span>·</span>
                        <span>{f.evidence.length} evidence item{f.evidence.length !== 1 ? "s" : ""}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {f.cve && <Badge variant="outline" className="text-xs">{f.cve}</Badge>}
                      <StatusIcon className={`h-4 w-4 ${
                        f.status === "verified" ? "text-green-400" :
                        f.status === "rejected" ? "text-red-400" :
                        f.status === "submitted" ? "text-blue-400" : "text-zinc-500"
                      }`} />
                      {isExpanded ? <ChevronUp className="h-4 w-4 text-zinc-500" /> : <ChevronDown className="h-4 w-4 text-zinc-500" />}
                    </div>
                  </div>

                  {/* Expanded detail */}
                  {isExpanded && (
                    <div className="border-t border-zinc-800 p-4 space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <div className="text-xs text-zinc-500 mb-1">Description</div>
                          <div className="text-sm text-zinc-300 whitespace-pre-wrap">{f.description}</div>
                        </div>
                        <div className="space-y-2">
                          {f.cvss && (
                            <div><span className="text-xs text-zinc-500">CVSS:</span> <span className="text-sm text-zinc-300">{f.cvss}</span></div>
                          )}
                          {f.cwe && (
                            <div><span className="text-xs text-zinc-500">CWE:</span> <span className="text-sm text-zinc-300">{f.cwe}</span></div>
                          )}
                          <div><span className="text-xs text-zinc-500">Submitted by:</span> <span className="text-sm text-zinc-300">{f.submittedBy}</span></div>
                          <div><span className="text-xs text-zinc-500">Date:</span> <span className="text-sm text-zinc-300">{new Date(f.submittedAt).toLocaleString()}</span></div>
                          {f.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {f.tags.map(t => <Badge key={t} variant="outline" className="text-xs">{t}</Badge>)}
                            </div>
                          )}
                        </div>
                      </div>

                      {f.stepsToReproduce && (
                        <div>
                          <div className="text-xs text-zinc-500 mb-1">Steps to Reproduce</div>
                          <div className="text-sm text-zinc-300 whitespace-pre-wrap bg-zinc-950 rounded p-2 font-mono text-xs">{f.stepsToReproduce}</div>
                        </div>
                      )}

                      {f.impact && (
                        <div>
                          <div className="text-xs text-zinc-500 mb-1">Impact</div>
                          <div className="text-sm text-zinc-300">{f.impact}</div>
                        </div>
                      )}

                      {f.remediation && (
                        <div>
                          <div className="text-xs text-zinc-500 mb-1">Remediation</div>
                          <div className="text-sm text-zinc-300">{f.remediation}</div>
                        </div>
                      )}

                      {/* Evidence Gallery */}
                      {f.evidence.length > 0 && (
                        <div>
                          <div className="text-xs text-zinc-500 mb-2">Evidence ({f.evidence.length})</div>
                          <div className="space-y-2">
                            {f.evidence.map((ev, idx) => (
                              <Card key={idx} className="bg-zinc-950 border-zinc-800">
                                <CardContent className="p-3">
                                  <div className="flex items-center gap-2 mb-2">
                                    {(() => {
                                      const EvidenceIcon = EVIDENCE_TYPES.find(t => t.value === ev.type)?.icon || FileText;
                                      return <EvidenceIcon className="h-3.5 w-3.5 text-zinc-400" />;
                                    })()}
                                    <span className="text-xs font-medium text-zinc-300">{ev.name}</span>
                                    <Badge variant="outline" className="text-xs">{ev.type.replace(/_/g, " ")}</Badge>
                                  </div>
                                  {ev.url && ev.type === "screenshot" && (
                                    <img src={ev.url} alt={ev.caption || ev.name} className="max-h-64 rounded border border-zinc-700" />
                                  )}
                                  {ev.url && ev.type !== "screenshot" && (
                                    <a href={ev.url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:underline flex items-center gap-1">
                                      <Paperclip className="h-3 w-3" /> {ev.name}
                                    </a>
                                  )}
                                  {ev.textContent && (
                                    <pre className="text-xs font-mono text-zinc-400 bg-zinc-900 rounded p-2 max-h-48 overflow-auto whitespace-pre-wrap">
                                      {ev.textContent}
                                    </pre>
                                  )}
                                  {ev.caption && <div className="text-xs text-zinc-500 mt-1 italic">{ev.caption}</div>}
                                </CardContent>
                              </Card>
                            ))}
                          </div>
                        </div>
                      )}

                      {f.notes && (
                        <div>
                          <div className="text-xs text-zinc-500 mb-1">Operator Notes</div>
                          <div className="text-sm text-zinc-400 italic">{f.notes}</div>
                        </div>
                      )}

                      {/* Actions */}
                      <div className="flex gap-2 pt-2 border-t border-zinc-800">
                        <Button
                          variant="outline" size="sm" className="gap-1 text-xs"
                          onClick={() => updateMutation.mutate({ engagementId, findingId: f.id, status: "verified" })}
                          disabled={f.status === "verified"}
                        >
                          <CheckCircle2 className="h-3 w-3" /> Verify
                        </Button>
                        <Button
                          variant="outline" size="sm" className="gap-1 text-xs"
                          onClick={() => updateMutation.mutate({ engagementId, findingId: f.id, status: "rejected" })}
                          disabled={f.status === "rejected"}
                        >
                          <XCircle className="h-3 w-3" /> Reject
                        </Button>
                        <div className="ml-auto">
                          <Button
                            variant="ghost" size="sm" className="gap-1 text-xs text-red-400 hover:text-red-300"
                            onClick={() => {
                              if (confirm("Delete this finding? This cannot be undone.")) {
                                deleteMutation.mutate({ engagementId, findingId: f.id });
                              }
                            }}
                          >
                            <Trash2 className="h-3 w-3" /> Delete
                          </Button>
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
