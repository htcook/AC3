import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  ShieldAlert, Link2, Plus, Search, CheckCircle2, XCircle,
  AlertTriangle, Shield, Loader2, RefreshCw, Hash, Eye
} from "lucide-react";
import { formatKsiId, getKsiLabel, getThemeLabel, getThemeFromKsiId } from "@/lib/ksi-labels";
import { getKsiEnriched, getCoverageBadgeClass } from "@/lib/ksi-enriched-data";
import EvidenceTimeline from "@/components/EvidenceTimeline";

const EVIDENCE_TYPES = [
  "scan_result", "configuration_check", "log_entry", "screenshot",
  "document", "api_response", "test_result", "attestation",
  "policy_document", "training_record", "incident_report", "audit_log"
] as const;

const COLLECTION_METHODS = ["automated", "manual", "hybrid"] as const;

export default function KsiEvidenceChain() {
  
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [showCollectDialog, setShowCollectDialog] = useState(false);
  const [showChainDialog, setShowChainDialog] = useState(false);

  // Form state for collecting evidence
  const [newEvidence, setNewEvidence] = useState({
    ksiId: "",
    title: "",
    description: "",
    evidenceType: "scan_result" as typeof EVIDENCE_TYPES[number],
    sourceModule: "",
    sourceId: "",
    collectionMethod: "automated" as typeof COLLECTION_METHODS[number],
  });

  // Form state for creating chains
  const [newChain, setNewChain] = useState({
    ksiId: "",
    name: "",
    description: "",
  });

  const utils = trpc.useUtils();

  const evidenceQuery = trpc.ksiEvidenceChain.listEvidence.useQuery(
    statusFilter !== "all" ? { status: statusFilter as any } : undefined
  );
  const chainsQuery = trpc.ksiEvidenceChain.listChains.useQuery();
  const defsQuery = trpc.ksiEvidenceChain.listDefinitions.useQuery();

  const collectMutation = trpc.ksiEvidenceChain.collectEvidence.useMutation({
    onSuccess: (data) => {
      toast.success(`Evidence Collected: ID: ${data.evidenceId} — Hash: ${data.integrityHash.slice(0, 16)}...`);
      setShowCollectDialog(false);
      utils.ksiEvidenceChain.listEvidence.invalidate();
      utils.ksiEvidenceChain.getDashboardStats.invalidate();
      setNewEvidence({ ksiId: "", title: "", description: "", evidenceType: "scan_result", sourceModule: "", sourceId: "", collectionMethod: "automated" });
    },
    onError: (err) => toast.error("Error: " + err.message),
  });

  const createChainMutation = trpc.ksiEvidenceChain.createChain.useMutation({
    onSuccess: (data) => {
      toast.success(`Chain Created: Chain ID: ${data.chainId}`);
      setShowChainDialog(false);
      utils.ksiEvidenceChain.listChains.invalidate();
      setNewChain({ ksiId: "", name: "", description: "" });
    },
  });

  const verifyChainMutation = trpc.ksiEvidenceChain.verifyChain.useMutation({
    onSuccess: (data) => {
      if (data.valid) {
        toast.success(`Chain Valid: ${data.evidenceCount} evidence items verified`);
      } else {
        toast.error(`Chain Broken at ${data.brokenAt}`);
      }
      utils.ksiEvidenceChain.listChains.invalidate();
    },
  });

  const validateMutation = trpc.ksiEvidenceChain.validateEvidence.useMutation({
    onSuccess: () => {
      toast.success("Evidence Updated");
      utils.ksiEvidenceChain.listEvidence.invalidate();
    },
  });

  const evidence = evidenceQuery.data?.evidence || [];
  const chains = chainsQuery.data || [];
  const defs = defsQuery.data || [];

  const filteredEvidence = useMemo(() => {
    if (!searchTerm) return evidence;
    const lower = searchTerm.toLowerCase();
    return evidence.filter((e: any) =>
      e.title?.toLowerCase().includes(lower) ||
      e.ksiId?.toLowerCase().includes(lower) ||
      e.sourceModule?.toLowerCase().includes(lower) ||
      e.evidenceId?.toLowerCase().includes(lower)
    );
  }, [evidence, searchTerm]);

  const ksiOptions = defs.length > 0
    ? defs.map((d: any) => ({ value: d.ksiId, label: `${d.ksiId}: ${d.title}` }))
    : [];

  return (
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldAlert className="h-7 w-7 text-blue-500" />
            Indicator Evidence Chain
          </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Trace the full evidence chain for Key Security Indicators — from initial collection through analysis to final assessment. Each KSI shows its provenance: which source reported it, when it was collected, how it was validated, and what confidence level it carries. Use this page to verify intelligence quality and maintain audit trails for your threat assessments.</p>
          <p className="text-muted-foreground mt-1">
            Tamper-evident evidence collection with SHA-256 hash chaining for FedRAMP compliance
          </p>
        </div>
        <div className="flex gap-2">
          <Dialog open={showCollectDialog} onOpenChange={setShowCollectDialog}>
            <DialogTrigger asChild>
              <Button size="sm"><Plus className="h-4 w-4 mr-1" /> Collect Evidence</Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Collect Evidence</DialogTitle>
                <DialogDescription>Add a new evidence artifact linked to a KSI</DialogDescription>
              </DialogHeader>
              <div className="space-y-3">
                <div>
                  <Label>KSI</Label>
                  <Select value={newEvidence.ksiId} onValueChange={(v) => setNewEvidence(p => ({ ...p, ksiId: v }))}>
                    <SelectTrigger><SelectValue placeholder="Select KSI..." /></SelectTrigger>
                    <SelectContent>
                      {ksiOptions.map((o: any) => (
                        <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Title</Label>
                  <Input value={newEvidence.title} onChange={(e) => setNewEvidence(p => ({ ...p, title: e.target.value }))} placeholder="Evidence title..." />
                </div>
                <div>
                  <Label>Description</Label>
                  <Textarea value={newEvidence.description} onChange={(e) => setNewEvidence(p => ({ ...p, description: e.target.value }))} placeholder="Describe the evidence..." />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label>Evidence Type</Label>
                    <Select value={newEvidence.evidenceType} onValueChange={(v) => setNewEvidence(p => ({ ...p, evidenceType: v as any }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {EVIDENCE_TYPES.map(t => (
                          <SelectItem key={t} value={t}>{t.replace(/_/g, " ")}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Collection Method</Label>
                    <Select value={newEvidence.collectionMethod} onValueChange={(v) => setNewEvidence(p => ({ ...p, collectionMethod: v as any }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {COLLECTION_METHODS.map(m => (
                          <SelectItem key={m} value={m}>{m}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <Label>Source Module</Label>
                  <Input value={newEvidence.sourceModule} onChange={(e) => setNewEvidence(p => ({ ...p, sourceModule: e.target.value }))} placeholder="e.g., SIEM Integration" />
                </div>
              </div>
              <DialogFooter>
                <Button onClick={() => collectMutation.mutate(newEvidence)} disabled={!newEvidence.ksiId || !newEvidence.title || !newEvidence.sourceModule || collectMutation.isPending}>
                  {collectMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Plus className="h-4 w-4 mr-1" />}
                  Collect
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={showChainDialog} onOpenChange={setShowChainDialog}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm"><Link2 className="h-4 w-4 mr-1" /> New Chain</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create Evidence Chain</DialogTitle>
                <DialogDescription>Create a named chain to track evidence integrity for a KSI</DialogDescription>
              </DialogHeader>
              <div className="space-y-3">
                <div>
                  <Label>KSI</Label>
                  <Select value={newChain.ksiId} onValueChange={(v) => setNewChain(p => ({ ...p, ksiId: v }))}>
                    <SelectTrigger><SelectValue placeholder="Select KSI..." /></SelectTrigger>
                    <SelectContent>
                      {ksiOptions.map((o: any) => (
                        <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Chain Name</Label>
                  <Input value={newChain.name} onChange={(e) => setNewChain(p => ({ ...p, name: e.target.value }))} placeholder="e.g., Q1 2026 MFA Compliance" />
                </div>
                <div>
                  <Label>Description</Label>
                  <Textarea value={newChain.description} onChange={(e) => setNewChain(p => ({ ...p, description: e.target.value }))} />
                </div>
              </div>
              <DialogFooter>
                <Button onClick={() => createChainMutation.mutate(newChain)} disabled={!newChain.ksiId || !newChain.name}>
                  Create Chain
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <Tabs defaultValue="timeline" className="space-y-4">
        <TabsList>
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
          <TabsTrigger value="evidence">Evidence ({evidence.length})</TabsTrigger>
          <TabsTrigger value="chains">Chains ({chains.length})</TabsTrigger>
          <TabsTrigger value="definitions">KSI Catalog ({defs.length})</TabsTrigger>
        </TabsList>

        {/* Timeline Tab — visual hash-linked timeline */}
        <TabsContent value="timeline">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Evidence Chain Timeline</CardTitle>
              <CardDescription>Visual timeline showing evidence collection with SHA-256 hash chain links. Each item is cryptographically linked to the previous, forming a tamper-evident audit trail.</CardDescription>
            </CardHeader>
            <CardContent>
              <EvidenceTimeline evidence={filteredEvidence} maxItems={30} />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Evidence Tab */}
        <TabsContent value="evidence" className="space-y-4">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input className="pl-9" placeholder="Search evidence..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="collected">Collected</SelectItem>
                <SelectItem value="verified">Verified</SelectItem>
                <SelectItem value="validated">Validated</SelectItem>
                <SelectItem value="expired">Expired</SelectItem>
                <SelectItem value="rejected">Rejected</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="icon" onClick={() => evidenceQuery.refetch()}>
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>

          {filteredEvidence.length > 0 ? (
            <div className="space-y-2">
              {filteredEvidence.map((ev: any) => (
                <Card key={ev.evidenceId}>
                  <CardContent className="py-3 px-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs" title={formatKsiId(ev.ksiId)}>{ev.ksiId}</Badge>
                          <span className="font-medium text-sm">{ev.title}</span>
                          <span className="text-xs text-muted-foreground hidden md:inline">({getKsiEnriched(ev.ksiId)?.name || getKsiLabel(ev.ksiId)})</span>
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                          <span>{ev.evidenceType?.replace(/_/g, " ")}</span>
                          <span>·</span>
                          <span>{ev.sourceModule}</span>
                          <span>·</span>
                          <span>{ev.collectionMethod}</span>
                        </div>
                        <div className="flex items-center gap-1 mt-1 text-xs font-mono text-muted-foreground">
                          <Hash className="h-3 w-3" />
                          {ev.integrityHash?.slice(0, 32)}...
                          {ev.previousHash && (
                            <span className="ml-2 text-blue-400">← {ev.previousHash.slice(0, 12)}...</span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={
                          ev.status === "validated" ? "default" :
                          ev.status === "verified" ? "secondary" :
                          ev.status === "rejected" ? "destructive" :
                          "outline"
                        }>
                          {ev.status}
                        </Badge>
                        {ev.status === "collected" && (
                          <Button size="sm" variant="ghost" onClick={() => validateMutation.mutate({ evidenceId: ev.evidenceId, status: "verified" })}>
                            <CheckCircle2 className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <ShieldAlert className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p className="font-medium">No evidence collected yet</p>
                <p className="text-sm mt-1">Click "Collect Evidence" to add your first artifact</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Chains Tab */}
        <TabsContent value="chains" className="space-y-4">
          {chains.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {chains.map((chain: any) => (
                <Card key={chain.chainId}>
                  <CardContent className="py-4 px-4">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          {chain.chainValid ? (
                            <Shield className="h-5 w-5 text-emerald-500" />
                          ) : (
                            <ShieldAlert className="h-5 w-5 text-red-500" />
                          )}
                          <span className="font-medium">{chain.name}</span>
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {formatKsiId(chain.ksiId)} · {chain.evidenceCount || 0} evidence items
                        </div>
                        {chain.chainHash && (
                          <div className="text-xs font-mono text-muted-foreground mt-1">
                            Chain hash: {chain.chainHash.slice(0, 24)}...
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={
                          chain.status === "active" ? "default" :
                          chain.status === "complete" ? "secondary" :
                          chain.status === "broken" ? "destructive" :
                          "outline"
                        }>
                          {chain.status}
                        </Badge>
                        <Button size="sm" variant="ghost" onClick={() => verifyChainMutation.mutate({ chainId: chain.chainId })} disabled={verifyChainMutation.isPending}>
                          {verifyChainMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <Link2 className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p className="font-medium">No evidence chains created</p>
                <p className="text-sm mt-1">Create a chain to track evidence integrity for a KSI</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* KSI Definitions Tab */}
        <TabsContent value="definitions" className="space-y-4">
          {defs.length > 0 ? (
            <div className="space-y-2">
              {defs.map((def: any) => {
                const enriched = getKsiEnriched(def.ksiId);
                return (
                <Card key={def.ksiId}>
                  <CardContent className="py-3 px-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs font-mono" title={formatKsiId(def.ksiId)}>{def.ksiId}</Badge>
                          <span className="text-sm font-medium">{enriched?.name || def.title}</span>
                        </div>
                        {enriched && (
                          <p className="text-xs text-muted-foreground mt-1.5 leading-relaxed max-w-2xl">{enriched.requirement}</p>
                        )}
                        <div className="text-xs text-muted-foreground mt-1">
                          {getThemeLabel(getThemeFromKsiId(def.ksiId))} · {enriched?.validationMethod || def.validationType} validation · {enriched?.frequency || def.frequency}
                        </div>
                        {enriched && enriched.aceModules.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1.5">
                            {enriched.aceModules.map((m, i) => (
                              <Badge key={i} variant="outline" className="text-[10px] h-4 px-1 text-blue-400 border-blue-500/30">{m.name}</Badge>
                            ))}
                          </div>
                        )}
                        {!enriched && def.aceC3Module && (
                          <div className="text-xs text-blue-400 mt-0.5">Module: {def.aceC3Module}</div>
                        )}
                      </div>
                      <Badge className={enriched ? getCoverageBadgeClass(enriched.coverageLevel) : undefined} variant={
                        !enriched ? (def.coverageStatus === "direct" ? "default" :
                        def.coverageStatus === "supporting" ? "secondary" :
                        "outline") : "outline"
                      }>
                        {enriched?.coverageLevel || def.coverageStatus}
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
                );
              })}
            </div>
          ) : (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <Eye className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p className="font-medium">KSI catalog not loaded</p>
                <p className="text-sm mt-1">Go to KSI Dashboard and click "Seed KSI Catalog"</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
