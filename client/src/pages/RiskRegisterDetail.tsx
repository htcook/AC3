import { useState, useMemo } from "react";
import { useLocation, useParams } from "wouter";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import {
  ArrowLeft, Save, Trash2, ShieldCheck, ShieldAlert, Clock,
  AlertTriangle, CheckCircle2, FileText, Activity, Loader2,
  ExternalLink, Link2, Calendar, User, Eye, XCircle, Shield,
} from "lucide-react";

function SeverityBadge({ severity }: { severity: string | null }) {
  const s = severity?.toLowerCase() || "unknown";
  const colors: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    moderate: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    informational: "bg-gray-500/15 text-gray-400 border-gray-500/30",
  };
  return <Badge variant="outline" className={`text-xs font-medium ${colors[s] || colors.informational}`}>{severity || "Unknown"}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    open: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    closed: "bg-gray-500/15 text-gray-400 border-gray-500/30",
    risk_accepted: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    false_positive: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
    operationally_required: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    vendor_dependent: "bg-pink-500/15 text-pink-400 border-pink-500/30",
    deferred: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };
  const labels: Record<string, string> = {
    open: "Open", closed: "Closed", risk_accepted: "Risk Accepted",
    false_positive: "False Positive", operationally_required: "Op. Required",
    vendor_dependent: "Vendor Dep.", deferred: "Deferred",
  };
  return <Badge variant="outline" className={`text-xs font-medium ${colors[status] || ""}`}>{labels[status] || status}</Badge>;
}

export default function RiskRegisterDetail() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const entryId = Number(params.id);
  const utils = trpc.useUtils();

  const { data, isLoading, error } = trpc.riskRegister.get.useQuery({ id: entryId }, { enabled: !isNaN(entryId) });

  // Editable fields
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<Record<string, any>>({});
  const [showRiskDialog, setShowRiskDialog] = useState(false);
  const [riskDecision, setRiskDecision] = useState<string>("risk_accepted");
  const [riskJustification, setRiskJustification] = useState("");
  const [riskCompensating, setRiskCompensating] = useState("");
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);

  const startEditing = () => {
    if (!data?.entry) return;
    const e = data.entry;
    setForm({
      weaknessName: e.weaknessName,
      weaknessDescription: e.weaknessDescription || "",
      controls: e.controls || "",
      severity: e.severity || "moderate",
      adjustedRiskRating: e.adjustedRiskRating || e.severity || "moderate",
      category: e.category || "vulnerability",
      assetIdentifier: e.assetIdentifier || "",
      pointOfContact: e.pointOfContact || "",
      remediationPlan: e.remediationPlan || "",
      scheduledCompletionDate: e.scheduledCompletionDate ? new Date(e.scheduledCompletionDate).toISOString().slice(0, 10) : "",
      status: e.status,
      cve: e.cve || "",
      cvssScore: e.cvssScore || "",
      vendorDependency: e.vendorDependency || "No",
      vendorDependentProductName: e.vendorDependentProductName || "",
      impactLevel: e.impactLevel || "",
      comments: e.comments || "",
      compensatingControls: e.compensatingControls || "",
      deviationRationale: e.deviationRationale || "",
    });
    setEditing(true);
  };

  const updateMutation = trpc.riskRegister.update.useMutation({
    onSuccess: () => {
      toast.success("Entry updated");
      setEditing(false);
      utils.riskRegister.get.invalidate({ id: entryId });
      utils.riskRegister.list.invalidate();
    },
    onError: (err) => toast.error("Update failed", { description: err.message }),
  });

  const acceptRiskMutation = trpc.riskRegister.acceptRisk.useMutation({
    onSuccess: () => {
      toast.success("Risk decision recorded");
      setShowRiskDialog(false);
      setRiskJustification("");
      setRiskCompensating("");
      utils.riskRegister.get.invalidate({ id: entryId });
      utils.riskRegister.list.invalidate();
    },
    onError: (err) => toast.error("Risk decision failed", { description: err.message }),
  });

  const deleteMutation = trpc.riskRegister.delete.useMutation({
    onSuccess: () => {
      toast.success("Entry deleted");
      navigate("/risk-register");
    },
    onError: (err) => toast.error("Delete failed", { description: err.message }),
  });

  const handleSave = () => {
    const updates: any = { id: entryId };
    Object.entries(form).forEach(([key, val]) => {
      if (val !== undefined && val !== null) updates[key] = val;
    });
    // Convert scheduledCompletionDate to ISO string for DB
    if (updates.scheduledCompletionDate === "") updates.scheduledCompletionDate = null;
    updateMutation.mutate(updates);
  };

  if (isLoading) {
    return (
      <div className="space-y-6 p-1">
        <Skeleton className="h-10 w-48" />
        <Skeleton className="h-64 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  if (error || !data?.entry) {
    return (
      <div className="p-12 text-center">
        <AlertTriangle className="h-12 w-12 mx-auto text-destructive mb-4" />
        <h2 className="text-xl font-bold">Entry Not Found</h2>
        <p className="text-muted-foreground mt-2">{error?.message || "The requested risk register entry does not exist."}</p>
        <Button variant="outline" className="mt-4" onClick={() => navigate("/risk-register")}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Register
        </Button>
      </div>
    );
  }

  const entry = data.entry;
  const isOverdue = entry.status === "open" && entry.scheduledCompletionDate && new Date(entry.scheduledCompletionDate) < new Date();

  return (
    <div className="space-y-6 p-1">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate("/risk-register")}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold tracking-tight font-mono">{entry.poamId}</h1>
              <SeverityBadge severity={entry.severity} />
              <StatusBadge status={entry.status} />
              {isOverdue && (
                <Badge variant="outline" className="bg-red-500/15 text-red-400 border-red-500/30 text-xs">
                  <Clock className="h-3 w-3 mr-1" /> Overdue
                </Badge>
              )}
            </div>
            <p className="text-muted-foreground mt-1 text-sm max-w-2xl">{entry.weaknessName}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {!editing ? (
            <>
              <Dialog open={showRiskDialog} onOpenChange={setShowRiskDialog}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm" disabled={entry.status !== "open"}>
                    <Shield className="h-4 w-4 mr-2" /> Risk Decision
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Record Risk Decision</DialogTitle>
                    <DialogDescription>
                      Document a formal risk acceptance, false positive determination, or operational requirement for this POA&M item.
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4 py-4">
                    <div>
                      <Label>Decision</Label>
                      <Select value={riskDecision} onValueChange={setRiskDecision}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="risk_accepted">Risk Accepted</SelectItem>
                          <SelectItem value="false_positive">False Positive</SelectItem>
                          <SelectItem value="operationally_required">Operationally Required</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label>Justification (min 10 characters)</Label>
                      <Textarea
                        value={riskJustification}
                        onChange={e => setRiskJustification(e.target.value)}
                        placeholder="Provide detailed justification for this risk decision..."
                        rows={4}
                      />
                    </div>
                    <div>
                      <Label>Compensating Controls (optional)</Label>
                      <Textarea
                        value={riskCompensating}
                        onChange={e => setRiskCompensating(e.target.value)}
                        placeholder="Describe any compensating controls in place..."
                        rows={3}
                      />
                    </div>
                  </div>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setShowRiskDialog(false)}>Cancel</Button>
                    <Button
                      onClick={() => acceptRiskMutation.mutate({
                        id: entryId,
                        decision: riskDecision as any,
                        justification: riskJustification,
                        compensatingControls: riskCompensating || undefined,
                      })}
                      disabled={riskJustification.length < 10 || acceptRiskMutation.isPending}
                    >
                      {acceptRiskMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                      Record Decision
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
              <Button size="sm" onClick={startEditing}>Edit</Button>
              <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
                <DialogTrigger asChild>
                  <Button variant="destructive" size="sm"><Trash2 className="h-4 w-4" /></Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Delete Entry</DialogTitle>
                    <DialogDescription>This will permanently delete {entry.poamId} and all associated activity logs.</DialogDescription>
                  </DialogHeader>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setShowDeleteDialog(false)}>Cancel</Button>
                    <Button variant="destructive" onClick={() => deleteMutation.mutate({ id: entryId })} disabled={deleteMutation.isPending}>
                      {deleteMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                      Delete
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </>
          ) : (
            <>
              <Button variant="outline" size="sm" onClick={() => setEditing(false)}>Cancel</Button>
              <Button size="sm" onClick={handleSave} disabled={updateMutation.isPending}>
                {updateMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Save className="h-4 w-4 mr-2" />}
                Save
              </Button>
            </>
          )}
        </div>
      </div>

      <Tabs defaultValue="details" className="space-y-4">
        <TabsList>
          <TabsTrigger value="details">Details</TabsTrigger>
          <TabsTrigger value="remediation">Remediation</TabsTrigger>
          <TabsTrigger value="risk">Risk & Compliance</TabsTrigger>
          <TabsTrigger value="activity">Activity Log ({data.activity.length})</TabsTrigger>
        </TabsList>

        {/* Details Tab */}
        <TabsContent value="details" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-base">Weakness Information</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                {editing ? (
                  <>
                    <div><Label>Weakness Name</Label><Input value={form.weaknessName} onChange={e => setForm(f => ({ ...f, weaknessName: e.target.value }))} /></div>
                    <div><Label>Description</Label><Textarea value={form.weaknessDescription} onChange={e => setForm(f => ({ ...f, weaknessDescription: e.target.value }))} rows={4} /></div>
                    <div><Label>NIST SP 800-53 Controls</Label><Input value={form.controls} onChange={e => setForm(f => ({ ...f, controls: e.target.value }))} placeholder="e.g., RA-5, SI-2, CM-6" /></div>
                    <div className="grid grid-cols-2 gap-3">
                      <div><Label>Severity</Label>
                        <Select value={form.severity} onValueChange={v => setForm(f => ({ ...f, severity: v }))}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="critical">Critical</SelectItem>
                            <SelectItem value="high">High</SelectItem>
                            <SelectItem value="moderate">Moderate</SelectItem>
                            <SelectItem value="low">Low</SelectItem>
                            <SelectItem value="informational">Informational</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div><Label>Category</Label>
                        <Select value={form.category} onValueChange={v => setForm(f => ({ ...f, category: v }))}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="vulnerability">Vulnerability</SelectItem>
                            <SelectItem value="misconfiguration">Misconfiguration</SelectItem>
                            <SelectItem value="software_flaw">Software Flaw</SelectItem>
                            <SelectItem value="operational">Operational</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div><Label>CVE</Label><Input value={form.cve} onChange={e => setForm(f => ({ ...f, cve: e.target.value }))} placeholder="CVE-2024-XXXXX" /></div>
                      <div><Label>CVSS Score</Label><Input value={form.cvssScore} onChange={e => setForm(f => ({ ...f, cvssScore: e.target.value }))} placeholder="9.8" /></div>
                    </div>
                  </>
                ) : (
                  <>
                    <InfoRow label="Weakness Name" value={entry.weaknessName} />
                    <InfoRow label="Description" value={entry.weaknessDescription} />
                    <InfoRow label="Controls" value={entry.controls} />
                    <div className="grid grid-cols-2 gap-4">
                      <InfoRow label="Original Risk Rating" value={entry.originalRiskRating} badge />
                      <InfoRow label="Adjusted Risk Rating" value={entry.adjustedRiskRating} badge />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <InfoRow label="Category" value={entry.category} />
                      <InfoRow label="Impact Level" value={entry.impactLevel} />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <InfoRow label="CVE" value={entry.cve} mono />
                      <InfoRow label="CVSS Score" value={entry.cvssScore} />
                    </div>
                    <InfoRow label="Detector Source" value={entry.weaknessDetectorSource} />
                    <InfoRow label="Source Identifier" value={entry.weaknessSourceIdentifier} mono />
                  </>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle className="text-base">Asset & Assignment</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                {editing ? (
                  <>
                    <div><Label>Asset Identifier</Label><Input value={form.assetIdentifier} onChange={e => setForm(f => ({ ...f, assetIdentifier: e.target.value }))} /></div>
                    <div><Label>Point of Contact</Label><Input value={form.pointOfContact} onChange={e => setForm(f => ({ ...f, pointOfContact: e.target.value }))} /></div>
                    <div><Label>Status</Label>
                      <Select value={form.status} onValueChange={v => setForm(f => ({ ...f, status: v }))}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="open">Open</SelectItem>
                          <SelectItem value="closed">Closed</SelectItem>
                          <SelectItem value="risk_accepted">Risk Accepted</SelectItem>
                          <SelectItem value="false_positive">False Positive</SelectItem>
                          <SelectItem value="operationally_required">Op. Required</SelectItem>
                          <SelectItem value="vendor_dependent">Vendor Dependent</SelectItem>
                          <SelectItem value="deferred">Deferred</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div><Label>Vendor Dependency</Label>
                      <Select value={form.vendorDependency} onValueChange={v => setForm(f => ({ ...f, vendorDependency: v }))}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="No">No</SelectItem>
                          <SelectItem value="Yes">Yes</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    {form.vendorDependency === "Yes" && (
                      <div><Label>Vendor Product Name</Label><Input value={form.vendorDependentProductName} onChange={e => setForm(f => ({ ...f, vendorDependentProductName: e.target.value }))} /></div>
                    )}
                    <div><Label>Comments</Label><Textarea value={form.comments} onChange={e => setForm(f => ({ ...f, comments: e.target.value }))} rows={3} /></div>
                  </>
                ) : (
                  <>
                    <InfoRow label="Asset Identifier" value={entry.assetIdentifier} />
                    <InfoRow label="Point of Contact" value={entry.pointOfContact} />
                    <InfoRow label="Source Type" value={entry.sourceType} />
                    <InfoRow label="Source Engagement" value={entry.sourceEngagementId} mono />
                    <div className="grid grid-cols-2 gap-4">
                      <InfoRow label="Vendor Dependency" value={entry.vendorDependency} />
                      <InfoRow label="Vendor Product" value={entry.vendorDependentProductName} />
                    </div>
                    <InfoRow label="Comments" value={entry.comments} />
                  </>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Dates Card */}
          <Card>
            <CardHeader><CardTitle className="text-base">Timeline</CardTitle></CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <DateField label="Detection Date" value={entry.originalDetectionDate} />
                <DateField label="Scheduled Completion" value={entry.scheduledCompletionDate} overdue={!!isOverdue} editing={editing} editValue={form.scheduledCompletionDate} onChange={v => setForm(f => ({ ...f, scheduledCompletionDate: v }))} />
                <DateField label="Actual Completion" value={entry.actualCompletionDate} />
                <DateField label="Last Status Date" value={entry.statusDate} />
                <DateField label="Created" value={entry.createdAt} />
                <DateField label="Updated" value={entry.updatedAt} />
                <DateField label="Closed" value={entry.closedAt} />
                <DateField label="Last Vendor Check-In" value={entry.lastVendorCheckinDate} />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Remediation Tab */}
        <TabsContent value="remediation" className="space-y-4">
          <Card>
            <CardHeader><CardTitle className="text-base">Remediation Plan</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              {editing ? (
                <>
                  <div><Label>Overall Remediation Plan</Label><Textarea value={form.remediationPlan} onChange={e => setForm(f => ({ ...f, remediationPlan: e.target.value }))} rows={6} /></div>
                  <div><Label>Scheduled Completion Date</Label><Input type="date" value={form.scheduledCompletionDate} onChange={e => setForm(f => ({ ...f, scheduledCompletionDate: e.target.value }))} /></div>
                </>
              ) : (
                <>
                  <InfoRow label="Overall Remediation Plan" value={entry.remediationPlan} />
                  <InfoRow label="Resources Required" value={entry.resourcesRequired} />
                  <InfoRow label="Milestones" value={entry.milestones ? JSON.stringify(entry.milestones, null, 2) : null} mono />
                  <InfoRow label="Milestone Changes" value={entry.milestoneChanges ? JSON.stringify(entry.milestoneChanges, null, 2) : null} mono />
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Risk & Compliance Tab */}
        <TabsContent value="risk" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-base">Risk Decision</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <InfoRow label="Risk Decision" value={entry.riskDecision} />
                <InfoRow label="Decision By" value={entry.riskDecisionBy} />
                <DateField label="Decision Date" value={entry.riskDecisionDate} />
                <InfoRow label="Justification" value={entry.riskDecisionJustification} />
                <InfoRow label="Compensating Controls" value={entry.compensatingControls} />
                <InfoRow label="Risk Adjustment" value={entry.riskAdjustment} />
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-base">FedRAMP POA&M Fields</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <InfoRow label="False Positive" value={entry.falsePositive} />
                <InfoRow label="Operational Requirement" value={entry.operationalRequirement} />
                <InfoRow label="Deviation Rationale" value={entry.deviationRationale} />
                <InfoRow label="Supporting Documents" value={entry.supportingDocuments} />
                <InfoRow label="BOD 22-01 Tracking" value={entry.bod2201Tracking} />
                <DateField label="BOD 22-01 Due Date" value={entry.bod2201DueDate} />
                <InfoRow label="CSO Name" value={entry.csoName} />
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Activity Log Tab */}
        <TabsContent value="activity" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Activity className="h-4 w-4" /> Activity Log
              </CardTitle>
              <CardDescription>Audit trail of all changes to this POA&M entry</CardDescription>
            </CardHeader>
            <CardContent>
              {data.activity.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8">No activity recorded yet.</p>
              ) : (
                <div className="space-y-3">
                  {data.activity.map((log, i) => (
                    <div key={log.id} className="flex items-start gap-3 p-3 rounded-lg bg-muted/30">
                      <div className="p-1.5 rounded-full bg-primary/10 mt-0.5">
                        <Activity className="h-3 w-3 text-primary" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">{log.action.replace(/_/g, " ")}</span>
                          <span className="text-xs text-muted-foreground">
                            {log.createdAt ? new Date(log.createdAt).toLocaleString() : ""}
                          </span>
                        </div>
                        {log.performedByName && (
                          <p className="text-xs text-muted-foreground mt-0.5">by {log.performedByName}</p>
                        )}
                        {log.notes && (
                          <p className="text-xs text-muted-foreground mt-1 font-mono bg-muted/50 p-2 rounded">
                            {log.notes.length > 200 ? log.notes.slice(0, 200) + "..." : log.notes}
                          </p>
                        )}
                        {log.field && (
                          <div className="text-xs mt-1">
                            <span className="text-muted-foreground">Field: </span>
                            <span className="font-mono">{log.field}</span>
                            {log.previousValue && <span className="text-muted-foreground"> from </span>}
                            {log.previousValue && <span className="text-red-400 line-through">{log.previousValue}</span>}
                            {log.newValue && <span className="text-muted-foreground"> to </span>}
                            {log.newValue && <span className="text-emerald-400">{log.newValue}</span>}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─── Helper Components ───
function InfoRow({ label, value, badge, mono }: { label: string; value: string | null | undefined; badge?: boolean; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground mb-0.5">{label}</p>
      {badge ? (
        <SeverityBadge severity={value || null} />
      ) : (
        <p className={`text-sm ${mono ? "font-mono" : ""} ${value ? "" : "text-muted-foreground/50 italic"}`}>
          {value || "Not set"}
        </p>
      )}
    </div>
  );
}

function DateField({ label, value, overdue, editing, editValue, onChange }: {
  label: string;
  value: string | null | undefined;
  overdue?: boolean;
  editing?: boolean;
  editValue?: string;
  onChange?: (v: string) => void;
}) {
  if (editing && onChange) {
    return (
      <div>
        <Label className="text-xs">{label}</Label>
        <Input type="date" value={editValue || ""} onChange={e => onChange(e.target.value)} className="mt-1" />
      </div>
    );
  }
  return (
    <div>
      <p className="text-xs text-muted-foreground mb-0.5">{label}</p>
      <p className={`text-sm ${overdue ? "text-red-400 font-medium" : ""} ${value ? "" : "text-muted-foreground/50 italic"}`}>
        {value ? new Date(value).toLocaleDateString() : "Not set"}
        {overdue && <AlertTriangle className="inline h-3 w-3 ml-1 text-red-400" />}
      </p>
    </div>
  );
}
