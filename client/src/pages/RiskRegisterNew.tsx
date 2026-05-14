import { useState } from "react";
import { useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ArrowLeft, Save, Loader2, ClipboardCheck } from "lucide-react";

export default function RiskRegisterNew() {
  const [, navigate] = useLocation();
  const [form, setForm] = useState({
    weaknessName: "",
    weaknessDescription: "",
    controls: "",
    severity: "moderate" as "critical" | "high" | "moderate" | "low" | "informational",
    category: "vulnerability",
    assetIdentifier: "",
    pointOfContact: "",
    remediationPlan: "",
    scheduledCompletionDate: "",
    cve: "",
    cvssScore: "",
    detectorSource: "Manual Entry",
    sourceIdentifier: "",
    vendorDependency: "No",
    vendorDependentProductName: "",
    impactLevel: "",
    comments: "",
  });

  const createMutation = trpc.riskRegister.create.useMutation({
    onSuccess: (result) => {
      toast.success(`Created POA&M entry ${result.poamId}`);
      navigate(`/risk-register/${result.id}`);
    },
    onError: (err) => toast.error("Failed to create entry", { description: err.message }),
  });

  const handleSubmit = () => {
    if (!form.weaknessName.trim()) {
      toast.error("Weakness name is required");
      return;
    }
    createMutation.mutate({
      ...form,
      scheduledCompletionDate: form.scheduledCompletionDate || undefined,
      vendorDependentProductName: form.vendorDependency === "Yes" ? form.vendorDependentProductName : undefined,
    });
  };

  const updateField = (field: string, value: string) => setForm(f => ({ ...f, [field]: value }));

  return (
    <div className="space-y-6 p-1">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate("/risk-register")}>
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20">
            <ClipboardCheck className="h-6 w-6 text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">New Risk Register Entry</h1>
            <p className="text-muted-foreground text-sm mt-0.5">
              Manually add a POA&M item to the risk register. A unique POA&M ID will be auto-generated.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Weakness Information */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Weakness Information</CardTitle>
            <CardDescription>Describe the vulnerability or weakness being tracked</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label>Weakness Name *</Label>
              <Input value={form.weaknessName} onChange={e => updateField("weaknessName", e.target.value)} placeholder="e.g., SQL Injection in Login Form" />
            </div>
            <div>
              <Label>Description</Label>
              <Textarea value={form.weaknessDescription} onChange={e => updateField("weaknessDescription", e.target.value)} placeholder="Detailed description of the weakness..." rows={4} />
            </div>
            <div>
              <Label>NIST SP 800-53 Controls</Label>
              <Input value={form.controls} onChange={e => updateField("controls", e.target.value)} placeholder="e.g., RA-5, SI-2, CM-6" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Severity *</Label>
                <Select value={form.severity} onValueChange={v => updateField("severity", v)}>
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
              <div>
                <Label>Category</Label>
                <Select value={form.category} onValueChange={v => updateField("category", v)}>
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
              <div>
                <Label>CVE</Label>
                <Input value={form.cve} onChange={e => updateField("cve", e.target.value)} placeholder="CVE-2024-XXXXX" />
              </div>
              <div>
                <Label>CVSS Score</Label>
                <Input value={form.cvssScore} onChange={e => updateField("cvssScore", e.target.value)} placeholder="9.8" />
              </div>
            </div>
            <div>
              <Label>Impact Level</Label>
              <Select value={form.impactLevel || "none"} onValueChange={v => updateField("impactLevel", v === "none" ? "" : v)}>
                <SelectTrigger><SelectValue placeholder="Select impact level" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">Not specified</SelectItem>
                  <SelectItem value="Low">Low</SelectItem>
                  <SelectItem value="Moderate">Moderate</SelectItem>
                  <SelectItem value="High">High</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        {/* Asset & Remediation */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Asset & Remediation</CardTitle>
            <CardDescription>Identify affected assets and remediation plan</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label>Asset Identifier</Label>
              <Input value={form.assetIdentifier} onChange={e => updateField("assetIdentifier", e.target.value)} placeholder="e.g., web-server-01, 10.0.1.50" />
            </div>
            <div>
              <Label>Point of Contact</Label>
              <Input value={form.pointOfContact} onChange={e => updateField("pointOfContact", e.target.value)} placeholder="e.g., Security Team Lead" />
            </div>
            <div>
              <Label>Detector Source</Label>
              <Input value={form.detectorSource} onChange={e => updateField("detectorSource", e.target.value)} placeholder="e.g., Nessus, Manual Review" />
            </div>
            <div>
              <Label>Source Identifier</Label>
              <Input value={form.sourceIdentifier} onChange={e => updateField("sourceIdentifier", e.target.value)} placeholder="e.g., Plugin ID, Finding ID" />
            </div>
            <div>
              <Label>Remediation Plan</Label>
              <Textarea value={form.remediationPlan} onChange={e => updateField("remediationPlan", e.target.value)} placeholder="Steps to remediate this weakness..." rows={4} />
            </div>
            <div>
              <Label>Scheduled Completion Date</Label>
              <Input type="date" value={form.scheduledCompletionDate} onChange={e => updateField("scheduledCompletionDate", e.target.value)} />
            </div>
            <div>
              <Label>Vendor Dependency</Label>
              <Select value={form.vendorDependency} onValueChange={v => updateField("vendorDependency", v)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="No">No</SelectItem>
                  <SelectItem value="Yes">Yes</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {form.vendorDependency === "Yes" && (
              <div>
                <Label>Vendor Product Name</Label>
                <Input value={form.vendorDependentProductName} onChange={e => updateField("vendorDependentProductName", e.target.value)} placeholder="e.g., Apache HTTP Server" />
              </div>
            )}
            <div>
              <Label>Comments</Label>
              <Textarea value={form.comments} onChange={e => updateField("comments", e.target.value)} placeholder="Additional notes..." rows={3} />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Submit */}
      <div className="flex justify-end gap-3">
        <Button variant="outline" onClick={() => navigate("/risk-register")}>Cancel</Button>
        <Button onClick={handleSubmit} disabled={createMutation.isPending || !form.weaknessName.trim()}>
          {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Save className="h-4 w-4 mr-2" />}
          Create Entry
        </Button>
      </div>
    </div>
  );
}
