import { useState, useEffect, useMemo } from "react";
import { useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import {
  Shield, Building2, Scale, FileText, BookOpen, LogOut,
  CheckCircle, AlertTriangle, Clock, Edit3, Save, X, Plus,
  Trash2, Eye, ChevronDown, ChevronUp, Globe, Server,
  Lock, Users, Calendar, Radio, Database, Target, Hash,
  Briefcase, MapPin, DollarSign, UserCheck, ClipboardList
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";

// ─── Auth helpers ─────────────────────────────────────────────────
function getCustomerToken(): string | null {
  return localStorage.getItem("customer_token");
}

function getCustomerInfo(): any {
  try {
    return JSON.parse(localStorage.getItem("customer_info") || "null");
  } catch { return null; }
}

function clearCustomerAuth() {
  localStorage.removeItem("customer_token");
  localStorage.removeItem("customer_refresh_token");
  localStorage.removeItem("customer_info");
}

// ─── Severity helpers ─────────────────────────────────────────────
function statusColor(status: string): string {
  switch (status?.toLowerCase()) {
    case "active": case "approved": case "certified": return "bg-green-500/20 text-green-300 border-green-500/30";
    case "pending_review": case "in_progress": return "bg-amber-500/20 text-amber-300 border-amber-500/30";
    case "draft": case "none": return "bg-slate-500/20 text-slate-300 border-slate-500/30";
    case "expired": case "revoked": return "bg-red-500/20 text-red-300 border-red-500/30";
    default: return "bg-slate-500/20 text-slate-300 border-slate-500/30";
  }
}

// ─── Known regulatory frameworks ──────────────────────────────────
const KNOWN_FRAMEWORKS = [
  "NIST CSF", "NIST 800-53", "NIST 800-171", "CMMC", "SOC 2", "SOC 1",
  "ISO 27001", "ISO 27002", "PCI DSS", "HIPAA", "HITECH", "GDPR",
  "CCPA", "FERPA", "GLBA", "SOX", "FedRAMP", "FISMA", "CJIS",
  "NERC CIP", "IEC 62443", "DFARS", "ITAR", "EAR", "SWIFT CSP",
  "CIS Controls", "OWASP", "MITRE ATT&CK",
];

// ─── Main Component ──────────────────────────────────────────────
export default function CustomerPortalDashboard() {
  const [, navigate] = useLocation();
  const token = getCustomerToken();
  const customerInfo = getCustomerInfo();

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!token) navigate("/customer-login");
  }, [token, navigate]);

  if (!token) return null;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Header */}
      <header className="border-b border-slate-800/50 bg-slate-950/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-teal-500/20 to-cyan-500/20 border border-teal-500/30 flex items-center justify-center">
              <Shield className="w-5 h-5 text-teal-400" />
            </div>
            <div>
              <h1 className="text-base font-bold text-white">Customer Portal</h1>
              <p className="text-xs text-slate-500">
                {customerInfo?.contactName} &middot; {customerInfo?.email}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Badge variant="outline" className={`capitalize text-xs ${statusColor(customerInfo?.role || "viewer")}`}>
              {customerInfo?.role || "viewer"}
            </Badge>
            <Button
              size="sm"
              variant="ghost"
              className="text-slate-400 hover:text-white"
              onClick={() => {
                clearCustomerAuth();
                navigate("/customer-login");
                toast.info("Signed out successfully.");
              }}
            >
              <LogOut className="w-4 h-4 mr-1.5" />
              Sign Out
            </Button>
          </div>
        </div>
      </header>

      {/* Page description */}
      <div className="max-w-6xl mx-auto px-4 sm:px-6 pt-6 pb-2">
        <p className="text-sm text-slate-400 max-w-3xl">
          Welcome to your secure customer portal. Review your organization profile, manage Rules of Engagement scope boundaries,
          confirm applicable regulatory frameworks, and access shared reports from your security assessment team.
        </p>
      </div>

      {/* Main Content */}
      <main className="max-w-6xl mx-auto px-4 sm:px-6 py-6">
        <Tabs defaultValue="profile" className="space-y-6">
          <TabsList className="bg-slate-800/50 border border-slate-700/50 p-1">
            <TabsTrigger value="profile" className="data-[state=active]:bg-teal-600 data-[state=active]:text-white text-slate-400">
              <Building2 className="w-4 h-4 mr-1.5" /> Org Profile
            </TabsTrigger>
            <TabsTrigger value="roe" className="data-[state=active]:bg-teal-600 data-[state=active]:text-white text-slate-400">
              <Scale className="w-4 h-4 mr-1.5" /> Rules of Engagement
            </TabsTrigger>
            <TabsTrigger value="frameworks" className="data-[state=active]:bg-teal-600 data-[state=active]:text-white text-slate-400">
              <BookOpen className="w-4 h-4 mr-1.5" /> Regulatory Frameworks
            </TabsTrigger>
            <TabsTrigger value="reports" className="data-[state=active]:bg-teal-600 data-[state=active]:text-white text-slate-400">
              <FileText className="w-4 h-4 mr-1.5" /> Reports
            </TabsTrigger>
            <TabsTrigger value="audit" className="data-[state=active]:bg-teal-600 data-[state=active]:text-white text-slate-400">
              <ClipboardList className="w-4 h-4 mr-1.5" /> Audit Log
            </TabsTrigger>
          </TabsList>

          {/* ─── Org Profile Tab ─────────────────────────────────── */}
          <TabsContent value="profile">
            <OrgProfileTab token={token} customerRole={customerInfo?.role} />
          </TabsContent>

          {/* ─── RoE Tab ─────────────────────────────────────────── */}
          <TabsContent value="roe">
            <RoeTab token={token} customerRole={customerInfo?.role} />
          </TabsContent>

          {/* ─── Regulatory Frameworks Tab ────────────────────────── */}
          <TabsContent value="frameworks">
            <FrameworksTab token={token} customerRole={customerInfo?.role} />
          </TabsContent>

          {/* ─── Reports Tab ─────────────────────────────────────── */}
          <TabsContent value="reports">
            <ReportsTab token={token} />
          </TabsContent>

          {/* ─── Audit Log Tab ───────────────────────────────────── */}
          <TabsContent value="audit">
            <AuditLogTab token={token} />
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/50 py-6 text-center text-xs text-slate-600">
        <p>Powered by <strong className="text-slate-500">Spicy TIP GPT</strong> &mdash; Harrison Cook, AceofCloud</p>
        <p className="mt-1">All actions are logged for compliance (NIST 800-53 AU/AC)</p>
      </footer>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Org Profile Tab
// ═══════════════════════════════════════════════════════════════════
function OrgProfileTab({ token, customerRole }: { token: string; customerRole?: string }) {
  const { data, isLoading, refetch } = trpc.customerPortal.getOrgProfile.useQuery({ token });
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<Record<string, any>>({});

  const updateMutation = trpc.customerPortal.updateOrgProfile.useMutation({
    onSuccess: () => {
      toast.success("Organization profile updated successfully.");
      setEditing(false);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  useEffect(() => {
    if (data?.profile) {
      setForm({
        companyName: data.profile.companyName || "",
        industry: data.profile.industry || "",
        subIndustry: data.profile.subIndustry || "",
        employeeCount: data.profile.employeeCount || "",
        annualRevenue: data.profile.annualRevenue || "",
        headquarters: data.profile.headquarters || "",
        description: data.profile.description || "",
        publicCompany: data.profile.publicCompany ?? false,
        stockTicker: data.profile.stockTicker || "",
      });
    }
  }, [data?.profile]);

  if (isLoading) return <LoadingCard />;

  const profile = data?.profile;
  const tenant = data?.tenant;
  const canEdit = customerRole !== "viewer";

  return (
    <div className="space-y-6">
      {/* Verification Status */}
      <Card className="bg-slate-900/60 border-slate-700/50">
        <CardContent className="p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            {profile?.customerVerified ? (
              <>
                <CheckCircle className="w-5 h-5 text-green-400" />
                <div>
                  <p className="text-sm font-medium text-white">Profile Verified</p>
                  <p className="text-xs text-slate-500">
                    Last verified {profile.lastVerifiedAt ? new Date(profile.lastVerifiedAt).toLocaleDateString() : "N/A"}
                  </p>
                </div>
              </>
            ) : (
              <>
                <AlertTriangle className="w-5 h-5 text-amber-400" />
                <div>
                  <p className="text-sm font-medium text-white">Profile Not Yet Verified</p>
                  <p className="text-xs text-slate-500">Please review and confirm your organization details</p>
                </div>
              </>
            )}
          </div>
          {canEdit && !editing && (
            <Button size="sm" onClick={() => setEditing(true)} className="bg-teal-600 hover:bg-teal-700 text-white">
              <Edit3 className="w-4 h-4 mr-1.5" /> Edit Profile
            </Button>
          )}
          {editing && (
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={() => setEditing(false)} className="border-slate-600 text-slate-300">
                <X className="w-4 h-4 mr-1.5" /> Cancel
              </Button>
              <Button
                size="sm"
                onClick={() => updateMutation.mutate({ token, corrections: form })}
                disabled={updateMutation.isPending}
                className="bg-teal-600 hover:bg-teal-700 text-white"
              >
                <Save className="w-4 h-4 mr-1.5" /> {updateMutation.isPending ? "Saving..." : "Save Changes"}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Profile Details */}
      <Card className="bg-slate-900/60 border-slate-700/50">
        <CardHeader>
          <CardTitle className="text-lg text-white flex items-center gap-2">
            <Building2 className="w-5 h-5 text-teal-400" />
            Organization Details
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <ProfileField
              icon={<Building2 className="w-4 h-4" />}
              label="Company Name"
              value={form.companyName || profile?.companyName}
              editing={editing}
              onChange={(v) => setForm({ ...form, companyName: v })}
            />
            <ProfileField
              icon={<Briefcase className="w-4 h-4" />}
              label="Industry"
              value={form.industry || profile?.industry}
              editing={editing}
              onChange={(v) => setForm({ ...form, industry: v })}
            />
            <ProfileField
              icon={<Hash className="w-4 h-4" />}
              label="Sub-Industry"
              value={form.subIndustry || profile?.subIndustry}
              editing={editing}
              onChange={(v) => setForm({ ...form, subIndustry: v })}
            />
            <ProfileField
              icon={<Users className="w-4 h-4" />}
              label="Employee Count"
              value={form.employeeCount || profile?.employeeCount}
              editing={editing}
              onChange={(v) => setForm({ ...form, employeeCount: v })}
            />
            <ProfileField
              icon={<DollarSign className="w-4 h-4" />}
              label="Annual Revenue"
              value={form.annualRevenue || profile?.annualRevenue}
              editing={editing}
              onChange={(v) => setForm({ ...form, annualRevenue: v })}
            />
            <ProfileField
              icon={<MapPin className="w-4 h-4" />}
              label="Headquarters"
              value={form.headquarters || profile?.headquarters}
              editing={editing}
              onChange={(v) => setForm({ ...form, headquarters: v })}
            />
          </div>
          {(editing || profile?.description) && (
            <div className="mt-5">
              <Label className="text-xs text-slate-500 uppercase tracking-wider">Description</Label>
              {editing ? (
                <Textarea
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  className="mt-1 bg-slate-800/80 border-slate-600 text-white min-h-[80px]"
                  placeholder="Brief description of the organization..."
                />
              ) : (
                <p className="mt-1 text-sm text-slate-300">{profile?.description || "—"}</p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Tenant Info */}
      {tenant && (
        <Card className="bg-slate-900/60 border-slate-700/50">
          <CardHeader>
            <CardTitle className="text-base text-white">Tenant Information</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <p className="text-xs text-slate-500">Tenant Name</p>
                <p className="text-slate-300">{tenant.name}</p>
              </div>
              <div>
                <p className="text-xs text-slate-500">Primary Domain</p>
                <p className="text-slate-300">{tenant.primaryDomain || "—"}</p>
              </div>
              <div>
                <p className="text-xs text-slate-500">Status</p>
                <Badge variant="outline" className={`capitalize ${statusColor(tenant.status || "active")}`}>
                  {tenant.status || "active"}
                </Badge>
              </div>
              <div>
                <p className="text-xs text-slate-500">Created</p>
                <p className="text-slate-300">{tenant.createdAt ? new Date(tenant.createdAt).toLocaleDateString() : "—"}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// RoE Tab
// ═══════════════════════════════════════════════════════════════════
function RoeTab({ token, customerRole }: { token: string; customerRole?: string }) {
  const { data: docs, isLoading, refetch } = trpc.customerPortal.getRoeDocuments.useQuery({ token });
  const [expandedDoc, setExpandedDoc] = useState<number | null>(null);
  const [addingScopeItem, setAddingScopeItem] = useState(false);
  const [newScopeItem, setNewScopeItem] = useState({
    type: "in_scope" as "in_scope" | "out_of_scope",
    category: "domain" as any,
    value: "",
    description: "",
    restrictions: "",
  });

  const updateScopeMutation = trpc.customerPortal.updateScopeBoundaries.useMutation({
    onSuccess: () => {
      toast.success("Scope boundaries updated.");
      setAddingScopeItem(false);
      setNewScopeItem({ type: "in_scope", category: "domain", value: "", description: "", restrictions: "" });
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  if (isLoading) return <LoadingCard />;
  if (!docs || docs.length === 0) {
    return (
      <Card className="bg-slate-900/60 border-slate-700/50">
        <CardContent className="py-12 text-center">
          <Scale className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <p className="text-slate-400">No Rules of Engagement documents found.</p>
          <p className="text-xs text-slate-500 mt-1">Your engagement team will share RoE documents here.</p>
        </CardContent>
      </Card>
    );
  }

  const canEdit = customerRole !== "viewer";

  return (
    <div className="space-y-4">
      {docs.map((doc: any) => (
        <Card key={doc.id} className="bg-slate-900/60 border-slate-700/50">
          <CardHeader
            className="cursor-pointer"
            onClick={() => setExpandedDoc(expandedDoc === doc.id ? null : doc.id)}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Scale className="w-5 h-5 text-teal-400" />
                <div>
                  <CardTitle className="text-base text-white">{doc.title || `RoE #${doc.id}`}</CardTitle>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Version {doc.version || 1} &middot; Created {new Date(doc.createdAt).toLocaleDateString()}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline" className={`capitalize text-xs ${statusColor(doc.status || "draft")}`}>
                  {(doc.status || "draft").replace(/_/g, " ")}
                </Badge>
                {expandedDoc === doc.id ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
              </div>
            </div>
          </CardHeader>

          {expandedDoc === doc.id && (
            <CardContent className="space-y-4 pt-0">
              {/* Purpose */}
              {doc.purpose && (
                <div>
                  <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">Purpose</p>
                  <p className="text-sm text-slate-300 leading-relaxed">{doc.purpose}</p>
                </div>
              )}

              {/* Scope Inclusions */}
              {doc.scopeInclusions && (
                <div>
                  <p className="text-xs font-medium text-green-400 uppercase tracking-wider mb-2">In-Scope Assets</p>
                  <div className="space-y-1">
                    {(Array.isArray(doc.scopeInclusions) ? doc.scopeInclusions : JSON.parse(doc.scopeInclusions || "[]")).map((item: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 text-sm text-slate-300 p-2 rounded bg-slate-800/30">
                        <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />
                        <span>{typeof item === "string" ? item : `${item.type || ""}: ${item.value || item.description || JSON.stringify(item)}`}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Scope Exclusions */}
              {doc.scopeExclusions && (
                <div>
                  <p className="text-xs font-medium text-red-400 uppercase tracking-wider mb-2">Out-of-Scope / Exclusions</p>
                  <div className="space-y-1">
                    {(Array.isArray(doc.scopeExclusions) ? doc.scopeExclusions : JSON.parse(doc.scopeExclusions || "[]")).map((item: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 text-sm text-slate-300 p-2 rounded bg-slate-800/30">
                        <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                        <span>{typeof item === "string" ? item : `${item.type || ""}: ${item.value || item.description || JSON.stringify(item)}`}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Testing Types & Attack Vectors */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {doc.testingTypes && (
                  <div>
                    <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Testing Types</p>
                    <div className="flex flex-wrap gap-1.5">
                      {(Array.isArray(doc.testingTypes) ? doc.testingTypes : JSON.parse(doc.testingTypes || "[]")).map((t: string, i: number) => (
                        <Badge key={i} variant="outline" className="border-teal-500/30 text-teal-300 capitalize text-xs">
                          {t.replace(/_/g, " ")}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {doc.attackVectors && (
                  <div>
                    <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Attack Vectors</p>
                    <div className="flex flex-wrap gap-1.5">
                      {(Array.isArray(doc.attackVectors) ? doc.attackVectors : JSON.parse(doc.attackVectors || "[]")).map((v: string, i: number) => (
                        <Badge key={i} variant="outline" className="border-orange-500/30 text-orange-300 capitalize text-xs">
                          {v.replace(/_/g, " ")}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Schedule */}
              {(doc.scheduleStart || doc.scheduleEnd) && (
                <div>
                  <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Schedule</p>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                    {doc.scheduleStart && (
                      <div><p className="text-xs text-slate-500">Start</p><p className="text-slate-300">{new Date(doc.scheduleStart).toLocaleDateString()}</p></div>
                    )}
                    {doc.scheduleEnd && (
                      <div><p className="text-xs text-slate-500">End</p><p className="text-slate-300">{new Date(doc.scheduleEnd).toLocaleDateString()}</p></div>
                    )}
                    {doc.scheduleTimezone && (
                      <div><p className="text-xs text-slate-500">Timezone</p><p className="text-slate-300">{doc.scheduleTimezone}</p></div>
                    )}
                    {doc.scheduleWindow && (
                      <div><p className="text-xs text-slate-500">Window</p><p className="text-slate-300">{doc.scheduleWindow}</p></div>
                    )}
                  </div>
                </div>
              )}

              {/* Add Scope Boundary (for admin/signer) */}
              {canEdit && (doc.status === "pending_review" || doc.status === "draft") && (
                <div className="border-t border-slate-700/50 pt-4">
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-sm font-medium text-white">Add Scope Boundary</p>
                    {!addingScopeItem && (
                      <Button size="sm" onClick={() => setAddingScopeItem(true)} className="bg-teal-600 hover:bg-teal-700 text-white">
                        <Plus className="w-4 h-4 mr-1" /> Add Item
                      </Button>
                    )}
                  </div>
                  {addingScopeItem && (
                    <div className="space-y-3 p-4 rounded-lg bg-slate-800/30 border border-slate-700/30">
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <Label className="text-xs text-slate-400">Type</Label>
                          <Select value={newScopeItem.type} onValueChange={(v) => setNewScopeItem({ ...newScopeItem, type: v as any })}>
                            <SelectTrigger className="bg-slate-800 border-slate-600 text-white mt-1">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="in_scope">In Scope</SelectItem>
                              <SelectItem value="out_of_scope">Out of Scope</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div>
                          <Label className="text-xs text-slate-400">Category</Label>
                          <Select value={newScopeItem.category} onValueChange={(v) => setNewScopeItem({ ...newScopeItem, category: v })}>
                            <SelectTrigger className="bg-slate-800 border-slate-600 text-white mt-1">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="domain">Domain</SelectItem>
                              <SelectItem value="ip_range">IP Range</SelectItem>
                              <SelectItem value="network">Network</SelectItem>
                              <SelectItem value="application">Application</SelectItem>
                              <SelectItem value="service">Service</SelectItem>
                              <SelectItem value="physical">Physical</SelectItem>
                              <SelectItem value="social_engineering">Social Engineering</SelectItem>
                              <SelectItem value="other">Other</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                      <div>
                        <Label className="text-xs text-slate-400">Value</Label>
                        <Input
                          value={newScopeItem.value}
                          onChange={(e) => setNewScopeItem({ ...newScopeItem, value: e.target.value })}
                          placeholder="e.g., *.example.com, 10.0.0.0/24"
                          className="bg-slate-800 border-slate-600 text-white mt-1"
                        />
                      </div>
                      <div>
                        <Label className="text-xs text-slate-400">Description (optional)</Label>
                        <Input
                          value={newScopeItem.description}
                          onChange={(e) => setNewScopeItem({ ...newScopeItem, description: e.target.value })}
                          placeholder="Brief description..."
                          className="bg-slate-800 border-slate-600 text-white mt-1"
                        />
                      </div>
                      <div className="flex gap-2 justify-end">
                        <Button size="sm" variant="outline" onClick={() => setAddingScopeItem(false)} className="border-slate-600 text-slate-300">
                          Cancel
                        </Button>
                        <Button
                          size="sm"
                          disabled={!newScopeItem.value || updateScopeMutation.isPending}
                          onClick={() => {
                            updateScopeMutation.mutate({
                              token,
                              roeId: doc.id,
                              scopeItems: [newScopeItem],
                            });
                          }}
                          className="bg-teal-600 hover:bg-teal-700 text-white"
                        >
                          {updateScopeMutation.isPending ? "Saving..." : "Add Boundary"}
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          )}
        </Card>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Regulatory Frameworks Tab
// ═══════════════════════════════════════════════════════════════════
function FrameworksTab({ token, customerRole }: { token: string; customerRole?: string }) {
  const { data: frameworks, isLoading, refetch } = trpc.customerPortal.getRegulatoryFrameworks.useQuery({ token });
  const [editing, setEditing] = useState(false);
  const [editedFrameworks, setEditedFrameworks] = useState<any[]>([]);

  const updateMutation = trpc.customerPortal.updateRegulatoryFrameworks.useMutation({
    onSuccess: () => {
      toast.success("Regulatory frameworks updated.");
      setEditing(false);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  useEffect(() => {
    if (frameworks) {
      setEditedFrameworks(frameworks.map((f: any) => ({
        frameworkName: f.frameworkName,
        applicable: f.applicable ?? true,
        notes: f.notes || "",
        certificationStatus: f.certificationStatus || "none",
        certificationDate: f.certificationDate || "",
        expirationDate: f.expirationDate || "",
      })));
    }
  }, [frameworks]);

  if (isLoading) return <LoadingCard />;

  const canEdit = customerRole !== "viewer";

  const addFramework = (name: string) => {
    if (editedFrameworks.some(f => f.frameworkName === name)) return;
    setEditedFrameworks([...editedFrameworks, {
      frameworkName: name,
      applicable: true,
      notes: "",
      certificationStatus: "none",
      certificationDate: "",
      expirationDate: "",
    }]);
  };

  const removeFramework = (idx: number) => {
    setEditedFrameworks(editedFrameworks.filter((_, i) => i !== idx));
  };

  const toggleApplicable = (idx: number) => {
    const updated = [...editedFrameworks];
    updated[idx].applicable = !updated[idx].applicable;
    setEditedFrameworks(updated);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <Card className="bg-slate-900/60 border-slate-700/50">
        <CardContent className="p-4 flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-white">Applicable Regulatory Frameworks</p>
            <p className="text-xs text-slate-500">
              Select which compliance frameworks apply to your organization. This helps tailor the security assessment.
            </p>
          </div>
          {canEdit && (
            <div className="flex gap-2">
              {editing ? (
                <>
                  <Button size="sm" variant="outline" onClick={() => { setEditing(false); }} className="border-slate-600 text-slate-300">
                    <X className="w-4 h-4 mr-1" /> Cancel
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => updateMutation.mutate({ token, frameworks: editedFrameworks })}
                    disabled={updateMutation.isPending}
                    className="bg-teal-600 hover:bg-teal-700 text-white"
                  >
                    <Save className="w-4 h-4 mr-1" /> {updateMutation.isPending ? "Saving..." : "Save"}
                  </Button>
                </>
              ) : (
                <Button size="sm" onClick={() => setEditing(true)} className="bg-teal-600 hover:bg-teal-700 text-white">
                  <Edit3 className="w-4 h-4 mr-1" /> Edit
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Framework List */}
      {editedFrameworks.length === 0 && !editing ? (
        <Card className="bg-slate-900/60 border-slate-700/50">
          <CardContent className="py-12 text-center">
            <BookOpen className="w-12 h-12 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400">No regulatory frameworks configured yet.</p>
            {canEdit && (
              <Button size="sm" onClick={() => setEditing(true)} className="mt-3 bg-teal-600 hover:bg-teal-700 text-white">
                <Plus className="w-4 h-4 mr-1" /> Add Frameworks
              </Button>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {editedFrameworks.map((fw, idx) => (
            <Card key={idx} className={`border-slate-700/50 ${fw.applicable ? "bg-slate-900/60" : "bg-slate-900/30 opacity-60"}`}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {editing && (
                      <button onClick={() => toggleApplicable(idx)} className="shrink-0">
                        {fw.applicable ? (
                          <CheckCircle className="w-5 h-5 text-green-400" />
                        ) : (
                          <div className="w-5 h-5 rounded-full border-2 border-slate-600" />
                        )}
                      </button>
                    )}
                    <p className="font-medium text-white text-sm">{fw.frameworkName}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={`capitalize text-xs ${statusColor(fw.certificationStatus)}`}>
                      {fw.certificationStatus === "none" ? "Not Certified" : fw.certificationStatus.replace(/_/g, " ")}
                    </Badge>
                    {editing && (
                      <button onClick={() => removeFramework(idx)} className="text-red-400 hover:text-red-300">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>
                {editing && (
                  <div className="mt-2 space-y-2">
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <Label className="text-xs text-slate-500">Status</Label>
                        <Select
                          value={fw.certificationStatus}
                          onValueChange={(v) => {
                            const updated = [...editedFrameworks];
                            updated[idx].certificationStatus = v;
                            setEditedFrameworks(updated);
                          }}
                        >
                          <SelectTrigger className="bg-slate-800 border-slate-600 text-white text-xs mt-0.5 h-8">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="none">Not Certified</SelectItem>
                            <SelectItem value="in_progress">In Progress</SelectItem>
                            <SelectItem value="certified">Certified</SelectItem>
                            <SelectItem value="expired">Expired</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div>
                        <Label className="text-xs text-slate-500">Notes</Label>
                        <Input
                          value={fw.notes}
                          onChange={(e) => {
                            const updated = [...editedFrameworks];
                            updated[idx].notes = e.target.value;
                            setEditedFrameworks(updated);
                          }}
                          placeholder="Optional notes"
                          className="bg-slate-800 border-slate-600 text-white text-xs mt-0.5 h-8"
                        />
                      </div>
                    </div>
                  </div>
                )}
                {!editing && fw.notes && (
                  <p className="text-xs text-slate-500 mt-1">{fw.notes}</p>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Add Framework (when editing) */}
      {editing && (
        <Card className="bg-slate-900/60 border-slate-700/50 border-dashed">
          <CardContent className="p-4">
            <p className="text-xs text-slate-500 mb-3">Add a framework:</p>
            <div className="flex flex-wrap gap-1.5">
              {KNOWN_FRAMEWORKS.filter(f => !editedFrameworks.some(ef => ef.frameworkName === f)).map(f => (
                <Button
                  key={f}
                  size="sm"
                  variant="outline"
                  onClick={() => addFramework(f)}
                  className="border-slate-600 text-slate-400 hover:text-white hover:border-teal-500 text-xs h-7"
                >
                  <Plus className="w-3 h-3 mr-1" /> {f}
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Reports Tab
// ═══════════════════════════════════════════════════════════════════
function ReportsTab({ token }: { token: string }) {
  const { data: reports, isLoading } = trpc.customerPortal.getSharedReports.useQuery({ token });

  if (isLoading) return <LoadingCard />;
  if (!reports || reports.length === 0) {
    return (
      <Card className="bg-slate-900/60 border-slate-700/50">
        <CardContent className="py-12 text-center">
          <FileText className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <p className="text-slate-400">No reports have been shared with you yet.</p>
          <p className="text-xs text-slate-500 mt-1">Your engagement team will share reports as they become available.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-3">
      {reports.map((r: any) => (
        <Card key={r.id} className="bg-slate-900/60 border-slate-700/50">
          <CardContent className="p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-teal-500/10 flex items-center justify-center">
                <FileText className="w-5 h-5 text-teal-400" />
              </div>
              <div>
                <p className="font-medium text-white text-sm">
                  {r.report?.title || `${r.reportType?.toUpperCase()} Report`}
                </p>
                <p className="text-xs text-slate-500">
                  Shared by {r.sharedBy} &middot; {new Date(r.sharedAt).toLocaleDateString()}
                  {r.expiresAt && ` · Expires ${new Date(r.expiresAt).toLocaleDateString()}`}
                </p>
                {r.message && <p className="text-xs text-slate-400 mt-1">{r.message}</p>}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="capitalize text-xs border-slate-600 text-slate-300">
                {r.reportType?.replace(/_/g, " ")}
              </Badge>
              {r.report?.status && (
                <Badge variant="outline" className={`capitalize text-xs ${statusColor(r.report.status)}`}>
                  {r.report.status}
                </Badge>
              )}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Audit Log Tab
// ═══════════════════════════════════════════════════════════════════
function AuditLogTab({ token }: { token: string }) {
  const { data: logs, isLoading } = trpc.customerPortal.getAuditLog.useQuery({ token, limit: 50 });

  if (isLoading) return <LoadingCard />;
  if (!logs || logs.length === 0) {
    return (
      <Card className="bg-slate-900/60 border-slate-700/50">
        <CardContent className="py-12 text-center">
          <ClipboardList className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <p className="text-slate-400">No audit log entries yet.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-slate-900/60 border-slate-700/50">
      <CardHeader>
        <CardTitle className="text-base text-white flex items-center gap-2">
          <ClipboardList className="w-5 h-5 text-teal-400" />
          Activity Log
        </CardTitle>
        <p className="text-xs text-slate-500">All portal actions are recorded for NIST 800-53 AU compliance.</p>
      </CardHeader>
      <CardContent>
        <div className="space-y-2 max-h-[500px] overflow-y-auto">
          {logs.map((log: any) => (
            <div key={log.id} className="flex items-start gap-3 p-3 rounded-lg bg-slate-800/30 border border-slate-700/20">
              <div className="w-2 h-2 rounded-full bg-teal-400 mt-1.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <p className="text-sm text-white font-medium capitalize">
                    {log.action?.replace(/_/g, " ")}
                  </p>
                  <p className="text-xs text-slate-500">
                    {new Date(log.timestamp).toLocaleString()}
                  </p>
                </div>
                {log.resource && (
                  <p className="text-xs text-slate-400 mt-0.5">
                    Resource: {log.resource} {log.resourceId ? `#${log.resourceId}` : ""}
                  </p>
                )}
                {log.ipAddress && (
                  <p className="text-xs text-slate-500">IP: {log.ipAddress}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Shared Components
// ═══════════════════════════════════════════════════════════════════
function LoadingCard() {
  return (
    <Card className="bg-slate-900/60 border-slate-700/50">
      <CardContent className="py-12 text-center">
        <div className="w-8 h-8 border-2 border-teal-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
        <p className="text-slate-400 text-sm">Loading...</p>
      </CardContent>
    </Card>
  );
}

function ProfileField({
  icon, label, value, editing, onChange
}: {
  icon: React.ReactNode;
  label: string;
  value: any;
  editing: boolean;
  onChange: (v: string) => void;
}) {
  return (
    <div>
      <Label className="text-xs text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
        {icon} {label}
      </Label>
      {editing ? (
        <Input
          value={value || ""}
          onChange={(e) => onChange(e.target.value)}
          className="mt-1 bg-slate-800/80 border-slate-600 text-white"
          placeholder={`Enter ${label.toLowerCase()}`}
        />
      ) : (
        <p className="mt-1 text-sm text-slate-300">{value || "—"}</p>
      )}
    </div>
  );
}
