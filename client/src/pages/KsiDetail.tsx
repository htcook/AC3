import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Shield, CheckCircle2, AlertTriangle, XCircle, Search,
  FileText, Clock, ArrowLeft, Link2, Activity, Database,
  ChevronRight, ExternalLink
} from "lucide-react";
import AppShell from "@/components/AppShell";
import { Link, useParams } from "wouter";
import { getKsiLabel, getThemeLabel } from "@/lib/ksi-labels";

export default function KsiDetail() {
  const params = useParams<{ ksiId: string }>();
  const ksiId = params.ksiId || "";

  const defsQuery = trpc.ksiEvidenceChain.getCoverageSummary.useQuery();
  const evidenceQuery = trpc.ksiEvidenceChain.listEvidence.useQuery({ ksiId, limit: 50 });
  const validationQuery = trpc.ksiValidation.listRuns.useQuery({ ksiId, limit: 50 });
  const mappingsQuery = trpc.ksiEvidenceChain.getControlMappings.useQuery();

  const def = useMemo(() => {
    if (!defsQuery.data) return null;
    return defsQuery.data.definitions?.find((d: any) => d.ksiId === ksiId) || null;
  }, [defsQuery.data, ksiId]);

  const controlMappings = useMemo(() => {
    if (!mappingsQuery.data) return [];
    return (mappingsQuery.data as any[]).filter((m: any) => m.ksiId === ksiId);
  }, [mappingsQuery.data, ksiId]);

  const evidence = evidenceQuery.data || [];
  const validationRuns = (validationQuery.data as any)?.runs || validationQuery.data || [];

  const getSatisfactionState = () => {
    if (!def) return "unknown";
    const latestRun = Array.isArray(validationRuns) && validationRuns[0];
    if (latestRun?.status === "passed") return "satisfied";
    if (def.coverageStatus === "direct" && Array.isArray(evidence) && evidence.length > 0) return "satisfied";
    if (def.coverageStatus === "supporting") return "partially-satisfied";
    return "not-satisfied";
  };

  const satisfaction = getSatisfactionState();

  if (defsQuery.isLoading) {
    return (
      <AppShell activePath="/ksi-hub">
        <div className="flex items-center justify-center h-96">
          <div className="text-center space-y-3">
            <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full mx-auto" />
            <p className="text-muted-foreground">Loading KSI detail...</p>
          </div>
        </div>
      </AppShell>
    );
  }

  if (!def) {
    return (
      <AppShell activePath="/ksi-hub">
        <div className="text-center py-16 space-y-4">
          <XCircle className="w-12 h-12 text-muted-foreground mx-auto" />
          <h2 className="text-xl font-bold">KSI Not Found</h2>
          <p className="text-muted-foreground">No definition found for KSI ID: {ksiId}</p>
          <Link href="/ksi-hub">
            <Button variant="outline"><ArrowLeft className="w-4 h-4 mr-1" /> Back to KSI Hub</Button>
          </Link>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell activePath="/ksi-hub">
      <div className="space-y-6">
        {/* Breadcrumb + Header */}
        <div>
          <div className="flex items-center gap-1 text-sm text-muted-foreground mb-3">
            <Link href="/ksi-hub"><span className="hover:text-foreground cursor-pointer">KSI Hub</span></Link>
            <ChevronRight className="w-3 h-3" />
            <Link href="/ksi-dashboard"><span className="hover:text-foreground cursor-pointer">Dashboard</span></Link>
            <ChevronRight className="w-3 h-3" />
            <span className="text-foreground font-medium">{ksiId}</span>
          </div>

          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold flex items-center gap-3">
                <Shield className="h-7 w-7 text-blue-500" />
                {ksiId}
              </h1>
              <p className="text-lg text-muted-foreground mt-1">{getKsiLabel(ksiId) || def.title}</p>
              <p className="text-sm text-muted-foreground mt-1 max-w-3xl">
                Unified view of this Key Security Indicator showing its definition, evidence chain, validation history, and NIST SP 800-53 control mappings. Use this page to assess the current posture and identify gaps for this specific KSI.
              </p>
            </div>
            <div className="flex items-center gap-2">
              {satisfaction === "satisfied" && (
                <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 text-sm px-3 py-1">
                  <CheckCircle2 className="w-4 h-4 mr-1" /> Satisfied
                </Badge>
              )}
              {satisfaction === "partially-satisfied" && (
                <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30 text-sm px-3 py-1">
                  <AlertTriangle className="w-4 h-4 mr-1" /> Partially Satisfied
                </Badge>
              )}
              {satisfaction === "not-satisfied" && (
                <Badge className="bg-red-500/20 text-red-400 border-red-500/30 text-sm px-3 py-1">
                  <XCircle className="w-4 h-4 mr-1" /> Not Satisfied
                </Badge>
              )}
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-xs text-muted-foreground">Theme</div>
              <div className="text-sm font-medium mt-1">{getThemeLabel(def.themeCode) || def.themeName}</div>
              <Badge variant="outline" className="mt-1 text-xs font-mono">{def.themeCode}</Badge>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-xs text-muted-foreground">Coverage</div>
              <Badge className={`mt-1 ${def.coverageStatus === "direct" ? "bg-emerald-500/20 text-emerald-400" : def.coverageStatus === "supporting" ? "bg-amber-500/20 text-amber-400" : "bg-muted text-muted-foreground"}`}>
                {def.coverageStatus}
              </Badge>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-xs text-muted-foreground">Evidence Items</div>
              <div className="text-2xl font-bold mt-1 text-emerald-400">{Array.isArray(evidence) ? evidence.length : 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-xs text-muted-foreground">Validation Runs</div>
              <div className="text-2xl font-bold mt-1 text-blue-400">{Array.isArray(validationRuns) ? validationRuns.length : 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-xs text-muted-foreground">NIST Controls</div>
              <div className="text-2xl font-bold mt-1">{controlMappings.length}</div>
            </CardContent>
          </Card>
        </div>

        {/* Tabbed Content */}
        <Tabs defaultValue="definition" className="space-y-4">
          <TabsList>
            <TabsTrigger value="definition">Definition</TabsTrigger>
            <TabsTrigger value="evidence">Evidence ({Array.isArray(evidence) ? evidence.length : 0})</TabsTrigger>
            <TabsTrigger value="validation">Validation ({Array.isArray(validationRuns) ? validationRuns.length : 0})</TabsTrigger>
            <TabsTrigger value="controls">NIST Controls ({controlMappings.length})</TabsTrigger>
          </TabsList>

          <TabsContent value="definition">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">KSI Definition</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">Description</div>
                      <p className="text-sm">{def.description || "No description available"}</p>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">ACE C3 Module</div>
                      <p className="text-sm font-medium">{def.aceC3Module || "Not assigned"}</p>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">Category</div>
                      <p className="text-sm font-medium">{def.category || "General"}</p>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">Validation Type</div>
                      <Badge variant="outline">{def.validationType || "N/A"}</Badge>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">Frequency</div>
                      <Badge variant="outline">{def.frequency || "N/A"}</Badge>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">Implementation Notes</div>
                      <p className="text-sm">{def.implementationNotes || "No notes"}</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="evidence">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Database className="w-4 h-4" /> Evidence Chain
                </CardTitle>
                <CardDescription>All evidence items collected for this KSI</CardDescription>
              </CardHeader>
              <CardContent>
                {Array.isArray(evidence) && evidence.length > 0 ? (
                  <div className="space-y-3">
                    {evidence.map((e: any, i: number) => (
                      <div key={e.id || i} className="p-3 border rounded-lg">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-xs">{e.evidenceType}</Badge>
                            <span className="text-sm font-medium">{e.title}</span>
                          </div>
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <Badge variant={e.collectionMethod === "automated" ? "default" : "outline"} className="text-[10px]">
                              {e.collectionMethod}
                            </Badge>
                            <span>{e.createdAt ? new Date(e.createdAt).toLocaleDateString() : "—"}</span>
                          </div>
                        </div>
                        {e.description && <p className="text-xs text-muted-foreground mt-1">{e.description}</p>}
                        {e.integrityHash && (
                          <div className="flex items-center gap-1 mt-2 text-[10px] font-mono text-muted-foreground">
                            <Link2 className="w-3 h-3" /> SHA-256: {e.integrityHash.slice(0, 24)}...
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Database className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p>No evidence collected for this KSI yet</p>
                    <Link href="/ksi-auto-collector">
                      <Button variant="outline" size="sm" className="mt-2">Go to Auto-Collector</Button>
                    </Link>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="validation">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Activity className="w-4 h-4" /> Validation History
                </CardTitle>
                <CardDescription>All validation runs for this KSI</CardDescription>
              </CardHeader>
              <CardContent>
                {Array.isArray(validationRuns) && validationRuns.length > 0 ? (
                  <div className="space-y-2">
                    {validationRuns.map((run: any, i: number) => (
                      <div key={run.id || i} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex items-center gap-3">
                          {run.status === "passed" && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                          {run.status === "failed" && <XCircle className="w-4 h-4 text-red-400" />}
                          {run.status !== "passed" && run.status !== "failed" && <Clock className="w-4 h-4 text-muted-foreground" />}
                          <div>
                            <div className="text-sm font-medium">{run.runType || "Validation"} Run</div>
                            <div className="text-xs text-muted-foreground">
                              {run.completedAt ? new Date(run.completedAt).toLocaleString() : run.createdAt ? new Date(run.createdAt).toLocaleString() : "—"}
                            </div>
                          </div>
                        </div>
                        <Badge variant={run.status === "passed" ? "default" : run.status === "failed" ? "destructive" : "outline"}>
                          {run.status}
                        </Badge>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p>No validation runs for this KSI yet</p>
                    <Link href="/ksi-validation">
                      <Button variant="outline" size="sm" className="mt-2">Go to Validation</Button>
                    </Link>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="controls">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <FileText className="w-4 h-4" /> NIST SP 800-53 Control Mappings
                </CardTitle>
                <CardDescription>Controls mapped to this KSI for FedRAMP compliance</CardDescription>
              </CardHeader>
              <CardContent>
                {controlMappings.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {controlMappings.map((m: any, i: number) => (
                      <div key={m.id || i} className="p-3 border rounded-lg">
                        <div className="flex items-center justify-between">
                          <Badge variant="outline" className="font-mono">{m.controlId}</Badge>
                          <Badge variant="outline" className="text-xs">{m.mappingType || "mapped"}</Badge>
                        </div>
                        {m.controlTitle && <p className="text-sm mt-1">{m.controlTitle}</p>}
                        {m.notes && <p className="text-xs text-muted-foreground mt-1">{m.notes}</p>}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <FileText className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p>No NIST control mappings for this KSI</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
