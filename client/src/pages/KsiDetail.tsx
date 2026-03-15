import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Shield, CheckCircle2, AlertTriangle, XCircle, Search,
  FileText, Clock, ArrowLeft, Link2, Activity, Database,
  ChevronRight, ExternalLink, Cpu, BookOpen, Zap, Target
} from "lucide-react";
import AppShell from "@/components/AppShell";
import { Link, useParams } from "wouter";
import { getKsiLabel, getThemeLabel } from "@/lib/ksi-labels";
import { getKsiEnriched, getThemeEnriched, getCoverageBadgeClass } from "@/lib/ksi-enriched-data";

export default function KsiDetail() {
  const params = useParams<{ ksiId: string }>();
  const ksiId = params.ksiId || "";

  const defsQuery = trpc.ksiEvidenceChain.getCoverageSummary.useQuery();
  const evidenceQuery = trpc.ksiEvidenceChain.listEvidence.useQuery({ ksiId, limit: 50 });
  const validationQuery = trpc.ksiValidation.listRuns.useQuery({ ksiId, limit: 50 });
  const mappingsQuery = trpc.ksiEvidenceChain.getControlMappings.useQuery();

  const enriched = useMemo(() => getKsiEnriched(ksiId), [ksiId]);
  const themeEnriched = useMemo(() => {
    if (!enriched) return null;
    return getThemeEnriched(enriched.themeCode);
  }, [enriched]);

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
    if (!def && !enriched) return "unknown";
    const latestRun = Array.isArray(validationRuns) && validationRuns[0];
    if (latestRun?.status === "passed") return "satisfied";
    const coverage = enriched?.coverageLevel || def?.coverageStatus;
    if (coverage === "direct" && Array.isArray(evidence) && evidence.length > 0) return "satisfied";
    if (coverage === "supporting") return "partially-satisfied";
    if (coverage === "planned") return "not-satisfied";
    return "not-satisfied";
  };

  const satisfaction = getSatisfactionState();

  if (defsQuery.isLoading) {
    return (
      <AppShell activePath="/ksi-dashboard">
        <div className="flex items-center justify-center h-96">
          <div className="text-center space-y-3">
            <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full mx-auto" />
            <p className="text-muted-foreground">Loading KSI detail...</p>
          </div>
        </div>
      </AppShell>
    );
  }

  if (!def && !enriched) {
    return (
      <AppShell activePath="/ksi-dashboard">
        <div className="text-center py-16 space-y-4">
          <XCircle className="w-12 h-12 text-muted-foreground mx-auto" />
          <h2 className="text-xl font-bold">KSI Not Found</h2>
          <p className="text-muted-foreground">No definition found for KSI ID: {ksiId}</p>
          <Link href="/ksi-dashboard">
            <Button variant="outline"><ArrowLeft className="w-4 h-4 mr-1" /> Back to KSI Hub</Button>
          </Link>
        </div>
      </AppShell>
    );
  }

  const coverageLevel = enriched?.coverageLevel || def?.coverageStatus || "planned";
  const displayName = enriched?.name || getKsiLabel(ksiId) || def?.title || ksiId;

  return (
    <AppShell activePath="/ksi-dashboard">
      <div className="space-y-6">
        {/* Breadcrumb + Header */}
        <div>
          <div className="flex items-center gap-1 text-sm text-muted-foreground mb-3">
            <Link href="/ksi-dashboard"><span className="hover:text-foreground cursor-pointer">KSI Hub</span></Link>
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
              <p className="text-lg text-muted-foreground mt-1">{displayName}</p>
              {enriched && (
                <p className="text-sm text-muted-foreground mt-2 max-w-3xl leading-relaxed">
                  {enriched.requirement}
                </p>
              )}
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
              <div className="text-sm font-medium mt-1">{themeEnriched?.name || getThemeLabel(enriched?.themeCode || def?.themeCode) || def?.themeName}</div>
              <Badge variant="outline" className="mt-1 text-xs font-mono">{enriched?.themeCode || def?.themeCode}</Badge>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-xs text-muted-foreground">Coverage</div>
              <Badge className={`mt-1 ${getCoverageBadgeClass(coverageLevel as any)}`}>
                {coverageLevel}
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
              <div className="text-2xl font-bold mt-1">{enriched?.nistControls.length || controlMappings.length}</div>
            </CardContent>
          </Card>
        </div>

        {/* Tabbed Content */}
        <Tabs defaultValue="ace-c3" className="space-y-4">
          <TabsList>
            <TabsTrigger value="ace-c3">AC3 Mapping</TabsTrigger>
            <TabsTrigger value="definition">Definition</TabsTrigger>
            <TabsTrigger value="evidence">Evidence ({Array.isArray(evidence) ? evidence.length : 0})</TabsTrigger>
            <TabsTrigger value="validation">Validation ({Array.isArray(validationRuns) ? validationRuns.length : 0})</TabsTrigger>
            <TabsTrigger value="controls">NIST Controls ({enriched?.nistControls.length || controlMappings.length})</TabsTrigger>
          </TabsList>

          {/* AC3 Mapping Tab - NEW */}
          <TabsContent value="ace-c3">
            {enriched ? (
              <div className="space-y-4">
                {/* How AC3 Delivers */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Shield className="w-4 h-4 text-blue-400" />
                      How AC3 {coverageLevel === "direct" ? "Meets" : coverageLevel === "supporting" ? "Supports" : "Plans to Address"} This KSI
                    </CardTitle>
                    <CardDescription>
                      Coverage Level: <Badge className={getCoverageBadgeClass(coverageLevel as any)}>{coverageLevel}</Badge>
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm leading-relaxed">{enriched.howAceC3Delivers}</p>
                  </CardContent>
                </Card>

                {/* AC3 Modules */}
                {enriched.aceModules.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base flex items-center gap-2">
                        <Cpu className="w-4 h-4 text-purple-400" />
                        AC3 Modules Involved ({enriched.aceModules.length})
                      </CardTitle>
                      <CardDescription>
                        Each module contributes specific capabilities to satisfy this indicator
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {enriched.aceModules.map((mod, i) => (
                          <div key={i} className="p-3 border rounded-lg bg-accent/30">
                            <div className="flex items-start gap-3">
                              <div className="w-8 h-8 rounded-md bg-blue-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                                <Cpu className="w-4 h-4 text-blue-400" />
                              </div>
                              <div className="flex-1">
                                <div className="font-medium text-sm">{mod.name}</div>
                                <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{mod.role}</p>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Evidence Types & Validation */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {enriched.evidenceTypes.length > 0 && (
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base flex items-center gap-2">
                          <FileText className="w-4 h-4 text-emerald-400" />
                          Evidence Types Produced
                        </CardTitle>
                        <CardDescription>
                          Types of evidence artifacts generated to demonstrate compliance
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          {enriched.evidenceTypes.map((et, i) => (
                            <div key={i} className="flex items-center gap-2 p-2 border rounded-md">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                              <span className="text-sm">{et}</span>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  )}

                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base flex items-center gap-2">
                        <Target className="w-4 h-4 text-amber-400" />
                        Validation & Compliance Details
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        <div className="p-3 border rounded-lg">
                          <div className="text-xs text-muted-foreground mb-1">Validation Method</div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-sm">
                              {enriched.validationMethod === "machine" ? "⚙ Machine" :
                               enriched.validationMethod === "human" ? "👤 Human" :
                               enriched.validationMethod === "mixed" ? "⚡ Mixed" : "◌ N/A"}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {enriched.validationMethod === "machine" ? "Automated validation through platform tools" :
                               enriched.validationMethod === "human" ? "Requires human review and assessment" :
                               enriched.validationMethod === "mixed" ? "Combination of automated and human validation" : "Not yet determined"}
                            </span>
                          </div>
                        </div>

                        <div className="p-3 border rounded-lg">
                          <div className="text-xs text-muted-foreground mb-1">Assessment Frequency</div>
                          <div className="flex items-center gap-2">
                            <Clock className="w-4 h-4 text-blue-400" />
                            <span className="text-sm font-medium capitalize">{enriched.frequency}</span>
                          </div>
                        </div>

                        <div className="p-3 border rounded-lg">
                          <div className="text-xs text-muted-foreground mb-1">NIST SP 800-53 Controls</div>
                          <div className="flex flex-wrap gap-1.5 mt-1">
                            {enriched.nistControls.length > 0 ? enriched.nistControls.map((ctrl, i) => (
                              <Badge key={i} variant="outline" className="font-mono text-xs">{ctrl}</Badge>
                            )) : (
                              <span className="text-xs text-muted-foreground">No controls mapped</span>
                            )}
                          </div>
                        </div>

                        {themeEnriched && (
                          <div className="p-3 border rounded-lg">
                            <div className="text-xs text-muted-foreground mb-1">Parent Theme</div>
                            <div className="text-sm font-medium">{themeEnriched.name} ({themeEnriched.code})</div>
                            <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{themeEnriched.ac3Narrative}</p>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Planned items note */}
                {coverageLevel === "planned" && (
                  <Card className="border-dashed">
                    <CardContent className="pt-6">
                      <div className="text-center space-y-2">
                        <Zap className="w-8 h-8 text-muted-foreground mx-auto" />
                        <p className="text-sm font-medium">Planned for Future Development</p>
                        <p className="text-xs text-muted-foreground max-w-lg mx-auto">
                          This KSI is outside the current scope of AC3's offensive security capabilities. 
                          It requires organizational processes or infrastructure-level capabilities that are planned for future platform development.
                        </p>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>
            ) : (
              <Card>
                <CardContent className="pt-6">
                  <div className="text-center py-8 text-muted-foreground">
                    <BookOpen className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p>No enriched AC3 mapping data available for this KSI</p>
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="definition">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">KSI Definition</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">FedRAMP 20x Requirement</div>
                      <p className="text-sm leading-relaxed">{enriched?.requirement || def?.description || "No description available"}</p>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">AC3 Module(s)</div>
                      {enriched && enriched.aceModules.length > 0 ? (
                        <div className="flex flex-wrap gap-1.5">
                          {enriched.aceModules.map((m, i) => (
                            <Badge key={i} variant="outline" className="text-xs">{m.name}</Badge>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm font-medium">{def?.ac3Module || "Not assigned"}</p>
                      )}
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">Category</div>
                      <p className="text-sm font-medium">{def?.category || themeEnriched?.name || "General"}</p>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">Validation Type</div>
                      <Badge variant="outline">{enriched?.validationMethod || def?.validationType || "N/A"}</Badge>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">Frequency</div>
                      <Badge variant="outline">{enriched?.frequency || def?.frequency || "N/A"}</Badge>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">NIST Controls</div>
                      {enriched && enriched.nistControls.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {enriched.nistControls.map((c, i) => (
                            <Badge key={i} variant="outline" className="font-mono text-xs">{c}</Badge>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm">No controls mapped</p>
                      )}
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1">Implementation Notes</div>
                      <p className="text-sm">{def?.implementationNotes || (enriched ? enriched.howAceC3Delivers.slice(0, 200) + "..." : "No notes")}</p>
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
                    {enriched && enriched.evidenceTypes.length > 0 && (
                      <div className="mt-3 max-w-md mx-auto">
                        <p className="text-xs mb-2">Expected evidence types for this KSI:</p>
                        <div className="flex flex-wrap gap-1 justify-center">
                          {enriched.evidenceTypes.map((et, i) => (
                            <Badge key={i} variant="outline" className="text-[10px]">{et}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    <Link href="/ksi-auto-collector">
                      <Button variant="outline" size="sm" className="mt-3">Go to Auto-Collector</Button>
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
                {/* Show enriched NIST controls even if DB mappings are empty */}
                {(controlMappings.length > 0 || (enriched && enriched.nistControls.length > 0)) ? (
                  <div className="space-y-4">
                    {enriched && enriched.nistControls.length > 0 && (
                      <div className="p-3 bg-accent/30 rounded-lg mb-3">
                        <div className="text-xs text-muted-foreground mb-2">Primary NIST SP 800-53 Controls (from KSI definition)</div>
                        <div className="flex flex-wrap gap-2">
                          {enriched.nistControls.map((ctrl, i) => (
                            <Badge key={i} variant="outline" className="font-mono text-sm px-2.5 py-1">{ctrl}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {controlMappings.length > 0 && (
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
                    )}
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
