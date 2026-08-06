"use client";

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Upload, File, Trash2, AlertCircle, Loader2, BarChart, List, ShieldAlert, ShieldCheck, TrendingDown, Eye, CheckCircle2, XCircle, HelpCircle } from "lucide-react";
import AppShell from "@/components/AppShell";

type ScannerType = 'nessus' | 'qualys' | 'rapid7' | 'openvas' | 'custom';

const StatCard = ({ title, value, icon: Icon, subtitle }: { title: string; value: string | number; icon: React.ElementType; subtitle?: string }) => (
  <Card>
    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
      <CardTitle className="text-sm font-medium">{title}</CardTitle>
      <Icon className="h-4 w-4 text-muted-foreground" />
    </CardHeader>
    <CardContent>
      <div className="text-2xl font-bold">{value}</div>
      {subtitle && <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>}
    </CardContent>
  </Card>
);

const SeverityBadge = ({ severity }: { severity: string }) => {
  const lowerSeverity = severity.toLowerCase();
  const color = {
    critical: "bg-red-600 hover:bg-red-700",
    high: "bg-orange-500 hover:bg-orange-600",
    medium: "bg-yellow-500 hover:bg-yellow-600",
    low: "bg-blue-500 hover:bg-blue-600",
    info: "bg-gray-500 hover:bg-gray-600",
  }[lowerSeverity] || "bg-gray-400";

  return <Badge className={`${color} text-white`}>{severity}</Badge>;
};

const VerdictBadge = ({ verdict }: { verdict: string | null }) => {
  if (!verdict) return <Badge variant="outline" className="text-muted-foreground">Pending</Badge>;
  const config: Record<string, { color: string; icon: React.ElementType; label: string }> = {
    confirmed: { color: "bg-green-600 hover:bg-green-700", icon: CheckCircle2, label: "Confirmed" },
    likely: { color: "bg-emerald-500 hover:bg-emerald-600", icon: ShieldCheck, label: "Likely" },
    unverified: { color: "bg-yellow-500 hover:bg-yellow-600", icon: HelpCircle, label: "Unverified" },
    likely_false_positive: { color: "bg-orange-500 hover:bg-orange-600", icon: XCircle, label: "Likely FP" },
    false_positive: { color: "bg-red-500 hover:bg-red-600", icon: XCircle, label: "False Positive" },
  };
  const c = config[verdict] || { color: "bg-gray-400", icon: HelpCircle, label: verdict };
  const Icon = c.icon;
  return <Badge className={`${c.color} text-white flex items-center gap-1 w-fit`}><Icon className="h-3 w-3" />{c.label}</Badge>;
};

const ConfidenceBar = ({ score }: { score: number | null }) => {
  if (score === null || score === undefined) return <span className="text-xs text-muted-foreground">—</span>;
  const color = score >= 80 ? "bg-green-500" : score >= 60 ? "bg-emerald-500" : score >= 30 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs font-mono w-8 text-right">{score}%</span>
    </div>
  );
};

const ImportScanDialog = ({ onImportSuccess }: { onImportSuccess: () => void }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [scannerType, setScannerType] = useState<ScannerType | null>(null);
  const [file, setFile] = useState<File | null>(null);

  const importMutation = trpc.vulnScanner.importScan.useMutation({
    onSuccess: (data) => {
      const corrMsg = data.corroboration
        ? ` Corroboration: ${data.corroboration.corroborated} confirmed, ${data.corroboration.suppressed} suppressed (~${data.corroboration.estimatedFPReduction}% FP reduction).`
        : "";
      toast.success(`Imported ${data.totalVulns} vulnerabilities across ${data.totalHosts} hosts.${corrMsg}`);
      onImportSuccess();
      setIsOpen(false);
      setFile(null);
      setScannerType(null);
    },
    onError: (error) => {
      toast.error("Import failed: " + error.message);
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setFile(e.target.files[0]);
    }
  };

  const handleImport = () => {
    if (!scannerType || !file) {
      toast.warning("Please select a scanner type and a file.");
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const fileContent = e.target?.result as string;
      importMutation.mutate({ scannerType, fileContent, fileName: file.name });
    };
    reader.readAsDataURL(file);
  };

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button>
          <Upload className="mr-2 h-4 w-4" /> Import Scan
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[425px] bg-background text-foreground">
        <DialogHeader>
          <DialogTitle>Import Vulnerability Scan</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          <Select onValueChange={(value) => setScannerType(value as ScannerType)}>
            <SelectTrigger>
              <SelectValue placeholder="Select Scanner Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="nessus">Nessus</SelectItem>
              <SelectItem value="qualys">Qualys</SelectItem>
              <SelectItem value="rapid7">Rapid7</SelectItem>
              <SelectItem value="openvas">OpenVAS</SelectItem>
              <SelectItem value="custom">Custom</SelectItem>
            </SelectContent>
          </Select>
          <Input type="file" onChange={handleFileChange} className="cursor-pointer" />
          {file && <p className="text-sm text-muted-foreground">Selected: {file.name}</p>}
        </div>
        <Button onClick={handleImport} disabled={importMutation.isPending}>
          {importMutation.isPending ? (
            <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Importing &amp; Corroborating...</>
          ) : (
            "Import & Corroborate"
          )}
        </Button>
      </DialogContent>
    </Dialog>
  );
};

// Corroboration Summary Panel
const CorroborationSummary = ({ importId }: { importId: number }) => {
  const summaryQuery = trpc.vulnScanner.getCorroborationSummary.useQuery({ importId });

  if (summaryQuery.isLoading) return <div className="flex justify-center p-4"><Loader2 className="h-5 w-5 animate-spin" /></div>;
  if (!summaryQuery.data || summaryQuery.data.totalAnalyzed === 0) return null;

  const s = summaryQuery.data;
  return (
    <Card className="border-emerald-500/30 bg-emerald-500/5">
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-emerald-500" />
          Corroboration Analysis
        </CardTitle>
        <CardDescription>Cross-source confidence scoring for this import</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-emerald-500">{s.confirmed + s.likely}</div>
            <div className="text-xs text-muted-foreground">Corroborated</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-500">{s.unverified}</div>
            <div className="text-xs text-muted-foreground">Unverified</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-500">{s.likelyFP + s.falsePositive}</div>
            <div className="text-xs text-muted-foreground">Likely FP</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-500">{s.fpReductionPercent}%</div>
            <div className="text-xs text-muted-foreground">FP Reduction</div>
          </div>
        </div>
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span>Average Confidence</span>
            <span className="font-mono">{s.avgConfidence}%</span>
          </div>
          <Progress value={s.avgConfidence} className="h-2" />
          <div className="flex justify-between text-sm">
            <span>Suppressed Findings</span>
            <span className="font-mono">{s.suppressed} / {s.totalAnalyzed}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

// Global Corroboration Stats
const GlobalCorroborationStats = () => {
  const globalQuery = trpc.vulnScanner.getGlobalCorroborationStats.useQuery();

  if (globalQuery.isLoading || !globalQuery.data || globalQuery.data.totalFindings === 0) return null;

  const g = globalQuery.data;
  return (
    <Card className="border-blue-500/30 bg-blue-500/5">
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <TrendingDown className="h-5 w-5 text-blue-500" />
          Global False Positive Reduction
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold">{g.totalFindings}</div>
            <div className="text-xs text-muted-foreground">Total Analyzed</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-emerald-500">{g.confirmedCount}</div>
            <div className="text-xs text-muted-foreground">Confirmed</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-500">{g.falsePositiveCount}</div>
            <div className="text-xs text-muted-foreground">False Positives</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-500">{g.fpReductionPercent}%</div>
            <div className="text-xs text-muted-foreground">FP Reduction</div>
          </div>
        </div>
        <div className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
          <span>Avg Confidence: {g.avgOriginalConfidence}% → {g.avgAdjustedConfidence}%</span>
          {g.avgAdjustedConfidence > g.avgOriginalConfidence && (
            <Badge variant="outline" className="text-emerald-500 border-emerald-500/30">+{g.avgAdjustedConfidence - g.avgOriginalConfidence}%</Badge>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default function VulnScannerPage() {
  const utils = trpc.useUtils();
  const [selectedImportId, setSelectedImportId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState("findings");

  const statsQuery = trpc.vulnScanner.getStats.useQuery();
  const importsQuery = trpc.vulnScanner.listImports.useQuery();

  // Use the listFindings endpoint with the selected import
  const findingsInput = useMemo(() => selectedImportId ? { importId: selectedImportId } : { importId: 0 }, [selectedImportId]);
  const findingsQuery = trpc.vulnScanner.listFindings.useQuery(findingsInput, { enabled: !!selectedImportId });

  const deleteMutation = trpc.vulnScanner.deleteImport.useMutation({
    onSuccess: () => {
      toast.success("Import deleted successfully.");
      utils.vulnScanner.listImports.invalidate();
      utils.vulnScanner.getStats.invalidate();
      utils.vulnScanner.getGlobalCorroborationStats.invalidate();
      if (selectedImportId === deleteMutation.variables?.id) {
        setSelectedImportId(null);
      }
    },
    onError: (error) => {
      toast.error("Failed to delete import: " + error.message);
    },
  });

  const handleImportSuccess = () => {
    utils.vulnScanner.listImports.invalidate();
    utils.vulnScanner.getStats.invalidate();
    utils.vulnScanner.getGlobalCorroborationStats.invalidate();
  };

  return (
    <AppShell activePath="/vuln-scanner">
      <div className="min-h-screen bg-background text-foreground p-4 md:p-8">
      <header className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold">Vulnerability Scanner</h1>
          <p className="text-muted-foreground mt-1">Import, corroborate, and analyze vulnerability scan results</p>
        </div>
        <ImportScanDialog onImportSuccess={handleImportSuccess} />
      </header>

      {/* Statistics Row */}
      <section className="mb-6">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {statsQuery.isLoading ? (
            [...Array(4)].map((_, i) => <Card key={i} className="h-[105px] animate-pulse bg-muted"/>)
          ) : statsQuery.isError ? (
            <Alert variant="destructive" className="col-span-4">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>Could not load statistics: {statsQuery.error.message}</AlertDescription>
            </Alert>
          ) : statsQuery.data && (
            <>
              <StatCard title="Total Imports" value={statsQuery.data.totalImports} icon={File} />
              <StatCard title="Total Vulnerabilities" value={statsQuery.data.totalVulns} icon={ShieldAlert} />
              <StatCard title="Total Hosts" value={statsQuery.data.totalHosts} icon={List} />
              <div className="grid grid-cols-4 gap-1 rounded-lg border bg-card text-card-foreground shadow-sm p-4 items-center">
                <div className="text-center"><SeverityBadge severity="Critical" /><p className="font-bold text-lg mt-1">{statsQuery.data.critical}</p></div>
                <div className="text-center"><SeverityBadge severity="High" /><p className="font-bold text-lg mt-1">{statsQuery.data.high}</p></div>
                <div className="text-center"><SeverityBadge severity="Medium" /><p className="font-bold text-lg mt-1">{statsQuery.data.medium}</p></div>
                <div className="text-center"><SeverityBadge severity="Low" /><p className="font-bold text-lg mt-1">{statsQuery.data.low}</p></div>
              </div>
            </>
          )}
        </div>
      </section>

      {/* Global Corroboration Stats */}
      <section className="mb-6">
        <GlobalCorroborationStats />
      </section>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Import History - Left Column */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Import History</CardTitle>
            <CardDescription>Click an import to view findings and corroboration.</CardDescription>
          </CardHeader>
          <CardContent className="max-h-[600px] overflow-y-auto">
            {importsQuery.isLoading ? (
              <div className="flex items-center justify-center p-8">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : importsQuery.isError ? (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{importsQuery.error.message}</AlertDescription>
              </Alert>
            ) : (importsQuery.data?.length ?? 0) === 0 ? (
              <div className="text-center py-10">
                <p className="text-muted-foreground">No scans imported yet.</p>
                <p className="text-sm text-muted-foreground mt-1">Click "Import Scan" to get started.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {importsQuery.data?.map((imp) => (
                  <div
                    key={imp.id}
                    onClick={() => setSelectedImportId(imp.id)}
                    className={`p-3 rounded-lg cursor-pointer border transition-colors ${
                      selectedImportId === imp.id
                        ? "border-primary bg-primary/5"
                        : "border-transparent hover:bg-muted/50"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm truncate">{imp.fileName}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="outline" className="text-xs">{imp.scannerType}</Badge>
                          <span className="text-xs text-muted-foreground">{imp.totalVulns} vulns</span>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">{new Date(imp.importedAt).toLocaleString()}</p>
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="shrink-0"
                        onClick={(e) => { e.stopPropagation(); deleteMutation.mutate({ id: imp.id }); }}
                        disabled={deleteMutation.isPending && deleteMutation.variables?.id === imp.id}
                      >
                        {deleteMutation.isPending && deleteMutation.variables?.id === imp.id
                          ? <Loader2 className="h-4 w-4 animate-spin" />
                          : <Trash2 className="h-4 w-4 text-red-500" />}
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Findings & Corroboration - Right Column */}
        <div className="lg:col-span-2 space-y-4">
          {!selectedImportId ? (
            <Card>
              <CardContent className="flex items-center justify-center min-h-[400px]">
                <div className="text-center text-muted-foreground">
                  <Eye className="h-12 w-12 mx-auto mb-3 opacity-30" />
                  <p>Select an import from the list to view findings and corroboration analysis.</p>
                </div>
              </CardContent>
            </Card>
          ) : (
            <>
              {/* Corroboration Summary for selected import */}
              <CorroborationSummary importId={selectedImportId} />

              {/* Tabs: Findings / Corroboration Details */}
              <Card>
                <Tabs value={activeTab} onValueChange={setActiveTab}>
                  <CardHeader className="pb-2">
                    <TabsList>
                      <TabsTrigger value="findings">Findings</TabsTrigger>
                      <TabsTrigger value="corroboration">Corroboration Details</TabsTrigger>
                    </TabsList>
                  </CardHeader>
                  <CardContent>
                    <TabsContent value="findings" className="mt-0">
                      <FindingsTable importId={selectedImportId} />
                    </TabsContent>
                    <TabsContent value="corroboration" className="mt-0">
                      <CorroborationDetailsTable importId={selectedImportId} />
                    </TabsContent>
                  </CardContent>
                </Tabs>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
    </AppShell>
  );
}

// Findings Table Component
function FindingsTable({ importId }: { importId: number }) {
  const findingsQuery = trpc.vulnScanner.listFindings.useQuery({ importId });

  if (findingsQuery.isLoading) return <div className="flex justify-center p-8"><Loader2 className="h-6 w-6 animate-spin" /></div>;
  if (findingsQuery.isError) return <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{findingsQuery.error.message}</AlertDescription></Alert>;
  if (!findingsQuery.data || findingsQuery.data.length === 0) return <p className="text-center text-muted-foreground py-8">No findings for this import.</p>;

  return (
    <div className="max-h-[500px] overflow-y-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Severity</TableHead>
            <TableHead>CVE</TableHead>
            <TableHead>Title</TableHead>
            <TableHead>Host</TableHead>
            <TableHead>Confidence</TableHead>
            <TableHead>Verdict</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {findingsQuery.data.map((f: any) => (
            <TableRow key={f.id} className={f.suppressRecommended ? "opacity-50" : ""}>
              <TableCell><SeverityBadge severity={f.severity} /></TableCell>
              <TableCell className="font-mono text-xs">{f.cveId || "—"}</TableCell>
              <TableCell className="font-medium max-w-[200px] truncate" title={f.title}>{f.title}</TableCell>
              <TableCell className="text-xs">{f.hostIp || f.hostName || "—"}</TableCell>
              <TableCell><ConfidenceBar score={f.corroborationScore} /></TableCell>
              <TableCell><VerdictBadge verdict={f.corroborationVerdict} /></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

// Corroboration Details Table
function CorroborationDetailsTable({ importId }: { importId: number }) {
  const detailsQuery = trpc.vulnScanner.getCorroborationDetails.useQuery({ importId });

  if (detailsQuery.isLoading) return <div className="flex justify-center p-8"><Loader2 className="h-6 w-6 animate-spin" /></div>;
  if (detailsQuery.isError) return <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{detailsQuery.error.message}</AlertDescription></Alert>;
  if (!detailsQuery.data || detailsQuery.data.length === 0) return <p className="text-center text-muted-foreground py-8">No corroboration data available for this import.</p>;

  return (
    <div className="max-h-[500px] overflow-y-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Finding</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Original</TableHead>
            <TableHead>Adjusted</TableHead>
            <TableHead>Sources</TableHead>
            <TableHead>Verdict</TableHead>
            <TableHead>Suppress</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {detailsQuery.data.map((cr: any) => (
            <TableRow key={cr.id} className={cr.suppressRecommendation ? "opacity-50 bg-red-500/5" : ""}>
              <TableCell className="max-w-[180px]">
                <div className="truncate font-medium text-sm" title={cr.findingTitle}>{cr.findingTitle}</div>
                {cr.findingCve && <span className="text-xs font-mono text-muted-foreground">{cr.findingCve}</span>}
              </TableCell>
              <TableCell><SeverityBadge severity={cr.findingSeverity} /></TableCell>
              <TableCell><span className="font-mono text-sm">{cr.originalConfidence}%</span></TableCell>
              <TableCell><ConfidenceBar score={cr.adjustedConfidence} /></TableCell>
              <TableCell>
                <div className="flex items-center gap-1">
                  <span className="text-emerald-500 font-mono text-xs">+{cr.corroboratingCount}</span>
                  <span className="text-muted-foreground">/</span>
                  <span className="text-red-500 font-mono text-xs">-{cr.contradictingCount}</span>
                </div>
              </TableCell>
              <TableCell><VerdictBadge verdict={cr.verdict} /></TableCell>
              <TableCell>
                {cr.suppressRecommendation ? (
                  <Badge variant="destructive" className="text-xs">Suppress</Badge>
                ) : (
                  <span className="text-xs text-muted-foreground">Keep</span>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
