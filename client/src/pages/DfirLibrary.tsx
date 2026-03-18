import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogDescription } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  Newspaper, Upload, Globe, Search, Sparkles, Download, Trash2,
  ExternalLink, Shield, Bug, Hash, Eye, ChevronLeft, ChevronRight,
  Loader2, AlertTriangle, CheckCircle2, Clock, FileText, Brain,
  RefreshCw, Database, Target, Crosshair, BarChart3
} from "lucide-react";

const SOURCE_COLORS: Record<string, string> = {
  dfir_report: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  cisa: "bg-red-500/10 text-red-400 border-red-500/20",
  otx: "bg-green-500/10 text-green-400 border-green-500/20",
  mandiant: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  unit42: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  recorded_future: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  manual: "bg-gray-500/10 text-gray-400 border-gray-500/20",
};

const STATUS_COLORS: Record<string, string> = {
  pending: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  parsed: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  enriched: "bg-green-500/10 text-green-400 border-green-500/20",
  training_ready: "bg-purple-500/10 text-purple-400 border-purple-500/20",
};

const SOURCE_LABELS: Record<string, string> = {
  dfir_report: "DFIR Report",
  cisa: "CISA",
  otx: "OTX",
  mandiant: "Mandiant",
  unit42: "Unit 42",
  recorded_future: "Recorded Future",
  manual: "Manual",
};

export default function DfirLibrary() {

  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState<string | undefined>();
  const [statusFilter, setStatusFilter] = useState<string | undefined>();
  const [selectedReportId, setSelectedReportId] = useState<number | null>(null);
  const [iocSearch, setIocSearch] = useState("");
  const [activeTab, setActiveTab] = useState("reports");

  // Queries
  const reportsQuery = trpc.dfirLibrary.list.useQuery({
    page,
    pageSize: 20,
    search: search || undefined,
    source: sourceFilter as any,
    status: statusFilter as any,
  });

  const statsQuery = trpc.dfirLibrary.stats.useQuery();

  const reportDetailQuery = trpc.dfirLibrary.getById.useQuery(
    { id: selectedReportId! },
    { enabled: !!selectedReportId }
  );

  const iocSearchQuery = trpc.dfirLibrary.searchIocs.useQuery(
    { query: iocSearch },
    { enabled: iocSearch.length >= 3 }
  );

  // Mutations
  const scrapeUrlMutation = trpc.dfirLibrary.scrapeUrl.useMutation({
    onSuccess: (data) => {
      toast.success("Report Scraped", { description: `"${data.title}" — ${data.techniquesFound} techniques, ${data.iocsFound} IOCs` });
      reportsQuery.refetch();
      statsQuery.refetch();
    },
    onError: (err) => toast.error("Scrape Failed", { description: err.message }),
  });

  const scrapeIndexMutation = trpc.dfirLibrary.scrapeIndex.useMutation({
    onSuccess: (data) => {
      toast.success("Batch Scrape Complete", { description: `Imported ${data.imported}, skipped ${data.skipped}, failed ${data.failed}` });
      reportsQuery.refetch();
      statsQuery.refetch();
    },
    onError: (err) => toast.error("Batch Scrape Failed", { description: err.message }),
  });

  const importReportMutation = trpc.dfirLibrary.importReport.useMutation({
    onSuccess: (data) => {
      toast.success("Report Imported", { description: `"${data.title}" — ${data.techniquesFound} techniques, ${data.iocsFound} IOCs` });
      reportsQuery.refetch();
      statsQuery.refetch();
    },
    onError: (err) => toast.error("Import Failed", { description: err.message }),
  });

  const enrichMutation = trpc.dfirLibrary.enrichReport.useMutation({
    onSuccess: (data) => {
      toast.success("Report Enriched", { description: `Added ${data.enrichedFields.techniquesAdded} techniques` });
      reportDetailQuery.refetch();
      reportsQuery.refetch();
    },
    onError: (err) => toast.error("Enrichment Failed", { description: err.message }),
  });

  const deleteMutation = trpc.dfirLibrary.deleteReport.useMutation({
    onSuccess: () => {
      toast.success("Report Deleted");
      setSelectedReportId(null);
      reportsQuery.refetch();
      statsQuery.refetch();
    },
  });

  const exportMutation = trpc.dfirLibrary.exportTrainingData.useQuery(undefined, { enabled: false });

  const seedLibraryMutation = trpc.dfirLibrary.seedLibrary.useMutation({
    onSuccess: (data) => {
      toast.success("Library Seeded", { description: `Imported ${data.totalImported}, skipped ${data.totalSkipped}, failed ${data.totalFailed}` });
      reportsQuery.refetch();
      statsQuery.refetch();
    },
    onError: (err) => toast.error("Seed Failed", { description: err.message }),
  });
  const [seedSources, setSeedSources] = useState<string[]>(['dfir_report', 'cisa']);
  const [seedMaxPerSource, setSeedMaxPerSource] = useState(15);

  // Upload handler
  const [uploadContent, setUploadContent] = useState("");
  const [uploadUrl, setUploadUrl] = useState("");
  const [scrapeUrl, setScrapeUrl] = useState("");
  const [batchCount, setBatchCount] = useState(10);

  const totalPages = Math.ceil((reportsQuery.data?.total || 0) / 20);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Newspaper className="h-6 w-6 text-cyan-400" />
            DFIR Report Library
          </h1>
          <p className="text-muted-foreground mt-1">
            Threat intelligence reports from DFIR Report, CISA, OTX, and manual uploads
          </p>
        </div>
      </div>

      {/* Stats Cards */}
      {statsQuery.data && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="bg-card/50">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <Database className="h-4 w-4" />
                Total Reports
              </div>
              <div className="text-2xl font-bold mt-1">{statsQuery.data.totalReports}</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <Target className="h-4 w-4" />
                IOCs Tracked
              </div>
              <div className="text-2xl font-bold mt-1">{statsQuery.data.totalIocs.toLocaleString()}</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <Crosshair className="h-4 w-4" />
                ATT&CK Techniques
              </div>
              <div className="text-2xl font-bold mt-1">{statsQuery.data.uniqueTechniques}</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <BarChart3 className="h-4 w-4" />
                Sources
              </div>
              <div className="flex gap-1 mt-1 flex-wrap">
                {statsQuery.data.bySource.map((s: any) => (
                  <Badge key={s.source} variant="outline" className={SOURCE_COLORS[s.source] || ""}>
                    {SOURCE_LABELS[s.source] || s.source}: {s.count}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="reports">Reports</TabsTrigger>
          <TabsTrigger value="ingest">Ingest</TabsTrigger>
          <TabsTrigger value="ioc-search">IOC Search</TabsTrigger>
        </TabsList>

        {/* ─── Reports Tab ─────────────────────────────────────────────── */}
        <TabsContent value="reports" className="space-y-4">
          {/* Filters */}
          <div className="flex gap-3 flex-wrap">
            <Input
              placeholder="Search reports..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              className="max-w-xs"
            />
            <Select value={sourceFilter || "all"} onValueChange={(v) => { setSourceFilter(v === "all" ? undefined : v); setPage(1); }}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="All Sources" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Sources</SelectItem>
                <SelectItem value="dfir_report">DFIR Report</SelectItem>
                <SelectItem value="cisa">CISA</SelectItem>
                <SelectItem value="otx">OTX</SelectItem>
                <SelectItem value="manual">Manual</SelectItem>
              </SelectContent>
            </Select>
            <Select value={statusFilter || "all"} onValueChange={(v) => { setStatusFilter(v === "all" ? undefined : v); setPage(1); }}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="All Statuses" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="parsed">Parsed</SelectItem>
                <SelectItem value="enriched">Enriched</SelectItem>
                <SelectItem value="training_ready">Training Ready</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" onClick={() => reportsQuery.refetch()}>
              <RefreshCw className="h-4 w-4 mr-1" /> Refresh
            </Button>
          </div>

          {/* Report List */}
          {reportsQuery.isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <div className="space-y-3">
              {(reportsQuery.data?.reports || []).map((report: any) => (
                <Card
                  key={report.id}
                  className="cursor-pointer hover:border-cyan-500/40 transition-colors"
                  onClick={() => setSelectedReportId(report.id)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant="outline" className={SOURCE_COLORS[report.source] || ""}>
                            {SOURCE_LABELS[report.source] || report.source}
                          </Badge>
                          <Badge variant="outline" className={STATUS_COLORS[report.status] || ""}>
                            {report.status}
                          </Badge>
                          {report.publishedAt && (
                            <span className="text-xs text-muted-foreground">
                              {new Date(report.publishedAt).toLocaleDateString()}
                            </span>
                          )}
                        </div>
                        <h3 className="font-semibold mt-1 truncate">{report.title}</h3>
                        {report.summary && (
                          <p className="text-sm text-muted-foreground mt-1 line-clamp-2">{report.summary}</p>
                        )}
                        <div className="flex gap-2 mt-2 flex-wrap">
                          {(report.threatActors as string[] || []).slice(0, 3).map((a: string) => (
                            <Badge key={a} variant="secondary" className="text-xs">
                              <Shield className="h-3 w-3 mr-1" />{a}
                            </Badge>
                          ))}
                          {(report.malwareFamilies as string[] || []).slice(0, 3).map((m: string) => (
                            <Badge key={m} variant="secondary" className="text-xs bg-red-500/10 text-red-400">
                              <Bug className="h-3 w-3 mr-1" />{m}
                            </Badge>
                          ))}
                          {(report.mitreAttackTechniques as any[] || []).length > 0 && (
                            <Badge variant="secondary" className="text-xs bg-cyan-500/10 text-cyan-400">
                              <Crosshair className="h-3 w-3 mr-1" />
                              {(report.mitreAttackTechniques as any[]).length} techniques
                            </Badge>
                          )}
                        </div>
                      </div>
                      {report.url && (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="shrink-0"
                          onClick={(e) => { e.stopPropagation(); window.open(report.url, '_blank'); }}
                        >
                          <ExternalLink className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}

              {(reportsQuery.data?.reports || []).length === 0 && (
                <Card className="bg-card/50">
                  <CardContent className="p-8 text-center text-muted-foreground">
                    <Newspaper className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p>No reports found. Use the Ingest tab to import reports.</p>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2">
              <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-sm text-muted-foreground">
                Page {page} of {totalPages}
              </span>
              <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          )}
        </TabsContent>

        {/* ─── Ingest Tab ──────────────────────────────────────────────── */}
        <TabsContent value="ingest" className="space-y-4">
          <div className="grid md:grid-cols-2 gap-4">
            {/* Scrape Single URL */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Globe className="h-4 w-4 text-blue-400" />
                  Scrape URL
                </CardTitle>
                <CardDescription>Fetch and parse a single report from a URL</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Input
                  placeholder="https://thedfirreport.com/2025/..."
                  value={scrapeUrl}
                  onChange={(e) => setScrapeUrl(e.target.value)}
                />
                <Button
                  onClick={() => scrapeUrlMutation.mutate({ url: scrapeUrl })}
                  disabled={!scrapeUrl || scrapeUrlMutation.isPending}
                  className="w-full"
                >
                  {scrapeUrlMutation.isPending ? (
                    <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Scraping...</>
                  ) : (
                    <><Globe className="h-4 w-4 mr-2" /> Scrape Report</>
                  )}
                </Button>
              </CardContent>
            </Card>

            {/* Batch Scrape DFIR Report */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <RefreshCw className="h-4 w-4 text-green-400" />
                  Batch Scrape — The DFIR Report
                </CardTitle>
                <CardDescription>Auto-scrape latest reports from thedfirreport.com</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">Max reports:</span>
                  <Input
                    type="number"
                    min={1}
                    max={50}
                    value={batchCount}
                    onChange={(e) => setBatchCount(Number(e.target.value))}
                    className="w-20"
                  />
                </div>
                <Button
                  onClick={() => scrapeIndexMutation.mutate({ maxReports: batchCount })}
                  disabled={scrapeIndexMutation.isPending}
                  className="w-full"
                >
                  {scrapeIndexMutation.isPending ? (
                    <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Scraping Index...</>
                  ) : (
                    <><Download className="h-4 w-4 mr-2" /> Scrape Latest Reports</>
                  )}
                </Button>
                {scrapeIndexMutation.data && (
                  <div className="text-sm text-muted-foreground">
                    Found {scrapeIndexMutation.data.totalFound} reports:
                    {" "}{scrapeIndexMutation.data.imported} imported,
                    {" "}{scrapeIndexMutation.data.skipped} skipped,
                    {" "}{scrapeIndexMutation.data.failed} failed
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Seed Library (Multi-Source) */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Database className="h-4 w-4 text-cyan-400" />
                  Seed Library
                </CardTitle>
                <CardDescription>Bulk import from multiple sources (DFIR Report + CISA)</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <label className="flex items-center gap-1.5 text-sm">
                    <input type="checkbox" checked={seedSources.includes('dfir_report')} onChange={(e) => {
                      setSeedSources(prev => e.target.checked ? [...prev, 'dfir_report'] : prev.filter(s => s !== 'dfir_report'));
                    }} className="rounded" />
                    DFIR Report
                  </label>
                  <label className="flex items-center gap-1.5 text-sm">
                    <input type="checkbox" checked={seedSources.includes('cisa')} onChange={(e) => {
                      setSeedSources(prev => e.target.checked ? [...prev, 'cisa'] : prev.filter(s => s !== 'cisa'));
                    }} className="rounded" />
                    CISA
                  </label>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">Max per source:</span>
                  <Input type="number" min={1} max={30} value={seedMaxPerSource} onChange={(e) => setSeedMaxPerSource(Number(e.target.value))} className="w-20" />
                </div>
                <Button
                  onClick={() => seedLibraryMutation.mutate({ sources: seedSources as any, maxPerSource: seedMaxPerSource })}
                  disabled={seedLibraryMutation.isPending || seedSources.length === 0}
                  className="w-full"
                >
                  {seedLibraryMutation.isPending ? (
                    <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Seeding Library...</>
                  ) : (
                    <><Database className="h-4 w-4 mr-2" /> Seed Library ({seedSources.length} sources)</>
                  )}
                </Button>
                {seedLibraryMutation.data && (
                  <div className="text-sm space-y-1">
                    <div className="text-muted-foreground">
                      Imported {seedLibraryMutation.data.totalImported}, skipped {seedLibraryMutation.data.totalSkipped}, failed {seedLibraryMutation.data.totalFailed}
                    </div>
                    <div className="max-h-32 overflow-y-auto text-xs space-y-0.5">
                      {seedLibraryMutation.data.results.map((r: any, i: number) => (
                        <div key={i} className={`flex items-center gap-1 ${r.status === 'imported' ? 'text-green-400' : r.status === 'skipped' ? 'text-yellow-400' : 'text-red-400'}`}>
                          {r.status === 'imported' ? <CheckCircle2 className="h-3 w-3" /> : r.status === 'skipped' ? <Clock className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
                          <span className="truncate">{r.title || r.url}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Manual Upload */}
            <Card className="md:col-span-2">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Upload className="h-4 w-4 text-purple-400" />
                  Upload Report
                </CardTitle>
                <CardDescription>
                  Paste report content (HTML, STIX JSON, OTX JSON, or plain text/markdown)
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Input
                  placeholder="Source URL (optional)"
                  value={uploadUrl}
                  onChange={(e) => setUploadUrl(e.target.value)}
                />
                <Textarea
                  placeholder="Paste report content here..."
                  value={uploadContent}
                  onChange={(e) => setUploadContent(e.target.value)}
                  rows={8}
                  className="font-mono text-xs"
                />
                <div className="flex gap-2">
                  <Button
                    onClick={() => importReportMutation.mutate({
                      content: uploadContent,
                      url: uploadUrl || undefined,
                    })}
                    disabled={!uploadContent || importReportMutation.isPending}
                  >
                    {importReportMutation.isPending ? (
                      <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Importing...</>
                    ) : (
                      <><Upload className="h-4 w-4 mr-2" /> Auto-Detect & Import</>
                    )}
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => {
                      const fileInput = document.createElement('input');
                      fileInput.type = 'file';
                      fileInput.accept = '.json,.html,.htm,.txt,.md,.xml';
                      fileInput.onchange = async (e) => {
                        const file = (e.target as HTMLInputElement).files?.[0];
                        if (file) {
                          const text = await file.text();
                          setUploadContent(text);
                        }
                      };
                      fileInput.click();
                    }}
                  >
                    <FileText className="h-4 w-4 mr-2" /> Load File
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ─── IOC Search Tab ──────────────────────────────────────────── */}
        <TabsContent value="ioc-search" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Search className="h-4 w-4 text-yellow-400" />
                IOC Search
              </CardTitle>
              <CardDescription>Search across all ingested IOCs (IPs, domains, hashes, CVEs)</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input
                placeholder="Search IOCs (min 3 chars)..."
                value={iocSearch}
                onChange={(e) => setIocSearch(e.target.value)}
              />
              {iocSearchQuery.data && (
                <div className="space-y-2">
                  {iocSearchQuery.data.length === 0 ? (
                    <p className="text-sm text-muted-foreground py-4 text-center">No IOCs found matching "{iocSearch}"</p>
                  ) : (
                    iocSearchQuery.data.map((ioc: any) => (
                      <div key={ioc.iocId} className="flex items-center justify-between p-3 rounded-lg border bg-card/50">
                        <div className="flex items-center gap-3">
                          <Badge variant="outline" className="text-xs">
                            {ioc.iocType}
                          </Badge>
                          <code className="text-sm font-mono">{ioc.value}</code>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="secondary" className={SOURCE_COLORS[ioc.reportSource] || ""}>
                            {SOURCE_LABELS[ioc.reportSource] || ioc.reportSource}
                          </Badge>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => { setSelectedReportId(ioc.reportId); setActiveTab("reports"); }}
                          >
                            <Eye className="h-4 w-4 mr-1" /> View Report
                          </Button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* ─── Report Detail Dialog ──────────────────────────────────────── */}
      <Dialog open={!!selectedReportId} onOpenChange={(open) => { if (!open) setSelectedReportId(null); }}>
        <DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto">
          {reportDetailQuery.isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : reportDetailQuery.data ? (
            <>
              <DialogHeader>
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant="outline" className={SOURCE_COLORS[reportDetailQuery.data.source] || ""}>
                    {SOURCE_LABELS[reportDetailQuery.data.source] || reportDetailQuery.data.source}
                  </Badge>
                  <Badge variant="outline" className={STATUS_COLORS[reportDetailQuery.data.status] || ""}>
                    {reportDetailQuery.data.status}
                  </Badge>
                </div>
                <DialogTitle className="text-lg">{reportDetailQuery.data.title}</DialogTitle>
                <DialogDescription>
                  {reportDetailQuery.data.publishedAt && (
                    <span>Published: {new Date(reportDetailQuery.data.publishedAt).toLocaleDateString()}</span>
                  )}
                  {reportDetailQuery.data.url && (
                    <a href={reportDetailQuery.data.url} target="_blank" rel="noopener noreferrer" className="ml-2 text-cyan-400 hover:underline inline-flex items-center gap-1">
                      <ExternalLink className="h-3 w-3" /> Source
                    </a>
                  )}
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4 mt-4">
                {/* Summary */}
                {reportDetailQuery.data.summary && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-1">Summary</h4>
                    <p className="text-sm">{reportDetailQuery.data.summary}</p>
                  </div>
                )}

                {/* Threat Actors & Malware */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-1">Threat Actors</h4>
                    <div className="flex gap-1 flex-wrap">
                      {(reportDetailQuery.data.threatActors as string[] || []).length === 0 ? (
                        <span className="text-xs text-muted-foreground">None identified</span>
                      ) : (
                        (reportDetailQuery.data.threatActors as string[]).map((a: string) => (
                          <Badge key={a} variant="secondary"><Shield className="h-3 w-3 mr-1" />{a}</Badge>
                        ))
                      )}
                    </div>
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-1">Malware Families</h4>
                    <div className="flex gap-1 flex-wrap">
                      {(reportDetailQuery.data.malwareFamilies as string[] || []).length === 0 ? (
                        <span className="text-xs text-muted-foreground">None identified</span>
                      ) : (
                        (reportDetailQuery.data.malwareFamilies as string[]).map((m: string) => (
                          <Badge key={m} variant="secondary" className="bg-red-500/10 text-red-400"><Bug className="h-3 w-3 mr-1" />{m}</Badge>
                        ))
                      )}
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK Techniques */}
                {(reportDetailQuery.data.mitreAttackTechniques as any[] || []).length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-1">
                      MITRE ATT&CK Techniques ({(reportDetailQuery.data.mitreAttackTechniques as any[]).length})
                    </h4>
                    <div className="flex gap-1 flex-wrap">
                      {(reportDetailQuery.data.mitreAttackTechniques as any[]).map((t: any, i: number) => (
                        <Badge key={i} variant="outline" className="text-xs bg-cyan-500/10 text-cyan-400 border-cyan-500/20">
                          {t.techniqueId} — {t.name}
                          {t.tactic !== 'Unknown' && <span className="ml-1 opacity-60">({t.tactic})</span>}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Diamond Model */}
                {reportDetailQuery.data.diamondModel && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-1">Diamond Model</h4>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      {Object.entries(reportDetailQuery.data.diamondModel as Record<string, string>).map(([k, v]) => (
                        v && <div key={k}><span className="text-muted-foreground capitalize">{k}:</span> {v}</div>
                      ))}
                    </div>
                  </div>
                )}

                {/* IOCs */}
                {reportDetailQuery.data.iocs.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-1">
                      IOCs ({reportDetailQuery.data.iocs.length})
                    </h4>
                    <div className="max-h-48 overflow-y-auto space-y-1">
                      {reportDetailQuery.data.iocs.map((ioc: any) => (
                        <div key={ioc.id} className="flex items-center gap-2 text-xs p-1.5 rounded bg-muted/30">
                          <Badge variant="outline" className="text-[10px] shrink-0">{ioc.iocType}</Badge>
                          <code className="font-mono truncate">{ioc.value}</code>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Tags */}
                {(reportDetailQuery.data.tags as string[] || []).length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-1">Tags</h4>
                    <div className="flex gap-1 flex-wrap">
                      {(reportDetailQuery.data.tags as string[]).map((t: string) => (
                        <Badge key={t} variant="secondary" className="text-xs">{t}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actions */}
                <div className="flex gap-2 pt-2 border-t">
                  <Button
                    size="sm"
                    onClick={() => enrichMutation.mutate({ id: selectedReportId! })}
                    disabled={enrichMutation.isPending}
                  >
                    {enrichMutation.isPending ? (
                      <><Loader2 className="h-4 w-4 mr-1 animate-spin" /> Enriching...</>
                    ) : (
                      <><Sparkles className="h-4 w-4 mr-1" /> LLM Enrich</>
                    )}
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => { if (confirm("Delete this report?")) deleteMutation.mutate({ id: selectedReportId! }); }}
                  >
                    <Trash2 className="h-4 w-4 mr-1" /> Delete
                  </Button>
                </div>
              </div>
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
