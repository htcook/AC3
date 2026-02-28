/**
 * Batch Domain Scanner — CSV upload, hybrid scoring, risk card browser, and export.
 * Allows bulk domain scanning with progress tracking and persisted results.
 */
import { useState, useRef, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import {
  Upload, Search, Download, Trash2, RefreshCw, Shield, AlertTriangle,
  FileText, Globe, BarChart3, ChevronDown, ChevronUp, Filter, X,
  Loader2, CheckCircle2, XCircle, Clock,
} from "lucide-react";

// Priority tier colors
const TIER_COLORS: Record<string, string> = {
  P0: "bg-red-600 text-white",
  P1: "bg-red-500 text-white",
  P2: "bg-amber-500 text-white",
  P3: "bg-blue-500 text-white",
};

const SECTOR_LABELS: Record<string, string> = {
  banking_financial_services: "Banking & Financial",
  healthcare_providers: "Healthcare",
  pharmaceuticals_biotech: "Pharma & Biotech",
  federal_government: "Government",
  defense_aerospace: "Defense & Aerospace",
  electric_gas_utilities: "Energy & Utilities",
  saas_tech: "SaaS / Tech",
};

function parseCsvText(text: string): Array<{
  domain: string;
  sector?: string;
  subSector?: string;
  naicsCode?: string;
  regulatory?: string;
  country?: string;
}> {
  const lines = text.trim().split("\n");
  if (lines.length < 2) return [];

  const header = lines[0].split(",").map((h) => h.trim().toLowerCase().replace(/['"]/g, ""));
  const domainIdx = header.findIndex((h) => h === "domain" || h === "hostname" || h === "url");
  const sectorIdx = header.findIndex((h) => h === "sector" || h === "industry");
  const subSectorIdx = header.findIndex((h) => h === "subsector" || h === "sub_sector" || h === "sub-sector" || h === "category");
  const naicsIdx = header.findIndex((h) => h === "naics" || h === "naics_code");
  const regIdx = header.findIndex((h) => h === "regulatory" || h === "compliance" || h === "frameworks");
  const countryIdx = header.findIndex((h) => h === "country" || h === "region");

  if (domainIdx === -1) return [];

  return lines.slice(1).map((line) => {
    const cols = line.split(",").map((c) => c.trim().replace(/['"]/g, ""));
    return {
      domain: cols[domainIdx]?.replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "",
      sector: sectorIdx >= 0 ? cols[sectorIdx] : undefined,
      subSector: subSectorIdx >= 0 ? cols[subSectorIdx] : undefined,
      naicsCode: naicsIdx >= 0 ? cols[naicsIdx] : undefined,
      regulatory: regIdx >= 0 ? cols[regIdx] : undefined,
      country: countryIdx >= 0 ? cols[countryIdx] : undefined,
    };
  }).filter((d) => d.domain && d.domain.includes("."));
}

export default function BatchDomainScanner() {

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [activeTab, setActiveTab] = useState("upload");
  const [parsedDomains, setParsedDomains] = useState<ReturnType<typeof parseCsvText>>([]);
  const [scanProgress, setScanProgress] = useState<{ running: boolean; total: number; done: number; batchId?: string }>({
    running: false, total: 0, done: 0,
  });
  const [filterSector, setFilterSector] = useState<string>("all");
  const [filterTier, setFilterTier] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedCard, setExpandedCard] = useState<number | null>(null);
  const [selectedBatch, setSelectedBatch] = useState<string>("all");

  // Queries
  const riskCardsQuery = trpc.scoring.listRiskCards.useQuery(
    selectedBatch !== "all" ? { batchId: selectedBatch, limit: 500 } : { limit: 500 },
    { enabled: activeTab === "results" }
  );
  const statsQuery = trpc.scoring.getRiskCardStats.useQuery(undefined, {
    enabled: activeTab === "results",
  });

  // Mutations
  const batchScanMutation = trpc.scoring.batchScanDomains.useMutation({
    onSuccess: (data) => {
      setScanProgress({ running: false, total: data.totalProcessed + data.totalErrors, done: data.totalProcessed + data.totalErrors, batchId: data.batchId });
      toast.success(`Batch Scan Complete: ${data.totalProcessed} domains scored, ${data.totalErrors} errors`);
      riskCardsQuery.refetch();
      statsQuery.refetch();
      setActiveTab("results");
    },
    onError: (err) => {
      setScanProgress((p) => ({ ...p, running: false }));
      toast.error(`Scan Failed: ${err.message}`);
    },
  });

  const deleteBatchMutation = trpc.scoring.deleteRiskCardBatch.useMutation({
    onSuccess: () => {
      toast.success("Batch Deleted");
      riskCardsQuery.refetch();
      statsQuery.refetch();
    },
  });

  // CSV upload handler
  const handleFileUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      const domains = parseCsvText(text);
      setParsedDomains(domains);
      if (domains.length === 0) {
        toast.error("No valid domains found — CSV must have a 'domain' column");
      } else {
        toast.success(`${domains.length} domains parsed — ready to scan`);
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  }, []);

  // Start batch scan
  const startScan = useCallback(() => {
    if (parsedDomains.length === 0) return;
    setScanProgress({ running: true, total: parsedDomains.length, done: 0 });
    batchScanMutation.mutate({ domains: parsedDomains });
  }, [parsedDomains, batchScanMutation]);

  // Filter risk cards
  const filteredCards = useMemo(() => {
    if (!riskCardsQuery.data) return [];
    return riskCardsQuery.data.filter((card: any) => {
      if (filterSector !== "all" && card.inferredSector !== filterSector) return false;
      if (filterTier !== "all" && card.priorityTier !== filterTier) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return card.domain?.toLowerCase().includes(q) ||
          card.scanTitle?.toLowerCase().includes(q) ||
          card.industry?.toLowerCase().includes(q);
      }
      return true;
    });
  }, [riskCardsQuery.data, filterSector, filterTier, searchQuery]);

  // Export to CSV
  const exportCsv = useCallback(() => {
    if (!filteredCards.length) return;
    const headers = ["Domain", "Sector", "Industry", "NAICS", "Hybrid Score", "Priority Tier", "Confidence", "Regulatory Tags", "Batch ID"];
    const rows = filteredCards.map((c: any) => [
      c.domain, c.inferredSector, c.industry || "", c.naicsCode || "",
      typeof c.hybridScore === "string" ? JSON.parse(c.hybridScore) : c.hybridScore,
      c.priorityTier, c.confidenceBand,
      Array.isArray(c.regulatoryTags) ? c.regulatoryTags.join(";") : (typeof c.regulatoryTags === "string" ? JSON.parse(c.regulatoryTags).join(";") : ""),
      c.batchId || "",
    ]);
    const csv = [headers.join(","), ...rows.map((r: any[]) => r.map((v: any) => `"${v}"`).join(","))].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hybrid-risk-cards-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [filteredCards]);

  // Get unique batches
  const batches = useMemo(() => {
    if (!riskCardsQuery.data) return [];
    const set = new Set<string>();
    riskCardsQuery.data.forEach((c: any) => { if (c.batchId) set.add(c.batchId); });
    return Array.from(set).sort().reverse();
  }, [riskCardsQuery.data]);

  // Sector breakdown for preview
  const sectorBreakdown = useMemo(() => {
    const map: Record<string, number> = {};
    parsedDomains.forEach((d) => {
      const s = d.sector || "Unknown";
      map[s] = (map[s] || 0) + 1;
    });
    return Object.entries(map).sort((a, b) => b[1] - a[1]);
  }, [parsedDomains]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Batch Domain Scanner</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Upload CSV domains for bulk hybrid scoring, risk card generation, and LLM training data
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={exportCsv} disabled={!filteredCards.length}>
            <Download className="w-4 h-4 mr-1" /> Export CSV
          </Button>
          <Button variant="outline" size="sm" onClick={() => { riskCardsQuery.refetch(); statsQuery.refetch(); }}>
            <RefreshCw className="w-4 h-4 mr-1" /> Refresh
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      {statsQuery.data && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="bg-card/50">
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-foreground">{statsQuery.data.total || 0}</div>
              <div className="text-xs text-muted-foreground">Total Risk Cards</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-foreground">{statsQuery.data.sectors || 0}</div>
              <div className="text-xs text-muted-foreground">Sectors Covered</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-foreground">{statsQuery.data.batches || 0}</div>
              <div className="text-xs text-muted-foreground">Batch Scans</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-red-500">{statsQuery.data.criticalCount || 0}</div>
              <div className="text-xs text-muted-foreground">P0/P1 Critical</div>
            </CardContent>
          </Card>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="upload"><Upload className="w-4 h-4 mr-1" /> Upload & Scan</TabsTrigger>
          <TabsTrigger value="results"><Shield className="w-4 h-4 mr-1" /> Risk Cards</TabsTrigger>
        </TabsList>

        {/* Upload Tab */}
        <TabsContent value="upload" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Upload Domain CSV</CardTitle>
              <CardDescription>
                CSV must include a <code className="text-xs bg-muted px-1 rounded">domain</code> column.
                Optional: <code className="text-xs bg-muted px-1 rounded">sector</code>,{" "}
                <code className="text-xs bg-muted px-1 rounded">subsector</code>,{" "}
                <code className="text-xs bg-muted px-1 rounded">naics</code>,{" "}
                <code className="text-xs bg-muted px-1 rounded">regulatory</code>,{" "}
                <code className="text-xs bg-muted px-1 rounded">country</code>
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div
                className="border-2 border-dashed border-border rounded-lg p-8 text-center cursor-pointer hover:border-primary/50 transition-colors"
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload className="w-8 h-8 mx-auto mb-2 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  Click to upload CSV or drag and drop
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  Supports .csv files with domain lists
                </p>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv"
                  className="hidden"
                  onChange={handleFileUpload}
                />
              </div>

              {/* Parsed Preview */}
              {parsedDomains.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-foreground">
                      {parsedDomains.length} domains ready to scan
                    </h3>
                    <Button variant="ghost" size="sm" onClick={() => setParsedDomains([])}>
                      <X className="w-4 h-4 mr-1" /> Clear
                    </Button>
                  </div>

                  {/* Sector breakdown */}
                  <div className="flex flex-wrap gap-2">
                    {sectorBreakdown.map(([sector, count]) => (
                      <Badge key={sector} variant="secondary" className="text-xs">
                        {sector}: {count}
                      </Badge>
                    ))}
                  </div>

                  {/* Domain preview table */}
                  <div className="max-h-[300px] overflow-y-auto border rounded-lg">
                    <table className="w-full text-xs">
                      <thead className="bg-muted/50 sticky top-0">
                        <tr>
                          <th className="text-left p-2 font-medium">Domain</th>
                          <th className="text-left p-2 font-medium">Sector</th>
                          <th className="text-left p-2 font-medium">Sub-Sector</th>
                          <th className="text-left p-2 font-medium">NAICS</th>
                        </tr>
                      </thead>
                      <tbody>
                        {parsedDomains.slice(0, 50).map((d, i) => (
                          <tr key={i} className="border-t border-border/50">
                            <td className="p-2 font-mono">{d.domain}</td>
                            <td className="p-2">{d.sector || "—"}</td>
                            <td className="p-2">{d.subSector || "—"}</td>
                            <td className="p-2">{d.naicsCode || "—"}</td>
                          </tr>
                        ))}
                        {parsedDomains.length > 50 && (
                          <tr>
                            <td colSpan={4} className="p-2 text-center text-muted-foreground">
                              ... and {parsedDomains.length - 50} more
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Scan button */}
                  <Button
                    onClick={startScan}
                    disabled={scanProgress.running}
                    className="w-full"
                    size="lg"
                  >
                    {scanProgress.running ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Scanning {parsedDomains.length} domains...
                      </>
                    ) : (
                      <>
                        <Shield className="w-4 h-4 mr-2" />
                        Run Hybrid Scoring on {parsedDomains.length} Domains
                      </>
                    )}
                  </Button>
                </div>
              )}

              {/* Progress */}
              {scanProgress.running && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Processing...</span>
                    <span className="font-mono text-foreground">
                      <Loader2 className="w-3 h-3 inline animate-spin mr-1" />
                      {scanProgress.total} domains
                    </span>
                  </div>
                  <Progress value={undefined} className="h-2" />
                </div>
              )}

              {/* Completion */}
              {!scanProgress.running && scanProgress.batchId && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-green-500/10 border border-green-500/20">
                  <CheckCircle2 className="w-5 h-5 text-green-500" />
                  <div>
                    <p className="text-sm font-medium text-foreground">Scan Complete</p>
                    <p className="text-xs text-muted-foreground">
                      Batch: {scanProgress.batchId} — {scanProgress.done} domains processed
                    </p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Results Tab */}
        <TabsContent value="results" className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3 items-center">
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search domains..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9"
                />
              </div>
            </div>
            <Select value={filterSector} onValueChange={setFilterSector}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="All Sectors" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Sectors</SelectItem>
                {Object.entries(SECTOR_LABELS).map(([k, v]) => (
                  <SelectItem key={k} value={k}>{v}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={filterTier} onValueChange={setFilterTier}>
              <SelectTrigger className="w-[120px]">
                <SelectValue placeholder="All Tiers" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tiers</SelectItem>
                <SelectItem value="P0">P0 — Critical</SelectItem>
                <SelectItem value="P1">P1 — High</SelectItem>
                <SelectItem value="P2">P2 — Medium</SelectItem>
                <SelectItem value="P3">P3 — Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={selectedBatch} onValueChange={setSelectedBatch}>
              <SelectTrigger className="w-[200px]">
                <SelectValue placeholder="All Batches" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Batches</SelectItem>
                {batches.map((b) => (
                  <SelectItem key={b} value={b}>{b}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            {(filterSector !== "all" || filterTier !== "all" || searchQuery || selectedBatch !== "all") && (
              <Button variant="ghost" size="sm" onClick={() => { setFilterSector("all"); setFilterTier("all"); setSearchQuery(""); setSelectedBatch("all"); }}>
                <X className="w-4 h-4 mr-1" /> Clear Filters
              </Button>
            )}
          </div>

          <p className="text-xs text-muted-foreground">
            Showing {filteredCards.length} of {riskCardsQuery.data?.length || 0} risk cards
          </p>

          {/* Risk Card Grid */}
          {riskCardsQuery.isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : filteredCards.length === 0 ? (
            <Card className="bg-card/50">
              <CardContent className="py-12 text-center">
                <FileText className="w-8 h-8 mx-auto mb-2 text-muted-foreground/50" />
                <p className="text-sm text-muted-foreground">No risk cards found</p>
                <p className="text-xs text-muted-foreground mt-1">Upload a CSV and run a scan to generate risk cards</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {filteredCards.map((card: any) => {
                const isExpanded = expandedCard === card.id;
                const hybridScore = typeof card.hybridScore === "string" ? JSON.parse(card.hybridScore) : card.hybridScore;
                const topDrivers = typeof card.topDrivers === "string" ? JSON.parse(card.topDrivers) : card.topDrivers;
                const recommendedActions = typeof card.recommendedActions === "string" ? JSON.parse(card.recommendedActions) : card.recommendedActions;
                const threatLikelihood = typeof card.threatLikelihood === "string" ? JSON.parse(card.threatLikelihood) : card.threatLikelihood;
                const calderaOps = typeof card.calderaOps === "string" ? JSON.parse(card.calderaOps) : card.calderaOps;
                const regulatoryTags = typeof card.regulatoryTags === "string" ? JSON.parse(card.regulatoryTags) : card.regulatoryTags;

                return (
                  <Card key={card.id} className="bg-card/50 hover:bg-card/80 transition-colors">
                    <div
                      className="flex items-center gap-3 p-4 cursor-pointer"
                      onClick={() => setExpandedCard(isExpanded ? null : card.id)}
                    >
                      <Badge className={TIER_COLORS[card.priorityTier] || "bg-gray-500 text-white"}>
                        {card.priorityTier}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <Globe className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                          <span className="font-mono text-sm font-medium text-foreground truncate">{card.domain}</span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-xs text-muted-foreground">
                            {SECTOR_LABELS[card.inferredSector] || card.inferredSector}
                          </span>
                          {card.industry && (
                            <span className="text-xs text-muted-foreground">• {card.industry}</span>
                          )}
                          {card.naicsCode && (
                            <Badge variant="outline" className="text-[10px] h-4">NAICS {card.naicsCode}</Badge>
                          )}
                        </div>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <div className="text-lg font-bold text-foreground">
                          {typeof hybridScore === "number" ? hybridScore.toFixed(2) : hybridScore}
                        </div>
                        <div className="text-[10px] text-muted-foreground">Hybrid Score</div>
                      </div>
                      <Badge variant="outline" className="text-xs">
                        {card.confidenceBand}
                      </Badge>
                      {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                    </div>

                    {isExpanded && (
                      <CardContent className="pt-0 pb-4 px-4 border-t border-border/50">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-3">
                          {/* Top Drivers */}
                          <div>
                            <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">Top Risk Drivers</h4>
                            {Array.isArray(topDrivers) && topDrivers.length > 0 ? (
                              <div className="space-y-1.5">
                                {topDrivers.slice(0, 5).map((d: any, i: number) => (
                                  <div key={i} className="flex items-start gap-2 text-xs">
                                    <AlertTriangle className="w-3 h-3 text-amber-500 mt-0.5 flex-shrink-0" />
                                    <div>
                                      <span className="font-medium text-foreground">{d.dimension || d.label || "Driver"}</span>
                                      {d.evidence && <span className="text-muted-foreground ml-1">— {d.evidence}</span>}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-xs text-muted-foreground">No drivers available</p>
                            )}
                          </div>

                          {/* Threat Likelihood */}
                          <div>
                            <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">Threat Likelihood</h4>
                            {threatLikelihood && typeof threatLikelihood === "object" ? (
                              <div className="space-y-1">
                                {Object.entries(threatLikelihood).slice(0, 6).map(([key, val]: [string, any]) => (
                                  <div key={key} className="flex items-center justify-between text-xs">
                                    <span className="text-foreground capitalize">{key.replace(/_/g, " ")}</span>
                                    <span className="font-mono text-muted-foreground">
                                      {typeof val === "number" ? (val * 100).toFixed(0) + "%" : typeof val === "object" && val?.probability ? (val.probability * 100).toFixed(0) + "%" : String(val)}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-xs text-muted-foreground">No threat data</p>
                            )}
                          </div>

                          {/* Recommended Actions */}
                          <div>
                            <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">Recommended Actions</h4>
                            {Array.isArray(recommendedActions) && recommendedActions.length > 0 ? (
                              <div className="space-y-1">
                                {recommendedActions.slice(0, 5).map((a: any, i: number) => (
                                  <div key={i} className="flex items-start gap-2 text-xs">
                                    <CheckCircle2 className="w-3 h-3 text-green-500 mt-0.5 flex-shrink-0" />
                                    <span className="text-foreground">{typeof a === "string" ? a : a.action || a.label || JSON.stringify(a)}</span>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-xs text-muted-foreground">No actions available</p>
                            )}
                          </div>
                        </div>

                        {/* Regulatory & Caldera */}
                        <div className="flex flex-wrap gap-4 mt-4 pt-3 border-t border-border/50">
                          {Array.isArray(regulatoryTags) && regulatoryTags.length > 0 && (
                            <div>
                              <span className="text-[10px] text-muted-foreground uppercase">Regulatory:</span>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {regulatoryTags.map((t: string, i: number) => (
                                  <Badge key={i} variant="outline" className="text-[10px]">{t}</Badge>
                                ))}
                              </div>
                            </div>
                          )}
                          {calderaOps && (
                            <div>
                              <span className="text-[10px] text-muted-foreground uppercase">Caldera Priority:</span>
                              <div className="mt-1">
                                <Badge variant="secondary" className="text-[10px]">
                                  {typeof calderaOps === "object" ? calderaOps.tier || calderaOps.priority || JSON.stringify(calderaOps) : calderaOps}
                                </Badge>
                              </div>
                            </div>
                          )}
                        </div>
                      </CardContent>
                    )}
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
