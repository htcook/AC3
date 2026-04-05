import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Globe, Search, FileText, Download, Eye, Shield,
  AlertTriangle, CheckCircle2, Loader2, Brain, ExternalLink, Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { exportDiReport } from "@/lib/export-di-report";

function riskBadge(score: number | null | undefined) {
  if (!score) return <Badge variant="outline" className="text-[10px] text-muted-foreground">N/A</Badge>;
  const cls = score >= 70 ? "bg-red-500/20 text-red-400 border-red-500/30"
    : score >= 40 ? "bg-orange-500/20 text-orange-400 border-orange-500/30"
    : "bg-green-500/20 text-green-400 border-green-500/30";
  return <Badge variant="outline" className={`text-[10px] ${cls}`}>{score}/100</Badge>;
}

export default function DomainIntelReports() {
  const [, navigate] = useLocation();
  const scansQuery = trpc.domainIntel.listScans.useQuery();
  const [search, setSearch] = useState("");
  const [generatingId, setGeneratingId] = useState<number | null>(null);

  // Delete scan mutation
  const deleteScan = trpc.domainIntel.deleteScan.useMutation({
    onSuccess: () => { toast.success('Scan deleted'); scansQuery.refetch(); },
    onError: (err: any) => { toast.error(`Delete failed: ${err.message || 'Unknown error'}`); },
  });

  // Only show completed scans that can generate reports
  const completedScans = useMemo(() => {
    if (!scansQuery.data) return [];
    return scansQuery.data
      .filter((s: any) => s.status === "completed" || s.status === "scan_complete")
      .filter((s: any) => {
        if (!search.trim()) return true;
        const q = search.toLowerCase();
        return s.primaryDomain?.toLowerCase().includes(q) ||
          s.customerName?.toLowerCase().includes(q) ||
          s.sector?.toLowerCase().includes(q);
      })
      .sort((a: any, b: any) => new Date(b.updatedAt || b.createdAt).getTime() - new Date(a.updatedAt || a.createdAt).getTime());
  }, [scansQuery.data, search]);

  const handleGenerateReport = async (scan: any) => {
    setGeneratingId(scan.id);
    try {
      // Fetch full scan data for the report
      const response = await fetch(`/api/trpc/domainIntel.getScan?input=${encodeURIComponent(JSON.stringify({ id: scan.id }))}`);
      const result = await response.json();
      const fullData = result?.result?.data;
      if (!fullData?.scan) {
        toast.error("Failed to load scan data for report generation");
        return;
      }
      const fullScan = fullData.scan;
      const pipeline = fullScan.pipelineOutput || {};
      const assets = fullData.assets || [];
      const fullScanData = { ...fullScan, ...pipeline, assets, observations: pipeline?.observations || [] };
      await exportDiReport(fullScan.primaryDomain, fullScanData);
      toast.success("Domain Intelligence report PDF generated successfully");
    } catch (err: any) {
      toast.error("Report generation failed: " + (err.message || "Unknown error"));
    } finally {
      setGeneratingId(null);
    }
  };

  if (scansQuery.isLoading) {
    return (
      <div className="space-y-3">
        {[1, 2, 3].map(i => <Skeleton key={i} className="h-20 w-full" />)}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by domain, client, or sector..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-9 h-9 text-sm"
          />
        </div>
        <Badge variant="outline" className="text-xs whitespace-nowrap">
          {completedScans.length} scan{completedScans.length !== 1 ? "s" : ""} available
        </Badge>
      </div>

      {completedScans.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Brain className="h-12 w-12 text-muted-foreground mb-3" />
            <p className="text-sm text-muted-foreground">
              {search ? "No matching scans found" : "No completed domain intelligence scans yet"}
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              Run a Domain Intelligence scan to generate reports
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {completedScans.map((scan: any) => (
            <Card key={scan.id} className="hover:bg-accent/5 transition-colors">
              <CardContent className="flex items-center gap-4 py-3 px-4">
                <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-purple-500/10">
                  <Globe className="h-5 w-5 text-purple-400" />
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-medium truncate">
                      {scan.primaryDomain}
                    </span>
                    {riskBadge(scan.overallRiskScore)}
                    {scan.totalFindings > 0 && (
                      <Badge variant="outline" className="text-[10px]">
                        {scan.totalFindings} findings
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-3 mt-0.5 text-xs text-muted-foreground">
                    {scan.customerName && <span>{scan.customerName}</span>}
                    {scan.sector && <span className="capitalize">{scan.sector}</span>}
                    <span>{new Date(scan.updatedAt || scan.createdAt).toLocaleDateString()}</span>
                    {scan.totalAssets > 0 && <span>{scan.totalAssets} assets</span>}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs h-8"
                    onClick={() => navigate(`/domain-intel/${scan.id}`)}
                  >
                    <Eye className="h-3.5 w-3.5 mr-1" />
                    View
                  </Button>
                  <Button
                    size="sm"
                    className="text-xs h-8 bg-purple-600 hover:bg-purple-700 text-white"
                    disabled={generatingId === scan.id}
                    onClick={() => handleGenerateReport(scan)}
                  >
                    {generatingId === scan.id ? (
                      <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                    ) : (
                      <Download className="h-3.5 w-3.5 mr-1" />
                    )}
                    DI Report
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 w-8 p-0 text-red-400 hover:text-red-300 hover:bg-red-500/10"
                    disabled={deleteScan.isPending}
                    onClick={() => {
                      if (confirm(`Delete scan for ${scan.primaryDomain}? This will remove all associated data and cannot be undone.`)) {
                        deleteScan.mutate({ scanId: scan.id });
                      }
                    }}
                    title="Delete scan"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
