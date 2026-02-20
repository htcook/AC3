import { useState, useRef } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  ClipboardCheck, Download, FileText, Shield, AlertTriangle,
  Building2, Clock, Network, Target, ChevronDown, ChevronRight,
  Printer, Loader2, RefreshCw, TrendingUp, Layers,
} from "lucide-react";
import { exportBiaReportPdf } from "@/lib/export-utils";

// ─── Types ──────────────────────────────────────────────────────────────

interface BiaReportTable {
  caption: string;
  headers: string[];
  rows: string[][];
}

interface BiaReportSection {
  id: string;
  title: string;
  content: string;
  tables?: BiaReportTable[];
}

interface BiaReport {
  title: string;
  generatedAt: string;
  organization: {
    customerName: string;
    primaryDomain: string;
    sector: string;
    clientType: string;
    criticalFunctions: string[];
    complianceFlags: string[];
  };
  overallRiskScore: number;
  overallRiskBand: string;
  systemSecurityCategorization: {
    confidentiality: string;
    integrity: string;
    availability: string;
    overall: string;
  };
  sections: BiaReportSection[];
  assetCount: number;
  criticalAssetCount: number;
  highAssetCount: number;
}

// ─── Risk Band Colors ───────────────────────────────────────────────────

function riskBandColor(band: string) {
  switch (band.toLowerCase()) {
    case 'critical': return 'bg-red-500/10 text-red-400 border-red-500/30';
    case 'high': return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
    case 'medium': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
    case 'low': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    default: return 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30';
  }
}

function fipsColor(level: string) {
  switch (level.toUpperCase()) {
    case 'HIGH': return 'text-red-400';
    case 'MODERATE': return 'text-yellow-400';
    case 'LOW': return 'text-emerald-400';
    default: return 'text-zinc-400';
  }
}

// ─── Section Icons ──────────────────────────────────────────────────────

const sectionIcons: Record<string, React.ReactNode> = {
  'executive-overview': <Target className="w-5 h-5 text-cyan-400" />,
  'fips199': <Shield className="w-5 h-5 text-violet-400" />,
  'mission-functions': <Building2 className="w-5 h-5 text-amber-400" />,
  'criticality': <AlertTriangle className="w-5 h-5 text-red-400" />,
  'recovery-objectives': <Clock className="w-5 h-5 text-blue-400" />,
  'dependencies': <Network className="w-5 h-5 text-emerald-400" />,
  'risk-distribution': <TrendingUp className="w-5 h-5 text-orange-400" />,
  'recommendations': <Layers className="w-5 h-5 text-cyan-400" />,
};

// ─── Component ──────────────────────────────────────────────────────────

export default function BiaReportPage() {
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [report, setReport] = useState<BiaReport | null>(null);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set());
  const reportRef = useRef<HTMLDivElement>(null);

  const scansQ = trpc.domainIntel.listScans.useQuery();
  const generateMutation = trpc.domainIntel.generateBiaReport.useMutation({
    onSuccess: (data) => {
      setReport(data as BiaReport);
      // Expand all sections by default
      setExpandedSections(new Set((data as BiaReport).sections.map(s => s.id)));
      toast.success('BIA report generated successfully');
    },
    onError: (err) => {
      toast.error(err.message || 'Failed to generate BIA report');
    },
  });

  const completedScans = (scansQ.data || []).filter(
    (s: any) => ['scan_complete', 'completed'].includes(s.status)
  );

  const toggleSection = (id: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const expandAll = () => setExpandedSections(new Set(report?.sections.map(s => s.id) || []));
  const collapseAll = () => setExpandedSections(new Set());

  const handleGenerate = () => {
    if (!selectedScanId) {
      toast.error('Please select a completed scan first');
      return;
    }
    generateMutation.mutate({ scanId: parseInt(selectedScanId) });
  };

  const handleExportPdf = () => {
    if (!report) return;
    exportBiaReportPdf(report);
    toast.success('BIA report exported as PDF');
  };

  const handlePrint = () => {
    window.print();
  };

  // ─── Render ─────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <ClipboardCheck className="w-6 h-6 text-cyan-400" />
            Auto-BIA Report Generator
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            NIST IR 8286D-aligned Business Impact Analysis with FIPS 199 categorization
          </p>
        </div>
        <div className="flex gap-2">
          {report && (
            <>
              <Button variant="outline" size="sm" onClick={handlePrint}>
                <Printer className="w-4 h-4 mr-1" /> Print
              </Button>
              <Button variant="outline" size="sm" onClick={handleExportPdf}>
                <Download className="w-4 h-4 mr-1" /> Export PDF
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Scan Selector */}
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            Generate Business Impact Analysis
          </CardTitle>
          <CardDescription className="text-xs">
            Select a completed domain intel scan to generate a formal BIA report with FIPS 199 categorization,
            mission function mapping, recovery objectives, and remediation priorities.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3 items-end">
            <div className="flex-1 max-w-md">
              <label className="text-xs text-zinc-400 mb-1 block">Completed Scan</label>
              <Select value={selectedScanId} onValueChange={setSelectedScanId}>
                <SelectTrigger className="h-9 text-sm">
                  <SelectValue placeholder="Select a completed scan..." />
                </SelectTrigger>
                <SelectContent>
                  {completedScans.map((scan: any) => (
                    <SelectItem key={scan.id} value={String(scan.id)}>
                      {scan.primaryDomain} — {scan.totalAssets || 0} assets — {new Date(scan.createdAt).toLocaleDateString()}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              onClick={handleGenerate}
              disabled={!selectedScanId || generateMutation.isPending}
              className="bg-cyan-600 hover:bg-cyan-700"
            >
              {generateMutation.isPending ? (
                <><Loader2 className="w-4 h-4 mr-1 animate-spin" /> Generating...</>
              ) : (
                <><RefreshCw className="w-4 h-4 mr-1" /> Generate BIA Report</>
              )}
            </Button>
          </div>
          {completedScans.length === 0 && (
            <p className="text-xs text-zinc-500 mt-3">
              No completed scans found. Run a domain intel scan first to generate a BIA report.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Report Content */}
      {report && (
        <div ref={reportRef} className="space-y-4 print:space-y-2">
          {/* Report Header Card */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-6">
              <div className="flex items-start justify-between">
                <div>
                  <h2 className="text-xl font-bold text-zinc-100">{report.title}</h2>
                  <p className="text-xs text-zinc-500 mt-1">
                    Generated: {new Date(report.generatedAt).toLocaleString()} | {report.assetCount} assets analyzed
                  </p>
                </div>
                <div className="text-right space-y-2">
                  <Badge className={`${riskBandColor(report.overallRiskBand)} text-sm px-3 py-1`}>
                    Risk: {report.overallRiskScore}/100 ({report.overallRiskBand.toUpperCase()})
                  </Badge>
                  <div className="flex gap-1 justify-end">
                    <Badge variant="outline" className={fipsColor(report.systemSecurityCategorization.overall)}>
                      FIPS 199: {report.systemSecurityCategorization.overall}
                    </Badge>
                  </div>
                </div>
              </div>

              {/* FIPS 199 Summary Bar */}
              <div className="mt-4 grid grid-cols-3 gap-3">
                <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider">Confidentiality</p>
                  <p className={`text-sm font-bold ${fipsColor(report.systemSecurityCategorization.confidentiality)}`}>
                    {report.systemSecurityCategorization.confidentiality}
                  </p>
                </div>
                <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider">Integrity</p>
                  <p className={`text-sm font-bold ${fipsColor(report.systemSecurityCategorization.integrity)}`}>
                    {report.systemSecurityCategorization.integrity}
                  </p>
                </div>
                <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider">Availability</p>
                  <p className={`text-sm font-bold ${fipsColor(report.systemSecurityCategorization.availability)}`}>
                    {report.systemSecurityCategorization.availability}
                  </p>
                </div>
              </div>

              {/* Quick Stats */}
              <div className="mt-4 flex gap-4 text-xs text-zinc-400">
                <span>Critical Assets: <strong className="text-red-400">{report.criticalAssetCount}</strong></span>
                <span>High Assets: <strong className="text-orange-400">{report.highAssetCount}</strong></span>
                <span>Total Assets: <strong className="text-zinc-200">{report.assetCount}</strong></span>
                <span>Sector: <strong className="text-zinc-200">{report.organization.sector}</strong></span>
              </div>
            </CardContent>
          </Card>

          {/* Section Controls */}
          <div className="flex gap-2 print:hidden">
            <Button variant="ghost" size="sm" className="text-xs" onClick={expandAll}>
              Expand All
            </Button>
            <Button variant="ghost" size="sm" className="text-xs" onClick={collapseAll}>
              Collapse All
            </Button>
          </div>

          {/* Report Sections */}
          {report.sections.map((section) => (
            <Card key={section.id} className="bg-zinc-900/50 border-zinc-800 print:break-inside-avoid">
              <CardHeader
                className="pb-2 cursor-pointer hover:bg-zinc-800/30 transition-colors print:cursor-default"
                onClick={() => toggleSection(section.id)}
              >
                <div className="flex items-center gap-2">
                  <span className="print:hidden">
                    {expandedSections.has(section.id) ? (
                      <ChevronDown className="w-4 h-4 text-zinc-500" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-zinc-500" />
                    )}
                  </span>
                  {sectionIcons[section.id] || <FileText className="w-5 h-5 text-zinc-400" />}
                  <CardTitle className="text-sm">{section.title}</CardTitle>
                </div>
              </CardHeader>

              {(expandedSections.has(section.id) || false) && (
                <CardContent className="pt-0">
                  {/* Section Content (Markdown-like rendering) */}
                  <div className="text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap">
                    {section.content.split('\n').map((line, i) => {
                      if (line.startsWith('**') && line.includes(':**')) {
                        const [label, ...rest] = line.split(':**');
                        return (
                          <p key={i} className="mb-2">
                            <strong className="text-zinc-100">{label.replace(/\*\*/g, '')}:</strong>
                            {rest.join(':**').replace(/\*\*/g, '')}
                          </p>
                        );
                      }
                      if (line.startsWith('- **')) {
                        return (
                          <p key={i} className="mb-1 pl-4">
                            <span className="text-zinc-500 mr-1">&bull;</span>
                            <span dangerouslySetInnerHTML={{
                              __html: line.slice(2)
                                .replace(/\*\*(.*?)\*\*/g, '<strong class="text-zinc-100">$1</strong>')
                            }} />
                          </p>
                        );
                      }
                      if (line.trim() === '') return <br key={i} />;
                      return (
                        <p key={i} className="mb-2" dangerouslySetInnerHTML={{
                          __html: line.replace(/\*\*(.*?)\*\*/g, '<strong class="text-zinc-100">$1</strong>')
                        }} />
                      );
                    })}
                  </div>

                  {/* Section Tables */}
                  {section.tables?.map((table, ti) => (
                    <div key={ti} className="mt-4">
                      <p className="text-xs text-zinc-500 mb-2 font-medium">{table.caption}</p>
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="border-b border-zinc-700">
                              {table.headers.map((h, hi) => (
                                <th key={hi} className="text-left py-2 px-3 text-zinc-400 font-medium whitespace-nowrap">
                                  {h}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {table.rows.map((row, ri) => (
                              <tr key={ri} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                                {row.map((cell, ci) => {
                                  // Color-code risk bands and FIPS levels
                                  let cellClass = "py-2 px-3 text-zinc-300";
                                  if (['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'MEDIUM'].includes(cell.toUpperCase())) {
                                    const c = cell.toUpperCase();
                                    if (c === 'CRITICAL') cellClass = "py-2 px-3 text-red-400 font-medium";
                                    else if (c === 'HIGH') cellClass = "py-2 px-3 text-orange-400 font-medium";
                                    else if (c === 'MODERATE' || c === 'MEDIUM') cellClass = "py-2 px-3 text-yellow-400 font-medium";
                                    else if (c === 'LOW') cellClass = "py-2 px-3 text-emerald-400 font-medium";
                                  }
                                  if (cell === 'YES') cellClass = "py-2 px-3 text-red-400 font-bold";
                                  return (
                                    <td key={ci} className={cellClass}>
                                      {cell}
                                    </td>
                                  );
                                })}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ))}
                </CardContent>
              )}
            </Card>
          ))}

          {/* Footer */}
          <Card className="bg-zinc-900/50 border-zinc-800 print:break-inside-avoid">
            <CardContent className="p-4">
              <p className="text-[10px] text-zinc-600 text-center">
                This Business Impact Analysis was generated using automated OSINT and vulnerability intelligence.
                All findings should be validated by qualified security professionals before informing risk decisions.
                Report generated in accordance with NIST IR 8286D, FIPS 199, and NIST SP 800-34 Rev. 1 guidance.
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Empty State */}
      {!report && !generateMutation.isPending && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="py-16 text-center">
            <ClipboardCheck className="w-12 h-12 mx-auto mb-4 text-zinc-600" />
            <h3 className="text-lg font-medium text-zinc-300 mb-2">No BIA Report Generated</h3>
            <p className="text-sm text-zinc-500 max-w-md mx-auto">
              Select a completed domain intel scan above and click "Generate BIA Report" to create
              a comprehensive Business Impact Analysis with FIPS 199 categorization, mission function
              mapping, and recovery objectives.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Loading State */}
      {generateMutation.isPending && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="py-16 text-center">
            <Loader2 className="w-10 h-10 mx-auto mb-4 text-cyan-400 animate-spin" />
            <h3 className="text-lg font-medium text-zinc-300 mb-2">Generating BIA Report...</h3>
            <p className="text-sm text-zinc-500">
              Analyzing assets, computing FIPS 199 categorization, mapping mission functions,
              and building recovery objectives...
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
