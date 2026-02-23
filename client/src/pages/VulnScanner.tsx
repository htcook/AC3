import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { UploadCloud, FileText, Trash2, AlertCircle, Loader2, BarChart2, HelpCircle } from "lucide-react";

// Mock Chart component - replace with your actual charting library
const Chart = ({ data, type }: { data: any; type: string }) => (
  <div className="w-full h-64 bg-slate-800/50 rounded-lg flex items-center justify-center">
    <BarChart2 className="h-12 w-12 text-slate-500" />
    <p className="ml-4 text-slate-500">Chart placeholder for {type}</p>
  </div>
);

const severityColors = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-yellow-500",
  Low: "bg-blue-500",
  Info: "bg-gray-500",
};

export default function VulnScanner() {
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [scannerType, setScannerType] = useState("nessus");
  const [file, setFile] = useState<File | null>(null);

  const utils = trpc.useUtils();

  const { data: scans, isLoading: isLoadingScans, error: scansError } = trpc.vulnScanner.listScans.useQuery();
  const { data: stats, isLoading: isLoadingStats } = trpc.vulnScanner.getVulnStats.useQuery();
  const { data: scanDetails, isLoading: isLoadingDetails } = trpc.vulnScanner.getScanDetails.useQuery(
    { id: selectedScanId! },
    { enabled: !!selectedScanId }
  );

  const importMutation = trpc.vulnScanner.importScan.useMutation({
    onSuccess: () => {
      toast.success("Scan imported successfully!");
      utils.vulnScanner.listScans.invalidate();
      utils.vulnScanner.getVulnStats.invalidate();
      setFile(null);
    },
    onError: (error) => {
      toast.error("Failed to import scan: " + error.message);
    },
  });

  const deleteMutation = trpc.vulnScanner.deleteScan.useMutation({
    onSuccess: () => {
      toast.success("Scan deleted successfully!");
      utils.vulnScanner.listScans.invalidate();
      utils.vulnScanner.getVulnStats.invalidate();
      setSelectedScanId(null);
    },
    onError: (error) => {
      toast.error("Failed to delete scan: " + error.message);
    },
  });

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files) {
      setFile(event.target.files[0]);
    }
  };

  const handleImport = useCallback(() => {
    if (!file) {
      toast.warning("Please select a file to import.");
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      const rawData = e.target?.result as string;
      importMutation.mutate({ scannerType, fileName: file.name, rawData });
    };
    reader.readAsText(file);
  }, [file, scannerType, importMutation]);

  const handleDelete = (id: string) => {
    if (window.confirm("Are you sure you want to delete this scan?")) {
      deleteMutation.mutate({ id });
    }
  };

  const summaryStats = useMemo(() => {
    if (!stats) return { total: 0, critical: 0, high: 0, medium: 0 };
    return {
      total: stats.totalVulns,
      critical: stats.bySeverity.Critical || 0,
      high: stats.bySeverity.High || 0,
      medium: stats.bySeverity.Medium || 0,
    };
  }, [stats]);

  return (
    <div className="min-h-screen bg-slate-900 text-white p-4 sm:p-6 lg:p-8">
      <Card className="bg-slate-950/50 border-slate-800 mb-6">
        <CardHeader>
          <CardTitle className="flex items-center text-2xl">
            <HelpCircle className="h-6 w-6 mr-3 text-blue-400" />
            Vulnerability Scanner Import Hub
          </CardTitle>
          <CardDescription className="text-slate-400 pt-2">
            Import, view, and analyze vulnerability scan results from various scanners. This hub centralizes scan data, providing insights into your security posture through aggregated statistics and detailed vulnerability breakdowns.
          </CardDescription>
        </CardHeader>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-slate-300">Total Vulnerabilities</CardTitle>
            <AlertCircle className="h-4 w-4 text-slate-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{isLoadingStats ? <Loader2 className="h-6 w-6 animate-spin" /> : summaryStats.total}</div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-red-400">Critical</CardTitle>
            <AlertCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{isLoadingStats ? <Loader2 className="h-6 w-6 animate-spin" /> : summaryStats.critical}</div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-orange-400">High</CardTitle>
            <AlertCircle className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{isLoadingStats ? <Loader2 className="h-6 w-6 animate-spin" /> : summaryStats.high}</div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-yellow-400">Medium</CardTitle>
            <AlertCircle className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{isLoadingStats ? <Loader2 className="h-6 w-6 animate-spin" /> : summaryStats.medium}</div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-1 flex flex-col gap-6">
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle>Import Scan Results</CardTitle>
              <CardDescription>Upload a file from a supported scanner.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="scanner-type">Scanner Type</Label>
                <Select value={scannerType} onValueChange={setScannerType}>
                  <SelectTrigger id="scanner-type" className="bg-slate-800 border-slate-700">
                    <SelectValue placeholder="Select scanner" />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-700 text-white">
                    <SelectItem value="nessus">Nessus</SelectItem>
                    <SelectItem value="qualys">Qualys</SelectItem>
                    <SelectItem value="rapid7">Rapid7</SelectItem>
                    <SelectItem value="openvas">OpenVAS</SelectItem>
                    <SelectItem value="custom">Custom</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="file-upload">Scan File</Label>
                <div className="flex items-center space-x-2">
                    <Input id="file-upload" type="file" onChange={handleFileChange} className="bg-slate-800 border-slate-700 file:text-white" />
                </div>
                {file && <p className="text-sm text-slate-400">Selected: {file.name}</p>}
              </div>
            </CardContent>
            <CardFooter>
              <Button onClick={handleImport} disabled={importMutation.isLoading || !file} className="w-full bg-blue-600 hover:bg-blue-700">
                {importMutation.isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <UploadCloud className="mr-2 h-4 w-4" />}
                Import Scan
              </Button>
            </CardFooter>
          </Card>
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle>Vulnerability Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoadingStats ? (
                <div className="flex justify-center items-center h-64"><Loader2 className="h-8 w-8 animate-spin text-slate-500" /></div>
              ) : stats ? (
                <Chart data={stats.bySeverity} type="Severity Breakdown" />
              ) : (
                <div className="text-center text-slate-500 py-10">No stats available.</div>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="lg:col-span-2">
          <Card className="bg-slate-900 border-slate-800 h-full">
            <Tabs defaultValue="history" className="h-full flex flex-col">
              <CardHeader className="flex-row items-center justify-between">
                <TabsList className="bg-slate-800">
                  <TabsTrigger value="history">Scan History</TabsTrigger>
                  <TabsTrigger value="details" disabled={!selectedScanId}>Vulnerability Details</TabsTrigger>
                </TabsList>
                {selectedScanId && (
                    <Button variant="destructive" size="sm" onClick={() => handleDelete(selectedScanId)} disabled={deleteMutation.isLoading}>
                        {deleteMutation.isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                    </Button>
                )}
              </CardHeader>
              <TabsContent value="history" className="flex-grow">
                <CardContent>
                  {isLoadingScans ? (
                    <div className="flex justify-center items-center h-96"><Loader2 className="h-8 w-8 animate-spin text-slate-500" /></div>
                  ) : scans && scans.length > 0 ? (
                    <Table>
                      <TableHeader>
                        <TableRow className="border-slate-800 hover:bg-slate-800/50">
                          <TableHead>File Name</TableHead>
                          <TableHead>Scanner</TableHead>
                          <TableHead>Date</TableHead>
                          <TableHead>Vulns</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {scans.map((scan) => (
                          <TableRow key={scan.id} onClick={() => setSelectedScanId(scan.id)} className={`cursor-pointer border-slate-800 hover:bg-slate-800/50 ${selectedScanId === scan.id ? 'bg-slate-800' : ''}`}>
                            <TableCell className="font-medium">{scan.fileName}</TableCell>
                            <TableCell><Badge variant="outline" className="border-slate-600 text-slate-300">{scan.scannerType}</Badge></TableCell>
                            <TableCell>{new Date(scan.createdAt).toLocaleDateString()}</TableCell>
                            <TableCell>{scan.vulnCount}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  ) : (
                    <div className="text-center text-slate-500 py-20">
                      <FileText className="mx-auto h-12 w-12" />
                      <h3 className="mt-4 text-lg font-semibold">No Scans Found</h3>
                      <p className="mt-1 text-sm">Import your first scan to see it here.</p>
                    </div>
                  )}
                </CardContent>
              </TabsContent>
              <TabsContent value="details" className="flex-grow overflow-y-auto">
                <CardContent>
                  {isLoadingDetails ? (
                    <div className="flex justify-center items-center h-96"><Loader2 className="h-8 w-8 animate-spin text-slate-500" /></div>
                  ) : scanDetails ? (
                    <div className="space-y-4">
                      <h3 className="text-xl font-bold">{scanDetails.fileName}</h3>
                      <div className="flex space-x-4 text-sm text-slate-400">
                        <span>Scanner: <Badge variant="secondary">{scanDetails.scannerType}</Badge></span>
                        <span>Date: {new Date(scanDetails.createdAt).toLocaleString()}</span>
                      </div>
                      <div className="flex items-center space-x-4 pt-2">
                        {Object.entries(scanDetails.severityCounts).map(([severity, count]) => (
                          <div key={severity} className="flex items-center text-sm">
                            <span className={`w-3 h-3 rounded-full mr-2 ${severityColors[severity as keyof typeof severityColors]}`}></span>
                            <span>{severity}: {count}</span>
                          </div>
                        ))}
                      </div>
                      <Table>
                        <TableHeader>
                          <TableRow className="border-slate-800 hover:bg-slate-800/50">
                            <TableHead>Severity</TableHead>
                            <TableHead>Vulnerability</TableHead>
                            <TableHead>CVSS</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {scanDetails.vulnerabilities.map((vuln) => (
                            <TableRow key={vuln.id} className="border-slate-800 hover:bg-slate-800/50">
                              <TableCell><Badge className={`${severityColors[vuln.severity as keyof typeof severityColors]}`}>{vuln.severity}</Badge></TableCell>
                              <TableCell className="font-medium">{vuln.name}</TableCell>
                              <TableCell>{vuln.cvssScore}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  ) : (
                    <div className="text-center text-slate-500 py-20">
                      <h3 className="mt-4 text-lg font-semibold">Select a scan to view details</h3>
                    </div>
                  )}
                </CardContent>
              </TabsContent>
            </Tabs>
          </Card>
        </div>
      </div>
    </div>
  );
}
