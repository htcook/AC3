"use client";

import { useState } from "react";
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
import { Upload, File, Trash2, AlertCircle, Loader2, BarChart, List, ShieldAlert } from "lucide-react";

type ScannerType = 'nessus' | 'qualys' | 'rapid7' | 'openvas' | 'custom';

const StatCard = ({ title, value, icon: Icon }: { title: string; value: string | number; icon: React.ElementType }) => (
  <Card>
    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
      <CardTitle className="text-sm font-medium">{title}</CardTitle>
      <Icon className="h-4 w-4 text-muted-foreground" />
    </CardHeader>
    <CardContent>
      <div className="text-2xl font-bold">{value}</div>
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

const ImportScanDialog = ({ onImportSuccess }: { onImportSuccess: () => void }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [scannerType, setScannerType] = useState<ScannerType | null>(null);
  const [file, setFile] = useState<File | null>(null);

  const importMutation = trpc.vulnScanner.importScan.useMutation({
    onSuccess: (data) => {
      toast.success(`Successfully imported scan: ${data.totalVulns} vulnerabilities found across ${data.totalHosts} hosts.`);
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
            <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Importing...</>
          ) : (
            "Import"
          )}
        </Button>
      </DialogContent>
    </Dialog>
  );
};

export default function VulnScannerPage() {
  const utils = trpc.useUtils();
  const [selectedImportId, setSelectedImportId] = useState<number | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const statsQuery = trpc.vulnScanner.getStats.useQuery();
  const importsQuery = trpc.vulnScanner.listImports.useQuery();
  // getFindings not available - findings are embedded in import data
  const findingsQuery = { data: null as any, isLoading: false, isError: false, error: null as any };

  const deleteMutation = trpc.vulnScanner.deleteImport.useMutation({
    onSuccess: () => {
      toast.success("Import deleted successfully.");
      utils.vulnScanner.listImports.invalidate();
      utils.vulnScanner.getStats.invalidate();
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
  };

  return (
    <div className="min-h-screen bg-background text-foreground p-4 md:p-8">
      <header className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold">Vulnerability Scanner</h1>
        <ImportScanDialog onImportSuccess={handleImportSuccess} />
      </header>

      <section className="mb-8">
        <h2 className="text-xl font-semibold mb-4 flex items-center"><BarChart className="mr-2 h-5 w-5" />Overall Statistics</h2>
        {statsQuery.isLoading ? (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {[...Array(4)].map((_, i) => <Card key={i} className="h-[105px] animate-pulse bg-muted"/>)}
          </div>
        ) : statsQuery.isError ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>Could not load statistics: {statsQuery.error.message}</AlertDescription>
          </Alert>
        ) : statsQuery.data && (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <StatCard title="Total Imports" value={statsQuery.data.totalImports} icon={File} />
            <StatCard title="Total Vulnerabilities" value={statsQuery.data.totalVulns} icon={ShieldAlert} />
            <StatCard title="Total Hosts" value={statsQuery.data.totalHosts} icon={List} />
            <div className="grid grid-cols-2 gap-2 md:col-span-2 lg:col-span-1 lg:grid-cols-4 rounded-lg border bg-card text-card-foreground shadow-sm p-4 items-center">
                <div className="text-center"><SeverityBadge severity="Critical" /><p className="font-bold text-lg">{statsQuery.data.critical}</p></div>
                <div className="text-center"><SeverityBadge severity="High" /><p className="font-bold text-lg">{statsQuery.data.high}</p></div>
                <div className="text-center"><SeverityBadge severity="Medium" /><p className="font-bold text-lg">{statsQuery.data.medium}</p></div>
                <div className="text-center"><SeverityBadge severity="Low" /><p className="font-bold text-lg">{statsQuery.data.low}</p></div>
            </div>
          </div>
        )}
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <Card>
          <CardHeader>
            <CardTitle>Import History</CardTitle>
            <CardDescription>List of all imported vulnerability scans.</CardDescription>
          </CardHeader>
          <CardContent>
            {importsQuery.isLoading ? (
              <div className="flex items-center justify-center p-8">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : importsQuery.isError ? (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>Could not load import history: {importsQuery.error.message}</AlertDescription>
              </Alert>
            ) : (importsQuery.data?.length ?? 0) === 0 ? (
              <div className="text-center py-10">
                <p className="text-muted-foreground">No scans have been imported yet.</p>
                <p className="text-sm text-muted-foreground">Click "Import Scan" to get started.</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>File Name</TableHead>
                    <TableHead>Scanner</TableHead>
                    <TableHead>Vulns</TableHead>
                    <TableHead>Imported At</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {importsQuery.data?.map((imp) => (
                    <TableRow
                      key={imp.id}
                      onClick={() => setSelectedImportId(imp.id)}
                      className={`cursor-pointer ${selectedImportId === imp.id ? 'bg-muted/50' : 'hover:bg-muted/20'}`}
                    >
                      <TableCell className="font-medium">{imp.fileName}</TableCell>
                      <TableCell>{imp.scannerType}</TableCell>
                      <TableCell>{imp.totalVulns}</TableCell>
                      <TableCell>{new Date(imp.importedAt).toLocaleDateString()}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={(e) => { e.stopPropagation(); deleteMutation.mutate({ id: imp.id }); }}
                          disabled={deleteMutation.isPending && deleteMutation.variables?.id === imp.id}
                        >
                          {deleteMutation.isPending && deleteMutation.variables?.id === imp.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4 text-red-500" />}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Vulnerability Findings</CardTitle>
            <CardDescription>Findings from the selected scan import.</CardDescription>
          </CardHeader>
          <CardContent>
            {!selectedImportId ? (
              <div className="flex items-center justify-center h-full min-h-[300px] text-muted-foreground">
                <p>Select an import from the list to view its findings.</p>
              </div>
            ) : findingsQuery.isLoading ? (
              <div className="flex items-center justify-center h-full min-h-[300px]">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : findingsQuery.isError ? (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>Could not load findings: {findingsQuery.error.message}</AlertDescription>
              </Alert>
            ) : findingsQuery.data.length === 0 ? (
              <div className="flex items-center justify-center h-full min-h-[300px] text-muted-foreground">
                <p>No findings for this import or filter.</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Severity</TableHead>
                    <TableHead>Plugin ID</TableHead>
                    <TableHead>Vulnerability</TableHead>
                    <TableHead>Host</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findingsQuery.data.map((finding: any) => (
                    <TableRow key={finding.id}>
                      <TableCell><SeverityBadge severity={finding.severity} /></TableCell>
                      <TableCell>{finding.pluginId}</TableCell>
                      <TableCell className="font-medium">{finding.name}</TableCell>
                      <TableCell>{finding.host}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
