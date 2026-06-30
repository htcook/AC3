import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import {
  FileText, Search, RefreshCw, CheckCircle2, XCircle,
  AlertTriangle, Shield, ClipboardCheck, BarChart3, Plus
} from "lucide-react";

const FRAMEWORK_LABELS: Record<string, string> = {
  soc2: "SOC 2",
  iso27001: "ISO 27001",
  nist_csf: "NIST CSF",
  pci_dss: "PCI DSS",
  fedramp: "FedRAMP",
  dod_stig: "DoD STIG",
  cmmc: "CMMC 2.0",
};

const FRAMEWORK_COLORS: Record<string, string> = {
  soc2: "text-blue-400 border-blue-500/30",
  iso27001: "text-green-400 border-green-500/30",
  nist_csf: "text-purple-400 border-purple-500/30",
  pci_dss: "text-orange-400 border-orange-500/30",
  fedramp: "text-cyan-400 border-cyan-500/30",
  dod_stig: "text-red-400 border-red-500/30",
  cmmc: "text-yellow-400 border-yellow-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  covered: "bg-green-500/20 text-green-400",
  partial: "bg-yellow-500/20 text-yellow-400",
  gap: "bg-red-500/20 text-red-400",
  not_applicable: "bg-slate-500/20 text-slate-400",
  compensating: "bg-blue-500/20 text-blue-400",
};

export default function ComplianceMapper() {
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedFramework, setSelectedFramework] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");

  // Use the built-in framework catalog (static data from server lib)
  const frameworkCatalog = trpc.complianceMapper.getFrameworkCatalog.useQuery();
  // Use DB-stored frameworks
  const dbFrameworks = trpc.complianceMapper.listFrameworks.useQuery({});
  // Mappings from DB
  const mappings = trpc.complianceMapper.listMappings.useQuery({});
  // Stats
  const stats = trpc.complianceMapper.getStats.useQuery();

  // Load controls for selected framework
  const selectedFwControls = trpc.complianceMapper.getFrameworkControls.useQuery(
    { frameworkKey: selectedFramework },
    { enabled: selectedFramework !== "all" }
  );

  const createMappingMut = trpc.complianceMapper.createMapping.useMutation({
    onSuccess: () => {
      toast.success("Control mapping created.");
      mappings.refetch();
    },
    onError: (err: { message: string }) => toast.error(err.message),
  });

  const filteredCatalog = useMemo(() => {
    if (!frameworkCatalog.data) return [] as NonNullable<typeof frameworkCatalog.data>;
    let items = [...frameworkCatalog.data];
    if (selectedFramework !== "all") {
      items = items.filter((f) => f.key === selectedFramework);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      items = items.filter((f) => (f.name || '').toLowerCase().includes(q) || f.key.toLowerCase().includes(q));
    }
    return items;
  }, [frameworkCatalog.data, selectedFramework, searchQuery]);

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <ClipboardCheck className="h-7 w-7 text-blue-400" />
              Compliance Framework Mapping
            </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Map your security findings and controls to compliance frameworks like NIST 800-53, ISO 27001, PCI DSS, HIPAA, and CMMC. This tool automatically correlates discovered vulnerabilities with specific compliance requirements to show which controls are satisfied and which have gaps. Use it to generate compliance-ready evidence and identify which findings have regulatory implications.</p>
            <p className="text-muted-foreground mt-1">
              SOC 2, ISO 27001, NIST CSF, PCI DSS, FedRAMP, DoD STIG, and CMMC 2.0 control mapping
            </p>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Built-in Frameworks</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.builtInFrameworks ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Built-in Controls</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalBuiltInControls ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">DB Frameworks</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalFrameworks ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Mappings</p>
              <p className="text-2xl font-bold text-green-400">{stats.data?.totalMappings ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Reports</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalReports ?? 0}</p>
            </CardContent>
          </Card>
        </div>

        {/* Filters */}
        <div className="flex gap-3 items-center">
          <Select value={selectedFramework} onValueChange={setSelectedFramework}>
            <SelectTrigger className="w-48"><SelectValue placeholder="Framework" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Frameworks</SelectItem>
              {Object.entries(FRAMEWORK_LABELS).map(([k, v]) => (
                <SelectItem key={k} value={k}>{v}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search controls..." className="pl-9" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
          </div>
          <Button variant="outline" size="sm" onClick={() => { frameworkCatalog.refetch(); mappings.refetch(); }}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="overview">Framework Overview</TabsTrigger>
            <TabsTrigger value="controls">Control Details</TabsTrigger>
            <TabsTrigger value="mappings">Mappings ({mappings.data?.length ?? 0})</TabsTrigger>
            <TabsTrigger value="gaps">Gap Analysis</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredCatalog.map((fw) => (
                <Card key={fw.key} className="bg-card/50 border-border/50 hover:border-blue-500/30 transition-colors">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-lg">{fw.name}</CardTitle>
                      <Badge variant="outline" className={FRAMEWORK_COLORS[fw.key] ?? "text-foreground"}>
                        {fw.controlCount} controls
                      </Badge>
                    </div>
                    <CardDescription>v{fw.version}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Controls</span>
                        <span className="font-mono text-foreground">{fw.controlCount}</span>
                      </div>
                      <Button variant="outline" size="sm" className="w-full mt-2" onClick={() => {
                        setSelectedFramework(fw.key);
                        setActiveTab("controls");
                      }}>
                        View Controls
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          <TabsContent value="controls" className="space-y-3">
            {selectedFramework === "all" ? (
              <div className="text-center py-12 text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p>Select a framework to view its controls</p>
              </div>
            ) : selectedFwControls.isLoading ? (
              <div className="text-center py-12 text-muted-foreground">Loading controls...</div>
            ) : selectedFwControls.data ? (
              <div className="space-y-3">
                <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  {selectedFwControls.data.name} (v{selectedFwControls.data.version})
                </h3>
                {selectedFwControls.data.controls
                  .filter((c) => {
                    if (!searchQuery) return true;
                    const q = searchQuery.toLowerCase();
                    return (c.controlId || '').toLowerCase().includes(q) || c.controlName.toLowerCase().includes(q) || c.description.toLowerCase().includes(q);
                  })
                  .map((control) => (
                    <Card key={control.controlId} className="bg-card/50 border-border/50">
                      <CardContent className="py-3">
                        <div className="flex items-start justify-between">
                          <div className="space-y-1 flex-1">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className="font-mono text-xs">{control.controlId}</Badge>
                              <h4 className="font-medium text-foreground text-sm">{control.controlName}</h4>
                            </div>
                            <p className="text-xs text-muted-foreground">{control.description}</p>
                            {control.category && (
                              <Badge variant="secondary" className="text-xs">{control.category}</Badge>
                            )}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
              </div>
            ) : null}
          </TabsContent>

          <TabsContent value="mappings" className="space-y-3">
            {mappings.data?.map((mapping) => (
              <Card key={mapping.id} className="bg-card/50 border-border/50">
                <CardContent className="py-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {mapping.mappingStatus === "covered" ? (
                        <CheckCircle2 className="h-4 w-4 text-green-400" />
                      ) : mapping.mappingStatus === "gap" ? (
                        <XCircle className="h-4 w-4 text-red-400" />
                      ) : (
                        <AlertTriangle className="h-4 w-4 text-yellow-400" />
                      )}
                      <Badge variant="outline" className="font-mono text-xs">Control #{mapping.controlId}</Badge>
                      <span className="text-sm text-foreground">{mapping.findingSource}</span>
                    </div>
                    <Badge variant="outline" className={STATUS_COLORS[mapping.mappingStatus]}>
                      {mapping.mappingStatus.replace(/_/g, " ")}
                    </Badge>
                  </div>
                  {mapping.evidenceNotes && (
                    <p className="text-xs text-muted-foreground mt-2">{mapping.evidenceNotes}</p>
                  )}
                </CardContent>
              </Card>
            ))}
            {(!mappings.data || mappings.data.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <FileText className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p>No control mappings created yet</p>
                <p className="text-sm mt-1">Use the Auto-Map feature or create mappings manually</p>
              </div>
            )}
          </TabsContent>

          <TabsContent value="gaps" className="space-y-4">
            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <CardTitle>Gap Analysis by Framework</CardTitle>
                <CardDescription>Built-in framework coverage overview</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {filteredCatalog.map((fw) => {
                    return (
                      <div key={fw.key} className="p-4 rounded-lg border border-border/50 bg-background/50">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={FRAMEWORK_COLORS[fw.key]}>{fw.name}</Badge>
                            <span className="text-sm text-muted-foreground">{fw.controlCount} controls</span>
                          </div>
                          <span className="text-sm text-muted-foreground">v{fw.version}</span>
                        </div>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-muted-foreground">Total Controls</span>
                            <span className="font-mono text-foreground ml-2">{fw.controlCount}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Status</span>
                            <Badge variant="outline" className="ml-2 text-yellow-400 border-yellow-500/30">Needs Assessment</Badge>
                          </div>
                        </div>
                        <Button variant="outline" size="sm" className="mt-3 w-full" onClick={() => {
                          setSelectedFramework(fw.key);
                          setActiveTab("controls");
                        }}>
                          <BarChart3 className="h-3 w-3 mr-1" /> View Controls & Begin Assessment
                        </Button>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
