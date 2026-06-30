import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { useState } from "react";
import { useLocation } from "wouter";
import { Plus, Eye, Pencil, Copy, Trash2, FileText, Shield, Target, Globe, Loader2 } from "lucide-react";
import AppShell from "@/components/AppShell";

const TYPE_ICONS: Record<string, React.ReactNode> = {
  engagement: <Target className="w-3.5 h-3.5" />,
  executive: <FileText className="w-3.5 h-3.5" />,
  compliance: <Shield className="w-3.5 h-3.5" />,
  vulnerability: <Globe className="w-3.5 h-3.5" />,
  custom: <FileText className="w-3.5 h-3.5" />,
};

const TYPE_COLORS: Record<string, string> = {
  engagement: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  executive: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  compliance: "bg-green-500/10 text-green-400 border-green-500/20",
  vulnerability: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  custom: "bg-gray-500/10 text-gray-400 border-gray-500/20",
};

const ReportTemplatesPage = () => {
  const [, setLocation] = useLocation();
  const [previewTemplate, setPreviewTemplate] = useState<any>(null);
  const [isPreviewOpen, setPreviewOpen] = useState(false);

  const utils = trpc.useUtils();
  const { data: templates, isLoading } = trpc.reportTemplates.list.useQuery({} as any);

  const deleteTemplate = trpc.reportTemplates.delete.useMutation({
    onSuccess: () => {
      utils.reportTemplates.list.invalidate();
      toast.success("Template deleted");
    },
    onError: (err) => toast.error(`Failed to delete: ${err.message}`),
  });

  const duplicateTemplate = trpc.reportTemplates.duplicate.useMutation({
    onSuccess: () => {
      utils.reportTemplates.list.invalidate();
      toast.success("Template duplicated");
    },
    onError: (err) => toast.error(`Failed to duplicate: ${err.message}`),
  });

  const { mutate: renderPreview, isPending: isPreviewRendering, data: previewData } = trpc.reportTemplates.renderPreview.useMutation();

  const handlePreview = (template: any) => {
    setPreviewTemplate(template);
    renderPreview({ id: template.id, sampleData: {
      client_name: "AceofCloud Security",
      report_date: new Date().toLocaleDateString(),
      report_title: template.name,
      assessor_name: "Security Analyst",
      engagement_id: "AC3-2024-001",
      domain: "example.com",
      total_assets: "47",
      risk_score: "72",
      critical_findings: "3",
      high_findings: "7",
      medium_findings: "12",
      low_findings: "5",
      total_vulns: "27",
      cvss_avg: "6.8",
      cvss_max: "9.8",
      recon_coverage: "87%",
      executive_summary: "During the assessment, several critical vulnerabilities were identified.",
      methodology: "OWASP Testing Guide v4, PTES, NIST SP 800-115",
    }});
    setPreviewOpen(true);
  };

  if (isLoading) {
    return (
      <AppShell activePath="/report-templates">
        <div className="flex items-center justify-center h-64">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell activePath="/report-templates">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold">Report Templates</h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
              Manage and customize report templates for different engagement types. Each template defines the structure,
              sections, branding, and data fields that will be auto-populated from your engagement findings.
            </p>
          </div>
          <Button onClick={() => setLocation("/report-templates/new")}>
            <Plus className="w-4 h-4 mr-2" />
            New Template
          </Button>
        </div>

        {(templates ?? []).length === 0 ? (
          <Card className="bg-card/50 border-border/50">
            <CardContent className="flex flex-col items-center justify-center py-16">
              <FileText className="w-12 h-12 text-muted-foreground/50 mb-4" />
              <h3 className="text-lg font-medium mb-1">No Templates Yet</h3>
              <p className="text-sm text-muted-foreground mb-4">Create your first report template to get started.</p>
              <Button onClick={() => setLocation("/report-templates/new")}>
                <Plus className="w-4 h-4 mr-2" />
                Create Template
              </Button>
            </CardContent>
          </Card>
        ) : (
          <Card className="bg-card/50 border-border/50">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[300px]">Template</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last Modified</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(templates ?? []).map((template: any) => (
                    <TableRow key={template.id} className="group">
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-md border ${TYPE_COLORS[template.templateType] || TYPE_COLORS.custom}`}>
                            {TYPE_ICONS[template.templateType] || TYPE_ICONS.custom}
                          </div>
                          <div>
                            <div className="font-medium text-sm">{template.name}</div>
                            {template.description && (
                              <div className="text-xs text-muted-foreground truncate max-w-[250px]">
                                {template.description}
                              </div>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[10px] capitalize">
                          {template.templateType}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {template.isDefault ? (
                          <Badge className="bg-primary/10 text-primary border-primary/20 text-[10px]">Default</Badge>
                        ) : (
                          <Badge variant="outline" className="text-[10px]">Active</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {template.updatedAt ? new Date(template.updatedAt).toLocaleDateString() : "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1 opacity-60 group-hover:opacity-100 transition-opacity">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => handlePreview(template)}
                            title="Preview"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => setLocation(`/report-templates/${template.id}/edit`)}
                            title="Edit"
                          >
                            <Pencil className="w-3.5 h-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => duplicateTemplate.mutate({ id: template.id })}
                            title="Duplicate"
                          >
                            <Copy className="w-3.5 h-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7 text-destructive hover:text-destructive"
                            onClick={() => {
                              if (confirm("Delete this template?")) {
                                deleteTemplate.mutate({ id: template.id });
                              }
                            }}
                            title="Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}

        {/* Preview Dialog */}
        <Dialog open={isPreviewOpen} onOpenChange={setPreviewOpen}>
          <DialogContent className="max-w-5xl h-[85vh] flex flex-col">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Eye className="w-4 h-4" />
                Preview: {previewTemplate?.name}
              </DialogTitle>
            </DialogHeader>
            <div className="flex-grow border rounded-md overflow-hidden bg-white">
              {isPreviewRendering ? (
                <div className="flex items-center justify-center h-full">
                  <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                </div>
              ) : previewData ? (
                <iframe srcDoc={previewData.html} className="w-full h-full border-0" title="Report Preview" />
              ) : (
                <div className="flex items-center justify-center h-full text-muted-foreground">
                  Could not load preview.
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </AppShell>
  );
};

export default ReportTemplatesPage;
