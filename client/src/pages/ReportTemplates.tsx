import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { useState } from "react";
import AppShell from "@/components/AppShell";
type ReportTemplate = any;

const ReportTemplatesPage = () => {
  const [selectedTemplate, setSelectedTemplate] = useState<ReportTemplate | null>(null);
  const [isPreviewOpen, setPreviewOpen] = useState(false);
  const [isFormOpen, setFormOpen] = useState(false);

  const utils = trpc.useUtils();

  const { data: templates, isLoading, isError, error } = trpc.reportTemplates.list.useQuery({} as any);

  const createTemplate = trpc.reportTemplates.create.useMutation({
    onSuccess: () => {
      utils.reportTemplates.list.invalidate();
      toast.success("Template created successfully");
      setFormOpen(false);
    },
    onError: (err) => {
      toast.error(`Failed to create template: ${err.message}`);
    },
  });

  const updateTemplate = trpc.reportTemplates.update.useMutation({
    onSuccess: () => {
      utils.reportTemplates.list.invalidate();
      toast.success("Template updated successfully");
      setFormOpen(false);
    },
    onError: (err) => {
      toast.error(`Failed to update template: ${err.message}`);
    },
  });

  const deleteTemplate = trpc.reportTemplates.delete.useMutation({
    onSuccess: () => {
      utils.reportTemplates.list.invalidate();
      toast.success("Template deleted successfully");
    },
    onError: (err) => {
      toast.error(`Failed to delete template: ${err.message}`);
    },
  });

  const { mutate: renderPreview, isPending: isPreviewRendering, data: previewData } = trpc.reportTemplates.renderPreview.useMutation();

  const handleFormSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const data = Object.fromEntries(formData.entries()) as any;

    if (selectedTemplate) {
      updateTemplate.mutate({ id: selectedTemplate.id, ...data });
    } else {
      createTemplate.mutate(data);
    }
  };

  const handlePreview = (template: ReportTemplate) => {
    setSelectedTemplate(template);
    renderPreview({ id: template.id, sampleData: {} });
    setPreviewOpen(true);
  };

  if (isLoading) {
    return <div>Loading templates...</div>;
  }

  if (isError) {
    return <div>Error: {error.message}</div>;
  }

  return (
    <AppShell activePath="/report-templates">
      <div className="p-4 bg-background text-foreground">
      <Card>
        <CardHeader>
          <CardTitle>Report Templates</CardTitle>
          <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Manage and customize report templates for different engagement types and deliverables. Create templates for penetration test reports, vulnerability assessments, red team summaries, and executive briefings. Each template defines the structure, sections, branding, and data fields that will be auto-populated from your engagement findings.</p>
          <Dialog open={isFormOpen} onOpenChange={setFormOpen}>
            <DialogTrigger asChild>
              <Button onClick={() => setSelectedTemplate(null)}>Create Template</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>{selectedTemplate ? "Edit" : "Create"} Template</DialogTitle>
              </DialogHeader>
              <form onSubmit={handleFormSubmit} className="space-y-4">
                <Input name="name" placeholder="Template Name" defaultValue={selectedTemplate?.name} required />
                <Input name="description" placeholder="Description" defaultValue={selectedTemplate?.description ?? ""} />
                <Select name="templateType" defaultValue={selectedTemplate?.templateType ?? "custom"} required>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="executive">Executive</SelectItem>
                    <SelectItem value="technical">Technical</SelectItem>
                    <SelectItem value="compliance">Compliance</SelectItem>
                    <SelectItem value="custom">Custom</SelectItem>
                  </SelectContent>
                </Select>
                <textarea name="templateContent" placeholder="Jinja2 Template Content" className="w-full p-2 border rounded bg-background" rows={10} defaultValue={selectedTemplate?.templateContent} required />
                <Button type="submit" disabled={createTemplate.isPending || updateTemplate.isPending}>
                  {createTemplate.isPending || updateTemplate.isPending ? "Saving..." : "Save"}
                </Button>
              </form>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          {(templates ?? []).length === 0 ? (
            <div className="text-center py-8">No templates found.</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Default</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(templates ?? []).map((template) => (
                  <TableRow key={template.id}>
                    <TableCell>{template.name}</TableCell>
                    <TableCell><Badge>{template.templateType}</Badge></TableCell>
                    <TableCell>{template.isDefault ? <Badge variant="secondary">Default</Badge> : null}</TableCell>
                    <TableCell className="space-x-2">
                      <Button variant="outline" size="sm" onClick={() => handlePreview(template)}>Preview</Button>
                      <Button variant="outline" size="sm" onClick={() => { setSelectedTemplate(template); setFormOpen(true); }}>Edit</Button>
                      <Button variant="destructive" size="sm" onClick={() => deleteTemplate.mutate({ id: template.id })}>Delete</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={isPreviewOpen} onOpenChange={setPreviewOpen}>
        <DialogContent className="max-w-4xl h-[80vh] flex flex-col">
          <DialogHeader>
            <DialogTitle>Preview: {selectedTemplate?.name}</DialogTitle>
          </DialogHeader>
          <div className="flex-grow border rounded overflow-auto">
            {isPreviewRendering ? (
              <div className="flex items-center justify-center h-full">Loading preview...</div>
            ) : previewData ? (
              <iframe srcDoc={previewData.html} className="w-full h-full" />
            ) : (
              <div className="flex items-center justify-center h-full">Could not load preview.</div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
    </AppShell>
  );
};

export default ReportTemplatesPage;
