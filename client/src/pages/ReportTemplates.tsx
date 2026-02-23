import { useState, useMemo } from 'react';
import { trpc } from '@/lib/trpc';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { toast } from 'sonner';
import { FilePlus2, Edit, Trash2, Copy, Eye, Loader2, AlertCircle, BarChart, FileText, ShieldCheck } from 'lucide-react';

// Mock for syntax highlighting editor, replace with a real one like CodeMirror or Monaco
const CodeEditor = ({ value, onChange }) => (
  <textarea
    value={value}
    onChange={(e) => onChange(e.target.value)}
    className="w-full h-96 bg-zinc-900 border border-zinc-700 rounded-md p-4 font-mono text-sm text-white focus:outline-none focus:ring-2 focus:ring-slate-500"
  />
);

const ReportTemplates = () => {
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [previewContent, setPreviewContent] = useState('');
  const [isPreviewLoading, setIsPreviewLoading] = useState(false);

  const utils = trpc.useUtils();
  const { data: templates, isLoading, isError } = trpc.reportTemplates.list.useQuery();

  const createMutation = trpc.reportTemplates.create.useMutation({
    onSuccess: () => {
      utils.reportTemplates.list.invalidate();
      toast.success('Template created successfully!');
      setIsDialogOpen(false);
    },
    onError: (error) => toast.error(`Failed to create template: ${error.message}`),
  });

  const updateMutation = trpc.reportTemplates.update.useMutation({
    onSuccess: () => {
      utils.reportTemplates.list.invalidate();
      toast.success('Template updated successfully!');
      setIsDialogOpen(false);
      setSelectedTemplate(null);
    },
    onError: (error) => toast.error(`Failed to update template: ${error.message}`),
  });

  const deleteMutation = trpc.reportTemplates.delete.useMutation({
    onSuccess: () => {
      utils.reportTemplates.list.invalidate();
      toast.success('Template deleted successfully!');
    },
    onError: (error) => toast.error(`Failed to delete template: ${error.message}`),
  });

  const duplicateMutation = trpc.reportTemplates.duplicate.useMutation({
    onSuccess: () => {
      utils.reportTemplates.list.invalidate();
      toast.success('Template duplicated successfully!');
    },
    onError: (error) => toast.error(`Failed to duplicate template: ${error.message}`),
  });

  const previewMutation = trpc.reportTemplates.renderPreview.useMutation({
    onSuccess: (data) => {
      setPreviewContent(data.html);
      setIsPreviewLoading(false);
    },
    onError: (error) => {
      toast.error(`Failed to render preview: ${error.message}`);
      setPreviewContent('<p class="text-red-400">Error rendering preview.</p>');
      setIsPreviewLoading(false);
    },
  });

  const handleFormSubmit = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());
    const submissionData = {
        ...data,
        variables: data.variables ? JSON.parse(data.variables) : undefined,
    };

    if (selectedTemplate) {
      updateMutation.mutate({ id: selectedTemplate.id, ...submissionData });
    } else {
      createMutation.mutate(submissionData);
    }
  };

  const handleGeneratePreview = (templateId) => {
    setIsPreviewLoading(true);
    // Using dummy data for preview. In a real app, you might have a form to collect this.
    const sampleData = { user: { name: 'John Doe' }, findings: [{ title: 'Critical Vulnerability Found' }] };
    previewMutation.mutate({ id: templateId, sampleData });
  };

  const summaryStats = useMemo(() => {
    if (!templates) return { total: 0, executive: 0, technical: 0, compliance: 0 };
    return {
      total: templates.length,
      executive: templates.filter(t => t.category === 'executive').length,
      technical: templates.filter(t => t.category === 'technical').length,
      compliance: templates.filter(t => t.category === 'compliance').length,
    };
  }, [templates]);

  return (
    <div className="p-8 bg-zinc-900 text-white min-h-screen">
      <Card className="mb-8 bg-zinc-800 border-zinc-700">
        <CardHeader>
          <CardTitle>Report Templates</CardTitle>
          <CardDescription className="text-zinc-400">
            Create, edit, and manage customizable report templates for executive summaries, technical reports, and compliance documents. This engine supports Jinja2, Markdown, and HTML formats for flexible report generation.
          </CardDescription>
        </CardHeader>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-8">
        <Card className="bg-zinc-800 border-zinc-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Templates</CardTitle>
            <FileText className="h-4 w-4 text-zinc-400" />
          </CardHeader>
          <CardContent><div className="text-2xl font-bold">{summaryStats.total}</div></CardContent>
        </Card>
        <Card className="bg-zinc-800 border-zinc-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Executive</CardTitle>
            <BarChart className="h-4 w-4 text-zinc-400" />
          </CardHeader>
          <CardContent><div className="text-2xl font-bold">{summaryStats.executive}</div></CardContent>
        </Card>
        <Card className="bg-zinc-800 border-zinc-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Technical</CardTitle>
            <FileText className="h-4 w-4 text-zinc-400" />
          </CardHeader>
          <CardContent><div className="text-2xl font-bold">{summaryStats.technical}</div></CardContent>
        </Card>
        <Card className="bg-zinc-800 border-zinc-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Compliance</CardTitle>
            <ShieldCheck className="h-4 w-4 text-zinc-400" />
          </CardHeader>
          <CardContent><div className="text-2xl font-bold">{summaryStats.compliance}</div></CardContent>
        </Card>
      </div>

      <div className="flex justify-end mb-4">
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={() => setSelectedTemplate(null)}><FilePlus2 className="mr-2 h-4 w-4" /> Create Template</Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[800px] bg-zinc-900 border-zinc-700 text-white">
            <form onSubmit={handleFormSubmit}>
              <DialogHeader>
                <DialogTitle>{selectedTemplate ? 'Edit' : 'Create'} Template</DialogTitle>
                <DialogDescription>Fill in the details for your new report template.</DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="name" className="text-right">Name</Label>
                  <Input id="name" name="name" defaultValue={selectedTemplate?.name} className="col-span-3 bg-zinc-800 border-zinc-600" />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="format" className="text-right">Format</Label>
                  <Select name="format" defaultValue={selectedTemplate?.format}>
                    <SelectTrigger className="col-span-3 bg-zinc-800 border-zinc-600">
                      <SelectValue placeholder="Select a format" />
                    </SelectTrigger>
                    <SelectContent className="bg-zinc-800 text-white border-zinc-700">
                      <SelectItem value="jinja2">Jinja2</SelectItem>
                      <SelectItem value="markdown">Markdown</SelectItem>
                      <SelectItem value="html">HTML</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="category" className="text-right">Category</Label>
                  <Select name="category" defaultValue={selectedTemplate?.category}>
                    <SelectTrigger className="col-span-3 bg-zinc-800 border-zinc-600">
                      <SelectValue placeholder="Select a category" />
                    </SelectTrigger>
                    <SelectContent className="bg-zinc-800 text-white border-zinc-700">
                      <SelectItem value="executive">Executive</SelectItem>
                      <SelectItem value="technical">Technical</SelectItem>
                      <SelectItem value="compliance">Compliance</SelectItem>
                      <SelectItem value="custom">Custom</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid grid-cols-4 items-start gap-4">
                  <Label htmlFor="templateContent" className="text-right pt-2">Template Content</Label>
                  <div className="col-span-3">
                    <CodeEditor 
                        name="templateContent"
                        value={selectedTemplate?.templateContent || ''}
                        onChange={(value) => {
                            // This is a workaround for the mock editor
                            // In a real app, the editor component would handle its state.
                            setSelectedTemplate(prev => ({...(prev || {}), templateContent: value}))
                        }}
                    />
                    <input type="hidden" name="templateContent" value={selectedTemplate?.templateContent || ''} />
                  </div>
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createMutation.isLoading || updateMutation.isLoading}>
                  {(createMutation.isLoading || updateMutation.isLoading) && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Save
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Card className="bg-zinc-800 border-zinc-700">
        <CardHeader>
          <CardTitle>Template Library</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading && <div className="flex justify-center items-center p-8"><Loader2 className="h-8 w-8 animate-spin text-slate-400" /></div>}
          {isError && <div className="flex flex-col items-center p-8 text-red-400"><AlertCircle className="h-8 w-8 mb-2" /><span>Error loading templates.</span></div>}
          {!isLoading && !isError && templates && templates.length === 0 && (
            <div className="text-center p-8 text-zinc-400">No templates found. Get started by creating one!</div>
          )}
          {!isLoading && !isError && templates && templates.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-700">
                  <TableHead>Name</TableHead>
                  <TableHead>Format</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {templates.map((template) => (
                  <TableRow key={template.id} className="border-zinc-700">
                    <TableCell className="font-medium">{template.name}</TableCell>
                    <TableCell><Badge variant="outline" className="border-slate-500 text-slate-300">{template.format}</Badge></TableCell>
                    <TableCell><Badge variant="secondary" className="bg-slate-700 text-slate-200 hover:bg-slate-600">{template.category}</Badge></TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" onClick={() => handleGeneratePreview(template.id)}><Eye className="h-4 w-4" /></Button>
                      <Button variant="ghost" size="icon" onClick={() => { setSelectedTemplate(template); setIsDialogOpen(true); }}><Edit className="h-4 w-4" /></Button>
                      <Button variant="ghost" size="icon" onClick={() => duplicateMutation.mutate({ id: template.id })}><Copy className="h-4 w-4" /></Button>
                      <Button variant="ghost" size="icon" className="text-red-500 hover:text-red-400" onClick={() => deleteMutation.mutate({ id: template.id })}><Trash2 className="h-4 w-4" /></Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {previewContent && (
          <Card className="mt-8 bg-zinc-800 border-zinc-700">
              <CardHeader>
                  <CardTitle>Template Preview</CardTitle>
              </CardHeader>
              <CardContent>
                  {isPreviewLoading ? (
                      <div className="flex justify-center items-center p-8"><Loader2 className="h-8 w-8 animate-spin text-slate-400" /></div>
                  ) : (
                      <div className="prose prose-invert max-w-none p-4 bg-zinc-900 rounded-md" dangerouslySetInnerHTML={{ __html: previewContent }} />
                  )}
              </CardContent>
          </Card>
      )}
    </div>
  );
};

export default ReportTemplates;
