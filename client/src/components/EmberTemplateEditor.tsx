import { useState, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Save, Copy, Trash2, Edit3, Plus, X, GripVertical,
  Loader2, Zap, AlertTriangle, BookTemplate, Star,
  ChevronDown, ChevronUp, Search, FolderOpen,
} from "lucide-react";

// ─── Types ──────────────────────────────────────────────────────────────────

interface TaskStep {
  taskType: string;
  params: Record<string, string>;
  priority: number;
  requiresElevation: boolean;
  delayMs?: number;
}

interface CustomTemplate {
  templateId: string;
  name: string;
  description: string | null;
  category: string;
  risk: string;
  estimatedDuration: string | null;
  tags: string[];
  steps: TaskStep[];
  clonedFrom: string | null;
  createdBy: string | null;
  isShared: number;
  usageCount: number;
  lastUsedAt: number | null;
  createdAt: number;
  updatedAt: number;
}

const TASK_TYPES = [
  "shell_exec", "recon", "file_ops", "exfil", "cred_dump",
  "lateral_move", "persist", "screenshot", "keylog", "privesc", "self_destruct",
];

const CATEGORIES = [
  { value: "recon", label: "Reconnaissance" },
  { value: "credential", label: "Credential Ops" },
  { value: "persistence", label: "Persistence" },
  { value: "lateral", label: "Lateral Movement" },
  { value: "exfil", label: "Exfiltration" },
  { value: "custom", label: "Custom" },
];

const RISK_LEVELS = [
  { value: "low", label: "Low", color: "text-emerald-400" },
  { value: "medium", label: "Medium", color: "text-amber-400" },
  { value: "high", label: "High", color: "text-orange-400" },
  { value: "critical", label: "Critical", color: "text-red-400" },
];

const RISK_META: Record<string, { label: string; color: string; bg: string }> = {
  low: { label: "Low", color: "text-emerald-400", bg: "bg-emerald-500/20" },
  medium: { label: "Medium", color: "text-amber-400", bg: "bg-amber-500/20" },
  high: { label: "High", color: "text-orange-400", bg: "bg-orange-500/20" },
  critical: { label: "Critical", color: "text-red-400", bg: "bg-red-500/20" },
};

const CAT_META: Record<string, { label: string; color: string; bg: string; border: string }> = {
  recon: { label: "Recon", color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30" },
  credential: { label: "Cred Ops", color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/30" },
  persistence: { label: "Persist", color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  lateral: { label: "Lateral", color: "text-cyan-400", bg: "bg-cyan-500/10", border: "border-cyan-500/30" },
  exfil: { label: "Exfil", color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30" },
  custom: { label: "Custom", color: "text-zinc-400", bg: "bg-zinc-500/10", border: "border-zinc-500/30" },
};

// ─── Step Editor ────────────────────────────────────────────────────────────

function StepEditor({
  step,
  index,
  onChange,
  onRemove,
  onMoveUp,
  onMoveDown,
  isFirst,
  isLast,
}: {
  step: TaskStep;
  index: number;
  onChange: (step: TaskStep) => void;
  onRemove: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
  isFirst: boolean;
  isLast: boolean;
}) {
  const [paramsText, setParamsText] = useState(
    Object.entries(step.params).map(([k, v]) => `${k}=${v}`).join("\n")
  );

  const parseParams = (text: string): Record<string, string> => {
    const params: Record<string, string> = {};
    text.split("\n").forEach((line) => {
      const idx = line.indexOf("=");
      if (idx > 0) {
        params[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      }
    });
    return params;
  };

  return (
    <div className="bg-zinc-900/60 rounded-lg p-3 space-y-2 border border-zinc-700/50">
      <div className="flex items-center gap-2">
        <GripVertical className="h-3.5 w-3.5 text-zinc-600 shrink-0" />
        <span className="text-[10px] font-mono text-muted-foreground w-5">#{index + 1}</span>
        <Select
          value={step.taskType}
          onValueChange={(v) => onChange({ ...step, taskType: v })}
        >
          <SelectTrigger className="h-7 text-xs flex-1">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TASK_TYPES.map((t) => (
              <SelectItem key={t} value={t}>{t}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          type="number"
          value={step.priority}
          onChange={(e) => onChange({ ...step, priority: parseInt(e.target.value) || 5 })}
          className="h-7 w-14 text-xs text-center"
          title="Priority (1-10)"
          min={1}
          max={10}
        />
        <Button
          variant="ghost"
          size="sm"
          className={`h-7 w-7 p-0 ${step.requiresElevation ? "text-amber-400" : "text-zinc-600"}`}
          onClick={() => onChange({ ...step, requiresElevation: !step.requiresElevation })}
          title={step.requiresElevation ? "Requires elevation (click to toggle)" : "No elevation (click to toggle)"}
        >
          <Zap className="h-3.5 w-3.5" />
        </Button>
        <div className="flex gap-0.5">
          <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={onMoveUp} disabled={isFirst}>
            <ChevronUp className="h-3 w-3" />
          </Button>
          <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={onMoveDown} disabled={isLast}>
            <ChevronDown className="h-3 w-3" />
          </Button>
        </div>
        <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-red-400 hover:text-red-300" onClick={onRemove}>
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>
      <Textarea
        value={paramsText}
        onChange={(e) => {
          setParamsText(e.target.value);
          onChange({ ...step, params: parseParams(e.target.value) });
        }}
        placeholder="key=value (one per line)"
        className="text-xs font-mono min-h-[40px] h-auto resize-y bg-zinc-950/50"
        rows={Math.max(1, paramsText.split("\n").length)}
      />
      <div className="flex items-center gap-2">
        <label className="text-[10px] text-muted-foreground">Delay (ms):</label>
        <Input
          type="number"
          value={step.delayMs ?? 0}
          onChange={(e) => onChange({ ...step, delayMs: parseInt(e.target.value) || 0 })}
          className="h-6 w-20 text-[10px]"
          min={0}
          step={500}
        />
      </div>
    </div>
  );
}

// ─── Template Editor Dialog ─────────────────────────────────────────────────

function TemplateEditorDialog({
  template,
  open,
  onOpenChange,
  onSaved,
}: {
  template: Partial<CustomTemplate> | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved: () => void;
}) {
  const isEditing = !!template?.templateId;
  const [name, setName] = useState(template?.name ?? "");
  const [description, setDescription] = useState(template?.description ?? "");
  const [category, setCategory] = useState(template?.category ?? "custom");
  const [risk, setRisk] = useState(template?.risk ?? "medium");
  const [estimatedDuration, setEstimatedDuration] = useState(template?.estimatedDuration ?? "");
  const [tagsText, setTagsText] = useState((template?.tags ?? []).join(", "));
  const [steps, setSteps] = useState<TaskStep[]>(
    template?.steps ?? [{ taskType: "shell_exec", params: {}, priority: 5, requiresElevation: false }]
  );

  const saveMutation = trpc.emberTemplates.saveTemplate.useMutation();
  const cloneMutation = trpc.emberTemplates.cloneTemplate.useMutation();

  const handleSave = async () => {
    if (!name.trim()) {
      toast.error("Template name is required");
      return;
    }
    if (steps.length === 0) {
      toast.error("At least one step is required");
      return;
    }

    try {
      const tags = tagsText.split(",").map((t) => t.trim()).filter(Boolean);
      if (isEditing) {
        await saveMutation.mutateAsync({
          templateId: template!.templateId!,
          name,
          description: description || undefined,
          category: category as any,
          risk: risk as any,
          estimatedDuration: estimatedDuration || undefined,
          tags,
          steps,
        });
        toast.success(`Template "${name}" updated`);
      } else if (template?.clonedFrom) {
        await cloneMutation.mutateAsync({
          sourceId: template.clonedFrom,
          name,
          description: description || undefined,
          category: category as any,
          risk: risk as any,
          estimatedDuration: estimatedDuration || undefined,
          tags,
          steps,
        });
        toast.success(`Template "${name}" saved as custom`);
      } else {
        await saveMutation.mutateAsync({
          name,
          description: description || undefined,
          category: category as any,
          risk: risk as any,
          estimatedDuration: estimatedDuration || undefined,
          tags,
          steps,
        });
        toast.success(`Template "${name}" created`);
      }
      onSaved();
      onOpenChange(false);
    } catch (err: any) {
      toast.error(`Save failed: ${err.message}`);
    }
  };

  const addStep = () => {
    setSteps([...steps, { taskType: "shell_exec", params: {}, priority: 5, requiresElevation: false }]);
  };

  const updateStep = (index: number, step: TaskStep) => {
    const newSteps = [...steps];
    newSteps[index] = step;
    setSteps(newSteps);
  };

  const removeStep = (index: number) => {
    setSteps(steps.filter((_, i) => i !== index));
  };

  const moveStep = (index: number, direction: -1 | 1) => {
    const newSteps = [...steps];
    const target = index + direction;
    if (target < 0 || target >= newSteps.length) return;
    [newSteps[index], newSteps[target]] = [newSteps[target], newSteps[index]];
    setSteps(newSteps);
  };

  const saving = saveMutation.isPending || cloneMutation.isPending;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Edit3 className="h-5 w-5 text-amber-400" />
            {isEditing ? "Edit Template" : template?.clonedFrom ? "Customize & Save Template" : "Create Custom Template"}
          </DialogTitle>
          <DialogDescription>
            {isEditing
              ? "Modify the template parameters and task steps."
              : template?.clonedFrom
              ? "Customize the built-in template and save it as your own."
              : "Create a new reusable task template from scratch."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Template Metadata */}
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2 space-y-1.5">
              <label className="text-xs font-medium">Template Name</label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="My Custom Template"
                className="h-8 text-sm"
              />
            </div>
            <div className="col-span-2 space-y-1.5">
              <label className="text-xs font-medium">Description</label>
              <Textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="What this template does..."
                className="text-xs min-h-[60px] resize-y"
                rows={2}
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium">Category</label>
              <Select value={category} onValueChange={setCategory}>
                <SelectTrigger className="h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CATEGORIES.map((c) => (
                    <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium">Risk Level</label>
              <Select value={risk} onValueChange={setRisk}>
                <SelectTrigger className="h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {RISK_LEVELS.map((r) => (
                    <SelectItem key={r.value} value={r.value}>
                      <span className={r.color}>{r.label}</span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium">Est. Duration</label>
              <Input
                value={estimatedDuration}
                onChange={(e) => setEstimatedDuration(e.target.value)}
                placeholder="2-5 min"
                className="h-8 text-xs"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium">Tags (comma-separated)</label>
              <Input
                value={tagsText}
                onChange={(e) => setTagsText(e.target.value)}
                placeholder="recon, passive, network"
                className="h-8 text-xs"
              />
            </div>
          </div>

          {/* Steps Editor */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium">Task Steps ({steps.length})</label>
              <Button variant="outline" size="sm" className="h-6 text-[10px]" onClick={addStep}>
                <Plus className="h-3 w-3 mr-1" />
                Add Step
              </Button>
            </div>
            <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
              {steps.map((step, i) => (
                <StepEditor
                  key={i}
                  step={step}
                  index={i}
                  onChange={(s) => updateStep(i, s)}
                  onRemove={() => removeStep(i)}
                  onMoveUp={() => moveStep(i, -1)}
                  onMoveDown={() => moveStep(i, 1)}
                  isFirst={i === 0}
                  isLast={i === steps.length - 1}
                />
              ))}
              {steps.length === 0 && (
                <div className="text-center py-4 text-muted-foreground text-xs">
                  No steps defined. Click "Add Step" to begin.
                </div>
              )}
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={saving} className="bg-amber-600 hover:bg-amber-700">
            {saving ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Save className="h-4 w-4 mr-1.5" />}
            {saving ? "Saving..." : isEditing ? "Update Template" : "Save Template"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Custom Template Card ───────────────────────────────────────────────────

function CustomTemplateCard({
  template,
  onEdit,
  onDelete,
  onDeploy,
}: {
  template: CustomTemplate;
  onEdit: () => void;
  onDelete: () => void;
  onDeploy: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const catMeta = CAT_META[template.category] ?? CAT_META.custom;
  const riskMeta = RISK_META[template.risk] ?? RISK_META.medium;
  const steps = (template.steps as TaskStep[]) || [];

  return (
    <Card className={`${catMeta.border} ${catMeta.bg} hover:border-opacity-60 transition-all`}>
      <CardContent className="p-4 space-y-3">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold truncate">{template.name}</h3>
              {template.clonedFrom && (
                <Badge variant="outline" className="text-[8px] px-1 py-0 border-zinc-600 shrink-0">
                  <Copy className="h-2.5 w-2.5 mr-0.5" />
                  cloned
                </Badge>
              )}
            </div>
            <div className="flex items-center gap-2 mt-0.5">
              <Badge variant="outline" className={`text-[9px] px-1.5 py-0 ${riskMeta.bg} ${riskMeta.color} border-0`}>
                {riskMeta.label} Risk
              </Badge>
              <Badge variant="outline" className={`text-[9px] px-1.5 py-0 ${catMeta.bg} ${catMeta.color} border-0`}>
                {catMeta.label}
              </Badge>
              {template.estimatedDuration && (
                <span className="text-[10px] text-muted-foreground">{template.estimatedDuration}</span>
              )}
            </div>
          </div>
          <div className="flex gap-1 shrink-0">
            <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-zinc-400 hover:text-zinc-200" onClick={onEdit}>
              <Edit3 className="h-3.5 w-3.5" />
            </Button>
            <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-red-400 hover:text-red-300" onClick={onDelete}>
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
            <Button size="sm" className="h-7 text-xs bg-zinc-700 hover:bg-zinc-600" onClick={onDeploy}>
              Deploy
            </Button>
          </div>
        </div>

        {template.description && (
          <p className="text-xs text-muted-foreground leading-relaxed">{template.description}</p>
        )}

        <div className="flex items-center justify-between">
          <div className="flex gap-1 flex-wrap">
            {((template.tags as string[]) || []).map((tag) => (
              <Badge key={tag} variant="outline" className="text-[9px] px-1.5 py-0 border-zinc-600">
                {tag}
              </Badge>
            ))}
          </div>
          <div className="flex items-center gap-2">
            {template.usageCount > 0 && (
              <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                <Star className="h-2.5 w-2.5" />
                {template.usageCount} uses
              </span>
            )}
            <Button
              variant="ghost"
              size="sm"
              className="h-6 text-[10px] text-muted-foreground"
              onClick={() => setExpanded(!expanded)}
            >
              {steps.length} steps
              {expanded ? <ChevronUp className="h-3 w-3 ml-1" /> : <ChevronDown className="h-3 w-3 ml-1" />}
            </Button>
          </div>
        </div>

        {expanded && (
          <div className="bg-zinc-900/50 rounded-lg p-2 space-y-1.5">
            {steps.map((step, i) => (
              <div key={i} className="flex items-center gap-2 text-[11px]">
                <span className="text-muted-foreground font-mono w-4">{i + 1}.</span>
                <Badge variant="outline" className="text-[9px] px-1.5 py-0 font-mono">
                  {step.taskType}
                </Badge>
                <span className="text-zinc-400 truncate flex-1">
                  {Object.entries(step.params).map(([k, v]) => `${k}=${v}`).join(", ") || "no params"}
                </span>
                {step.requiresElevation && (
                  <Zap className="h-3 w-3 text-amber-400 shrink-0" />
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────

export default function EmberTemplateEditor({
  agents,
  onDeployCustom,
}: {
  agents: Array<{ id: string; name: string }>;
  onDeployCustom?: (steps: TaskStep[], agentId: string) => void;
}) {
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<Partial<CustomTemplate> | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  const { data: customTemplates, refetch } = trpc.emberTemplates.listTemplates.useQuery();
  const deleteMutation = trpc.emberTemplates.deleteTemplate.useMutation();
  const trackUsage = trpc.emberTemplates.trackTemplateUsage.useMutation();
  const queueTask = trpc.ember.queueTask.useMutation();

  const handleCreate = () => {
    setEditingTemplate(null);
    setEditorOpen(true);
  };

  const handleEdit = (template: CustomTemplate) => {
    setEditingTemplate(template);
    setEditorOpen(true);
  };

  const handleCloneBuiltIn = (builtInId: string, name: string, steps: TaskStep[], category: string, risk: string, tags: string[], description: string, estimatedDuration: string) => {
    setEditingTemplate({
      name: `${name} (Custom)`,
      description,
      category,
      risk,
      estimatedDuration,
      tags,
      steps: [...steps],
      clonedFrom: builtInId,
    });
    setEditorOpen(true);
  };

  const handleDelete = async (templateId: string) => {
    if (!confirm("Delete this custom template?")) return;
    try {
      await deleteMutation.mutateAsync({ templateId });
      toast.success("Template deleted");
      refetch();
    } catch (err: any) {
      toast.error(`Delete failed: ${err.message}`);
    }
  };

  const handleDeploy = async (template: CustomTemplate) => {
    if (agents.length === 0) {
      toast.error("No active Ember agents available");
      return;
    }
    // Track usage
    trackUsage.mutate({ templateId: template.templateId });

    const steps = (template.steps as TaskStep[]) || [];
    const agentId = agents[0].id; // Default to first agent

    let success = 0;
    let fail = 0;
    for (const step of steps) {
      try {
        await queueTask.mutateAsync({
          agentId,
          taskType: step.taskType,
          params: step.params,
          priority: step.priority,
          requiresElevation: step.requiresElevation,
        });
        success++;
      } catch {
        fail++;
      }
    }

    if (fail === 0) {
      toast.success(`Deployed ${success} tasks from "${template.name}"`);
    } else {
      toast.warning(`Deployed: ${success} queued, ${fail} failed`);
    }
  };

  const filtered = (customTemplates ?? []).filter((t) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      t.name.toLowerCase().includes(q) ||
      (t.description ?? "").toLowerCase().includes(q) ||
      (t.category ?? "").toLowerCase().includes(q)
    );
  });

  return (
    <>
      <Card className="border-zinc-700/50">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BookTemplate className="h-4 w-4 text-purple-400" />
              Custom Templates
            </CardTitle>
            <Button size="sm" className="h-7 text-xs bg-purple-600 hover:bg-purple-700" onClick={handleCreate}>
              <Plus className="h-3 w-3 mr-1" />
              New Template
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Create, customize, and save your own task templates. Clone built-in templates
            to modify parameters, or build from scratch for custom operations.
          </p>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Search */}
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder="Search custom templates..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-8 text-xs pl-8"
              />
            </div>
          </div>

          {/* Custom Templates List */}
          {filtered.length > 0 ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 max-h-[400px] overflow-y-auto pr-1">
              {filtered.map((t) => (
                <CustomTemplateCard
                  key={t.templateId}
                  template={t as unknown as CustomTemplate}
                  onEdit={() => handleEdit(t as unknown as CustomTemplate)}
                  onDelete={() => handleDelete(t.templateId)}
                  onDeploy={() => handleDeploy(t as unknown as CustomTemplate)}
                />
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <FolderOpen className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No custom templates yet</p>
              <p className="text-xs mt-1">
                Create one from scratch or clone a built-in template from the Templates section above.
              </p>
            </div>
          )}

          {/* Stats */}
          <div className="flex items-center justify-between text-[10px] text-muted-foreground pt-2 border-t border-zinc-800">
            <span>{customTemplates?.length ?? 0} custom templates</span>
            <span>
              {(customTemplates ?? []).reduce((sum, t) => sum + (t.usageCount ?? 0), 0)} total deployments
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Editor Dialog */}
      <TemplateEditorDialog
        template={editingTemplate}
        open={editorOpen}
        onOpenChange={setEditorOpen}
        onSaved={() => refetch()}
      />
    </>
  );
}

// Export the clone handler type for the parent component
export type { TaskStep, CustomTemplate };
export { TASK_TYPES, CATEGORIES, RISK_LEVELS };
