/**
 * Customer Stack Profile Page
 * ============================
 * Manage customer technology stacks, match to scanner modules,
 * generate tailored test plans, run live probes, and link profiles
 * to engagements for orchestrator auto-load.
 *
 * @author Harrison Cook — AceofCloud
 */

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import {
  Plus, Trash2, Search, Layers, Shield, Zap, AlertTriangle,
  ChevronDown, ChevronRight, Loader2, Radar, FileText, X,
  CheckCircle2, XCircle, Target, Link2, Unlink, Bug,
} from "lucide-react";

// ─── Technology Categories ──────────────────────────────────────────────────

const TECH_CATEGORIES = [
  { key: "languages", label: "Languages", placeholder: "e.g. Python, Go, Java, TypeScript" },
  { key: "webFrameworks", label: "Web Frameworks", placeholder: "e.g. React, Django, Spring Boot, FastAPI" },
  { key: "dataAndMl", label: "Data & ML", placeholder: "e.g. TensorFlow, PyTorch, Pandas, Spark" },
  { key: "genaiAndLlm", label: "GenAI & LLM", placeholder: "e.g. LangChain, OpenAI, Anthropic, FAISS" },
  { key: "cloudServices", label: "Cloud Services", placeholder: "e.g. AWS, Azure, GCP, Firebase" },
  { key: "securityTools", label: "Security Tools", placeholder: "e.g. Vault, CrowdStrike, Splunk" },
  { key: "devopsAndCi", label: "DevOps & CI/CD", placeholder: "e.g. GitHub Actions, Jenkins, Docker, K8s" },
  { key: "databasesList", label: "Databases", placeholder: "e.g. PostgreSQL, MongoDB, Redis, DynamoDB" },
  { key: "infrastructure", label: "Infrastructure", placeholder: "e.g. Nginx, Apache, Cloudflare, Terraform" },
  { key: "other", label: "Other", placeholder: "e.g. Streamlit, Jupyter, custom frameworks" },
] as const;

type CategoryKey = typeof TECH_CATEGORIES[number]["key"];

// Technologies that support version-specific CVE matching
const VERSION_TRACKABLE_TECHS = [
  "streamlit", "jupyter", "jupyterlab", "jupyterhub", "langchain",
  "faiss", "firebase", "github actions",
];

// ─── Tag Input Component ────────────────────────────────────────────────────

function TagInput({
  tags,
  onTagsChange,
  placeholder,
}: {
  tags: string[];
  onTagsChange: (tags: string[]) => void;
  placeholder: string;
}) {
  const [inputValue, setInputValue] = useState("");

  const addTag = (value: string) => {
    const trimmed = value.trim();
    if (trimmed && !tags.includes(trimmed)) {
      onTagsChange([...tags, trimmed]);
    }
    setInputValue("");
  };

  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap gap-1.5 min-h-[28px]">
        {tags.map((tag) => (
          <Badge key={tag} variant="secondary" className="gap-1 text-xs">
            {tag}
            <X
              className="h-3 w-3 cursor-pointer hover:text-destructive"
              onClick={() => onTagsChange(tags.filter((t) => t !== tag))}
            />
          </Badge>
        ))}
      </div>
      <Input
        value={inputValue}
        onChange={(e) => setInputValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            addTag(inputValue);
          }
        }}
        onBlur={() => inputValue && addTag(inputValue)}
        placeholder={placeholder}
        className="h-8 text-sm"
      />
    </div>
  );
}

// ─── Version CVE Badge ──────────────────────────────────────────────────────

function CveSeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };
  return (
    <Badge variant="outline" className={`text-[10px] ${colors[severity] || ""}`}>
      {severity.toUpperCase()}
    </Badge>
  );
}

// ─── Engagement Linker Component ────────────────────────────────────────────

function EngagementLinker({
  profileId,
  currentEngagementId,
  onLinked,
}: {
  profileId: number;
  currentEngagementId: number | null;
  onLinked: () => void;
}) {
  const [engagementIdInput, setEngagementIdInput] = useState("");
  const utils = trpc.useUtils();

  const linkMutation = trpc.stackProfile.linkToEngagement.useMutation({
    onSuccess: () => {
      toast.success("Profile linked to engagement");
      utils.stackProfile.list.invalidate();
      onLinked();
    },
    onError: (err) => toast.error(`Link failed: ${err.message}`),
  });

  const unlinkMutation = trpc.stackProfile.unlinkFromEngagement.useMutation({
    onSuccess: () => {
      toast.success("Profile unlinked from engagement");
      utils.stackProfile.list.invalidate();
      onLinked();
    },
    onError: (err) => toast.error(`Unlink failed: ${err.message}`),
  });

  if (currentEngagementId) {
    return (
      <div className="flex items-center gap-2">
        <Badge variant="secondary" className="text-xs gap-1">
          <Link2 className="h-3 w-3 text-emerald-400" />
          Engagement #{currentEngagementId}
        </Badge>
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6"
          onClick={() => unlinkMutation.mutate({ profileId })}
          disabled={unlinkMutation.isPending}
        >
          {unlinkMutation.isPending ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Unlink className="h-3 w-3 text-muted-foreground hover:text-destructive" />
          )}
        </Button>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-1.5">
      <Input
        value={engagementIdInput}
        onChange={(e) => setEngagementIdInput(e.target.value.replace(/\D/g, ""))}
        placeholder="Engagement ID"
        className="h-7 w-28 text-xs"
      />
      <Button
        variant="outline"
        size="sm"
        className="h-7 text-xs"
        onClick={() => {
          const id = parseInt(engagementIdInput);
          if (!id || isNaN(id)) { toast.error("Enter a valid engagement ID"); return; }
          linkMutation.mutate({ profileId, engagementId: id });
        }}
        disabled={linkMutation.isPending || !engagementIdInput}
      >
        {linkMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Link2 className="h-3 w-3" />}
        <span className="ml-1">Link</span>
      </Button>
    </div>
  );
}

// ─── Profile Form ───────────────────────────────────────────────────────────

function ProfileForm({
  onSave,
  initialData,
  onCancel,
}: {
  onSave: (data: any) => void;
  initialData?: any;
  onCancel: () => void;
}) {
  const [customerName, setCustomerName] = useState(initialData?.customerName || "");
  const [notes, setNotes] = useState(initialData?.notes || "");
  const [techStacks, setTechStacks] = useState<Record<CategoryKey, string[]>>(() => {
    const initial: Record<string, string[]> = {};
    for (const cat of TECH_CATEGORIES) {
      initial[cat.key] = initialData?.[cat.key] || [];
    }
    return initial as Record<CategoryKey, string[]>;
  });
  const [technologyVersions, setTechnologyVersions] = useState<Record<string, string>>(
    () => initialData?.technologyVersions || {}
  );
  const [showVersions, setShowVersions] = useState(
    () => initialData?.technologyVersions && Object.keys(initialData.technologyVersions).length > 0
  );

  const allTechs = useMemo(
    () => Object.values(techStacks).flat().filter(Boolean),
    [techStacks]
  );

  // Find which techs support version tracking
  const versionTrackableTechs = useMemo(() => {
    return allTechs.filter(t =>
      VERSION_TRACKABLE_TECHS.some(vt =>
        t.toLowerCase().includes(vt) || vt.includes(t.toLowerCase())
      )
    );
  }, [allTechs]);

  // Live scanner matching preview
  const matchPreview = trpc.stackProfile.matchScanners.useMutation();

  // Version CVE preview
  const versionCvePreview = trpc.stackProfile.lookupVersionCves.useMutation();

  const handlePreview = () => {
    if (allTechs.length === 0) {
      toast.error("Add at least one technology to match scanners");
      return;
    }
    matchPreview.mutate({ technologies: allTechs });
    // Also check version CVEs if any versions are set
    const activeVersions = Object.fromEntries(
      Object.entries(technologyVersions).filter(([, v]) => v.trim())
    );
    if (Object.keys(activeVersions).length > 0) {
      versionCvePreview.mutate({ technologyVersions: activeVersions });
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Layers className="h-5 w-5 text-emerald-400" />
          {initialData ? "Edit Stack Profile" : "New Customer Stack Profile"}
        </CardTitle>
        <CardDescription>
          Define the customer's technology stack to auto-match scanner modules and generate tailored test plans.
          Add version numbers to enable version-specific CVE matching.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Customer Name */}
        <div className="space-y-2">
          <Label htmlFor="customerName">Customer Name</Label>
          <Input
            id="customerName"
            value={customerName}
            onChange={(e) => setCustomerName(e.target.value)}
            placeholder="e.g. Acme Corp"
          />
        </div>

        {/* Technology Categories */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {TECH_CATEGORIES.map((cat) => (
            <div key={cat.key} className="space-y-1">
              <Label className="text-xs font-medium text-muted-foreground">{cat.label}</Label>
              <TagInput
                tags={techStacks[cat.key]}
                onTagsChange={(tags) =>
                  setTechStacks((prev) => ({ ...prev, [cat.key]: tags }))
                }
                placeholder={cat.placeholder}
              />
            </div>
          ))}
        </div>

        {/* Version Tracking Section */}
        {versionTrackableTechs.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="flex items-center gap-2">
                <Bug className="h-4 w-4 text-amber-400" />
                Technology Versions (CVE Matching)
              </Label>
              <Button
                variant="ghost"
                size="sm"
                className="text-xs"
                onClick={() => setShowVersions(!showVersions)}
              >
                {showVersions ? "Hide" : "Show"} Version Fields
                {showVersions ? <ChevronDown className="h-3 w-3 ml-1" /> : <ChevronRight className="h-3 w-3 ml-1" />}
              </Button>
            </div>
            {showVersions && (
              <div className="rounded-lg border bg-card/50 p-4 space-y-3">
                <p className="text-xs text-muted-foreground">
                  Enter version numbers for technologies with known CVE ranges.
                  The system will flag version-specific vulnerabilities automatically.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                  {versionTrackableTechs.map((tech) => (
                    <div key={tech} className="space-y-1">
                      <Label className="text-[11px] text-muted-foreground">{tech}</Label>
                      <Input
                        value={technologyVersions[tech.toLowerCase()] || ""}
                        onChange={(e) =>
                          setTechnologyVersions((prev) => ({
                            ...prev,
                            [tech.toLowerCase()]: e.target.value,
                          }))
                        }
                        placeholder="e.g. 1.28.0"
                        className="h-7 text-xs"
                      />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Notes */}
        <div className="space-y-2">
          <Label htmlFor="notes">Notes</Label>
          <Textarea
            id="notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Additional context about the customer's environment..."
            rows={3}
          />
        </div>

        {/* Scanner Match Preview */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handlePreview} disabled={matchPreview.isPending}>
              {matchPreview.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Radar className="h-4 w-4 mr-1" />}
              Preview Scanner Match
            </Button>
            <span className="text-xs text-muted-foreground">
              {allTechs.length} technologies across {Object.values(techStacks).filter(v => v.length > 0).length} categories
            </span>
          </div>

          {matchPreview.data && (
            <div className="rounded-lg border bg-card p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Scanner Coverage</span>
                <Badge variant={matchPreview.data.coveragePercent >= 70 ? "default" : "destructive"}>
                  {matchPreview.data.coveragePercent}% covered
                </Badge>
              </div>
              {matchPreview.data.matched.length > 0 && (
                <div className="space-y-1">
                  <span className="text-xs text-muted-foreground">Matched Scanners:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {matchPreview.data.matched.map((s: string) => (
                      <Badge key={s} variant="secondary" className="text-xs">
                        <CheckCircle2 className="h-3 w-3 mr-1 text-emerald-400" />
                        {s}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {matchPreview.data.gaps.length > 0 && (
                <div className="space-y-1">
                  <span className="text-xs text-muted-foreground">Coverage Gaps:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {matchPreview.data.gaps.map((g: string) => (
                      <Badge key={g} variant="outline" className="text-xs text-amber-400 border-amber-400/30">
                        <AlertTriangle className="h-3 w-3 mr-1" />
                        {g}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Version CVE Preview */}
          {versionCvePreview.data && versionCvePreview.data.cves.length > 0 && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-4 space-y-3">
              <div className="flex items-center gap-2">
                <Bug className="h-4 w-4 text-red-400" />
                <span className="text-sm font-medium text-red-400">
                  {versionCvePreview.data.cves.length} Version-Specific CVEs Found
                </span>
              </div>
              <div className="space-y-2">
                {versionCvePreview.data.cves.map((cve: any, i: number) => (
                  <div key={i} className="text-xs border-l-2 border-red-400/50 pl-3 py-1">
                    <div className="flex items-center gap-2">
                      <CveSeverityBadge severity={cve.severity} />
                      <span className="font-mono font-medium">{cve.cveId}</span>
                      <span className="text-muted-foreground">
                        {cve.technology} {cve.version} &lt; {cve.affectedBelow}
                      </span>
                    </div>
                    <p className="text-muted-foreground mt-0.5">{cve.title}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <Separator />

        {/* Actions */}
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onCancel}>Cancel</Button>
          <Button
            onClick={() => {
              if (!customerName.trim()) {
                toast.error("Customer name is required");
                return;
              }
              const activeVersions = Object.fromEntries(
                Object.entries(technologyVersions).filter(([, v]) => v.trim())
              );
              onSave({
                customerName,
                ...techStacks,
                technologyVersions: Object.keys(activeVersions).length > 0 ? activeVersions : undefined,
                notes,
              });
            }}
          >
            {initialData ? "Update Profile" : "Create Profile"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Test Plan Viewer ───────────────────────────────────────────────────────

function TestPlanViewer({ profileId }: { profileId: number }) {
  const [expanded, setExpanded] = useState(false);
  const generatePlan = trpc.stackProfile.generateTestPlan.useMutation({
    onSuccess: () => toast.success("Test plan generated successfully"),
    onError: (err) => toast.error(`Failed to generate test plan: ${err.message}`),
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => generatePlan.mutate({ profileId })}
          disabled={generatePlan.isPending}
        >
          {generatePlan.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <FileText className="h-4 w-4 mr-1" />
          )}
          Generate Test Plan
        </Button>
      </div>

      {generatePlan.data?.testPlan && (
        <div className="rounded-lg border bg-card">
          <button
            className="w-full flex items-center justify-between p-3 text-sm font-medium hover:bg-accent/50 transition-colors"
            onClick={() => setExpanded(!expanded)}
          >
            <span className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-emerald-400" />
              Generated Test Plan ({generatePlan.data.testPlan.length} items)
            </span>
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </button>
          {expanded && (
            <div className="border-t divide-y">
              {generatePlan.data.testPlan.map((item: any, i: number) => (
                <div key={i} className="p-3 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">{item.title}</span>
                    <Badge
                      variant={
                        item.priority === "critical" ? "destructive" :
                        item.priority === "high" ? "destructive" :
                        "secondary"
                      }
                      className="text-xs"
                    >
                      {item.priority}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{item.description}</p>
                  <span className="text-[10px] text-muted-foreground/60">Scanner: {item.scannerModule}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Live Probe Panel ───────────────────────────────────────────────────────

function LiveProbePanel() {
  const [targetUrl, setTargetUrl] = useState("");
  const [probeResults, setProbeResults] = useState<any>(null);

  const runProbes = trpc.stackProfile.runLiveProbes.useMutation({
    onSuccess: (data) => {
      setProbeResults(data);
      toast.success(`Live probes complete: ${data.totalFindings || 0} findings`);
    },
    onError: (err) => toast.error(`Probe failed: ${err.message}`),
  });

  const detectTech = trpc.stackProfile.detectTechnologies.useMutation({
    onSuccess: (data) => {
      toast.success(`Detected ${data.confirmedTechnologies?.length || 0} technologies`);
    },
    onError: (err) => toast.error(`Detection failed: ${err.message}`),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Target className="h-5 w-5 text-amber-400" />
          Live Probes & Tech Detection
        </CardTitle>
        <CardDescription>
          Run live HTTP probes and technology auto-detection against a target URL.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Input
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://target.example.com"
            className="flex-1"
          />
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (!targetUrl) { toast.error("Enter a target URL"); return; }
              detectTech.mutate({ targetUrl });
            }}
            disabled={detectTech.isPending}
          >
            {detectTech.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            <span className="ml-1 hidden sm:inline">Detect</span>
          </Button>
          <Button
            size="sm"
            onClick={() => {
              if (!targetUrl) { toast.error("Enter a target URL"); return; }
              runProbes.mutate({ targetUrl });
            }}
            disabled={runProbes.isPending}
          >
            {runProbes.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
            <span className="ml-1 hidden sm:inline">Probe</span>
          </Button>
        </div>

        {/* Tech Detection Results */}
        {detectTech.data && (
          <div className="rounded-lg border bg-card p-4 space-y-2">
            <div className="text-sm font-medium flex items-center gap-2">
              <Radar className="h-4 w-4 text-blue-400" />
              Technology Detection Results
            </div>
            {detectTech.data.confirmedTechnologies?.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {detectTech.data.confirmedTechnologies.map((tech: string) => (
                  <Badge key={tech} className="text-xs">{tech}</Badge>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">No specialized technologies detected above threshold.</p>
            )}
            {detectTech.data.recommendedScanners?.length > 0 && (
              <div className="space-y-1 mt-2">
                <span className="text-xs text-muted-foreground">Recommended Scanners:</span>
                {detectTech.data.recommendedScanners.map((s: any, i: number) => (
                  <div key={i} className="text-xs flex items-center gap-2">
                    <Badge variant="secondary" className="text-[10px]">P{s.priority}</Badge>
                    <span>{s.scannerModule}</span>
                    <span className="text-muted-foreground/60">— {s.rationale?.substring(0, 80)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Probe Results */}
        {probeResults && (
          <div className="rounded-lg border bg-card p-4 space-y-2">
            <div className="text-sm font-medium flex items-center gap-2">
              <Zap className="h-4 w-4 text-amber-400" />
              Probe Results — {probeResults.totalFindings || 0} findings
            </div>
            {probeResults.findings?.map((finding: any, i: number) => (
              <div key={i} className="text-xs border-l-2 border-amber-400/50 pl-3 py-1">
                <div className="flex items-center gap-2">
                  <Badge
                    variant={finding.severity === "critical" || finding.severity === "high" ? "destructive" : "secondary"}
                    className="text-[10px]"
                  >
                    {finding.severity}
                  </Badge>
                  <span className="font-medium">{finding.title || finding.path}</span>
                </div>
                {finding.detail && <p className="text-muted-foreground mt-0.5">{finding.detail}</p>}
              </div>
            )) || <p className="text-xs text-muted-foreground">No findings from live probes.</p>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Version CVE Summary ────────────────────────────────────────────────────

function VersionCveSummary({ profile }: { profile: any }) {
  const [expanded, setExpanded] = useState(false);
  const versions = profile.technologyVersions as Record<string, string> | null;
  if (!versions || Object.keys(versions).length === 0) return null;

  const lookupCves = trpc.stackProfile.lookupVersionCves.useMutation();

  return (
    <div className="space-y-2">
      <button
        className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
        onClick={() => {
          if (!expanded && !lookupCves.data) {
            lookupCves.mutate({ technologyVersions: versions });
          }
          setExpanded(!expanded);
        }}
      >
        {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        <Bug className="h-3 w-3 text-amber-400" />
        Version CVEs ({Object.keys(versions).length} tracked)
      </button>
      {expanded && (
        <div className="space-y-2 pl-4">
          {/* Version list */}
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(versions).map(([tech, ver]) => (
              <Badge key={tech} variant="outline" className="text-[10px] font-mono">
                {tech}: {ver}
              </Badge>
            ))}
          </div>
          {/* CVE results */}
          {lookupCves.isPending && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" /> Checking CVE database...
            </div>
          )}
          {lookupCves.data && lookupCves.data.cves.length > 0 && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 space-y-2">
              <span className="text-xs font-medium text-red-400">
                {lookupCves.data.cves.length} CVEs affect these versions
              </span>
              {lookupCves.data.cves.map((cve: any, i: number) => (
                <div key={i} className="text-[11px] border-l-2 border-red-400/50 pl-2 py-0.5">
                  <div className="flex items-center gap-1.5">
                    <CveSeverityBadge severity={cve.severity} />
                    <span className="font-mono">{cve.cveId}</span>
                  </div>
                  <p className="text-muted-foreground">{cve.title}</p>
                </div>
              ))}
            </div>
          )}
          {lookupCves.data && lookupCves.data.cves.length === 0 && (
            <p className="text-xs text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="h-3 w-3" /> No known CVEs for these versions
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Profile Card ───────────────────────────────────────────────────────────

function ProfileCard({
  profile,
  onEdit,
  onDelete,
}: {
  profile: any;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const [showTestPlan, setShowTestPlan] = useState(false);
  const utils = trpc.useUtils();
  const allTechs = useMemo(() => {
    const stacks = [
      profile.languages, profile.webFrameworks, profile.dataAndMl,
      profile.genaiAndLlm, profile.cloudServices, profile.securityTools,
      profile.devopsAndCi, profile.databasesList, profile.infrastructure,
      profile.other,
    ];
    return stacks.flat().filter(Boolean);
  }, [profile]);

  return (
    <Card className="group">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div>
            <CardTitle className="text-base">{profile.customerName}</CardTitle>
            <CardDescription className="text-xs mt-1">
              {allTechs.length} technologies • {(profile.matchedScanners || []).length} scanners matched
              {profile.coveragePercent != null && ` • ${profile.coveragePercent}% coverage`}
            </CardDescription>
          </div>
          <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onEdit}>
              <FileText className="h-3.5 w-3.5" />
            </Button>
            <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={onDelete}>
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* Engagement Link */}
        <EngagementLinker
          profileId={profile.id}
          currentEngagementId={profile.engagementId}
          onLinked={() => utils.stackProfile.list.invalidate()}
        />

        {/* Tech tags preview */}
        <div className="flex flex-wrap gap-1">
          {allTechs.slice(0, 12).map((tech: string) => (
            <Badge key={tech} variant="secondary" className="text-[10px]">{tech}</Badge>
          ))}
          {allTechs.length > 12 && (
            <Badge variant="outline" className="text-[10px]">+{allTechs.length - 12} more</Badge>
          )}
        </div>

        {/* Scanner coverage bar */}
        {profile.coveragePercent != null && (
          <div className="space-y-1">
            <div className="flex justify-between text-[10px] text-muted-foreground">
              <span>Scanner Coverage</span>
              <span>{profile.coveragePercent}%</span>
            </div>
            <div className="h-1.5 rounded-full bg-muted overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  profile.coveragePercent >= 70 ? "bg-emerald-500" :
                  profile.coveragePercent >= 40 ? "bg-amber-500" : "bg-red-500"
                }`}
                style={{ width: `${profile.coveragePercent}%` }}
              />
            </div>
          </div>
        )}

        {/* Gaps */}
        {profile.gaps && profile.gaps.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {profile.gaps.slice(0, 5).map((gap: string) => (
              <Badge key={gap} variant="outline" className="text-[10px] text-amber-400 border-amber-400/30">
                <AlertTriangle className="h-2.5 w-2.5 mr-0.5" />
                {gap}
              </Badge>
            ))}
          </div>
        )}

        {/* Version CVE Summary */}
        <VersionCveSummary profile={profile} />

        {/* Test Plan Section */}
        <div className="pt-1">
          <button
            className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
            onClick={() => setShowTestPlan(!showTestPlan)}
          >
            {showTestPlan ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
            Test Plan
          </button>
          {showTestPlan && <TestPlanViewer profileId={profile.id} />}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function StackProfiles() {
  const [showForm, setShowForm] = useState(false);
  const [editingProfile, setEditingProfile] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState("");

  const utils = trpc.useUtils();
  const { data: profiles, isLoading } = trpc.stackProfile.list.useQuery();

  const createProfile = trpc.stackProfile.create.useMutation({
    onSuccess: (data) => {
      const cveMsg = data.versionCves?.length
        ? ` — ${data.versionCves.length} version-specific CVEs found!`
        : "";
      toast.success(`Profile created — ${data.matchedScanners.length} scanners matched (${data.coveragePercent}% coverage)${cveMsg}`);
      utils.stackProfile.list.invalidate();
      setShowForm(false);
    },
    onError: (err) => toast.error(`Failed to create profile: ${err.message}`),
  });

  const updateProfile = trpc.stackProfile.update.useMutation({
    onSuccess: (data) => {
      const cveMsg = data.versionCves?.length
        ? ` — ${data.versionCves.length} version-specific CVEs found!`
        : "";
      toast.success(`Profile updated${cveMsg}`);
      utils.stackProfile.list.invalidate();
      setEditingProfile(null);
      setShowForm(false);
    },
    onError: (err) => toast.error(`Failed to update profile: ${err.message}`),
  });

  const deleteProfile = trpc.stackProfile.delete.useMutation({
    onSuccess: () => {
      toast.success("Profile deleted");
      utils.stackProfile.list.invalidate();
    },
    onError: (err) => toast.error(`Failed to delete profile: ${err.message}`),
  });

  const filteredProfiles = useMemo(() => {
    if (!profiles || !searchQuery) return profiles || [];
    const q = searchQuery.toLowerCase();
    return profiles.filter((p: any) =>
      p.customerName.toLowerCase().includes(q) ||
      [p.languages, p.webFrameworks, p.dataAndMl, p.genaiAndLlm, p.cloudServices,
       p.securityTools, p.devopsAndCi, p.databasesList, p.infrastructure, p.other]
        .flat()
        .filter(Boolean)
        .some((t: string) => t.toLowerCase().includes(q))
    );
  }, [profiles, searchQuery]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Layers className="h-6 w-6 text-emerald-400" />
            Customer Stack Profiles
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Map customer technology stacks to scanner modules, identify coverage gaps, track version-specific CVEs,
            and link profiles to engagements for automatic orchestrator pre-loading.
          </p>
        </div>
        <Button onClick={() => { setEditingProfile(null); setShowForm(true); }}>
          <Plus className="h-4 w-4 mr-1" />
          New Profile
        </Button>
      </div>

      {/* Live Probes Panel */}
      <LiveProbePanel />

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search profiles or technologies..."
          className="pl-9"
        />
      </div>

      {/* Form */}
      {showForm && (
        <ProfileForm
          initialData={editingProfile}
          onSave={(data) => {
            if (editingProfile) {
              updateProfile.mutate({ id: editingProfile.id, ...data });
            } else {
              createProfile.mutate(data);
            }
          }}
          onCancel={() => { setShowForm(false); setEditingProfile(null); }}
        />
      )}

      {/* Profile Grid */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : filteredProfiles.length === 0 ? (
        <Card className="flex flex-col items-center justify-center py-12 text-center">
          <Layers className="h-10 w-10 text-muted-foreground/40 mb-3" />
          <p className="text-sm text-muted-foreground">
            {searchQuery ? "No profiles match your search." : "No stack profiles yet. Create one to get started."}
          </p>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filteredProfiles.map((profile: any) => (
            <ProfileCard
              key={profile.id}
              profile={profile}
              onEdit={() => { setEditingProfile(profile); setShowForm(true); }}
              onDelete={() => {
                if (confirm(`Delete profile for "${profile.customerName}"?`)) {
                  deleteProfile.mutate({ id: profile.id });
                }
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}
