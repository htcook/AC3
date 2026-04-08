import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import {
  Loader2,
  Shield,
  Target,
  Crosshair,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Zap,
  Globe,
  FileText,
  Layers,
  Search,
  Rocket,
} from "lucide-react";
import { PlatformIcon, PLATFORM_NAMES } from "@/components/PlatformIcons";

interface CreateEngagementDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated?: (engagementId: number) => void;
}

type WizardStep = "select" | "scanning" | "preview" | "configure" | "creating";

export function CreateEngagementDialog({
  open,
  onOpenChange,
  onCreated,
}: CreateEngagementDialogProps) {
  const [step, setStep] = useState<WizardStep>("select");
  const [selectedProgramId, setSelectedProgramId] = useState<number | null>(null);
  const [manualUrl, setManualUrl] = useState("");
  const [manualName, setManualName] = useState("");
  const [preview, setPreview] = useState<any>(null);
  const [customName, setCustomName] = useState("");
  const [scanMode, setScanMode] = useState<"strict_passive" | "standard" | "active">("standard");
  const [searchQuery, setSearchQuery] = useState("");

  // Fetch programs list
  const programsInput = useMemo(() => ({ limit: 100 }), []);
  const { data: programsData } = trpc.bugBounty.listPrograms.useQuery(programsInput);

  const filteredPrograms = useMemo(() => {
    const programs = programsData?.programs || [];
    if (!searchQuery) return programs;
    const q = searchQuery.toLowerCase();
    return programs.filter(
      (p: any) =>
        p.name?.toLowerCase().includes(q) ||
        p.handle?.toLowerCase().includes(q) ||
        p.platform?.toLowerCase().includes(q)
    );
  }, [programsData, searchQuery]);

  // Build engagement preview mutation
  const buildPreview = trpc.bugBounty.buildEngagementPreview.useMutation({
    onSuccess: (data: any) => {
      setPreview(data);
      setCustomName(data.engagementName || "");
      setStep("preview");
    },
    onError: (e: any) => {
      toast.error(`Failed to analyze program: ${e.message}`);
      setStep("select");
    },
  });

  // Create engagement mutation
  const createEngagement = trpc.bugBounty.createEngagementFromProgram.useMutation({
    onSuccess: (data: any) => {
      toast.success(
        `Engagement created with ${data.scopeAssetsCreated} scope assets and ${data.phasesCreated} phases`
      );
      onCreated?.(data.engagementId);
      handleClose();
    },
    onError: (e: any) => {
      toast.error(`Failed to create engagement: ${e.message}`);
      setStep("configure");
    },
  });

  const handleSelectProgram = (program: any) => {
    setSelectedProgramId(program.id);
    setStep("scanning");
    buildPreview.mutate({
      programId: program.id,
      programUrl: program.url || undefined,
      programName: program.name,
      platform: program.platform,
    });
  };

  const handleManualScan = () => {
    if (!manualUrl && !manualName) {
      toast.error("Enter a program URL or name");
      return;
    }
    setStep("scanning");
    buildPreview.mutate({
      programUrl: manualUrl || undefined,
      programName: manualName || manualUrl,
    });
  };

  const handleCreate = () => {
    if (!preview) return;
    setStep("creating");
    createEngagement.mutate({
      preview,
      customName: customName || undefined,
      scanMode,
    });
  };

  const handleClose = () => {
    setStep("select");
    setSelectedProgramId(null);
    setManualUrl("");
    setManualName("");
    setPreview(null);
    setCustomName("");
    setScanMode("standard");
    setSearchQuery("");
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="bg-zinc-900 border-zinc-800 max-w-3xl max-h-[85vh] overflow-y-auto">
        {/* ─── Step 1: Select Program ─── */}
        {step === "select" && (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Rocket className="h-5 w-5 text-emerald-400" />
                Create Engagement from Program
              </DialogTitle>
              <DialogDescription>
                Select a synced bug bounty program or enter a program URL. The AI
                engine will scan the program page and auto-generate ROE, scope,
                test environment, and engagement phases.
              </DialogDescription>
            </DialogHeader>

            {/* Manual URL entry */}
            <Card className="bg-zinc-800/50 border-zinc-700">
              <CardContent className="pt-4 pb-3">
                <Label className="text-sm font-medium mb-2 block">
                  Scan a Program URL
                </Label>
                <div className="flex gap-2">
                  <Input
                    value={manualUrl}
                    onChange={(e) => setManualUrl(e.target.value)}
                    placeholder="https://hackerone.com/program-name"
                    className="bg-zinc-900 border-zinc-700 flex-1"
                  />
                  <Input
                    value={manualName}
                    onChange={(e) => setManualName(e.target.value)}
                    placeholder="Program name (optional)"
                    className="bg-zinc-900 border-zinc-700 w-48"
                  />
                  <Button
                    onClick={handleManualScan}
                    disabled={!manualUrl && !manualName}
                    size="sm"
                  >
                    <Zap className="h-4 w-4 mr-1" />
                    Scan
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Program list */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label className="text-sm font-medium">
                  Or Select a Synced Program
                </Label>
                <div className="relative w-56">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                  <Input
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter programs..."
                    className="pl-8 h-8 bg-zinc-800 border-zinc-700 text-xs"
                  />
                </div>
              </div>

              <div className="max-h-[40vh] overflow-y-auto space-y-2 pr-1">
                {filteredPrograms.map((p: any) => (
                  <div
                    key={p.id}
                    className={`flex items-center justify-between p-3 rounded-lg border cursor-pointer transition-all hover:bg-zinc-800/80 ${
                      selectedProgramId === p.id
                        ? "border-emerald-500/50 bg-emerald-500/5"
                        : "border-zinc-800 bg-zinc-900/50"
                    }`}
                    onClick={() => handleSelectProgram(p)}
                  >
                    <div className="flex items-center gap-3">
                      {p.logoUrl ? (
                        <img
                          src={p.logoUrl}
                          alt=""
                          className="h-8 w-8 rounded"
                        />
                      ) : (
                        <div className="h-8 w-8 rounded bg-zinc-800 flex items-center justify-center">
                          <Shield className="h-4 w-4 text-zinc-500" />
                        </div>
                      )}
                      <div>
                        <p className="text-sm font-medium">{p.name}</p>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                          <PlatformIcon
                            platform={p.platform}
                            size={12}
                          />
                          <span>
                            {PLATFORM_NAMES[p.platform] || p.platform}
                          </span>
                          {p.state && (
                            <Badge
                              variant="outline"
                              className="text-[10px] h-4"
                            >
                              {p.state}
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                    <ChevronRight className="h-4 w-4 text-zinc-500" />
                  </div>
                ))}
                {filteredPrograms.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground">
                    <Globe className="h-8 w-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">
                      No programs found. Sync from HackerOne first or enter a
                      URL above.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </>
        )}

        {/* ─── Step 2: Scanning ─── */}
        {step === "scanning" && (
          <div className="py-12 text-center">
            <Loader2 className="h-12 w-12 animate-spin mx-auto mb-4 text-emerald-400" />
            <h3 className="text-lg font-semibold mb-2">
              Analyzing Program...
            </h3>
            <p className="text-sm text-muted-foreground max-w-md mx-auto">
              The AI engine is scanning the program page, extracting rules of
              engagement, scope assets, test environment requirements, and
              building an engagement phase plan. This may take 15-30 seconds.
            </p>
            <div className="flex items-center justify-center gap-6 mt-6 text-xs text-muted-foreground">
              <div className="flex items-center gap-1.5">
                <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Fetching program page
              </div>
              <div className="flex items-center gap-1.5">
                <div className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
                Extracting ROE
              </div>
              <div className="flex items-center gap-1.5">
                <div className="h-1.5 w-1.5 rounded-full bg-purple-400 animate-pulse" />
                Building scope
              </div>
            </div>
          </div>
        )}

        {/* ─── Step 3: Preview ─── */}
        {step === "preview" && preview && (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                Engagement Plan Preview
              </DialogTitle>
              <DialogDescription>
                Review the AI-generated engagement plan. You can customize the
                name and scan mode before creating.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 max-h-[55vh] overflow-y-auto pr-1">
              {/* ROE Summary */}
              <Card className="bg-zinc-800/50 border-zinc-700">
                <CardContent className="pt-4 pb-3">
                  <div className="flex items-center gap-2 mb-3">
                    <FileText className="h-4 w-4 text-red-400" />
                    <h4 className="text-sm font-semibold">
                      Rules of Engagement
                    </h4>
                  </div>
                  {preview.roe?.prohibitedActions?.length > 0 && (
                    <div className="mb-2">
                      <p className="text-xs font-medium text-red-400 mb-1">
                        Prohibited Actions
                      </p>
                      <ul className="text-xs text-muted-foreground space-y-0.5">
                        {preview.roe.prohibitedActions
                          .slice(0, 5)
                          .map((a: string, i: number) => (
                            <li key={i} className="flex items-start gap-1.5">
                              <AlertTriangle className="h-3 w-3 text-red-400 mt-0.5 shrink-0" />
                              {a}
                            </li>
                          ))}
                      </ul>
                    </div>
                  )}
                  {preview.roe?.mandatoryRequirements?.length > 0 && (
                    <div className="mb-2">
                      <p className="text-xs font-medium text-blue-400 mb-1">
                        Mandatory Requirements
                      </p>
                      <ul className="text-xs text-muted-foreground space-y-0.5">
                        {preview.roe.mandatoryRequirements
                          .slice(0, 5)
                          .map((r: string, i: number) => (
                            <li key={i} className="flex items-start gap-1.5">
                              <CheckCircle2 className="h-3 w-3 text-blue-400 mt-0.5 shrink-0" />
                              {r}
                            </li>
                          ))}
                      </ul>
                    </div>
                  )}
                  {preview.roe?.bountyRange && (
                    <div className="flex gap-3 mt-2">
                      {Object.entries(preview.roe.bountyRange).map(
                        ([sev, amt]: [string, any]) =>
                          amt > 0 && (
                            <Badge
                              key={sev}
                              variant="outline"
                              className="text-xs"
                            >
                              {sev}: ${Number(amt).toLocaleString()}
                            </Badge>
                          )
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Scope Assets */}
              <Card className="bg-zinc-800/50 border-zinc-700">
                <CardContent className="pt-4 pb-3">
                  <div className="flex items-center gap-2 mb-3">
                    <Crosshair className="h-4 w-4 text-cyan-400" />
                    <h4 className="text-sm font-semibold">
                      Scope Assets ({preview.scope?.assets?.length || 0})
                    </h4>
                  </div>
                  <div className="space-y-1.5">
                    {(preview.scope?.assets || [])
                      .slice(0, 10)
                      .map((asset: any, i: number) => (
                        <div
                          key={i}
                          className="flex items-center justify-between text-xs p-2 bg-zinc-900/50 rounded"
                        >
                          <div className="flex items-center gap-2">
                            <Badge
                              variant="outline"
                              className="text-[10px] h-4"
                            >
                              {asset.type || "url"}
                            </Badge>
                            <span className="font-mono">{asset.name}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {asset.tier && (
                              <Badge
                                variant="outline"
                                className="text-[10px] h-4"
                              >
                                {asset.tier}
                              </Badge>
                            )}
                            {asset.eligibleForBounty && (
                              <Badge className="bg-emerald-500/20 text-emerald-400 text-[10px] h-4">
                                Bounty
                              </Badge>
                            )}
                          </div>
                        </div>
                      ))}
                    {(preview.scope?.assets?.length || 0) > 10 && (
                      <p className="text-xs text-muted-foreground text-center">
                        ...and {preview.scope.assets.length - 10} more assets
                      </p>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Test Environment */}
              {preview.testEnvironment && (
                <Card className="bg-zinc-800/50 border-zinc-700">
                  <CardContent className="pt-4 pb-3">
                    <div className="flex items-center gap-2 mb-3">
                      <Layers className="h-4 w-4 text-purple-400" />
                      <h4 className="text-sm font-semibold">
                        Test Environment
                      </h4>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      {preview.testEnvironment.hasStagingEnv && (
                        <div className="flex items-center gap-1.5 text-emerald-400">
                          <CheckCircle2 className="h-3 w-3" />
                          Staging environment available
                        </div>
                      )}
                      {preview.testEnvironment.requiresAuth && (
                        <div className="flex items-center gap-1.5 text-yellow-400">
                          <AlertTriangle className="h-3 w-3" />
                          Authentication required
                        </div>
                      )}
                      {preview.testEnvironment.recommendedTools?.length >
                        0 && (
                        <div className="col-span-2 mt-1">
                          <p className="text-muted-foreground mb-1">
                            Recommended tools:
                          </p>
                          <div className="flex flex-wrap gap-1">
                            {preview.testEnvironment.recommendedTools.map(
                              (t: string, i: number) => (
                                <Badge
                                  key={i}
                                  variant="outline"
                                  className="text-[10px]"
                                >
                                  {t}
                                </Badge>
                              )
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Phases */}
              {preview.phases?.length > 0 && (
                <Card className="bg-zinc-800/50 border-zinc-700">
                  <CardContent className="pt-4 pb-3">
                    <div className="flex items-center gap-2 mb-3">
                      <Target className="h-4 w-4 text-amber-400" />
                      <h4 className="text-sm font-semibold">
                        Engagement Phases ({preview.phases.length})
                      </h4>
                    </div>
                    <div className="space-y-2">
                      {preview.phases.map((phase: any, i: number) => (
                        <div
                          key={i}
                          className="flex items-start gap-3 text-xs"
                        >
                          <div className="h-6 w-6 rounded-full bg-zinc-800 border border-zinc-700 flex items-center justify-center text-[10px] font-mono shrink-0 mt-0.5">
                            {i + 1}
                          </div>
                          <div>
                            <p className="font-medium">{phase.name}</p>
                            <p className="text-muted-foreground">
                              {phase.focus}
                            </p>
                            {phase.tools?.length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-1">
                                {phase.tools.map((t: string, j: number) => (
                                  <Badge
                                    key={j}
                                    variant="outline"
                                    className="text-[10px] h-4"
                                  >
                                    {t}
                                  </Badge>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>

            <DialogFooter className="gap-2">
              <Button variant="outline" onClick={() => setStep("select")}>
                Back
              </Button>
              <Button onClick={() => setStep("configure")}>
                <ChevronRight className="h-4 w-4 mr-1" />
                Configure & Create
              </Button>
            </DialogFooter>
          </>
        )}

        {/* ─── Step 4: Configure ─── */}
        {step === "configure" && (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Target className="h-5 w-5 text-amber-400" />
                Configure Engagement
              </DialogTitle>
              <DialogDescription>
                Customize the engagement name and scan mode before creating.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4">
              <div>
                <Label>Engagement Name</Label>
                <Input
                  value={customName}
                  onChange={(e) => setCustomName(e.target.value)}
                  placeholder={preview?.engagementName || "Engagement name"}
                  className="bg-zinc-800 border-zinc-700 mt-1"
                />
              </div>

              <div>
                <Label>Scan Mode</Label>
                <Select
                  value={scanMode}
                  onValueChange={(v) =>
                    setScanMode(v as "strict_passive" | "standard" | "active")
                  }
                >
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="strict_passive">
                      Strict Passive — OSINT only, no direct interaction
                    </SelectItem>
                    <SelectItem value="standard">
                      Standard — Passive recon + light active scanning
                    </SelectItem>
                    <SelectItem value="active">
                      Active — Full active scanning and exploitation
                    </SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground mt-1">
                  {scanMode === "strict_passive" &&
                    "Only OSINT and passive reconnaissance. No direct interaction with target systems."}
                  {scanMode === "standard" &&
                    "Passive recon plus light active scanning (port scans, service enumeration). No exploitation."}
                  {scanMode === "active" &&
                    "Full active scanning, vulnerability validation, and exploitation attempts within ROE."}
                </p>
              </div>

              {/* Summary */}
              <Card className="bg-emerald-950/30 border-emerald-500/20">
                <CardContent className="py-3 px-4">
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div>
                      <p className="text-lg font-bold text-emerald-400">
                        {preview?.scope?.assets?.length || 0}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Scope Assets
                      </p>
                    </div>
                    <div>
                      <p className="text-lg font-bold text-amber-400">
                        {preview?.phases?.length || 0}
                      </p>
                      <p className="text-xs text-muted-foreground">Phases</p>
                    </div>
                    <div>
                      <p className="text-lg font-bold text-purple-400">
                        {preview?.roe?.prohibitedActions?.length || 0}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        ROE Rules
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            <DialogFooter className="gap-2">
              <Button variant="outline" onClick={() => setStep("preview")}>
                Back
              </Button>
              <Button onClick={handleCreate}>
                <Rocket className="h-4 w-4 mr-1" />
                Create Engagement
              </Button>
            </DialogFooter>
          </>
        )}

        {/* ─── Step 5: Creating ─── */}
        {step === "creating" && (
          <div className="py-12 text-center">
            <Loader2 className="h-12 w-12 animate-spin mx-auto mb-4 text-emerald-400" />
            <h3 className="text-lg font-semibold mb-2">
              Creating Engagement...
            </h3>
            <p className="text-sm text-muted-foreground">
              Building the engagement, inserting scope assets, creating timeline
              phases, and configuring the test environment.
            </p>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
