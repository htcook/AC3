import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Brain, Database, Cpu, TrendingUp, RefreshCw, Play, Download,
  CheckCircle2, Clock, AlertTriangle, Zap, GraduationCap,
  BarChart3, FileJson, Upload,
} from "lucide-react";

const MODEL_LABELS: Record<string, string> = {
  recon_analyst: "Recon Analyst",
  exploit_selector: "Exploit Selector",
  evasion_optimizer: "Evasion Optimizer",
  lateral_planner: "Lateral Planner",
  persistence_engineer: "Persistence Engineer",
  cognitive_core: "Cognitive Core",
};

const MODEL_COLORS: Record<string, string> = {
  recon_analyst: "text-blue-400",
  exploit_selector: "text-red-400",
  evasion_optimizer: "text-purple-400",
  lateral_planner: "text-amber-400",
  persistence_engineer: "text-emerald-400",
  cognitive_core: "text-cyan-400",
};

export default function TestLabTraining() {
  // toast from sonner is already imported
  const [selectedModel, setSelectedModel] = useState<string>("recon_analyst");

  const { data: trainingStatus, isLoading, refetch } = trpc.testLab.getTrainingStatus.useQuery();
  const { data: graduation } = trpc.testLab.getGraduationStatus.useQuery();

  const generateDataset = trpc.testLab.generateDataset.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.exampleCount ?? 0} examples for ${selectedModel}`);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const startFineTune = trpc.testLab.startFineTuning.useMutation({
    onSuccess: (data) => {
      toast.success(`Job ${data.jobId?.slice(0, 8)} is running`);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const runBenchmark = trpc.testLab.runBenchmark.useMutation({
    onSuccess: (data) => {
      toast.success(`Score: ${data.averageScore ?? 0}%`);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const promoteModel = trpc.testLab.promoteModel.useMutation({
    onSuccess: () => {
      toast.success(`${MODEL_LABELS[selectedModel]} promoted to production`);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const models = Object.keys(MODEL_LABELS);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 rounded-lg">
            <Brain className="h-7 w-7 text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">LLM Training Pipeline</h1>
            <p className="text-muted-foreground">
              Train and fine-tune specialist models for Ember's cognitive core
            </p>
          </div>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      {/* Pipeline Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="border-blue-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Training Examples</p>
                <p className="text-3xl font-bold">{trainingStatus?.totalExamples ?? 0}</p>
              </div>
              <Database className="h-8 w-8 text-blue-400 opacity-50" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-emerald-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Datasets</p>
                <p className="text-3xl font-bold">{trainingStatus?.totalDatasets ?? 0}</p>
              </div>
              <FileJson className="h-8 w-8 text-emerald-400 opacity-50" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-amber-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Fine-Tune Jobs</p>
                <p className="text-3xl font-bold">{trainingStatus?.totalFineTuneJobs ?? 0}</p>
              </div>
              <Cpu className="h-8 w-8 text-amber-400 opacity-50" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-purple-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Active Jobs</p>
                <p className="text-3xl font-bold">{trainingStatus?.activeJobs ?? 0}</p>
              </div>
              <Zap className="h-8 w-8 text-purple-400 opacity-50" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Specialist Model Cards */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Cpu className="h-5 w-5" />
            Specialist Models
          </CardTitle>
          <CardDescription>Select a model to manage training, fine-tuning, and benchmarking</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
            {models.map(model => {
              const config = trainingStatus?.specialistModels?.find((m: any) => m.model === model);
              const gradState = graduation?.modelStates?.find((m: any) => m.model === model);
              return (
                <button
                  key={model}
                  onClick={() => setSelectedModel(model)}
                  className={`p-3 rounded-lg border text-left transition-all ${
                    selectedModel === model
                      ? "border-primary bg-primary/5"
                      : "border-muted hover:border-muted-foreground/30"
                  }`}
                >
                  <p className={`text-xs font-medium ${MODEL_COLORS[model]}`}>
                    {MODEL_LABELS[model]}
                  </p>
                  <p className="text-lg font-bold mt-1">{config?.trainingExampleCount ?? 0}</p>
                  <p className="text-xs text-muted-foreground">examples</p>
                  {gradState && (
                    <Badge variant="outline" className="mt-1 text-xs">
                      Tier {gradState.currentTier ?? 1}
                    </Badge>
                  )}
                </button>
              );
            })}
          </div>

          {/* Selected Model Actions */}
          <div className="border-t pt-4">
            <h3 className="font-medium mb-3 flex items-center gap-2">
              <span className={MODEL_COLORS[selectedModel]}>
                {MODEL_LABELS[selectedModel]}
              </span>
              — Training Pipeline
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <Button
                variant="outline"
                className="h-auto py-4 flex-col gap-2"
                onClick={() => generateDataset.mutate({ specialistModel: selectedModel })}
                disabled={generateDataset.isPending}
              >
                {generateDataset.isPending ? (
                  <RefreshCw className="h-5 w-5 animate-spin" />
                ) : (
                  <Database className="h-5 w-5 text-blue-400" />
                )}
                <span className="text-xs">Generate Dataset</span>
              </Button>

              <Button
                variant="outline"
                className="h-auto py-4 flex-col gap-2"
                onClick={() => startFineTune.mutate({ specialistModel: selectedModel })}
                disabled={startFineTune.isPending}
              >
                {startFineTune.isPending ? (
                  <RefreshCw className="h-5 w-5 animate-spin" />
                ) : (
                  <Upload className="h-5 w-5 text-amber-400" />
                )}
                <span className="text-xs">Start Fine-Tuning</span>
              </Button>

              <Button
                variant="outline"
                className="h-auto py-4 flex-col gap-2"
                onClick={() => runBenchmark.mutate({ specialistModel: selectedModel })}
                disabled={runBenchmark.isPending}
              >
                {runBenchmark.isPending ? (
                  <RefreshCw className="h-5 w-5 animate-spin" />
                ) : (
                  <BarChart3 className="h-5 w-5 text-emerald-400" />
                )}
                <span className="text-xs">Run Benchmark</span>
              </Button>

              <Button
                variant="outline"
                className="h-auto py-4 flex-col gap-2"
                onClick={() => promoteModel.mutate({ specialistModel: selectedModel })}
                disabled={promoteModel.isPending}
              >
                {promoteModel.isPending ? (
                  <RefreshCw className="h-5 w-5 animate-spin" />
                ) : (
                  <TrendingUp className="h-5 w-5 text-purple-400" />
                )}
                <span className="text-xs">Promote to Prod</span>
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Graduation Bridge */}
      {graduation && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <GraduationCap className="h-5 w-5 text-amber-400" />
              Graduation Engine Bridge
            </CardTitle>
            <CardDescription>
              Model tier progression — higher tiers unlock harder scenarios and more capabilities
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {graduation.modelStates?.map((state: any) => (
                <div key={state.model} className="p-4 bg-muted/30 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className={`font-medium text-sm ${MODEL_COLORS[state.model] || ""}`}>
                      {MODEL_LABELS[state.model] || state.model}
                    </span>
                    <Badge variant={state.currentTier >= 4 ? "default" : "secondary"}>
                      Tier {state.currentTier}
                    </Badge>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-xs">
                      <span className="text-muted-foreground">Scenarios Completed</span>
                      <span>{state.scenariosCompleted ?? 0}</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-muted-foreground">Avg Score</span>
                      <span>{state.averageScore ?? 0}%</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-muted-foreground">Lab Access</span>
                      <Badge variant="outline" className="text-xs">{state.labAccess ?? "basic"}</Badge>
                    </div>
                    {/* Tier progress bar */}
                    <div className="mt-2">
                      <div className="flex gap-1">
                        {[1, 2, 3, 4, 5].map(tier => (
                          <div
                            key={tier}
                            className={`h-2 flex-1 rounded-full ${
                              tier <= (state.currentTier ?? 1) ? "bg-amber-400" : "bg-muted"
                            }`}
                          />
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
