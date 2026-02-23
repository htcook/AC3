import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { ShieldCheck, Search, Loader2, ChevronDown, ChevronUp } from "lucide-react";

export default function CompensatingControls() {
  const [cveId, setCveId] = useState("");
  const [techniqueId, setTechniqueId] = useState("");
  const [targetService, setTargetService] = useState("");
  const [existingControls, setExistingControls] = useState<string[]>([]);
  const [evalResult, setEvalResult] = useState<any>(null);
  const [expandedCatalog, setExpandedCatalog] = useState(false);

  const catalogQuery = trpc.compensatingControls.getCatalog.useQuery();

  const evaluateMut = trpc.compensatingControls.evaluate.useMutation({
    onSuccess: (data) => {
      setEvalResult(data);
      toast.success("Evaluation complete");
    },
    onError: (err) => toast.error(err.message),
  });

  const handleEvaluate = () => {
    if (!cveId.trim() && !techniqueId.trim()) {
      toast.error("Enter a CVE ID or ATT&CK technique ID");
      return;
    }
    evaluateMut.mutate({
      cveId: cveId.trim() || undefined,
      techniqueId: techniqueId.trim() || undefined,
      targetService: targetService.trim() || undefined,
      existingControls,
    });
  };

  const toggleControl = (controlId: string) => {
    setExistingControls(prev =>
      prev.includes(controlId) ? prev.filter(c => c !== controlId) : [...prev, controlId]
    );
  };

  const effectivenessColor = (score: number) => {
    if (score >= 80) return "text-green-500";
    if (score >= 50) return "text-yellow-500";
    return "text-red-500";
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <ShieldCheck className="h-6 w-6 text-green-500" />
          Compensating Control Awareness
        </h1>
        <p className="text-muted-foreground mt-1">
          Evaluate how existing security controls mitigate vulnerabilities and adjust risk scores accordingly.
        </p>
      </div>

      {/* Evaluation Form */}
      <Card>
        <CardHeader>
          <CardTitle>Evaluate Controls</CardTitle>
          <CardDescription>Assess compensating control effectiveness for a vulnerability or technique</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Input placeholder="CVE ID (e.g., CVE-2021-44228)" value={cveId} onChange={e => setCveId(e.target.value)} />
            <Input placeholder="ATT&CK Technique (e.g., T1190)" value={techniqueId} onChange={e => setTechniqueId(e.target.value)} />
            <Input placeholder="Target Service (e.g., apache)" value={targetService} onChange={e => setTargetService(e.target.value)} />
          </div>

          {catalogQuery.data && (
            <div>
              <label className="text-sm font-medium mb-2 block">Active Controls ({existingControls.length} selected)</label>
              <div className="flex flex-wrap gap-2">
                {catalogQuery.data.slice(0, expandedCatalog ? undefined : 12).map((ctrl: any) => (
                  <Badge
                    key={ctrl.id}
                    variant={existingControls.includes(ctrl.id) ? "default" : "outline"}
                    className="cursor-pointer"
                    onClick={() => toggleControl(ctrl.id)}
                  >
                    {ctrl.name}
                  </Badge>
                ))}
                {catalogQuery.data.length > 12 && (
                  <Button variant="ghost" size="sm" onClick={() => setExpandedCatalog(!expandedCatalog)}>
                    {expandedCatalog ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    {expandedCatalog ? "Less" : `+${catalogQuery.data.length - 12} more`}
                  </Button>
                )}
              </div>
            </div>
          )}

          <Button onClick={handleEvaluate} disabled={evaluateMut.isPending}>
            {evaluateMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Search className="h-4 w-4 mr-2" />}
            Evaluate
          </Button>
        </CardContent>
      </Card>

      {/* Evaluation Results */}
      {evalResult && (
        <Card>
          <CardHeader>
            <CardTitle>Evaluation Results</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-3 rounded bg-muted">
                <div className={`text-2xl font-bold ${effectivenessColor(evalResult.overallEffectiveness ?? 0)}`}>
                  {evalResult.overallEffectiveness ?? 0}%
                </div>
                <div className="text-xs text-muted-foreground">Overall Effectiveness</div>
              </div>
              <div className="text-center p-3 rounded bg-muted">
                <div className="text-2xl font-bold">{evalResult.adjustedRiskScore ?? "N/A"}</div>
                <div className="text-xs text-muted-foreground">Adjusted Risk Score</div>
              </div>
              <div className="text-center p-3 rounded bg-muted">
                <div className="text-2xl font-bold">{evalResult.matchingControls?.length ?? 0}</div>
                <div className="text-xs text-muted-foreground">Matching Controls</div>
              </div>
              <div className="text-center p-3 rounded bg-muted">
                <div className="text-2xl font-bold">{evalResult.gaps?.length ?? 0}</div>
                <div className="text-xs text-muted-foreground">Control Gaps</div>
              </div>
            </div>

            {evalResult.matchingControls && evalResult.matchingControls.length > 0 && (
              <div>
                <h4 className="font-medium mb-2">Matching Controls</h4>
                <div className="space-y-2">
                  {evalResult.matchingControls.map((ctrl: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-2 rounded border">
                      <div>
                        <span className="font-medium text-sm">{ctrl.name || ctrl.controlId}</span>
                        {ctrl.description && <p className="text-xs text-muted-foreground">{ctrl.description}</p>}
                      </div>
                      <Badge className={effectivenessColor(ctrl.effectiveness ?? 0)}>
                        {ctrl.effectiveness ?? 0}%
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {evalResult.gaps && evalResult.gaps.length > 0 && (
              <div>
                <h4 className="font-medium mb-2">Control Gaps</h4>
                <div className="space-y-1">
                  {evalResult.gaps.map((gap: string, i: number) => (
                    <div key={i} className="flex items-center gap-2 p-2 rounded border border-yellow-500/30 bg-yellow-500/5">
                      <Badge variant="outline" className="text-yellow-500">Gap</Badge>
                      <span className="text-sm">{gap}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {evalResult.recommendations && evalResult.recommendations.length > 0 && (
              <div className="p-3 rounded bg-muted">
                <h4 className="font-medium mb-2">Recommendations</h4>
                <ul className="space-y-1">
                  {evalResult.recommendations.map((rec: string, i: number) => (
                    <li key={i} className="text-sm text-muted-foreground">• {rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
