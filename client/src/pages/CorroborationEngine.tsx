import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Shield, Search, CheckCircle, XCircle, AlertTriangle, HelpCircle, Loader2 } from "lucide-react";

const FINDING_TYPES = ["vulnerability", "credential", "domain", "ip", "indicator"] as const;
const SOURCE_OPTIONS = ["nvd", "shodan", "censys", "urlscan", "abuseipdb", "virustotal", "securitytrails", "dehashed"] as const;

const verdictConfig: Record<string, { color: string; icon: typeof CheckCircle; label: string }> = {
  confirmed: { color: "text-red-500", icon: CheckCircle, label: "Confirmed" },
  false_positive: { color: "text-green-500", icon: XCircle, label: "False Positive" },
  suspicious: { color: "text-yellow-500", icon: AlertTriangle, label: "Suspicious" },
  unverified: { color: "text-zinc-400", icon: HelpCircle, label: "Unverified" },
};

export default function CorroborationEngine() {
  const [findingType, setFindingType] = useState<string>("vulnerability");
  const [findingValue, setFindingValue] = useState("");
  const [selectedSources, setSelectedSources] = useState<string[]>([]);
  const [results, setResults] = useState<any>(null);

  const sourcesQuery = trpc.corroborationEngine.getSources.useQuery();
  const corroborateMut = trpc.corroborationEngine.corroborate.useMutation({
    onSuccess: (data) => {
      setResults(data);
      toast.success("Corroboration complete");
    },
    onError: (err) => toast.error(err.message),
  });

  const batchMut = trpc.corroborationEngine.batchCorroborate.useMutation({
    onSuccess: (data) => {
      setResults(data);
      toast.success(`Batch corroboration complete: ${data.total} findings analyzed`);
    },
    onError: (err) => toast.error(err.message),
  });

  const handleCorroborate = () => {
    if (!findingValue.trim()) { toast.error("Enter a finding value"); return; }
    corroborateMut.mutate({
      findingType: findingType as any,
      findingValue: findingValue.trim(),
      sources: selectedSources.length > 0 ? selectedSources as any : undefined,
    });
  };

  const toggleSource = (src: string) => {
    setSelectedSources(prev =>
      prev.includes(src) ? prev.filter(s => s !== src) : [...prev, src]
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Shield className="h-6 w-6 text-blue-500" />
          Cross-Source Corroboration Engine
        </h1>
        <p className="text-muted-foreground mt-1">
          Validate findings across multiple intelligence sources to reduce false positives by 30-40%.
        </p>
      </div>

      {/* Input Form */}
      <Card>
        <CardHeader>
          <CardTitle>Corroborate Finding</CardTitle>
          <CardDescription>Enter a finding to validate across intelligence sources</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-sm font-medium mb-1 block">Finding Type</label>
              <Select value={findingType} onValueChange={setFindingType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {FINDING_TYPES.map(t => (
                    <SelectItem key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="md:col-span-2">
              <label className="text-sm font-medium mb-1 block">Finding Value</label>
              <Input
                placeholder="e.g., CVE-2021-44228, 192.168.1.1, example.com"
                value={findingValue}
                onChange={e => setFindingValue(e.target.value)}
              />
            </div>
          </div>

          <div>
            <label className="text-sm font-medium mb-2 block">Intelligence Sources</label>
            <div className="flex flex-wrap gap-2">
              {SOURCE_OPTIONS.map(src => (
                <Badge
                  key={src}
                  variant={selectedSources.includes(src) ? "default" : "outline"}
                  className="cursor-pointer"
                  onClick={() => toggleSource(src)}
                >
                  {src}
                </Badge>
              ))}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {selectedSources.length === 0 ? "All sources will be queried" : `${selectedSources.length} source(s) selected`}
            </p>
          </div>

          <Button onClick={handleCorroborate} disabled={corroborateMut.isPending}>
            {corroborateMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Search className="h-4 w-4 mr-2" />}
            Corroborate
          </Button>
        </CardContent>
      </Card>

      {/* Available Sources */}
      {sourcesQuery.data && (
        <Card>
          <CardHeader>
            <CardTitle>Available Sources</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {sourcesQuery.data.map((src: any) => (
                <div key={src.name} className="flex items-center gap-2 p-2 rounded border">
                  <div className={`w-2 h-2 rounded-full ${src.available ? "bg-green-500" : "bg-zinc-400"}`} />
                  <span className="text-sm font-medium">{src.name}</span>
                  {src.requiresApiKey && <Badge variant="outline" className="text-xs">API Key</Badge>}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Results */}
      {results && !("total" in results && "results" in results && "confirmedCount" in results) && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              Corroboration Result
              {results.overallVerdict && (() => {
                const cfg = verdictConfig[results.overallVerdict] || verdictConfig.unverified;
                const Icon = cfg.icon;
                return <Badge className={cfg.color}><Icon className="h-3 w-3 mr-1" />{cfg.label}</Badge>;
              })()}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-3 rounded bg-muted">
                <div className="text-2xl font-bold">{results.confidenceScore ?? 0}%</div>
                <div className="text-xs text-muted-foreground">Confidence</div>
              </div>
              <div className="text-center p-3 rounded bg-muted">
                <div className="text-2xl font-bold">{results.sourcesQueried ?? 0}</div>
                <div className="text-xs text-muted-foreground">Sources Queried</div>
              </div>
              <div className="text-center p-3 rounded bg-muted">
                <div className="text-2xl font-bold">{results.sourcesConfirming ?? 0}</div>
                <div className="text-xs text-muted-foreground">Confirming</div>
              </div>
              <div className="text-center p-3 rounded bg-muted">
                <div className="text-2xl font-bold">{results.sourcesDenying ?? 0}</div>
                <div className="text-xs text-muted-foreground">Denying</div>
              </div>
            </div>

            {results.sourceResults && (
              <div className="space-y-2">
                <h4 className="font-medium">Source Details</h4>
                {results.sourceResults.map((sr: any, i: number) => (
                  <div key={i} className="flex items-center justify-between p-2 rounded border">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">{sr.source}</Badge>
                      <span className="text-sm">{sr.detail || "No detail"}</span>
                    </div>
                    <Badge variant={sr.verdict === "confirmed" ? "destructive" : sr.verdict === "denied" ? "default" : "secondary"}>
                      {sr.verdict}
                    </Badge>
                  </div>
                ))}
              </div>
            )}

            {results.reasoning && (
              <div className="p-3 rounded bg-muted">
                <h4 className="font-medium mb-1">Reasoning</h4>
                <p className="text-sm text-muted-foreground">{results.reasoning}</p>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
