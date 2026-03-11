// @ts-nocheck
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  ArrowLeft, Shield, Target, AlertTriangle, Brain, Globe, Server,
  ChevronDown, ChevronUp, Crosshair, Zap, FileText, ExternalLink,
  Activity, Lock, Eye, Network, Loader2, BarChart3, Bug, Skull, Database, Cpu,
  TrendingUp, Fingerprint, Radar, Info, Search, Radio, Scan, Flag, Undo2, MessageSquare,
  Download, FlaskConical, Mail, ShieldAlert, ShieldCheck, ShieldX, CheckCircle2, XCircle, RefreshCw,
  Layers, Play, Pause, Settings2, GitBranch, Link2, Users, Hash, Clock, Unplug, Wifi,
  Workflow, Lightbulb, Route, Telescope, ShieldQuestion, ArrowRightLeft, KeyRound,
  Box, ClipboardCheck, PackageSearch, GitCompareArrows
} from "lucide-react";

export default function ValidateTop10Banner({ scanId, validationSummary }: { scanId: number; validationSummary: any }) {
  const [showMsfSelect, setShowMsfSelect] = useState(false);
  const [selectedMsf, setSelectedMsf] = useState<string>("");
  const msfServersQuery = trpc.metasploit.listServers.useQuery(undefined, { enabled: showMsfSelect });
  const startRunMutation = trpc.validation.startRun.useMutation({
    onSuccess: (data) => {
      toast.success(`Validation run #${data.runId} started — validating ${data.totalCandidates} candidates in ${data.mode} mode`);
      setShowMsfSelect(false);
    },
    onError: (err) => {
      toast.error(`Validation failed: ${err.message}`);
    },
  });

  // If validation already exists for this scan, show summary instead
  if (validationSummary?.hasValidation) {
    const run = validationSummary.run;
    return (
      <Card className="border-emerald-500/30 bg-emerald-500/5">
        <CardContent className="p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-emerald-500/10">
              <FlaskConical className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <p className="font-semibold text-sm flex items-center gap-2">
                Exploit Validation Complete
                <Badge variant="outline" className="text-xs border-emerald-500/40 text-emerald-400">
                  {validationSummary.exploitableCount} exploitable
                </Badge>
                <Badge variant="outline" className="text-xs border-zinc-500/40 text-zinc-400">
                  {validationSummary.totalValidated} validated
                </Badge>
              </p>
              <p className="text-xs text-muted-foreground mt-0.5">
                {run?.mode === 'check_only' ? 'Non-destructive check' : run?.mode === 'safe_exploit' ? 'Safe exploit' : 'Auxiliary scan'} mode
                {run?.completedAt ? ` — completed ${new Date(run.completedAt).toLocaleString()}` : ''}
              </p>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="text-xs"
            onClick={() => window.location.href = '/validation-engine'}
          >
            <FlaskConical className="h-3.5 w-3.5 mr-1.5" /> View Full Results
          </Button>
        </CardContent>
      </Card>
    );
  }

  // Show the launch button
  return (
    <Card className="border-amber-500/30 bg-amber-500/5">
      <CardContent className="p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-amber-500/10">
            <FlaskConical className="h-5 w-5 text-amber-400" />
          </div>
          <div>
            <p className="font-semibold text-sm">Validate Top 10 Critical Findings</p>
            <p className="text-xs text-muted-foreground mt-0.5">
              Run safe, non-destructive exploit validation against the highest-confidence KEV matches and exploit module targets. Results feed directly into risk scores.
            </p>
          </div>
        </div>
        {!showMsfSelect ? (
          <Button
            className="bg-amber-600 hover:bg-amber-700 shrink-0 text-xs"
            size="sm"
            onClick={() => setShowMsfSelect(true)}
          >
            <FlaskConical className="h-3.5 w-3.5 mr-1.5" /> Validate Top 10
          </Button>
        ) : (
          <div className="flex items-center gap-2 shrink-0">
            <Select value={selectedMsf} onValueChange={setSelectedMsf}>
              <SelectTrigger className="w-44 h-8 text-xs">
                <SelectValue placeholder="Select C2 Server" />
              </SelectTrigger>
              <SelectContent>
                {(msfServersQuery.data || []).map((s: any) => (
                  <SelectItem key={s.id} value={String(s.id)}>
                    {s.name || s.host}
                  </SelectItem>
                ))}
                {(msfServersQuery.data || []).length === 0 && (
                  <SelectItem value="none" disabled>No servers configured</SelectItem>
                )}
              </SelectContent>
            </Select>
            <Button
              size="sm"
              className="bg-amber-600 hover:bg-amber-700 text-xs"
              disabled={!selectedMsf || selectedMsf === 'none' || startRunMutation.isPending}
              onClick={() => {
                startRunMutation.mutate({
                  scanId,
                  msfServerId: Number(selectedMsf),
                  mode: 'check_only',
                  maxCandidates: 10,
                });
              }}
            >
              {startRunMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
              ) : (
                <Zap className="h-3.5 w-3.5 mr-1.5" />
              )}
              Launch
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="text-xs"
              onClick={() => setShowMsfSelect(false)}
            >
              Cancel
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}


// ─── Accuracy Insights Tab Component ─────────────────────────────────


