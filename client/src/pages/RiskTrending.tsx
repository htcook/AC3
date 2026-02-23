import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { ShieldCheck, TrendingUp, AlertTriangle, Clock, Target, Trash2, PlusCircle, Loader2, Info, LineChart } from "lucide-react";

const StatCard = ({ title, value, icon: Icon, change, unit }) => (
  <Card className="bg-slate-800/50 border-slate-700">
    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
      <CardTitle className="text-sm font-medium text-slate-300">{title}</CardTitle>
      <Icon className="h-4 w-4 text-slate-400" />
    </CardHeader>
    <CardContent>
      <div className="text-2xl font-bold text-white">{value}{unit}</div>
      {change && <p className="text-xs text-slate-400">{change}</p>}
    </CardContent>
  </Card>
);

const CreateSnapshotForm = ({ setOpen }) => {
  const [overallScore, setOverallScore] = useState(0);
  const utils = trpc.useUtils();

  const createSnapshotMutation = trpc.riskTrending.createSnapshot.useMutation({
    onSuccess: () => {
      toast.success("Snapshot created successfully.");
      utils.riskTrending.listSnapshots.invalidate();
      utils.riskTrending.getLatest.invalidate();
      utils.riskTrending.getTrend.invalidate();
      setOpen(false);
    },
    onError: (error) => {
      toast.error("Failed to create snapshot:", { description: error.message });
    },
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    createSnapshotMutation.mutate({ overallScore });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <Label htmlFor="overallScore" className="text-slate-300">Overall Risk Score</Label>
        <Input
          id="overallScore"
          type="number"
          value={overallScore}
          onChange={(e) => setOverallScore(Number(e.target.value))}
          className="bg-slate-700 border-slate-600 text-white"
          required
        />
      </div>
      <DialogFooter>
        <Button type="submit" disabled={createSnapshotMutation.isPending}>
          {createSnapshotMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
          Create Snapshot
        </Button>
      </DialogFooter>
    </form>
  );
};

export default function RiskTrending() {
  const [isCreateDialogOpen, setCreateDialogOpen] = useState(false);

  const { data: latestSnapshot, isLoading: isLoadingLatest, error: latestError } = trpc.riskTrending.getLatest.useQuery();
  const { data: trendData, isLoading: isLoadingTrend, error: trendError } = trpc.riskTrending.getTrend.useQuery({ days: 30 });
  const { data: snapshots, isLoading: isLoadingSnapshots, error: snapshotsError } = trpc.riskTrending.listSnapshots.useQuery({});

  const utils = trpc.useUtils();

  const deleteSnapshotMutation = trpc.riskTrending.deleteSnapshot.useMutation({
    onSuccess: () => {
      toast.success("Snapshot deleted.");
      utils.riskTrending.listSnapshots.invalidate();
      utils.riskTrending.getLatest.invalidate();
      utils.riskTrending.getTrend.invalidate();
    },
    onError: (error) => {
      toast.error("Failed to delete snapshot:", { description: error.message });
    },
  });

  const handleDelete = useCallback((id: string) => {
    if (window.confirm("Are you sure you want to delete this snapshot?")) {
      deleteSnapshotMutation.mutate({ id });
    }
  }, [deleteSnapshotMutation]);

  const summaryStats = useMemo(() => {
    if (!latestSnapshot) return [];
    return [
      { title: "Overall Risk Score", value: latestSnapshot.overallScore, icon: ShieldCheck, change: "↑ 2.1% from last month" },
      { title: "Detection Coverage", value: latestSnapshot.detectionCoveragePercent, unit: '%', icon: Target, change: "↑ 5% from last month" },
      { title: "Prevention Coverage", value: latestSnapshot.preventionCoveragePercent, unit: '%', icon: ShieldCheck, change: "↓ 1% from last month" },
      { title: "Critical Vulnerabilities", value: latestSnapshot.criticalVulnCount, icon: AlertTriangle, change: "↓ 12 from last month" },
      { title: "Mean Time to Detect", value: `${(latestSnapshot.meanTimeToDetectMs / 3600000).toFixed(1)}h`, icon: Clock, change: "↓ 0.5h from last month" },
      { title: "Mean Time to Respond", value: `${(latestSnapshot.meanTimeToRespondMs / 3600000).toFixed(1)}h`, icon: Clock, change: "↑ 1.2h from last month" },
    ];
  }, [latestSnapshot]);

  return (
    <div className="min-h-screen bg-slate-900 text-white p-8 space-y-6">
      <Card className="bg-slate-800/50 border-slate-700">
        <CardContent className="pt-6">
          <div className="flex items-center space-x-3">
            <Info className="h-5 w-5 text-blue-400" />
            <p className="text-slate-300">
              This executive dashboard provides a high-level overview of the organization's security posture over time. It visualizes key risk metrics, coverage percentages, and operational efficiency to track trends and inform strategic decisions.
            </p>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        {isLoadingLatest ? (
          Array.from({ length: 6 }).map((_, i) => (
            <Card key={i} className="bg-slate-800/50 border-slate-700 h-28 animate-pulse" />
          ))
        ) : latestError ? (
          <div className="col-span-full text-red-400">Error loading latest stats: {latestError.message}</div>
        ) : (
          summaryStats.map(stat => <StatCard key={stat.title} {...stat} />)
        )}
      </div>

      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="flex items-center"><LineChart className="mr-2 h-5 w-5" />Risk Score Trend (Last 30 Days)</CardTitle>
          <CardDescription className="text-slate-400">Visualizing the overall risk score trend over the past month.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-72 flex items-center justify-center bg-slate-900/50 rounded-lg border-2 border-dashed border-slate-700">
            {isLoadingTrend ? (
              <Loader2 className="h-8 w-8 animate-spin text-slate-500" />
            ) : trendError ? (
              <div className="text-red-400">Error loading trend data: {trendError.message}</div>
            ) : (
              <div className="text-center text-slate-400">
                <p className="text-lg font-semibold">Chart Placeholder</p>
                <p className="text-sm">Data points for the last 30 days would be rendered here.</p>
                <pre className="mt-4 text-xs text-left bg-slate-800 p-2 rounded-md overflow-auto max-h-40">
                  {JSON.stringify(trendData, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Snapshot History</CardTitle>
            <CardDescription className="text-slate-400">A log of all manually and automatically generated risk snapshots.</CardDescription>
          </div>
          <Dialog open={isCreateDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button><PlusCircle className="mr-2 h-4 w-4" />Create Snapshot</Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[425px] bg-slate-800 border-slate-700 text-white">
              <DialogHeader>
                <DialogTitle>Create New Snapshot</DialogTitle>
                <DialogDescription className="text-slate-400">
                  Manually create a new risk snapshot. Only the overall score is required.
                </DialogDescription>
              </DialogHeader>
              <CreateSnapshotForm setOpen={setCreateDialogOpen} />
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="border-slate-700 hover:bg-slate-800/60">
                <TableHead className="text-white">Date</TableHead>
                <TableHead className="text-white">Risk Score</TableHead>
                <TableHead className="text-white">Detection %</TableHead>
                <TableHead className="text-white">Prevention %</TableHead>
                <TableHead className="text-white">Critical Vulns</TableHead>
                <TableHead className="text-white">Source</TableHead>
                <TableHead className="text-right text-white">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoadingSnapshots ? (
                <TableRow><TableCell colSpan={7} className="text-center"><Loader2 className="inline-block h-6 w-6 animate-spin text-slate-500" /></TableCell></TableRow>
              ) : snapshotsError ? (
                <TableRow><TableCell colSpan={7} className="text-center text-red-400">Error: {snapshotsError.message}</TableCell></TableRow>
              ) : snapshots && snapshots.length > 0 ? (
                snapshots.map((snapshot) => (
                  <TableRow key={snapshot.id} className="border-slate-700 hover:bg-slate-800/60">
                    <TableCell>{new Date(snapshot.createdAt).toLocaleDateString()}</TableCell>
                    <TableCell className="font-medium">{snapshot.overallScore}</TableCell>
                    <TableCell>{snapshot.detectionCoveragePercent ?? 'N/A'}</TableCell>
                    <TableCell>{snapshot.preventionCoveragePercent ?? 'N/A'}</TableCell>
                    <TableCell>{snapshot.criticalVulnCount ?? 'N/A'}</TableCell>
                    <TableCell>{snapshot.source ?? 'N/A'}</TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" onClick={() => handleDelete(snapshot.id)} disabled={deleteSnapshotMutation.isPending && deleteSnapshotMutation.variables?.id === snapshot.id}>
                        <Trash2 className="h-4 w-4 text-red-500" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow><TableCell colSpan={7} className="text-center text-slate-400">No snapshots found.</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
