import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import {
  CalendarClock, Plus, Play, Pause, Trash2, RefreshCw, Server,
  CheckCircle2, XCircle, Clock, Loader2, AlertTriangle,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

const SCANNER_TYPES = [
  { value: "nessus", label: "Nessus", color: "bg-green-500/20 text-green-400" },
  { value: "qualys", label: "Qualys", color: "bg-blue-500/20 text-blue-400" },
  { value: "rapid7", label: "Rapid7 InsightVM", color: "bg-orange-500/20 text-orange-400" },
  { value: "openvas", label: "OpenVAS", color: "bg-emerald-500/20 text-emerald-400" },
  { value: "burp", label: "Burp Suite", color: "bg-amber-500/20 text-amber-400" },
  { value: "zap", label: "OWASP ZAP", color: "bg-purple-500/20 text-purple-400" },
] as const;

const FREQUENCY_OPTIONS = [
  { value: "every_hour", label: "Every Hour" },
  { value: "every_2h", label: "Every 2 Hours" },
  { value: "every_6h", label: "Every 6 Hours" },
  { value: "every_12h", label: "Every 12 Hours" },
  { value: "every_day", label: "Daily" },
  { value: "every_week", label: "Weekly" },
] as const;

function statusBadge(status: string) {
  switch (status) {
    case "success": return <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30"><CheckCircle2 className="w-3 h-3 mr-1" /> Success</Badge>;
    case "failed": return <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30"><XCircle className="w-3 h-3 mr-1" /> Failed</Badge>;
    case "running": return <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/30"><Loader2 className="w-3 h-3 mr-1 animate-spin" /> Running</Badge>;
    default: return <Badge variant="outline" className="bg-zinc-500/10 text-zinc-400 border-zinc-500/30"><Clock className="w-3 h-3 mr-1" /> Never Run</Badge>;
  }
}

export default function ScanSchedules() {

  const utils = trpc.useUtils();
  const [showCreate, setShowCreate] = useState(false);

  // Form state
  const [name, setName] = useState("");
  const [scannerType, setScannerType] = useState<string>("nessus");
  const [apiUrl, setApiUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [scanId, setScanId] = useState("");
  const [cronExpression, setCronExpression] = useState("every_day");
  const [autoStart, setAutoStart] = useState(true);

  const { data: schedules, isLoading } = trpc.scanSchedules.list.useQuery();
  const { data: status } = trpc.scanSchedules.status.useQuery();

  const createMut = trpc.scanSchedules.create.useMutation({
    onSuccess: () => {
      toast.success("Schedule Created", { description: "Recurring scan import schedule has been created." });
      utils.scanSchedules.list.invalidate();
      utils.scanSchedules.status.invalidate();
      setShowCreate(false);
      resetForm();
    },
    onError: (err) => toast.error("Error", { description: err.message }),
  });

  const toggleMut = trpc.scanSchedules.toggle.useMutation({
    onSuccess: (data) => {
      toast.success(data.isActive ? "Schedule Activated" : "Schedule Paused");
      utils.scanSchedules.list.invalidate();
      utils.scanSchedules.status.invalidate();
    },
  });

  const runNowMut = trpc.scanSchedules.runNow.useMutation({
    onSuccess: () => {
      toast.success("Manual Run Triggered", { description: "The scan import is running now." });
      setTimeout(() => utils.scanSchedules.list.invalidate(), 3000);
    },
  });

  const deleteMut = trpc.scanSchedules.delete.useMutation({
    onSuccess: () => {
      toast.success("Schedule Deleted");
      utils.scanSchedules.list.invalidate();
      utils.scanSchedules.status.invalidate();
    },
  });

  function resetForm() {
    setName(""); setScannerType("nessus"); setApiUrl(""); setApiKey("");
    setUsername(""); setPassword(""); setScanId(""); setCronExpression("every_day"); setAutoStart(true);
  }

  function handleCreate() {
    createMut.mutate({
      name,
      scannerType: scannerType as any,
      connectionConfig: {
        apiUrl,
        ...(apiKey && { apiKey }),
        ...(username && { username }),
        ...(password && { password }),
        ...(scanId && { scanId }),
      },
      cronExpression,
      autoStart,
    });
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <CalendarClock className="w-6 h-6 text-emerald-400" />
            Scan Import Schedules
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Set up recurring scan report imports from scanner APIs. Schedules automatically fetch, parse, and import vulnerability findings at configured intervals.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
            <Server className="w-3 h-3 mr-1" />
            {status?.activeTimers ?? 0} Active Timers
          </Badge>
          <Dialog open={showCreate} onOpenChange={setShowCreate}>
            <DialogTrigger asChild>
              <Button size="sm"><Plus className="w-4 h-4 mr-1" /> New Schedule</Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Create Scan Schedule</DialogTitle>
                <DialogDescription>Configure a recurring scan import from a scanner API endpoint.</DialogDescription>
              </DialogHeader>
              <div className="space-y-4 mt-2">
                <div>
                  <Label>Schedule Name</Label>
                  <Input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Nightly Nessus Import" />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Scanner Type</Label>
                    <Select value={scannerType} onValueChange={setScannerType}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {SCANNER_TYPES.map(s => (
                          <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Frequency</Label>
                    <Select value={cronExpression} onValueChange={setCronExpression}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {FREQUENCY_OPTIONS.map(f => (
                          <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <Label>API URL</Label>
                  <Input value={apiUrl} onChange={e => setApiUrl(e.target.value)} placeholder="https://nessus.example.com:8834" />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>API Key</Label>
                    <Input value={apiKey} onChange={e => setApiKey(e.target.value)} placeholder="Access key" type="password" />
                  </div>
                  <div>
                    <Label>Scan/Report ID</Label>
                    <Input value={scanId} onChange={e => setScanId(e.target.value)} placeholder="Scan ID to fetch" />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Username (optional)</Label>
                    <Input value={username} onChange={e => setUsername(e.target.value)} placeholder="API username" />
                  </div>
                  <div>
                    <Label>Password (optional)</Label>
                    <Input value={password} onChange={e => setPassword(e.target.value)} placeholder="API password" type="password" />
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Switch checked={autoStart} onCheckedChange={setAutoStart} />
                  <Label>Auto-start on creation</Label>
                </div>
                <Button onClick={handleCreate} disabled={!name || !apiUrl || createMut.isPending} className="w-full">
                  {createMut.isPending ? <Loader2 className="w-4 h-4 mr-1 animate-spin" /> : <Plus className="w-4 h-4 mr-1" />}
                  Create Schedule
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold">{schedules?.length ?? 0}</div>
            <div className="text-xs text-muted-foreground">Total Schedules</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-green-400">{schedules?.filter(s => s.isActive).length ?? 0}</div>
            <div className="text-xs text-muted-foreground">Active</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-blue-400">{schedules?.reduce((a, s) => a + (s.totalRuns ?? 0), 0) ?? 0}</div>
            <div className="text-xs text-muted-foreground">Total Runs</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-amber-400">{schedules?.reduce((a, s) => a + (s.totalFindings ?? 0), 0) ?? 0}</div>
            <div className="text-xs text-muted-foreground">Total Findings</div>
          </CardContent>
        </Card>
      </div>

      {/* Schedule List */}
      {isLoading ? (
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-8 text-center">
            <Loader2 className="w-6 h-6 animate-spin mx-auto text-muted-foreground" />
          </CardContent>
        </Card>
      ) : !schedules?.length ? (
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-8 text-center">
            <CalendarClock className="w-10 h-10 mx-auto text-muted-foreground mb-3" />
            <p className="text-muted-foreground">No scan schedules configured yet.</p>
            <p className="text-xs text-muted-foreground mt-1">Create a schedule to automatically import scan reports from your vulnerability scanners.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {schedules.map(schedule => {
            const scannerInfo = SCANNER_TYPES.find(s => s.value === schedule.scannerType);
            const freqInfo = FREQUENCY_OPTIONS.find(f => f.value === schedule.cronExpression);
            const stats = schedule.lastRunStats as any;
            return (
              <Card key={schedule.id} className="bg-zinc-900/60 border-zinc-800">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${schedule.isActive ? 'bg-green-400 animate-pulse' : 'bg-zinc-600'}`} />
                      <div>
                        <div className="font-medium flex items-center gap-2">
                          {schedule.name}
                          <Badge variant="outline" className={scannerInfo?.color ?? ""}>{scannerInfo?.label ?? schedule.scannerType}</Badge>
                          {statusBadge(schedule.lastRunStatus)}
                        </div>
                        <div className="text-xs text-muted-foreground mt-0.5 flex items-center gap-3">
                          <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {freqInfo?.label ?? schedule.cronExpression}</span>
                          {schedule.engagementName && <span>→ {schedule.engagementName}</span>}
                          <span>{schedule.totalRuns} runs · {schedule.totalFindings} findings</span>
                          {schedule.lastRunAt && <span>Last: {new Date(schedule.lastRunAt).toLocaleString()}</span>}
                        </div>
                        {stats?.error && (
                          <div className="text-xs text-red-400 mt-1 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" /> {stats.error}
                          </div>
                        )}
                        {stats?.totalParsed != null && schedule.lastRunStatus === 'success' && (
                          <div className="text-xs text-green-400 mt-1">
                            Parsed: {stats.totalParsed} · Imported: {stats.imported} · Skipped: {stats.skipped}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => runNowMut.mutate({ id: schedule.id })}
                        disabled={runNowMut.isPending}
                      >
                        <Play className="w-3 h-3 mr-1" /> Run Now
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => toggleMut.mutate({ id: schedule.id })}
                        disabled={toggleMut.isPending}
                      >
                        {schedule.isActive ? <Pause className="w-3 h-3 mr-1" /> : <RefreshCw className="w-3 h-3 mr-1" />}
                        {schedule.isActive ? "Pause" : "Resume"}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="text-red-400 hover:text-red-300"
                        onClick={() => {
                          if (confirm("Delete this schedule?")) deleteMut.mutate({ id: schedule.id });
                        }}
                        disabled={deleteMut.isPending}
                      >
                        <Trash2 className="w-3 h-3" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
