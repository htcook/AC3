import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import {
  Download,
  FileText,
  Shield,
  Lock,
  Crosshair,
  ArrowUpDown,
  Network,
  Clock,
  BarChart3,
  Loader2,
} from "lucide-react";
import AppShell from "@/components/AppShell";

function downloadContent(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

interface ExportCardProps {
  title: string;
  description: string;
  icon: React.ReactNode;
  onExport: (format: "csv" | "json") => void;
  isLoading: boolean;
  count?: number;
}

function ExportCard({ title, description, icon, onExport, isLoading, count }: ExportCardProps) {
  const [format, setFormat] = useState<"csv" | "json">("csv");

  return (
    <Card className="border-zinc-800 bg-zinc-900/50">
      <CardHeader className="pb-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-zinc-800">{icon}</div>
          <div className="flex-1">
            <CardTitle className="text-sm font-medium text-zinc-100">{title}</CardTitle>
            <CardDescription className="text-xs text-zinc-500">{description}</CardDescription>
          </div>
          {count !== undefined && (
            <span className="text-xs font-mono text-emerald-400 bg-emerald-400/10 px-2 py-0.5 rounded">
              {count} records
            </span>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-2">
          <Select value={format} onValueChange={(v) => setFormat(v as "csv" | "json")}>
            <SelectTrigger className="w-24 h-8 text-xs bg-zinc-800 border-zinc-700">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="csv">CSV</SelectItem>
              <SelectItem value="json">JSON</SelectItem>
            </SelectContent>
          </Select>
          <Button
            size="sm"
            variant="outline"
            className="h-8 text-xs gap-1.5"
            onClick={() => onExport(format)}
            disabled={isLoading}
          >
            {isLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
            Export
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default function ExportCenter() {
  const [loadingKey, setLoadingKey] = useState<string | null>(null);
  const [counts, setCounts] = useState<Record<string, number>>({});

  const exportCredentials = trpc.reportExport.exportCredentials.useMutation({
    onSuccess: (data) => {
      downloadContent(data.content, data.filename, data.mimeType);
      setCounts((p) => ({ ...p, credentials: data.count }));
      toast.success(`Exported ${data.count} credential findings`);
      setLoadingKey(null);
    },
    onError: (err) => { toast.error(err.message); setLoadingKey(null); },
  });

  const exportTimeline = trpc.reportExport.exportTimeline.useMutation({
    onSuccess: (data) => {
      downloadContent(data.content, data.filename, data.mimeType);
      setCounts((p) => ({ ...p, timeline: data.count }));
      toast.success(`Exported ${data.count} timeline events`);
      setLoadingKey(null);
    },
    onError: (err) => { toast.error(err.message); setLoadingKey(null); },
  });

  const exportOpsec = trpc.reportExport.exportOpsec.useMutation({
    onSuccess: (data) => {
      downloadContent(data.content, data.filename, data.mimeType);
      setCounts((p) => ({ ...p, opsec: data.count }));
      toast.success(`Exported ${data.count} OPSEC events`);
      setLoadingKey(null);
    },
    onError: (err) => { toast.error(err.message); setLoadingKey(null); },
  });

  const exportExploits = trpc.reportExport.exportExploits.useMutation({
    onSuccess: (data) => {
      downloadContent(data.content, data.filename, data.mimeType);
      setCounts((p) => ({ ...p, exploits: data.count }));
      toast.success(`Exported ${data.count} exploitation attempts`);
      setLoadingKey(null);
    },
    onError: (err) => { toast.error(err.message); setLoadingKey(null); },
  });

  const exportPrivesc = trpc.reportExport.exportPrivesc.useMutation({
    onSuccess: (data) => {
      downloadContent(data.content, data.filename, data.mimeType);
      setCounts((p) => ({ ...p, privesc: data.count }));
      toast.success(`Exported ${data.count} privesc findings`);
      setLoadingKey(null);
    },
    onError: (err) => { toast.error(err.message); setLoadingKey(null); },
  });

  const exportLateral = trpc.reportExport.exportLateral.useMutation({
    onSuccess: (data) => {
      downloadContent(data.content, data.filename, data.mimeType);
      setCounts((p) => ({ ...p, lateral: data.count }));
      toast.success(`Exported ${data.count} lateral movement paths`);
      setLoadingKey(null);
    },
    onError: (err) => { toast.error(err.message); setLoadingKey(null); },
  });

  const exportSummary = trpc.reportExport.executiveSummary.useMutation({
    onSuccess: (data) => {
      downloadContent(data.content, data.filename, data.mimeType);
      toast.success("Executive summary exported");
      setLoadingKey(null);
    },
    onError: (err) => { toast.error(err.message); setLoadingKey(null); },
  });

  const exportCards = [
    {
      key: "summary",
      title: "Executive Summary",
      description: "High-level overview with key metrics across all modules",
      icon: <BarChart3 className="h-4 w-4 text-amber-400" />,
      onExport: (format: "csv" | "json") => { setLoadingKey("summary"); exportSummary.mutate({ format }); },
    },
    {
      key: "credentials",
      title: "Credential Findings",
      description: "All discovered credentials from Hydra, Medusa, NetExec, and built-in engine",
      icon: <Lock className="h-4 w-4 text-red-400" />,
      onExport: (format: "csv" | "json") => { setLoadingKey("credentials"); exportCredentials.mutate({ format }); },
    },
    {
      key: "timeline",
      title: "Engagement Timeline",
      description: "Unified timeline events across all kill chain phases",
      icon: <Clock className="h-4 w-4 text-blue-400" />,
      onExport: (format: "csv" | "json") => { setLoadingKey("timeline"); exportTimeline.mutate({ format }); },
    },
    {
      key: "opsec",
      title: "OPSEC Events",
      description: "Risk scores, detection technologies, burn indicators",
      icon: <Shield className="h-4 w-4 text-emerald-400" />,
      onExport: (format: "csv" | "json") => { setLoadingKey("opsec"); exportOpsec.mutate({ format }); },
    },
    {
      key: "exploits",
      title: "Exploitation Attempts",
      description: "CVE matches, exploit execution results, evidence captured",
      icon: <Crosshair className="h-4 w-4 text-orange-400" />,
      onExport: (format: "csv" | "json") => { setLoadingKey("exploits"); exportExploits.mutate({ format }); },
    },
    {
      key: "privesc",
      title: "Privilege Escalation Findings",
      description: "Windows, Linux, cloud, and Kerberos privesc vectors",
      icon: <ArrowUpDown className="h-4 w-4 text-purple-400" />,
      onExport: (format: "csv" | "json") => { setLoadingKey("privesc"); exportPrivesc.mutate({ format }); },
    },
    {
      key: "lateral",
      title: "Lateral Movement Paths",
      description: "Pivot routes, techniques, and credential usage across hosts",
      icon: <Network className="h-4 w-4 text-cyan-400" />,
      onExport: (format: "csv" | "json") => { setLoadingKey("lateral"); exportLateral.mutate({ format }); },
    },
  ];

  return (
      <AppShell activePath="/export-center">
      <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Export Center</h1>
        <p className="text-sm text-zinc-400 mt-1">
          Download pentest report artifacts as CSV or JSON. Each export pulls live data from the database
          and formats it for inclusion in engagement reports, compliance documentation, or external analysis tools.
        </p>
      </div>

      <div className="flex items-center gap-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
        <FileText className="h-5 w-5 text-amber-400 shrink-0" />
        <p className="text-xs text-amber-200">
          <strong>Tip:</strong> Start with the Executive Summary for a high-level overview, then export individual
          modules for detailed appendices. CSV exports are compatible with Excel, Google Sheets, and most SIEM platforms.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {exportCards.map((card) => (
          <ExportCard
            key={card.key}
            title={card.title}
            description={card.description}
            icon={card.icon}
            onExport={card.onExport}
            isLoading={loadingKey === card.key}
            count={counts[card.key]}
          />
        ))}
      </div>

      <Card className="border-zinc-800 bg-zinc-900/50">
        <CardHeader>
          <CardTitle className="text-sm font-medium text-zinc-100">Bulk Export</CardTitle>
          <CardDescription className="text-xs text-zinc-500">
            Export all data types at once as a combined package
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5"
              disabled={loadingKey === "bulk-csv"}
              onClick={() => {
                setLoadingKey("bulk-csv");
                Promise.all([
                  exportSummary.mutateAsync({ format: "csv" }),
                  exportCredentials.mutateAsync({ format: "csv" }),
                  exportTimeline.mutateAsync({ format: "csv" }),
                  exportOpsec.mutateAsync({ format: "csv" }),
                  exportExploits.mutateAsync({ format: "csv" }),
                  exportPrivesc.mutateAsync({ format: "csv" }),
                  exportLateral.mutateAsync({ format: "csv" }),
                ]).then((results) => {
                  results.forEach((r) => downloadContent(r.content, r.filename, r.mimeType));
                  toast.success("All CSV exports downloaded");
                  setLoadingKey(null);
                }).catch(() => { toast.error("Bulk export failed"); setLoadingKey(null); });
              }}
            >
              {loadingKey === "bulk-csv" ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
              Export All as CSV
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5"
              disabled={loadingKey === "bulk-json"}
              onClick={() => {
                setLoadingKey("bulk-json");
                Promise.all([
                  exportSummary.mutateAsync({ format: "json" }),
                  exportCredentials.mutateAsync({ format: "json" }),
                  exportTimeline.mutateAsync({ format: "json" }),
                  exportOpsec.mutateAsync({ format: "json" }),
                  exportExploits.mutateAsync({ format: "json" }),
                  exportPrivesc.mutateAsync({ format: "json" }),
                  exportLateral.mutateAsync({ format: "json" }),
                ]).then((results) => {
                  results.forEach((r) => downloadContent(r.content, r.filename, r.mimeType));
                  toast.success("All JSON exports downloaded");
                  setLoadingKey(null);
                }).catch(() => { toast.error("Bulk export failed"); setLoadingKey(null); });
              }}
            >
              {loadingKey === "bulk-json" ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
              Export All as JSON
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
      </AppShell>
  );
}
