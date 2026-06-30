import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import {
  AlertTriangle, RefreshCw, Search, Shield, Globe, Bug, Clock,
  ExternalLink, Copy, Filter, Download, Zap, Database, Activity,
  ChevronDown, ChevronRight, Radio, FileJson,
} from "lucide-react";

const SEVERITY_CONFIG: Record<string, { color: string; bg: string }> = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/20 border-red-500/30' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/20 border-orange-500/30' },
  medium: { color: 'text-amber-400', bg: 'bg-amber-500/20 border-amber-500/30' },
  low: { color: 'text-blue-400', bg: 'bg-blue-500/20 border-blue-500/30' },
  info: { color: 'text-gray-400', bg: 'bg-gray-500/20 border-gray-500/30' },
};

const SOURCE_CONFIG: Record<string, { label: string; icon: React.ComponentType<{className?: string}>; color: string }> = {
  cisa_kev: { label: 'KEV', icon: Shield, color: 'text-red-400' },
  alienvault_otx: { label: 'AlienVault OTX', icon: Globe, color: 'text-blue-400' },
  abusech_urlhaus: { label: 'threat intelligence feeds URLhaus', icon: Bug, color: 'text-green-400' },
};

export default function IOCFeed() {
  const [search, setSearch] = useState("");
  const [selectedSource, setSelectedSource] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [selectedType, setSelectedType] = useState<string | null>(null);

  const { data: feedEntries, isLoading, refetch } = trpc.iocFeed.list.useQuery({
    limit: 500,
    feedSource: selectedSource || undefined,
    severity: selectedSeverity || undefined,
  });

  const { data: stats } = trpc.iocFeed.stats.useQuery();

  const fetchCisaKev = trpc.iocFeed.fetchCisaKev.useMutation({
    onSuccess: (data) => { toast.success(`Fetched ${data.fetched} known exploited vulnerabilities (KEV) entries`); refetch(); },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const fetchAbuseCh = trpc.iocFeed.fetchAbuseCh.useMutation({
    onSuccess: (data) => { toast.success(`Fetched ${data.fetched} threat intelligence feeds entries`); refetch(); },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const fetchThreatFox = trpc.iocFeed.fetchThreatFox.useMutation({
    onSuccess: (data: any) => { toast.success(`Fetched ${data.fetched} malware indicator entries`); refetch(); },
    onError: (err: any) => toast.error(sanitizeErrorForToast(err)),
  });

  const fetchAllMutation = trpc.iocFeed.fetchAll.useMutation({
    onSuccess: (data: any) => { toast.success(`Fetched from ${data.results?.length || 0} sources`); refetch(); },
    onError: (err: any) => toast.error(sanitizeErrorForToast(err)),
  });

  const isFetching = fetchCisaKev.isPending || fetchAbuseCh.isPending || fetchThreatFox.isPending || fetchAllMutation.isPending;

  const fetchAll = () => {
    fetchAllMutation.mutate();
  };

  const entries = feedEntries?.entries || [];

  const filteredEntries = useMemo(() => {
    let result = entries;
    if (selectedType) {
      result = result.filter((e: any) => e.iocType === selectedType);
    }
    if (search) {
      const q = search.toLowerCase();
      result = result.filter((e: any) =>
        (e.title || '').toLowerCase().includes(q) ||
        (e.description || '').toLowerCase().includes(q) ||
        (e.iocValue || '').toLowerCase().includes(q) ||
        (e.cveId || '').toLowerCase().includes(q)
      );
    }
    return result;
  }, [entries, selectedType, search]);

  const iocTypes = useMemo(() => {
    const types = new Set(entries.map((e: any) => e.iocType).filter(Boolean));
    return Array.from(types).sort() as string[];
  }, [entries]);

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
              <Radio className="w-7 h-7 text-red-400 animate-pulse" />
              Live IOC Feed
            </h1>
            <p className="text-muted-foreground mt-1">
              Real-time threat intelligence from KEV, AlienVault OTX, and threat intelligence feeds
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              disabled={isLoading}
            >
              <RefreshCw className={`w-4 h-4 mr-1 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button
              size="sm"
              onClick={fetchAll}
              disabled={isFetching}
              className="bg-red-600 hover:bg-red-700"
            >
              <Download className={`w-4 h-4 mr-1 ${isFetching ? 'animate-spin' : ''}`} />
              Fetch All Sources
            </Button>
            <Link href="/stix-export">
              <Button size="sm" variant="outline" className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10">
                <FileJson className="w-4 h-4 mr-1" />
                STIX Export
              </Button>
            </Link>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-2 md:grid-cols-4 gap-2 sm:gap-3">
          <Card className="border-border/50">
            <CardContent className="p-4 flex items-center gap-3">
              <Database className="w-8 h-8 text-cyan-400" />
              <div>
                <p className="text-2xl font-bold">{stats?.total ?? entries.length}</p>
                <p className="text-xs text-muted-foreground">Total IOCs</p>
              </div>
            </CardContent>
          </Card>
          {Object.entries(SOURCE_CONFIG).map(([key, config]) => {
            const Icon = config.icon;
            const count = entries.filter((e: any) => e.feedSource === key).length;
            return (
              <Card key={key} className="border-border/50">
                <CardContent className="p-4 flex items-center gap-3">
                  <Icon className={`w-8 h-8 ${config.color}`} />
                  <div>
                    <p className="text-2xl font-bold">{count}</p>
                    <p className="text-xs text-muted-foreground">{config.label}</p>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Feed Source Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 sm:gap-4">
          <FeedSourceCard
            name="KEV"
            description="Known Exploited Vulnerabilities catalog — actively exploited CVEs requiring remediation"
            icon={Shield}
            color="text-red-400"
            onFetch={() => fetchCisaKev.mutate()}
            fetching={fetchCisaKev.isPending}
            count={entries.filter((e: any) => e.feedSource === 'cisa_kev').length}
          />
          <FeedSourceCard
            name="malware indicator feeds"
            description="threat intelligence feeds malware indicator feeds — IOCs associated with malware including C2, payloads, and configs"
            icon={Globe}
            color="text-blue-400"
            onFetch={() => fetchThreatFox.mutate()}
            fetching={fetchThreatFox.isPending}
            count={entries.filter((e: any) => e.feedSource === 'abusech_threatfox').length}
          />
          <FeedSourceCard
            name="threat intelligence feeds URLhaus"
            description="Malicious URL database — phishing, malware distribution, and C2 server URLs"
            icon={Bug}
            color="text-green-400"
            onFetch={() => fetchAbuseCh.mutate()}
            fetching={fetchAbuseCh.isPending}
            count={entries.filter((e: any) => e.feedSource === 'abusech_urlhaus').length}
          />
        </div>

        {/* Filters */}
        <Card className="border-border/50">
          <CardContent className="p-4">
            <div className="flex flex-wrap gap-3 items-center">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search IOCs, CVEs, descriptions..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9"
                />
              </div>
              <div className="flex gap-2 items-center">
                <Filter className="w-4 h-4 text-muted-foreground" />
                <select
                  value={selectedSource || ''}
                  onChange={(e) => setSelectedSource(e.target.value || null)}
                  className="bg-background border rounded px-3 py-2 text-sm"
                >
                  <option value="">All Sources</option>
                  {Object.entries(SOURCE_CONFIG).map(([key, config]) => (
                    <option key={key} value={key}>{config.label}</option>
                  ))}
                </select>
                <select
                  value={selectedSeverity || ''}
                  onChange={(e) => setSelectedSeverity(e.target.value || null)}
                  className="bg-background border rounded px-3 py-2 text-sm"
                >
                  <option value="">All Severities</option>
                  {['critical', 'high', 'medium', 'low', 'info'].map(s => (
                    <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                  ))}
                </select>
                <select
                  value={selectedType || ''}
                  onChange={(e) => setSelectedType(e.target.value || null)}
                  className="bg-background border rounded px-3 py-2 text-sm"
                >
                  <option value="">All Types</option>
                  {iocTypes.map(t => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Feed Entries */}
        <div className="space-y-2">
          {isLoading ? (
            <div className="text-center py-12 text-muted-foreground">
              <RefreshCw className="w-8 h-8 mx-auto mb-3 animate-spin" />
              <p>Loading IOC feed...</p>
            </div>
          ) : filteredEntries.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <AlertTriangle className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p className="text-lg font-semibold mb-2">No IOC entries found</p>
              <p className="text-sm mb-4">Click "Fetch All Sources" to pull the latest threat intelligence</p>
              <Button onClick={fetchAll} disabled={isFetching} className="bg-red-600 hover:bg-red-700">
                <Download className="w-4 h-4 mr-1" />
                Fetch All Sources
              </Button>
            </div>
          ) : (
            filteredEntries.map((entry: any) => (
              <IOCEntryCard key={entry.id} entry={entry} />
            ))
          )}
        </div>
      </div>
    </AppShell>
  );
}

function FeedSourceCard({ name, description, icon: Icon, color, onFetch, fetching, count }: {
  name: string; description: string; icon: React.ComponentType<{className?: string}>;
  color: string; onFetch: () => void; fetching: boolean; count: number;
}) {
  return (
    <Card className="border-border/50 hover:border-cyan-500/30 transition-colors">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <Icon className={`w-5 h-5 ${color}`} />
          {name}
          <Badge variant="secondary" className="ml-auto text-xs">{count} entries</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-xs text-muted-foreground mb-3">{description}</p>
        <Button
          variant="outline"
          size="sm"
          className="w-full"
          onClick={onFetch}
          disabled={fetching}
        >
          <Download className={`w-4 h-4 mr-1 ${fetching ? 'animate-spin' : ''}`} />
          {fetching ? 'Fetching...' : `Fetch Latest`}
        </Button>
      </CardContent>
    </Card>
  );
}

function IOCEntryCard({ entry }: { entry: any }) {
  const [expanded, setExpanded] = useState(false);
  const severity = SEVERITY_CONFIG[entry.severity] || SEVERITY_CONFIG.info;
  const source = SOURCE_CONFIG[entry.feedSource] || { label: entry.feedSource, icon: Activity, color: 'text-gray-400' };
  const SourceIcon = source.icon;

  return (
    <Card className={`border-l-2 ${severity.bg} border-border/30`}>
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <SourceIcon className={`w-5 h-5 mt-0.5 shrink-0 ${source.color}`} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <Badge variant="outline" className={`text-xs ${severity.bg}`}>{entry.severity}</Badge>
              <Badge variant="outline" className="text-xs">{source.label}</Badge>
              {entry.iocType && <Badge variant="secondary" className="text-xs font-mono">{entry.iocType}</Badge>}
              {entry.cveId && (
                <Badge variant="outline" className="text-xs font-mono text-red-400 border-red-500/30">
                  {entry.cveId}
                </Badge>
              )}
              <span className="text-[10px] text-muted-foreground ml-auto flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {entry.dateAdded ? new Date(entry.dateAdded).toLocaleDateString() : 'Unknown'}
              </span>
            </div>
            <h4 className="font-semibold text-sm mb-1">{entry.title}</h4>
            <p className={`text-xs text-muted-foreground ${expanded ? '' : 'line-clamp-2'}`}>{entry.description}</p>
            {entry.iocValue && (
              <div className="flex items-center gap-2 mt-2 bg-black/20 rounded px-2 py-1">
                <span className="text-xs font-mono text-foreground/80 break-all flex-1">{entry.iocValue}</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(entry.iocValue); toast.success("IOC copied"); }}
                  className="text-muted-foreground hover:text-foreground shrink-0"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
            {expanded && (
              <div className="mt-3 space-y-2 text-xs">
                {entry.affectedProduct && (
                  <div><span className="text-muted-foreground">Product:</span> {entry.affectedProduct}</div>
                )}
                {entry.affectedVendor && (
                  <div><span className="text-muted-foreground">Vendor:</span> {entry.affectedVendor}</div>
                )}
                {entry.sourceUrl && (
                  <a href={entry.sourceUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300">
                    <ExternalLink className="w-3 h-3" /> View Source
                  </a>
                )}
              </div>
            )}
            <button
              onClick={() => setExpanded(!expanded)}
              className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 mt-2"
            >
              {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
              {expanded ? 'Less' : 'More'}
            </button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
