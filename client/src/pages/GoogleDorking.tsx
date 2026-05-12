import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import {
  Search, Shield, AlertTriangle, Globe, ExternalLink, Play,
  CheckCircle, XCircle, Wifi, WifiOff, FolderOpen, FileWarning,
  Database, Lock, Server, Cloud, Code, Eye, Loader2, Copy,
  ChevronDown, ChevronUp,
} from "lucide-react";

// ─── Severity badge ────────────────────────────────────────────────────
function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-500 text-white",
    medium: "bg-yellow-500 text-black",
    low: "bg-blue-500 text-white",
    info: "bg-slate-500 text-white",
  };
  return (
    <Badge className={colors[severity?.toLowerCase()] || "bg-slate-500 text-white"}>
      {severity?.toUpperCase() || "UNKNOWN"}
    </Badge>
  );
}

// ─── Category icon mapping ─────────────────────────────────────────────
const categoryIcons: Record<string, React.ReactNode> = {
  exposed_panels: <Shield className="h-4 w-4" />,
  sensitive_files: <FileWarning className="h-4 w-4" />,
  directory_listings: <FolderOpen className="h-4 w-4" />,
  config_files: <Code className="h-4 w-4" />,
  database_exposure: <Database className="h-4 w-4" />,
  login_pages: <Lock className="h-4 w-4" />,
  error_messages: <AlertTriangle className="h-4 w-4" />,
  vulnerable_servers: <Server className="h-4 w-4" />,
  cloud_exposure: <Cloud className="h-4 w-4" />,
  api_exposure: <Globe className="h-4 w-4" />,
};

// ─── Overview Tab ──────────────────────────────────────────────────────
function OverviewTab() {
  const healthQ = trpc.googleDorking.health.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const categoriesQ = trpc.googleDorking.categories.useQuery(undefined, { staleTime: 300_000 });

  if (healthQ.isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-28 rounded-xl" />
        ))}
      </div>
    );
  }

  const health = healthQ.data;
  const categories = categoriesQ.data || [];

  return (
    <div className="space-y-6">
      {/* Connection Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              {health?.connected ? (
                <Wifi className="h-8 w-8 text-green-500" />
              ) : health?.configured ? (
                <WifiOff className="h-8 w-8 text-yellow-500" />
              ) : (
                <XCircle className="h-8 w-8 text-red-500" />
              )}
              <div>
                <p className="text-sm text-muted-foreground">API Status</p>
                <p className="text-lg font-semibold">
                  {health?.connected ? "Connected" : health?.configured ? "Configured (Not Connected)" : "Not Configured"}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Search className="h-8 w-8 text-blue-500" />
              <div>
                <p className="text-sm text-muted-foreground">Dork Templates</p>
                <p className="text-lg font-semibold">{health?.templateCount || 0}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <FolderOpen className="h-8 w-8 text-purple-500" />
              <div>
                <p className="text-sm text-muted-foreground">Categories</p>
                <p className="text-lg font-semibold">{categories.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* API Configuration Notice */}
      {!health?.configured && (
        <Card className="border-yellow-500/50 bg-yellow-500/5">
          <CardContent className="pt-6">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-yellow-500 mt-0.5" />
              <div>
                <p className="font-medium">Google Custom Search API Not Configured</p>
                <p className="text-sm text-muted-foreground mt-1">
                  To use live Google Dorking, set <code className="bg-muted px-1 rounded">GOOGLE_CSE_API_KEY</code> and{" "}
                  <code className="bg-muted px-1 rounded">GOOGLE_CSE_ID</code> environment variables.
                </p>
                <p className="text-sm text-muted-foreground mt-1">
                  Free tier: 100 queries/day. Get an API key from{" "}
                  <a href="https://console.cloud.google.com/apis/credentials" target="_blank" rel="noopener" className="text-blue-400 underline">
                    Google Cloud Console
                  </a>{" "}
                  and create a search engine at{" "}
                  <a href="https://programmablesearchengine.google.com/" target="_blank" rel="noopener" className="text-blue-400 underline">
                    Programmable Search Engine
                  </a>.
                </p>
                <p className="text-sm text-muted-foreground mt-1">
                  You can still browse templates and preview queries without an API key.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Category Grid */}
      <div>
        <h3 className="text-lg font-semibold mb-3">Dork Categories</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {categories.map((cat) => (
            <Card key={cat.id} className="hover:border-primary/50 transition-colors">
              <CardContent className="pt-4 pb-4">
                <div className="flex items-center gap-2 mb-1">
                  {categoryIcons[cat.id] || <Search className="h-4 w-4" />}
                  <span className="font-medium text-sm">{cat.name}</span>
                  <Badge variant="outline" className="ml-auto text-xs">{cat.count} dorks</Badge>
                </div>
                <p className="text-xs text-muted-foreground">{cat.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Templates Tab ─────────────────────────────────────────────────────
function TemplatesTab() {
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [previewDomain, setPreviewDomain] = useState("");
  const categoriesQ = trpc.googleDorking.categories.useQuery(undefined, { staleTime: 300_000 });
  const templatesQ = trpc.googleDorking.templates.useQuery(
    selectedCategory === "all" ? undefined : { category: selectedCategory },
    { staleTime: 300_000 }
  );

  const categories = categoriesQ.data || [];
  const templates = templatesQ.data || [];

  return (
    <div className="space-y-4">
      {/* Category Filter */}
      <div className="flex flex-wrap gap-2">
        <Button
          variant={selectedCategory === "all" ? "default" : "outline"}
          size="sm"
          onClick={() => setSelectedCategory("all")}
        >
          All ({categories.reduce((s, c) => s + c.count, 0)})
        </Button>
        {categories.map((cat) => (
          <Button
            key={cat.id}
            variant={selectedCategory === cat.id ? "default" : "outline"}
            size="sm"
            onClick={() => setSelectedCategory(cat.id)}
          >
            {categoryIcons[cat.id]}
            <span className="ml-1">{cat.name} ({cat.count})</span>
          </Button>
        ))}
      </div>

      {/* Preview Domain Input */}
      <div className="flex gap-2 items-center">
        <Input
          placeholder="Enter domain to preview queries (e.g., example.com)"
          value={previewDomain}
          onChange={(e) => setPreviewDomain(e.target.value)}
          className="max-w-md"
        />
        {previewDomain && (
          <span className="text-xs text-muted-foreground">
            Showing queries for <strong>{previewDomain}</strong>
          </span>
        )}
      </div>

      {/* Template List */}
      <div className="space-y-2">
        {templates.map((t) => (
          <TemplateRow key={t.id} template={t} domain={previewDomain} />
        ))}
        {templates.length === 0 && (
          <p className="text-muted-foreground text-center py-8">No templates found for this category.</p>
        )}
      </div>
    </div>
  );
}

function TemplateRow({ template, domain }: { template: any; domain: string }) {
  const [expanded, setExpanded] = useState(false);
  const { toast } = useToast();

  const resolvedQuery = domain
    ? template.query.replace(/\{\{domain\}\}/g, domain)
    : template.query;

  const copyQuery = () => {
    navigator.clipboard.writeText(resolvedQuery);
    toast({ title: "Copied", description: "Query copied to clipboard" });
  };

  return (
    <Card className="overflow-hidden">
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-muted/30 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <SeverityBadge severity={template.severity} />
        <span className="font-medium text-sm flex-1">{template.name}</span>
        {template.mitreTechnique && (
          <Badge variant="outline" className="text-xs font-mono">{template.mitreTechnique}</Badge>
        )}
        {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
      </div>
      {expanded && (
        <div className="px-4 pb-3 border-t border-border/50 pt-3 space-y-2">
          <p className="text-sm text-muted-foreground">{template.description}</p>
          <div className="bg-muted/50 rounded-md p-3 font-mono text-xs break-all flex items-start gap-2">
            <code className="flex-1">{resolvedQuery}</code>
            <Button variant="ghost" size="sm" className="h-6 w-6 p-0 shrink-0" onClick={copyQuery}>
              <Copy className="h-3 w-3" />
            </Button>
          </div>
          <div className="flex gap-2">
            <a
              href={`https://www.google.com/search?q=${encodeURIComponent(resolvedQuery)}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              <Button variant="outline" size="sm">
                <ExternalLink className="h-3 w-3 mr-1" /> Open in Google
              </Button>
            </a>
          </div>
        </div>
      )}
    </Card>
  );
}

// ─── Scan Tab ──────────────────────────────────────────────────────────
function ScanTab() {
  const [domain, setDomain] = useState("");
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const categoriesQ = trpc.googleDorking.categories.useQuery(undefined, { staleTime: 300_000 });
  const scanMut = trpc.googleDorking.runScan.useMutation();
  const { toast } = useToast();

  const categories = categoriesQ.data || [];

  const toggleCategory = (id: string) => {
    setSelectedCategories((prev) =>
      prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]
    );
  };

  const startScan = () => {
    if (!domain.trim()) {
      toast({ title: "Error", description: "Enter a target domain", variant: "destructive" });
      return;
    }
    scanMut.mutate({
      domain: domain.trim(),
      categories: selectedCategories.length > 0 ? selectedCategories : undefined,
      delayMs: 1200,
    });
  };

  const summary = scanMut.data?.summary;

  return (
    <div className="space-y-6">
      {/* Scan Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Domain Scan</CardTitle>
          <CardDescription>
            Run multiple dork queries against a target domain. Each query counts against the 100/day free tier limit.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              placeholder="Target domain (e.g., example.com)"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="max-w-md"
            />
            <Button onClick={startScan} disabled={scanMut.isPending || !domain.trim()}>
              {scanMut.isPending ? (
                <><Loader2 className="h-4 w-4 mr-1 animate-spin" /> Scanning...</>
              ) : (
                <><Play className="h-4 w-4 mr-1" /> Start Scan</>
              )}
            </Button>
          </div>

          {/* Category Selection */}
          <div>
            <p className="text-sm font-medium mb-2">
              Select categories (leave empty for all):
            </p>
            <div className="flex flex-wrap gap-2">
              {categories.map((cat) => (
                <Button
                  key={cat.id}
                  variant={selectedCategories.includes(cat.id) ? "default" : "outline"}
                  size="sm"
                  onClick={() => toggleCategory(cat.id)}
                >
                  {categoryIcons[cat.id]}
                  <span className="ml-1">{cat.name}</span>
                </Button>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Not Configured Warning */}
      {scanMut.data && !scanMut.data.configured && (
        <Card className="border-yellow-500/50 bg-yellow-500/5">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-yellow-500" />
              <p>Google CSE not configured. Set GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID to enable scanning.</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan Results */}
      {summary && (
        <div className="space-y-4">
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <Card>
              <CardContent className="pt-4 pb-4 text-center">
                <p className="text-2xl font-bold">{summary.totalFindings}</p>
                <p className="text-xs text-muted-foreground">Total Findings</p>
              </CardContent>
            </Card>
            <Card className="border-red-500/30">
              <CardContent className="pt-4 pb-4 text-center">
                <p className="text-2xl font-bold text-red-500">{summary.criticalCount}</p>
                <p className="text-xs text-muted-foreground">Critical</p>
              </CardContent>
            </Card>
            <Card className="border-orange-500/30">
              <CardContent className="pt-4 pb-4 text-center">
                <p className="text-2xl font-bold text-orange-500">{summary.highCount}</p>
                <p className="text-xs text-muted-foreground">High</p>
              </CardContent>
            </Card>
            <Card className="border-yellow-500/30">
              <CardContent className="pt-4 pb-4 text-center">
                <p className="text-2xl font-bold text-yellow-500">{summary.mediumCount}</p>
                <p className="text-xs text-muted-foreground">Medium</p>
              </CardContent>
            </Card>
            <Card className="border-blue-500/30">
              <CardContent className="pt-4 pb-4 text-center">
                <p className="text-2xl font-bold text-blue-500">{summary.lowCount}</p>
                <p className="text-xs text-muted-foreground">Low</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 pb-4 text-center">
                <p className="text-2xl font-bold text-slate-400">{summary.infoCount}</p>
                <p className="text-xs text-muted-foreground">Info</p>
              </CardContent>
            </Card>
          </div>

          {/* Individual Results */}
          <div className="space-y-3">
            <h3 className="text-lg font-semibold">Findings ({summary.results.length} dorks with results)</h3>
            {summary.results.map((r: any, i: number) => (
              <ScanResultCard key={i} result={r} />
            ))}
            {summary.results.length === 0 && (
              <Card>
                <CardContent className="pt-6 text-center">
                  <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-2" />
                  <p className="font-medium">No findings detected</p>
                  <p className="text-sm text-muted-foreground">
                    No Google-indexed results matched the dork queries for {summary.domain}.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ScanResultCard({ result }: { result: any }) {
  const [expanded, setExpanded] = useState(false);
  const template = result.dorkTemplate;

  return (
    <Card>
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-muted/30 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <SeverityBadge severity={template.severity} />
        <span className="font-medium text-sm flex-1">{template.name}</span>
        <Badge variant="outline">{result.totalResults} results</Badge>
        {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
      </div>
      {expanded && (
        <div className="px-4 pb-3 border-t border-border/50 pt-3 space-y-2">
          <p className="text-xs text-muted-foreground font-mono bg-muted/50 p-2 rounded">{result.query}</p>
          <div className="space-y-2">
            {result.results.slice(0, 10).map((r: any, i: number) => (
              <div key={i} className="border border-border/50 rounded-md p-3">
                <a
                  href={r.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm font-medium text-blue-400 hover:underline flex items-center gap-1"
                >
                  {r.title} <ExternalLink className="h-3 w-3" />
                </a>
                <p className="text-xs text-green-400 font-mono mt-0.5">{r.formattedUrl}</p>
                <p className="text-xs text-muted-foreground mt-1">{r.snippet}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}

// ─── Custom Query Tab ──────────────────────────────────────────────────
function CustomQueryTab() {
  const [query, setQuery] = useState("");
  const customMut = trpc.googleDorking.executeCustom.useMutation();
  const { toast } = useToast();

  const executeQuery = () => {
    if (!query.trim()) {
      toast({ title: "Error", description: "Enter a search query", variant: "destructive" });
      return;
    }
    customMut.mutate({ query: query.trim() });
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Custom Dork Query</CardTitle>
          <CardDescription>
            Execute any Google dork query using the Custom Search API. Use standard Google operators
            like <code className="bg-muted px-1 rounded">site:</code>,{" "}
            <code className="bg-muted px-1 rounded">intitle:</code>,{" "}
            <code className="bg-muted px-1 rounded">inurl:</code>,{" "}
            <code className="bg-muted px-1 rounded">filetype:</code>.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input
              placeholder='e.g., site:example.com filetype:pdf "confidential"'
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeQuery()}
              className="font-mono text-sm"
            />
            <Button onClick={executeQuery} disabled={customMut.isPending || !query.trim()}>
              {customMut.isPending ? (
                <><Loader2 className="h-4 w-4 mr-1 animate-spin" /> Searching...</>
              ) : (
                <><Search className="h-4 w-4 mr-1" /> Search</>
              )}
            </Button>
          </div>

          {/* Quick dork examples */}
          <div className="flex flex-wrap gap-1">
            <span className="text-xs text-muted-foreground mr-1">Quick:</span>
            {[
              'site:example.com intitle:"index of"',
              'site:example.com filetype:env',
              'site:example.com inurl:admin',
              'site:example.com "api_key="',
            ].map((q) => (
              <button
                key={q}
                className="text-xs bg-muted px-2 py-0.5 rounded hover:bg-muted/80 font-mono"
                onClick={() => setQuery(q)}
              >
                {q.length > 35 ? q.slice(0, 35) + "..." : q}
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Not Configured */}
      {customMut.data && !customMut.data.configured && (
        <Card className="border-yellow-500/50 bg-yellow-500/5">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-yellow-500" />
              <p>Google CSE not configured. Set GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID.</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Results */}
      {customMut.data?.results && customMut.data.results.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-semibold">Results</h3>
            <Badge variant="outline">{customMut.data.totalResults} total</Badge>
            {customMut.data.searchTime && (
              <span className="text-xs text-muted-foreground">({customMut.data.searchTime.toFixed(2)}s)</span>
            )}
          </div>
          {customMut.data.results.map((r: any, i: number) => (
            <Card key={i}>
              <CardContent className="pt-4 pb-4">
                <a
                  href={r.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm font-medium text-blue-400 hover:underline flex items-center gap-1"
                >
                  {r.title} <ExternalLink className="h-3 w-3" />
                </a>
                <p className="text-xs text-green-400 font-mono mt-0.5">{r.formattedUrl}</p>
                <p className="text-xs text-muted-foreground mt-1">{r.snippet}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {customMut.data?.results && customMut.data.results.length === 0 && !customMut.data.error && (
        <Card>
          <CardContent className="pt-6 text-center">
            <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-2" />
            <p className="font-medium">No results found</p>
            <p className="text-sm text-muted-foreground">The query returned no matching results.</p>
          </CardContent>
        </Card>
      )}

      {customMut.data?.error && (
        <Card className="border-red-500/50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <XCircle className="h-5 w-5 text-red-500" />
              <p className="text-sm">{customMut.data.error}</p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────
export default function GoogleDorkingPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Search className="h-6 w-6" /> Google Dorking
        </h1>
        <p className="text-muted-foreground mt-1">
          OSINT reconnaissance using Google Custom Search API. Discover exposed panels, sensitive files,
          misconfigurations, and more via automated dork queries.
        </p>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
          <TabsTrigger value="scan">Domain Scan</TabsTrigger>
          <TabsTrigger value="custom">Custom Query</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab />
        </TabsContent>
        <TabsContent value="templates">
          <TemplatesTab />
        </TabsContent>
        <TabsContent value="scan">
          <ScanTab />
        </TabsContent>
        <TabsContent value="custom">
          <CustomQueryTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
