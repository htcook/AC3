import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Loader2, Globe, Search, Play, Shield, ShieldAlert, ShieldCheck,
  ExternalLink, ChevronRight, Clock, CheckCircle2, XCircle, AlertTriangle,
  Lock, Unlock, Server, Code, Eye, FileText, Cookie, Link2,
  ArrowRight, RefreshCw, ScanSearch, Radar, Bug, Layers, Network,
  ChevronDown, ChevronUp, Copy, BarChart3, GitCompare, TrendingUp, TrendingDown, Minus, Plus, ArrowUpRight, ArrowDownRight
} from "lucide-react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import AppShell from "@/components/AppShell";
import { useRoute } from "wouter";

// ─── Constants ───────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  high: "bg-red-500/20 text-red-400 border-red-500/30",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

const GRADE_COLORS: Record<string, string> = {
  "A+": "text-emerald-400 bg-emerald-500/20 border-emerald-500/30",
  "A": "text-emerald-400 bg-emerald-500/20 border-emerald-500/30",
  "B": "text-cyan-400 bg-cyan-500/20 border-cyan-500/30",
  "C": "text-amber-400 bg-amber-500/20 border-amber-500/30",
  "D": "text-orange-400 bg-orange-500/20 border-orange-500/30",
  "F": "text-red-400 bg-red-500/20 border-red-500/30",
};

// ─── Quick Scan Panel ────────────────────────────────────────────────────────

function QuickScanPanel() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<any>(null);

  const quickScan = trpc.webCrawler.quickScan.useMutation({
    onSuccess: (data) => {
      setResult(data);
      toast.success(`Scan complete — Grade: ${data.securityHeaderGrade}`);
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <div className="space-y-4">
      <div className="flex gap-3">
        <Input
          placeholder="https://example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="flex-1 bg-background/50 border-border/50"
          onKeyDown={(e) => e.key === "Enter" && url && quickScan.mutate({ url })}
        />
        <Button
          onClick={() => quickScan.mutate({ url })}
          disabled={!url || quickScan.isPending}
          className="bg-cyan-600 hover:bg-cyan-700 text-white"
        >
          {quickScan.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <ScanSearch className="w-4 h-4 mr-2" />}
          Quick Scan
        </Button>
      </div>

      {quickScan.isPending && (
        <Alert className="border-cyan-500/30 bg-cyan-500/5">
          <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
          <AlertDescription className="text-cyan-300">
            Scanning {url} — analyzing headers, technologies, exposed paths, and TLS configuration...
          </AlertDescription>
        </Alert>
      )}

      {result && <CrawlResultDetail result={result} />}
    </div>
  );
}

// ─── Domain Crawl Panel ──────────────────────────────────────────────────────

function DomainCrawlPanel() {
  const [domain, setDomain] = useState("");
  const [seedUrls, setSeedUrls] = useState("");
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxPages, setMaxPages] = useState(50);
  const [respectRobots, setRespectRobots] = useState(true);
  const [result, setResult] = useState<any>(null);
  const [showDialog, setShowDialog] = useState(false);

  const crawl = trpc.webCrawler.crawlDomain.useMutation({
    onSuccess: (data) => {
      setResult(data);
      setShowDialog(false);
      toast.success(`Crawl complete — ${data.totalUrlsCrawled} pages, ${data.totalFindings} findings`);
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <div className="space-y-4">
      <div className="flex gap-3 items-end">
        <div className="flex-1">
          <Label className="text-xs text-muted-foreground mb-1 block">Target Domain</Label>
          <Input
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            className="bg-background/50 border-border/50"
          />
        </div>
        <Dialog open={showDialog} onOpenChange={setShowDialog}>
          <DialogTrigger asChild>
            <Button variant="outline" className="border-border/50">
              <Layers className="w-4 h-4 mr-2" /> Configure
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-card border-border/50">
            <DialogHeader>
              <DialogTitle>Crawl Configuration</DialogTitle>
              <DialogDescription>Configure the crawl depth, page limits, and behavior.</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div>
                <Label className="text-xs text-muted-foreground">Seed URLs (one per line, optional)</Label>
                <textarea
                  className="w-full mt-1 p-2 bg-background/50 border border-border/50 rounded-md text-sm text-foreground resize-none"
                  rows={3}
                  placeholder="https://example.com/login&#10;https://example.com/api"
                  value={seedUrls}
                  onChange={(e) => setSeedUrls(e.target.value)}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-xs text-muted-foreground">Max Depth</Label>
                  <Input type="number" min={0} max={5} value={maxDepth} onChange={(e) => setMaxDepth(Number(e.target.value))} className="mt-1 bg-background/50 border-border/50" />
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Max Pages</Label>
                  <Input type="number" min={1} max={200} value={maxPages} onChange={(e) => setMaxPages(Number(e.target.value))} className="mt-1 bg-background/50 border-border/50" />
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Switch checked={respectRobots} onCheckedChange={setRespectRobots} />
                <Label className="text-sm">Respect robots.txt</Label>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowDialog(false)}>Cancel</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
        <Button
          onClick={() => crawl.mutate({
            domain,
            seedUrls: seedUrls.split("\n").filter(Boolean),
            maxDepth,
            maxPages,
            respectRobotsTxt: respectRobots,
          })}
          disabled={!domain || crawl.isPending}
          className="bg-red-600 hover:bg-red-700 text-white"
        >
          {crawl.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Radar className="w-4 h-4 mr-2" />}
          Start Crawl
        </Button>
      </div>

      {crawl.isPending && (
        <Alert className="border-red-500/30 bg-red-500/5">
          <Loader2 className="w-4 h-4 animate-spin text-red-400" />
          <AlertDescription className="text-red-300">
            Crawling {domain} — discovering pages, analyzing security posture, fingerprinting technologies...
            <br />
            <span className="text-xs text-muted-foreground">This may take 30-120 seconds depending on site size.</span>
          </AlertDescription>
        </Alert>
      )}

      {result && <CrawlJobSummary result={result} />}
    </div>
  );
}

// ─── Crawl Job Summary ───────────────────────────────────────────────────────

function CrawlJobSummary({ result }: { result: any }) {
  const [expandedPage, setExpandedPage] = useState<number | null>(null);

  return (
    <div className="space-y-4">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="bg-card/50 border-border/30">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-cyan-400">{result.totalUrlsCrawled}</div>
            <div className="text-xs text-muted-foreground">Pages Crawled</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/30">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-red-400">{result.totalFindings}</div>
            <div className="text-xs text-muted-foreground">Total Findings</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/30">
          <CardContent className="p-3 text-center">
            <Badge className={`text-lg px-3 py-1 ${GRADE_COLORS[result.securityGrade] || "text-gray-400 bg-gray-500/20"}`}>
              {result.securityGrade}
            </Badge>
            <div className="text-xs text-muted-foreground mt-1">Security Grade</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/30">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-amber-400">{result.technologiesSummary?.length || 0}</div>
            <div className="text-xs text-muted-foreground">Technologies</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/30">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-purple-400">{((result.completedAt - result.startedAt) / 1000).toFixed(1)}s</div>
            <div className="text-xs text-muted-foreground">Duration</div>
          </CardContent>
        </Card>
      </div>

      {/* Finding Breakdown */}
      <Card className="bg-card/50 border-border/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2"><ShieldAlert className="w-4 h-4 text-red-400" /> Finding Breakdown</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4 flex-wrap">
            {["critical", "high", "medium", "low", "info"].map((sev) => (
              <div key={sev} className="flex items-center gap-2">
                <Badge className={SEVERITY_COLORS[sev]}>{sev.toUpperCase()}</Badge>
                <span className="text-sm font-mono">{result.findingSummary?.[sev] || 0}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Technology Stack */}
      {result.technologiesSummary?.length > 0 && (
        <Card className="bg-card/50 border-border/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2"><Code className="w-4 h-4 text-cyan-400" /> Detected Technology Stack</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2 flex-wrap">
              {result.technologiesSummary.map((tech: any, i: number) => (
                <Badge key={i} variant="outline" className="border-border/50 text-xs">
                  {tech.name} {tech.version && <span className="text-muted-foreground ml-1">v{tech.version}</span>}
                  <span className="text-muted-foreground ml-1">({tech.category})</span>
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Pages List */}
      <Card className="bg-card/50 border-border/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2"><Globe className="w-4 h-4 text-cyan-400" /> Crawled Pages</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {result.pages?.map((page: any, i: number) => (
            <div key={i} className="border border-border/30 rounded-lg overflow-hidden">
              <button
                className="w-full flex items-center gap-3 p-3 hover:bg-muted/20 transition-colors text-left"
                onClick={() => setExpandedPage(expandedPage === i ? null : i)}
              >
                <Badge className={page.httpStatus < 400 ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400"}>
                  {page.httpStatus}
                </Badge>
                <Badge className={`text-xs ${GRADE_COLORS[page.securityHeaderGrade] || ""}`}>
                  {page.securityHeaderGrade}
                </Badge>
                <span className="text-sm font-mono truncate flex-1">{page.url}</span>
                <span className="text-xs text-muted-foreground">{page.responseTimeMs}ms</span>
                <span className="text-xs text-muted-foreground">{page.findings?.length || 0} findings</span>
                {expandedPage === i ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedPage === i && (
                <div className="border-t border-border/30 p-3">
                  <CrawlResultDetail result={page} />
                </div>
              )}
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Crawl Result Detail ─────────────────────────────────────────────────────

function CrawlResultDetail({ result }: { result: any }) {
  const [activeTab, setActiveTab] = useState("overview");

  return (
    <Tabs value={activeTab} onValueChange={setActiveTab}>
      <TabsList className="bg-muted/20 border border-border/30">
        <TabsTrigger value="overview">Overview</TabsTrigger>
        <TabsTrigger value="headers">Headers</TabsTrigger>
        <TabsTrigger value="tech">Technologies</TabsTrigger>
        <TabsTrigger value="findings">Findings ({result.findings?.length || 0})</TabsTrigger>
        <TabsTrigger value="links">Links</TabsTrigger>
        <TabsTrigger value="forms">Forms</TabsTrigger>
        {result.exposedPaths?.length > 0 && <TabsTrigger value="paths">Exposed Paths</TabsTrigger>}
        {result.cookies?.length > 0 && <TabsTrigger value="cookies">Cookies</TabsTrigger>}
        {result.tlsInfo && <TabsTrigger value="tls">TLS</TabsTrigger>}
      </TabsList>

      {/* Overview Tab */}
      <TabsContent value="overview" className="space-y-3 mt-3">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="p-3 bg-muted/10 rounded-lg border border-border/20">
            <div className="text-xs text-muted-foreground">HTTP Status</div>
            <div className={`text-lg font-bold ${result.httpStatus < 400 ? "text-emerald-400" : "text-red-400"}`}>{result.httpStatus}</div>
          </div>
          <div className="p-3 bg-muted/10 rounded-lg border border-border/20">
            <div className="text-xs text-muted-foreground">Security Grade</div>
            <Badge className={`text-lg mt-1 ${GRADE_COLORS[result.securityHeaderGrade] || ""}`}>{result.securityHeaderGrade}</Badge>
          </div>
          <div className="p-3 bg-muted/10 rounded-lg border border-border/20">
            <div className="text-xs text-muted-foreground">Response Time</div>
            <div className="text-lg font-bold text-cyan-400">{result.responseTimeMs}ms</div>
          </div>
          <div className="p-3 bg-muted/10 rounded-lg border border-border/20">
            <div className="text-xs text-muted-foreground">Content Type</div>
            <div className="text-sm font-mono truncate">{result.contentType?.split(";")[0]}</div>
          </div>
        </div>
        {result.pageTitle && (
          <div className="p-3 bg-muted/10 rounded-lg border border-border/20">
            <div className="text-xs text-muted-foreground mb-1">Page Title</div>
            <div className="text-sm">{result.pageTitle}</div>
          </div>
        )}
        {result.serverHeader && (
          <div className="p-3 bg-muted/10 rounded-lg border border-border/20">
            <div className="text-xs text-muted-foreground mb-1">Server</div>
            <div className="text-sm font-mono">{result.serverHeader} {result.poweredBy && `| X-Powered-By: ${result.poweredBy}`}</div>
          </div>
        )}
        {result.robotsTxt && (
          <div className="p-3 bg-muted/10 rounded-lg border border-border/20">
            <div className="text-xs text-muted-foreground mb-1">robots.txt</div>
            <pre className="text-xs font-mono text-muted-foreground max-h-32 overflow-auto whitespace-pre-wrap">{result.robotsTxt}</pre>
          </div>
        )}
        {result.securityTxt && (
          <div className="p-3 bg-muted/10 rounded-lg border border-border/20">
            <div className="text-xs text-muted-foreground mb-1">security.txt</div>
            <pre className="text-xs font-mono text-muted-foreground max-h-32 overflow-auto whitespace-pre-wrap">{result.securityTxt}</pre>
          </div>
        )}
      </TabsContent>

      {/* Security Headers Tab */}
      <TabsContent value="headers" className="space-y-3 mt-3">
        {result.securityHeaders?.present?.length > 0 && (
          <div>
            <h4 className="text-xs font-semibold text-emerald-400 mb-2 flex items-center gap-1"><ShieldCheck className="w-3 h-3" /> Present Headers</h4>
            <div className="space-y-1">
              {result.securityHeaders.present.map((h: any, i: number) => (
                <div key={i} className="flex items-center gap-2 p-2 bg-emerald-500/5 rounded border border-emerald-500/20">
                  <CheckCircle2 className={`w-3 h-3 ${h.status === "good" ? "text-emerald-400" : "text-amber-400"}`} />
                  <span className="text-xs font-mono font-semibold">{h.name}</span>
                  <span className="text-xs text-muted-foreground truncate flex-1">{h.value}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {result.securityHeaders?.missing?.length > 0 && (
          <div>
            <h4 className="text-xs font-semibold text-red-400 mb-2 flex items-center gap-1"><XCircle className="w-3 h-3" /> Missing Headers</h4>
            <div className="space-y-1">
              {result.securityHeaders.missing.map((h: any, i: number) => (
                <div key={i} className="flex items-center gap-2 p-2 bg-red-500/5 rounded border border-red-500/20">
                  <XCircle className="w-3 h-3 text-red-400" />
                  <Badge className={SEVERITY_COLORS[h.severity]} variant="outline">{h.severity}</Badge>
                  <span className="text-xs font-mono font-semibold">{h.name}</span>
                  <span className="text-xs text-muted-foreground">{h.description}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {result.securityHeaders?.misconfigured?.length > 0 && (
          <div>
            <h4 className="text-xs font-semibold text-amber-400 mb-2 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Misconfigured Headers</h4>
            <div className="space-y-1">
              {result.securityHeaders.misconfigured.map((h: any, i: number) => (
                <div key={i} className="flex items-start gap-2 p-2 bg-amber-500/5 rounded border border-amber-500/20">
                  <AlertTriangle className="w-3 h-3 text-amber-400 mt-0.5" />
                  <div>
                    <span className="text-xs font-mono font-semibold">{h.name}</span>
                    <div className="text-xs text-muted-foreground">{h.issue}</div>
                    <div className="text-xs text-muted-foreground font-mono mt-1">{h.value}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Raw Headers */}
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground mb-2">All Response Headers</h4>
          <div className="bg-muted/10 rounded-lg border border-border/20 p-3 max-h-48 overflow-auto">
            {Object.entries(result.rawHeaders || {}).map(([k, v]) => (
              <div key={k} className="text-xs font-mono">
                <span className="text-cyan-400">{k}:</span> <span className="text-muted-foreground">{String(v)}</span>
              </div>
            ))}
          </div>
        </div>
      </TabsContent>

      {/* Technologies Tab */}
      <TabsContent value="tech" className="mt-3">
        {result.detectedTechnologies?.length > 0 ? (
          <div className="space-y-2">
            {result.detectedTechnologies.map((tech: any, i: number) => (
              <div key={i} className="flex items-center gap-3 p-3 bg-muted/10 rounded-lg border border-border/20">
                <Code className="w-4 h-4 text-cyan-400" />
                <div className="flex-1">
                  <div className="text-sm font-semibold">{tech.name} {tech.version && <span className="text-muted-foreground font-normal">v{tech.version}</span>}</div>
                  <div className="text-xs text-muted-foreground">{tech.category}</div>
                </div>
                <div className="text-right">
                  <div className="text-xs text-muted-foreground">Confidence</div>
                  <Progress value={tech.confidence} className="w-20 h-1.5 mt-1" />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-muted-foreground text-sm">No technologies detected</div>
        )}
      </TabsContent>

      {/* Findings Tab */}
      <TabsContent value="findings" className="mt-3">
        {result.findings?.length > 0 ? (
          <div className="space-y-2">
            {result.findings.map((f: any, i: number) => (
              <div key={i} className="p-3 bg-muted/10 rounded-lg border border-border/20">
                <div className="flex items-center gap-2 mb-1">
                  <Badge className={SEVERITY_COLORS[f.severity]}>{f.severity.toUpperCase()}</Badge>
                  <span className="text-sm font-semibold">{f.title}</span>
                </div>
                <div className="text-xs text-muted-foreground mb-1">{f.description}</div>
                <div className="text-xs text-cyan-400/80">
                  <span className="font-semibold">Remediation:</span> {f.remediation}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-muted-foreground text-sm">No findings detected</div>
        )}
      </TabsContent>

      {/* Links Tab */}
      <TabsContent value="links" className="mt-3 space-y-3">
        <div>
          <h4 className="text-xs font-semibold text-cyan-400 mb-2 flex items-center gap-1"><Link2 className="w-3 h-3" /> Internal Links ({result.internalLinks?.length || 0})</h4>
          <div className="bg-muted/10 rounded-lg border border-border/20 p-3 max-h-48 overflow-auto space-y-1">
            {result.internalLinks?.slice(0, 50).map((link: string, i: number) => (
              <div key={i} className="text-xs font-mono text-muted-foreground truncate">{link}</div>
            ))}
            {(result.internalLinks?.length || 0) > 50 && (
              <div className="text-xs text-muted-foreground">... and {result.internalLinks.length - 50} more</div>
            )}
          </div>
        </div>
        <div>
          <h4 className="text-xs font-semibold text-amber-400 mb-2 flex items-center gap-1"><ExternalLink className="w-3 h-3" /> External Links ({result.externalLinks?.length || 0})</h4>
          <div className="bg-muted/10 rounded-lg border border-border/20 p-3 max-h-48 overflow-auto space-y-1">
            {result.externalLinks?.slice(0, 50).map((link: string, i: number) => (
              <div key={i} className="text-xs font-mono text-muted-foreground truncate">{link}</div>
            ))}
          </div>
        </div>
      </TabsContent>

      {/* Forms Tab */}
      <TabsContent value="forms" className="mt-3">
        {result.forms?.length > 0 ? (
          <div className="space-y-2">
            {result.forms.map((form: any, i: number) => (
              <div key={i} className="p-3 bg-muted/10 rounded-lg border border-border/20">
                <div className="flex items-center gap-2 mb-2">
                  <Badge variant="outline" className="border-border/50">{form.method}</Badge>
                  <span className="text-sm font-mono">{form.action || "(no action)"}</span>
                  {form.hasPasswordField && <Badge className="bg-red-500/20 text-red-400">Password Field</Badge>}
                  {form.hasFileUpload && <Badge className="bg-amber-500/20 text-amber-400">File Upload</Badge>}
                </div>
                <div className="flex gap-2 flex-wrap">
                  {form.inputs?.map((inp: any, j: number) => (
                    <Badge key={j} variant="outline" className="text-xs border-border/30">
                      {inp.name || "(unnamed)"} <span className="text-muted-foreground ml-1">{inp.type}</span>
                    </Badge>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-muted-foreground text-sm">No forms detected</div>
        )}
      </TabsContent>

      {/* Exposed Paths Tab */}
      <TabsContent value="paths" className="mt-3">
        <div className="space-y-2">
          {result.exposedPaths?.map((ep: any, i: number) => (
            <div key={i} className="flex items-center gap-3 p-3 bg-muted/10 rounded-lg border border-border/20">
              <Badge className={SEVERITY_COLORS[ep.severity]}>{ep.severity.toUpperCase()}</Badge>
              <span className="text-sm font-mono">{ep.path}</span>
              <Badge variant="outline" className="text-xs border-border/30">{ep.status}</Badge>
              <span className="text-xs text-muted-foreground flex-1">{ep.description}</span>
            </div>
          ))}
        </div>
      </TabsContent>

      {/* Cookies Tab */}
      <TabsContent value="cookies" className="mt-3">
        <div className="space-y-2">
          {result.cookies?.map((cookie: any, i: number) => (
            <div key={i} className="p-3 bg-muted/10 rounded-lg border border-border/20">
              <div className="flex items-center gap-2 mb-2">
                <Cookie className="w-4 h-4 text-amber-400" />
                <span className="text-sm font-mono font-semibold">{cookie.name}</span>
                {cookie.secure ? <Badge className="bg-emerald-500/20 text-emerald-400 text-xs">Secure</Badge> : <Badge className="bg-red-500/20 text-red-400 text-xs">No Secure</Badge>}
                {cookie.httpOnly ? <Badge className="bg-emerald-500/20 text-emerald-400 text-xs">HttpOnly</Badge> : <Badge className="bg-red-500/20 text-red-400 text-xs">No HttpOnly</Badge>}
                {cookie.sameSite && <Badge variant="outline" className="text-xs border-border/30">SameSite={cookie.sameSite}</Badge>}
              </div>
              {cookie.issues?.length > 0 && (
                <div className="space-y-1">
                  {cookie.issues.map((issue: string, j: number) => (
                    <div key={j} className="text-xs text-amber-400/80 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" /> {issue}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </TabsContent>

      {/* TLS Tab */}
      <TabsContent value="tls" className="mt-3">
        {result.tlsInfo && (
          <div className="space-y-2">
            {Object.entries(result.tlsInfo).map(([key, value]) => (
              <div key={key} className="flex items-center gap-3 p-2 bg-muted/10 rounded border border-border/20">
                <span className="text-xs font-mono text-cyan-400 w-32">{key}</span>
                <span className="text-xs font-mono text-muted-foreground truncate">{String(value || "—")}</span>
              </div>
            ))}
          </div>
        )}
      </TabsContent>
    </Tabs>
  );
}

// ─── History Panel ───────────────────────────────────────────────────────────

function HistoryPanel() {
  const { data: jobsData, isLoading } = trpc.webCrawler.listJobs.useQuery({ limit: 20, offset: 0 });

  if (isLoading) return <div className="flex items-center justify-center py-12"><Loader2 className="w-6 h-6 animate-spin text-cyan-400" /></div>;

  const jobs = jobsData?.jobs || [];

  if (jobs.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <ScanSearch className="w-12 h-12 mx-auto mb-3 opacity-30" />
        <p className="text-sm">No crawl history yet. Run a Quick Scan or Domain Crawl to get started.</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {jobs.map((job: any) => (
        <Card key={job.id} className="bg-card/50 border-border/30 hover:border-border/60 transition-colors">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Globe className="w-5 h-5 text-cyan-400" />
              <div className="flex-1">
                <div className="text-sm font-semibold">{job.targetDomain}</div>
                <div className="text-xs text-muted-foreground">
                  {new Date(job.createdAt).toLocaleString()} · {job.totalUrlsCrawled} pages · {job.totalFindings} findings
                </div>
              </div>
              <Badge className={`${GRADE_COLORS[job.securityGrade] || "text-gray-400 bg-gray-500/20"}`}>
                {job.securityGrade || "—"}
              </Badge>
              <Badge className={
                job.status === "completed" ? "bg-emerald-500/20 text-emerald-400" :
                job.status === "running" ? "bg-cyan-500/20 text-cyan-400" :
                job.status === "failed" ? "bg-red-500/20 text-red-400" :
                "bg-gray-500/20 text-gray-400"
              }>
                {job.status}
              </Badge>
            </div>
            {job.findingSummary && (
              <div className="flex gap-3 mt-2 ml-8">
                {["critical", "high", "medium", "low", "info"].map((sev) => (
                  job.findingSummary[sev] > 0 && (
                    <div key={sev} className="flex items-center gap-1">
                      <Badge className={`${SEVERITY_COLORS[sev]} text-xs`}>{sev[0].toUpperCase()}</Badge>
                      <span className="text-xs font-mono">{job.findingSummary[sev]}</span>
                    </div>
                  )
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Crawl Compare Panel ────────────────────────────────────────────────────

function CrawlComparePanel() {
  const [selectedDomain, setSelectedDomain] = useState<string>("");
  const [oldResultId, setOldResultId] = useState<string>("");
  const [newResultId, setNewResultId] = useState<string>("");

  const { data: comparableDomains, isLoading: domainsLoading } = trpc.webCrawler.comparableDomains.useQuery();
  const { data: crawlHistory } = trpc.webCrawler.crawlHistory.useQuery(
    { domain: selectedDomain },
    { enabled: !!selectedDomain },
  );
  const { data: comparison, isLoading: compareLoading, error: compareError } = trpc.webCrawler.compare.useQuery(
    { oldResultId: Number(oldResultId), newResultId: Number(newResultId) },
    { enabled: !!oldResultId && !!newResultId && oldResultId !== newResultId },
  );

  // Flatten all crawls for the domain into a single list for selection
  const allCrawls = useMemo(() => {
    if (!crawlHistory?.urls) return [];
    const flat: { id: number; url: string; crawledAt: string; grade: string; findingCount: number }[] = [];
    for (const u of crawlHistory.urls) {
      for (const c of u.crawls) {
        flat.push({ ...c, url: u.url });
      }
    }
    return flat.sort((a, b) => new Date(b.crawledAt).getTime() - new Date(a.crawledAt).getTime());
  }, [crawlHistory]);

  return (
    <div className="space-y-6">
      {/* Selection Controls */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <Label className="text-xs text-muted-foreground mb-1.5 block">Domain</Label>
          <Select value={selectedDomain} onValueChange={(v) => { setSelectedDomain(v); setOldResultId(""); setNewResultId(""); }}>
            <SelectTrigger className="bg-background/50 border-border/50">
              <SelectValue placeholder={domainsLoading ? "Loading..." : "Select domain"} />
            </SelectTrigger>
            <SelectContent>
              {(comparableDomains || []).map((d: any) => (
                <SelectItem key={d.domain} value={d.domain}>
                  {d.domain} ({d.crawlCount} crawls)
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label className="text-xs text-muted-foreground mb-1.5 block">Baseline (Older)</Label>
          <Select value={oldResultId} onValueChange={setOldResultId} disabled={!selectedDomain}>
            <SelectTrigger className="bg-background/50 border-border/50">
              <SelectValue placeholder="Select baseline crawl" />
            </SelectTrigger>
            <SelectContent>
              {allCrawls.filter(c => String(c.id) !== newResultId).map((c) => (
                <SelectItem key={c.id} value={String(c.id)}>
                  {new Date(c.crawledAt).toLocaleDateString()} — {c.grade} — {c.findingCount} findings
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label className="text-xs text-muted-foreground mb-1.5 block">Current (Newer)</Label>
          <Select value={newResultId} onValueChange={setNewResultId} disabled={!selectedDomain}>
            <SelectTrigger className="bg-background/50 border-border/50">
              <SelectValue placeholder="Select current crawl" />
            </SelectTrigger>
            <SelectContent>
              {allCrawls.filter(c => String(c.id) !== oldResultId).map((c) => (
                <SelectItem key={c.id} value={String(c.id)}>
                  {new Date(c.crawledAt).toLocaleDateString()} — {c.grade} — {c.findingCount} findings
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {!selectedDomain && (!comparableDomains || comparableDomains.length === 0) && !domainsLoading && (
        <Alert className="border-border/30 bg-muted/10">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <AlertDescription className="text-muted-foreground">
            No domains with multiple crawls found. Run at least two crawls on the same domain to enable comparison.
          </AlertDescription>
        </Alert>
      )}

      {compareLoading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-purple-400 mr-3" />
          <span className="text-muted-foreground">Generating comparison...</span>
        </div>
      )}

      {compareError && (
        <Alert className="border-red-500/30 bg-red-500/5">
          <XCircle className="w-4 h-4 text-red-400" />
          <AlertDescription className="text-red-300">{compareError.message}</AlertDescription>
        </Alert>
      )}

      {comparison && <ComparisonResults comparison={comparison} />}
    </div>
  );
}

// ─── Comparison Results Display ─────────────────────────────────────────────

function ComparisonResults({ comparison }: { comparison: any }) {
  const overallColor = comparison.overallChange === "improved" ? "text-emerald-400" :
    comparison.overallChange === "regressed" ? "text-red-400" :
    comparison.overallChange === "mixed" ? "text-amber-400" : "text-gray-400";

  const overallIcon = comparison.overallChange === "improved" ? <TrendingUp className="w-5 h-5" /> :
    comparison.overallChange === "regressed" ? <TrendingDown className="w-5 h-5" /> :
    comparison.overallChange === "mixed" ? <ArrowRight className="w-5 h-5" /> : <Minus className="w-5 h-5" />;

  const scoreColor = comparison.changeScore > 0 ? "text-emerald-400" : comparison.changeScore < 0 ? "text-red-400" : "text-gray-400";

  return (
    <div className="space-y-6">
      {/* Summary Banner */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="bg-card/50 border-border/30">
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold flex items-center justify-center gap-2 ${overallColor}`}>
              {overallIcon}
              <span className="capitalize">{comparison.overallChange}</span>
            </div>
            <div className="text-xs text-muted-foreground">Overall Change</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/30">
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold font-mono ${scoreColor}`}>
              {comparison.changeScore > 0 ? "+" : ""}{comparison.changeScore}
            </div>
            <div className="text-xs text-muted-foreground">Change Score</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/30">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-purple-400">{comparison.totalChanges}</div>
            <div className="text-xs text-muted-foreground">Total Changes</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/30">
          <CardContent className="p-3 text-center">
            <div className="flex items-center justify-center gap-2">
              <Badge className={GRADE_COLORS[comparison.headerDiff?.gradeChange?.old] || "text-gray-400 bg-gray-500/20"}>
                {comparison.headerDiff?.gradeChange?.old || "—"}
              </Badge>
              <ArrowRight className="w-4 h-4 text-muted-foreground" />
              <Badge className={GRADE_COLORS[comparison.headerDiff?.gradeChange?.new] || "text-gray-400 bg-gray-500/20"}>
                {comparison.headerDiff?.gradeChange?.new || "—"}
              </Badge>
            </div>
            <div className="text-xs text-muted-foreground mt-1">Grade Change</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/30">
          <CardContent className="p-3 text-center">
            <div className="text-sm text-muted-foreground">
              <div className="font-mono text-xs">{comparison.responseTimeDelta?.changeMs > 0 ? "+" : ""}{comparison.responseTimeDelta?.changeMs}ms</div>
              <div className="text-[10px]">({comparison.responseTimeDelta?.changePct > 0 ? "+" : ""}{comparison.responseTimeDelta?.changePct}%)</div>
            </div>
            <div className="text-xs text-muted-foreground">Response Time</div>
          </CardContent>
        </Card>
      </div>

      {/* Security Findings Diff */}
      {(comparison.findingDiff?.added?.length > 0 || comparison.findingDiff?.removed?.length > 0 || comparison.findingDiff?.severityChanges?.length > 0) && (
        <Card className="bg-card/50 border-border/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" /> Security Finding Changes
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {comparison.findingDiff.added.map((f: any, i: number) => (
              <div key={`added-${i}`} className="flex items-start gap-3 p-2 rounded-md bg-red-500/5 border border-red-500/20">
                <Plus className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <Badge className={`${SEVERITY_COLORS[f.severity]} text-xs`}>{f.severity}</Badge>
                    <span className="text-sm font-medium">{f.title}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">{f.description}</p>
                </div>
                <Badge className="bg-red-500/20 text-red-400 text-xs shrink-0">NEW</Badge>
              </div>
            ))}
            {comparison.findingDiff.removed.map((f: any, i: number) => (
              <div key={`removed-${i}`} className="flex items-start gap-3 p-2 rounded-md bg-emerald-500/5 border border-emerald-500/20">
                <Minus className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <Badge className={`${SEVERITY_COLORS[f.severity]} text-xs`}>{f.severity}</Badge>
                    <span className="text-sm font-medium line-through opacity-60">{f.title}</span>
                  </div>
                </div>
                <Badge className="bg-emerald-500/20 text-emerald-400 text-xs shrink-0">RESOLVED</Badge>
              </div>
            ))}
            {comparison.findingDiff.severityChanges?.map((f: any, i: number) => (
              <div key={`sev-${i}`} className={`flex items-start gap-3 p-2 rounded-md ${f.direction === "escalated" ? "bg-amber-500/5 border border-amber-500/20" : "bg-cyan-500/5 border border-cyan-500/20"}`}>
                {f.direction === "escalated" ? <ArrowUpRight className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" /> : <ArrowDownRight className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />}
                <div className="flex-1 min-w-0">
                  <span className="text-sm font-medium">{f.title}</span>
                  <div className="flex items-center gap-2 mt-0.5">
                    <Badge className={`${SEVERITY_COLORS[f.oldSeverity]} text-xs`}>{f.oldSeverity}</Badge>
                    <ArrowRight className="w-3 h-3 text-muted-foreground" />
                    <Badge className={`${SEVERITY_COLORS[f.newSeverity]} text-xs`}>{f.newSeverity}</Badge>
                  </div>
                </div>
                <Badge className={f.direction === "escalated" ? "bg-amber-500/20 text-amber-400 text-xs" : "bg-cyan-500/20 text-cyan-400 text-xs"}>
                  {f.direction === "escalated" ? "ESCALATED" : "DE-ESCALATED"}
                </Badge>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Technology Changes */}
      {(comparison.technologyDiff?.added?.length > 0 || comparison.technologyDiff?.removed?.length > 0 || comparison.technologyDiff?.versionChanged?.length > 0) && (
        <Card className="bg-card/50 border-border/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400" /> Technology Changes
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {comparison.technologyDiff.added.map((t: any, i: number) => (
                <div key={`ta-${i}`} className="flex items-center gap-3 p-2 rounded-md bg-cyan-500/5 border border-cyan-500/20">
                  <Plus className="w-4 h-4 text-cyan-400" />
                  <span className="text-sm">{t.name} {t.version ? `v${t.version}` : ""}</span>
                  <Badge variant="outline" className="text-xs ml-auto">{t.category}</Badge>
                  <Badge className="bg-cyan-500/20 text-cyan-400 text-xs">NEW</Badge>
                </div>
              ))}
              {comparison.technologyDiff.removed.map((t: any, i: number) => (
                <div key={`tr-${i}`} className="flex items-center gap-3 p-2 rounded-md bg-gray-500/5 border border-gray-500/20">
                  <Minus className="w-4 h-4 text-gray-400" />
                  <span className="text-sm line-through opacity-60">{t.name} {t.version ? `v${t.version}` : ""}</span>
                  <Badge variant="outline" className="text-xs ml-auto">{t.category}</Badge>
                  <Badge className="bg-gray-500/20 text-gray-400 text-xs">REMOVED</Badge>
                </div>
              ))}
              {comparison.technologyDiff.versionChanged.map((t: any, i: number) => (
                <div key={`tv-${i}`} className="flex items-center gap-3 p-2 rounded-md bg-amber-500/5 border border-amber-500/20">
                  <RefreshCw className="w-4 h-4 text-amber-400" />
                  <span className="text-sm">{t.name}</span>
                  <span className="text-xs font-mono text-muted-foreground">{t.oldVersion || "?"} → {t.newVersion || "?"}</span>
                  <Badge variant="outline" className="text-xs ml-auto">{t.category}</Badge>
                  <Badge className="bg-amber-500/20 text-amber-400 text-xs">UPDATED</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Exposed Path Changes */}
      {(comparison.exposedPathDiff?.added?.length > 0 || comparison.exposedPathDiff?.removed?.length > 0) && (
        <Card className="bg-card/50 border-border/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Eye className="w-4 h-4 text-amber-400" /> Exposed Path Changes
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {comparison.exposedPathDiff.added.map((p: any, i: number) => (
                <div key={`pa-${i}`} className="flex items-center gap-3 p-2 rounded-md bg-red-500/5 border border-red-500/20">
                  <Plus className="w-4 h-4 text-red-400" />
                  <code className="text-sm font-mono">{p.path}</code>
                  <Badge className={`${SEVERITY_COLORS[p.severity]} text-xs ml-auto`}>{p.severity}</Badge>
                  <Badge className="bg-red-500/20 text-red-400 text-xs">NEW</Badge>
                </div>
              ))}
              {comparison.exposedPathDiff.removed.map((p: any, i: number) => (
                <div key={`pr-${i}`} className="flex items-center gap-3 p-2 rounded-md bg-emerald-500/5 border border-emerald-500/20">
                  <Minus className="w-4 h-4 text-emerald-400" />
                  <code className="text-sm font-mono line-through opacity-60">{p.path}</code>
                  <Badge className="bg-emerald-500/20 text-emerald-400 text-xs ml-auto">SECURED</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Header Changes */}
      {(comparison.headerDiff?.present?.filter((h: any) => h.type !== "unchanged")?.length > 0 || comparison.headerDiff?.missing?.length > 0) && (
        <Card className="bg-card/50 border-border/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-400" /> Security Header Changes
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {comparison.headerDiff.present.filter((h: any) => h.type !== "unchanged").map((h: any, i: number) => (
                <div key={`hp-${i}`} className={`flex items-center gap-3 p-2 rounded-md ${
                  h.type === "added" ? "bg-emerald-500/5 border border-emerald-500/20" :
                  h.type === "removed" ? "bg-red-500/5 border border-red-500/20" :
                  "bg-amber-500/5 border border-amber-500/20"
                }`}>
                  {h.type === "added" ? <Plus className="w-4 h-4 text-emerald-400" /> :
                   h.type === "removed" ? <Minus className="w-4 h-4 text-red-400" /> :
                   <RefreshCw className="w-4 h-4 text-amber-400" />}
                  <code className="text-sm font-mono">{h.label}</code>
                  {h.type === "changed" && (
                    <span className="text-xs text-muted-foreground truncate max-w-xs">{h.oldValue?.substring(0, 40)} → {h.newValue?.substring(0, 40)}</span>
                  )}
                  <Badge className={`text-xs ml-auto ${
                    h.type === "added" ? "bg-emerald-500/20 text-emerald-400" :
                    h.type === "removed" ? "bg-red-500/20 text-red-400" :
                    "bg-amber-500/20 text-amber-400"
                  }`}>
                    {h.type === "added" ? "ADDED" : h.type === "removed" ? "REMOVED" : "CHANGED"}
                  </Badge>
                </div>
              ))}
              {comparison.headerDiff.missing.map((h: any, i: number) => (
                <div key={`hm-${i}`} className={`flex items-center gap-3 p-2 rounded-md ${
                  h.type === "added" ? "bg-red-500/5 border border-red-500/20" :
                  "bg-emerald-500/5 border border-emerald-500/20"
                }`}>
                  {h.type === "added" ? <AlertTriangle className="w-4 h-4 text-red-400" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                  <code className="text-sm font-mono">{h.label}</code>
                  <span className="text-xs text-muted-foreground">{h.detail}</span>
                  <Badge className={`text-xs ml-auto ${h.type === "added" ? "bg-red-500/20 text-red-400" : "bg-emerald-500/20 text-emerald-400"}`}>
                    {h.type === "added" ? "REGRESSION" : "FIXED"}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Cookie Changes */}
      {(comparison.cookieDiff?.added?.length > 0 || comparison.cookieDiff?.removed?.length > 0 || comparison.cookieDiff?.changed?.length > 0) && (
        <Card className="bg-card/50 border-border/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Cookie className="w-4 h-4 text-orange-400" /> Cookie Changes
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {comparison.cookieDiff.added.map((c: any, i: number) => (
                <div key={`ca-${i}`} className="flex items-center gap-3 p-2 rounded-md bg-cyan-500/5 border border-cyan-500/20">
                  <Plus className="w-4 h-4 text-cyan-400" />
                  <code className="text-sm font-mono">{c.name}</code>
                  {c.issues?.length > 0 && <span className="text-xs text-amber-400">{c.issues.length} issue(s)</span>}
                  <Badge className="bg-cyan-500/20 text-cyan-400 text-xs ml-auto">NEW</Badge>
                </div>
              ))}
              {comparison.cookieDiff.removed.map((c: any, i: number) => (
                <div key={`cr-${i}`} className="flex items-center gap-3 p-2 rounded-md bg-gray-500/5 border border-gray-500/20">
                  <Minus className="w-4 h-4 text-gray-400" />
                  <code className="text-sm font-mono line-through opacity-60">{c.name}</code>
                  <Badge className="bg-gray-500/20 text-gray-400 text-xs ml-auto">REMOVED</Badge>
                </div>
              ))}
              {comparison.cookieDiff.changed.map((c: any, i: number) => (
                <div key={`cc-${i}`} className="flex items-center gap-3 p-2 rounded-md bg-amber-500/5 border border-amber-500/20">
                  <RefreshCw className="w-4 h-4 text-amber-400" />
                  <code className="text-sm font-mono">{c.name}</code>
                  <span className="text-xs text-muted-foreground">{c.changes?.join(", ")}</span>
                  <Badge className="bg-amber-500/20 text-amber-400 text-xs ml-auto">CHANGED</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* TLS Changes */}
      {comparison.tlsChanged && comparison.tlsChanges?.length > 0 && (
        <Card className="bg-card/50 border-border/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Lock className="w-4 h-4 text-green-400" /> TLS Certificate Changes
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {comparison.tlsChanges.map((change: string, i: number) => (
                <div key={i} className="flex items-center gap-3 p-2 rounded-md bg-amber-500/5 border border-amber-500/20">
                  <RefreshCw className="w-4 h-4 text-amber-400" />
                  <span className="text-sm">{change}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Metrics Comparison */}
      <Card className="bg-card/50 border-border/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-muted-foreground" /> Metrics Comparison
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-3 rounded-lg bg-muted/10 border border-border/20">
              <div className="text-xs text-muted-foreground mb-1">Response Time</div>
              <div className="text-sm font-mono">{comparison.responseTimeDelta?.old}ms → {comparison.responseTimeDelta?.new}ms</div>
              <div className={`text-xs font-mono ${comparison.responseTimeDelta?.changeMs > 0 ? "text-amber-400" : comparison.responseTimeDelta?.changeMs < 0 ? "text-emerald-400" : "text-gray-400"}`}>
                {comparison.responseTimeDelta?.changeMs > 0 ? "+" : ""}{comparison.responseTimeDelta?.changeMs}ms
              </div>
            </div>
            <div className="text-center p-3 rounded-lg bg-muted/10 border border-border/20">
              <div className="text-xs text-muted-foreground mb-1">Content Size</div>
              <div className="text-sm font-mono">{Math.round((comparison.contentSizeDelta?.old || 0) / 1024)}KB → {Math.round((comparison.contentSizeDelta?.new || 0) / 1024)}KB</div>
              <div className={`text-xs font-mono ${comparison.contentSizeDelta?.changePct > 10 ? "text-amber-400" : "text-gray-400"}`}>
                {comparison.contentSizeDelta?.changePct > 0 ? "+" : ""}{comparison.contentSizeDelta?.changePct}%
              </div>
            </div>
            <div className="text-center p-3 rounded-lg bg-muted/10 border border-border/20">
              <div className="text-xs text-muted-foreground mb-1">Internal Links</div>
              <div className="text-sm font-mono">{comparison.linkCountDelta?.oldInternal} → {comparison.linkCountDelta?.newInternal}</div>
            </div>
            <div className="text-center p-3 rounded-lg bg-muted/10 border border-border/20">
              <div className="text-xs text-muted-foreground mb-1">Forms</div>
              <div className="text-sm font-mono">{comparison.formCountDelta?.old} → {comparison.formCountDelta?.new}</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* No Changes State */}
      {comparison.totalChanges === 0 && (
        <Alert className="border-emerald-500/30 bg-emerald-500/5">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <AlertDescription className="text-emerald-300">
            No security-relevant changes detected between these two crawls. The security posture is stable.
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function WebCrawler() {
  const [activeTab, setActiveTab] = useState("quick");

  return (
    <AppShell>
      <div className="p-6 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500/20 to-red-500/20 border border-cyan-500/30 flex items-center justify-center">
              <ScanSearch className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Web Crawler</h1>
              <p className="text-sm text-muted-foreground">
                Lightweight web scanner for discovered assets — analyzes security headers, fingerprints technologies, discovers exposed paths, and surfaces attack surface findings.
              </p>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-muted/20 border border-border/30">
            <TabsTrigger value="quick" className="flex items-center gap-1.5">
              <ScanSearch className="w-3.5 h-3.5" /> Quick Scan
            </TabsTrigger>
            <TabsTrigger value="domain" className="flex items-center gap-1.5">
              <Radar className="w-3.5 h-3.5" /> Domain Crawl
            </TabsTrigger>
            <TabsTrigger value="history" className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" /> History
            </TabsTrigger>
            <TabsTrigger value="compare" className="flex items-center gap-1.5">
              <GitCompare className="w-3.5 h-3.5" /> Compare
            </TabsTrigger>
          </TabsList>

          <TabsContent value="quick" className="mt-4">
            <Card className="bg-card/50 border-border/30">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <ScanSearch className="w-4 h-4 text-cyan-400" /> Quick Scan
                </CardTitle>
                <CardDescription>
                  Scan a single URL — analyzes HTTP security headers, detects technologies, checks for exposed paths (robots.txt, .env, .git), inspects cookies, and retrieves TLS certificate details.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <QuickScanPanel />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="domain" className="mt-4">
            <Card className="bg-card/50 border-border/30">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Radar className="w-4 h-4 text-red-400" /> Domain Crawl
                </CardTitle>
                <CardDescription>
                  Crawl an entire domain — follows internal links up to a configurable depth, scans each page for security issues, and produces an aggregated security posture report with technology fingerprinting.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <DomainCrawlPanel />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="history" className="mt-4">
            <Card className="bg-card/50 border-border/30">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Clock className="w-4 h-4 text-muted-foreground" /> Crawl History
                </CardTitle>
                <CardDescription>Previous crawl jobs and their results.</CardDescription>
              </CardHeader>
              <CardContent>
                <HistoryPanel />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="compare" className="mt-4">
            <Card className="bg-card/50 border-border/30">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <GitCompare className="w-4 h-4 text-purple-400" /> Crawl Comparison
                </CardTitle>
                <CardDescription>
                  Compare two crawl results for the same domain to identify security regressions, new findings, technology changes, and exposed path drift.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CrawlComparePanel />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
