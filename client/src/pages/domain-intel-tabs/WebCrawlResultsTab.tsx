// @ts-nocheck
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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

export default function WebCrawlResultsTab({ scanId }: { scanId: number }) {
  const { data, isLoading } = trpc.webCrawler.listResults.useQuery({ scanId, limit: 50 }, { enabled: !!scanId });
  const [expandedId, setExpandedId] = useState<number | null>(null);

  if (isLoading) return <div className="flex items-center justify-center py-12"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /> <span className="ml-2 text-muted-foreground">Loading web crawl results...</span></div>;
  if (!data?.results?.length) return (
    <Card><CardContent className="py-12 text-center">
      <Globe className="h-12 w-12 text-muted-foreground/40 mx-auto mb-3" />
      <p className="text-muted-foreground">No web crawl results available for this scan.</p>
      <p className="text-xs text-muted-foreground/60 mt-1">Web crawl data is collected automatically during domain scans when auto-crawl is enabled.</p>
    </CardContent></Card>
  );

  const results = data.results;
  const gradeColor = (g: string | null) => {
    if (!g) return "text-muted-foreground";
    if (g.startsWith("A")) return "text-emerald-400";
    if (g === "B") return "text-yellow-400";
    if (g === "C") return "text-orange-400";
    return "text-red-400";
  };

  return (
    <div className="space-y-4">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card><CardContent className="py-3 text-center">
          <div className="text-2xl font-bold">{results.length}</div>
          <div className="text-xs text-muted-foreground">Pages Crawled</div>
        </CardContent></Card>
        <Card><CardContent className="py-3 text-center">
          <div className="text-2xl font-bold">{results.filter((r: any) => r.forms && JSON.parse(typeof r.forms === 'string' ? r.forms : JSON.stringify(r.forms)).length > 0).length}</div>
          <div className="text-xs text-muted-foreground">Pages with Forms</div>
        </CardContent></Card>
        <Card><CardContent className="py-3 text-center">
          <div className="text-2xl font-bold">{results.reduce((acc: number, r: any) => acc + (r.totalFindings || 0), 0)}</div>
          <div className="text-xs text-muted-foreground">Security Findings</div>
        </CardContent></Card>
        <Card><CardContent className="py-3 text-center">
          <div className="text-2xl font-bold">{new Set(results.flatMap((r: any) => { try { const t = typeof r.detectedTechnologies === 'string' ? JSON.parse(r.detectedTechnologies) : (r.detectedTechnologies || []); return t.map((x: any) => x.name); } catch { return []; } })).size}</div>
          <div className="text-xs text-muted-foreground">Technologies</div>
        </CardContent></Card>
        <Card><CardContent className="py-3 text-center">
          <div className="text-2xl font-bold">{results.filter((r: any) => r.exposedPaths && (typeof r.exposedPaths === 'string' ? JSON.parse(r.exposedPaths) : r.exposedPaths).length > 0).length}</div>
          <div className="text-xs text-muted-foreground">Exposed Paths</div>
        </CardContent></Card>
      </div>

      {/* Page Results */}
      {results.map((result: any) => {
        const isExpanded = expandedId === result.id;
        const techs = (() => { try { return typeof result.detectedTechnologies === 'string' ? JSON.parse(result.detectedTechnologies) : (result.detectedTechnologies || []); } catch { return []; } })();
        const forms = (() => { try { return typeof result.forms === 'string' ? JSON.parse(result.forms) : (result.forms || []); } catch { return []; } })();
        const cookies = (() => { try { return typeof result.cookies === 'string' ? JSON.parse(result.cookies) : (result.cookies || []); } catch { return []; } })();
        const secHeaders = (() => { try { return typeof result.securityHeaders === 'string' ? JSON.parse(result.securityHeaders) : (result.securityHeaders || {}); } catch { return {}; } })();
        const exposed = (() => { try { return typeof result.exposedPaths === 'string' ? JSON.parse(result.exposedPaths) : (result.exposedPaths || []); } catch { return []; } })();
        const findings = (() => { try { return typeof result.findings === 'string' ? JSON.parse(result.findings) : (result.findings || []); } catch { return []; } })();
        const extLinks = (() => { try { return typeof result.externalLinks === 'string' ? JSON.parse(result.externalLinks) : (result.externalLinks || []); } catch { return []; } })();

        return (
          <Card key={result.id} className="overflow-hidden">
            <div className="p-4 flex items-center justify-between cursor-pointer hover:bg-muted/30 transition-colors" onClick={() => setExpandedId(isExpanded ? null : result.id)}>
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <div className={`flex-shrink-0 w-2 h-2 rounded-full ${result.httpStatus === 200 ? 'bg-emerald-500' : result.httpStatus && result.httpStatus < 400 ? 'bg-yellow-500' : 'bg-red-500'}`} />
                <div className="min-w-0">
                  <div className="font-mono text-sm truncate">{result.targetUrl}</div>
                  <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                    <Badge variant="outline" className="text-xs">{result.httpStatus || '?'}</Badge>
                    {result.responseTimeMs && <span>{result.responseTimeMs}ms</span>}
                    {result.securityHeaderGrade && <Badge variant="outline" className={`text-xs ${gradeColor(result.securityHeaderGrade)}`}>Headers: {result.securityHeaderGrade}</Badge>}
                    {techs.length > 0 && <span>{techs.length} tech</span>}
                    {forms.length > 0 && <Badge variant="outline" className="text-xs text-amber-400 border-amber-500/40">{forms.length} form{forms.length > 1 ? 's' : ''}</Badge>}
                    {result.totalFindings > 0 && <Badge variant="outline" className="text-xs text-red-400 border-red-500/40">{result.totalFindings} findings</Badge>}
                  </div>
                </div>
              </div>
              {isExpanded ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
            </div>

            {isExpanded && (
              <div className="border-t px-4 pb-4 space-y-4">
                {/* Page Info */}
                <div className="pt-3 grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                  {result.pageTitle && <div><span className="text-muted-foreground">Title:</span> {result.pageTitle}</div>}
                  {result.serverHeader && <div><span className="text-muted-foreground">Server:</span> <code className="text-xs">{result.serverHeader}</code></div>}
                  {result.poweredBy && <div><span className="text-muted-foreground">Powered By:</span> <code className="text-xs">{result.poweredBy}</code></div>}
                  {result.contentType && <div><span className="text-muted-foreground">Content-Type:</span> <code className="text-xs">{result.contentType}</code></div>}
                </div>

                {/* Security Headers */}
                {(secHeaders.present?.length > 0 || secHeaders.missing?.length > 0) && (
                  <div>
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-2"><Shield className="h-4 w-4" /> Security Headers</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {secHeaders.present?.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-xs text-emerald-400 font-medium">Present</span>
                          {secHeaders.present.map((h: string, i: number) => (
                            <div key={i} className="flex items-center gap-1 text-xs"><CheckCircle2 className="h-3 w-3 text-emerald-500" /> {h}</div>
                          ))}
                        </div>
                      )}
                      {secHeaders.missing?.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-xs text-red-400 font-medium">Missing</span>
                          {secHeaders.missing.map((h: string, i: number) => (
                            <div key={i} className="flex items-center gap-1 text-xs"><XCircle className="h-3 w-3 text-red-500" /> {h}</div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Technologies */}
                {techs.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-2"><Cpu className="h-4 w-4" /> Detected Technologies</h4>
                    <div className="flex flex-wrap gap-2">
                      {techs.map((t: any, i: number) => (
                        <Badge key={i} variant="secondary" className="text-xs">
                          {t.name}{t.version ? ` v${t.version}` : ''} <span className="text-muted-foreground ml-1">({t.category || 'unknown'})</span>
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Forms */}
                {forms.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-2"><KeyRound className="h-4 w-4 text-amber-400" /> Forms (Attack Surface)</h4>
                    <div className="space-y-2">
                      {forms.map((f: any, i: number) => (
                        <div key={i} className="bg-muted/30 rounded p-2 text-xs">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge variant="outline" className="text-xs">{(f.method || 'GET').toUpperCase()}</Badge>
                            <code className="text-muted-foreground">{f.action || '(self)'}</code>
                            {f.inputs?.some((inp: any) => inp.type === 'password') && <Badge className="bg-red-500/20 text-red-400 text-xs">Has Password Field</Badge>}
                          </div>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {(f.inputs || []).map((inp: any, j: number) => (
                              <span key={j} className={`px-1.5 py-0.5 rounded text-xs ${inp.type === 'password' ? 'bg-red-500/20 text-red-300' : inp.type === 'email' ? 'bg-blue-500/20 text-blue-300' : 'bg-muted text-muted-foreground'}`}>
                                {inp.name || inp.type}:{inp.type}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Cookies */}
                {cookies.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-2"><Database className="h-4 w-4" /> Cookies</h4>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead><tr className="border-b text-muted-foreground"><th className="text-left py-1 pr-3">Name</th><th className="text-left py-1 pr-3">Secure</th><th className="text-left py-1 pr-3">HttpOnly</th><th className="text-left py-1 pr-3">SameSite</th></tr></thead>
                        <tbody>
                          {cookies.map((c: any, i: number) => (
                            <tr key={i} className="border-b border-border/30">
                              <td className="py-1 pr-3 font-mono">{c.name}</td>
                              <td className="py-1 pr-3">{c.secure ? <CheckCircle2 className="h-3 w-3 text-emerald-500" /> : <XCircle className="h-3 w-3 text-red-500" />}</td>
                              <td className="py-1 pr-3">{c.httpOnly ? <CheckCircle2 className="h-3 w-3 text-emerald-500" /> : <XCircle className="h-3 w-3 text-red-500" />}</td>
                              <td className="py-1 pr-3">{c.sameSite || 'None'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Exposed Paths */}
                {exposed.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-2"><Eye className="h-4 w-4 text-red-400" /> Exposed Paths</h4>
                    <div className="flex flex-wrap gap-2">
                      {exposed.map((p: any, i: number) => (
                        <Badge key={i} variant="outline" className={`text-xs ${p.status === 200 ? 'text-red-400 border-red-500/40' : 'text-muted-foreground'}`}>
                          {p.path} ({p.status})
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Security Findings */}
                {findings.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-2"><AlertTriangle className="h-4 w-4 text-amber-400" /> Security Findings</h4>
                    <div className="space-y-1">
                      {findings.map((f: any, i: number) => (
                        <div key={i} className="flex items-start gap-2 text-xs">
                          <Badge variant="outline" className={`text-xs flex-shrink-0 ${f.severity === 'critical' ? 'text-red-400 border-red-500/40' : f.severity === 'high' ? 'text-orange-400 border-orange-500/40' : f.severity === 'medium' ? 'text-yellow-400 border-yellow-500/40' : 'text-emerald-400 border-emerald-500/40'}`}>{f.severity}</Badge>
                          <div><span className="font-medium">{f.title}</span> {f.description && <span className="text-muted-foreground">— {f.description}</span>}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* External Links */}
                {extLinks.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-2"><Link2 className="h-4 w-4" /> External Links ({extLinks.length})</h4>
                    <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
                      {extLinks.slice(0, 30).map((l: string, i: number) => (
                        <Badge key={i} variant="outline" className="text-xs font-mono truncate max-w-xs">{l}</Badge>
                      ))}
                      {extLinks.length > 30 && <span className="text-xs text-muted-foreground">+{extLinks.length - 30} more</span>}
                    </div>
                  </div>
                )}

                {/* robots.txt / security.txt */}
                {(result.robotsTxt || result.securityTxt) && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {result.robotsTxt && (
                      <div>
                        <h4 className="text-sm font-semibold mb-1">robots.txt</h4>
                        <pre className="text-xs bg-muted/30 rounded p-2 max-h-32 overflow-y-auto whitespace-pre-wrap">{result.robotsTxt}</pre>
                      </div>
                    )}
                    {result.securityTxt && (
                      <div>
                        <h4 className="text-sm font-semibold mb-1">security.txt</h4>
                        <pre className="text-xs bg-muted/30 rounded p-2 max-h-32 overflow-y-auto whitespace-pre-wrap">{result.securityTxt}</pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   Entity Profile & BIA Tab — shows resolved org, financials, and impact tiers
   ═══════════════════════════════════════════════════════════════════════════ */

