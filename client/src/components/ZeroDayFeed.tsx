import { trpc } from "@/lib/trpc";
import { useState, useMemo, useEffect, useRef } from "react";
import { Link } from "wouter";
import {
  AlertTriangle, Shield, Bug, Zap, ExternalLink, ChevronRight,
  RefreshCw, Flame, Crosshair, Clock, TrendingUp, Eye, Pause, Play,
  ChevronDown, ChevronUp, Filter,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import TrendingSparkline from "@/components/TrendingSparkline";

type FeedTab = "zero_day" | "weaponized" | "kev";

interface VulnEntry {
  cveId: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  cvssScore: number | null;
  vendor: string;
  product: string;
  datePublished: string;
  dateAdded?: string;
  sources: string[];
  exploitAvailable: boolean;
  inTheWild: boolean;
  kevListed: boolean;
  ransomwareLinked: boolean;
  suggestedTechniques: string[];
  attackVector?: string;
}

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "text-red-500", bg: "bg-red-500/15", border: "border-red-500/40" },
  high: { color: "text-orange-500", bg: "bg-orange-500/15", border: "border-orange-500/40" },
  medium: { color: "text-yellow-500", bg: "bg-yellow-500/15", border: "border-yellow-500/40" },
  low: { color: "text-green-500", bg: "bg-green-500/15", border: "border-green-500/40" },
  unknown: { color: "text-muted-foreground", bg: "bg-muted/30", border: "border-border" },
};

function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;
  const hours = Math.floor(diff / (1000 * 60 * 60));
  if (hours < 1) return "< 1h ago";
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  if (days < 30) return `${Math.floor(days / 7)}w ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

export default function ZeroDayFeed() {
  const [activeTab, setActiveTab] = useState<FeedTab>("zero_day");
  const [isPaused, setIsPaused] = useState(false);
  const [expandedCve, setExpandedCve] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const tickerRef = useRef<HTMLDivElement>(null);

  // Data queries
  const { data: stats, isLoading: statsLoading } = trpc.calderaProxy.getVulnFeedStats.useQuery(undefined, {
    staleTime: 5 * 60 * 1000,
  });
  const { data: zeroDays, isLoading: zdLoading, refetch: refetchZd } = trpc.calderaProxy.getRecentZeroDays.useQuery(
    { limit: 30 },
    { staleTime: 5 * 60 * 1000 }
  );
  const { data: weaponized, isLoading: wLoading, refetch: refetchW } = trpc.calderaProxy.getWeaponizedCves.useQuery(
    { limit: 30 },
    { staleTime: 5 * 60 * 1000 }
  );
  const { data: kevData, isLoading: kevLoading } = trpc.calderaProxy.getKevCatalog.useQuery(undefined, {
    staleTime: 5 * 60 * 1000,
  });

  // Ticker items — combine top critical items from all feeds
  const tickerItems = useMemo(() => {
    const items: Array<{ cveId: string; severity: string; label: string; type: string }> = [];
    (zeroDays || []).slice(0, 8).forEach(v => {
      items.push({ cveId: v.cveId, severity: v.severity, label: `${v.cveId} — ${v.vendor} ${v.product}`, type: "0-DAY" });
    });
    (weaponized || []).slice(0, 5).forEach(v => {
      items.push({ cveId: v.cveId, severity: v.severity, label: `${v.cveId} — ${v.vendor} ${v.product}`, type: "EXPLOIT" });
    });
    return items;
  }, [zeroDays, weaponized]);

  // Active feed data
  const activeFeed = useMemo(() => {
    let data: VulnEntry[] = [];
    if (activeTab === "zero_day") data = zeroDays || [];
    else if (activeTab === "weaponized") data = weaponized || [];
    else if (activeTab === "kev") {
      // Convert KEV catalog to VulnEntry-like format
      data = (kevData?.vulnerabilities || []).slice(0, 30).map((v: any) => ({
        cveId: v.cveID,
        title: v.vulnerabilityName || v.cveID,
        description: v.shortDescription || "",
        severity: "critical" as const,
        cvssScore: null,
        vendor: v.vendorProject || "",
        product: v.product || "",
        datePublished: v.dateAdded || "",
        dateAdded: v.dateAdded,
        sources: ["cisa_kev"],
        exploitAvailable: true,
        inTheWild: true,
        kevListed: true,
        ransomwareLinked: v.knownRansomwareCampaignUse === "Known",
        suggestedTechniques: [],
        attackVector: undefined,
      }));
    }
    if (severityFilter !== "all") {
      data = data.filter(v => v.severity === severityFilter);
    }
    return data;
  }, [activeTab, zeroDays, weaponized, kevData, severityFilter]);

  const isLoading = activeTab === "zero_day" ? zdLoading : activeTab === "weaponized" ? wLoading : kevLoading;

  const handleRefresh = () => {
    refetchZd();
    refetchW();
    toast.success("Refreshing vulnerability feeds...");
  };

  // Keyboard navigation for ticker
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!tickerRef.current) return;
      if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        e.preventDefault();
        setIsPaused(true);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const tabs: Array<{ id: FeedTab; label: string; icon: React.ReactNode; count: number; color: string }> = [
    {
      id: "zero_day",
      label: "0-DAY ACTIVE",
      icon: <Flame className="w-3.5 h-3.5" />,
      count: stats?.inTheWildCount ?? 0,
      color: "text-red-500 border-red-500/40",
    },
    {
      id: "weaponized",
      label: "WEAPONIZED",
      icon: <Crosshair className="w-3.5 h-3.5" />,
      count: stats?.exploitAvailableCount ?? 0,
      color: "text-orange-500 border-orange-500/40",
    },
    {
      id: "kev",
      label: "CISA KEV",
      icon: <Shield className="w-3.5 h-3.5" />,
      count: kevData?.totalVulnerabilities ?? 0,
      color: "text-yellow-500 border-yellow-500/40",
    },
  ];

  return (
    <div className="space-y-3">
      {/* ── Scrolling Ticker ── */}
      <div
        ref={tickerRef}
        className="relative overflow-hidden bg-card border border-red-500/30 h-9"
        onMouseEnter={() => setIsPaused(true)}
        onMouseLeave={() => setIsPaused(false)}
        role="marquee"
        aria-label="Live vulnerability feed ticker"
      >
        <div className="absolute left-0 top-0 h-full w-8 bg-gradient-to-r from-card to-transparent z-10 pointer-events-none" />
        <div className="absolute right-0 top-0 h-full w-8 bg-gradient-to-l from-card to-transparent z-10 pointer-events-none" />
        <div className="absolute left-0 top-0 h-full flex items-center px-2 z-20 bg-red-500/20 border-r border-red-500/40">
          <Flame className="w-3.5 h-3.5 text-red-500 animate-pulse" />
        </div>
        <div
          className={`flex items-center h-full gap-6 pl-10 whitespace-nowrap relative z-[5] ${isPaused ? "" : "animate-ticker"}`}
          style={{ animationPlayState: isPaused ? "paused" : "running" }}
        >
          {tickerItems.length > 0 ? (
            [...tickerItems, ...tickerItems].map((item, i) => {
              const sev = SEVERITY_CONFIG[item.severity] || SEVERITY_CONFIG.unknown;
              return (
                <span
                  key={`${item.cveId}-${i}`}
                  className="flex items-center gap-2 text-xs shrink-0 cursor-pointer hover:opacity-80 transition-opacity"
                  onClick={(e) => {
                    e.stopPropagation();
                    window.location.href = `/vuln-intel?search=${encodeURIComponent(item.cveId)}`;
                  }}
                  role="link"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") window.location.href = `/vuln-intel?search=${encodeURIComponent(item.cveId)}`;
                  }}
                  aria-label={`View details for ${item.cveId}`}
                >
                  <span className={`px-1.5 py-0.5 text-[9px] font-display tracking-wider ${sev.bg} ${sev.color} ${sev.border} border`}>
                    {item.type}
                  </span>
                  <span className={`font-mono ${sev.color}`}>{item.cveId}</span>
                  <span className="text-muted-foreground">—</span>
                  <span className="text-muted-foreground max-w-[200px] truncate">{item.label.split(" — ")[1]}</span>
                </span>
              );
            })
          ) : (
            <span className="text-xs text-muted-foreground">Loading vulnerability feeds...</span>
          )}
        </div>
        <button
          onClick={() => setIsPaused(!isPaused)}
          className="absolute right-2 top-1/2 -translate-y-1/2 z-20 p-1 hover:bg-secondary rounded"
          aria-label={isPaused ? "Resume ticker" : "Pause ticker"}
        >
          {isPaused ? <Play className="w-3 h-3 text-muted-foreground" /> : <Pause className="w-3 h-3 text-muted-foreground" />}
        </button>
      </div>

      {/* ── Stats Bar ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        <div className="bg-card border border-red-500/30 p-2.5 text-center">
          <div className="font-display text-xl text-red-500">{stats?.inTheWildCount ?? "..."}</div>
          <div className="text-[9px] tracking-widest text-muted-foreground">0-DAY ACTIVE</div>
        </div>
        <div className="bg-card border border-orange-500/30 p-2.5 text-center">
          <div className="font-display text-xl text-orange-500">{stats?.exploitAvailableCount ?? "..."}</div>
          <div className="text-[9px] tracking-widest text-muted-foreground">WEAPONIZED CVEs</div>
        </div>
        <div className="bg-card border border-yellow-500/30 p-2.5 text-center">
          <div className="font-display text-xl text-yellow-500">{stats?.kevListedCount ?? "..."}</div>
          <div className="text-[9px] tracking-widest text-muted-foreground">CISA KEV</div>
        </div>
        <div className="bg-card border border-purple-500/30 p-2.5 text-center">
          <div className="font-display text-xl text-purple-500">{stats?.ransomwareLinkedCount ?? "..."}</div>
          <div className="text-[9px] tracking-widest text-muted-foreground">RANSOMWARE LINKED</div>
        </div>
      </div>

      {/* ── Trending CVEs Sparkline ── */}
      <TrendingSparkline />

      {/* ── Feed Health ── */}
      {stats?.feedHealth && (
        <div className="flex items-center gap-3 text-[10px] font-display tracking-wider text-muted-foreground">
          <span>FEED STATUS:</span>
          {Object.entries(stats.feedHealth).map(([source, health]) => (
            <span key={source} className="flex items-center gap-1">
              <div className={`w-1.5 h-1.5 rounded-full ${health === "ok" ? "bg-green-500" : health === "stale" ? "bg-yellow-500" : "bg-red-500"}`} />
              {source.replace("_", " ").toUpperCase()}
            </span>
          ))}
          {stats.lastUpdated && (
            <span className="ml-auto flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {timeAgo(stats.lastUpdated)}
            </span>
          )}
        </div>
      )}

      {/* ── Tab Selector ── */}
      <div className="flex items-center gap-2 border-b border-border pb-2">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => { setActiveTab(tab.id); setExpandedCve(null); }}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-display tracking-wider transition-colors border-b-2 -mb-[9px] ${
              activeTab === tab.id
                ? `${tab.color} border-current`
                : "text-muted-foreground border-transparent hover:text-foreground"
            }`}
          >
            {tab.icon}
            {tab.label}
            <span className={`ml-1 px-1.5 py-0.5 text-[9px] rounded ${activeTab === tab.id ? "bg-current/10" : "bg-muted"}`}>
              {tab.count > 999 ? `${(tab.count / 1000).toFixed(1)}K` : tab.count}
            </span>
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="text-[10px] bg-background border border-border px-2 py-1 font-display tracking-wider"
          >
            <option value="all">ALL SEVERITY</option>
            <option value="critical">CRITICAL</option>
            <option value="high">HIGH</option>
            <option value="medium">MEDIUM</option>
          </select>
          <Button variant="ghost" size="sm" onClick={handleRefresh} className="h-7 px-2">
            <RefreshCw className="w-3 h-3" />
          </Button>
        </div>
      </div>

      {/* ── Feed List ── */}
      <div className="space-y-1.5 max-h-[420px] overflow-y-auto pr-1">
        {isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground text-sm">
            <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
            Loading feed data...
          </div>
        ) : activeFeed.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground text-sm">
            No entries match the current filter.
          </div>
        ) : (
          activeFeed.slice(0, 20).map((vuln) => {
            const sev = SEVERITY_CONFIG[vuln.severity] || SEVERITY_CONFIG.unknown;
            const isExpanded = expandedCve === vuln.cveId;
            return (
              <div
                key={vuln.cveId}
                className={`bg-card border ${sev.border} transition-all hover:bg-secondary/20 cursor-pointer`}
                onClick={() => setExpandedCve(isExpanded ? null : vuln.cveId)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && setExpandedCve(isExpanded ? null : vuln.cveId)}
              >
                <div className="flex items-center gap-3 px-3 py-2.5">
                  {/* Severity indicator */}
                  <div className={`w-1 h-8 shrink-0 ${sev.color.replace("text-", "bg-")}`} />

                  {/* CVE ID + vendor */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-sm font-medium ${sev.color}`}>{vuln.cveId}</span>
                      {vuln.cvssScore && (
                        <span className={`text-[10px] font-display tracking-wider px-1.5 py-0.5 ${sev.bg} ${sev.color} border ${sev.border}`}>
                          CVSS {vuln.cvssScore.toFixed(1)}
                        </span>
                      )}
                      {vuln.inTheWild && (
                        <span className="text-[9px] font-display tracking-wider px-1.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 flex items-center gap-1">
                          <Flame className="w-2.5 h-2.5" /> IN THE WILD
                        </span>
                      )}
                      {vuln.kevListed && (
                        <span className="text-[9px] font-display tracking-wider px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
                          KEV
                        </span>
                      )}
                      {vuln.ransomwareLinked && (
                        <span className="text-[9px] font-display tracking-wider px-1.5 py-0.5 bg-purple-500/20 text-purple-400 border border-purple-500/30">
                          RANSOMWARE
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground mt-0.5 truncate">
                      {vuln.vendor} {vuln.product} — {vuln.title || vuln.description?.slice(0, 80)}
                    </div>
                  </div>

                  {/* Time + expand */}
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] text-muted-foreground font-display tracking-wider">
                      {timeAgo(vuln.datePublished || vuln.dateAdded || "")}
                    </span>
                    {isExpanded ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
                  </div>
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="px-3 pb-3 pt-1 border-t border-border/50 space-y-2">
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {vuln.description?.slice(0, 300) || "No description available."}
                      {(vuln.description?.length || 0) > 300 && "..."}
                    </p>
                    <div className="flex flex-wrap items-center gap-2">
                      {vuln.sources?.map(s => (
                        <span key={s} className="text-[9px] font-display tracking-wider px-1.5 py-0.5 bg-muted border border-border">
                          {s.replace("_", " ").toUpperCase()}
                        </span>
                      ))}
                      {vuln.attackVector && (
                        <span className="text-[9px] font-display tracking-wider px-1.5 py-0.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                          {vuln.attackVector}
                        </span>
                      )}
                      {vuln.suggestedTechniques?.slice(0, 3).map(t => (
                        <span key={t} className="text-[9px] font-mono px-1.5 py-0.5 bg-primary/10 text-primary border border-primary/30">
                          {t}
                        </span>
                      ))}
                    </div>
                    <div className="flex items-center gap-2 pt-1">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${vuln.cveId}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[10px] font-display tracking-wider text-primary hover:underline flex items-center gap-1"
                        onClick={(e) => e.stopPropagation()}
                      >
                        NVD <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                      {vuln.kevListed && (
                        <a
                          href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[10px] font-display tracking-wider text-yellow-400 hover:underline flex items-center gap-1"
                          onClick={(e) => e.stopPropagation()}
                        >
                          CISA KEV <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      )}
                      <Link
                        href={`/vuln-intel?search=${vuln.cveId}`}
                        className="text-[10px] font-display tracking-wider text-cyan-400 hover:underline flex items-center gap-1"
                        onClick={(e: React.MouseEvent) => e.stopPropagation()}
                      >
                        FULL INTEL <ChevronRight className="w-2.5 h-2.5" />
                      </Link>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* ── View All Link ── */}
      <div className="flex items-center justify-between pt-1">
        <div className="text-[10px] text-muted-foreground font-display tracking-wider">
          Showing {Math.min(20, activeFeed.length)} of {activeFeed.length} entries
          {stats?.totalEntries && ` · ${stats.totalEntries.toLocaleString()} total CVEs tracked`}
        </div>
        <Link href="/vuln-intel">
          <Button variant="ghost" size="sm" className="font-display tracking-wider text-xs text-primary hover:text-primary/80">
            FULL VULN INTEL <ChevronRight className="w-3 h-3 ml-1" />
          </Button>
        </Link>
      </div>
    </div>
  );
}
