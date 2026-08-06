/**
 * Bug Bounty Live Feed Panel
 * 
 * Real-time feed of HackerOne/Bugcrowd activity:
 * - Disclosed reports with severity badges
 * - New scope changes and program updates
 * - Payout tracking
 * - Platform health indicators
 */

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Activity, AlertTriangle, CheckCircle2, XCircle, Clock,
  RefreshCw, Globe, Shield, ExternalLink, DollarSign,
  TrendingUp, Loader2, Radio, Zap, Target, Eye,
  ArrowUpRight, CircleDot, WifiOff,
} from "lucide-react";

// ─── Severity Config ──────────────────────────────────────────────────────────

const severityConfig = {
  critical: { color: "text-red-400", bg: "bg-red-500/15 border-red-500/30", label: "Critical" },
  high: { color: "text-orange-400", bg: "bg-orange-500/15 border-orange-500/30", label: "High" },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/15 border-yellow-500/30", label: "Medium" },
  low: { color: "text-blue-400", bg: "bg-blue-500/15 border-blue-500/30", label: "Low" },
  none: { color: "text-zinc-400", bg: "bg-zinc-500/15 border-zinc-500/30", label: "Info" },
};

const platformConfig = {
  hackerone: { color: "text-purple-400", bg: "bg-purple-500/15", label: "HackerOne", icon: "H1" },
  bugcrowd: { color: "text-orange-400", bg: "bg-orange-500/15", label: "Bugcrowd", icon: "BC" },
  intigriti: { color: "text-blue-400", bg: "bg-blue-500/15", label: "Intigriti", icon: "IG" },
};

const eventTypeConfig = {
  disclosure: { icon: Eye, color: "text-green-400", label: "Disclosure" },
  scope_change: { icon: Target, color: "text-yellow-400", label: "Scope Change" },
  payout: { icon: DollarSign, color: "text-emerald-400", label: "Payout" },
  new_program: { icon: Zap, color: "text-blue-400", label: "New Program" },
  program_update: { icon: RefreshCw, color: "text-zinc-400", label: "Update" },
};

// ─── Component ────────────────────────────────────────────────────────────────

export function BugBountyLiveFeed() {
  const [activeTab, setActiveTab] = useState("feed");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [platformFilter, setPlatformFilter] = useState<string | undefined>(undefined);

  const feedStatus = trpc.bugBountyFeeds.getFeedStatus.useQuery(undefined, {
    refetchInterval: 60000,
  });

  const feedEvents = trpc.bugBountyFeeds.getFeedEvents.useQuery(
    { limit: 50, typeFilter: "all" as any },
    { refetchInterval: 120000, enabled: feedStatus.data?.isConfigured }
  );

  const analytics = trpc.bugBountyFeeds.getFeedAnalytics.useQuery(undefined, {
    refetchInterval: 300000,
    enabled: feedStatus.data?.isConfigured,
  });

  const disclosedReports = trpc.bugBountyFeeds.getDisclosedReports.useQuery(
    { platform: platformFilter as any, severityFilter: severityFilter as any, page: 1 },
    { enabled: feedStatus.data?.isConfigured && activeTab === "reports" }
  );

  const programs = trpc.bugBountyFeeds.getPrograms.useQuery(
    { platform: platformFilter as any, page: 1, onlyBounties: true },
    { enabled: feedStatus.data?.isConfigured && activeTab === "programs" }
  );

  // Not configured state
  if (feedStatus.data && !feedStatus.data.isConfigured) {
    return (
      <Card className="border-zinc-800 bg-zinc-900/50">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-zinc-500" />
            <CardTitle className="text-sm font-medium text-zinc-300">Live Feed</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center gap-3 py-6 text-center">
            <WifiOff className="h-8 w-8 text-zinc-600" />
            <div>
              <p className="text-sm font-medium text-zinc-400">Feed Not Configured</p>
              <p className="text-xs text-zinc-500 mt-1">
                Add API keys for HackerOne or Bugcrowd to enable live feed.
              </p>
            </div>
            <div className="text-xs text-zinc-600 space-y-1 mt-2">
              <p><code className="bg-zinc-800 px-1 rounded">HACKERONE_API_USERNAME</code> + <code className="bg-zinc-800 px-1 rounded">HACKERONE_API_KEY</code></p>
              <p><code className="bg-zinc-800 px-1 rounded">BUGCROWD_API_TOKEN</code></p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-zinc-800 bg-zinc-900/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-green-400 animate-pulse" />
            <CardTitle className="text-sm font-medium text-zinc-300">Live Feed</CardTitle>
            {feedStatus.data?.configuredPlatforms.map(p => (
              <Badge key={p} variant="outline" className={`text-[10px] ${platformConfig[p as keyof typeof platformConfig]?.bg || ""}`}>
                {platformConfig[p as keyof typeof platformConfig]?.icon || p}
              </Badge>
            ))}
          </div>
          <div className="flex items-center gap-2">
            {feedStatus.data?.state.feedHealth === "healthy" && (
              <Badge variant="outline" className="text-[10px] bg-green-500/10 border-green-500/30 text-green-400">
                <CircleDot className="h-2 w-2 mr-1" /> Live
              </Badge>
            )}
            {feedStatus.data?.state.feedHealth === "degraded" && (
              <Badge variant="outline" className="text-[10px] bg-yellow-500/10 border-yellow-500/30 text-yellow-400">
                <AlertTriangle className="h-2 w-2 mr-1" /> Degraded
              </Badge>
            )}
          </div>
        </div>
        {analytics.data && (
          <div className="grid grid-cols-4 gap-2 mt-3">
            <div className="text-center p-2 rounded bg-zinc-800/50">
              <p className="text-lg font-bold text-zinc-200">{analytics.data.state.totalPrograms}</p>
              <p className="text-[10px] text-zinc-500">Programs</p>
            </div>
            <div className="text-center p-2 rounded bg-zinc-800/50">
              <p className="text-lg font-bold text-zinc-200">{analytics.data.eventCount}</p>
              <p className="text-[10px] text-zinc-500">Events</p>
            </div>
            <div className="text-center p-2 rounded bg-zinc-800/50">
              <p className="text-lg font-bold text-emerald-400">
                ${analytics.data.totalPayouts.toLocaleString()}
              </p>
              <p className="text-[10px] text-zinc-500">Payouts</p>
            </div>
            <div className="text-center p-2 rounded bg-zinc-800/50">
              <p className="text-lg font-bold text-red-400">{analytics.data.severityBreakdown.critical}</p>
              <p className="text-[10px] text-zinc-500">Critical</p>
            </div>
          </div>
        )}
      </CardHeader>

      <CardContent className="pt-0">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="w-full bg-zinc-800/50 h-8">
            <TabsTrigger value="feed" className="text-xs flex-1">Feed</TabsTrigger>
            <TabsTrigger value="reports" className="text-xs flex-1">Reports</TabsTrigger>
            <TabsTrigger value="programs" className="text-xs flex-1">Programs</TabsTrigger>
          </TabsList>

          {/* Feed Events Tab */}
          <TabsContent value="feed" className="mt-3">
            <ScrollArea className="h-[360px]">
              {feedEvents.isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-5 w-5 animate-spin text-zinc-500" />
                </div>
              ) : feedEvents.data?.events.length === 0 ? (
                <div className="text-center py-8 text-zinc-500 text-sm">
                  No feed events yet. Data will appear after first fetch.
                </div>
              ) : (
                <div className="space-y-2">
                  {feedEvents.data?.events.map(event => {
                    const typeConf = eventTypeConfig[event.type as keyof typeof eventTypeConfig];
                    const Icon = typeConf?.icon || Activity;
                    return (
                      <div
                        key={event.id}
                        className="flex items-start gap-2 p-2 rounded-md hover:bg-zinc-800/50 transition-colors cursor-pointer group"
                        onClick={() => window.open(event.url, "_blank")}
                      >
                        <Icon className={`h-3.5 w-3.5 mt-0.5 shrink-0 ${typeConf?.color || "text-zinc-400"}`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs text-zinc-300 truncate group-hover:text-zinc-100">
                            {event.title}
                          </p>
                          <div className="flex items-center gap-1.5 mt-0.5">
                            <Badge variant="outline" className={`text-[9px] px-1 py-0 ${platformConfig[event.platform as keyof typeof platformConfig]?.bg || ""}`}>
                              {platformConfig[event.platform as keyof typeof platformConfig]?.icon || event.platform}
                            </Badge>
                            {event.severity && event.severity !== "none" && (
                              <Badge variant="outline" className={`text-[9px] px-1 py-0 ${severityConfig[event.severity as keyof typeof severityConfig]?.bg || ""}`}>
                                {event.severity}
                              </Badge>
                            )}
                            {event.amount && (
                              <span className="text-[9px] text-emerald-400 font-medium">
                                ${event.amount.toLocaleString()}
                              </span>
                            )}
                            <span className="text-[9px] text-zinc-600 ml-auto">
                              {new Date(event.timestamp).toLocaleDateString()}
                            </span>
                          </div>
                        </div>
                        <ExternalLink className="h-3 w-3 text-zinc-600 opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                    );
                  })}
                </div>
              )}
            </ScrollArea>
          </TabsContent>

          {/* Disclosed Reports Tab */}
          <TabsContent value="reports" className="mt-3">
            <div className="flex items-center gap-2 mb-3">
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="h-7 text-xs w-28 bg-zinc-800 border-zinc-700">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <ScrollArea className="h-[320px]">
              {disclosedReports.isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-5 w-5 animate-spin text-zinc-500" />
                </div>
              ) : disclosedReports.data?.reports.length === 0 ? (
                <div className="text-center py-8 text-zinc-500 text-sm">
                  No disclosed reports found.
                </div>
              ) : (
                <div className="space-y-2">
                  {disclosedReports.data?.reports.map(report => (
                    <div
                      key={report.id}
                      className="p-2 rounded-md border border-zinc-800 hover:border-zinc-700 transition-colors cursor-pointer"
                      onClick={() => window.open(report.url, "_blank")}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-xs text-zinc-300 font-medium truncate flex-1">
                          {report.title}
                        </p>
                        <Badge variant="outline" className={`text-[9px] shrink-0 ${severityConfig[report.severity]?.bg || ""}`}>
                          {report.severity}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-[10px] text-zinc-500">{report.programHandle}</span>
                        {report.bountyAmount && (
                          <span className="text-[10px] text-emerald-400 font-medium">
                            ${report.bountyAmount.toLocaleString()}
                          </span>
                        )}
                        {report.cweId && (
                          <span className="text-[10px] text-zinc-600">{report.cweId}</span>
                        )}
                        <span className="text-[10px] text-zinc-600 ml-auto">
                          {new Date(report.disclosedAt).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </TabsContent>

          {/* Programs Tab */}
          <TabsContent value="programs" className="mt-3">
            <ScrollArea className="h-[360px]">
              {programs.isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-5 w-5 animate-spin text-zinc-500" />
                </div>
              ) : programs.data?.programs.length === 0 ? (
                <div className="text-center py-8 text-zinc-500 text-sm">
                  No programs found.
                </div>
              ) : (
                <div className="space-y-2">
                  {programs.data?.programs.map(program => (
                    <div
                      key={`${program.platform}-${program.handle}`}
                      className="p-2 rounded-md border border-zinc-800 hover:border-zinc-700 transition-colors cursor-pointer"
                      onClick={() => window.open(program.url, "_blank")}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={`text-[9px] px-1 ${platformConfig[program.platform]?.bg || ""}`}>
                            {platformConfig[program.platform]?.icon}
                          </Badge>
                          <span className="text-xs text-zinc-300 font-medium">{program.name}</span>
                        </div>
                        {program.rewardRange && (
                          <span className="text-[10px] text-emerald-400">
                            ${program.rewardRange.min}–${program.rewardRange.max.toLocaleString()}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-[10px] text-zinc-500">
                        <span>{program.reportsResolved} resolved</span>
                        <span>{program.hackerCount} hackers</span>
                        {program.managed && <Badge variant="outline" className="text-[9px] px-1 bg-blue-500/10 border-blue-500/30 text-blue-400">Managed</Badge>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
