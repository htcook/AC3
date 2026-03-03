import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import {
  Shield, Zap, Server, Globe, Search, CheckCircle2, XCircle,
  AlertTriangle, BarChart3, Clock, Target, Cpu, Network, Lock,
  ChevronDown, ChevronUp, Info
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── Static Knowledge Base (matches server TOOL_KNOWLEDGE_BASE) ─────────────
const TOOLS = {
  hydra: {
    name: "THC Hydra",
    license: "AGPL-3.0",
    icon: Zap,
    color: "text-amber-400",
    bgColor: "bg-amber-500/10",
    borderColor: "border-amber-500/20",
    description: "Fast parallel brute-force across 50+ protocols. Best for high-speed credential spraying.",
    strengths: [
      "Fastest parallel brute-force engine",
      "50+ protocol modules",
      "HTTP form attacks with custom failure strings",
      "Restore/resume interrupted sessions",
      "IPv6 support",
    ],
    weaknesses: [
      "No AD/domain awareness",
      "No pass-the-hash support",
      "Noisy — easily detected by IDS",
      "No post-auth actions",
    ],
    protocols: [
      "ssh", "ftp", "telnet", "http-get", "http-post", "http-form",
      "smb", "rdp", "vnc", "mysql", "mssql", "postgres", "oracle",
      "smtp", "pop3", "imap", "ldap", "snmp", "socks5", "redis",
      "mongodb", "memcached", "cisco", "cisco-enable", "svn", "ncp",
      "nntp", "pcnfs", "rexec", "rlogin", "rsh", "s7-300", "sip",
      "teamspeak", "xmpp", "afp", "firebird", "adam6500", "asterisk",
      "cobaltstrike", "cvs", "http-proxy", "icq", "irc", "pcanywhere",
      "radmin2", "sapr3", "smb2", "smtp-enum",
    ],
    bestFor: ["Speed-critical brute force", "Web form attacks", "Multi-protocol spraying"],
    speed: 95,
    stealth: 20,
    adSupport: 5,
    versatility: 85,
  },
  medusa: {
    name: "Medusa",
    license: "GPLv2",
    icon: Server,
    color: "text-emerald-400",
    bgColor: "bg-emerald-500/10",
    borderColor: "border-emerald-500/20",
    description: "Stable modular service-specific attacks. Best for reliable targeted authentication testing.",
    strengths: [
      "Modular architecture — easy to extend",
      "Stable and reliable for long-running attacks",
      "Good error handling and recovery",
      "Thread-safe parallel execution",
      "Low memory footprint",
    ],
    weaknesses: [
      "Fewer protocols than Hydra",
      "Slower than Hydra for large credential lists",
      "No HTTP form support",
      "Limited AD integration",
    ],
    protocols: [
      "ssh", "ftp", "telnet", "http", "smb", "smb-nt", "rdp",
      "vnc", "mysql", "mssql", "postgres", "oracle", "smtp",
      "pop3", "imap", "snmp", "svn", "ncp", "nntp", "pcanywhere",
      "rexec", "rlogin", "rsh", "smbnt", "wrapper", "web-form",
      "cvs", "afp",
    ],
    bestFor: ["Stable long-running attacks", "Service-specific testing", "Low-resource environments"],
    speed: 65,
    stealth: 35,
    adSupport: 15,
    versatility: 55,
  },
  netexec: {
    name: "NetExec (CrackMapExec)",
    license: "BSD 2-Clause",
    icon: Network,
    color: "text-violet-400",
    bgColor: "bg-violet-500/10",
    borderColor: "border-violet-500/20",
    description: "Active Directory & Windows domain attack specialist. Best for post-exploitation and lateral movement.",
    strengths: [
      "Full AD/domain attack support",
      "Pass-the-hash, pass-the-ticket",
      "Kerberoasting, AS-REP roasting",
      "Post-auth module execution (Mimikatz, etc.)",
      "Domain enumeration and user spraying",
      "SAM/LSA/NTDS dumping",
    ],
    weaknesses: [
      "Limited to Windows/AD protocols",
      "Slower for pure brute-force",
      "Requires domain context for best results",
      "Python dependency chain",
    ],
    protocols: [
      "smb", "winrm", "ldap", "mssql", "ssh", "rdp", "ftp",
      "wmi", "vnc",
    ],
    bestFor: ["AD/domain attacks", "Pass-the-hash", "Post-exploitation", "Lateral movement"],
    speed: 45,
    stealth: 60,
    adSupport: 95,
    versatility: 40,
  },
  builtin: {
    name: "Ace C3 Built-in Engine",
    license: "Proprietary",
    icon: Shield,
    color: "text-cyan-400",
    bgColor: "bg-cyan-500/10",
    borderColor: "border-cyan-500/20",
    description: "LLM-powered credential attack engine with OPSEC awareness and auto-persistence.",
    strengths: [
      "LLM-powered intelligent attack planning",
      "OPSEC-aware — scores detection risk",
      "Auto-persistence to database",
      "Integrated with engagement workflow",
      "Campaign Advisor recommendations",
      "OEM default credential database",
    ],
    weaknesses: [
      "Depends on external tools for execution",
      "LLM latency for recommendations",
      "No direct protocol implementation",
    ],
    protocols: [
      "ssh", "ftp", "telnet", "http", "smb", "rdp", "vnc",
      "mysql", "mssql", "postgres", "smtp", "pop3", "imap",
      "ldap", "snmp", "redis", "mongodb",
    ],
    bestFor: ["Intelligent tool selection", "OPSEC-aware operations", "Engagement integration"],
    speed: 70,
    stealth: 80,
    adSupport: 50,
    versatility: 90,
  },
};

const ALL_PROTOCOLS = Array.from(
  new Set(Object.values(TOOLS).flatMap((t) => t.protocols))
).sort();

const PROTOCOL_CATEGORIES: Record<string, string[]> = {
  "Remote Access": ["ssh", "rdp", "vnc", "telnet", "rlogin", "rsh", "rexec", "pcanywhere", "radmin2"],
  "Web & HTTP": ["http", "http-get", "http-post", "http-form", "http-proxy", "web-form", "socks5"],
  "Email": ["smtp", "pop3", "imap", "smtp-enum"],
  "Database": ["mysql", "mssql", "postgres", "oracle", "redis", "mongodb", "memcached", "firebird"],
  "File Transfer": ["ftp", "svn", "cvs", "ncp", "afp"],
  "Directory & Auth": ["ldap", "snmp", "sip", "xmpp"],
  "Windows / AD": ["smb", "smb2", "smb-nt", "smbnt", "winrm", "wmi"],
  "Other": ["cisco", "cisco-enable", "nntp", "pcnfs", "s7-300", "teamspeak", "irc", "icq",
    "asterisk", "adam6500", "cobaltstrike", "sapr3", "wrapper"],
};

function StatBar({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[10px] font-display tracking-wider">
        <span className="text-muted-foreground">{label}</span>
        <span className={color}>{value}%</span>
      </div>
      <div className="h-1.5 bg-secondary rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color.replace("text-", "bg-")}`}
          style={{ width: `${value}%` }}
        />
      </div>
    </div>
  );
}

function ToolCard({ toolKey }: { toolKey: keyof typeof TOOLS }) {
  const [expanded, setExpanded] = useState(false);
  const tool = TOOLS[toolKey];
  const Icon = tool.icon;
  const detectedTools = trpc.webAppScanning.detectExternalTools.useQuery(undefined, {
    retry: false,
    refetchOnWindowFocus: false,
  });
  const isInstalled = toolKey === "builtin" ? true :
    detectedTools.data?.tools?.some((t: any) => t.name === toolKey && t.installed);

  return (
    <Card className={`${tool.borderColor} border`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 ${tool.bgColor} rounded-lg flex items-center justify-center`}>
              <Icon className={`w-5 h-5 ${tool.color}`} />
            </div>
            <div>
              <CardTitle className="text-sm font-display tracking-wider">{tool.name}</CardTitle>
              <div className="flex items-center gap-2 mt-0.5">
                <Badge variant="outline" className="text-[9px] h-4">{tool.license}</Badge>
                {isInstalled ? (
                  <Badge className="text-[9px] h-4 bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
                    <CheckCircle2 className="w-2.5 h-2.5 mr-1" /> INSTALLED
                  </Badge>
                ) : (
                  <Badge variant="outline" className="text-[9px] h-4 text-muted-foreground">
                    NOT DETECTED
                  </Badge>
                )}
              </div>
            </div>
          </div>
        </div>
        <p className="text-xs text-muted-foreground mt-2">{tool.description}</p>
      </CardHeader>
      <CardContent className="space-y-3">
        <StatBar label="SPEED" value={tool.speed} color={tool.color} />
        <StatBar label="STEALTH" value={tool.stealth} color={tool.color} />
        <StatBar label="AD SUPPORT" value={tool.adSupport} color={tool.color} />
        <StatBar label="VERSATILITY" value={tool.versatility} color={tool.color} />

        <div className="pt-2">
          <p className="text-[10px] font-display tracking-wider text-muted-foreground mb-1.5">BEST FOR</p>
          <div className="flex flex-wrap gap-1">
            {tool.bestFor.map((use) => (
              <Badge key={use} variant="outline" className="text-[9px]">{use}</Badge>
            ))}
          </div>
        </div>

        <Button
          variant="ghost"
          size="sm"
          className="w-full text-[10px] font-display tracking-wider h-7"
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? <ChevronUp className="w-3 h-3 mr-1" /> : <ChevronDown className="w-3 h-3 mr-1" />}
          {expanded ? "HIDE DETAILS" : "SHOW DETAILS"}
        </Button>

        {expanded && (
          <div className="space-y-3 pt-2 border-t border-border">
            <div>
              <p className="text-[10px] font-display tracking-wider text-emerald-400 mb-1">STRENGTHS</p>
              <ul className="space-y-0.5">
                {tool.strengths.map((s) => (
                  <li key={s} className="text-[10px] text-muted-foreground flex items-start gap-1.5">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400 mt-0.5 flex-shrink-0" />
                    {s}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <p className="text-[10px] font-display tracking-wider text-red-400 mb-1">WEAKNESSES</p>
              <ul className="space-y-0.5">
                {tool.weaknesses.map((w) => (
                  <li key={w} className="text-[10px] text-muted-foreground flex items-start gap-1.5">
                    <XCircle className="w-3 h-3 text-red-400 mt-0.5 flex-shrink-0" />
                    {w}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <p className="text-[10px] font-display tracking-wider text-muted-foreground mb-1">
                PROTOCOLS ({tool.protocols.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {tool.protocols.map((p) => (
                  <Badge key={p} variant="secondary" className="text-[9px] h-4">{p}</Badge>
                ))}
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ProtocolMatrix() {
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);

  const filteredCategories = useMemo(() => {
    const categories = selectedCategory
      ? { [selectedCategory]: PROTOCOL_CATEGORIES[selectedCategory] }
      : PROTOCOL_CATEGORIES;

    if (!search) return categories;

    const filtered: Record<string, string[]> = {};
    for (const [cat, protocols] of Object.entries(categories)) {
      const matched = protocols.filter((p) => p.toLowerCase().includes(search.toLowerCase()));
      if (matched.length > 0) filtered[cat] = matched;
    }
    return filtered;
  }, [search, selectedCategory]);

  const toolKeys = Object.keys(TOOLS) as (keyof typeof TOOLS)[];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Filter protocols..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8 h-8 text-xs"
          />
        </div>
        <div className="flex flex-wrap gap-1">
          <Button
            variant={selectedCategory === null ? "default" : "outline"}
            size="sm"
            className="text-[9px] h-6 px-2"
            onClick={() => setSelectedCategory(null)}
          >
            ALL
          </Button>
          {Object.keys(PROTOCOL_CATEGORIES).map((cat) => (
            <Button
              key={cat}
              variant={selectedCategory === cat ? "default" : "outline"}
              size="sm"
              className="text-[9px] h-6 px-2"
              onClick={() => setSelectedCategory(cat === selectedCategory ? null : cat)}
            >
              {cat.toUpperCase()}
            </Button>
          ))}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left py-2 px-3 text-[10px] font-display tracking-wider text-muted-foreground w-40">
                PROTOCOL
              </th>
              {toolKeys.map((key) => (
                <th key={key} className="text-center py-2 px-3 text-[10px] font-display tracking-wider">
                  <span className={TOOLS[key].color}>{TOOLS[key].name.split(" ")[0].toUpperCase()}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Object.entries(filteredCategories).map(([category, protocols]) => (
              <>
                <tr key={`cat-${category}`} className="bg-secondary/30">
                  <td colSpan={toolKeys.length + 1} className="py-1.5 px-3 text-[10px] font-display tracking-widest text-muted-foreground">
                    {category.toUpperCase()}
                  </td>
                </tr>
                {protocols.map((protocol) => (
                  <tr key={protocol} className="border-b border-border/50 hover:bg-secondary/20">
                    <td className="py-1.5 px-3 font-mono text-[11px]">{protocol}</td>
                    {toolKeys.map((key) => (
                      <td key={key} className="text-center py-1.5 px-3">
                        {TOOLS[key].protocols.includes(protocol) ? (
                          <CheckCircle2 className={`w-3.5 h-3.5 mx-auto ${TOOLS[key].color}`} />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 mx-auto text-secondary" />
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </>
            ))}
          </tbody>
        </table>
      </div>

      {/* Summary row */}
      <div className="flex items-center justify-between px-3 py-2 bg-secondary/30 rounded-lg">
        <span className="text-[10px] font-display tracking-wider text-muted-foreground">TOTAL PROTOCOLS</span>
        <div className="flex items-center gap-6">
          {toolKeys.map((key) => (
            <div key={key} className="text-center">
              <span className={`text-sm font-bold ${TOOLS[key].color}`}>{TOOLS[key].protocols.length}</span>
              <p className="text-[8px] text-muted-foreground">{TOOLS[key].name.split(" ")[0]}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function DecisionMatrix() {
  const scenarios = [
    {
      scenario: "Brute-force SSH across 100 hosts",
      recommended: "hydra",
      reason: "Fastest parallel execution, native SSH module",
      opsecRisk: "HIGH",
    },
    {
      scenario: "AD domain password spray",
      recommended: "netexec",
      reason: "Domain-aware, respects lockout policies, Kerberos support",
      opsecRisk: "MEDIUM",
    },
    {
      scenario: "Web login form attack",
      recommended: "hydra",
      reason: "HTTP form module with custom failure string detection",
      opsecRisk: "MEDIUM",
    },
    {
      scenario: "Pass-the-hash lateral movement",
      recommended: "netexec",
      reason: "Native NTLM hash support, SMB/WinRM execution",
      opsecRisk: "HIGH",
    },
    {
      scenario: "Database credential testing",
      recommended: "medusa",
      reason: "Stable, reliable for long-running DB auth tests",
      opsecRisk: "LOW",
    },
    {
      scenario: "OPSEC-sensitive engagement",
      recommended: "builtin",
      reason: "LLM scores detection risk, recommends safest approach",
      opsecRisk: "VARIES",
    },
    {
      scenario: "Kerberoasting / AS-REP roasting",
      recommended: "netexec",
      reason: "Built-in Kerberos attack modules with ticket extraction",
      opsecRisk: "MEDIUM",
    },
    {
      scenario: "Multi-protocol credential spray",
      recommended: "hydra",
      reason: "50+ protocols, fastest parallel execution",
      opsecRisk: "HIGH",
    },
    {
      scenario: "OEM default credential check",
      recommended: "builtin",
      reason: "Integrated OEM credential database with vendor matching",
      opsecRisk: "LOW",
    },
    {
      scenario: "Post-auth module execution",
      recommended: "netexec",
      reason: "Mimikatz, SAM dump, NTDS extraction after authentication",
      opsecRisk: "HIGH",
    },
  ];

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border">
            <th className="text-left py-2 px-3 text-[10px] font-display tracking-wider text-muted-foreground">SCENARIO</th>
            <th className="text-left py-2 px-3 text-[10px] font-display tracking-wider text-muted-foreground">RECOMMENDED</th>
            <th className="text-left py-2 px-3 text-[10px] font-display tracking-wider text-muted-foreground">REASON</th>
            <th className="text-center py-2 px-3 text-[10px] font-display tracking-wider text-muted-foreground">OPSEC RISK</th>
          </tr>
        </thead>
        <tbody>
          {scenarios.map((s, i) => {
            const tool = TOOLS[s.recommended as keyof typeof TOOLS];
            const Icon = tool.icon;
            return (
              <tr key={i} className="border-b border-border/50 hover:bg-secondary/20">
                <td className="py-2 px-3 text-muted-foreground">{s.scenario}</td>
                <td className="py-2 px-3">
                  <div className="flex items-center gap-1.5">
                    <Icon className={`w-3.5 h-3.5 ${tool.color}`} />
                    <span className={tool.color}>{tool.name}</span>
                  </div>
                </td>
                <td className="py-2 px-3 text-muted-foreground max-w-xs">{s.reason}</td>
                <td className="text-center py-2 px-3">
                  <Badge
                    variant="outline"
                    className={`text-[9px] ${
                      s.opsecRisk === "HIGH" ? "text-red-400 border-red-500/30" :
                      s.opsecRisk === "MEDIUM" ? "text-amber-400 border-amber-500/30" :
                      s.opsecRisk === "LOW" ? "text-emerald-400 border-emerald-500/30" :
                      "text-muted-foreground"
                    }`}
                  >
                    {s.opsecRisk}
                  </Badge>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function ToolComparison() {
  return (
      <AppShell activePath="/tool-comparison">
      <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-display tracking-wider">TOOL COMPARISON</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Side-by-side analysis of credential attack tools — protocol coverage, capabilities, and decision matrix
        </p>
      </div>

      <Tabs defaultValue="cards">
        <TabsList>
          <TabsTrigger value="cards" className="text-[10px] font-display tracking-wider">TOOL CARDS</TabsTrigger>
          <TabsTrigger value="matrix" className="text-[10px] font-display tracking-wider">PROTOCOL MATRIX</TabsTrigger>
          <TabsTrigger value="decisions" className="text-[10px] font-display tracking-wider">DECISION GUIDE</TabsTrigger>
        </TabsList>

        <TabsContent value="cards" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(Object.keys(TOOLS) as (keyof typeof TOOLS)[]).map((key) => (
              <ToolCard key={key} toolKey={key} />
            ))}
          </div>

          {/* Radar-style comparison summary */}
          <Card className="mt-4">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-primary" />
                CAPABILITY COMPARISON
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-4 gap-4">
                {(["speed", "stealth", "adSupport", "versatility"] as const).map((metric) => (
                  <div key={metric} className="space-y-2">
                    <p className="text-[10px] font-display tracking-widest text-center text-muted-foreground">
                      {metric === "adSupport" ? "AD SUPPORT" : metric.toUpperCase()}
                    </p>
                    {(Object.keys(TOOLS) as (keyof typeof TOOLS)[]).map((key) => {
                      const tool = TOOLS[key];
                      return (
                        <div key={key} className="flex items-center gap-2">
                          <span className={`text-[9px] w-14 truncate ${tool.color}`}>
                            {tool.name.split(" ")[0]}
                          </span>
                          <div className="flex-1 h-1.5 bg-secondary rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${tool.color.replace("text-", "bg-")}`}
                              style={{ width: `${tool[metric]}%` }}
                            />
                          </div>
                          <span className="text-[9px] text-muted-foreground w-7 text-right">{tool[metric]}</span>
                        </div>
                      );
                    })}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="matrix" className="mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Globe className="w-4 h-4 text-primary" />
                PROTOCOL COVERAGE MATRIX
              </CardTitle>
              <p className="text-[10px] text-muted-foreground">
                {ALL_PROTOCOLS.length} unique protocols across all tools
              </p>
            </CardHeader>
            <CardContent>
              <ProtocolMatrix />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="decisions" className="mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Target className="w-4 h-4 text-primary" />
                DECISION GUIDE
              </CardTitle>
              <p className="text-[10px] text-muted-foreground">
                When to use each tool based on attack scenario and OPSEC requirements
              </p>
            </CardHeader>
            <CardContent>
              <DecisionMatrix />
            </CardContent>
          </Card>

          {/* Quick Decision Flowchart */}
          <Card className="mt-4">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Info className="w-4 h-4 text-primary" />
                QUICK DECISION FLOWCHART
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex items-center gap-3 p-3 bg-secondary/30 rounded-lg">
                  <div className="w-6 h-6 bg-violet-500/20 rounded flex items-center justify-center text-[10px] font-bold text-violet-400">1</div>
                  <div className="flex-1">
                    <p className="text-xs font-medium">Is this an Active Directory / Windows domain target?</p>
                    <p className="text-[10px] text-muted-foreground">If YES → <span className="text-violet-400 font-medium">NetExec</span> (domain-aware, PtH, Kerberos)</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 p-3 bg-secondary/30 rounded-lg">
                  <div className="w-6 h-6 bg-amber-500/20 rounded flex items-center justify-center text-[10px] font-bold text-amber-400">2</div>
                  <div className="flex-1">
                    <p className="text-xs font-medium">Is speed the priority? Large credential lists?</p>
                    <p className="text-[10px] text-muted-foreground">If YES → <span className="text-amber-400 font-medium">Hydra</span> (fastest parallel engine, 50+ protocols)</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 p-3 bg-secondary/30 rounded-lg">
                  <div className="w-6 h-6 bg-emerald-500/20 rounded flex items-center justify-center text-[10px] font-bold text-emerald-400">3</div>
                  <div className="flex-1">
                    <p className="text-xs font-medium">Need stability for long-running service tests?</p>
                    <p className="text-[10px] text-muted-foreground">If YES → <span className="text-emerald-400 font-medium">Medusa</span> (reliable, low memory, good error recovery)</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 p-3 bg-secondary/30 rounded-lg">
                  <div className="w-6 h-6 bg-cyan-500/20 rounded flex items-center justify-center text-[10px] font-bold text-cyan-400">4</div>
                  <div className="flex-1">
                    <p className="text-xs font-medium">OPSEC-sensitive? Need intelligent recommendations?</p>
                    <p className="text-[10px] text-muted-foreground">If YES → <span className="text-cyan-400 font-medium">Ace C3 Built-in</span> (LLM scores risk, recommends safest approach)</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
      </AppShell>
  );
}
