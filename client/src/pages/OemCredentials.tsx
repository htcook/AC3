/**
 * OEM Default Credentials — Reference Table for Operators & AI
 *
 * This page provides a searchable reference of known default credentials for
 * common network equipment, servers, databases, SCADA/ICS systems, and web
 * applications. During discovery and enumeration, matching credentials are
 * automatically collected and made available here, in the AI chat, and to
 * automated testing tools (SSH, FTP, admin panel brute-force, etc.).
 *
 * These are NOT risk-rated findings — they are intelligence data for use
 * during active testing and exploitation phases within authorized ROE.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Key,
  Search,
  Copy,
  Eye,
  EyeOff,
  Shield,
  Router,
  Server,
  Database,
  Globe,
  Cpu,
  Printer,
  Camera,
  RefreshCw,
} from "lucide-react";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";

const PROTOCOL_COLORS: Record<string, string> = {
  ssh: "text-green-400 bg-green-500/10 border-green-500/20",
  telnet: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  http: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  https: "text-blue-500 bg-blue-500/10 border-blue-500/20",
  ftp: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  snmp: "text-purple-400 bg-purple-500/10 border-purple-500/20",
  rdp: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
  mysql: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  postgres: "text-indigo-400 bg-indigo-500/10 border-indigo-500/20",
  redis: "text-red-400 bg-red-500/10 border-red-500/20",
  mongodb: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  modbus: "text-rose-400 bg-rose-500/10 border-rose-500/20",
};

const TAG_ICONS: Record<string, React.ReactNode> = {
  router: <Router className="w-3 h-3" />,
  firewall: <Shield className="w-3 h-3" />,
  server: <Server className="w-3 h-3" />,
  database: <Database className="w-3 h-3" />,
  webapp: <Globe className="w-3 h-3" />,
  ics: <Cpu className="w-3 h-3" />,
  scada: <Cpu className="w-3 h-3" />,
  printer: <Printer className="w-3 h-3" />,
  camera: <Camera className="w-3 h-3" />,
};

export default function OemCredentials() {

  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState<string>("all");
  const [showPasswords, setShowPasswords] = useState(false);
  const [page, setPage] = useState(0);
  const pageSize = 50;

  const allCreds = trpc.oemCreds.listAll.useQuery({
    limit: pageSize,
    offset: page * pageSize,
    protocol: protocolFilter !== "all" ? protocolFilter : undefined,
  });

  const searchResults = trpc.oemCreds.search.useQuery(
    { query: search },
    { enabled: search.length >= 2 }
  );

  const displayData = useMemo(() => {
    if (search.length >= 2 && searchResults.data) {
      return { credentials: searchResults.data, total: searchResults.data.length };
    }
    return allCreds.data || { credentials: [], total: 0 };
  }, [search, searchResults.data, allCreds.data]);

  const copyCredential = (vendor: string, username: string, password: string) => {
    navigator.clipboard.writeText(`${username}:${password}`);
    toast.success(`Copied ${vendor} credentials`);
  };

  return (
      <AppShell activePath="/oem-credentials">
      <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">OEM Default Credentials</h1>
        <p className="text-muted-foreground mt-1">
          Searchable reference of known default credentials for network equipment, servers, databases,
          SCADA/ICS, and web applications. These credentials are automatically matched against
          discovered technologies during enumeration and fed to automated testing tools (SSH, FTP,
          admin panel testing) and the AI assistant.
        </p>
        <div className="flex items-center gap-2 mt-2">
          <Badge variant="outline" className="text-[10px] text-amber-500 border-amber-500/20 bg-amber-500/10">
            <Shield className="w-3 h-3 mr-1" />
            ROE Required — Use only within authorized engagement scope
          </Badge>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search vendor, product, protocol..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            className="pl-9"
          />
        </div>
        <Select value={protocolFilter} onValueChange={(v) => { setProtocolFilter(v); setPage(0); }}>
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="Protocol" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Protocols</SelectItem>
            <SelectItem value="ssh">SSH</SelectItem>
            <SelectItem value="telnet">Telnet</SelectItem>
            <SelectItem value="http">HTTP</SelectItem>
            <SelectItem value="https">HTTPS</SelectItem>
            <SelectItem value="ftp">FTP</SelectItem>
            <SelectItem value="snmp">SNMP</SelectItem>
            <SelectItem value="rdp">RDP</SelectItem>
            <SelectItem value="mysql">MySQL</SelectItem>
            <SelectItem value="postgres">PostgreSQL</SelectItem>
            <SelectItem value="redis">Redis</SelectItem>
            <SelectItem value="mongodb">MongoDB</SelectItem>
            <SelectItem value="modbus">Modbus</SelectItem>
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowPasswords(!showPasswords)}
        >
          {showPasswords ? (
            <><EyeOff className="w-4 h-4 mr-2" /> Hide Passwords</>
          ) : (
            <><Eye className="w-4 h-4 mr-2" /> Show Passwords</>
          )}
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => allCreds.refetch()}
          disabled={allCreds.isFetching}
        >
          <RefreshCw className={`w-4 h-4 mr-2 ${allCreds.isFetching ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {/* Stats */}
      <div className="flex items-center gap-4 text-sm text-muted-foreground">
        <span>
          <Key className="w-4 h-4 inline mr-1" />
          {displayData.total} credential{displayData.total !== 1 ? "s" : ""}
        </span>
        {search.length >= 2 && (
          <span className="text-primary">Filtered by: "{search}"</span>
        )}
      </div>

      {/* Credentials Table */}
      <Card className="border-border/50">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[180px]">Vendor / Product</TableHead>
                <TableHead className="w-[100px]">Protocol</TableHead>
                <TableHead className="w-[80px]">Port</TableHead>
                <TableHead className="w-[140px]">Username</TableHead>
                <TableHead className="w-[140px]">Password</TableHead>
                <TableHead className="w-[100px]">Access Level</TableHead>
                <TableHead>Tags</TableHead>
                <TableHead className="w-[60px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(allCreds.isLoading || (search.length >= 2 && searchResults.isLoading)) && (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                    Loading credentials...
                  </TableCell>
                </TableRow>
              )}

              {!allCreds.isLoading && displayData.credentials.length === 0 && (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                    No credentials found matching filters.
                  </TableCell>
                </TableRow>
              )}

              {displayData.credentials.map((cred: any, i: number) => (
                <TableRow key={`${cred.vendor}-${cred.product}-${cred.username}-${i}`} className="hover:bg-muted/30">
                  <TableCell>
                    <div>
                      <p className="font-medium text-sm">{cred.vendor}</p>
                      <p className="text-xs text-muted-foreground">{cred.product}</p>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={`text-[10px] uppercase ${PROTOCOL_COLORS[cred.protocol] || ""}`}
                    >
                      {cred.protocol}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {cred.port || "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {cred.username || <span className="text-muted-foreground italic">(blank)</span>}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {showPasswords ? (
                      cred.password || <span className="text-muted-foreground italic">(blank)</span>
                    ) : (
                      "••••••••"
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={`text-[10px] ${
                        cred.accessLevel === "admin" || cred.accessLevel === "root"
                          ? "text-red-400 border-red-500/20"
                          : cred.accessLevel === "privileged"
                          ? "text-orange-400 border-orange-500/20"
                          : "text-muted-foreground"
                      }`}
                    >
                      {cred.accessLevel}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {cred.tags?.map((tag: string) => (
                        <span
                          key={tag}
                          className="inline-flex items-center gap-0.5 text-[9px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground"
                        >
                          {TAG_ICONS[tag] || null}
                          {tag}
                        </span>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => copyCredential(cred.vendor, cred.username, cred.password)}
                      title="Copy username:password"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Pagination */}
      {!search && displayData.total > pageSize && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, displayData.total)} of {displayData.total}
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={page === 0}
              onClick={() => setPage(p => p - 1)}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={(page + 1) * pageSize >= displayData.total}
              onClick={() => setPage(p => p + 1)}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
      </AppShell>
  );
}
