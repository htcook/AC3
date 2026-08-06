import { useParams } from "wouter";
import { trpc } from "@/lib/trpc";
import { Shield, Globe, Lock, AlertTriangle, CheckCircle2, Loader2, Server, Wifi, FileWarning } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function ScanResults() {
  const { token } = useParams<{ token: string }>();
  const { data, isLoading, error } = trpc.freeScan.getResults.useQuery(
    { token: token || "" },
    { enabled: !!token, refetchInterval: (data) => data?.state?.data?.status === "running" ? 10000 : false }
  );

  if (isLoading) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-12 h-12 text-emerald-400 animate-spin" />
          <p className="text-zinc-400">Loading scan results...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-zinc-900 border border-zinc-800 rounded-lg p-8 text-center">
          <FileWarning className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-zinc-100 mb-2">Results Not Found</h2>
          <p className="text-zinc-400 text-sm">{error.message || "This scan link may have expired or is invalid."}</p>
          <Button
            variant="outline"
            className="mt-6 border-zinc-600 text-zinc-300 hover:bg-zinc-800"
            onClick={() => window.location.href = "/"}
          >
            Return to Homepage
          </Button>
        </div>
      </div>
    );
  }

  const scan = data;
  const results = scan?.results ? (typeof scan.results === "string" ? JSON.parse(scan.results) : scan.results) : null;
  const isRunning = scan?.status === "running" || scan?.status === "pending";

  return (
    <div className="min-h-screen bg-zinc-950">
      {/* Header */}
      <header className="border-b border-zinc-800 bg-zinc-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-emerald-400" />
            <span className="text-xl font-display tracking-wider text-zinc-100">AC3</span>
            <span className="text-zinc-500 text-sm ml-2">Domain Intelligence Report</span>
          </div>
          <Button
            className="bg-emerald-600 hover:bg-emerald-500 text-white text-sm"
            onClick={() => window.location.href = "/"}
          >
            Get Full Platform Access
          </Button>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-8">
        {/* Scan Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Globe className="w-6 h-6 text-emerald-400" />
            <h1 className="text-2xl font-bold text-zinc-100">{scan?.targetDomain}</h1>
            <span className={`px-2 py-0.5 rounded text-xs font-medium ${
              scan?.status === "completed" ? "bg-emerald-500/20 text-emerald-400" :
              isRunning ? "bg-yellow-500/20 text-yellow-400" :
              "bg-red-500/20 text-red-400"
            }`}>
              {scan?.status === "completed" ? "Complete" : isRunning ? "Scanning..." : scan?.status}
            </span>
          </div>
          <p className="text-zinc-500 text-sm">
            Scanned on {scan?.createdAt ? new Date(scan.createdAt).toLocaleDateString() : "—"}
            {scan?.completedAt && ` • Completed in ${Math.round((new Date(scan.completedAt).getTime() - new Date(scan.createdAt).getTime()) / 1000)}s`}
          </p>
        </div>

        {isRunning && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-8 text-center">
            <Loader2 className="w-10 h-10 text-emerald-400 animate-spin mx-auto mb-4" />
            <h2 className="text-lg font-semibold text-zinc-100 mb-2">Scan In Progress</h2>
            <p className="text-zinc-400 text-sm">
              Your Domain Intelligence scan is running. This page will automatically update when results are ready (typically 2-5 minutes).
            </p>
          </div>
        )}

        {scan?.status === "completed" && results && (
          <div className="grid gap-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <SummaryCard
                icon={<Globe className="w-5 h-5" />}
                label="Subdomains"
                value={results.subdomains?.length || 0}
                color="blue"
              />
              <SummaryCard
                icon={<Server className="w-5 h-5" />}
                label="Open Ports"
                value={results.openPorts?.length || 0}
                color="yellow"
              />
              <SummaryCard
                icon={<Lock className="w-5 h-5" />}
                label="SSL Issues"
                value={results.sslIssues?.length || 0}
                color={results.sslIssues?.length > 0 ? "red" : "green"}
              />
              <SummaryCard
                icon={<AlertTriangle className="w-5 h-5" />}
                label="Findings"
                value={results.findings?.length || 0}
                color={results.findings?.length > 0 ? "orange" : "green"}
              />
            </div>

            {/* DNS Records */}
            {results.dns && (
              <ResultSection title="DNS Configuration" icon={<Wifi className="w-5 h-5 text-blue-400" />}>
                <div className="grid gap-2">
                  {results.dns.map((record: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 p-2 bg-zinc-800/50 rounded text-sm">
                      <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs font-mono min-w-[50px] text-center">
                        {record.type}
                      </span>
                      <span className="text-zinc-300 font-mono text-xs break-all">{record.value}</span>
                    </div>
                  ))}
                </div>
              </ResultSection>
            )}

            {/* Subdomains */}
            {results.subdomains?.length > 0 && (
              <ResultSection title="Discovered Subdomains" icon={<Globe className="w-5 h-5 text-emerald-400" />}>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {results.subdomains.map((sub: string, i: number) => (
                    <div key={i} className="p-2 bg-zinc-800/50 rounded text-sm text-zinc-300 font-mono">
                      {sub}
                    </div>
                  ))}
                </div>
              </ResultSection>
            )}

            {/* Open Ports */}
            {results.openPorts?.length > 0 && (
              <ResultSection title="Open Ports & Services" icon={<Server className="w-5 h-5 text-yellow-400" />}>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-zinc-800 text-zinc-500">
                        <th className="text-left py-2 px-3">Port</th>
                        <th className="text-left py-2 px-3">Service</th>
                        <th className="text-left py-2 px-3">Version</th>
                        <th className="text-left py-2 px-3">Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.openPorts.map((port: any, i: number) => (
                        <tr key={i} className="border-b border-zinc-800/50">
                          <td className="py-2 px-3 text-zinc-300 font-mono">{port.port}</td>
                          <td className="py-2 px-3 text-zinc-300">{port.service || "—"}</td>
                          <td className="py-2 px-3 text-zinc-400 text-xs">{port.version || "—"}</td>
                          <td className="py-2 px-3">
                            <span className={`px-2 py-0.5 rounded text-xs ${
                              port.risk === "high" ? "bg-red-500/20 text-red-400" :
                              port.risk === "medium" ? "bg-yellow-500/20 text-yellow-400" :
                              "bg-zinc-700 text-zinc-400"
                            }`}>
                              {port.risk || "info"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </ResultSection>
            )}

            {/* SSL/TLS Analysis */}
            {results.ssl && (
              <ResultSection title="SSL/TLS Analysis" icon={<Lock className="w-5 h-5 text-emerald-400" />}>
                <div className="grid gap-3">
                  <div className="flex items-center gap-3 p-3 bg-zinc-800/50 rounded">
                    {results.ssl.valid ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                    )}
                    <div>
                      <p className="text-zinc-200 text-sm font-medium">
                        {results.ssl.valid ? "Valid Certificate" : "Certificate Issues Detected"}
                      </p>
                      <p className="text-zinc-500 text-xs">
                        Issuer: {results.ssl.issuer || "Unknown"} • Expires: {results.ssl.expires || "Unknown"}
                      </p>
                    </div>
                  </div>
                  {results.sslIssues?.map((issue: string, i: number) => (
                    <div key={i} className="flex items-start gap-2 p-2 bg-red-500/5 border border-red-500/20 rounded text-sm text-red-300">
                      <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                      {issue}
                    </div>
                  ))}
                </div>
              </ResultSection>
            )}

            {/* Security Findings */}
            {results.findings?.length > 0 && (
              <ResultSection title="Security Findings" icon={<AlertTriangle className="w-5 h-5 text-orange-400" />}>
                <div className="grid gap-3">
                  {results.findings.map((finding: any, i: number) => (
                    <div key={i} className="p-4 bg-zinc-800/50 rounded border-l-2 border-l-orange-500">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                          finding.severity === "critical" ? "bg-red-500/20 text-red-400" :
                          finding.severity === "high" ? "bg-orange-500/20 text-orange-400" :
                          finding.severity === "medium" ? "bg-yellow-500/20 text-yellow-400" :
                          "bg-blue-500/20 text-blue-400"
                        }`}>
                          {finding.severity}
                        </span>
                        <h4 className="text-zinc-200 text-sm font-medium">{finding.title}</h4>
                      </div>
                      <p className="text-zinc-400 text-xs mt-1">{finding.description}</p>
                    </div>
                  ))}
                </div>
              </ResultSection>
            )}

            {/* CTA */}
            <div className="bg-gradient-to-r from-emerald-900/30 to-zinc-900 border border-emerald-500/30 rounded-lg p-8 text-center mt-4">
              <h3 className="text-xl font-semibold text-zinc-100 mb-2">Want Continuous Monitoring?</h3>
              <p className="text-zinc-400 text-sm mb-6 max-w-lg mx-auto">
                AC3 provides 24/7 domain intelligence monitoring, automated threat detection, vulnerability scanning, and red team simulation capabilities. Schedule a demo to see the full platform.
              </p>
              <div className="flex items-center justify-center gap-4">
                <Button
                  className="bg-emerald-600 hover:bg-emerald-500 text-white"
                  onClick={() => window.location.href = "/"}
                >
                  Schedule a Demo
                </Button>
                <Button
                  variant="outline"
                  className="border-zinc-600 text-zinc-300 hover:bg-zinc-800"
                  onClick={() => window.location.href = "/"}
                >
                  Learn More
                </Button>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800 mt-12 py-6">
        <p className="text-center text-zinc-600 text-xs">
          &copy; {new Date().getFullYear()} Ace of Cloud &middot; Autonomous Cybersecurity Command Center
        </p>
      </footer>
    </div>
  );
}

function SummaryCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: number; color: string }) {
  const colorMap: Record<string, string> = {
    blue: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    yellow: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
    red: "text-red-400 bg-red-500/10 border-red-500/30",
    green: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
    orange: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  };
  return (
    <div className={`p-4 rounded-lg border ${colorMap[color] || colorMap.blue}`}>
      <div className="flex items-center gap-2 mb-2">
        <span className={color === "blue" ? "text-blue-400" : color === "yellow" ? "text-yellow-400" : color === "red" ? "text-red-400" : color === "green" ? "text-emerald-400" : "text-orange-400"}>
          {icon}
        </span>
        <span className="text-zinc-400 text-sm">{label}</span>
      </div>
      <p className="text-2xl font-bold text-zinc-100">{value}</p>
    </div>
  );
}

function ResultSection({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 p-4 border-b border-zinc-800">
        {icon}
        <h3 className="text-zinc-100 font-medium">{title}</h3>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}
