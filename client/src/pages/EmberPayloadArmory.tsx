import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Binary, ChevronLeft, Copy, Download, Flame, Search,
  Shield, Clock, RefreshCw, Eye, Terminal, FileCode
} from "lucide-react";
import { Link } from "wouter";

const FORMAT_COLORS: Record<string, string> = {
  bash_oneliner: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  bash_script: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  python_stager: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  powershell_oneliner: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  powershell_script: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  hta_dropper: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  dll_sideload: "bg-red-500/20 text-red-400 border-red-500/30",
  elf_binary: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  shellcode_raw: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

export default function EmberPayloadArmory() {
  const [searchFilter, setSearchFilter] = useState("");
  const [selectedPayload, setSelectedPayload] = useState<any>(null);

  const dashboardQuery = trpc.ember.getDashboard.useQuery(undefined, { refetchInterval: 10000 });

  // We'll use the dashboard data for now since there's no dedicated listPayloads endpoint
  // In production, this would have its own paginated query

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link href="/ember">
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <ChevronLeft className="w-4 h-4" />
            </Button>
          </Link>
          <div className="p-2 rounded-lg bg-gradient-to-br from-amber-500/20 to-orange-600/20 border border-amber-500/30">
            <Binary className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Payload Armory</h1>
            <p className="text-sm text-muted-foreground">Generated payloads and deployment artifacts</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Link href="/ember/deploy">
            <Button className="bg-amber-600 hover:bg-amber-700 text-white">
              <Flame className="w-4 h-4 mr-2" /> Generate New
            </Button>
          </Link>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-foreground">{dashboardQuery.data?.totalPayloads ?? 0}</p>
            <p className="text-xs text-muted-foreground">Total Payloads</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-emerald-400">{dashboardQuery.data?.activeAgents ?? 0}</p>
            <p className="text-xs text-muted-foreground">Active Deployments</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-amber-400">5</p>
            <p className="text-xs text-muted-foreground">Profiles Available</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-blue-400">15</p>
            <p className="text-xs text-muted-foreground">Payload Formats</p>
          </CardContent>
        </Card>
      </div>

      {/* Payload Format Catalog */}
      <Card className="bg-card/50 border-border/50">
        <CardHeader>
          <CardTitle className="text-base">Available Payload Formats</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {[
              { format: "bash_oneliner", name: "Bash One-Liner", desc: "Single-line bash payload for quick deployment via SSH or command injection", platform: "Linux" },
              { format: "bash_script", name: "Bash Script", desc: "Full-featured bash agent with beacon, tasking, evasion, and system enumeration", platform: "Linux" },
              { format: "python_stager", name: "Python Stager", desc: "Cross-platform Python agent using only stdlib — no pip dependencies", platform: "Cross-Platform" },
              { format: "powershell_oneliner", name: "PowerShell One-Liner", desc: "Encoded PowerShell payload for Windows command injection", platform: "Windows" },
              { format: "powershell_script", name: "PowerShell Script", desc: "Full PowerShell agent with AMSI bypass and ETW patching", platform: "Windows" },
              { format: "hta_dropper", name: "HTA Dropper", desc: "HTML Application dropper for initial access via phishing", platform: "Windows" },
              { format: "dll_sideload", name: "DLL Sideload", desc: "DLL for sideloading into legitimate applications", platform: "Windows" },
              { format: "msi_installer", name: "MSI Installer", desc: "Windows Installer package with custom actions", platform: "Windows" },
              { format: "elf_binary", name: "ELF Binary", desc: "Compiled Linux executable with anti-analysis features", platform: "Linux" },
              { format: "service_executable", name: "Service EXE", desc: "Windows service binary for persistent access", platform: "Windows" },
              { format: "shellcode_raw", name: "Raw Shellcode", desc: "Position-independent shellcode for injection techniques", platform: "Cross-Platform" },
              { format: "iso_container", name: "ISO Container", desc: "ISO image with embedded payload — bypasses Mark-of-the-Web", platform: "Windows" },
              { format: "lnk_shortcut", name: "LNK Shortcut", desc: "Windows shortcut file with hidden execution arguments", platform: "Windows" },
              { format: "macro_document", name: "Macro Document", desc: "Office document with obfuscated VBA macro dropper", platform: "Windows" },
              { format: "bof_module", name: "BOF Module", desc: "Beacon Object File for in-memory execution", platform: "Cross-Platform" },
            ].map((item) => (
              <Card key={item.format} className="bg-muted/20 border-border/30 hover:border-amber-500/30 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {item.format.includes("bash") || item.format.includes("elf") ? (
                        <Terminal className="w-4 h-4 text-emerald-400" />
                      ) : item.format.includes("python") ? (
                        <FileCode className="w-4 h-4 text-blue-400" />
                      ) : (
                        <Binary className="w-4 h-4 text-amber-400" />
                      )}
                      <span className="text-sm font-medium text-foreground">{item.name}</span>
                    </div>
                    <Badge variant="outline" className={`text-[9px] ${FORMAT_COLORS[item.format] || "bg-zinc-500/20 text-zinc-400"}`}>
                      {item.platform}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">{item.desc}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Empty State for Payload History */}
      <Card className="bg-card/30 border-border/30">
        <CardContent className="p-8 text-center">
          <Binary className="w-12 h-12 text-amber-400/20 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-foreground mb-2">Payload History</h3>
          <p className="text-sm text-muted-foreground mb-4">
            Generated payloads will appear here with their deployment status, detection rates, and associated agents.
          </p>
          <Link href="/ember/deploy">
            <Button className="bg-amber-600 hover:bg-amber-700 text-white">
              <Flame className="w-4 h-4 mr-2" /> Generate First Payload
            </Button>
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}
