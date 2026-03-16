import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Slider } from "@/components/ui/slider";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import {
  Flame, Rocket, Shield, Eye, Terminal, Copy, Download,
  AlertTriangle, ChevronLeft, Cpu, Radio, Lock, Clock,
  Zap, Search, Boxes, Brain, Server, Globe, Binary,
  FileCode, Settings, Crosshair
} from "lucide-react";
import { Link } from "wouter";

const PROFILE_DESCRIPTIONS: Record<string, { title: string; desc: string; icon: React.ReactNode; color: string }> = {
  ghost: {
    title: "Ghost",
    desc: "Maximum stealth. Long beacon intervals, minimal footprint, memory-only execution. For persistent access in high-security environments.",
    icon: <Eye className="w-5 h-5" />,
    color: "border-zinc-500/50 hover:border-zinc-400/70 bg-zinc-500/5",
  },
  scout: {
    title: "Scout",
    desc: "Reconnaissance-focused. System enumeration, network mapping, credential harvesting. Balanced stealth and capability.",
    icon: <Search className="w-5 h-5" />,
    color: "border-blue-500/50 hover:border-blue-400/70 bg-blue-500/5",
  },
  striker: {
    title: "Striker",
    desc: "Offensive operations. Exploitation, privilege escalation, lateral movement. Aggressive beacon with full capability set.",
    icon: <Zap className="w-5 h-5" />,
    color: "border-red-500/50 hover:border-red-400/70 bg-red-500/5",
  },
  sentinel: {
    title: "Sentinel",
    desc: "Defensive validation. EDR evasion testing, detection rule validation, security control assessment. Controlled and auditable.",
    icon: <Shield className="w-5 h-5" />,
    color: "border-emerald-500/50 hover:border-emerald-400/70 bg-emerald-500/5",
  },
  hydra: {
    title: "Hydra",
    desc: "Multi-headed persistence. Spawns child agents, establishes redundant C2 channels, self-healing mesh network.",
    icon: <Boxes className="w-5 h-5" />,
    color: "border-purple-500/50 hover:border-purple-400/70 bg-purple-500/5",
  },
};

const FORMAT_OPTIONS = [
  { value: "bash_oneliner", label: "Bash One-Liner", platform: "linux", icon: <Terminal className="w-4 h-4" /> },
  { value: "bash_script", label: "Bash Script", platform: "linux", icon: <FileCode className="w-4 h-4" /> },
  { value: "python_stager", label: "Python Stager", platform: "cross", icon: <Binary className="w-4 h-4" /> },
  { value: "powershell_oneliner", label: "PowerShell One-Liner", platform: "windows", icon: <Terminal className="w-4 h-4" /> },
  { value: "powershell_script", label: "PowerShell Script", platform: "windows", icon: <FileCode className="w-4 h-4" /> },
  { value: "hta_dropper", label: "HTA Dropper", platform: "windows", icon: <Globe className="w-4 h-4" /> },
  { value: "dll_sideload", label: "DLL Sideload", platform: "windows", icon: <Cpu className="w-4 h-4" /> },
  { value: "msi_installer", label: "MSI Installer", platform: "windows", icon: <Settings className="w-4 h-4" /> },
  { value: "elf_binary", label: "ELF Binary", platform: "linux", icon: <Cpu className="w-4 h-4" /> },
  { value: "service_executable", label: "Service EXE", platform: "windows", icon: <Server className="w-4 h-4" /> },
  { value: "shellcode_raw", label: "Raw Shellcode", platform: "cross", icon: <Binary className="w-4 h-4" /> },
  { value: "iso_container", label: "ISO Container", platform: "windows", icon: <Crosshair className="w-4 h-4" /> },
];

export default function EmberDeploy() {
  const [activeTab, setActiveTab] = useState("configure");
  const [profile, setProfile] = useState("scout");
  const [platform, setPlatform] = useState("linux_x64");
  const [format, setFormat] = useState("bash_script");
  const [callbackUrls, setCallbackUrls] = useState("");
  const [beaconInterval, setBeaconInterval] = useState(60);
  const [jitterPercent, setJitterPercent] = useState(15);
  const [killDate, setKillDate] = useState("");
  const [autonomy, setAutonomy] = useState("manual");
  const [sandboxDetection, setSandboxDetection] = useState(true);
  const [antiDebugging, setAntiDebugging] = useState(true);
  const [processHollowing, setProcessHollowing] = useState(false);
  const [memoryEncryption, setMemoryEncryption] = useState(false);
  const [obfuscationLevel, setObfuscationLevel] = useState([3]);
  const [engagementId, setEngagementId] = useState("");
  const [generatedPayload, setGeneratedPayload] = useState<any>(null);

  const metadataQuery = trpc.ember.getMetadata.useQuery();

  const generatePayload = trpc.ember.generatePayload.useMutation({
    onSuccess: (data) => {
      setGeneratedPayload(data);
      setActiveTab("output");
      toast.success("Payload generated successfully");
    },
    onError: (e) => toast.error(`Generation failed: ${e.message}`),
  });

  const handleGenerate = () => {
    const urls = callbackUrls.split("\n").map(u => u.trim()).filter(Boolean);
    if (urls.length === 0) {
      toast.error("At least one callback URL is required");
      return;
    }
    generatePayload.mutate({
      profile: profile as any,
      platform: platform as any,
      format: format as any,
      callbackUrls: urls,
      beaconInterval,
      jitterPercent,
      killDate: killDate ? new Date(killDate).getTime() : undefined,
      autonomy: autonomy as any,
      evasion: {
        sandboxDetection,
        antiDebugging,
        processHollowing,
        memoryEncryption,
        obfuscationLevel: obfuscationLevel[0],
      },
      engagementId: engagementId ? parseInt(engagementId) : undefined,
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link href="/ember">
          <Button variant="ghost" size="icon" className="h-8 w-8">
            <ChevronLeft className="w-4 h-4" />
          </Button>
        </Link>
        <div className="p-2 rounded-lg bg-gradient-to-br from-amber-500/20 to-orange-600/20 border border-amber-500/30">
          <Rocket className="w-5 h-5 text-amber-400" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight">Deploy Ember Agent</h1>
          <p className="text-sm text-muted-foreground">Configure and generate agent payloads for deployment</p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/50">
          <TabsTrigger value="configure">1. Configure</TabsTrigger>
          <TabsTrigger value="evasion">2. Evasion</TabsTrigger>
          <TabsTrigger value="output" disabled={!generatedPayload}>3. Output</TabsTrigger>
        </TabsList>

        {/* Step 1: Configure */}
        <TabsContent value="configure" className="space-y-6">
          {/* Profile Selection */}
          <Card className="bg-card/50 border-border/50">
            <CardHeader>
              <CardTitle className="text-base">Agent Profile</CardTitle>
              <CardDescription>Select the operational profile that matches your mission objectives</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
                {Object.entries(PROFILE_DESCRIPTIONS).map(([key, prof]) => (
                  <button
                    key={key}
                    onClick={() => setProfile(key)}
                    className={`p-4 rounded-lg border-2 text-left transition-all ${prof.color} ${profile === key ? "ring-2 ring-amber-500/50 border-amber-500/70" : ""}`}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      {prof.icon}
                      <span className="font-semibold text-sm text-foreground">{prof.title}</span>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">{prof.desc}</p>
                  </button>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Payload Format & Platform */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <CardTitle className="text-base">Target Platform</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Select value={platform} onValueChange={setPlatform}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="linux_x64">Linux x64</SelectItem>
                    <SelectItem value="linux_arm64">Linux ARM64</SelectItem>
                    <SelectItem value="windows_x64">Windows x64</SelectItem>
                    <SelectItem value="windows_x86">Windows x86</SelectItem>
                    <SelectItem value="macos_x64">macOS x64</SelectItem>
                    <SelectItem value="macos_arm64">macOS ARM64</SelectItem>
                  </SelectContent>
                </Select>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <CardTitle className="text-base">Payload Format</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Select value={format} onValueChange={setFormat}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {FORMAT_OPTIONS.map((f) => (
                      <SelectItem key={f.value} value={f.value}>
                        <span className="flex items-center gap-2">
                          {f.icon} {f.label}
                          <Badge variant="outline" className="text-[9px] ml-1">{f.platform}</Badge>
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </CardContent>
            </Card>
          </div>

          {/* C2 Configuration */}
          <Card className="bg-card/50 border-border/50">
            <CardHeader>
              <CardTitle className="text-base">C2 Configuration</CardTitle>
              <CardDescription>Callback URLs and beacon timing</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Callback URLs (one per line, first is primary)</Label>
                <Textarea
                  placeholder={"https://c2.example.com\nhttps://fallback1.example.com\nhttps://fallback2.example.com"}
                  value={callbackUrls}
                  onChange={(e) => setCallbackUrls(e.target.value)}
                  rows={3}
                  className="font-mono text-sm"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label>Beacon Interval ({beaconInterval}s)</Label>
                  <Slider
                    value={[beaconInterval]}
                    onValueChange={(v) => setBeaconInterval(v[0])}
                    min={5}
                    max={3600}
                    step={5}
                  />
                  <p className="text-[10px] text-muted-foreground">
                    {beaconInterval < 30 ? "Aggressive" : beaconInterval < 120 ? "Moderate" : beaconInterval < 600 ? "Stealthy" : "Deep Sleep"}
                  </p>
                </div>
                <div className="space-y-2">
                  <Label>Jitter ({jitterPercent}%)</Label>
                  <Slider
                    value={[jitterPercent]}
                    onValueChange={(v) => setJitterPercent(v[0])}
                    min={0}
                    max={50}
                    step={1}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Kill Date (optional)</Label>
                  <Input
                    type="datetime-local"
                    value={killDate}
                    onChange={(e) => setKillDate(e.target.value)}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label>Autonomy Level</Label>
                <Select value={autonomy} onValueChange={setAutonomy}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="manual">Manual — Operator controls all actions</SelectItem>
                    <SelectItem value="guided">Guided — Agent suggests, operator approves</SelectItem>
                    <SelectItem value="semi_auto">Semi-Auto — Agent acts within approved playbook</SelectItem>
                    <SelectItem value="full_auto">Full Auto — Agent operates autonomously (requires safety engine)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Engagement ID (optional)</Label>
                <Input
                  placeholder="Link to an existing engagement"
                  value={engagementId}
                  onChange={(e) => setEngagementId(e.target.value)}
                />
              </div>
            </CardContent>
          </Card>

          <div className="flex justify-end">
            <Button onClick={() => setActiveTab("evasion")} className="bg-amber-600 hover:bg-amber-700 text-white">
              Next: Evasion Settings <ChevronLeft className="w-4 h-4 ml-2 rotate-180" />
            </Button>
          </div>
        </TabsContent>

        {/* Step 2: Evasion */}
        <TabsContent value="evasion" className="space-y-6">
          <Card className="bg-card/50 border-border/50">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Shield className="w-4 h-4 text-amber-400" />
                Evasion Configuration
              </CardTitle>
              <CardDescription>Configure anti-detection and anti-analysis techniques</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">Sandbox Detection</Label>
                      <p className="text-xs text-muted-foreground">Detect VM/sandbox environments before execution</p>
                    </div>
                    <Switch checked={sandboxDetection} onCheckedChange={setSandboxDetection} />
                  </div>
                  <Separator />
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">Anti-Debugging</Label>
                      <p className="text-xs text-muted-foreground">Detect debuggers and analysis tools</p>
                    </div>
                    <Switch checked={antiDebugging} onCheckedChange={setAntiDebugging} />
                  </div>
                  <Separator />
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">Process Hollowing</Label>
                      <p className="text-xs text-muted-foreground">Inject into legitimate process memory space</p>
                    </div>
                    <Switch checked={processHollowing} onCheckedChange={setProcessHollowing} />
                  </div>
                  <Separator />
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-sm">Memory Encryption (Evanesco)</Label>
                      <p className="text-xs text-muted-foreground">Encrypt agent memory pages when idle</p>
                    </div>
                    <Switch checked={memoryEncryption} onCheckedChange={setMemoryEncryption} />
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="space-y-3">
                    <Label>Obfuscation Level: {obfuscationLevel[0]}/5</Label>
                    <Slider
                      value={obfuscationLevel}
                      onValueChange={setObfuscationLevel}
                      min={0}
                      max={5}
                      step={1}
                    />
                    <div className="flex justify-between text-[10px] text-muted-foreground">
                      <span>None</span>
                      <span>Light</span>
                      <span>Moderate</span>
                      <span>Heavy</span>
                      <span>Extreme</span>
                      <span>Paranoid</span>
                    </div>
                  </div>

                  <Card className="bg-muted/30 border-border/30 mt-4">
                    <CardContent className="p-4">
                      <h4 className="text-sm font-medium text-foreground mb-2 flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                        Estimated Detection Rate
                      </h4>
                      <div className="space-y-2">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">AV/EDR Detection</span>
                          <span className="font-mono text-foreground">
                            ~{Math.max(5, 50 - obfuscationLevel[0] * 8 - (sandboxDetection ? 3 : 0) - (antiDebugging ? 3 : 0) - (processHollowing ? 5 : 0) - (memoryEncryption ? 5 : 0))}%
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">Network Detection</span>
                          <span className="font-mono text-foreground">
                            ~{Math.max(5, 35 - (jitterPercent > 20 ? 10 : 0) - (beaconInterval > 300 ? 10 : 0))}%
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">Behavioral Analysis</span>
                          <span className="font-mono text-foreground">
                            ~{Math.max(10, 40 - obfuscationLevel[0] * 5)}%
                          </span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="flex justify-between">
            <Button variant="outline" onClick={() => setActiveTab("configure")}>
              <ChevronLeft className="w-4 h-4 mr-2" /> Back
            </Button>
            <Button
              onClick={handleGenerate}
              disabled={generatePayload.isPending}
              className="bg-amber-600 hover:bg-amber-700 text-white"
            >
              {generatePayload.isPending ? (
                <>Generating...</>
              ) : (
                <><Flame className="w-4 h-4 mr-2" /> Generate Payload</>
              )}
            </Button>
          </div>
        </TabsContent>

        {/* Step 3: Output */}
        <TabsContent value="output" className="space-y-6">
          {generatedPayload && (
            <>
              {/* Summary */}
              <Card className="bg-card/50 border-amber-500/30">
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Flame className="w-4 h-4 text-amber-400" />
                    Payload Generated
                  </CardTitle>
                  <CardDescription>
                    {generatedPayload.format} — {generatedPayload.filename}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <p className="text-xs text-muted-foreground">Size</p>
                      <p className="font-mono text-foreground">{(generatedPayload.size / 1024).toFixed(1)} KB</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Hash</p>
                      <p className="font-mono text-foreground truncate">{generatedPayload.hash}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Est. Detection</p>
                      <p className="font-mono text-foreground">{generatedPayload.estimatedDetectionRate}%</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Capabilities</p>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {generatedPayload.capabilities?.slice(0, 4).map((c: string) => (
                          <Badge key={c} variant="outline" className="text-[9px]">{c}</Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Payload Code */}
              <Card className="bg-card/50 border-border/50">
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle className="text-base">Payload</CardTitle>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        navigator.clipboard.writeText(generatedPayload.payload);
                        toast.success("Copied to clipboard");
                      }}
                    >
                      <Copy className="w-3 h-3 mr-1" /> Copy
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        const blob = new Blob([generatedPayload.payload], { type: generatedPayload.contentType });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = generatedPayload.filename;
                        a.click();
                        URL.revokeObjectURL(url);
                      }}
                    >
                      <Download className="w-3 h-3 mr-1" /> Download
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <pre className="bg-zinc-950 border border-border/30 rounded-lg p-4 overflow-x-auto text-xs text-emerald-400 font-mono max-h-96 overflow-y-auto">
                    {generatedPayload.payload}
                  </pre>
                </CardContent>
              </Card>

              {/* One-Liner */}
              {generatedPayload.oneLiner && (
                <Card className="bg-card/50 border-border/50">
                  <CardHeader className="flex flex-row items-center justify-between">
                    <CardTitle className="text-base">Quick Deploy (One-Liner)</CardTitle>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        navigator.clipboard.writeText(generatedPayload.oneLiner);
                        toast.success("One-liner copied");
                      }}
                    >
                      <Copy className="w-3 h-3 mr-1" /> Copy
                    </Button>
                  </CardHeader>
                  <CardContent>
                    <pre className="bg-zinc-950 border border-border/30 rounded-lg p-3 overflow-x-auto text-xs text-amber-400 font-mono">
                      {generatedPayload.oneLiner}
                    </pre>
                  </CardContent>
                </Card>
              )}

              {/* Evasion Techniques */}
              <Card className="bg-card/50 border-border/50">
                <CardHeader>
                  <CardTitle className="text-base">Evasion Techniques Applied</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {generatedPayload.evasionTechniques?.map((t: string) => (
                      <Badge key={t} variant="outline" className="bg-amber-500/10 text-amber-400 border-amber-500/30">
                        <Shield className="w-3 h-3 mr-1" /> {t.replace(/_/g, " ")}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <div className="flex justify-between">
                <Button variant="outline" onClick={() => { setGeneratedPayload(null); setActiveTab("configure"); }}>
                  Generate Another
                </Button>
                <Link href="/ember">
                  <Button className="bg-amber-600 hover:bg-amber-700 text-white">
                    Back to Fleet
                  </Button>
                </Link>
              </div>
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
