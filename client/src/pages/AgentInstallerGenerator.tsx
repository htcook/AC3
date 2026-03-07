import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Download, Terminal, Shield, Cpu, Monitor, Smartphone,
  Copy, CheckCircle2, Settings, Loader2, FileCode
} from "lucide-react";

export default function AgentInstallerGenerator() {
  
  const { data: platforms } = trpc.agentInstaller.listPlatforms.useQuery();
  const { data: profiles } = trpc.agentInstaller.listProfiles.useQuery();

  const [platform, setPlatform] = useState("linux_x64");
  const [profile, setProfile] = useState("full");
  const [callbackHost, setCallbackHost] = useState("");
  const [callbackPort, setCallbackPort] = useState(443);
  const [beaconProtocol, setBeaconProtocol] = useState("https");
  const [beaconInterval, setBeaconInterval] = useState(60);
  const [jitter, setJitter] = useState(10);
  const [encrypted, setEncrypted] = useState(true);
  const [obfuscated, setObfuscated] = useState(false);
  const [agentName, setAgentName] = useState("");
  const [group, setGroup] = useState("");

  const { data: capabilities } = trpc.agentInstaller.getProfileCapabilities.useQuery(
    { profile: profile as any },
  );

  const generateMutation = trpc.agentInstaller.generateInstaller.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.filename} ready for download`);
    },
  });

  const handleGenerate = () => {
    if (!callbackHost) {
      toast.error("Callback host is required");
      return;
    }
    generateMutation.mutate({
      platform: platform as any,
      profile: profile as any,
      callbackHost,
      callbackPort,
      beaconProtocol: beaconProtocol as any,
      beaconIntervalSec: beaconInterval,
      jitterPercent: jitter,
      encrypted,
      obfuscated,
      agentName: agentName || undefined,
      group: group || undefined,
    });
  };

  const copyScript = () => {
    if (generateMutation.data?.script) {
      navigator.clipboard.writeText(generateMutation.data.script);
      toast.success("Installer script copied to clipboard" );
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Agent Installer Generator</h1>
        <p className="text-muted-foreground mt-1">
          Generate downloadable agent packages for internal network testing across Linux, Windows, and macOS platforms.
        </p>
      </div>

      <div className="grid grid-cols-5 gap-3">
        {platforms?.map((p: any) => (
          <Card key={p.platform} className={`cursor-pointer transition-all ${platform === p.platform ? "border-primary bg-primary/5" : "border-border/50 hover:border-border"}`} onClick={() => setPlatform(p.platform)}>
            <CardContent className="pt-4 text-center">
              <Monitor className={`h-6 w-6 mx-auto mb-2 ${platform === p.platform ? "text-primary" : "text-muted-foreground"}`} />
              <p className="text-xs font-medium">{p.name}</p>
              <p className="text-[10px] text-muted-foreground">{p.os} / {p.arch}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Configuration */}
        <Card className="col-span-2 border-border/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Settings className="h-4 w-4 text-primary" /> Agent Configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-xs">Agent Profile</Label>
                <Select value={profile} onValueChange={setProfile}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {profiles?.map((p: any) => (
                      <SelectItem key={p.profile} value={p.profile}>{p.name} ({p.capabilityCount} caps)</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Beacon Protocol</Label>
                <Select value={beaconProtocol} onValueChange={setBeaconProtocol}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="https">HTTPS</SelectItem>
                    <SelectItem value="dns">DNS</SelectItem>
                    <SelectItem value="websocket">WebSocket</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Callback Host</Label>
                <Input placeholder="c2.example.com" value={callbackHost} onChange={e => setCallbackHost(e.target.value)} />
              </div>
              <div>
                <Label className="text-xs">Callback Port</Label>
                <Input type="number" value={callbackPort} onChange={e => setCallbackPort(parseInt(e.target.value) || 443)} />
              </div>
              <div>
                <Label className="text-xs">Beacon Interval (sec)</Label>
                <Input type="number" value={beaconInterval} onChange={e => setBeaconInterval(parseInt(e.target.value) || 60)} />
              </div>
              <div>
                <Label className="text-xs">Jitter (%)</Label>
                <Input type="number" value={jitter} onChange={e => setJitter(parseInt(e.target.value) || 10)} />
              </div>
              <div>
                <Label className="text-xs">Agent Name (optional)</Label>
                <Input placeholder="recon-agent-01" value={agentName} onChange={e => setAgentName(e.target.value)} />
              </div>
              <div>
                <Label className="text-xs">Group (optional)</Label>
                <Input placeholder="red-team" value={group} onChange={e => setGroup(e.target.value)} />
              </div>
            </div>
            <div className="flex gap-6">
              <div className="flex items-center gap-2">
                <Switch checked={encrypted} onCheckedChange={setEncrypted} />
                <Label className="text-xs">Encrypted Comms</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch checked={obfuscated} onCheckedChange={setObfuscated} />
                <Label className="text-xs">Obfuscated Payload</Label>
              </div>
            </div>
            <Button onClick={handleGenerate} disabled={generateMutation.isPending} className="w-full">
              {generateMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Download className="h-4 w-4 mr-2" />}
              Generate Installer
            </Button>
          </CardContent>
        </Card>

        {/* Profile Capabilities */}
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Cpu className="h-4 w-4 text-cyan-400" /> Profile Capabilities</CardTitle>
            <CardDescription>{profiles?.find((p: any) => p.profile === profile)?.name ?? profile}</CardDescription>
          </CardHeader>
          <CardContent>
            {capabilities && capabilities.length > 0 ? (
              <div className="space-y-2">
                {capabilities.map((c: any, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-xs p-2 rounded-md bg-muted/20">
                    <CheckCircle2 className={`h-3.5 w-3.5 shrink-0 ${c.enabled ? "text-green-400" : "text-muted-foreground"}`} />
                    <span className="text-foreground">{c.name}</span>
                    <Badge variant="outline" className="ml-auto text-[10px]">{c.category}</Badge>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Select a profile to view capabilities.</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Generated Script Output */}
      {generateMutation.data && (
        <Card className="border-primary/20">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2 text-base"><FileCode className="h-4 w-4 text-green-400" /> Generated: {generateMutation.data.filename}</CardTitle>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={copyScript}><Copy className="h-3.5 w-3.5 mr-1" /> Copy</Button>
                <Button size="sm" onClick={() => {
                  const blob = new Blob([generateMutation.data!.script], { type: "text/plain" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = generateMutation.data!.filename;
                  a.click();
                  URL.revokeObjectURL(url);
                }}><Download className="h-3.5 w-3.5 mr-1" /> Download</Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4 mb-3 text-xs text-muted-foreground">
              <span>Size: {(generateMutation.data.size / 1024).toFixed(1)} KB</span>
              <span>Checksum: <code className="font-mono text-[10px]">{generateMutation.data.checksum?.slice(0, 16)}...</code></span>
              <Badge variant="outline" className="text-[10px]">{generateMutation.data.contentType}</Badge>
            </div>
            <pre className="text-[11px] font-mono bg-muted/30 rounded-md p-4 overflow-x-auto max-h-96 overflow-y-auto whitespace-pre-wrap">
              {generateMutation.data.script.slice(0, 5000)}{generateMutation.data.script.length > 5000 ? "\n\n# ... [truncated for display]" : ""}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
