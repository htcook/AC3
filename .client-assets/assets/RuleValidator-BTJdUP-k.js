import{r as m,j as e}from"./vendor-react-Bl6v6LwS.js";import{s as O}from"./error-sanitizer-CI-Iie4f.js";import{A as U}from"./AppShell-CalIWXXA.js";import{t as W,b as j,B as C}from"./index-OeFsxs3q.js";import{C as b,a as L,b as R,d as w}from"./card-BETBnzXG.js";import{B as l}from"./badge-CiQkoW6Y.js";import{T as H,a as K,b as $,c as M}from"./tabs-kHy5LeRi.js";import{P as I}from"./progress-CR-kESDa.js";import{S as Q}from"./separator-B8KK8pdq.js";import{T as Y}from"./textarea-CJ2sQs7i.js";import{I as q}from"./input-D0huuO23.js";import{S as X,a as Z,b as G,c as J,d as v}from"./select-UdPLMKea.js";import{S as ee,b8 as se,h as ae,w as te,L as ie,aF as ne,a2 as _,F as re,N as P,j as N,ag as ce,f as E,aE as le,aY as oe,i as de,Z as D,aa as me,_ as xe}from"./vendor-lucide-uC70LKLQ.js";import"./EmbedContext-DAsKL1LI.js";import"./useAuth-BstCPlfx.js";import"./vendor-shiki-BWiKDYuj.js";import"./dialog-BE56IWwZ.js";import"./useComposition-C_XvbhE0.js";const he={sigma:[{name:"PowerShell Encoded Command",technique:"T1059.001",content:`title: Suspicious PowerShell Encoded Command
id: 6a7c3e4f-5b2d-4a1e-8c9f-0d3e2f1a5b6c
status: experimental
description: Detects PowerShell execution with encoded commands
author: AceofCloud
date: 2026/02/14
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - '-e '
        Image|endswith: '\\powershell.exe'
    filter:
        ParentImage|endswith:
            - '\\msiexec.exe'
            - '\\sccm\\ccmexec.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate admin scripts using encoding
level: high
tags:
    - attack.execution
    - attack.t1059.001`},{name:"LSASS Memory Access",technique:"T1003.001",content:`title: LSASS Memory Access via Process
id: 7b8d4e5f-6c3a-4b2e-9d0f-1e4f3a2b6c7d
status: experimental
description: Detects suspicious access to LSASS process memory
author: AceofCloud
date: 2026/02/14
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1438'
            - '0x143a'
    filter:
        SourceImage|endswith:
            - '\\MsMpEng.exe'
            - '\\csrss.exe'
    condition: selection and not filter
falsepositives:
    - Security products accessing LSASS
level: critical
tags:
    - attack.credential-access
    - attack.t1003.001`}],yara:[{name:"Cobalt Strike Beacon",technique:"T1071.001",content:`rule CobaltStrike_Beacon_Detection
{
    meta:
        author = "AceofCloud"
        description = "Detects Cobalt Strike beacon patterns"
        date = "2026-02-14"
        reference = "https://attack.mitre.org/techniques/T1071/001/"
        severity = "critical"

    strings:
        $beacon1 = { 4D 5A 90 00 03 00 00 00 }
        $config1 = "sleeptime" ascii wide
        $config2 = "jitter" ascii wide
        $config3 = "publickey" ascii wide
        $pipe = "\\\\.\\pipe\\msagent_" ascii
        $ua = "Mozilla/5.0" ascii

    condition:
        $beacon1 at 0 and
        (2 of ($config*)) and
        ($pipe or $ua) and
        filesize < 1MB
}`},{name:"Mimikatz Memory Pattern",technique:"T1003.001",content:`rule Mimikatz_Memory_Detection
{
    meta:
        author = "AceofCloud"
        description = "Detects Mimikatz patterns in memory dumps"
        date = "2026-02-14"
        reference = "https://attack.mitre.org/techniques/T1003/001/"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "sekurlsa::wdigest" ascii wide nocase
        $s3 = "kerberos::golden" ascii wide nocase
        $s4 = "lsadump::sam" ascii wide nocase
        $s5 = "privilege::debug" ascii wide nocase
        $s6 = "token::elevate" ascii wide nocase

    condition:
        3 of them
}`}],suricata:[{name:"C2 Beacon Detection",technique:"T1071.001",content:'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible C2 Beacon - Regular Interval HTTP POST"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/"; http.header; content:"User-Agent: Mozilla/5.0"; threshold:type both, track by_src, count 10, seconds 60; sid:1000001; rev:1; classtype:trojan-activity; reference:url,attack.mitre.org/techniques/T1071/001/;)'}],splunk:[{name:"Suspicious Process Creation",technique:"T1059",content:`index=windows sourcetype=WinEventLog:Security EventCode=4688
| where match(CommandLine, "(?i)(powershell|cmd|wscript|cscript|mshta|regsvr32|rundll32)")
| where match(CommandLine, "(?i)(-enc|-encodedcommand|downloadstring|invoke-expression|iex|bypass)")
| eval risk_score=case(
    match(CommandLine, "(?i)encodedcommand"), 80,
    match(CommandLine, "(?i)downloadstring"), 90,
    match(CommandLine, "(?i)invoke-expression"), 85,
    1=1, 50)
| where risk_score >= 70
| stats count by Computer, Account_Name, CommandLine, ParentProcessName, risk_score
| sort -risk_score`}],kql:[{name:"Credential Dumping Detection",technique:"T1003",content:`DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("procdump.exe", "mimikatz.exe", "nanodump.exe")
    or (FileName == "rundll32.exe" and ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump")
    or (FileName == "powershell.exe" and ProcessCommandLine has_any ("sekurlsa", "lsass", "credential"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc`}]};function $e(){const[i,u]=m.useState("sigma"),[n,p]=m.useState(""),[r,y]=m.useState(""),[d,x]=m.useState(""),[h,t]=m.useState(!0),[s,o]=m.useState(null),[k,A]=m.useState("editor"),T=W.calderaProxy.validateRule.useMutation({onSuccess:a=>{o(a),A("results"),j.success(a.valid?`Rule is valid! Effectiveness: ${a.effectivenessScore}%`:`Rule has ${a.syntaxErrors.filter(c=>c.severity==="error").length} errors`)},onError:a=>j.error(`Validation failed: ${O(a)}`)}),F=()=>{if(!n.trim()){j.error("Please enter a rule to validate");return}T.mutate({ruleType:i,ruleContent:n,ruleName:r||void 0,techniqueId:d||void 0,useLLM:h})},V=a=>{p(a.content),y(a.name),x(a.technique),o(null),j.success(`Loaded sample: ${a.name}`)},z=()=>{navigator.clipboard.writeText(n),j.success("Rule copied to clipboard")},B=()=>{if(!s)return;const a={ruleName:r,ruleType:i,techniqueId:d,validation:s,exportedAt:new Date().toISOString()},c=new Blob([JSON.stringify(a,null,2)],{type:"application/json"}),g=URL.createObjectURL(c),f=document.createElement("a");f.href=g,f.download=`rule-validation-${r||"result"}.json`,f.click(),URL.revokeObjectURL(g),j.success("Results exported")};return e.jsx(U,{children:e.jsxs("div",{className:"space-y-6",children:[e.jsx("div",{className:"flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4",children:e.jsxs("div",{children:[e.jsxs("h1",{className:"text-2xl font-bold flex items-center gap-2",children:[e.jsx(ee,{className:"h-6 w-6"}),"Rule Validation Engine"]}),e.jsx("p",{className:"text-muted-foreground mt-1",children:"Validate Sigma, YARA, Suricata, Splunk SPL, and KQL detection rules before SIEM deployment"})]})}),e.jsxs("div",{className:"grid grid-cols-1 lg:grid-cols-3 gap-6",children:[e.jsx("div",{className:"lg:col-span-2",children:e.jsxs(H,{value:k,onValueChange:A,children:[e.jsxs(K,{children:[e.jsxs($,{value:"editor",children:[e.jsx(se,{className:"h-4 w-4 mr-1"}),"Editor"]}),e.jsxs($,{value:"results",disabled:!s,children:[e.jsx(ae,{className:"h-4 w-4 mr-1"}),"Results"]})]}),e.jsxs(M,{value:"editor",className:"mt-4 space-y-4",children:[e.jsxs("div",{className:"grid grid-cols-1 sm:grid-cols-3 gap-3",children:[e.jsxs("div",{children:[e.jsx("label",{className:"text-xs font-medium text-muted-foreground mb-1 block",children:"Rule Type"}),e.jsxs(X,{value:i,onValueChange:u,children:[e.jsx(Z,{children:e.jsx(G,{})}),e.jsxs(J,{children:[e.jsx(v,{value:"sigma",children:"Sigma"}),e.jsx(v,{value:"yara",children:"YARA"}),e.jsx(v,{value:"suricata",children:"Suricata"}),e.jsx(v,{value:"splunk",children:"Splunk SPL"}),e.jsx(v,{value:"kql",children:"KQL (Kusto)"})]})]})]}),e.jsxs("div",{children:[e.jsx("label",{className:"text-xs font-medium text-muted-foreground mb-1 block",children:"Rule Name"}),e.jsx(q,{placeholder:"e.g., PowerShell Encoded Command",value:r,onChange:a=>y(a.target.value)})]}),e.jsxs("div",{children:[e.jsx("label",{className:"text-xs font-medium text-muted-foreground mb-1 block",children:"MITRE Technique"}),e.jsx(q,{placeholder:"e.g., T1059.001",value:d,onChange:a=>x(a.target.value)})]})]}),e.jsxs("div",{className:"relative",children:[e.jsx(Y,{className:"font-mono text-sm min-h-[400px] resize-y",placeholder:`Paste your ${i.toUpperCase()} rule here...`,value:n,onChange:a=>p(a.target.value)}),e.jsx("div",{className:"absolute top-2 right-2 flex gap-1",children:e.jsx(C,{size:"sm",variant:"ghost",className:"h-7 px-2",onClick:z,disabled:!n,children:e.jsx(te,{className:"h-3 w-3"})})})]}),e.jsxs("div",{className:"flex items-center gap-3 flex-wrap",children:[e.jsxs(C,{onClick:F,disabled:T.isPending||!n.trim(),children:[T.isPending?e.jsx(ie,{className:"h-4 w-4 mr-2 animate-spin"}):e.jsx(ne,{className:"h-4 w-4 mr-2"}),"Validate Rule"]}),e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsx("input",{type:"checkbox",id:"useLLM",checked:h,onChange:a=>t(a.target.checked),className:"rounded"}),e.jsxs("label",{htmlFor:"useLLM",className:"text-sm flex items-center gap-1",children:[e.jsx(_,{className:"h-3 w-3"}),"LLM Deep Analysis"]})]}),e.jsxs("span",{className:"text-xs text-muted-foreground",children:[n.split(`
`).length," lines |"," ",n.length," chars"]})]})]}),e.jsx(M,{value:"results",className:"mt-4",children:s&&e.jsx(ue,{result:s,ruleName:r,ruleType:i,onExport:B})})]})}),e.jsxs("div",{className:"space-y-4",children:[e.jsxs(b,{children:[e.jsx(L,{className:"pb-3",children:e.jsx(R,{className:"text-sm",children:"Sample Rules"})}),e.jsx(w,{className:"space-y-2",children:Object.entries(he).map(([a,c])=>e.jsxs("div",{children:[e.jsx("p",{className:"text-xs font-medium text-muted-foreground uppercase mb-1",children:a}),c.map((g,f)=>e.jsxs(C,{variant:"ghost",size:"sm",className:"w-full justify-start text-xs h-8 mb-1",onClick:()=>{u(a),V(g)},children:[e.jsx(re,{className:"h-3 w-3 mr-2 shrink-0"}),e.jsx("span",{className:"truncate",children:g.name}),e.jsx(l,{variant:"outline",className:"ml-auto text-xs h-5 shrink-0",children:g.technique})]},f))]},a))})]}),s&&e.jsxs(b,{children:[e.jsx(L,{className:"pb-3",children:e.jsx(R,{className:"text-sm",children:"Quick Summary"})}),e.jsxs(w,{className:"space-y-3",children:[e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsx("span",{className:"text-sm",children:"Status"}),s.valid?e.jsxs(l,{className:"bg-green-500/10 text-green-500 border-green-500/20",children:[e.jsx(P,{className:"h-3 w-3 mr-1"}),"Valid"]}):e.jsxs(l,{className:"bg-red-500/10 text-red-500 border-red-500/20",children:[e.jsx(N,{className:"h-3 w-3 mr-1"}),"Invalid"]})]}),e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsx("span",{className:"text-sm",children:"Effectiveness"}),e.jsxs("span",{className:"font-bold",children:[s.effectivenessScore,"%"]})]}),e.jsx(I,{value:s.effectivenessScore,className:"h-2"}),e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsx("span",{className:"text-sm",children:"FP Risk"}),e.jsx(l,{variant:s.falsePositiveRisk==="low"?"default":s.falsePositiveRisk==="medium"?"secondary":"destructive",children:s.falsePositiveRisk})]}),e.jsx(Q,{}),e.jsxs("div",{className:"text-xs space-y-1",children:[e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{className:"text-muted-foreground",children:"Errors"}),e.jsx("span",{className:"text-red-500",children:s.syntaxErrors.filter(a=>a.severity==="error").length})]}),e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{className:"text-muted-foreground",children:"Warnings"}),e.jsx("span",{className:"text-yellow-500",children:s.syntaxErrors.filter(a=>a.severity==="warning").length+s.semanticWarnings.length})]}),e.jsxs("div",{className:"flex justify-between",children:[e.jsx("span",{className:"text-muted-foreground",children:"Suggestions"}),e.jsx("span",{children:s.suggestions.length})]})]})]})]}),s?.coverage&&e.jsxs(b,{children:[e.jsx(L,{className:"pb-3",children:e.jsx(R,{className:"text-sm",children:"Coverage"})}),e.jsxs(w,{className:"space-y-2 text-xs",children:[s.coverage.techniquesCovered.length>0&&e.jsxs("div",{children:[e.jsx("span",{className:"text-muted-foreground",children:"Techniques:"}),e.jsx("div",{className:"flex flex-wrap gap-1 mt-1",children:s.coverage.techniquesCovered.map((a,c)=>e.jsx(l,{variant:"outline",className:"text-xs",children:a},c))})]}),s.coverage.platformCompatibility.length>0&&e.jsxs("div",{children:[e.jsx("span",{className:"text-muted-foreground",children:"Platforms:"}),e.jsx("div",{className:"flex flex-wrap gap-1 mt-1",children:s.coverage.platformCompatibility.map((a,c)=>e.jsx(l,{variant:"secondary",className:"text-xs",children:a},c))})]}),s.coverage.dataSourcesRequired.length>0&&e.jsxs("div",{children:[e.jsx("span",{className:"text-muted-foreground",children:"Data Sources:"}),e.jsx("div",{className:"flex flex-wrap gap-1 mt-1",children:s.coverage.dataSourcesRequired.map((a,c)=>e.jsx(l,{variant:"outline",className:"text-xs",children:a},c))})]})]})]})]})]})]})})}function ue({result:i,ruleName:u,ruleType:n,onExport:p}){const[r,y]=m.useState(new Set(["errors","warnings","analysis"])),d=t=>{y(s=>{const o=new Set(s);return o.has(t)?o.delete(t):o.add(t),o})},x=i.syntaxErrors.filter(t=>t.severity==="error"),h=i.syntaxErrors.filter(t=>t.severity==="warning");return e.jsxs("div",{className:"space-y-4",children:[e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsxs("div",{className:"flex items-center gap-3",children:[i.valid?e.jsx("div",{className:"p-2 rounded-lg bg-green-500/10",children:e.jsx(P,{className:"h-6 w-6 text-green-500"})}):e.jsx("div",{className:"p-2 rounded-lg bg-red-500/10",children:e.jsx(N,{className:"h-6 w-6 text-red-500"})}),e.jsxs("div",{children:[e.jsx("h3",{className:"font-semibold",children:i.valid?"Rule is Valid":"Rule Has Errors"}),e.jsxs("p",{className:"text-sm text-muted-foreground",children:[u||n.toUpperCase()," | Effectiveness:"," ",i.effectivenessScore,"%"]})]})]}),e.jsxs(C,{size:"sm",variant:"outline",onClick:p,children:[e.jsx(ce,{className:"h-4 w-4 mr-1"}),"Export"]})]}),e.jsx(b,{children:e.jsxs(w,{className:"pt-4 pb-3",children:[e.jsxs("div",{className:"flex items-center justify-between mb-2",children:[e.jsx("span",{className:"text-sm font-medium",children:"Effectiveness Score"}),e.jsxs("span",{className:`text-2xl font-bold ${i.effectivenessScore>=80?"text-green-500":i.effectivenessScore>=60?"text-yellow-500":"text-red-500"}`,children:[i.effectivenessScore,"/100"]})]}),e.jsx(I,{value:i.effectivenessScore,className:"h-2"}),e.jsxs("div",{className:"flex items-center justify-between mt-2 text-xs text-muted-foreground",children:[e.jsxs("span",{children:["False Positive Risk:"," ",e.jsx(l,{variant:i.falsePositiveRisk==="low"?"default":i.falsePositiveRisk==="medium"?"secondary":"destructive",className:"text-xs",children:i.falsePositiveRisk})]}),e.jsxs("span",{children:[x.length," errors | ",h.length," warnings |"," ",i.semanticWarnings.length," semantic issues"]})]})]})}),x.length>0&&e.jsx(S,{title:`Syntax Errors (${x.length})`,icon:e.jsx(N,{className:"h-4 w-4 text-red-500"}),isOpen:r.has("errors"),onToggle:()=>d("errors"),children:e.jsx("div",{className:"space-y-2",children:x.map((t,s)=>e.jsxs("div",{className:"flex items-start gap-2 p-2 bg-red-500/5 border border-red-500/20 rounded",children:[e.jsx(N,{className:"h-4 w-4 text-red-500 shrink-0 mt-0.5"}),e.jsxs("div",{className:"text-sm",children:[e.jsxs("span",{className:"font-mono text-xs text-muted-foreground",children:["Line ",t.line,t.column?`:${t.column}`:""]}),e.jsx("p",{children:t.message})]})]},s))})}),(h.length>0||i.semanticWarnings.length>0)&&e.jsx(S,{title:`Warnings (${h.length+i.semanticWarnings.length})`,icon:e.jsx(E,{className:"h-4 w-4 text-yellow-500"}),isOpen:r.has("warnings"),onToggle:()=>d("warnings"),children:e.jsxs("div",{className:"space-y-2",children:[h.map((t,s)=>e.jsxs("div",{className:"flex items-start gap-2 p-2 bg-yellow-500/5 border border-yellow-500/20 rounded",children:[e.jsx(E,{className:"h-4 w-4 text-yellow-500 shrink-0 mt-0.5"}),e.jsxs("div",{className:"text-sm",children:[e.jsxs("span",{className:"font-mono text-xs text-muted-foreground",children:["Line ",t.line]}),e.jsx("p",{children:t.message})]})]},`syn-${s}`)),i.semanticWarnings.map((t,s)=>e.jsxs("div",{className:`flex items-start gap-2 p-2 rounded border ${t.severity==="critical"?"bg-red-500/5 border-red-500/20":t.severity==="warning"?"bg-yellow-500/5 border-yellow-500/20":"bg-blue-500/5 border-blue-500/20"}`,children:[t.severity==="critical"?e.jsx(le,{className:"h-4 w-4 text-red-500 shrink-0 mt-0.5"}):t.severity==="warning"?e.jsx(E,{className:"h-4 w-4 text-yellow-500 shrink-0 mt-0.5"}):e.jsx(oe,{className:"h-4 w-4 text-blue-500 shrink-0 mt-0.5"}),e.jsxs("div",{className:"text-sm",children:[e.jsx("span",{className:"font-mono text-xs text-muted-foreground",children:t.field}),e.jsx("p",{children:t.message})]})]},`sem-${s}`))]})}),i.llmAnalysis&&e.jsx(S,{title:"AI Analysis",icon:e.jsx(_,{className:"h-4 w-4 text-purple-500"}),isOpen:r.has("analysis"),onToggle:()=>d("analysis"),children:e.jsxs("div",{className:"space-y-3",children:[e.jsx("p",{className:"text-sm leading-relaxed",children:i.llmAnalysis}),i.sampleMatches?.length>0&&e.jsxs("div",{className:"border rounded-lg p-3",children:[e.jsxs("h4",{className:"text-sm font-medium mb-2 flex items-center gap-2",children:[e.jsx(de,{className:"h-4 w-4"}),"Sample Data Match Test"]}),i.sampleMatches.map((t,s)=>e.jsxs("div",{className:"space-y-2",children:[e.jsx("div",{className:"flex items-center gap-2",children:t.matched?e.jsxs(l,{className:"bg-green-500/10 text-green-500 border-green-500/20",children:[e.jsx(P,{className:"h-3 w-3 mr-1"}),"Match (",t.confidence,"% confidence)"]}):e.jsxs(l,{className:"bg-red-500/10 text-red-500 border-red-500/20",children:[e.jsx(N,{className:"h-3 w-3 mr-1"}),"No Match (",t.confidence,"% confidence)"]})}),e.jsx("p",{className:"text-xs text-muted-foreground",children:t.explanation}),t.matchedFields.length>0&&e.jsx("div",{className:"flex flex-wrap gap-1",children:t.matchedFields.map((o,k)=>e.jsx(l,{variant:"outline",className:"text-xs",children:o},k))})]},s))]})]})}),i.suggestions.length>0&&e.jsx(S,{title:`Improvement Suggestions (${i.suggestions.length})`,icon:e.jsx(D,{className:"h-4 w-4 text-blue-500"}),isOpen:r.has("suggestions"),onToggle:()=>d("suggestions"),children:e.jsx("div",{className:"space-y-2",children:i.suggestions.map((t,s)=>e.jsxs("div",{className:"flex items-start gap-2 p-2 bg-blue-500/5 border border-blue-500/20 rounded",children:[e.jsx(D,{className:"h-4 w-4 text-blue-500 shrink-0 mt-0.5"}),e.jsx("p",{className:"text-sm",children:t})]},s))})})]})}function S({title:i,icon:u,isOpen:n,onToggle:p,children:r}){return e.jsxs(b,{children:[e.jsxs("div",{className:"flex items-center gap-2 p-4 cursor-pointer hover:bg-muted/50",onClick:p,children:[n?e.jsx(me,{className:"h-4 w-4 shrink-0"}):e.jsx(xe,{className:"h-4 w-4 shrink-0"}),u,e.jsx("span",{className:"font-medium text-sm",children:i})]}),n&&e.jsx(w,{className:"pt-0",children:r})]})}export{$e as default};
