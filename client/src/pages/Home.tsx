import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { useState, useEffect } from "react";
import {
  Key, Terminal, Activity, Users, ExternalLink, ChevronRight, Zap, Cloud,
  Mail, Phone, MapPin, Target, Shield, Radar, Globe, Crosshair, FileText,
  Briefcase, BarChart3, Sparkles, Network, Lock, Fingerprint, Scan,
  BookOpen, Server, Cpu, Eye, X, Brain, Layers, Radio, Workflow, Rocket,
  ShieldCheck, Palette, AlertTriangle, CheckCircle2, ArrowRight, Siren,
  Search, Code2, FileCode, Bug, Gauge, MonitorPlay, Building2, Stethoscope,
  GraduationCap, Landmark, Factory, ShoppingCart, Plane
} from "lucide-react";

const RECENT_UPDATES = [
  { date: "Feb 2026", title: "Evidence Corroboration Framework", desc: "3-tier validation system (Confirmed/Probable/Potential) with severity caps, evidence chains, and false-positive prevention" },
  { date: "Feb 2026", title: "Active DNS & Banner Verification", desc: "Real DNS resolution and HTTP header parsing to detect actual software versions and upgrade asset confidence" },
  { date: "Feb 2026", title: "Scan Comparison", desc: "Side-by-side scan diff showing new/removed assets, CVE changes, risk deltas, and evidence quality trends" },
  { date: "Feb 2026", title: "Vulnerability Intelligence", desc: "Unified 0-day tracker with CISA KEV, Project Zero, NVD, CIRCL, and Exploit-DB feeds with daily auto-sync" },
  { date: "Feb 2026", title: "Detection Coverage Matrix", desc: "Cross-reference validated rules against operation attack chains to identify SIEM gaps" },
  { date: "Feb 2026", title: "Post-Engagement Reports", desc: "Generate branded HTML reports with MITRE ATT&CK heatmaps, executive summaries, and remediation steps" },
  { date: "Feb 2026", title: "Auto Chain Builder", desc: "Build attack chains from matched actors, TTPs, and corroborated vulnerabilities — filters out unvalidated noise" },
  { date: "Feb 2026", title: "Landing Page Builder", desc: "Visual drag-and-drop editor with 6 theme presets and direct GoPhish export" },
];

function UpdatesPopup({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-card border-2 border-primary/50 w-full max-w-lg mx-4 max-h-[80vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between p-6 border-b border-border">
          <div>
            <h3 className="font-display text-xl tracking-wider text-primary">PLATFORM UPDATES</h3>
            <p className="text-sm text-muted-foreground mt-1">Recent additions to Ace C3</p>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors p-1">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="overflow-y-auto p-6 space-y-4">
          {RECENT_UPDATES.map((u, i) => (
            <div key={i} className="flex gap-4 items-start">
              <div className="flex-shrink-0 w-2 h-2 bg-primary rounded-full mt-2" />
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-display text-sm tracking-wider">{u.title}</span>
                  <span className="text-xs text-muted-foreground">{u.date}</span>
                </div>
                <p className="text-sm text-muted-foreground">{u.desc}</p>
              </div>
            </div>
          ))}
        </div>
        <div className="p-4 border-t border-border">
          <Button onClick={onClose} className="w-full font-display tracking-wider bg-primary hover:bg-primary/90">
            CONTINUE TO ACE C3
          </Button>
        </div>
      </div>
    </div>
  );
}

// Animated counter for stats
function AnimatedStat({ value, label, suffix = "" }: { value: number; label: string; suffix?: string }) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    const duration = 1500;
    const steps = 40;
    const increment = value / steps;
    let current = 0;
    const timer = setInterval(() => {
      current += increment;
      if (current >= value) {
        setCount(value);
        clearInterval(timer);
      } else {
        setCount(Math.floor(current));
      }
    }, duration / steps);
    return () => clearInterval(timer);
  }, [value]);
  return (
    <div className="text-center">
      <div className="font-display text-4xl sm:text-5xl lg:text-6xl text-white mb-2">
        {count.toLocaleString()}{suffix}
      </div>
      <div className="text-xs tracking-[0.25em] text-muted-foreground">{label}</div>
    </div>
  );
}



export default function Home() {
  const [showUpdates, setShowUpdates] = useState(true);

  return (
    <div className="min-h-screen bg-background text-foreground">
      {showUpdates && <UpdatesPopup onClose={() => setShowUpdates(false)} />}

      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="container flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <Cloud className="w-8 h-8 text-primary" />
            <span className="font-display text-2xl tracking-wider">ACE C3</span>
          </div>
          <div className="hidden md:flex items-center gap-6 text-sm font-display tracking-wider text-muted-foreground">
            <a href="#who-benefits" className="hover:text-primary transition-colors">WHO IT'S FOR</a>
            <a href="#capabilities" className="hover:text-primary transition-colors">CAPABILITIES</a>
            <a href="#operations" className="hover:text-primary transition-colors">OPERATIONS</a>
            <a href="#workflow" className="hover:text-primary transition-colors">WORKFLOW</a>
            <a href="#about" className="hover:text-primary transition-colors">ABOUT</a>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/login">
              <Button variant="ghost" className="font-display tracking-wider text-sm">
                LOG IN
              </Button>
            </Link>
            <Link href="/dashboard">
              <Button className="font-display tracking-wider bg-primary hover:bg-primary/90 text-sm">
                COMMAND CENTER
                <ChevronRight className="w-4 h-4 ml-1" />
              </Button>
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-28 pb-20 overflow-hidden">
        <div className="container">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1 border border-primary/40 text-primary text-xs font-display tracking-widest mb-6">
                <Siren className="w-3 h-3" />
                OFFENSIVE SECURITY PLATFORM
              </div>
              <h1 className="text-6xl md:text-8xl font-display leading-[0.9] tracking-tight mb-6">
                ACE
                <br />
                <span className="text-primary">C3</span>
              </h1>
              <p className="text-lg text-muted-foreground max-w-xl mb-4 leading-relaxed">
                Cyber Campaign Command — the offensive security execution platform that puts real attacks
                in motion. Run adversary emulation with MITRE Caldera, launch phishing campaigns through GoPhish,
                perform verified OSINT reconnaissance with DNS/banner validation, track vulnerabilities across
                5 intel feeds, and auto-generate detection rules to measure what your defenses actually catch.
              </p>
              <p className="text-sm text-primary mb-8 font-display tracking-wider">
                OFFENSIVE EXECUTION PLATFORM — POWERED BY ACE OF CLOUD
              </p>
              <div className="flex flex-wrap gap-3">
                <Link href="/dashboard">
                  <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-6 py-5">
                    ENTER COMMAND CENTER
                    <ChevronRight className="w-5 h-5 ml-1" />
                  </Button>
                </Link>
                <a href="https://caldera.aceofcloud.io" target="_blank" rel="noopener noreferrer">
                  <Button size="lg" variant="outline" className="font-display tracking-wider border-2 border-white/30 hover:border-white hover:bg-white hover:text-background px-6 py-5">
                    CALDERA SERVER
                    <ExternalLink className="w-4 h-4 ml-1" />
                  </Button>
                </a>
              </div>
            </div>

            {/* Hero Right — Live Platform Snapshot */}
            <div className="hidden lg:block">
              <div className="border-2 border-border bg-card/50 p-6 space-y-4">
                <div className="flex items-center gap-2 mb-4">
                  <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                  <span className="font-display text-xs tracking-widest text-muted-foreground">PLATFORM STATUS: OPERATIONAL</span>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { icon: Target, label: "Adversary Emulation", status: "MITRE Caldera" },
                    { icon: Zap, label: "Phishing Campaigns", status: "GoPhish" },
                    { icon: Radar, label: "OSINT & Recon", status: "DNS/Banner Verified" },
                    { icon: Bug, label: "Vuln Intelligence", status: "5 Feed Sources" },
                    { icon: ShieldCheck, label: "Detection Engineering", status: "5 Rule Formats" },
                    { icon: Brain, label: "Threat Intelligence", status: "492+ Actors" },
                  ].map((item) => (
                    <div key={item.label} className="flex items-center gap-3 p-3 bg-background/50 border border-border/50">
                      <item.icon className="w-4 h-4 text-primary flex-shrink-0" />
                      <div className="min-w-0">
                        <div className="text-xs font-display tracking-wider truncate">{item.label}</div>
                        <div className="text-[10px] text-muted-foreground">{item.status}</div>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="pt-2 border-t border-border/50 flex items-center justify-between text-[10px] text-muted-foreground font-display tracking-wider">
                  <span>50+ MODULES</span>
                  <span>28 API ROUTERS</span>
                  <span>427 TESTS PASSING</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Background Grid */}
        <div className="absolute inset-0 -z-10 opacity-[0.03]">
          <div className="absolute inset-0" style={{
            backgroundImage: `linear-gradient(to right, white 1px, transparent 1px),
                              linear-gradient(to bottom, white 1px, transparent 1px)`,
            backgroundSize: '60px 60px'
          }} />
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* Stats Bar */}
      <section className="py-16 bg-card/50">
        <div className="container">
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-8">
            <AnimatedStat value={492} label="THREAT ACTORS" suffix="+" />
            <AnimatedStat value={1940} label="CALDERA ABILITIES" suffix="+" />
            <AnimatedStat value={5} label="VULN FEED SOURCES" />
            <AnimatedStat value={3} label="CORROBORATION TIERS" />
            <AnimatedStat value={5} label="DETECTION FORMATS" />
            <AnimatedStat value={427} label="TESTS PASSING" />
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* Who Benefits */}
      <section id="who-benefits" className="py-20">
        <div className="container">
          <div className="mb-16">
            <h2 className="text-4xl sm:text-5xl lg:text-6xl font-display mb-4">WHO BENEFITS</h2>
            <p className="text-lg text-muted-foreground max-w-3xl">
              Ace C3 is built for teams that execute attacks, not just monitor for them. If your job
              involves breaking into systems, testing human defenses, or proving that detection stacks
              work under real adversary pressure — this is your command center.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 mb-12">
            <BenefitCard
              icon={<Crosshair className="w-7 h-7" />}
              title="RED TEAM OPERATORS"
              highlight="PRIMARY"
              description="Internal and consulting red teams running adversary emulation engagements. Ace C3 replaces the patchwork of disconnected tools with a single command center that chains OSINT, attack execution, detection validation, and client reporting into one workflow."
              features={[
                "Auto-build attack chains from corroborated vulnerabilities — no false positive noise",
                "1,940+ Caldera abilities mapped to MITRE ATT&CK across all 14 tactics",
                "5 vuln feed sources with 3-tier evidence corroboration",
                "Post-engagement reports with MITRE heatmaps generated in one click",
              ]}
            />
            <BenefitCard
              icon={<Shield className="w-7 h-7" />}
              title="PENETRATION TESTERS"
              highlight="PRIMARY"
              description="Independent and firm-based pentesters who need to scope engagements, execute phishing campaigns, and deliver professional reports. Ace C3 handles the full lifecycle from reconnaissance through branded deliverables."
              features={[
                "Domain intel with active DNS/banner verification and real version detection",
                "26 phishing templates across 10 categories with visual landing page builder",
                "Scan comparison to track risk posture changes between assessments",
                "Branded HTML reports with corroboration-filtered findings and remediation steps",
              ]}
            />
            <BenefitCard
              icon={<ShieldCheck className="w-7 h-7" />}
              title="PURPLE TEAM OPERATORS"
              highlight="PRIMARY"
              description="Offensive operators who need to prove whether defensive controls actually catch real TTPs. Ace C3 generates the attacks and the detection rules, then measures what got caught — closing the loop from execution to evidence."
              features={[
                "Auto-generate Sigma, YARA, and Suricata rules from each threat actor's techniques",
                "Validate rules in 5 formats with LLM-powered effectiveness scoring",
                "Detection coverage matrix shows exactly which techniques your SIEM misses",
                "Cross-reference operation attack chains against validated detection rules",
              ]}
            />
            <BenefitCard
              icon={<Server className="w-7 h-7" />}
              title="MANAGED SERVICE PROVIDERS"
              description="IT service providers managing security across multiple client environments. Ace C3's engagement management, automated pipelines, and per-client reporting let you scale offensive assessments without scaling headcount."
              features={[
                "Per-engagement tracking with linked campaigns, operations, and results",
                "Automated pipeline: OSINT → campaign design → template generation → launch",
                "Multi-tenant credential vault for API keys and access credentials",
                "Client-ready branded reports with compliance framework mapping",
              ]}
            />
            <BenefitCard
              icon={<Building2 className="w-7 h-7" />}
              title="ENTERPRISE SECURITY TEAMS"
              description="In-house security teams at enterprises, financial institutions, and technology companies who run internal red team exercises and phishing simulations to test employee awareness and infrastructure resilience."
              features={[
                "492+ threat actor profiles to emulate the adversaries most relevant to your sector",
                "Spoofability analysis with SPF/DKIM/DMARC scoring for your own domains",
                "Continuous OSINT monitoring with change detection and alerts",
                "Compliance mapping to NIST CSF, CMMC, and FedRAMP frameworks",
              ]}
            />
            <BenefitCard
              icon={<Landmark className="w-7 h-7" />}
              title="GOVERNMENT & DEFENSE CONTRACTORS"
              description="Organizations operating under FedRAMP, CMMC, or NIST 800-171 requirements who need to demonstrate security testing and compliance validation as part of their authorization process."
              features={[
                "FedRAMP control mapping with ATO boundary scoping",
                "CMMC Level 1–3 assessment support with control family coverage",
                "APT scenario library with nation-state threat group emulation",
                "Audit-ready reports with NIST 800-53 control mapping and ATT&CK references",
              ]}
            />
          </div>

          {/* Additional sectors */}
          <div className="border-2 border-border/50 p-6">
            <h3 className="font-display text-sm tracking-[0.25em] text-muted-foreground mb-4">ALSO SERVING</h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {[
                { icon: Stethoscope, label: "Healthcare", desc: "HIPAA-regulated environments" },
                { icon: GraduationCap, label: "Education", desc: "Universities & research institutions" },
                { icon: Factory, label: "Manufacturing", desc: "OT/ICS security validation" },
                { icon: ShoppingCart, label: "Retail & E-Commerce", desc: "PCI DSS environments" },
                { icon: Plane, label: "Critical Infrastructure", desc: "Energy, transport, utilities" },
                { icon: Network, label: "Cloud & SaaS Providers", desc: "Multi-tenant platforms" },
              ].map((s) => (
                <div key={s.label} className="flex items-start gap-3 p-3 bg-card/30 border border-border/30">
                  <s.icon className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
                  <div className="min-w-0">
                    <div className="text-xs font-display tracking-wider">{s.label}</div>
                    <div className="text-[10px] text-muted-foreground">{s.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* Core Capabilities — 6 Pillars */}
      <section id="capabilities" className="py-20">
        <div className="container">
          <div className="mb-16">
            <h2 className="text-4xl sm:text-5xl lg:text-6xl font-display mb-4">PLATFORM CAPABILITIES</h2>
            <p className="text-lg text-muted-foreground max-w-3xl">
              Six integrated pillars covering the full offensive execution lifecycle — from verified
              reconnaissance with evidence corroboration through live adversary emulation to detection
              rule generation and client reporting. Every finding is backed by evidence chains.
            </p>
          </div>

          <div className="grid lg:grid-cols-3 gap-6">
            {/* Pillar 1: Adversary Emulation */}
            <PillarCard
              icon={<Target className="w-7 h-7" />}
              number="01"
              title="ADVERSARY EMULATION"
              description="Execute real adversary tradecraft through MITRE Caldera. Deploy agents, run operations built from matched threat actors and corroborated vulnerabilities, and watch attack chains unfold in real time — with noise from unvalidated findings filtered out."
              features={[
                "Real-time operation monitoring with ATT&CK flow visualization",
                "Auto-build chains from corroborated vulns (confirmed/probable only)",
                "Agent deployment with trust level management",
                "1,940+ abilities across all MITRE ATT&CK tactics",
                "Vuln-feed-enriched chains with CVE-backed exploit steps",
                "Campaign execution dashboard with timeline and detection metrics",
              ]}
              link="/agents"
              linkLabel="DEPLOY AGENTS"
            />

            {/* Pillar 2: Social Engineering */}
            <PillarCard
              icon={<Zap className="w-7 h-7" />}
              number="02"
              title="SOCIAL ENGINEERING"
              description="Test the human attack surface. End-to-end phishing campaign execution through GoPhish with AI-powered template generation, a visual credential-capture page builder, and guided campaign launch."
              features={[
                "26 pre-built email templates across 10 categories",
                "Visual landing page builder with 6 theme presets (Microsoft, Google, Okta, AWS, Slack, Corporate)",
                "AI-powered template generation from threat actor TTPs",
                "6-step campaign wizard with template preview",
                "Template tagging, search, and difficulty filtering",
                "Recipient preview mode with device frames",
              ]}
              link="/phishing-ops"
              linkLabel="MANAGE CAMPAIGNS"
            />

            {/* Pillar 3: OSINT & Reconnaissance */}
            <PillarCard
              icon={<Radar className="w-7 h-7" />}
              number="03"
              title="OSINT & RECONNAISSANCE"
              description="Map the attack surface with verified evidence. Async domain intelligence pipeline with active DNS resolution, HTTP banner parsing for real version detection, and 3-tier corroboration that separates confirmed vulnerabilities from inferred risks."
              features={[
                "Active DNS & banner verification: real version detection from HTTP headers",
                "3-tier evidence corroboration: Confirmed, Probable, Potential with severity caps",
                "Async pipeline with real-time progress tracking (5 stages)",
                "Scan comparison: side-by-side risk posture delta over time",
                "Automatic threat actor matching from discovered attack surface",
                "SPF/DKIM/DMARC analysis with spoofability scoring",
              ]}
              link="/domain-intel"
              linkLabel="START SCANNING"
            />

            {/* Pillar 4: Threat Intelligence & Vuln Feeds */}
            <PillarCard
              icon={<Brain className="w-7 h-7" />}
              number="04"
              title="THREAT & VULN INTELLIGENCE"
              description="Know your adversary and their weapons. 492+ threat actor profiles with full TTP mapping, plus a unified vulnerability intelligence engine aggregating 5 feed sources with daily auto-sync and on-demand refresh."
              features={[
                "492+ threat actor profiles with MITRE ATT&CK mapping",
                "Unified vuln feeds: CISA KEV, Project Zero, NVD, CIRCL, Exploit-DB",
                "0-day tracker with exploit availability and weaponization indicators",
                "Daily auto-sync cron job with manual refresh trigger",
                "IOC feeds from Abuse.ch and ThreatFox",
                "APT scenario library and compliance framework mapping",
              ]}
              link="/vuln-intel"
              linkLabel="VULN INTELLIGENCE"
            />

            {/* Pillar 5: Detection Engineering */}
            <PillarCard
              icon={<ShieldCheck className="w-7 h-7" />}
              number="05"
              title="DETECTION ENGINEERING"
              description="Generate the detection rules your blue team should have written. Auto-create Sigma, YARA, and Suricata rules from the TTPs you just executed, then prove which ones your SIEM actually catches."
              features={[
                "Auto-generate Sigma, YARA, and Suricata rules from actor techniques",
                "Validate rules in 5 formats: Sigma, YARA, Suricata, Splunk SPL, KQL",
                "LLM-powered deep analysis with effectiveness scoring (0-100)",
                "Detection coverage matrix: rules vs operation attack chains",
                "False positive risk assessment and improvement suggestions",
                "Batch validation and sample log generation per technique",
              ]}
              link="/rule-validator"
              linkLabel="VALIDATE RULES"
            />

            {/* Pillar 6: Reporting & Automation */}
            <PillarCard
              icon={<BarChart3 className="w-7 h-7" />}
              number="06"
              title="REPORTING & AUTOMATION"
              description="Turn validated attack results into client-ready deliverables. Corroboration-aware reports only include confirmed and probable findings — no noise from unvalidated inferences. Automated pipelines handle the full lifecycle."
              features={[
                "Post-engagement HTML reports with custom branding",
                "Corroboration-aware: only confirmed/probable findings in reports",
                "MITRE ATT&CK heatmap visualization with evidence tiers",
                "Automated engagement pipeline: OSINT → design → launch",
                "AI campaign designer from corroborated OSINT findings",
                "Scan comparison reports for risk posture trending",
              ]}
              link="/post-engagement-report"
              linkLabel="GENERATE REPORTS"
            />
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* Operations Grid — All 45 Modules */}
      <section id="operations" className="py-20 bg-card/30">
        <div className="container">
          <div className="mb-16">
            <h2 className="text-4xl sm:text-5xl lg:text-6xl font-display mb-4">OPERATIONS CENTER</h2>
            <p className="text-lg text-muted-foreground max-w-3xl">
              50+ integrated modules organized across six operational domains.
              Every module connects to live backend APIs — no static dashboards.
            </p>
          </div>

          <div className="space-y-12">
            <ModuleSection
              title="COMMAND & CONTROL"
              color="text-primary"
              modules={[
                { icon: Activity, name: "Dashboard", desc: "Live operational overview with agent counts, campaign metrics, and system health" },
                { icon: Briefcase, name: "Engagements", desc: "Full lifecycle client engagement management with linked campaigns and results" },
                { icon: Key, name: "Credentials", desc: "Secure vault for API keys, SSH credentials, and admin access" },
                { icon: Target, name: "Adversaries", desc: "Caldera adversary profiles with custom creation and ability assignment" },
                { icon: Cpu, name: "Agents", desc: "Caldera agent deployment, trust management, and kill commands" },
                { icon: Users, name: "Team", desc: "Team member management and role-based access control" },
                { icon: FileText, name: "Activity Log", desc: "Full audit trail of all platform actions and API calls" },
              ]}
            />

            <ModuleSection
              title="CAMPAIGN OPERATIONS"
              color="text-red-400"
              modules={[
                { icon: Zap, name: "Campaigns", desc: "GoPhish campaign management with results tracking and completion controls" },
                { icon: Activity, name: "Campaign Execution", desc: "Real-time ATT&CK flow, timeline visualization, and detection rate metrics" },
                { icon: Crosshair, name: "Campaign Wizard", desc: "Guided 6-step launch: engagement, template, targets, SMTP, landing page, go" },
                { icon: Zap, name: "GoPhish Manager", desc: "Full API proxy with template sync, category tagging, and search/filter" },
                { icon: Palette, name: "Page Builder", desc: "Visual landing page editor with 6 themes and direct GoPhish export" },
                { icon: Workflow, name: "Auto Pipeline", desc: "Automated end-to-end: OSINT → campaign design → template → launch" },
                { icon: Sparkles, name: "Template Generator", desc: "AI-powered phishing template creation from threat actor TTPs" },
              ]}
            />

            <ModuleSection
              title="INTELLIGENCE & RECON"
              color="text-amber-400"
              modules={[
                { icon: Brain, name: "Domain Intel", desc: "Async pipeline: asset discovery, DNS/banner verification, corroborated risk scoring" },
                { icon: Scan, name: "DNS/Banner Verify", desc: "Active DNS resolution and HTTP header parsing for real version detection" },
                { icon: Radar, name: "Domain Recon", desc: "DNS/MX/SPF/DKIM/DMARC analysis, subdomains, spoofability scoring" },
                { icon: Eye, name: "Scan Comparison", desc: "Side-by-side diff of two scans: new/removed assets, CVE changes, risk deltas" },
                { icon: Bug, name: "Vuln Intelligence", desc: "Unified 0-day tracker: CISA KEV, Project Zero, NVD, CIRCL, Exploit-DB" },
                { icon: Radio, name: "IOC Feed", desc: "Aggregated feeds from CISA KEV, Abuse.ch, and ThreatFox" },
                { icon: Shield, name: "Threat Actors", desc: "492+ actor profiles with enrichment, TTPs, and detection rules" },
                { icon: Shield, name: "APT Scenarios", desc: "490+ threat group emulation scenarios for purple team exercises" },
                { icon: Layers, name: "Abilities Library", desc: "1,940+ Caldera abilities organized by MITRE ATT&CK tactic" },
                { icon: Brain, name: "TTP Knowledge", desc: "MITRE ATT&CK technique encyclopedia with Kali tool mapping" },
              ]}
            />

            <ModuleSection
              title="DETECTION & VALIDATION"
              color="text-green-400"
              modules={[
                { icon: ShieldCheck, name: "Rule Validator", desc: "Validate Sigma, YARA, Suricata, Splunk SPL, and KQL with LLM analysis" },
                { icon: Target, name: "Coverage Matrix", desc: "Cross-reference rules vs attack chains to find SIEM detection gaps" },
                { icon: FileCode, name: "Actor Rules", desc: "Auto-generate detection rules from each threat actor's known techniques" },
                { icon: FileText, name: "Template Library", desc: "26 phishing templates across 10 categories with preview and source view" },
              ]}
            />

            <ModuleSection
              title="REPORTING & COMPLIANCE"
              color="text-violet-400"
              modules={[
                { icon: FileText, name: "Engagement Report", desc: "AceofCloud-branded HTML reports with MITRE heatmaps and exec summaries" },
                { icon: BarChart3, name: "Report Generator", desc: "Engagement-based report compilation with campaign result aggregation" },
                { icon: FileText, name: "Security Report", desc: "Security posture assessment and vulnerability analysis reports" },
                { icon: FileText, name: "Compliance", desc: "NIST CSF, CMMC, and FedRAMP framework mapping and gap analysis" },
                { icon: Globe, name: "Infrastructure", desc: "Network architecture documentation and reference guides" },
              ]}
            />
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* Engagement Workflow */}
      <section id="workflow" className="py-20">
        <div className="container">
          <div className="mb-16">
            <h2 className="text-4xl sm:text-5xl lg:text-6xl font-display mb-4">ENGAGEMENT WORKFLOW</h2>
            <p className="text-lg text-muted-foreground max-w-3xl">
              Seven phases from initial reconnaissance through post-engagement reporting.
              Each phase is fully automated or wizard-guided — no manual context switching.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-7 gap-4">
            {[
              { step: "01", title: "ENGAGE", desc: "Create client engagement with scope, targets, and timeline", icon: Briefcase },
              { step: "02", title: "RECON", desc: "Domain intel with DNS/banner verification, vuln feeds, and corroborated risk scoring", icon: Radar },
              { step: "03", title: "DESIGN", desc: "AI generates campaign strategies from OSINT findings", icon: Sparkles },
              { step: "04", title: "BUILD", desc: "Create templates, landing pages, and adversary profiles", icon: Palette },
              { step: "05", title: "LAUNCH", desc: "Deploy phishing campaigns and adversary emulations", icon: Rocket },
              { step: "06", title: "DETECT", desc: "Validate detection rules against operation attack chains", icon: ShieldCheck },
              { step: "07", title: "REPORT", desc: "Generate branded reports with findings and remediation", icon: FileText },
            ].map((item) => (
              <div key={item.step} className="text-center p-4 border border-border/50 bg-card/30 hover:border-primary/50 transition-colors">
                <item.icon className="w-6 h-6 text-primary mx-auto mb-3" />
                <div className="text-2xl font-display text-primary mb-2">{item.step}</div>
                <h3 className="font-display text-sm tracking-wider mb-2">{item.title}</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* Architecture */}
      <section className="py-20 bg-card/30">
        <div className="container">
          <h2 className="text-4xl sm:text-5xl lg:text-6xl font-display mb-16">ARCHITECTURE</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
            <ArchCard
              icon={<Server className="w-6 h-6" />}
              title="CALDERA SERVER"
              items={[
                "Adversary emulation engine",
                "Agent C2 infrastructure",
                "1,940+ ability library",
                "Operation orchestration",
                "Auto chain builder",
              ]}
            />
            <ArchCard
              icon={<Target className="w-6 h-6" />}
              title="GOPHISH SERVER"
              items={[
                "Email campaign engine",
                "Credential harvesting",
                "Landing page hosting",
                "Template management",
                "Result tracking",
              ]}
            />
            <ArchCard
              icon={<Radar className="w-6 h-6" />}
              title="INTEL ENGINE"
              items={[
                "Domain intel with DNS/banner verification",
                "3-tier evidence corroboration",
                "Scan comparison & risk trending",
                "IOC feed aggregator",
                "Typosquat & spoofability analysis",
              ]}
            />
            <ArchCard
              icon={<Bug className="w-6 h-6" />}
              title="VULN FEED ENGINE"
              items={[
                "CISA KEV catalog",
                "Google Project Zero 0-days",
                "NVD/NIST CVE API 2.0",
                "CIRCL & Exploit-DB feeds",
                "Daily auto-sync + on-demand refresh",
              ]}
            />
            <ArchCard
              icon={<Sparkles className="w-6 h-6" />}
              title="AI LAYER"
              items={[
                "Campaign design from OSINT",
                "Detection rule generation",
                "Rule validation analysis",
                "Executive report summaries",
                "Corroboration-filtered chains",
              ]}
            />
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* About Ace of Cloud */}
      <section id="about" className="py-20">
        <div className="container">
          <h2 className="text-4xl sm:text-5xl lg:text-6xl font-display mb-8">ABOUT ACE OF CLOUD</h2>
          <div className="grid md:grid-cols-2 gap-12">
            <div>
              <p className="text-lg text-muted-foreground mb-6 leading-relaxed">
                Ace of Cloud provides cutting-edge cybersecurity solutions including FedRAMP Compliance,
                CMMC Preparation, Security Advisory, Secure Cloud Architecture, and Incident Response.
                Ace C3 is our offensive execution platform — purpose-built for teams that need to simulate
                real-world attacks, not just monitor for them.
              </p>
              <p className="text-lg text-muted-foreground mb-8 leading-relaxed">
                Where defensive platforms focus on telemetry normalization and alert prioritization, Ace C3
                focuses on the attack side: executing adversary emulation through MITRE Caldera, launching
                social engineering campaigns through GoPhish, performing verified OSINT reconnaissance with
                DNS/banner validation and 3-tier evidence corroboration, tracking vulnerabilities across 5
                intelligence feeds, and generating the detection rules that prove whether your defenses
                actually work under fire.
              </p>
              <div className="flex flex-wrap gap-3">
                <a href="https://aceofcloud.com" target="_blank" rel="noopener noreferrer">
                  <Button variant="outline" className="font-display tracking-wider border-2 border-primary text-primary hover:bg-primary hover:text-white">
                    VISIT ACEOFCLOUD.COM
                    <ExternalLink className="w-4 h-4 ml-2" />
                  </Button>
                </a>
                <Link href="/dashboard">
                  <Button className="font-display tracking-wider bg-primary hover:bg-primary/90">
                    ENTER COMMAND CENTER
                    <ArrowRight className="w-4 h-4 ml-2" />
                  </Button>
                </Link>
              </div>
            </div>
            <div className="space-y-6">
              <div className="flex items-start gap-4">
                <MapPin className="w-6 h-6 text-primary flex-shrink-0 mt-1" />
                <div>
                  <h4 className="font-display text-lg mb-1">HERNDON OFFICE</h4>
                  <p className="text-muted-foreground">13873 Park Center Rd, Suite 374<br />Herndon, Virginia 20171</p>
                </div>
              </div>
              <div className="flex items-start gap-4">
                <Mail className="w-6 h-6 text-primary flex-shrink-0 mt-1" />
                <div>
                  <h4 className="font-display text-lg mb-1">EMAIL</h4>
                  <a href="mailto:info@aceofcloud.com" className="text-primary hover:underline">info@aceofcloud.com</a>
                </div>
              </div>
              <div className="flex items-start gap-4">
                <Phone className="w-6 h-6 text-primary flex-shrink-0 mt-1" />
                <div>
                  <h4 className="font-display text-lg mb-1">PHONE</h4>
                  <a href="tel:703-488-8889" className="text-primary hover:underline">703-488-8889</a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-6 border-t border-border bg-card">
        <div className="container flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Cloud className="w-5 h-5 text-primary" />
            <span className="font-display tracking-wider">ACE C3</span>
          </div>
          <p className="text-sm text-muted-foreground text-center">
            Ace C3 — Cyber Campaign Command | Offensive Execution Platform | Powered by Ace of Cloud
          </p>
          <div className="flex items-center gap-4">
            <a href="https://aceofcloud.com" target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-primary transition-colors">
              <ExternalLink className="w-5 h-5" />
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

// === Component: Pillar Card ===
function PillarCard({
  icon, number, title, description, features, link, linkLabel
}: {
  icon: React.ReactNode; number: string; title: string; description: string;
  features: string[]; link: string; linkLabel: string;
}) {
  return (
    <div className="bg-card border-2 border-border hover:border-primary/50 transition-colors group flex flex-col">
      <div className="p-6 pb-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="text-primary">{icon}</div>
          <span className="font-display text-xs tracking-widest text-muted-foreground">{number}</span>
        </div>
        <h3 className="font-display text-xl tracking-wider mb-3">{title}</h3>
        <p className="text-sm text-muted-foreground leading-relaxed mb-4">{description}</p>
      </div>
      <div className="px-6 pb-4 flex-1">
        <div className="space-y-2">
          {features.map((f, i) => (
            <div key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
              <CheckCircle2 className="w-3 h-3 text-primary flex-shrink-0 mt-0.5" />
              <span>{f}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="p-6 pt-4 border-t border-border/50">
        <Link href={link}>
          <Button variant="ghost" size="sm" className="font-display tracking-wider text-primary text-xs p-0 h-auto hover:bg-transparent hover:text-primary/80">
            {linkLabel}
            <ArrowRight className="w-3 h-3 ml-1" />
          </Button>
        </Link>
      </div>
    </div>
  );
}

// === Component: Module Section ===
function ModuleSection({
  title, color, modules
}: {
  title: string; color: string;
  modules: { icon: React.ComponentType<{ className?: string }>; name: string; desc: string }[];
}) {
  return (
    <div>
      <h3 className={`font-display text-sm tracking-[0.25em] ${color} mb-4`}>{title}</h3>
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2">
        {modules.map((m) => (
          <div key={m.name} className="flex items-start gap-3 p-3 bg-card/50 border border-border/30 hover:border-border transition-colors">
            <m.icon className={`w-4 h-4 flex-shrink-0 mt-0.5 ${color}`} />
            <div className="min-w-0">
              <div className="text-xs font-display tracking-wider truncate">{m.name}</div>
              <div className="text-[10px] text-muted-foreground leading-relaxed">{m.desc}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// === Component: Benefit Card ===
function BenefitCard({
  icon, title, highlight, description, features
}: {
  icon: React.ReactNode; title: string; highlight?: string; description: string; features: string[];
}) {
  return (
    <div className={`bg-card border-2 ${highlight ? 'border-primary/50' : 'border-border'} hover:border-primary/70 transition-colors flex flex-col`}>
      <div className="p-6 pb-4">
        <div className="flex items-center justify-between mb-4">
          <div className="text-primary">{icon}</div>
          {highlight && (
            <span className="text-[10px] font-display tracking-widest px-2 py-0.5 bg-primary/10 text-primary border border-primary/30">
              {highlight}
            </span>
          )}
        </div>
        <h3 className="font-display text-lg tracking-wider mb-3">{title}</h3>
        <p className="text-sm text-muted-foreground leading-relaxed mb-4">{description}</p>
      </div>
      <div className="px-6 pb-6 flex-1">
        <div className="space-y-2">
          {features.map((f, i) => (
            <div key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
              <CheckCircle2 className="w-3 h-3 text-primary flex-shrink-0 mt-0.5" />
              <span>{f}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// === Component: Architecture Card ===
function ArchCard({ icon, title, items }: { icon: React.ReactNode; title: string; items: string[] }) {
  return (
    <div className="bg-background border-2 border-border p-6">
      <div className="flex items-center gap-3 mb-4">
        <div className="text-primary">{icon}</div>
        <h3 className="font-display text-lg tracking-wider">{title}</h3>
      </div>
      <div className="space-y-2">
        {items.map((item) => (
          <div key={item} className="flex items-center gap-2 text-sm text-muted-foreground">
            <div className="w-1.5 h-1.5 bg-primary flex-shrink-0" />
            {item}
          </div>
        ))}
      </div>
    </div>
  );
}
