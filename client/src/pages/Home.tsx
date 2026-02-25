import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { useState, useEffect, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import FedRAMPKSIMap from "@/components/FedRAMPKSIMap";
import {
  Key, Terminal, Activity, Users, ExternalLink, ChevronRight, Zap, Cloud,
  Mail, Phone, MapPin, Target, Shield, Radar, Globe, Crosshair, FileText,
  Briefcase, BarChart3, Sparkles, Network, Lock, Fingerprint, Scan,
  BookOpen, Server, Cpu, Eye, X, Brain, Layers, Radio, Workflow, Rocket,
  ShieldCheck, Palette, AlertTriangle, CheckCircle2, ArrowRight, Siren,
  Search, Code2, FileCode, Bug, Gauge, MonitorPlay, Building2, Stethoscope,
  GraduationCap, Landmark, Factory, ShoppingCart, Plane, ChevronDown, ChevronUp,
  Clock, TrendingUp, Unplug, FlaskConical, Camera, FileCheck2, Atom
} from "lucide-react";

// ─── Collapsible Section ────────────────────────────────────────────
function CollapsibleSection({ title, subtitle, defaultOpen = false, children }: {
  title: string; subtitle?: string; defaultOpen?: boolean; children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between text-left group"
      >
        <div>
          <h2 className="text-4xl sm:text-5xl font-display mb-1 group-hover:text-primary transition-colors">{title}</h2>
          {subtitle && <p className="text-lg text-muted-foreground max-w-3xl">{subtitle}</p>}
        </div>
        <div className="flex-shrink-0 ml-4 w-10 h-10 flex items-center justify-center border-2 border-border group-hover:border-primary transition-colors">
          {open ? <ChevronUp className="w-5 h-5 text-muted-foreground group-hover:text-primary" /> : <ChevronDown className="w-5 h-5 text-muted-foreground group-hover:text-primary" />}
        </div>
      </button>
      <div className={`overflow-hidden transition-all duration-500 ease-in-out ${open ? 'max-h-[5000px] opacity-100 mt-10' : 'max-h-0 opacity-0 mt-0'}`}>
        {children}
      </div>
    </div>
  );
}

// ─── What's New Popup ────────────────────────────────────────────────
const RECENT_UPDATES = [
  { date: "Feb 2026", title: "FedRAMP 20x KSI Coverage Map", desc: "Interactive map showing how ACE C3 covers 87% of all 55 FedRAMP 20x Key Security Indicators across 9 compliance themes. Dual-view for Cloud Service Providers seeking authorization and Federal Agencies monitoring their CSP portfolio. Expandable theme cards show individual KSI coverage with mapped ACE C3 modules." },
  { date: "Feb 2026", title: "ATT&CK Validation Tests", desc: "1,400+ ATT&CK-mapped atomic tests synced and ready to execute. Browse by technique, tactic, or platform. Run tests against target systems with full audit trails. Cross-module integration links validation tests to Attack Planner, Emulation Playbooks, Purple Team exercises, adversary operations, DAST findings, and detection rule validation." },
  { date: "Feb 2026", title: "DAST Server Deployed", desc: "Dedicated DAST scanning server deployed with auto-restart. Dual-mode scanning: passive recon for safe crawling and active DAST for coordinated attack testing. AI-powered scan configuration auto-tunes spider depth, authentication handlers, and scan policies based on target tech stack detection." },
  { date: "Feb 2026", title: "OpenAPI / GraphQL / SOAP Import", desc: "Import API specifications directly into DAST scans for targeted API security testing. Supports OpenAPI/Swagger, GraphQL introspection endpoints, and WSDL definitions. Auto-discovers API endpoints and parameters for comprehensive coverage beyond traditional web crawling." },
  { date: "Feb 2026", title: "Unified Offensive Stack", desc: "Full exploit, C2, and DAST stack unified under one command center — 2,600+ exploit modules, 1,900+ emulation abilities, DAST scanning, 1,400+ ATT&CK validation tests, and social engineering campaigns. All orchestrated with cross-tool correlation and ATT&CK mapping." },
  { date: "Feb 2026", title: "AI-Powered DAST Orchestrator", desc: "LLM trained on all 12 scanner API categories for full coverage. Auto-configures scan policies, authentication handlers (form-based, token-based, OAuth), and technology-specific rules. AI triage reduces false positives and maps findings to ATT&CK techniques with exploit correlation." },
  { date: "Feb 2026", title: "SIEM/EDR Evasion Engine", desc: "Three-tier evasion architecture: SIEM Rule Mutation Engine generates 9+ evasive variants per command. Payload Transformation Pipeline chains multiple obfuscation tools with configurable stealth profiles. Evasion Scorecard produces Campaign Stealth Scores with per-technique detection gaps and purple team remediation actions." },
  { date: "Feb 2026", title: "Red Team Discovery Coverage", desc: "Maps all 10 red team discovery priorities to pipeline connectors with weighted scoring. Coverage tab shows per-priority status, quality assessment, contributing sources, and MITRE ATT&CK technique alignment." },
  { date: "Feb 2026", title: "Confirmed-Only Vulnerability Counting", desc: "Vulnerability counts show only confirmed findings by default — KEV-listed, 0-day, or version-matched with exploit evidence. Tier toggle reveals probable and potential matches." },
  { date: "Feb 2026", title: "4 New OSINT Connectors", desc: "Email Security (DMARC/SPF/DKIM/MX spoofability scoring), HTTP Security Headers (WAF, CSP, HSTS), Cloud Asset Discovery (S3/Azure/GCP buckets), and DNS Deep Analysis (A/AAAA/CNAME/NS/SOA/TXT/SRV/CAA with CDN detection)." },
  { date: "Feb 2026", title: "Autonomous Validation Engine", desc: "LLM-driven exploit validation runs real checks against confirmed CVEs using exploit modules from multiple sources. Evidence capture stores console output, session data, and HTML proof reports." },
  { date: "Feb 2026", title: "Kill Chain Timeline & Event Streaming", desc: "Unified engagement timeline with WebSocket-powered live updates. Exploit results, agent deployments, scan progress, and atomic test executions appear instantly across all pages." },
  { date: "Feb 2026", title: "Phishing Exploit Library", desc: "17 advanced phishing techniques (BITB, AiTM, HTML smuggling, MFA bypass, OAuth abuse, ClickFix, quishing) auto-injected into campaign templates based on target intelligence." },
];

function UpdatesPopup({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-card border-2 border-primary/50 w-full max-w-lg mx-4 max-h-[80vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between p-6 border-b border-border">
          <div>
            <h3 className="font-display text-xl tracking-wider text-primary">WHAT'S NEW</h3>
            <p className="text-sm text-muted-foreground mt-1">Latest platform updates</p>
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

// ─── Animated Counter ────────────────────────────────────────────────
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
      <div className="font-display text-4xl sm:text-5xl text-white mb-2">
        {count.toLocaleString()}{suffix}
      </div>
      <div className="text-xs tracking-[0.25em] text-muted-foreground">{label}</div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════
//  HOMEPAGE
// ═════════════════════════════════════════════════════════════════════
export default function Home() {
  const [showUpdates, setShowUpdates] = useState(true);
  const { data: liveStats } = trpc.platformStats.getHomepageStats.useQuery(undefined, {
    staleTime: 5 * 60 * 1000, // cache for 5 minutes
    refetchOnWindowFocus: false,
  });

  // Fallback to verified static values if API hasn't loaded yet
  const stats = useMemo(() => ({
    exploitModules: liveStats?.metasploitModules ?? 2617, // API field name kept for backward compat
    threatActors: liveStats?.threatActors ?? 1694,
    calderaAbilities: liveStats?.calderaAbilities ?? 1919, // API field name kept for backward compat
    platformModules: liveStats?.platformModules ?? 29,
    exploitCatalogTotal: liveStats?.exploitCatalogTotal ?? 4281,
  }), [liveStats]);

  return (
    <div className="min-h-screen bg-background text-foreground">
      {showUpdates && <UpdatesPopup onClose={() => setShowUpdates(false)} />}

      {/* ─── Navigation ─────────────────────────────────────────── */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="container flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <Cloud className="w-8 h-8 text-primary" />
            <span className="font-display text-2xl tracking-wider">ACE C3</span>
          </div>
          <div className="hidden md:flex items-center gap-6 text-sm font-display tracking-wider text-muted-foreground">
            <a href="#how-it-works" className="hover:text-primary transition-colors">HOW IT WORKS</a>
            <a href="#who-its-for" className="hover:text-primary transition-colors">WHO IT'S FOR</a>
            <a href="#capabilities" className="hover:text-primary transition-colors">CAPABILITIES</a>
            <a href="#fedramp-20x" className="hover:text-primary transition-colors">FEDRAMP 20x</a>
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

      {/* ═══════════════════════════════════════════════════════════
          ABOVE THE FOLD — CUSTOMER-FACING, NON-TECHNICAL
          ═══════════════════════════════════════════════════════════ */}

      {/* ─── Hero Section ───────────────────────────────────────── */}
      <section className="relative pt-28 pb-24 overflow-hidden">
        <div className="container">
          <div className="max-w-4xl mx-auto text-center">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 border border-primary/40 text-primary text-xs font-display tracking-widest mb-8">
              <Shield className="w-3.5 h-3.5" />
              UNIFIED OFFENSIVE PLATFORM
            </div>

            <h1 className="text-5xl sm:text-6xl md:text-7xl lg:text-8xl font-display leading-[0.9] tracking-tight mb-8">
              KNOW YOUR
              <br />
              <span className="text-primary">WEAKNESSES</span>
              <br />
              <span className="text-3xl sm:text-4xl md:text-5xl text-muted-foreground font-display">BEFORE ATTACKERS DO.</span>
            </h1>

            <p className="text-xl md:text-2xl text-muted-foreground max-w-2xl mx-auto mb-6 leading-relaxed">
              Exploit execution, adversary emulation, DAST scanning, ATT&CK validation,
              and social engineering — unified under one AI-powered command center with evidence-backed reporting.
            </p>

            <p className="text-sm text-muted-foreground max-w-xl mx-auto mb-10">
              Stop switching between disconnected terminals. Ace C3 orchestrates your entire
              exploit-to-report workflow: reconnaissance, DAST scanning, adversary emulation,
              social engineering, detection validation, and compliance reporting — all correlated
              through MITRE ATT&CK.
            </p>

            <div className="flex flex-wrap justify-center gap-4 mb-12">
              <Link href="/dashboard">
                <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-8 py-6 text-base">
                  START TESTING YOUR DEFENSES
                  <ArrowRight className="w-5 h-5 ml-2" />
                </Button>
              </Link>
              <a href="#how-it-works">
                <Button size="lg" variant="outline" className="font-display tracking-wider border-2 border-white/30 hover:border-white hover:bg-white hover:text-background px-8 py-6 text-base">
                  SEE HOW IT WORKS
                  <ChevronDown className="w-5 h-5 ml-2" />
                </Button>
              </a>
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

      {/* ─── Three Value Propositions ───────────────────────────── */}
      <section className="py-20">
        <div className="container">
          <div className="grid md:grid-cols-3 gap-8 lg:gap-12">

            <div className="text-center px-4">
              <div className="w-16 h-16 mx-auto mb-6 flex items-center justify-center border-2 border-primary/50 bg-primary/5">
                <Search className="w-8 h-8 text-primary" />
              </div>
              <h3 className="font-display text-xl tracking-wider mb-4">SCAN & DISCOVER</h3>
              <p className="text-muted-foreground leading-relaxed">
                Automated DAST scans web applications for OWASP Top 10 vulnerabilities while 16 OSINT
                connectors map your external attack surface. AI auto-configures scan policies based
                on detected tech stacks — including API specs, authentication flows, and SPAs.
              </p>
            </div>

            <div className="text-center px-4">
              <div className="w-16 h-16 mx-auto mb-6 flex items-center justify-center border-2 border-primary/50 bg-primary/5">
                <Target className="w-8 h-8 text-primary" />
              </div>
              <h3 className="font-display text-xl tracking-wider mb-4">EXPLOIT & EMULATE</h3>
              <p className="text-muted-foreground leading-relaxed">
                Real exploit execution with 2,600+ modules. Adversary emulation with 1,900+
                abilities. 1,400+ ATT&CK validation tests. Social engineering campaigns with
                17 phishing techniques. All coordinated through one kill chain.
              </p>
            </div>

            <div className="text-center px-4">
              <div className="w-16 h-16 mx-auto mb-6 flex items-center justify-center border-2 border-primary/50 bg-primary/5">
                <ShieldCheck className="w-8 h-8 text-primary" />
              </div>
              <h3 className="font-display text-xl tracking-wider mb-4">VALIDATE & REPORT</h3>
              <p className="text-muted-foreground leading-relaxed">
                Every exploitable finding is backed by captured proof — console output, session data,
                and HTML evidence reports. Auto-generate detection rules from executed TTPs, measure
                SIEM coverage gaps, and deliver compliance-ready reports with evidence artifacts.
              </p>
            </div>

          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── How It Works (Plain English) ───────────────────────── */}
      <section id="how-it-works" className="py-20 bg-card/30">
        <div className="container">
          <div className="max-w-3xl mx-auto text-center mb-16">
            <h2 className="text-4xl sm:text-5xl font-display mb-4">HOW IT WORKS</h2>
            <p className="text-lg text-muted-foreground">
              Four steps from "I don't know what's vulnerable" to "here's proof of what needs fixing."
            </p>
          </div>

          <div className="max-w-4xl mx-auto">
            <div className="grid md:grid-cols-2 gap-6">
              {[
                {
                  step: "1",
                  icon: Radar,
                  title: "Discover Your Attack Surface",
                  desc: "Point Ace C3 at your domain. Automated DAST crawls web applications while 16 OSINT connectors map exposed servers, services, and technologies. AI auto-tunes scan policies based on detected tech stacks. Import OpenAPI, GraphQL, or SOAP specs for full API coverage."
                },
                {
                  step: "2",
                  icon: Bug,
                  title: "Match Vulnerabilities to Exploits",
                  desc: "DAST findings and confirmed CVEs are automatically matched to exploit modules and public exploit databases. 1,400+ ATT&CK techniques mapped to executable validation tests. You see exactly which weaknesses have working attacks."
                },
                {
                  step: "3",
                  icon: Crosshair,
                  title: "Execute Real Attacks",
                  desc: "Real exploit execution against confirmed vulnerabilities. Adversary emulation with APT-based profiles and 1,900+ abilities. Social engineering campaigns with 17 phishing techniques. ATT&CK validation tests confirm detection coverage — all controlled and audited."
                },
                {
                  step: "4",
                  icon: BarChart3,
                  title: "Validate, Measure & Report",
                  desc: "Autonomous validation confirms which CVEs are actually exploitable. Evidence capture stores console output, session data, and HTML proof reports. Auto-generate detection rules from executed TTPs. Deliver compliance-ready reports with validation coverage metrics and clickable evidence artifacts."
                },
              ].map((item) => (
                <div key={item.step} className="flex gap-5 p-6 border-2 border-border hover:border-primary/40 transition-colors bg-card/50">
                  <div className="flex-shrink-0">
                    <div className="w-12 h-12 flex items-center justify-center border-2 border-primary text-primary font-display text-xl">
                      {item.step}
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <item.icon className="w-4 h-4 text-primary" />
                      <h3 className="font-display text-base tracking-wider">{item.title}</h3>
                    </div>
                    <p className="text-sm text-muted-foreground leading-relaxed">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>



      <div className="w-full h-px bg-primary" />

      {/* ─── Stats Bar ──────────────────────────────────────────── */}
      <section className="py-16 bg-card/50">
        <div className="container">
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-8">
            <AnimatedStat value={stats.exploitModules} label="EXPLOIT MODULES" suffix="+" />
            <AnimatedStat value={stats.calderaAbilities} label="EMULATION ABILITIES" suffix="" />
            <AnimatedStat value={1400} label="ATT&CK VALIDATION TESTS" suffix="+" />
            <AnimatedStat value={stats.threatActors} label="THREAT ACTORS" suffix="+" />
            <AnimatedStat value={5} label="INTEGRATED TOOLS" suffix="" />
            <AnimatedStat value={stats.platformModules} label="PLATFORM MODULES" suffix="" />
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Who It's For (Simplified) ──────────────────────────── */}
      <section id="who-its-for" className="py-20">
        <div className="container">
          <div className="max-w-3xl mx-auto text-center mb-16">
            <h2 className="text-4xl sm:text-5xl font-display mb-4">WHO IT'S FOR</h2>
            <p className="text-lg text-muted-foreground">
              Designed for teams that need to prove security works — not just check compliance boxes.
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-5xl mx-auto">
            {[
              { icon: Crosshair, title: "Red Teams", desc: "Orchestrate exploits, emulation, DAST, and ATT&CK validation from one command center. Run full adversary emulation with real exploits, DAST scanning, and ATT&CK-mapped validation." },
              { icon: Shield, title: "Penetration Testers", desc: "Scope engagements, run DAST scans, execute exploits, launch phishing campaigns, and deliver evidence-backed reports — all in one workflow." },
              { icon: ShieldCheck, title: "Purple Teams", desc: "Execute ATT&CK validation tests and adversary operations, then immediately measure what your defenses catch. Auto-generate detection rules from executed TTPs." },
              { icon: Server, title: "Managed Service Providers", desc: "Scale offensive assessments across multiple clients with per-engagement tracking, automated pipelines, and branded reporting." },
              { icon: Building2, title: "Enterprise Security", desc: "Test employee awareness and infrastructure resilience with controlled attack simulations mapped to your industry's threat landscape." },
              { icon: Landmark, title: "Government & Defense", desc: "Support compliance with FedRAMP, CMMC, and NIST frameworks through evidence-based security testing and audit-ready reports." },
            ].map((item) => (
              <div key={item.title} className="p-6 border-2 border-border hover:border-primary/40 transition-colors bg-card/30">
                <item.icon className="w-7 h-7 text-primary mb-4" />
                <h3 className="font-display text-lg tracking-wider mb-3">{item.title}</h3>
                <p className="text-sm text-muted-foreground leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>

          {/* Additional sectors */}
          <div className="mt-8 max-w-5xl mx-auto">
            <div className="border border-border/50 p-6">
              <h3 className="font-display text-xs tracking-[0.25em] text-muted-foreground mb-4">ALSO DESIGNED FOR</h3>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                {[
                  { icon: Stethoscope, label: "Healthcare" },
                  { icon: GraduationCap, label: "Education" },
                  { icon: Factory, label: "Manufacturing" },
                  { icon: ShoppingCart, label: "Retail" },
                  { icon: Plane, label: "Critical Infrastructure" },
                  { icon: Network, label: "Cloud & SaaS" },
                ].map((s) => (
                  <div key={s.label} className="flex items-center gap-2 p-2 text-xs text-muted-foreground">
                    <s.icon className="w-3.5 h-3.5 text-primary flex-shrink-0" />
                    <span className="font-display tracking-wider">{s.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── CTA Break ──────────────────────────────────────────── */}
      <section className="py-16 bg-primary/5 border-y border-primary/20">
        <div className="container text-center">
          <h2 className="text-3xl sm:text-4xl font-display mb-4">READY TO TEST YOUR DEFENSES?</h2>
          <p className="text-muted-foreground mb-8 max-w-xl mx-auto">
            Enter the Command Center to orchestrate your full offensive stack — exploits, emulation, DAST, validation, and social engineering from one interface.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <Link href="/dashboard">
              <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-8 py-6">
                ENTER COMMAND CENTER
                <ChevronRight className="w-5 h-5 ml-2" />
              </Button>
            </Link>
            <a href="https://aceofcloud.com" target="_blank" rel="noopener noreferrer">
              <Button size="lg" variant="outline" className="font-display tracking-wider border-2 border-primary text-primary hover:bg-primary hover:text-white px-8 py-6">
                LEARN ABOUT ACE OF CLOUD
                <ExternalLink className="w-4 h-4 ml-2" />
              </Button>
            </a>
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════════════════════════
          BELOW THE FOLD — TECHNICAL DETAILS
          ═══════════════════════════════════════════════════════════ */}

      {/* ─── Platform Capabilities — 6 Pillars ──────────────────── */}
      <section id="capabilities" className="py-20">
        <div className="container">
          <div className="inline-flex items-center gap-2 px-3 py-1 border border-border text-muted-foreground text-xs font-display tracking-widest mb-6">
            <Terminal className="w-3 h-3" />
            TECHNICAL DETAILS
          </div>
          <CollapsibleSection
            title="PLATFORM CAPABILITIES"
            subtitle="Six integrated pillars covering the full offensive execution lifecycle."
          >
          <div className="grid lg:grid-cols-3 gap-6">
            <PillarCard
              icon={<Target className="w-7 h-7" />}
              number="01"
              title="ADVERSARY EMULATION"
              description={`${stats.exploitModules.toLocaleString()}+ exploit modules execute real attacks. ${stats.calderaAbilities.toLocaleString()} adversary abilities run emulation campaigns. 1,400+ ATT&CK validation tests confirm detection coverage. All correlated through MITRE ATT&CK mapping.`}
              features={[
                "Real exploit execution with session management",
                "Adversary emulation with APT-based profiles",
                "1,400+ ATT&CK-mapped validation tests",
                "Cross-tool correlation: exploits → abilities → validation tests",
                "Cloud-provisioned exploit infrastructure with agent stagers",
                "Real-time operation monitoring with ATT&CK visualization",
              ]}
              link="/agents"
              linkLabel="DEPLOY AGENTS"
            />

            <PillarCard
              icon={<Zap className="w-7 h-7" />}
              number="02"
              title="SOCIAL ENGINEERING"
              description="Social engineering with 17 phishing exploit techniques — BITB, AiTM, HTML smuggling, MFA bypass, OAuth abuse, ClickFix, quishing — auto-injected into campaigns based on target intelligence."
              features={[
                "17 phishing exploit techniques auto-matched to targets",
                "BITB fake SSO, AiTM proxy, HTML smuggling, MFA bypass",
                "Typosquat domain purchasing with auto DNS configuration",
                "AI-powered template generation from threat actor TTPs",
                "6-step campaign wizard with exploit-enhanced previews",
                "26 pre-built templates across 10 categories",
              ]}
              link="/phishing-ops"
              linkLabel="MANAGE CAMPAIGNS"
            />

            <PillarCard
              icon={<Radar className="w-7 h-7" />}
              number="03"
              title="OSINT & RECONNAISSANCE"
              description="DAST scanning with AI-powered configuration plus 16 passive recon connectors. Dual-mode: passive crawling for safe recon, active DAST for coordinated attack testing. Import OpenAPI, GraphQL, and SOAP specs for full API security coverage."
              features={[
                "DAST scanning with LLM-tuned scan policies",
                "OpenAPI / GraphQL / SOAP spec import for API testing",
                "AJAX Spider for JavaScript-heavy SPA applications",
                "16 OSINT connectors with confirmed-only vuln counting",
                "Email, HTTP headers, cloud assets, DNS deep analysis",
                "Scan comparison: side-by-side risk posture delta",
              ]}
              link="/domain-intel"
              linkLabel="START SCANNING"
            />

            <PillarCard
              icon={<Brain className="w-7 h-7" />}
              number="04"
              title="THREAT & VULN INTELLIGENCE"
              description={`${stats.threatActors.toLocaleString()} threat actor profiles with kill chain visualization, exploit cross-referencing, and one-click campaign deployment. Five aggregated vulnerability feeds with live verification.`}
              features={[
                "APT matching with kill chain and confidence breakdown",
                "Exploit cross-reference: which techniques have exploits",
                "One-click campaign deployment from matched threat actors",
                "Unified vuln feeds from 5+ authoritative sources",
                "0-day tracking with exploit availability indicators",
                "Aggregated IOC feeds from multiple threat intelligence sources",
              ]}
              link="/vuln-intel"
              linkLabel="VULN INTELLIGENCE"
            />

            <PillarCard
              icon={<ShieldCheck className="w-7 h-7" />}
              number="05"
              title="VALIDATION & DETECTION"
              description="Autonomous exploit validation confirms which CVEs are actually exploitable using LLM-built modules from multiple exploit sources. Evidence capture stores proof artifacts. Detection engineering auto-generates rules from executed TTPs."
              features={[
                "Autonomous Validation Engine with KEV/CVSS prioritization",
                "Evidence capture: console output, session info, HTML reports",
                "Validation Coverage metric with quality assessment tiers",
                "Auto-rescore assets based on confirmed exploitability",
                "Auto-generate Sigma, YARA, and Suricata detection rules",
                "Validate in 5 formats: Sigma, YARA, Suricata, SPL, KQL",
              ]}
              link="/validation-engine"
              linkLabel="VALIDATION ENGINE"
            />

            <PillarCard
              icon={<BarChart3 className="w-7 h-7" />}
              number="06"
              title="REPORTING & AUTOMATION"
              description="Professional reports with proof-of-exploit evidence artifacts, validation coverage metrics, and remediation steps. Executive summaries include color-coded coverage bars and clickable S3 evidence links."
              features={[
                "PDF reports with embedded S3 evidence artifact links",
                "Validation Coverage bar in executive summary exports",
                "Evidence Details page with artifact types and file sizes",
                "Kill chain timeline with real-time event streaming",
                "Unified Engagement Manager: OSINT → Exploit → Validate → Report",
                "Scan comparison reports for risk trending",
              ]}
              link="/post-engagement-report"
              linkLabel="GENERATE REPORTS"
            />
          </div>
          </CollapsibleSection>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Operations Grid — All Modules ──────────────────────── */}
      <section id="operations" className="py-20 bg-card/30">
        <div className="container">
          <CollapsibleSection
            title="OPERATIONS CENTER"
            subtitle="30+ integrated modules organized across six operational domains."
          >
          <div className="space-y-12">
            <ModuleSection
              title="COMMAND & CONTROL"
              color="text-primary"
              modules={[
                { icon: Activity, name: "Dashboard", desc: "Live operational overview with agent counts, campaign metrics, tool health, and ZAP scan status" },
                { icon: Briefcase, name: "Engagement Manager", desc: "Unified engagement + campaign management with 6-phase workflow" },
                { icon: Workflow, name: "Kill Chain Timeline", desc: "Real-time engagement timeline with WebSocket event streaming" },
                { icon: Key, name: "Credentials", desc: "Secure vault for API keys, SSH credentials, and admin access" },
                { icon: Target, name: "Adversaries", desc: "Adversary profiles with APT-based creation" },
                { icon: Cpu, name: "Agents", desc: "Agent deployment, trust management, and kill commands" },
                { icon: FileText, name: "Activity Log", desc: "Full audit trail of all platform actions" },
              ]}
            />

            <ModuleSection
              title="CAMPAIGN OPERATIONS"
              color="text-red-400"
              modules={[
                { icon: Zap, name: "Phishing Ops", desc: "Exploit-enhanced phishing campaigns with 15 advanced techniques" },
                { icon: Globe, name: "Typosquat Domains", desc: "Auto-identify, purchase, and configure typosquat domains for campaigns" },
                { icon: Crosshair, name: "Campaign Wizard", desc: "Guided 6-step launch with exploit-enhanced template previews" },
                { icon: Palette, name: "Page Builder", desc: "Visual landing page editor with exploit code injection" },
                { icon: Workflow, name: "Auto Pipeline", desc: "Automated: OSINT → exploit matching → campaign design → launch" },
                { icon: Sparkles, name: "Template Generator", desc: "AI-powered template creation with phishing exploit injection" },
              ]}
            />

            <ModuleSection
              title="EXPLOIT & EMULATION"
              color="text-orange-400"
              modules={[
                { icon: Bug, name: "Exploit Arsenal", desc: `Unified catalog: ${stats.exploitModules.toLocaleString()}+ exploit modules + phishing exploits + ATT&CK validation tests` },
                { icon: Server, name: "Exploit Servers", desc: "One-click cloud provisioning with auto-configured exploit frameworks" },
                { icon: Layers, name: "Abilities Library", desc: `${stats.calderaAbilities.toLocaleString()} emulation abilities organized by MITRE ATT&CK tactic` },
                { icon: Shield, name: "Threat Actors", desc: `${stats.threatActors.toLocaleString()} actor profiles with kill chains and campaign deployment` },
                { icon: Brain, name: "TTP Knowledge", desc: "MITRE ATT&CK technique encyclopedia with offensive tool mapping" },
                { icon: Atom, name: "ATT&CK Validation", desc: "1,400+ ATT&CK-mapped tests with cross-module integration and coverage mapping" },
              ]}
            />

            <ModuleSection
              title="INTELLIGENCE & RECON"
              color="text-amber-400"
              modules={[
                { icon: Brain, name: "Domain Intel", desc: "16 connectors with confirmed-only vuln counting and 3-tier corroboration" },
                { icon: Scan, name: "Web App Scanner", desc: "DAST with dual-mode scanning, AI config, OpenAPI/GraphQL import" },
                { icon: Radar, name: "Domain Recon", desc: "DNS deep, email security, HTTP headers, cloud assets, subdomains" },
                { icon: Eye, name: "Scan Comparison", desc: "Side-by-side diff: new/removed assets, CVE changes, risk deltas" },
                { icon: Radio, name: "IOC Feed", desc: "Aggregated feeds from multiple authoritative threat intelligence sources" },
              ]}
            />

            <ModuleSection
              title="DETECTION & VALIDATION"
              color="text-green-400"
              modules={[
                { icon: FlaskConical, name: "Validation Engine", desc: "LLM-driven exploit validation + ATT&CK test execution — KEV/CVSS prioritized, auto-rescore on confirmation" },
                { icon: Camera, name: "Evidence Capture", desc: "Automated proof collection: console output, session info, HTML reports, text screenshots stored in S3" },
                { icon: FileCheck2, name: "Validation Coverage", desc: "Real-time coverage metric tracking validated vs. unconfirmed findings with quality assessment tiers" },
                { icon: ShieldCheck, name: "Rule Validator", desc: "Validate Sigma, YARA, Suricata, Splunk SPL, and KQL with LLM analysis" },
                { icon: Target, name: "Coverage Matrix", desc: "Cross-reference rules vs attack chains to find SIEM gaps" },
                { icon: FileCode, name: "Actor Rules", desc: "Auto-generate detection rules from threat actor techniques" },
              ]}
            />

            <ModuleSection
              title="REPORTING & COMPLIANCE"
              color="text-violet-400"
              modules={[
                { icon: FileText, name: "Engagement Report", desc: "Branded HTML reports with MITRE heatmaps, evidence artifacts, and validation coverage" },
                { icon: BarChart3, name: "Report Generator", desc: "Executive summaries with proof-of-exploit evidence links and coverage bars" },
                { icon: Globe, name: "Compliance", desc: "NIST CSF, CMMC, and FedRAMP framework mapping" },
              ]}
            />
          </div>
          </CollapsibleSection>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Engagement Workflow ─────────────────────────────────── */}
      <section className="py-20">
        <div className="container">
          <CollapsibleSection
            title="ENGAGEMENT WORKFLOW"
            subtitle="Seven phases from OSINT through post-engagement reporting."
          >
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {[
              { step: "01", title: "RECON", desc: "DAST crawls web apps while 16 OSINT connectors map your attack surface with evidence-based risk scoring", icon: Radar },
              { step: "02", title: "EXPLOIT", desc: "Match DAST findings and confirmed CVEs to exploit modules and deploy with agent stagers", icon: Target },
              { step: "03", title: "OPERATE", desc: "Run adversary emulation operations with 1,900+ abilities and APT-based profiles", icon: Crosshair },
              { step: "04", title: "PHISH", desc: "Launch social engineering campaigns with 17 exploit-enhanced phishing techniques and typosquat domains", icon: Zap },
              { step: "05", title: "VALIDATE", desc: "Run ATT&CK validation tests and autonomous exploit validation with evidence capture", icon: FlaskConical },
              { step: "06", title: "DETECT", desc: "Auto-generate Sigma/YARA/Suricata rules from executed TTPs and measure SIEM coverage gaps", icon: ShieldCheck },
              { step: "07", title: "REPORT", desc: "Deliver reports with validation coverage metrics, evidence artifacts, and remediation steps", icon: FileText },
            ].map((item) => (
              <div key={item.step} className="text-center p-4 border border-border/50 bg-card/30 hover:border-primary/50 transition-colors">
                <item.icon className="w-6 h-6 text-primary mx-auto mb-3" />
                <div className="text-2xl font-display text-primary mb-2">{item.step}</div>
                <h3 className="font-display text-sm tracking-wider mb-2">{item.title}</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
          </CollapsibleSection>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Architecture ─────────────────────────────────────────── */}
      <section className="py-20 bg-card/30">
        <div className="container">
          <CollapsibleSection
            title="ARCHITECTURE"
            subtitle="Backend systems powering the platform."
          >
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-5">
            <ArchCard
              icon={<Server className="w-6 h-6" />}
              title="EXPLOIT & C2 ENGINE"
              items={[
                `${stats.exploitModules.toLocaleString()}+ exploit modules`,
                `${stats.calderaAbilities.toLocaleString()} adversary emulation abilities`,
                "1,400+ ATT&CK validation tests",
                "Cloud-provisioned exploit infrastructure",
                "Cross-tool correlation via MITRE ATT&CK",
              ]}
            />
            <ArchCard
              icon={<Target className="w-6 h-6" />}
              title="PHISHING & EXPLOIT LIBRARY"
              items={[
                "17 phishing exploit techniques",
                "BITB, AiTM, HTML smuggling, MFA bypass",
                "Typosquat domain purchasing + DNS config",
                "Intelligence-matched exploit injection",
                "Campaign execution & tracking",
              ]}
            />
            <ArchCard
              icon={<Radar className="w-6 h-6" />}
              title="DAST & RECON ENGINE"
              items={[
                "DAST scanning with AI-tuned policies",
                "OpenAPI / GraphQL / SOAP spec import",
                "16 passive recon connectors with confirmed-only counting",
                "3-tier evidence corroboration (confirmed/probable/potential)",
                "Scan comparison & risk trending",
              ]}
            />
            <ArchCard
              icon={<Bug className="w-6 h-6" />}
              title="VULN FEED ENGINE"
              items={[
                "KEV catalog with live verification",
                "Zero-day tracking with exploit availability",
                "Multiple national vulnerability databases",
                "Global exploit & advisory feeds",
                "Remote access vuln highlighting",
              ]}
            />
            <ArchCard
              icon={<FlaskConical className="w-6 h-6" />}
              title="VALIDATION & EVIDENCE ENGINE"
              items={[
                "LLM-driven exploit validation from multiple sources",
                "KEV/CVSS candidate prioritization",
                "4 evidence artifact types captured to S3",
                "Validation Coverage metric with quality tiers",
                "Auto-rescore assets on confirmed exploitability",
              ]}
            />
            <ArchCard
              icon={<Sparkles className="w-6 h-6" />}
              title="AI ORCHESTRATION LAYER"
              items={[
                "LLM-powered DAST scan configuration",
                "AI finding triage & false positive reduction",
                "Atomic test recommendation engine",
                "Detection rule auto-generation from TTPs",
                "Evidence-backed report generation",
              ]}
            />
            <ArchCard
              icon={<Radio className="w-6 h-6" />}
              title="REAL-TIME ENGINE"
              items={[
                "WebSocket event streaming",
                "Live kill chain timeline updates",
                "Exploit job monitoring",
                "Agent deployment tracking",
                "28 event types across 8 categories",
              ]}
            />
          </div>
          </CollapsibleSection>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── FedRAMP 20x KSI Map ────────────────────────────────── */}
      <FedRAMPKSIMap />

      <div className="w-full h-px bg-primary" />

      {/* ─── About Ace of Cloud ─────────────────────────────────── */}
      <section id="about" className="py-20">
        <div className="container">
          <h2 className="text-4xl sm:text-5xl font-display mb-8">ABOUT ACE OF CLOUD</h2>
          <div className="grid md:grid-cols-2 gap-12">
            <div>
              <p className="text-lg text-muted-foreground mb-6 leading-relaxed">
                Ace of Cloud provides cutting-edge cybersecurity solutions including FedRAMP Compliance,
                CMMC Preparation, Security Advisory, Secure Cloud Architecture, and Incident Response.
                Ace C3 is our unified offensive platform — orchestrating exploit execution, adversary emulation,
                DAST scanning, ATT&CK validation, and social engineering through a single AI-powered command center.
              </p>
              <p className="text-lg text-muted-foreground mb-8 leading-relaxed">
                Created by Harrison Cook, Ace C3 aligns to Gartner's CTEM framework across all five stages:
                scoping, discovery, prioritization, validation, and mobilization. Where vulnerability scanners
                stop at identification and BAS platforms stop at simulation, Ace C3 executes real exploits,
                runs adversary emulation, scans web applications, validates ATT&CK coverage, and tests
                human defenses — then captures evidence proving exploitability. Every finding is backed by proof, not theory.
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

      {/* ─── Footer ─────────────────────────────────────────────── */}
      <footer className="py-6 border-t border-border bg-card">
        <div className="container flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Cloud className="w-5 h-5 text-primary" />
            <span className="font-display tracking-wider">ACE C3</span>
          </div>
          <p className="text-sm text-muted-foreground text-center">
            Ace C3 — Unified Offensive Platform | Powered by Ace of Cloud
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

// ═══════════════════════════════════════════════════════════════════
//  HELPER COMPONENTS
// ═══════════════════════════════════════════════════════════════════

function ComparisonCard({
  icon, title, isOther, points
}: {
  icon: React.ReactNode; title: string; isOther?: boolean; points: string[];
}) {
  return (
    <div className={`p-6 border-2 ${isOther ? 'border-border bg-card/30' : 'border-primary/50 bg-primary/5'}`}>
      <div className="flex items-center gap-3 mb-5">
        <div className={isOther ? "text-muted-foreground" : "text-primary"}>{icon}</div>
        <h3 className={`font-display text-lg tracking-wider ${isOther ? 'text-muted-foreground' : 'text-primary'}`}>{title}</h3>
      </div>
      <div className="space-y-3">
        {points.map((p, i) => (
          <div key={i} className="flex items-start gap-3 text-sm">
            {isOther ? (
              <X className="w-4 h-4 text-red-400/60 flex-shrink-0 mt-0.5" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
            )}
            <span className={isOther ? "text-muted-foreground" : "text-foreground/80"}>{p}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

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
