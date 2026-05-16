import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { useState, useEffect, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import ThreatActorFeed from "@/components/ThreatActorFeed";
import {
  Terminal, Activity, ExternalLink, ChevronRight, Zap, Cloud,
  Target, Shield, Radar, Globe, Crosshair, FileText,
  Briefcase, BarChart3, Sparkles, Network, Lock, Fingerprint, Scan,
  Server, Cpu, Eye, X, Brain, Layers, Radio, Workflow, Rocket,
  ShieldCheck, Palette, CheckCircle2, ArrowRight,
  Search, FileCode, Bug, Building2, Stethoscope,
  GraduationCap, Landmark, Factory, ShoppingCart, Plane, ChevronDown, ChevronUp,
  Clock, TrendingUp, FlaskConical, Camera, FileCheck2, Atom,
  Menu, ShieldAlert, Scale, Handshake, Award, Key
} from "lucide-react";
import {
  Sheet, SheetTrigger, SheetContent, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";
import RequestDemoModal from "@/components/RequestDemoModal";
import FreeScanModal from "@/components/FreeScanModal";

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
  { date: "Apr 2026", title: "ScanForge Discovery Engine v2", desc: "Expanded the multi-tool discovery pipeline with Nerva service fingerprinting (120+ protocols), ssh-audit, testssl.sh, wafw00f WAF detection, katana web crawling, and context-aware scanning." },
  { date: "Mar 2026", title: "AC3 Report Generator", desc: "Generate professional pentest and red team reports. AI drafts narrative sections while the platform controls severity, evidence, and technique mappings. Includes executive summaries, QA review, and DOCX export." },
  { date: "Mar 2026", title: "Findings Deduplication", desc: "Automatically detects and merges duplicate findings during imports. Combines evidence, keeps the highest severity, and prevents duplicates within a single batch." },
  { date: "Mar 2026", title: "Engagement Findings Import", desc: "One-click import from completed engagements. Timeline events are automatically mapped to report findings with technique IDs, severity, and evidence." },
  { date: "Mar 2026", title: "Cloud Workload Testing", desc: "Test container, serverless, and cloud-native security across AWS, Azure, and GCP." },
  { date: "Mar 2026", title: "Forest Mapper", desc: "Visualize Active Directory forests, map trust relationships, and identify cross-forest attack paths." },
  { date: "Mar 2026", title: "SOAR & SOC Integration", desc: "Export findings, IOCs, and detection rules to SIEM, EDR, SOAR, and ticketing systems." },
  { date: "Feb 2026", title: "Discovery Chain", desc: "Automated 4-stage pipeline: subdomain enumeration, multi-engine port scanning, service fingerprinting with httpx, and vulnerability detection with Nuclei — all chained on dedicated infrastructure." },
  { date: "Feb 2026", title: "Unified Pipeline", desc: "All scanning tools feed into a single pipeline with cross-tool correlation and coverage tracking." },
  { date: "Feb 2026", title: "Threat Enrichment Engine", desc: "Continuously correlates threat actor TTPs and IOCs across all platform modules with risk scoring and priority updates." },
  { date: "Feb 2026", title: "Engagement Automation", desc: "5 engagement templates (pentest, red team, purple team, phishing, cloud) with pre-loaded techniques and abilities." },
  { date: "Feb 2026", title: "ATT&CK Validation Tests", desc: "1,400+ ATT&CK-mapped tests you can browse, execute, and track with full audit trails." },
  { date: "Feb 2026", title: "DAST Scanner", desc: "Dual-mode web app scanning: passive crawling for safe recon, active DAST for coordinated testing. AI auto-tunes scan policies." },
  { date: "Feb 2026", title: "Autonomous Validation", desc: "AI-driven exploit validation runs authorized checks against confirmed CVEs and captures proof artifacts." },
  { date: "Feb 2026", title: "Evasion Engine", desc: "Generate evasive command variants, chain obfuscation tools, and score campaign stealth with detection gap analysis." },
  { date: "Feb 2026", title: "Threat Actor Intelligence", desc: "Browse 1,600+ deduplicated threat actor profiles with ATT&CK-mapped techniques, tools, campaigns, and target sectors." },
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
            CONTINUE TO AC3
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
    staleTime: 5 * 60 * 1000,
    refetchOnWindowFocus: false,
  });

  const stats = useMemo(() => ({
    exploitModules: liveStats?.metasploitModules ?? 2617,
    threatActors: liveStats?.threatActors ?? 1694,
    calderaAbilities: liveStats?.calderaAbilities ?? 1919,
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
            <span className="font-display text-2xl tracking-wider">AC3</span>
          </div>
          {/* Desktop nav links */}
          <div className="hidden lg:flex items-center gap-6 text-sm font-display tracking-wider text-muted-foreground">
            <a href="#how-it-works" className="hover:text-primary transition-colors">HOW IT WORKS</a>
            <a href="#why-ac3" className="hover:text-primary transition-colors">WHY AC3</a>
            <a href="#capabilities" className="hover:text-primary transition-colors">CAPABILITIES</a>
            <a href="#safety" className="hover:text-primary transition-colors">SAFETY</a>
            <a href="#threat-feed" className="hover:text-primary transition-colors">THREAT FEED</a>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/login">
              <Button variant="ghost" className="hidden sm:inline-flex font-display tracking-wider text-sm">
                SIGN IN
              </Button>
            </Link>
            <FreeScanModal trigger={
              <Button className="hidden sm:inline-flex font-display tracking-wider bg-primary hover:bg-primary/90 text-sm">
                FREE SECURITY SCAN
                <ChevronRight className="w-4 h-4 ml-1" />
              </Button>
            } />
            {/* Mobile hamburger menu */}
            <Sheet>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Open navigation menu">
                  <Menu className="w-5 h-5" />
                </Button>
              </SheetTrigger>
              <SheetContent side="right" className="bg-background border-border w-72">
                <SheetHeader>
                  <SheetTitle className="flex items-center gap-2 font-display tracking-wider">
                    <Cloud className="w-5 h-5 text-primary" />
                    AC3
                  </SheetTitle>
                </SheetHeader>
                <nav className="flex flex-col gap-1 mt-4 px-2">
                  {[
                    { href: "#how-it-works", label: "HOW IT WORKS", icon: Workflow },
                    { href: "#why-ac3", label: "WHY AC3", icon: Award },
                    { href: "#capabilities", label: "CAPABILITIES", icon: Layers },
                    { href: "#safety", label: "SAFETY", icon: ShieldAlert },
                    { href: "#threat-feed", label: "THREAT FEED", icon: Radar },
                  ].map((item) => (
                    <a
                      key={item.href}
                      href={item.href}
                      className="flex items-center gap-3 px-3 py-3 text-sm font-display tracking-wider text-muted-foreground hover:text-primary hover:bg-primary/5 transition-colors"
                      onClick={() => {
                        const closeBtn = document.querySelector('[data-slot="sheet-content"] [data-slot="sheet-close"]') as HTMLButtonElement;
                        closeBtn?.click();
                      }}
                    >
                      <item.icon className="w-4 h-4" />
                      {item.label}
                    </a>
                  ))}
                  <div className="h-px bg-border my-3" />
                  <Link href="/login">
                    <span className="flex items-center gap-3 px-3 py-3 text-sm font-display tracking-wider text-muted-foreground hover:text-primary hover:bg-primary/5 transition-colors">
                      <Lock className="w-4 h-4" />
                      SIGN IN
                    </span>
                  </Link>
                  <FreeScanModal trigger={
                    <Button className="w-full mt-2 font-display tracking-wider bg-primary hover:bg-primary/90 text-sm">
                      FREE SECURITY SCAN
                    </Button>
                  } />
                </nav>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </nav>

      {/* ═══════════════════════════════════════════════════════════
          ABOVE THE FOLD — POSITIONING & MISSION
          ═══════════════════════════════════════════════════════════ */}

      {/* ─── Hero Section ───────────────────────────────────────── */}
      <section className="relative pt-28 pb-24 overflow-hidden">
        <div className="container">
          <div className="max-w-4xl mx-auto text-center">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 border border-primary/40 text-primary text-xs font-display tracking-widest mb-8">
              <Shield className="w-3.5 h-3.5" />
              AUTHORIZED OFFENSIVE SECURITY PLATFORM
            </div>

            <h1 className="text-5xl sm:text-6xl md:text-7xl lg:text-8xl font-display leading-[0.9] tracking-tight mb-8">
              VALIDATE YOUR
              <br />
              <span className="text-primary">DEFENSES</span>
              <br />
              <span className="text-3xl sm:text-4xl md:text-5xl text-muted-foreground font-display">WITH REAL-WORLD TESTING.</span>
            </h1>

            <p className="text-xl md:text-2xl text-muted-foreground max-w-2xl mx-auto mb-6 leading-relaxed">
              One platform for authorized offensive security — from reconnaissance and exploitation
              to adversary emulation, social engineering, and evidence-backed reporting.
            </p>

            <p className="text-sm text-muted-foreground max-w-xl mx-auto mb-10">
              AC3 unifies the full offensive testing lifecycle with safety architecture
              that ensures every action is scoped, audited, and defensible.
              Built by practitioners who understand both sides of the assessment problem.
            </p>

            {/* Early Access Badge */}
            <div className="inline-flex items-center gap-2 px-4 py-2 bg-primary/10 border border-primary/30 text-sm text-primary font-display tracking-wider mb-8">
              <Sparkles className="w-4 h-4" />
              CURRENTLY IN EARLY ACCESS PARTNERSHIP
            </div>

            <div className="flex flex-wrap justify-center gap-4 mb-12">
              <FreeScanModal trigger={
                <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-8 py-6 text-base">
                  FREE SECURITY SCAN
                  <ArrowRight className="w-5 h-5 ml-2" />
                </Button>
              } />
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

      {/* ─── Mission Statement ─────────────────────────────────── */}
      <section className="py-16 bg-card/30">
        <div className="container">
          <div className="max-w-3xl mx-auto text-center">
            <h2 className="font-display text-xs tracking-[0.3em] text-primary mb-6">OUR MISSION</h2>
            <p className="text-2xl sm:text-3xl font-display leading-relaxed text-foreground/90 mb-6">
              Improve security frameworks by example. Lower the cost of accurate assessment.
              Prioritize real exposure over compliance theater.
            </p>
            <p className="text-muted-foreground leading-relaxed max-w-2xl mx-auto">
              AC3 exists because security testing should produce actionable evidence of what works
              and what doesn't — not just satisfy checkbox requirements. We build tools that help
              teams validate their defenses through real testing while supporting the compliance
              reporting their organizations require.
            </p>
          </div>
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
              <h3 className="font-display text-xl tracking-wider mb-4">DISCOVER & ASSESS</h3>
              <p className="text-muted-foreground leading-relaxed">
                Automated web application scanning identifies vulnerabilities while OSINT connectors map
                your external attack surface. AI auto-configures scan policies based on your technology stack.
              </p>
            </div>

            <div className="text-center px-4">
              <div className="w-16 h-16 mx-auto mb-6 flex items-center justify-center border-2 border-primary/50 bg-primary/5">
                <Target className="w-8 h-8 text-primary" />
              </div>
              <h3 className="font-display text-xl tracking-wider mb-4">TEST & VALIDATE</h3>
              <p className="text-muted-foreground leading-relaxed">
                Execute authorized exploits with full audit trails, simulate adversary behavior
                with ATT&CK-mapped profiles, and run controlled social engineering assessments —
                all coordinated through a unified kill chain.
              </p>
            </div>

            <div className="text-center px-4">
              <div className="w-16 h-16 mx-auto mb-6 flex items-center justify-center border-2 border-primary/50 bg-primary/5">
                <ShieldCheck className="w-8 h-8 text-primary" />
              </div>
              <h3 className="font-display text-xl tracking-wider mb-4">PROVE & REPORT</h3>
              <p className="text-muted-foreground leading-relaxed">
                Every finding is backed by captured evidence. Threat intelligence keeps results current.
                Generate professional reports with AI-assisted narratives, human-reviewed severity,
                and evidence-backed findings ready for stakeholders.
              </p>
            </div>

          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── How It Works ───────────────────────────────────────── */}
      <section id="how-it-works" className="py-20 bg-card/30">
        <div className="container">
          <div className="max-w-3xl mx-auto text-center mb-16">
            <h2 className="text-4xl sm:text-5xl font-display mb-4">HOW IT WORKS</h2>
            <p className="text-lg text-muted-foreground">
              Four steps from discovery to defensible proof.
            </p>
          </div>

          <div className="max-w-4xl mx-auto">
            <div className="grid md:grid-cols-2 gap-6">
              {[
                {
                  step: "1",
                  icon: Radar,
                  title: "Discover Your Attack Surface",
                  desc: "Point AC3 at your domain. It automatically scans web applications, maps exposed services, and identifies technologies. Import API specs for deeper coverage."
                },
                {
                  step: "2",
                  icon: Bug,
                  title: "Match Vulnerabilities to Exploits",
                  desc: "Confirmed vulnerabilities are automatically matched to real exploit modules. You see exactly which weaknesses have working attacks — not just theoretical risk."
                },
                {
                  step: "3",
                  icon: Crosshair,
                  title: "Execute Authorized Testing",
                  desc: "Run scoped exploits, adversary emulation with APT profiles, and controlled social engineering campaigns. Every action is bounded by engagement scope, fully audited, and mapped to MITRE ATT&CK."
                },
                {
                  step: "4",
                  icon: BarChart3,
                  title: "Prove & Report",
                  desc: "Autonomous validation confirms which CVEs are actually exploitable. Threat intelligence enriches findings. Generate professional reports with evidence-backed findings and human-reviewed narratives."
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
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-8">
            <AnimatedStat value={stats.exploitModules} label="EXPLOIT MODULES" suffix="+" />
            <AnimatedStat value={stats.calderaAbilities} label="EMULATION ABILITIES" suffix="" />
            <AnimatedStat value={1400} label="ATT&CK VALIDATION TESTS" suffix="+" />
            <AnimatedStat value={stats.threatActors} label="THREAT ACTORS CATALOGED" suffix="+" />
            <AnimatedStat value={stats.platformModules} label="INTEGRATED MODULES" suffix="" />
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Safety Architecture ───────────────────────────────── */}
      <section id="safety" className="py-20">
        <div className="container">
          <div className="max-w-3xl mx-auto text-center mb-16">
            <h2 className="text-4xl sm:text-5xl font-display mb-4">SAFETY ARCHITECTURE</h2>
            <p className="text-lg text-muted-foreground">
              AI-enhanced offensive tooling demands rigorous safety controls.
              AC3 implements defense-in-depth at every layer — not as an afterthought, but as a design principle.
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-5xl mx-auto">
            {[
              {
                icon: ShieldAlert,
                title: "FIVE GATES OF OVERSIGHT",
                desc: "Every offensive action passes through scope validation, authorization check, human review gate, execution audit, and evidence capture before completion."
              },
              {
                icon: Lock,
                title: "SCOPE ENFORCEMENT BELOW THE LLM",
                desc: "Target scope is enforced at the transport layer — beneath the AI orchestration. The LLM cannot override engagement boundaries regardless of prompt."
              },
              {
                icon: Fingerprint,
                title: "HASH-CHAINED EVIDENCE INTEGRITY",
                desc: "All evidence artifacts are cryptographically chained. Tampering with any finding invalidates the chain, ensuring audit-ready integrity."
              },
              {
                icon: Eye,
                title: "HUMAN-IN-THE-LOOP SEVERITY",
                desc: "AI assists with narrative drafting and triage, but severity ratings and final findings require human review and approval before reporting."
              },
              {
                icon: Shield,
                title: "FIPS 140-2 CRYPTOGRAPHY",
                desc: "All data at rest and in transit uses FIPS 140-2 validated cryptographic modules. Session tokens, credentials, and evidence are protected to federal standards."
              },
              {
                icon: FileCheck2,
                title: "QA REVIEW PIPELINE",
                desc: "Reports pass through automated quality checks for prohibited content, evidence completeness, severity consistency, and audit readiness before delivery."
              },
            ].map((item) => (
              <div key={item.title} className="p-6 border-2 border-border hover:border-primary/40 transition-colors bg-card/30">
                <item.icon className="w-7 h-7 text-primary mb-4" />
                <h3 className="font-display text-base tracking-wider mb-3">{item.title}</h3>
                <p className="text-sm text-muted-foreground leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>

          <div className="mt-10 max-w-3xl mx-auto text-center">
            <p className="text-sm text-muted-foreground">
              AC3's safety architecture addresses the OWASP LLM Top 10 and has been designed for
              third-party adversarial testing. We treat safety as a competitive advantage, not compliance theater.
            </p>
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── How AC3 is Different ──────────────────────────────── */}
      <section id="why-ac3" className="py-20 bg-card/30">
        <div className="container">
          <div className="max-w-3xl mx-auto text-center mb-16">
            <h2 className="text-4xl sm:text-5xl font-display mb-4">HOW AC3 IS DIFFERENT</h2>
            <p className="text-lg text-muted-foreground">
              Most offensive security platforms optimize for either automation breadth or manual depth.
              AC3 integrates both with safety architecture that makes the combination defensible.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8 max-w-5xl mx-auto">
            <ComparisonCard
              icon={<Cloud className="w-6 h-6" />}
              title="AC3"
              points={[
                "Unified lifecycle: recon through reporting in one platform",
                "Safety-first AI: scope enforcement below the LLM layer",
                "Evidence-backed findings with hash-chained integrity",
                "Sector-aware scoring with CARVER+SHOCK methodology",
                "Human oversight at every severity and reporting decision",
                "Built by practitioners with decades of assessment experience",
                "Designed for regulated industries and defense-adjacent customers",
              ]}
            />
            <ComparisonCard
              icon={<Server className="w-6 h-6" />}
              title="TYPICAL PLATFORMS"
              isOther
              points={[
                "Point solutions requiring tool-switching between phases",
                "AI treated as pure capability without safety boundaries",
                "Automated findings without evidence chain or provenance",
                "Generic CVSS scoring without operational context",
                "Fully autonomous with limited human review gates",
                "Built by software engineers without practitioner depth",
                "Designed for general enterprise without sector specialization",
              ]}
            />
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Who It's For ──────────────────────────────────────── */}
      <section id="who-its-for" className="py-20">
        <div className="container">
          <div className="max-w-3xl mx-auto text-center mb-16">
            <h2 className="text-4xl sm:text-5xl font-display mb-4">WHO IT'S FOR</h2>
            <p className="text-lg text-muted-foreground">
              Designed for teams that need to validate security through real testing
              while supporting the compliance reporting their organizations require.
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-5xl mx-auto">
            {[
              { icon: Crosshair, title: "Red Teams", desc: "Execute authorized exploits, adversary emulation, and ATT&CK validation from one command center with full audit trails." },
              { icon: Shield, title: "Penetration Testers", desc: "Scope engagements, execute authorized testing, run controlled social engineering, and deliver evidence-backed reports in one workflow." },
              { icon: ShieldCheck, title: "Purple Teams", desc: "Execute attacks and immediately measure what your defenses catch. Auto-generate detection rules from executed techniques." },
              { icon: Server, title: "Managed Service Providers", desc: "Scale offensive assessments across clients with per-engagement tracking, branded reporting, and consistent methodology." },
              { icon: Building2, title: "Enterprise Security", desc: "Test employee awareness and infrastructure resilience with controlled, audited attack simulations and executive reporting." },
              { icon: Landmark, title: "Government & Defense", desc: "Support compliance with CMMC, NIST, and federal frameworks through evidence-based testing and audit-ready reports." },
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
              <h3 className="font-display text-xs tracking-[0.25em] text-muted-foreground mb-4">SECTOR EXPERTISE</h3>
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
          <h2 className="text-3xl sm:text-4xl font-display mb-4">READY TO VALIDATE YOUR DEFENSES?</h2>
          <p className="text-muted-foreground mb-4 max-w-xl mx-auto">
            AC3 is currently available through early access partnerships with select organizations.
          </p>
          <p className="text-xs text-muted-foreground mb-8 max-w-md mx-auto">
            General availability planned for Q4 2026. Early access partners receive dedicated onboarding
            and direct access to the engineering team.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <FreeScanModal trigger={
              <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-8 py-6">
                FREE SECURITY SCAN
                <ArrowRight className="w-5 h-5 ml-2" />
              </Button>
            } />
            <Link href="/login?returnTo=%2Fdashboard">
              <Button size="lg" variant="outline" className="font-display tracking-wider border-2 border-primary text-primary hover:bg-primary hover:text-white px-8 py-6">
                <Lock className="w-4 h-4 mr-2" />
                EXISTING PARTNER SIGN IN
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════════════════════════
          BELOW THE FOLD — TECHNICAL DETAILS
          ═══════════════════════════════════════════════════════════ */}

      {/* ─── Platform Capabilities — 8 Pillars ──────────────────── */}
      <section id="capabilities" className="py-20">
        <div className="container">
          <div className="inline-flex items-center gap-2 px-3 py-1 border border-border text-muted-foreground text-xs font-display tracking-widest mb-6">
            <Terminal className="w-3 h-3" />
            TECHNICAL DETAILS
          </div>
          <CollapsibleSection
            title="PLATFORM CAPABILITIES"
            subtitle={`Eight integrated pillars covering the full authorized offensive lifecycle — from reconnaissance through continuous threat enrichment. ${stats.platformModules} integrated modules.`}
          >
          <div className="grid lg:grid-cols-3 gap-6">
            <PillarCard
              icon={<Target className="w-7 h-7" />}
              number="01"
              title="ADVERSARY EMULATION"
              description={`${stats.exploitModules.toLocaleString()}+ exploit modules, ${stats.calderaAbilities.toLocaleString()} emulation abilities, and 1,400+ ATT&CK validation tests — all correlated through MITRE ATT&CK with full audit trails.`}
              features={[
                "Authorized exploit execution with session management and audit logging",
                "Adversary emulation with APT-based profiles and scoped boundaries",
                "1,400+ ATT&CK-mapped validation tests with evidence capture",
                "Cross-tool correlation across all modules via MITRE ATT&CK",
                "Cloud-provisioned engagement infrastructure for authorized operations",
                "Real-time operation monitoring with kill chain timeline",
              ]}
              link="/agents"
              linkLabel="DEPLOY AGENTS"
            />

            <PillarCard
              icon={<Zap className="w-7 h-7" />}
              number="02"
              title="SOCIAL ENGINEERING"
              description="Controlled social engineering assessment capabilities for authorized phishing exercises — automatically matched to targets based on intelligence and bounded by engagement scope."
              features={[
                "Multiple phishing techniques for authorized assessment campaigns",
                "Browser-in-the-browser, AiTM proxy, and credential harvesting simulations",
                "AI-powered template generation from threat actor TTPs",
                "Guided campaign wizard with scope enforcement and tracking",
                "Pre-built templates across multiple categories",
                "Full campaign audit trail with evidence collection",
              ]}
              link="/phishing-ops"
              linkLabel="MANAGE CAMPAIGNS"
            />

            <PillarCard
              icon={<Radar className="w-7 h-7" />}
              number="03"
              title="OSINT & RECONNAISSANCE"
              description="Web application scanning with AI-powered configuration plus passive recon connectors. Import API specs for full coverage. Compare scans to track changes over time."
              features={[
                "DAST scanning with LLM-tuned scan policies",
                "OpenAPI / GraphQL / SOAP spec import for API testing",
                "AJAX Spider for JavaScript-heavy SPA applications",
                "16 OSINT connectors with confirmed-only vulnerability counting",
                "Email, HTTP headers, cloud assets, DNS deep analysis",
                "Scan comparison: side-by-side risk posture delta",
              ]}
              link="/domain-intel"
              linkLabel="START SCANNING"
            />

            <PillarCard
              icon={<Brain className="w-7 h-7" />}
              number="04"
              title="THREAT INTELLIGENCE & ENRICHMENT"
              description={`${stats.threatActors.toLocaleString()} threat actor profiles sourced from MITRE ATT&CK and public attribution reports, with a continuous enrichment engine that correlates techniques and indicators across your security stack.`}
              features={[
                "Continuous enrichment engine with full-cycle automation",
                "Technique-to-threat-actor coverage matrix",
                "IOC feeds correlated across all platform modules",
                "Threat-informed validation priority scoring",
                "Attack vector enrichment with actor correlation",
                "Vulnerability feed aggregation with live verification",
              ]}
              link="/threat-enrichment"
              linkLabel="ENRICHMENT ENGINE"
            />

            <PillarCard
              icon={<ShieldCheck className="w-7 h-7" />}
              number="05"
              title="VALIDATION & DETECTION"
              description="Confirm which vulnerabilities are actually exploitable with automated validation. Capture proof artifacts. Auto-generate detection rules from executed techniques."
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
              title="REPORTING & COMPLIANCE"
              description="Professional reports with AI-assisted narratives, platform-controlled severity, and evidence-backed findings. QA review pipeline ensures audit readiness."
              features={[
                "DOCX export with QA review pipeline",
                "AI-assisted narrative drafting with mandatory human approval",
                "One-click import from engagements and Caldera operations",
                "Automatic findings deduplication",
                "Evidence artifact links in every report",
                "NIST CSF, CMMC, and SP 800-53 control mapping",
              ]}
              link="/ac3-reports"
              linkLabel="AC3 REPORTS"
            />

            <PillarCard
              icon={<Rocket className="w-7 h-7" />}
              number="07"
              title="ENGAGEMENT AUTOMATION"
              description="Launch automated engagements driven by threat intelligence. 5 templates with pre-loaded techniques, abilities, and kill chain phase mapping."
              features={[
                "5 templates: pentest, red team, purple team, phishing, cloud",
                "Kill chain phase mapping per engagement type",
                "Auto-loaded emulation abilities and exploit modules",
                "Live scanner integration with threat catalog cross-reference",
                "Scheduled auto-collection with 6 configurable sources",
                "Source health monitoring and evidence chain feeds",
              ]}
              link="/engagement-automation"
              linkLabel="ENGAGEMENT AUTOMATION"
            />

            <PillarCard
              icon={<Network className="w-7 h-7" />}
              number="08"
              title="AD & CLOUD ATTACK PATHS"
              description="Map Active Directory attack paths, import BloodHound data, and discover cloud attack paths across AWS, Azure, and GCP."
              features={[
                "AD attack simulation with privilege escalation path discovery",
                "BloodHound data import for domain relationship visualization",
                "Forest Mapper: cross-forest trust and attack vector enumeration",
                "Cloud attack path discovery across AWS, Azure, and GCP",
                "Cloud workload testing for containers and serverless",
                "AD domain connector with automated collection",
              ]}
              link="/attack-paths"
              linkLabel="ATTACK PATHS"
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
            subtitle={`${stats.platformModules} integrated modules organized across eight operational domains.`}
          >
          <div className="space-y-12">
            <ModuleSection
              title="COMMAND & CONTROL"
              color="text-primary"
              modules={[
                { icon: Activity, name: "Dashboard", desc: "Live operational overview with agent counts, campaign metrics, tool health, and scan status" },
                { icon: Briefcase, name: "Engagement Manager", desc: "Unified engagement + campaign management with 6-phase workflow" },
                { icon: Workflow, name: "Kill Chain Timeline", desc: "Real-time engagement timeline with WebSocket event streaming" },
                { icon: Key, name: "Credentials", desc: "Secure vault for API keys, SSH credentials, and admin access" },
                { icon: Target, name: "Adversaries", desc: "Adversary profiles with APT-based creation" },
                { icon: Cpu, name: "Agents", desc: "Agent deployment, trust management, and kill commands" },
                { icon: FileText, name: "Activity Log", desc: "Full audit trail of all platform actions" },
              ]}
            />

            <ModuleSection
              title="SOCIAL ENGINEERING OPERATIONS"
              color="text-red-400"
              modules={[
                { icon: Zap, name: "Phishing Ops", desc: "Controlled phishing campaigns with multiple assessment techniques" },
                { icon: Crosshair, name: "Campaign Wizard", desc: "Guided launch with scope enforcement and template previews" },
                { icon: Palette, name: "Page Builder", desc: "Visual landing page editor for credential harvesting simulations" },
                { icon: Workflow, name: "Auto Pipeline", desc: "Automated: OSINT → target profiling → campaign design → launch" },
                { icon: Sparkles, name: "Template Generator", desc: "AI-powered template creation matched to target intelligence" },
              ]}
            />

            <ModuleSection
              title="EXPLOIT & EMULATION"
              color="text-orange-400"
              modules={[
                { icon: Bug, name: "Exploit Arsenal", desc: `Unified catalog: ${stats.exploitModules.toLocaleString()}+ exploit modules + ATT&CK validation tests` },
                { icon: Server, name: "Engagement Infrastructure", desc: "Cloud-provisioned infrastructure for authorized engagement operations" },
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
                { icon: Brain, name: "Domain Intel", desc: "16 connectors with confirmed-only vulnerability counting and 3-tier corroboration" },
                { icon: Scan, name: "Web App Scanner", desc: "DAST with dual-mode scanning, AI config, OpenAPI/GraphQL import" },
                { icon: Radar, name: "Domain Recon", desc: "DNS deep, email security, HTTP headers, cloud assets, subdomains" },
                { icon: Eye, name: "Scan Comparison", desc: "Side-by-side diff: new/removed assets, CVE changes, risk deltas" },
                { icon: Radio, name: "IOC Feed", desc: "Aggregated feeds from multiple authoritative threat intelligence sources" },
                { icon: Network, name: "AD Attack Paths", desc: "Active Directory attack simulation, forest mapping, BloodHound import, and domain trust enumeration" },
                { icon: Cloud, name: "Cloud Attack Paths", desc: "Cloud attack path discovery and workload testing across AWS, Azure, and GCP" },
              ]}
            />

            <ModuleSection
              title="DETECTION & VALIDATION"
              color="text-green-400"
              modules={[
                { icon: FlaskConical, name: "Validation Engine", desc: "LLM-driven exploit validation + ATT&CK test execution — KEV/CVSS prioritized, auto-rescore on confirmation" },
                { icon: Camera, name: "Evidence Capture", desc: "Automated proof collection: console output, session info, HTML reports stored in S3" },
                { icon: FileCheck2, name: "Validation Coverage", desc: "Real-time coverage metric tracking validated vs. unconfirmed findings with quality assessment tiers" },
                { icon: ShieldCheck, name: "Rule Validator", desc: "Validate Sigma, YARA, Suricata, Splunk SPL, and KQL with LLM analysis" },
                { icon: Target, name: "Coverage Matrix", desc: "Cross-reference rules vs attack chains to find SIEM gaps" },
                { icon: FileCode, name: "Actor Rules", desc: "Auto-generate detection rules from threat actor techniques" },
              ]}
            />

            <ModuleSection
              title="THREAT ENRICHMENT & AUTOMATION"
              color="text-purple-400"
              modules={[
                { icon: Brain, name: "Enrichment Engine", desc: "Continuous threat intelligence enrichment correlating TTPs and IOCs across all platform modules" },
                { icon: TrendingUp, name: "Coverage Matrix", desc: "Technique-to-threat-actor coverage with density and risk scoring" },
                { icon: Zap, name: "Engagement Automation", desc: "5 engagement templates with kill chain mapping, pre-loaded emulation abilities" },
                { icon: Scan, name: "Live Scanner", desc: "Real-time cross-referencing of scan evidence against threat catalog with auto-collection pipelines" },
                { icon: Clock, name: "Scheduled Collection", desc: "Cron-based automated evidence collection with source health monitoring" },
                { icon: Radio, name: "IOC Feeds", desc: "Per-module IOC feeds from correlated threat actors for attack vectors, config, and validation" },
              ]}
            />

            <ModuleSection
              title="REPORTING & COMPLIANCE"
              color="text-violet-400"
              modules={[
                { icon: Shield, name: "AC3 Reports", desc: "Professional pentest and red team reports with AI-assisted narratives, DOCX export, and QA review" },
                { icon: FileText, name: "Engagement Report", desc: "Branded HTML reports with MITRE heatmaps, evidence artifacts, and validation coverage" },
                { icon: BarChart3, name: "Report Generator", desc: "Executive summaries with proof-of-exploit evidence links and coverage bars" },
                { icon: Globe, name: "Compliance Center", desc: "NIST CSF, CMMC, and framework mapping with SP 800-53 control mappings" },
                { icon: Layers, name: "Compliance Mapper", desc: "Cross-framework control mapping between NIST, CMMC, and custom frameworks" },
                { icon: FileCheck2, name: "Evidence Vault", desc: "Centralized evidence repository with artifact types, file sizes, and S3 storage links" },
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
            subtitle="Eight phases from reconnaissance through reporting — each bounded by engagement scope and fully audited."
          >
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
            {[
              { step: "01", title: "RECON", desc: "Scan web apps and map your attack surface with evidence-based risk scoring", icon: Radar },
              { step: "02", title: "EXPLOIT", desc: "Match confirmed vulnerabilities to exploit modules and deploy with agent stagers", icon: Target },
              { step: "03", title: "OPERATE", desc: "Run adversary emulation with APT-based profiles and scoped abilities", icon: Crosshair },
              { step: "04", title: "PHISH", desc: "Launch controlled social engineering campaigns for authorized assessments", icon: Zap },
              { step: "05", title: "VALIDATE", desc: "Run ATT&CK validation tests and confirm exploitability with evidence capture", icon: FlaskConical },
              { step: "06", title: "DETECT", desc: "Auto-generate detection rules from executed techniques and measure coverage gaps", icon: ShieldCheck },
              { step: "07", title: "ENRICH", desc: "Continuous threat intelligence correlates findings against threat actors and feeds IOCs to all modules", icon: Brain },
              { step: "08", title: "REPORT", desc: "Generate professional reports with AI-assisted narratives, evidence-backed findings, and QA review", icon: FileText },
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
                "Cloud-provisioned engagement infrastructure",
                "Cross-tool correlation via MITRE ATT&CK",
              ]}
            />
            <ArchCard
              icon={<Target className="w-6 h-6" />}
              title="SOCIAL ENGINEERING ENGINE"
              items={[
                "Multiple phishing assessment techniques",
                "Browser-in-the-browser and AiTM simulations",
                "Authorized campaign infrastructure provisioning",
                "Intelligence-matched template generation",
                "Full campaign audit trail and tracking",
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
                "Remote access vulnerability highlighting",
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
                "Evidence-backed report generation with human review",
              ]}
            />
            <ArchCard
              icon={<Brain className="w-6 h-6" />}
              title="THREAT ENRICHMENT ENGINE"
              items={[
                "Continuous TTP/IOC correlation across all platform modules",
                "Technique-to-threat-actor coverage matrix",
                "Cross-module IOC feeds and priority scoring",
                "Engagement automation with 5 templates",
                "Scheduled auto-collection with source health monitoring",
              ]}
            />
            <ArchCard
              icon={<FileText className="w-6 h-6" />}
              title="REPORTING ENGINE"
              items={[
                "LLM-bounded narrative drafting with mandatory human approval",
                "DOCX export with professional formatting",
                "Engagement import with deduplication",
                "QA review pipeline for audit readiness",
                "Platform-controlled severity, evidence, and NIST controls",
              ]}
            />
          </div>
          </CollapsibleSection>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Trust & Transparency ──────────────────────────────── */}
      <section className="py-20">
        <div className="container">
          <div className="max-w-3xl mx-auto text-center mb-12">
            <h2 className="text-4xl sm:text-5xl font-display mb-4">TRUST & TRANSPARENCY</h2>
            <p className="text-lg text-muted-foreground">
              Built by a team with deep expertise across offensive security, compliance frameworks,
              and regulated industry assessments.
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6 max-w-5xl mx-auto">
            {[
              {
                icon: Award,
                title: "PRACTITIONER-BUILT",
                desc: "Designed by security professionals with decades of combined experience in offensive testing, assessment methodology, and framework development."
              },
              {
                icon: Scale,
                title: "COMPLIANCE-READY",
                desc: "NIST CSF, CMMC, SP 800-53 control mapping built in. Designed to support FedRAMP-track organizations and defense-adjacent customers."
              },
              {
                icon: ShieldAlert,
                title: "SAFETY-FIRST AI",
                desc: "OWASP LLM Top 10 addressed. Scope enforcement below the AI layer. Designed for third-party adversarial testing and independent audit."
              },
              {
                icon: Handshake,
                title: "EARLY ACCESS MODEL",
                desc: "Currently partnering with select organizations. Dedicated onboarding, direct engineering access, and collaborative feature development."
              },
            ].map((item) => (
              <div key={item.title} className="text-center p-6">
                <item.icon className="w-8 h-8 text-primary mx-auto mb-4" />
                <h3 className="font-display text-sm tracking-wider mb-3">{item.title}</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>

          {/* Threat Intelligence Provenance */}
          <div className="mt-12 max-w-3xl mx-auto border border-border/50 p-6 bg-card/30">
            <h3 className="font-display text-sm tracking-wider mb-3 text-center">THREAT INTELLIGENCE SOURCES</h3>
            <p className="text-sm text-muted-foreground text-center leading-relaxed">
              AC3's threat catalog is curated from MITRE ATT&CK, publicly attributed government reports,
              and authoritative open-source intelligence feeds. We reproduce and correlate public attribution
              rather than making novel intelligence claims. All threat actor data includes source provenance.
            </p>
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Threat Actor Feed ──────────────────────────────────── */}
      <div id="threat-feed">
        <ThreatActorFeed />
      </div>

      {/* ─── Final CTA ──────────────────────────────────────────── */}
      <section className="py-16 bg-primary/5 border-y border-primary/20">
        <div className="container text-center">
          <h2 className="text-3xl sm:text-4xl font-display mb-4">JOIN THE EARLY ACCESS PROGRAM</h2>
          <p className="text-muted-foreground mb-8 max-w-xl mx-auto">
            Partner with us to validate your defenses with real-world testing methodology,
            evidence-backed findings, and safety architecture you can trust.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <FreeScanModal trigger={
              <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-8 py-6">
                FREE SECURITY SCAN
                <ArrowRight className="w-5 h-5 ml-2" />
              </Button>
            } />
            <a href="https://aceofcloud.com" target="_blank" rel="noopener noreferrer">
              <Button size="lg" variant="outline" className="font-display tracking-wider border-2 border-primary text-primary hover:bg-primary hover:text-white px-8 py-6">
                ABOUT ACE OF CLOUD
                <ExternalLink className="w-4 h-4 ml-2" />
              </Button>
            </a>
          </div>
        </div>
      </section>

      {/* ─── Footer ─────────────────────────────────────────────── */}
      <footer className="py-6 border-t border-border bg-card">
        <div className="container flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Cloud className="w-5 h-5 text-primary" />
            <span className="font-display tracking-wider">AC3</span>
          </div>
          <p className="text-sm text-muted-foreground text-center">
            AC3 — Authorized Offensive Security Platform | Built by Ace of Cloud | Harrison Cook
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
