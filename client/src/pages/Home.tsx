import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { useState, useEffect, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import {
  Key, Terminal, Activity, Users, ExternalLink, ChevronRight, Zap, Cloud,
  Mail, Phone, MapPin, Target, Shield, Radar, Globe, Crosshair, FileText,
  Briefcase, BarChart3, Sparkles, Network, Lock, Fingerprint, Scan,
  BookOpen, Server, Cpu, Eye, X, Brain, Layers, Radio, Workflow, Rocket,
  ShieldCheck, Palette, AlertTriangle, CheckCircle2, ArrowRight, Siren,
  Search, Code2, FileCode, Bug, Gauge, MonitorPlay, Building2, Stethoscope,
  GraduationCap, Landmark, Factory, ShoppingCart, Plane, ChevronDown,
  Clock, TrendingUp, Unplug, FlaskConical, Camera, FileCheck2
} from "lucide-react";

// ─── What's New Popup ────────────────────────────────────────────────
const RECENT_UPDATES = [
  { date: "Feb 2026", title: "Validation Coverage Metric", desc: "Real-time coverage tracking shows what percentage of critical findings have been validated with proof-of-exploit evidence. Color-coded progress bars in scan results and executive summary PDFs with quality assessment tiers." },
  { date: "Feb 2026", title: "Evidence Capture & Artifact Storage", desc: "Automated evidence collection during exploit validation — console output, session info, HTML evidence reports, and text screenshots stored in S3. Clickable artifact links embedded directly in PDF export reports." },
  { date: "Feb 2026", title: "Autonomous Validation Engine", desc: "LLM-driven exploit validation runs real checks against confirmed CVEs using modules built from Metasploit, ExploitDB, and other sources. Prioritizes KEV-listed and high-CVSS candidates, auto-rescores assets based on confirmed exploitability, and generates full audit trails." },
  { date: "Feb 2026", title: "Exploit Infrastructure Provisioning", desc: "One-click cloud provisioning for exploit frameworks. Auto-configures remote procedure calls, deploys agent stagers, and manages the full exploit-to-agent pipeline." },
  { date: "Feb 2026", title: "Unified Exploit Catalog", desc: "Merged phishing exploits and CVE exploits into a single catalog with adversary ability metadata. One-click sync for both initial-access and post-exploitation techniques." },
  { date: "Feb 2026", title: "Kill Chain Timeline", desc: "Unified engagement timeline visualizing the complete kill chain from OSINT recon through exploitation to post-exploitation with real-time WebSocket event streaming." },
  { date: "Feb 2026", title: "Real-Time Event Streaming", desc: "WebSocket-powered live updates across all pages. Exploit results, agent deployments, and pipeline progress appear instantly without page refresh." },
  { date: "Feb 2026", title: "Typosquat Domain Purchasing", desc: "Auto-identify top-10 typosquat domains per target, check availability, purchase via registrar, configure DNS, and auto-create phishing sending profiles." },
  { date: "Feb 2026", title: "Exploit Arsenal & Auto-Ingestion", desc: "Automatic CVE-to-exploit matching from public exploit databases. One-click deployment as adversary abilities with profile creation." },
  { date: "Feb 2026", title: "Phishing Exploit Library", desc: "17 advanced phishing techniques (BITB, AiTM, HTML smuggling, MFA bypass, OAuth abuse, ClickFix, quishing) auto-injected into campaign templates based on target intelligence." },
  { date: "Feb 2026", title: "Live Banner Verification", desc: "Real-time service banner verification confirms or denies vulnerability matches. Only confirmed exploits drive risk scores." },
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
            <span className="font-display text-2xl tracking-wider">ACE C3</span>
          </div>
          <div className="hidden md:flex items-center gap-6 text-sm font-display tracking-wider text-muted-foreground">
            <a href="#how-it-works" className="hover:text-primary transition-colors">HOW IT WORKS</a>
            <a href="#who-its-for" className="hover:text-primary transition-colors">WHO IT'S FOR</a>
            <a href="#capabilities" className="hover:text-primary transition-colors">CAPABILITIES</a>
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
              OFFENSIVE SECURITY PLATFORM
            </div>

            <h1 className="text-5xl sm:text-6xl md:text-7xl lg:text-8xl font-display leading-[0.9] tracking-tight mb-8">
              KNOW YOUR
              <br />
              <span className="text-primary">WEAKNESSES</span>
              <br />
              <span className="text-3xl sm:text-4xl md:text-5xl text-muted-foreground font-display">BEFORE ATTACKERS DO</span>
            </h1>

            <p className="text-xl md:text-2xl text-muted-foreground max-w-2xl mx-auto mb-6 leading-relaxed">
              Ace C3 finds your real security gaps the way attackers would,
              and shows you exactly what to fix — all from one platform.
            </p>

            <p className="text-sm text-muted-foreground max-w-xl mx-auto mb-10">
              Built for red teams, penetration testers, and security teams at enterprises,
              government agencies, and managed service providers.
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
              <h3 className="font-display text-xl tracking-wider mb-4">FIND REAL VULNERABILITIES</h3>
              <p className="text-muted-foreground leading-relaxed">
                Ace C3 scans your external attack surface and verifies every finding against
                live systems. No false positives, no guesswork — only confirmed weaknesses
                that real attackers could exploit.
              </p>
            </div>

            <div className="text-center px-4">
              <div className="w-16 h-16 mx-auto mb-6 flex items-center justify-center border-2 border-primary/50 bg-primary/5">
                <Target className="w-8 h-8 text-primary" />
              </div>
              <h3 className="font-display text-xl tracking-wider mb-4">TEST LIKE A REAL ATTACKER</h3>
              <p className="text-muted-foreground leading-relaxed">
                Go beyond scanning. Ace C3 automatically matches your vulnerabilities to real
                exploit code and runs actual attack simulations — the same techniques used by
                nation-state threat groups and criminal organizations.
              </p>
            </div>

            <div className="text-center px-4">
              <div className="w-16 h-16 mx-auto mb-6 flex items-center justify-center border-2 border-primary/50 bg-primary/5">
                <ShieldCheck className="w-8 h-8 text-primary" />
              </div>
              <h3 className="font-display text-xl tracking-wider mb-4">PROVE IT WITH EVIDENCE</h3>
              <p className="text-muted-foreground leading-relaxed">
                Every exploitable finding is backed by captured proof — console output, session data,
                and HTML evidence reports. Track your Validation Coverage to see exactly how much of
                your attack surface has been confirmed with real exploit evidence.
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
                  desc: "Point Ace C3 at your domain. It maps every exposed server, service, and technology — then verifies each one against live data to separate real risks from noise."
                },
                {
                  step: "2",
                  icon: Bug,
                  title: "Match Vulnerabilities to Exploits",
                  desc: "Confirmed vulnerabilities are automatically matched to real exploit code from public and proprietary databases. You see exactly which weaknesses have working attacks available."
                },
                {
                  step: "3",
                  icon: Crosshair,
                  title: "Simulate Real Attacks",
                  desc: "Run actual attack simulations using the same techniques as advanced threat groups. Test external exploits, phishing campaigns, and lateral movement — all controlled and audited."
                },
                {
                  step: "4",
                  icon: BarChart3,
                  title: "Validate, Measure & Report",
                  desc: "Run autonomous exploit validation against confirmed CVEs using LLM-built exploit modules sourced from Metasploit, ExploitDB, and other databases. Every exploitable finding is backed by captured evidence — console output, session data, and HTML reports stored in S3. See your Validation Coverage metric and get professional reports with proof-of-exploit artifacts."
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

      {/* ─── Why Ace C3 Stands Out ──────────────────────────────── */}
      <section className="py-20">
        <div className="container">
          <div className="max-w-3xl mx-auto text-center mb-16">
            <h2 className="text-4xl sm:text-5xl font-display mb-4">WHY ACE C3</h2>
            <p className="text-lg text-muted-foreground">
              Most security tools scan. Some simulate. Ace C3 does both — and closes the loop.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-6 max-w-5xl mx-auto">
            <ComparisonCard
              icon={<Unplug className="w-6 h-6" />}
              title="Other Tools"
              isOther
              points={[
                "Scan for vulnerabilities but don't test them",
                "Generate long lists of theoretical risks with no proof",
                "Require separate tools for scanning, testing, phishing, and reporting",
                "Leave you guessing whether your defenses actually work",
                "No evidence capture — findings are claims without proof",
                "No way to measure what percentage of findings are validated",
              ]}
            />
            <ComparisonCard
              icon={<Cloud className="w-6 h-6" />}
              title="Ace C3"
              points={[
                "Finds vulnerabilities AND validates them with LLM-built exploits from multiple sources",
                "Every exploitable finding backed by captured evidence artifacts in S3",
                "One platform: recon, exploitation, validation, phishing, detection, reporting",
                "Validation Coverage metric shows exactly how much is proven vs. unconfirmed",
                "PDF reports include clickable evidence links and coverage quality assessment",
                "Intelligence drives action — not just dashboards",
              ]}
            />
          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Stats Bar ──────────────────────────────────────────── */}
      <section className="py-16 bg-card/50">
        <div className="container">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-8">
            <AnimatedStat value={stats.exploitModules} label="EXPLOIT MODULES" suffix="+" />
            <AnimatedStat value={stats.threatActors} label="THREAT ACTORS" suffix="+" />
            <AnimatedStat value={stats.calderaAbilities} label="ADVERSARY ABILITIES" suffix="" />
            <AnimatedStat value={stats.platformModules} label="PLATFORM MODULES" suffix="" />
            <AnimatedStat value={4} label="EVIDENCE ARTIFACT TYPES" suffix="" />
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
              { icon: Crosshair, title: "Red Teams", desc: "Run full adversary emulation engagements with real exploits and APT-based attack chains from a single command center." },
              { icon: Shield, title: "Penetration Testers", desc: "Scope engagements, execute verified attacks, launch phishing campaigns, and deliver professional reports — all in one workflow." },
              { icon: ShieldCheck, title: "Purple Teams", desc: "Execute attacks and immediately measure what your defenses catch. Auto-generate detection rules from the TTPs you test." },
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
            Enter the Command Center to start discovering what attackers already know about your organization.
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
          <div className="mb-16">
            <div className="inline-flex items-center gap-2 px-3 py-1 border border-border text-muted-foreground text-xs font-display tracking-widest mb-4">
              <Terminal className="w-3 h-3" />
              TECHNICAL DETAILS
            </div>
            <h2 className="text-4xl sm:text-5xl font-display mb-4">PLATFORM CAPABILITIES</h2>
            <p className="text-lg text-muted-foreground max-w-3xl">
              Six integrated pillars covering the full offensive execution lifecycle — from verified
              reconnaissance through live adversary emulation to detection engineering and reporting.
            </p>
          </div>

          <div className="grid lg:grid-cols-3 gap-6">
            <PillarCard
              icon={<Target className="w-7 h-7" />}
              number="01"
              title="ADVERSARY EMULATION"
              description={`Match confirmed vulnerabilities to ${stats.exploitModules.toLocaleString()}+ LLM-built exploit modules sourced from Metasploit, ExploitDB, and other databases. Deploy as adversary abilities and execute real attack chains using APT adversary profiles.`}
              features={[
                "Automatic CVE-to-exploit matching from multiple databases",
                "One-click exploit deployment as adversary abilities",
                "Cloud-provisioned exploit infrastructure with agent stagers",
                "APT-based adversary profiles with kill chain coverage",
                "Remote access exploits (RCE, auth bypass) prioritized",
                "Real-time operation monitoring with ATT&CK visualization",
              ]}
              link="/agents"
              linkLabel="DEPLOY AGENTS"
            />

            <PillarCard
              icon={<Zap className="w-7 h-7" />}
              number="02"
              title="SOCIAL ENGINEERING"
              description="17 phishing exploit techniques — BITB, AiTM, HTML smuggling, MFA bypass, OAuth abuse, ClickFix, quishing — auto-injected into campaigns based on target intelligence."
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
              description="Verified domain intelligence with 3-tier evidence corroboration. Active DNS resolution, HTTP header parsing, and live banner confirmation separate real risks from noise."
              features={[
                "Live banner verification: real-time version confirmation",
                "3-tier evidence: Confirmed, Probable, Potential (unrated)",
                "Active DNS resolution + HTTP header parsing",
                "Remote access vulnerabilities highlighted",
                "Scan comparison: side-by-side risk posture delta",
                "SPF/DKIM/DMARC analysis with spoofability scoring",
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
              description="Autonomous exploit validation confirms which CVEs are actually exploitable using LLM-built modules from Metasploit, ExploitDB, and other sources. Evidence capture stores proof artifacts in S3. Detection engineering auto-generates rules from executed TTPs."
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
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Operations Grid — All Modules ──────────────────────── */}
      <section id="operations" className="py-20 bg-card/30">
        <div className="container">
          <div className="mb-16">
            <h2 className="text-4xl sm:text-5xl font-display mb-4">OPERATIONS CENTER</h2>
            <p className="text-lg text-muted-foreground max-w-3xl">
              29 integrated modules organized across six operational domains.
              Every module connects to live backend APIs.
            </p>
          </div>

          <div className="space-y-12">
            <ModuleSection
              title="COMMAND & CONTROL"
              color="text-primary"
              modules={[
                { icon: Activity, name: "Dashboard", desc: "Live operational overview with agent counts, campaign metrics, and system health" },
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
                { icon: Bug, name: "Exploit Arsenal", desc: `Unified catalog: ${stats.exploitModules.toLocaleString()}+ LLM-built exploit modules from Metasploit, ExploitDB & more + phishing exploits` },
                { icon: Server, name: "Exploit Servers", desc: "One-click cloud provisioning with auto-configured exploit frameworks" },
                { icon: Layers, name: "Abilities Library", desc: `${stats.calderaAbilities.toLocaleString()} adversary abilities organized by MITRE ATT&CK tactic` },
                { icon: Shield, name: "Threat Actors", desc: `${stats.threatActors.toLocaleString()} actor profiles with kill chains and campaign deployment` },
                { icon: Brain, name: "TTP Knowledge", desc: "MITRE ATT&CK technique encyclopedia with offensive tool mapping" },
              ]}
            />

            <ModuleSection
              title="INTELLIGENCE & RECON"
              color="text-amber-400"
              modules={[
                { icon: Brain, name: "Domain Intel", desc: "Verified pipeline: asset discovery, banner confirmation, exploit matching" },
                { icon: Scan, name: "Banner Verification", desc: "Real-time service banner verification confirms CVEs on live assets" },
                { icon: Radar, name: "Domain Recon", desc: "DNS/MX/SPF/DKIM/DMARC analysis, subdomains, spoofability scoring" },
                { icon: Eye, name: "Scan Comparison", desc: "Side-by-side diff: new/removed assets, CVE changes, risk deltas" },
                { icon: Radio, name: "IOC Feed", desc: "Aggregated feeds from multiple authoritative threat intelligence sources" },
              ]}
            />

            <ModuleSection
              title="DETECTION & VALIDATION"
              color="text-green-400"
              modules={[
                { icon: FlaskConical, name: "Validation Engine", desc: "LLM-driven exploit validation from multiple sources — KEV/CVSS prioritized, auto-rescore on confirmation" },
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
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Engagement Workflow ─────────────────────────────────── */}
      <section className="py-20">
        <div className="container">
          <div className="mb-16">
            <h2 className="text-4xl sm:text-5xl font-display mb-4">ENGAGEMENT WORKFLOW</h2>
            <p className="text-lg text-muted-foreground max-w-3xl">
              Seven phases from OSINT through post-engagement reporting. External attack vectors
              are tested before phishing — if exploitation succeeds, social engineering is optional.
              Validation confirms exploitability with captured evidence before reporting.
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {[
              { step: "01", title: "RECON", desc: "Verified domain intel with DNS/banner confirmation and evidence-based risk scoring", icon: Radar },
              { step: "02", title: "EXPLOIT", desc: "Match confirmed vulns to exploit databases and deploy with agent stagers", icon: Target },
              { step: "03", title: "OPERATE", desc: "Run adversary operations with exploit-backed abilities and APT profiles", icon: Crosshair },
              { step: "04", title: "PHISH", desc: "If external access not achieved: launch exploit-enhanced phishing with 17 techniques", icon: Zap },
              { step: "05", title: "VALIDATE", desc: "Autonomous exploit validation with evidence capture — console output, session data, and HTML proof reports", icon: FlaskConical },
              { step: "06", title: "DETECT", desc: "Auto-generate detection rules from executed TTPs and measure SIEM coverage gaps", icon: ShieldCheck },
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
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Architecture ───────────────────────────────────────── */}
      <section className="py-20 bg-card/30">
        <div className="container">
          <h2 className="text-4xl sm:text-5xl font-display mb-16">ARCHITECTURE</h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-5">
            <ArchCard
              icon={<Server className="w-6 h-6" />}
              title="ADVERSARY EMULATION ENGINE"
              items={[
                "Adversary emulation engine",
                "Cloud-provisioned exploit infrastructure",
                `${stats.exploitModules.toLocaleString()}+ LLM-built exploit modules from multiple sources`,
                "CVE-to-exploit auto-deployment",
                "Agent stager payload generation",
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
              title="INTEL ENGINE"
              items={[
                "Live banner verification",
                "3-tier evidence corroboration",
                "APT matching with kill chains",
                "Scan comparison & risk trending",
                "IOC feed aggregator",
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
                "LLM-driven multi-source exploit validation",
                "KEV/CVSS candidate prioritization",
                "4 evidence artifact types captured to S3",
                "Validation Coverage metric with quality tiers",
                "Auto-rescore assets on confirmed exploitability",
              ]}
            />
            <ArchCard
              icon={<Sparkles className="w-6 h-6" />}
              title="AI LAYER"
              items={[
                "Exploit-enhanced campaign design",
                "APT matching with confidence scoring",
                "Detection rule generation",
                "Rule validation analysis",
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
        </div>
      </section>

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
                Ace C3 is our intelligence-driven offensive execution platform — purpose-built for teams
                that turn vulnerability intelligence into real attacks and measurable results.
              </p>
              <p className="text-lg text-muted-foreground mb-8 leading-relaxed">
                Created by Harrison Cook, Ace C3 goes beyond scanning: verified reconnaissance confirms
                what is actually exposed, the Exploit Arsenal matches confirmed CVEs to real exploit code,
                and the Validation Engine confirms exploitability with captured evidence artifacts.
                Every finding is backed by proof — potential matches are flagged but never rated.
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
