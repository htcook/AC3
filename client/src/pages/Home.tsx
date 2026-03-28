import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { useState, useEffect, useMemo, useCallback, useRef } from "react";
import { trpc } from "@/lib/trpc";
import ThreatActorFeed from "@/components/ThreatActorFeed";
import {
  Key, Terminal, Activity, Users, ExternalLink, ChevronRight, Zap, Cloud,
  Target, Shield, Radar, Globe, Crosshair, FileText,
  Briefcase, BarChart3, Sparkles, Network, Lock, Fingerprint, Scan,
  BookOpen, Server, Cpu, Eye, X, Brain, Layers, Radio, Workflow, Rocket,
  ShieldCheck, Palette, AlertTriangle, CheckCircle2, ArrowRight, Siren,
  Search, Code2, FileCode, Bug, Gauge, MonitorPlay, Building2, Stethoscope,
  GraduationCap, Landmark, Factory, ShoppingCart, Plane, ChevronDown, ChevronUp,
  Clock, TrendingUp, Unplug, FlaskConical, Camera, FileCheck2, Atom, Info,
  Swords, Mountain, Droplets, Flame, Wind, CircleDot, Menu, ArrowUpRight
} from "lucide-react";
import { useInView } from "@/hooks/useInView";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from "@/components/ui/dialog";
import {
  Sheet, SheetTrigger, SheetContent, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";

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
  { date: "Mar 2026", title: "AC3 Report Generator", desc: "Generate professional pentest and red team reports. AI drafts narrative sections while the platform controls severity, evidence, and technique mappings. Includes executive summaries, QA review, and DOCX export." },
  { date: "Mar 2026", title: "DOCX Report Export", desc: "One-click Word document generation with title page, executive summary, findings table, and detailed sections. Branded and ready to deliver." },
  { date: "Mar 2026", title: "Findings Deduplication", desc: "Automatically detects and merges duplicate findings during imports. Combines evidence, keeps the highest severity, and prevents duplicates within a single batch." },
  { date: "Mar 2026", title: "Engagement Findings Import", desc: "One-click import from completed engagements. Timeline events are automatically mapped to report findings with technique IDs, severity, and evidence." },
  { date: "Mar 2026", title: "Caldera Operation Import", desc: "Import findings directly from Caldera operations. Each executed ability is mapped to a finding with technique IDs, severity, and command output evidence." },
  { date: "Mar 2026", title: "Cloud Workload Testing", desc: "Test container, serverless, and cloud-native security across AWS, Azure, and GCP." },
  { date: "Mar 2026", title: "Forest Mapper", desc: "Visualize Active Directory forests, map trust relationships, and identify cross-forest attack paths." },
  { date: "Mar 2026", title: "BloodHound Import", desc: "Import BloodHound data to visualize domain relationships and plan lateral movement paths." },
  { date: "Mar 2026", title: "Credential Auto-Rotation", desc: "Automated rotation for compromised credentials discovered during engagements." },
  { date: "Mar 2026", title: "SOAR & SOC Integration", desc: "Export findings, IOCs, and detection rules to SIEM, EDR, SOAR, and ticketing systems." },
  { date: "Feb 2026", title: "Discovery Chain", desc: "Automated 4-stage pipeline: subdomain enumeration, port scanning, service fingerprinting, and vulnerability scanning — all chained together." },
  { date: "Feb 2026", title: "Nmap Integration", desc: "8 scan profiles, 80+ NSE scripts, admin port scanning, and CVE extraction — all scope-enforced." },
  { date: "Feb 2026", title: "Unified Pipeline", desc: "All scanning tools feed into a single pipeline with cross-tool correlation and coverage tracking." },
  { date: "Feb 2026", title: "Passive Scan Clarity", desc: "Clear distinction between passive OSINT and active scanning, with prompts to create formal engagements." },
  { date: "Feb 2026", title: "Smarter Sorting", desc: "CVEs sorted by most recent. Threat actors sorted by most recently active. Faster triage." },
  { date: "Feb 2026", title: "Threat Enrichment Engine", desc: "Continuously correlates threat actor TTPs and IOCs across all platform modules with risk scoring and priority updates." },
  { date: "Feb 2026", title: "Live Scanner Integration", desc: "Real-time cross-referencing of scan results against the threat catalog with automated evidence collection." },
  { date: "Feb 2026", title: "Engagement Automation", desc: "5 engagement templates (pentest, red team, purple team, phishing, cloud) with pre-loaded techniques and abilities." },
  { date: "Feb 2026", title: "ATT&CK Validation Tests", desc: "1,400+ ATT&CK-mapped tests you can browse, execute, and track with full audit trails." },
  { date: "Feb 2026", title: "DAST Scanner", desc: "Dual-mode web app scanning: passive crawling for safe recon, active DAST for coordinated testing. AI auto-tunes scan policies." },
  { date: "Feb 2026", title: "API Spec Import", desc: "Import OpenAPI, GraphQL, and SOAP specs for targeted API security testing beyond traditional crawling." },
  { date: "Feb 2026", title: "Unified Offensive Stack", desc: "2,600+ exploits, 1,900+ emulation abilities, DAST scanning, 1,400+ ATT&CK tests, and social engineering — all in one place." },
  { date: "Feb 2026", title: "AI DAST Orchestrator", desc: "AI auto-configures scan policies, authentication handlers, and technology-specific rules. Reduces false positives." },
  { date: "Feb 2026", title: "Evasion Engine", desc: "Generate evasive command variants, chain obfuscation tools, and score campaign stealth with detection gap analysis." },
  { date: "Feb 2026", title: "Discovery Coverage", desc: "Track red team discovery priorities with weighted scoring and MITRE ATT&CK alignment." },
  { date: "Feb 2026", title: "Confirmed-Only Counting", desc: "Vulnerability counts show only confirmed findings by default. Toggle to see probable and potential matches." },
  { date: "Feb 2026", title: "4 New OSINT Connectors", desc: "Email security scoring, HTTP security headers, cloud asset discovery, and DNS deep analysis." },
  { date: "Feb 2026", title: "Autonomous Validation", desc: "AI-driven exploit validation runs real checks against confirmed CVEs and captures proof artifacts." },
  { date: "Feb 2026", title: "Kill Chain Timeline", desc: "Live engagement timeline with real-time updates for exploits, agents, scans, and tests." },
  { date: "Feb 2026", title: "Phishing Exploit Library", desc: "17 advanced phishing techniques auto-injected into campaigns based on target intelligence." },
  { date: "Feb 2026", title: "Crawl-to-Phish Pipeline", desc: "Clone login portals, detect vendors, and generate phishing templates from crawled pages." },
  { date: "Feb 2026", title: "Public Threat Actor Feed", desc: "Browse 1,700+ threat actor profiles with techniques, tools, and target sectors — no login required." },
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
// ─── Five Rings extended data for detail modals ─────────────────────
const FIVE_RINGS_DATA = [
  {
    kanji: "地", ring: "EARTH", romaji: "Chi",
    principle: "Establish the ground truth.",
    color: "from-amber-500/20 to-amber-900/5",
    borderColor: "border-amber-500/30 hover:border-amber-400/60",
    accentColor: "text-amber-400",
    bgAccent: "bg-amber-500/10",
    glowColor: "amber",
    icon: Mountain,
    doctrine: "Know what matters most to the organization before you test anything.",
    capabilities: [
      "Asset discovery and business impact analysis",
      "CARVER + Shock prioritization scoring",
      "Auto-BIA inference from technical signals",
      "16 OSINT connectors mapping the attack surface",
    ],
    musashi: "The Way of strategy is the Way of nature. When you appreciate the power of nature, knowing the rhythm of any situation, you will be able to hit the enemy naturally.",
    // Extended modal content
    objective: "Establish asset truth and business context",
    components: ["Asset Inventory Normalizer", "Auto-BIA Engine", "CARVER Baseliner"],
    outputs: ["Asset Criticality Profile", "Business Function Map", "Baseline Priority Queue"],
    strategicQuestions: [
      "What asset categories are present?",
      "Which systems plausibly map to identity, administration, communications, revenue, or customer trust?",
      "Which systems are choke points versus leaf nodes?",
      "Which technical signals imply critical business dependence?",
    ],
    carverFactors: [
      { name: "Criticality", weight: "17%", desc: "How important is the target to the mission?" },
      { name: "Accessibility", weight: "12%", desc: "How easily can the target be reached?" },
      { name: "Recuperability", weight: "10%", desc: "How quickly can the target recover?" },
      { name: "Vulnerability", weight: "12%", desc: "How susceptible is the target to attack?" },
      { name: "Effect", weight: "14%", desc: "What is the impact of a successful attack?" },
      { name: "Recognizability", weight: "5%", desc: "How easily can the target be identified?" },
    ],
    dataFlow: "Discovered assets, subdomains, auth surfaces, DNS records, software technologies, and sector inference are ingested, normalized, and tagged with exposure signals.",
  },
  {
    kanji: "水", ring: "WATER", romaji: "Sui",
    principle: "Adapt to the terrain.",
    color: "from-cyan-500/20 to-cyan-900/5",
    borderColor: "border-cyan-500/30 hover:border-cyan-400/60",
    accentColor: "text-cyan-400",
    bgAccent: "bg-cyan-500/10",
    glowColor: "cyan",
    icon: Droplets,
    doctrine: "Generate adaptive attack paths that flow around defenses, not through them.",
    capabilities: [
      "Multi-path attack graph generation",
      "Pivot logic with branch decision trees",
      "Stealth vs. speed vs. impact optimization",
      "Success probability estimation per path",
    ],
    musashi: "You should not have a favourite weapon. To become over-familiar with one weapon is as much a fault as not knowing it sufficiently well.",
    objective: "Generate adaptive pathways based on target conditions",
    components: ["Attack Graph Builder", "Branch Logic Engine", "Path Success Estimator"],
    outputs: ["Candidate Attack Paths", "Pivot Options", "Stealth vs. Speed Comparison"],
    strategicQuestions: [
      "Which attack path is viable with the fewest brittle assumptions?",
      "What alternative branches exist if controls hold?",
      "Which path best balances stealth, speed, and mission impact?",
    ],
    assessmentCriteria: [
      { name: "Success Probability", desc: "Likelihood the path reaches its objective" },
      { name: "Stealth", desc: "How likely the path avoids detection" },
      { name: "Speed", desc: "Time from initial access to objective" },
      { name: "Expected Impact", desc: "Business damage if the path succeeds" },
      { name: "Dependency Assumptions", desc: "How many conditions must hold true" },
    ],
    dataFlow: "Earth outputs feed into the attack graph builder, which generates candidate paths with branch decisions, pivot candidates, and success probability estimates.",
  },
  {
    kanji: "火", ring: "FIRE", romaji: "Ka",
    principle: "Act with purpose.",
    color: "from-red-500/20 to-red-900/5",
    borderColor: "border-red-500/30 hover:border-red-400/60",
    accentColor: "text-red-400",
    bgAccent: "bg-red-500/10",
    glowColor: "red",
    icon: Flame,
    doctrine: "Convert viable pathways into sequenced, validated operations with clear objectives.",
    capabilities: [
      "MITRE ATT&CK Mapped Campaign generation and execution",
      "Exploit sequencing with validation checkpoints",
      "Phishing campaigns with 17 advanced techniques",
      "Operation tempo optimization and guardrails",
    ],
    musashi: "The primary thing when you take a sword in your hands is your intention to cut the enemy, whatever the means.",
    objective: "Convert viable pathways into executable operation logic",
    components: ["MITRE ATT&CK Mapped Campaign Generator", "Validation Planner", "Timing Optimizer"],
    outputs: ["Campaign Plan", "Execution Sequence", "Validation Objectives"],
    strategicQuestions: [
      "What is the exact objective of the emulation?",
      "Which sequence validates the hypothesis fastest?",
      "What are the stop conditions and guardrails?",
    ],
    operationalDetails: [
      "2,600+ exploit modules from Metasploit integration",
      "1,900+ Caldera emulation abilities",
      "17 phishing techniques auto-injected based on target intel",
      "Real-time operation tempo with configurable guardrails",
    ],
    dataFlow: "Water's candidate paths are converted into emulation sequences with validation steps and an operation tempo plan.",
  },
  {
    kanji: "風", ring: "WIND", romaji: "Fū",
    principle: "Know other schools.",
    color: "from-emerald-500/20 to-emerald-900/5",
    borderColor: "border-emerald-500/30 hover:border-emerald-400/60",
    accentColor: "text-emerald-400",
    bgAccent: "bg-emerald-500/10",
    glowColor: "emerald",
    icon: Wind,
    doctrine: "Align operations to real adversary behavior — not theoretical attacks.",
    capabilities: [
      "1,700+ threat actor profiles with TTP mapping",
      "Sector-specific actor likelihood scoring",
      "MITRE ATT&CK technique alignment engine",
      "Campaign realism scoring against real tradecraft",
    ],
    musashi: "If you know the Way broadly you will see it in everything.",
    objective: "Align the plan to realistic adversary behavior",
    components: ["Threat Actor Registry", "MITRE Alignment Engine", "Sector-Actor Matcher"],
    outputs: ["Actor Likelihood Map", "TTP Overlay", "Campaign Realism Score"],
    strategicQuestions: [
      "Which real-world actors would care about this environment?",
      "Which ATT&CK patterns fit the sector and target profile?",
      "Which actor behaviors are common, rare, or implausible here?",
    ],
    sectorExamples: [
      { sector: "Government", actors: "APT29, APT28, Volt Typhoon", targets: "Identity, email, remote access, public-facing apps" },
      { sector: "Financial Services", actors: "FIN7, Lazarus Group", targets: "Payment systems, web apps, identity, endpoints" },
      { sector: "Healthcare", actors: "Wizard Spider, Lazarus Group", targets: "Identity, clinical apps, remote access, data repos" },
    ],
    dataFlow: "Fire's campaign plan is overlaid with likely actors, actor-matched TTPs, and realism adjustments based on sector intelligence.",
  },
  {
    kanji: "空", ring: "VOID", romaji: "Kū",
    principle: "See beyond the immediate step.",
    color: "from-violet-500/20 to-violet-900/5",
    borderColor: "border-violet-500/30 hover:border-violet-400/60",
    accentColor: "text-violet-400",
    bgAccent: "bg-violet-500/10",
    glowColor: "violet",
    icon: CircleDot,
    doctrine: "Predict likely outcomes, quantify uncertainty, and recommend the changes that matter most.",
    capabilities: [
      "AI-powered risk forecasting and escalation prediction",
      "Executive narrative generation with confidence bounds",
      "Mitigation delta analysis — what changes move the needle",
      "Compliance mapping across NIST, CMMC, and OWASP",
    ],
    musashi: "In the void is virtue, and no evil. Wisdom has existence, principle has existence, the Way has existence, spirit is nothingness.",
    objective: "Produce predictive reasoning and decision support",
    components: ["Strategic Reasoner", "Escalation Predictor", "Recommendation Engine"],
    outputs: ["Risk Forecast", "What-Changes Assessment", "Executive Narrative"],
    strategicQuestions: [
      "What is most likely to happen next if the organization is attacked?",
      "What single control change would most alter the forecast?",
      "Where is confidence weak and why?",
    ],
    reasoningTasks: [
      "Predict the most likely near-term compromise pattern",
      "List the top changes that would materially reduce risk",
      "Estimate which scores and pathways would change given a mitigation",
      "Compress the full assessment into a business-facing executive summary",
    ],
    dataFlow: "All prior ring outputs converge into predicted impact, confidence bounds, an executive summary, and mitigations with delta analysis.",
  },
];

// ─── Animated Ring Card wrapper ──────────────────────────────────────
function AnimatedRingCard({ children, index }: { children: React.ReactNode; index: number }) {
  const { ref, inView } = useInView({ threshold: 0.1 });
  return (
    <div
      ref={ref}
      className="transition-all duration-700 ease-out"
      style={{
        opacity: inView ? 1 : 0,
        transform: inView ? 'translateY(0)' : 'translateY(40px)',
        transitionDelay: `${index * 100}ms`,
      }}
    >
      {children}
    </div>
  );
}

export default function Home() {
  const [showUpdates, setShowUpdates] = useState(true);
  const [selectedRing, setSelectedRing] = useState<typeof FIVE_RINGS_DATA[number] | null>(null);
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
            <span className="font-display text-2xl tracking-wider">AC3</span>
          </div>
          {/* Desktop nav links */}
          <div className="hidden lg:flex items-center gap-6 text-sm font-display tracking-wider text-muted-foreground">
            <a href="#five-rings" className="hover:text-primary transition-colors">FIVE RINGS</a>
            <a href="#how-it-works" className="hover:text-primary transition-colors">HOW IT WORKS</a>
            <a href="#who-its-for" className="hover:text-primary transition-colors">WHO IT'S FOR</a>
            <a href="#capabilities" className="hover:text-primary transition-colors">CAPABILITIES</a>
            <a href="#threat-feed" className="hover:text-primary transition-colors">THREAT FEED</a>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/login">
              <Button variant="ghost" className="hidden sm:inline-flex font-display tracking-wider text-sm">
                LOG IN
              </Button>
            </Link>
            <Link href="/login?returnTo=%2Fdashboard">
              <Button className="hidden sm:inline-flex font-display tracking-wider bg-primary hover:bg-primary/90 text-sm">
                <Lock className="w-3.5 h-3.5 mr-1.5" />
                COMMAND CENTER
                <ChevronRight className="w-4 h-4 ml-1" />
              </Button>
            </Link>
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
                    { href: "#five-rings", label: "FIVE RINGS", icon: Swords },
                    { href: "#how-it-works", label: "HOW IT WORKS", icon: Workflow },
                    { href: "#who-its-for", label: "WHO IT'S FOR", icon: Users },
                    { href: "#capabilities", label: "CAPABILITIES", icon: Layers },
                    { href: "#threat-feed", label: "THREAT FEED", icon: Radar },
                  ].map((item) => (
                    <a
                      key={item.href}
                      href={item.href}
                      className="flex items-center gap-3 px-3 py-3 text-sm font-display tracking-wider text-muted-foreground hover:text-primary hover:bg-primary/5 transition-colors"
                      onClick={() => {
                        // Close sheet on nav click by finding and clicking the close button
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
                      LOG IN
                    </span>
                  </Link>
                  <Link href="/login?returnTo=%2Fdashboard">
                    <Button className="w-full mt-2 font-display tracking-wider bg-primary hover:bg-primary/90 text-sm">
                      <Lock className="w-3.5 h-3.5 mr-1.5" />
                      COMMAND CENTER
                    </Button>
                  </Link>
                </nav>
              </SheetContent>
            </Sheet>
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
              One platform for offensive security testing — from scanning and exploitation
              to phishing, detection validation, and professional reporting.
            </p>

            <p className="text-sm text-muted-foreground max-w-xl mx-auto mb-10">
              Stop switching between disconnected tools. AC3 brings reconnaissance, exploit execution,
              adversary emulation, social engineering, and compliance reporting into a single
              AI-powered command center.
            </p>

            <div className="flex flex-wrap justify-center gap-4 mb-12">
              <Link href="/login?returnTo=%2Fdashboard">
                <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-8 py-6 text-base">
                  <Lock className="w-4 h-4 mr-2" />
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
                Automated web app scanning finds vulnerabilities while OSINT connectors map
                your external attack surface. AI auto-configures scan policies based on your tech stack.
              </p>
            </div>

            <div className="text-center px-4">
              <div className="w-16 h-16 mx-auto mb-6 flex items-center justify-center border-2 border-primary/50 bg-primary/5">
                <Target className="w-8 h-8 text-primary" />
              </div>
              <h3 className="font-display text-xl tracking-wider mb-4">EXPLOIT & EMULATE</h3>
              <p className="text-muted-foreground leading-relaxed">
                Run real exploits, simulate adversary behavior, launch phishing campaigns,
                and validate ATT&CK coverage — all coordinated through one kill chain.
              </p>
            </div>

            <div className="text-center px-4">
              <div className="w-16 h-16 mx-auto mb-6 flex items-center justify-center border-2 border-primary/50 bg-primary/5">
                <ShieldCheck className="w-8 h-8 text-primary" />
              </div>
              <h3 className="font-display text-xl tracking-wider mb-4">ENRICH, VALIDATE & REPORT</h3>
              <p className="text-muted-foreground leading-relaxed">
                Threat intelligence keeps your findings current. Every exploitable weakness
                is backed by captured proof. Generate professional reports with AI-assisted
                narratives and evidence-backed findings.
              </p>
            </div>

          </div>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── Go Rin No Sho — Five Rings About Section ──────────── */}
      <section id="five-rings" className="py-24 relative overflow-hidden">
        {/* Subtle background texture */}
        <div className="absolute inset-0 -z-10 opacity-[0.02]">
          <div className="absolute inset-0" style={{
            backgroundImage: `radial-gradient(circle at 20% 50%, oklch(0.82 0.16 180 / 0.3) 0%, transparent 50%),
                              radial-gradient(circle at 80% 50%, oklch(0.65 0.18 280 / 0.2) 0%, transparent 50%)`
          }} />
        </div>

        <div className="container">
          {/* Section Header */}
          <div className="max-w-4xl mx-auto text-center mb-6">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 border border-primary/30 text-primary text-xs font-display tracking-widest mb-8">
              <Swords className="w-3.5 h-3.5" />
              STRATEGIC DOCTRINE
            </div>

            <h2 className="text-4xl sm:text-5xl md:text-6xl font-display leading-[0.95] tracking-tight mb-6">
              THE FIVE RINGS
            </h2>

            <p className="text-lg md:text-xl text-muted-foreground max-w-3xl mx-auto leading-relaxed mb-3">
              Inspired by Miyamoto Musashi's <span className="text-foreground italic">Go Rin No Sho</span> — the Book of Five Rings — AC3 applies the principles of strategic combat to offensive security.
            </p>
            <p className="text-sm text-muted-foreground/70 max-w-2xl mx-auto leading-relaxed">
              Each ring represents a layer of strategic reasoning that transforms scanning into strategy, and findings into actionable intelligence.
            </p>
          </div>

          {/* Five Rings Grid — Animated + Clickable */}
          <div className="mt-16 space-y-4">
            {FIVE_RINGS_DATA.map((ring, index) => (
              <AnimatedRingCard key={ring.ring} index={index}>
                <div
                  className={`group relative border-2 ${ring.borderColor} bg-gradient-to-r ${ring.color} transition-all duration-300 cursor-pointer`}
                  onClick={() => setSelectedRing(ring)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedRing(ring); } }}
                >
                  <div className="flex flex-col lg:flex-row">
                    {/* Kanji Side */}
                    <div className="flex-shrink-0 flex items-center justify-center lg:w-48 py-8 lg:py-0 border-b lg:border-b-0 lg:border-r border-inherit">
                      <div className="text-center">
                        <div className={`text-7xl lg:text-8xl font-bold ${ring.accentColor} opacity-80 group-hover:opacity-100 transition-opacity leading-none`} style={{ fontFamily: "'Noto Serif JP', serif" }}>
                          {ring.kanji}
                        </div>
                        <div className={`font-display text-xs tracking-[0.3em] ${ring.accentColor} mt-2 opacity-60`}>
                          {ring.romaji.toUpperCase()}
                        </div>
                      </div>
                    </div>

                    {/* Content Side */}
                    <div className="flex-1 p-6 lg:p-8">
                      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 mb-4">
                        <div>
                          <div className="flex items-center gap-3 mb-2">
                            <ring.icon className={`w-5 h-5 ${ring.accentColor}`} />
                            <h3 className={`font-display text-2xl tracking-wider ${ring.accentColor}`}>
                              {ring.ring}
                            </h3>
                          </div>
                          <p className="text-lg text-foreground/90 font-display tracking-wide">
                            {ring.principle}
                          </p>
                        </div>
                        <div className="flex items-center gap-3">
                          <div className={`flex-shrink-0 px-3 py-1 ${ring.bgAccent} border border-current/10 ${ring.accentColor} text-xs font-display tracking-widest`}>
                            RING {String(index + 1).padStart(2, '0')}
                          </div>
                          <ArrowUpRight className={`w-4 h-4 ${ring.accentColor} opacity-0 group-hover:opacity-100 transition-opacity`} />
                        </div>
                      </div>

                      <p className="text-sm text-muted-foreground leading-relaxed mb-5">
                        {ring.doctrine}
                      </p>

                      <div className="grid sm:grid-cols-2 gap-x-6 gap-y-2 mb-5">
                        {ring.capabilities.map((cap) => (
                          <div key={cap} className="flex items-start gap-2 text-sm">
                            <div className={`w-1.5 h-1.5 ${ring.bgAccent} border ${ring.borderColor.split(' ')[0]} flex-shrink-0 mt-1.5`} />
                            <span className="text-foreground/70">{cap}</span>
                          </div>
                        ))}
                      </div>

                      <div className="border-t border-inherit pt-4 flex items-end justify-between gap-4">
                        <p className="text-xs text-muted-foreground/60 italic leading-relaxed flex-1">
                          "{ring.musashi}"
                          <span className="not-italic ml-2 text-muted-foreground/40">— Musashi</span>
                        </p>
                        <span className={`text-xs font-display tracking-wider ${ring.accentColor} opacity-0 group-hover:opacity-80 transition-opacity whitespace-nowrap`}>
                          EXPLORE RING →
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </AnimatedRingCard>
            ))}
          </div>

          {/* Attribution Footer */}
          <div className="mt-12 text-center">
            <div className="inline-flex flex-col items-center gap-2">
              <p className="text-sm text-muted-foreground/60">
                Strategic doctrine adapted from <span className="text-foreground/70 italic">Go Rin No Sho</span> (1645) by Miyamoto Musashi
              </p>
              <p className="text-xs text-muted-foreground/40">
                Platform architecture by Harrison Cook — <a href="https://aceofcloud.com" target="_blank" rel="noopener noreferrer" className="text-primary/50 hover:text-primary transition-colors">Ace of Cloud</a>
              </p>
            </div>
          </div>

          {/* ─── Ring Detail Modal ──────────────────────────────────── */}
          <Dialog open={!!selectedRing} onOpenChange={(open) => !open && setSelectedRing(null)}>
            <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto bg-background border-2 border-border">
              {selectedRing && (() => {
                const r = selectedRing;
                return (
                  <>
                    <DialogHeader className="pb-4 border-b border-border">
                      <div className="flex items-center gap-4">
                        <div className={`text-6xl font-bold ${r.accentColor} leading-none`} style={{ fontFamily: "'Noto Serif JP', serif" }}>
                          {r.kanji}
                        </div>
                        <div>
                          <DialogTitle className={`font-display text-3xl tracking-wider ${r.accentColor}`}>
                            {r.ring}
                            <span className="text-muted-foreground/50 text-lg ml-3 font-normal">/ {r.romaji}</span>
                          </DialogTitle>
                          <DialogDescription className="text-foreground/80 text-base font-display tracking-wide mt-1">
                            {r.principle}
                          </DialogDescription>
                        </div>
                      </div>
                    </DialogHeader>

                    <div className="space-y-6 pt-4">
                      {/* Musashi Quote */}
                      <div className={`p-4 ${r.bgAccent} border ${r.borderColor.split(' ')[0]}`}>
                        <p className="text-sm italic text-foreground/80 leading-relaxed">
                          "{r.musashi}"
                        </p>
                        <p className="text-xs text-muted-foreground/60 mt-2">— Miyamoto Musashi, Go Rin No Sho</p>
                      </div>

                      {/* Objective */}
                      <div>
                        <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-2">STRATEGIC OBJECTIVE</h4>
                        <p className="text-foreground/90 leading-relaxed">{r.objective}</p>
                      </div>

                      {/* Doctrine */}
                      <div>
                        <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-2">DOCTRINE</h4>
                        <p className="text-foreground/80 leading-relaxed">{r.doctrine}</p>
                      </div>

                      {/* Components & Outputs */}
                      <div className="grid sm:grid-cols-2 gap-6">
                        <div>
                          <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-3">COMPONENTS</h4>
                          <div className="space-y-2">
                            {r.components.map((c) => (
                              <div key={c} className="flex items-center gap-2 text-sm">
                                <div className={`w-2 h-2 ${r.bgAccent} border ${r.borderColor.split(' ')[0]}`} />
                                <span className="text-foreground/80">{c}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                        <div>
                          <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-3">OUTPUTS</h4>
                          <div className="space-y-2">
                            {r.outputs.map((o) => (
                              <div key={o} className="flex items-center gap-2 text-sm">
                                <ArrowRight className={`w-3.5 h-3.5 ${r.accentColor} flex-shrink-0`} />
                                <span className="text-foreground/80">{o}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* Capabilities */}
                      <div>
                        <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-3">CAPABILITIES</h4>
                        <div className="grid sm:grid-cols-2 gap-x-6 gap-y-2">
                          {r.capabilities.map((cap) => (
                            <div key={cap} className="flex items-start gap-2 text-sm">
                              <div className={`w-1.5 h-1.5 ${r.bgAccent} border ${r.borderColor.split(' ')[0]} flex-shrink-0 mt-1.5`} />
                              <span className="text-foreground/70">{cap}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Strategic Questions */}
                      <div>
                        <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-3">STRATEGIC QUESTIONS THIS RING ANSWERS</h4>
                        <div className="space-y-2">
                          {r.strategicQuestions.map((q, i) => (
                            <div key={i} className="flex items-start gap-3 text-sm">
                              <span className={`${r.accentColor} font-display text-xs mt-0.5`}>{String(i + 1).padStart(2, '0')}</span>
                              <span className="text-foreground/80">{q}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Ring-specific detail sections */}
                      {'carverFactors' in r && r.carverFactors && (
                        <div>
                          <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-3">CARVER + SHOCK SCORING FACTORS</h4>
                          <div className="grid gap-2">
                            {(r as any).carverFactors.map((f: any) => (
                              <div key={f.name} className="flex items-center gap-3 text-sm p-2 bg-card/50 border border-border/50">
                                <span className={`${r.accentColor} font-display text-xs w-10 text-right`}>{f.weight}</span>
                                <span className="text-foreground/90 font-medium w-32">{f.name}</span>
                                <span className="text-muted-foreground">{f.desc}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {'assessmentCriteria' in r && r.assessmentCriteria && (
                        <div>
                          <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-3">PATH ASSESSMENT CRITERIA</h4>
                          <div className="grid gap-2">
                            {(r as any).assessmentCriteria.map((c: any) => (
                              <div key={c.name} className="flex items-start gap-3 text-sm p-2 bg-card/50 border border-border/50">
                                <span className={`${r.accentColor} font-medium w-40 flex-shrink-0`}>{c.name}</span>
                                <span className="text-muted-foreground">{c.desc}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {'operationalDetails' in r && r.operationalDetails && (
                        <div>
                          <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-3">OPERATIONAL ARSENAL</h4>
                          <div className="space-y-2">
                            {(r as any).operationalDetails.map((d: string, i: number) => (
                              <div key={i} className="flex items-start gap-2 text-sm">
                                <Flame className={`w-3.5 h-3.5 ${r.accentColor} flex-shrink-0 mt-0.5`} />
                                <span className="text-foreground/80">{d}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {'sectorExamples' in r && r.sectorExamples && (
                        <div>
                          <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-3">SECTOR-ACTOR ALIGNMENT EXAMPLES</h4>
                          <div className="grid gap-3">
                            {(r as any).sectorExamples.map((s: any) => (
                              <div key={s.sector} className="p-3 bg-card/50 border border-border/50">
                                <div className={`font-display text-sm ${r.accentColor} mb-1`}>{s.sector}</div>
                                <div className="text-xs text-muted-foreground"><span className="text-foreground/70">Actors:</span> {s.actors}</div>
                                <div className="text-xs text-muted-foreground mt-1"><span className="text-foreground/70">Targets:</span> {s.targets}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {'reasoningTasks' in r && r.reasoningTasks && (
                        <div>
                          <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-3">AI REASONING TASKS</h4>
                          <div className="space-y-2">
                            {(r as any).reasoningTasks.map((t: string, i: number) => (
                              <div key={i} className="flex items-start gap-3 text-sm">
                                <Brain className={`w-3.5 h-3.5 ${r.accentColor} flex-shrink-0 mt-0.5`} />
                                <span className="text-foreground/80">{t}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Data Flow */}
                      <div className="p-4 bg-card/30 border border-border/50">
                        <h4 className="font-display text-sm tracking-widest text-muted-foreground mb-2">DATA FLOW</h4>
                        <p className="text-sm text-foreground/70 leading-relaxed">{r.dataFlow}</p>
                      </div>
                    </div>
                  </>
                );
              })()}
            </DialogContent>
          </Dialog>
        </div>
      </section>

      <div className="w-full h-px bg-primary" />

      {/* ─── How It Works (Plain English) ───────────────────────── */}
      <section id="how-it-works" className="py-20 bg-card/30">
        <div className="container">
          <div className="max-w-3xl mx-auto text-center mb-16">
            <h2 className="text-4xl sm:text-5xl font-display mb-4">HOW IT WORKS</h2>
            <p className="text-lg text-muted-foreground">
              Four steps from discovery to proof.
            </p>
          </div>

          <div className="max-w-4xl mx-auto">
            <div className="grid md:grid-cols-2 gap-6">
              {[
                {
                  step: "1",
                  icon: Radar,
                  title: "Discover Your Attack Surface",
                  desc: "Point AC3 at your domain. It automatically scans web apps, maps exposed services, and identifies technologies. Import API specs for deeper coverage."
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
                  title: "Execute Real Attacks",
                  desc: "Execute real exploits, run adversary emulation with APT profiles, and launch phishing campaigns. Every action is controlled, audited, and mapped to ATT&CK."
                },
                {
                  step: "4",
                  icon: BarChart3,
                  title: "Enrich, Validate & Report",
                  desc: "Threat intelligence keeps findings current. Autonomous validation confirms which CVEs are actually exploitable. Generate professional reports with AI-assisted narratives and evidence-backed findings."
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
            <AnimatedStat value={stats.exploitCatalogTotal} label="EXPLOIT CATALOG" suffix="+" />
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
              { icon: Crosshair, title: "Red Teams", desc: "Run exploits, adversary emulation, and ATT&CK validation from one command center." },
              { icon: Shield, title: "Penetration Testers", desc: "Scope engagements, execute exploits, launch phishing, and deliver evidence-backed reports in one workflow." },
              { icon: ShieldCheck, title: "Purple Teams", desc: "Execute attacks and immediately measure what your defenses catch. Auto-generate detection rules." },
              { icon: Server, title: "Managed Service Providers", desc: "Scale offensive assessments across clients with per-engagement tracking and branded reporting." },
              { icon: Building2, title: "Enterprise Security", desc: "Test employee awareness and infrastructure resilience with controlled attack simulations." },
              { icon: Landmark, title: "Government & Defense", desc: "Support compliance with CMMC and NIST frameworks through evidence-based testing and audit-ready reports." },
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
            Enter the Command Center to run your full offensive testing workflow from one interface.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <Link href="/login?returnTo=%2Fdashboard">
              <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-8 py-6">
                <Lock className="w-4 h-4 mr-2" />
                SIGN IN TO COMMAND CENTER
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
            subtitle="Eight integrated pillars covering the full offensive execution lifecycle — from reconnaissance through continuous threat enrichment."
          >
          <div className="grid lg:grid-cols-3 gap-6">
            <PillarCard
              icon={<Target className="w-7 h-7" />}
              number="01"
              title="ADVERSARY EMULATION"
              description={`${stats.exploitModules.toLocaleString()}+ exploit modules, ${stats.calderaAbilities.toLocaleString()} emulation abilities, and 1,400+ ATT&CK validation tests — all correlated through MITRE ATT&CK.`}
              features={[
                "Real exploit execution with session management",
                "Adversary emulation with APT-based profiles",
                "1,400+ ATT&CK-mapped validation tests",
                "Cross-tool correlation across all modules",
                "Cloud-provisioned exploit infrastructure",
                "Real-time operation monitoring",
              ]}
              link="/agents"
              linkLabel="DEPLOY AGENTS"
            />

            <PillarCard
              icon={<Zap className="w-7 h-7" />}
              number="02"
              title="SOCIAL ENGINEERING"
              description="17 phishing techniques including browser-in-the-browser, MFA bypass, and HTML smuggling — automatically matched to targets based on intelligence."
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
              description="Web app scanning with AI-powered configuration plus passive recon connectors. Import API specs for full coverage. Compare scans to track changes over time."
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
              title="THREAT INTELLIGENCE & ENRICHMENT"
              description={`${stats.threatActors.toLocaleString()} threat actor profiles with a continuous enrichment engine that correlates techniques and indicators across your security stack. Five aggregated vulnerability feeds with live verification.`}
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
              description="Generate professional pentest and red team reports. AI drafts narrative sections while the platform controls severity, evidence, and technique mappings — all subject to human review."
              features={[
                "DOCX export with QA review pipeline",
                "AI-assisted narrative drafting with human approval",
                "One-click import from engagements and Caldera operations",
                "Automatic findings deduplication",
                "Evidence artifact links in every report",
                "Kill chain timeline with real-time updates",
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
                "Auto-loaded emulation abilities and Metasploit modules",
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
            subtitle="40+ integrated modules organized across eight operational domains."
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
                { icon: Network, name: "AD Attack Paths", desc: "Active Directory attack simulation, forest mapping, BloodHound import, and domain trust enumeration" },
                { icon: Cloud, name: "Cloud Attack Paths", desc: "Cloud attack path discovery and workload testing across AWS, Azure, and GCP" },
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
              title="THREAT ENRICHMENT & AUTOMATION"
              color="text-purple-400"
              modules={[
                { icon: Brain, name: "Enrichment Engine", desc: "Continuous threat intelligence enrichment correlating TTPs and IOCs across all platform modules" },
                { icon: TrendingUp, name: "Coverage Matrix", desc: "Technique-to-threat-actor coverage with density and risk scoring" },
                { icon: Zap, name: "Engagement Automation", desc: "5 engagement templates with kill chain mapping, pre-loaded emulation abilities and Metasploit modules" },
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
            subtitle="Eight phases from reconnaissance through reporting."
          >
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
            {[
              { step: "01", title: "RECON", desc: "Scan web apps and map your attack surface with evidence-based risk scoring", icon: Radar },
              { step: "02", title: "EXPLOIT", desc: "Match confirmed vulnerabilities to exploit modules and deploy with agent stagers", icon: Target },
              { step: "03", title: "OPERATE", desc: "Run adversary emulation with APT-based profiles and thousands of abilities", icon: Crosshair },
              { step: "04", title: "PHISH", desc: "Launch social engineering campaigns with advanced phishing techniques", icon: Zap },
              { step: "05", title: "VALIDATE", desc: "Run ATT&CK validation tests and confirm exploitability with evidence capture", icon: FlaskConical },
              { step: "06", title: "DETECT", desc: "Auto-generate detection rules from executed techniques and measure coverage gaps", icon: ShieldCheck },
              { step: "07", title: "ENRICH", desc: "Continuous threat intelligence correlates findings against threat actors and feeds IOCs to all modules", icon: Brain },
              { step: "08", title: "REPORT", desc: "Generate professional reports with AI-assisted narratives, one-click imports, and QA review", icon: FileText },
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
                "AC3 Report Generator with LLM-bounded narrative drafting",
                "DOCX export with professional formatting and S3 upload",
                "Engagement import and Caldera bulk import with deduplication",
                "QA review pipeline checking prohibited content and audit readiness",
                "Platform-controlled severity, evidence, ATT&CK IDs, and NIST controls",
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

      {/* ─── Threat Actor Feed ──────────────────────────────────── */}
      <div id="threat-feed">
        <ThreatActorFeed />
      </div>

      {/* ─── Footer ─────────────────────────────────────────────── */}
      <footer className="py-6 border-t border-border bg-card">
        <div className="container flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Cloud className="w-5 h-5 text-primary" />
            <span className="font-display tracking-wider">AC3</span>
          </div>
          <p className="text-sm text-muted-foreground text-center">
            AC3 — Unified Offensive Security Platform | Powered by Ace of Cloud
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
