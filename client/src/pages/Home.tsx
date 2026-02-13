import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { 
  Key, Terminal, Activity, Users, ExternalLink, ChevronRight, Zap, Cloud,
  Mail, Phone, MapPin, Target, Shield, Radar, Globe, Crosshair, FileText,
  Briefcase, BarChart3, Sparkles, Network, Lock, Fingerprint, Scan,
  BookOpen, Server, Cpu, Eye
} from "lucide-react";

export default function Home() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="container flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <Cloud className="w-8 h-8 text-primary" />
            <span className="font-display text-2xl tracking-wider">ACE OF CLOUD</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/dashboard">
              <Button variant="outline" className="font-display tracking-wider border-2 border-white hover:bg-white hover:text-background">
                DASHBOARD
                <ChevronRight className="w-4 h-4 ml-2" />
              </Button>
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        <div className="container">
          <div className="max-w-4xl">
            <h1 className="text-7xl md:text-9xl font-display leading-none tracking-tight mb-8">
              CYBER
              <br />
              <span className="text-primary">CAMPAIGN</span>
              <br />
              <span className="text-primary">COMMAND</span>
            </h1>
            
            <div className="w-full h-1 bg-primary my-8" />
            
            <p className="text-xl md:text-2xl text-muted-foreground max-w-2xl mb-6 leading-relaxed">
              <span className="text-primary font-semibold">C3</span> — The unified offensive security platform for MSPs and red teams. 
              Orchestrate MITRE Caldera adversary emulation, GoPhish phishing campaigns, OSINT reconnaissance, 
              and AI-powered campaign design from a single command center.
            </p>
            
            <p className="text-lg text-primary mb-12">
              Built by <span className="font-semibold">Harrison Cook</span> — Powered by <span className="font-semibold">Ace of Cloud</span>
            </p>

            <div className="flex flex-wrap gap-4">
              <Link href="/dashboard">
                <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-8 py-6 text-lg">
                  ENTER COMMAND CENTER
                  <ChevronRight className="w-5 h-5 ml-2" />
                </Button>
              </Link>
              <a href="https://caldera.aceofcloud.io" target="_blank" rel="noopener noreferrer">
                <Button size="lg" variant="outline" className="font-display tracking-wider border-2 border-white hover:bg-white hover:text-background px-8 py-6 text-lg">
                  CALDERA SERVER
                  <ExternalLink className="w-5 h-5 ml-2" />
                </Button>
              </a>
            </div>
          </div>
        </div>

        {/* Background Grid Pattern */}
        <div className="absolute inset-0 -z-10 opacity-5">
          <div className="absolute inset-0" style={{
            backgroundImage: `linear-gradient(to right, white 1px, transparent 1px),
                              linear-gradient(to bottom, white 1px, transparent 1px)`,
            backgroundSize: '60px 60px'
          }} />
        </div>
      </section>

      <div className="w-full h-1 bg-primary" />

      {/* Core Platform Capabilities */}
      <section className="py-20">
        <div className="container">
          <h2 className="text-5xl md:text-6xl font-display mb-4">PLATFORM CAPABILITIES</h2>
          <p className="text-lg text-muted-foreground mb-16 max-w-3xl">
            A full-spectrum offensive security operations platform combining adversary emulation, 
            social engineering, domain intelligence, and automated campaign design.
          </p>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            <FeatureCard
              icon={<Briefcase className="w-8 h-8" />}
              title="ENGAGEMENT MANAGEMENT"
              description="Create and manage client engagements with full lifecycle tracking — from planning through active assessment to completion. Link campaigns, track results, and maintain audit trails per engagement."
            />
            <FeatureCard
              icon={<Radar className="w-8 h-8" />}
              title="OSINT RECONNAISSANCE"
              description="Automated domain intelligence gathering: DNS/MX record analysis, SPF/DKIM/DMARC security assessment, subdomain enumeration via Certificate Transparency, and email spoofability scoring."
            />
            <FeatureCard
              icon={<Globe className="w-8 h-8" />}
              title="TYPOSQUAT DISCOVERY"
              description="Generate lookalike domains using 12 permutation algorithms (bitsquatting, homoglyph, transposition, etc.). Batch-check availability, track purchase status, and manage domain lifecycle for engagements."
            />
            <FeatureCard
              icon={<Sparkles className="w-8 h-8" />}
              title="AI CAMPAIGN DESIGNER"
              description="LLM-powered campaign auto-design that analyzes OSINT findings and generates tailored phishing strategies — including attack vectors, pretexts, templates, and sending domain recommendations."
            />
            <FeatureCard
              icon={<Lock className="w-8 h-8" />}
              title="SPOOFABILITY ANALYSIS"
              description="Comprehensive email security assessment with MX record checks, SPF/DKIM/DMARC policy analysis, and a 0-100 spoofability score. Determines whether to spoof directly or purchase a lookalike domain."
            />
            <FeatureCard
              icon={<Crosshair className="w-8 h-8" />}
              title="CAMPAIGN WIZARD"
              description="Guided 6-step campaign creation flow: engagement selection, template preview, target group configuration, SMTP profile, landing page, and launch — all without switching to the GoPhish UI."
            />
            <FeatureCard
              icon={<Target className="w-8 h-8" />}
              title="GOPHISH INTEGRATION"
              description="Full GoPhish API proxy with campaign management, template library with 9 help desk phishing templates (Zendesk, ServiceNow, Jira, etc.), one-click template sync, and campaign cloning."
            />
            <FeatureCard
              icon={<Activity className="w-8 h-8" />}
              title="CALDERA EMULATION"
              description="MITRE Caldera adversary emulation with real-time operation monitoring, agent deployment, ability execution tracking, and integration with 490+ threat group profiles."
            />
            <FeatureCard
              icon={<BarChart3 className="w-8 h-8" />}
              title="ENGAGEMENT RESULTS"
              description="Per-engagement results dashboard aggregating campaign stats: emails sent, opened, clicked, and credentials captured — with visual funnel charts and timeline views for client reporting."
            />
            <FeatureCard
              icon={<FileText className="w-8 h-8" />}
              title="TEMPLATE LIBRARY"
              description="9 pre-built help desk phishing templates covering Zendesk, ServiceNow, Jira, Freshdesk, ConnectWise, and more. Live preview with desktop/tablet/mobile views and GoPhish variable rendering."
            />
            <FeatureCard
              icon={<Key className="w-8 h-8" />}
              title="CREDENTIAL VAULT"
              description="Secure storage and management of admin credentials, API keys, SSH access, and server configurations with role-based access control."
            />
            <FeatureCard
              icon={<BookOpen className="w-8 h-8" />}
              title="COMPLIANCE & REPORTING"
              description="NIST CSF, CMMC, and FedRAMP compliance framework mapping. Security report generation and APT library with 490+ threat group profiles and MITRE ATT&CK technique mapping."
            />
          </div>
        </div>
      </section>

      <div className="w-full h-1 bg-primary" />

      {/* Technical Architecture */}
      <section className="py-20 bg-card">
        <div className="container">
          <h2 className="text-5xl md:text-6xl font-display mb-16">ARCHITECTURE</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
            <ArchCard
              icon={<Server className="w-6 h-6" />}
              title="CALDERA SERVER"
              items={["Adversary Emulation", "Agent Deployment", "Operation Monitoring", "Ability Execution"]}
            />
            <ArchCard
              icon={<Target className="w-6 h-6" />}
              title="GOPHISH SERVER"
              items={["Email Campaigns", "Credential Harvesting", "Landing Pages", "Template Engine"]}
            />
            <ArchCard
              icon={<Radar className="w-6 h-6" />}
              title="OSINT ENGINE"
              items={["DNS Analysis", "Subdomain Enum", "Typosquat Gen", "Spoofability Scoring"]}
            />
            <ArchCard
              icon={<Sparkles className="w-6 h-6" />}
              title="AI LAYER"
              items={["Campaign Design", "Tactical Assessment", "Spoof Analysis", "Threat Mapping"]}
            />
          </div>
        </div>
      </section>

      <div className="w-full h-1 bg-primary" />

      {/* Stats Section */}
      <section className="py-20">
        <div className="container">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
            <StatBlock value="492" label="THREAT GROUPS" />
            <StatBlock value="1,940" label="ABILITIES" />
            <StatBlock value="12" label="TYPOSQUAT ALGORITHMS" />
            <StatBlock value="9" label="PHISHING TEMPLATES" />
          </div>
        </div>
      </section>

      <div className="w-full h-1 bg-primary" />

      {/* Workflow */}
      <section className="py-20 bg-card">
        <div className="container">
          <h2 className="text-5xl md:text-6xl font-display mb-16">ENGAGEMENT WORKFLOW</h2>
          <div className="grid md:grid-cols-5 gap-6">
            {[
              { step: "01", title: "CREATE", desc: "Set up engagement with client details and target domain" },
              { step: "02", title: "RECON", desc: "Run OSINT scan — DNS, subdomains, typosquats, spoofability" },
              { step: "03", title: "DESIGN", desc: "AI generates campaign strategies from OSINT findings" },
              { step: "04", title: "LAUNCH", desc: "Deploy phishing campaigns and adversary emulations" },
              { step: "05", title: "REPORT", desc: "Aggregate results and generate client-ready reports" },
            ].map((item) => (
              <div key={item.step} className="text-center">
                <div className="text-5xl font-display text-primary mb-4">{item.step}</div>
                <h3 className="font-display text-xl mb-2">{item.title}</h3>
                <p className="text-sm text-muted-foreground">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <div className="w-full h-1 bg-primary" />

      {/* About Ace of Cloud */}
      <section className="py-20">
        <div className="container">
          <h2 className="text-5xl md:text-6xl font-display mb-8">ABOUT ACE OF CLOUD</h2>
          <div className="grid md:grid-cols-2 gap-12">
            <div>
              <p className="text-lg text-muted-foreground mb-6 leading-relaxed">
                Ace of Cloud provides cutting-edge cybersecurity solutions including FedRAMP Compliance, 
                CMMC Preparation, Security Advisory, Secure Cloud Architecture, and Incident Response. 
                The C3 platform represents our commitment to building tools that empower MSPs and red teams 
                with enterprise-grade offensive security capabilities.
              </p>
              <p className="text-lg text-muted-foreground mb-8 leading-relaxed">
                Designed and built by Harrison Cook, C3 integrates open-source tools like MITRE Caldera 
                and GoPhish with custom OSINT reconnaissance, AI-powered campaign design, and comprehensive 
                engagement management into a unified command center.
              </p>
              <a href="https://aceofcloud.com" target="_blank" rel="noopener noreferrer">
                <Button variant="outline" className="font-display tracking-wider border-2 border-primary text-primary hover:bg-primary hover:text-white">
                  VISIT ACEOFCLOUD.COM
                  <ExternalLink className="w-4 h-4 ml-2" />
                </Button>
              </a>
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
      <footer className="py-8 border-t border-border bg-card">
        <div className="container flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Cloud className="w-5 h-5 text-primary" />
            <span className="font-display tracking-wider">ACE OF CLOUD</span>
          </div>
          <p className="text-sm text-muted-foreground">
            C3 — Cyber Campaign Command | Built by Harrison Cook | Powered by Ace of Cloud
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

function FeatureCard({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <div className="bg-card border-2 border-border p-8 hover:border-primary transition-colors group">
      <div className="text-primary mb-4 group-hover:scale-110 transition-transform">
        {icon}
      </div>
      <h3 className="font-display text-2xl mb-3">{title}</h3>
      <p className="text-muted-foreground">{description}</p>
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
            <div className="w-1.5 h-1.5 bg-primary" />
            {item}
          </div>
        ))}
      </div>
    </div>
  );
}

function StatBlock({ value, label }: { value: string; label: string }) {
  return (
    <div>
      <div className="font-display text-5xl md:text-7xl text-white mb-2">{value}</div>
      <div className="text-xs tracking-widest text-muted-foreground">{label}</div>
    </div>
  );
}
