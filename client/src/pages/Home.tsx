import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { 
  Key, 
  Terminal, 
  Activity, 
  Users, 
  ExternalLink,
  ChevronRight,
  Zap,
  Cloud,
  Mail,
  Phone,
  MapPin,
  Target
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
            
            {/* Teal Divider */}
            <div className="w-full h-1 bg-primary my-8" />
            
            <p className="text-xl md:text-2xl text-muted-foreground max-w-2xl mb-6 leading-relaxed">
              <span className="text-primary font-semibold">C3</span> — Your unified command center for offensive security operations. 
              Combine MITRE Caldera adversary emulation with GoPhish phishing campaigns to orchestrate, 
              monitor, and report on full-spectrum attack simulations from a single dashboard.
            </p>
            
            <p className="text-lg text-primary mb-12">
              Powered by <span className="font-semibold">Ace of Cloud</span> — Cutting-Edge Cybersecurity Solutions
            </p>

            <div className="flex flex-wrap gap-4">
              <Link href="/dashboard">
                <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-8 py-6 text-lg">
                  GET STARTED
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

      {/* Teal Divider Full Width */}
      <div className="w-full h-1 bg-primary" />

      {/* Features Grid */}
      <section className="py-20">
        <div className="container">
          <h2 className="text-5xl md:text-6xl font-display mb-16">CAPABILITIES</h2>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            <FeatureCard
              icon={<Activity className="w-8 h-8" />}
              title="SERVER MONITORING"
              description="Real-time health checks, uptime tracking, and resource monitoring for your Caldera deployment."
            />
            <FeatureCard
              icon={<Key className="w-8 h-8" />}
              title="CREDENTIAL VAULT"
              description="Secure storage and management of admin credentials, API keys, and SSH access details."
            />
            <FeatureCard
              icon={<Terminal className="w-8 h-8" />}
              title="API INTEGRATION"
              description="Live statistics from Caldera API showing adversaries, abilities, and active operations."
            />
            <FeatureCard
              icon={<Users className="w-8 h-8" />}
              title="TEAM ACCESS"
              description="Role-based permissions for team members with admin, user, and viewer access levels."
            />
            <FeatureCard
              icon={<Zap className="w-8 h-8" />}
              title="QUICK ACTIONS"
              description="One-click access to Caldera UI, SSH commands, and API testing utilities."
            />
            <FeatureCard
              icon={<Target className="w-8 h-8" />}
              title="THREAT BROWSER"
              description="Browse 490+ MITRE ATT&CK threat group profiles and APT29 VCD campaigns."
            />
          </div>
        </div>
      </section>

      {/* Teal Divider Full Width */}
      <div className="w-full h-1 bg-primary" />

      {/* Stats Section */}
      <section className="py-20 bg-card">
        <div className="container">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
            <StatBlock value="492" label="ADVERSARIES" />
            <StatBlock value="1,940" label="ABILITIES" />
            <StatBlock value="348" label="ADVERSARY TTP'S" />
            <StatBlock value="24/7" label="MONITORING" />
          </div>
        </div>
      </section>

      {/* Teal Divider Full Width */}
      <div className="w-full h-1 bg-primary" />

      {/* About Ace of Cloud */}
      <section className="py-20">
        <div className="container">
          <h2 className="text-5xl md:text-6xl font-display mb-8">ABOUT ACE OF CLOUD</h2>
          <div className="grid md:grid-cols-2 gap-12">
            <div>
              <p className="text-lg text-muted-foreground mb-6 leading-relaxed">
                Ace of Cloud provides reliable compliance and data migration services tailored to your needs. 
                Trust us to secure your digital assets with cutting-edge cybersecurity solutions.
              </p>
              <p className="text-lg text-muted-foreground mb-8 leading-relaxed">
                Our services include FedRAMP Compliance, CMMC Preparation, Security Advisory, 
                Secure Cloud Architecture, and Incident Response.
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
            C3 — Cyber Campaign Command | Powered by Ace of Cloud Cybersecurity
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

function StatBlock({ value, label }: { value: string; label: string }) {
  return (
    <div>
      <div className="font-display text-5xl md:text-7xl text-white mb-2">{value}</div>
      <div className="text-xs tracking-widest text-muted-foreground">{label}</div>
    </div>
  );
}
