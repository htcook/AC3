import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { getLoginUrl } from "@/const";
import { Link } from "wouter";
import { 
  Shield, 
  Terminal, 
  Activity, 
  Users, 
  ExternalLink,
  ChevronRight,
  Zap
} from "lucide-react";

export default function Home() {
  const { user, loading, isAuthenticated } = useAuth();

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="container flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-primary" />
            <span className="font-display text-2xl tracking-wider">CALDERA</span>
          </div>
          <div className="flex items-center gap-4">
            {loading ? (
              <div className="w-24 h-10 bg-muted animate-pulse" />
            ) : isAuthenticated ? (
              <Link href="/dashboard">
                <Button variant="outline" className="font-display tracking-wider border-2 border-white hover:bg-white hover:text-black">
                  DASHBOARD
                  <ChevronRight className="w-4 h-4 ml-2" />
                </Button>
              </Link>
            ) : (
              <a href={getLoginUrl()}>
                <Button variant="outline" className="font-display tracking-wider border-2 border-white hover:bg-white hover:text-black">
                  LOGIN
                </Button>
              </a>
            )}
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        <div className="container">
          <div className="max-w-4xl">
            <h1 className="text-7xl md:text-9xl font-display leading-none tracking-tight mb-8">
              COMMAND
              <br />
              <span className="text-primary">CENTER</span>
            </h1>
            
            {/* Red Divider */}
            <div className="w-full h-1 bg-primary my-8" />
            
            <p className="text-xl md:text-2xl text-muted-foreground max-w-2xl mb-12 leading-relaxed">
              Centralized management interface for MITRE Caldera adversary emulation platform. 
              Monitor server health, manage credentials, and orchestrate red team operations.
            </p>

            <div className="flex flex-wrap gap-4">
              {isAuthenticated ? (
                <Link href="/dashboard">
                  <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-8 py-6 text-lg">
                    ENTER DASHBOARD
                    <Zap className="w-5 h-5 ml-2" />
                  </Button>
                </Link>
              ) : (
                <a href={getLoginUrl()}>
                  <Button size="lg" className="font-display tracking-wider bg-primary hover:bg-primary/90 text-white px-8 py-6 text-lg">
                    GET STARTED
                    <ChevronRight className="w-5 h-5 ml-2" />
                  </Button>
                </a>
              )}
              <a href="https://137.184.7.224" target="_blank" rel="noopener noreferrer">
                <Button size="lg" variant="outline" className="font-display tracking-wider border-2 border-white hover:bg-white hover:text-black px-8 py-6 text-lg">
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

      {/* Red Divider Full Width */}
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
              icon={<Shield className="w-8 h-8" />}
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
              icon={<Shield className="w-8 h-8" />}
              title="THREAT BROWSER"
              description="Browse 156+ MITRE ATT&CK threat group profiles and APT29 VCD campaigns."
            />
          </div>
        </div>
      </section>

      {/* Red Divider Full Width */}
      <div className="w-full h-1 bg-primary" />

      {/* Stats Section */}
      <section className="py-20 bg-card">
        <div className="container">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
            <StatBlock value="156+" label="THREAT GROUPS" />
            <StatBlock value="1,940+" label="ABILITIES" />
            <StatBlock value="46" label="APT29 TTPS" />
            <StatBlock value="24/7" label="MONITORING" />
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 border-t border-border">
        <div className="container flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            <span className="font-display tracking-wider">CALDERA DASHBOARD</span>
          </div>
          <p className="text-sm text-muted-foreground">
            MITRE Caldera Server Management Interface
          </p>
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
