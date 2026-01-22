import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Link, useLocation } from "wouter";
import { 
  Shield, 
  Activity, 
  Key,
  Users,
  LogOut,
  Menu,
  X,
  Target,
  FileText,
  Search,
  ChevronRight,
  Zap,
  Globe,
  Filter
} from "lucide-react";
import { useState, useEffect, useMemo } from "react";

// Sample adversary data - in production this would come from the API
const ADVERSARIES = [
  { id: 'apt29-vcd-enhanced', name: 'APT29_VCD_Cloud_Compromise_Enhanced', description: 'Enhanced APT29 emulation for VMware Cloud Director', abilities: 46, featured: true, tags: ['APT29', 'Cloud', 'VCD'] },
  { id: 'apt29-vcd', name: 'APT29_VCD_Cloud_Compromise', description: 'APT29 emulation in VMware Cloud Director environment', abilities: 11, featured: true, tags: ['APT29', 'Cloud'] },
  { id: 'apt29', name: 'APT29 (Cozy Bear)', description: 'Russian state-sponsored threat group', abilities: 89, tags: ['Russia', 'APT'] },
  { id: 'apt28', name: 'APT28 (Fancy Bear)', description: 'Russian military intelligence threat group', abilities: 76, tags: ['Russia', 'APT'] },
  { id: 'apt41', name: 'APT41 (Double Dragon)', description: 'Chinese state-sponsored threat group', abilities: 65, tags: ['China', 'APT'] },
  { id: 'lazarus', name: 'Lazarus Group', description: 'North Korean state-sponsored threat group', abilities: 72, tags: ['DPRK', 'APT'] },
  { id: 'fin7', name: 'FIN7 (Carbanak)', description: 'Financially motivated cybercrime group', abilities: 58, tags: ['Cybercrime', 'Financial'] },
  { id: 'wizard-spider', name: 'Wizard Spider', description: 'Russian cybercrime group behind TrickBot and Ryuk', abilities: 45, tags: ['Russia', 'Ransomware'] },
  { id: 'sandworm', name: 'Sandworm Team', description: 'Russian military intelligence unit targeting Ukraine', abilities: 52, tags: ['Russia', 'ICS'] },
  { id: 'turla', name: 'Turla (Snake)', description: 'Russian FSB-attributed threat group', abilities: 61, tags: ['Russia', 'APT'] },
  { id: 'muddywater', name: 'MuddyWater', description: 'Iranian state-sponsored threat group', abilities: 38, tags: ['Iran', 'APT'] },
  { id: 'apt33', name: 'APT33 (Elfin)', description: 'Iranian state-sponsored threat group', abilities: 42, tags: ['Iran', 'APT'] },
  { id: 'kimsuky', name: 'Kimsuky', description: 'North Korean threat group targeting South Korea', abilities: 35, tags: ['DPRK', 'APT'] },
  { id: 'volt-typhoon', name: 'Volt Typhoon', description: 'Chinese state-sponsored group targeting US infrastructure', abilities: 28, tags: ['China', 'APT'] },
  { id: 'scattered-spider', name: 'Scattered Spider', description: 'Financially motivated threat group using social engineering', abilities: 22, tags: ['Cybercrime', 'Social Engineering'] },
];

export default function Adversaries() {
  const { user, logout, isAuthenticated, loading: authLoading } = useAuth();
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTag, setSelectedTag] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate('/');
    }
  }, [authLoading, isAuthenticated, navigate]);

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  // Get unique tags
  const allTags = useMemo(() => {
    const tags = new Set<string>();
    ADVERSARIES.forEach(a => a.tags.forEach(t => tags.add(t)));
    return Array.from(tags).sort();
  }, []);

  // Filter adversaries
  const filteredAdversaries = useMemo(() => {
    return ADVERSARIES.filter(a => {
      const matchesSearch = searchQuery === '' || 
        a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        a.description.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesTag = !selectedTag || a.tags.includes(selectedTag);
      return matchesSearch && matchesTag;
    });
  }, [searchQuery, selectedTag]);

  const featuredAdversaries = filteredAdversaries.filter(a => a.featured);
  const otherAdversaries = filteredAdversaries.filter(a => !a.featured);

  if (authLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-primary border-t-transparent animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-card border-r border-border transform transition-transform duration-200 lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex flex-col h-full">
          <div className="p-6 border-b border-border">
            <Link href="/" className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-primary" />
              <span className="font-display text-xl tracking-wider">CALDERA</span>
            </Link>
          </div>

          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity />} label="DASHBOARD" />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" active />
            <NavItem href="/team" icon={<Users />} label="TEAM" />
            <NavItem href="/activity" icon={<FileText />} label="ACTIVITY" />
          </nav>

          <div className="p-4 border-t border-border">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 bg-primary/20 flex items-center justify-center">
                <span className="font-display text-primary">{user?.name?.[0] || 'U'}</span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{user?.name || 'User'}</p>
                <p className="text-xs text-muted-foreground uppercase">{user?.role || 'viewer'}</p>
              </div>
            </div>
            <Button variant="outline" size="sm" className="w-full font-display tracking-wider" onClick={handleLogout}>
              <LogOut className="w-4 h-4 mr-2" />
              LOGOUT
            </Button>
          </div>
        </div>
      </aside>

      <button
        className="fixed top-4 left-4 z-50 lg:hidden p-2 bg-card border border-border"
        onClick={() => setSidebarOpen(!sidebarOpen)}
      >
        {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      <main className="flex-1 lg:ml-64">
        <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4">
            <h1 className="font-display text-3xl md:text-4xl">ADVERSARIES</h1>
            <p className="text-sm text-muted-foreground">MITRE ATT&CK threat group profiles and campaigns</p>
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">
          {/* Search and Filter */}
          <div className="flex flex-col md:flex-row gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                placeholder="Search adversaries..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 bg-card border-2 border-border font-mono"
              />
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setSelectedTag(null)}
                className={`px-3 py-2 text-xs font-display tracking-wider border-2 transition-colors ${!selectedTag ? 'bg-primary border-primary' : 'border-border hover:border-primary'}`}
              >
                ALL
              </button>
              {allTags.slice(0, 6).map(tag => (
                <button
                  key={tag}
                  onClick={() => setSelectedTag(selectedTag === tag ? null : tag)}
                  className={`px-3 py-2 text-xs font-display tracking-wider border-2 transition-colors ${selectedTag === tag ? 'bg-primary border-primary' : 'border-border hover:border-primary'}`}
                >
                  {tag.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Featured Campaigns */}
          {featuredAdversaries.length > 0 && (
            <section>
              <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
                <Zap className="w-6 h-6 text-primary" />
                FEATURED CAMPAIGNS
              </h2>
              <div className="grid md:grid-cols-2 gap-4">
                {featuredAdversaries.map(adversary => (
                  <Link key={adversary.id} href={`/adversaries/${adversary.id}`}>
                    <div className="bg-card border-2 border-primary p-6 hover:bg-primary/10 transition-colors cursor-pointer h-full">
                      <div className="flex items-start justify-between mb-4">
                        <h3 className="font-display text-xl text-primary">{adversary.name}</h3>
                        <span className="px-2 py-1 bg-primary/20 text-primary text-xs font-display">{adversary.abilities} TTPs</span>
                      </div>
                      <p className="text-muted-foreground mb-4">{adversary.description}</p>
                      <div className="flex flex-wrap gap-2">
                        {adversary.tags.map(tag => (
                          <span key={tag} className="px-2 py-1 bg-secondary text-xs">{tag}</span>
                        ))}
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            </section>
          )}

          <div className="w-full h-0.5 bg-primary" />

          {/* All Adversaries */}
          <section>
            <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
              <Globe className="w-6 h-6 text-primary" />
              THREAT GROUPS ({filteredAdversaries.length})
            </h2>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
              {otherAdversaries.map(adversary => (
                <Link key={adversary.id} href={`/adversaries/${adversary.id}`}>
                  <div className="bg-card border-2 border-border p-6 hover:border-primary transition-colors cursor-pointer h-full">
                    <div className="flex items-start justify-between mb-2">
                      <h3 className="font-display text-lg">{adversary.name}</h3>
                      <span className="px-2 py-1 bg-secondary text-xs">{adversary.abilities}</span>
                    </div>
                    <p className="text-sm text-muted-foreground mb-3">{adversary.description}</p>
                    <div className="flex flex-wrap gap-1">
                      {adversary.tags.map(tag => (
                        <span key={tag} className="px-2 py-0.5 bg-secondary/50 text-xs">{tag}</span>
                      ))}
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </section>

          {filteredAdversaries.length === 0 && (
            <div className="text-center py-12">
              <Target className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">No adversaries found matching your criteria</p>
            </div>
          )}
        </div>
      </main>

      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/50 z-40 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}
    </div>
  );
}

function NavItem({ href, icon, label, active }: { href: string; icon: React.ReactNode; label: string; active?: boolean }) {
  return (
    <Link href={href}>
      <div className={`flex items-center gap-3 px-4 py-3 font-display tracking-wider text-sm transition-colors ${active ? 'bg-primary/20 text-primary border-l-2 border-primary' : 'hover:bg-secondary'}`}>
        {icon}
        {label}
      </div>
    </Link>
  );
}
