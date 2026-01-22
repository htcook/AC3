import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Link, useLocation } from "wouter";
import { 
  Cloud, 
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
  Filter,
  RefreshCw,
  Cpu
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import { useState, useEffect, useMemo } from "react";

// DigitalOcean Caldera Server config
const CALDERA_API = {
  url: 'http://137.184.7.224:8888',
  apiKey: 'ADMIN123',
};

interface Adversary {
  adversary_id: string;
  name: string;
  description: string;
  atomic_ordering: string[];
  tags?: string[];
}

export default function Adversaries() {
  const { user, logout, isAuthenticated, loading: authLoading } = useAuth();
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTag, setSelectedTag] = useState<string | null>(null);
  const [adversaries, setAdversaries] = useState<Adversary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate('/');
    }
  }, [authLoading, isAuthenticated, navigate]);

  // Fetch adversaries from DigitalOcean Caldera API
  useEffect(() => {
    const fetchAdversaries = async () => {
      try {
        const response = await fetch(`${CALDERA_API.url}/api/v2/adversaries`, {
          headers: { 'KEY': CALDERA_API.apiKey },
        });
        if (response.ok) {
          const data = await response.json();
          setAdversaries(Array.isArray(data) ? data : []);
        }
      } catch (error) {
        console.error('Failed to fetch adversaries:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchAdversaries();
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  // Derive tags from adversary names
  const allTags = useMemo(() => {
    const tags = new Set<string>();
    adversaries.forEach(a => {
      if (a.name.includes('APT')) tags.add('APT');
      if (a.name.includes('FIN')) tags.add('Financial');
      if (a.name.includes('VCD') || a.name.includes('Cloud')) tags.add('Cloud');
      if (a.name.toLowerCase().includes('russia') || a.name.includes('Turla') || a.name.includes('Sandworm')) tags.add('Russia');
      if (a.name.toLowerCase().includes('china') || a.name.includes('Volt')) tags.add('China');
      if (a.name.toLowerCase().includes('iran') || a.name.includes('MuddyWater')) tags.add('Iran');
      if (a.name.toLowerCase().includes('dprk') || a.name.includes('Lazarus') || a.name.includes('Kimsuky')) tags.add('DPRK');
    });
    return Array.from(tags).sort();
  }, [adversaries]);

  // Filter adversaries
  const filteredAdversaries = useMemo(() => {
    return adversaries.filter(a => {
      const matchesSearch = searchQuery === '' || 
        a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (a.description || '').toLowerCase().includes(searchQuery.toLowerCase());
      
      if (!selectedTag) return matchesSearch;
      
      // Tag matching logic
      const name = a.name.toLowerCase();
      if (selectedTag === 'APT' && name.includes('apt')) return matchesSearch;
      if (selectedTag === 'Financial' && name.includes('fin')) return matchesSearch;
      if (selectedTag === 'Cloud' && (name.includes('vcd') || name.includes('cloud'))) return matchesSearch;
      if (selectedTag === 'Russia' && (name.includes('turla') || name.includes('sandworm') || name.includes('apt28') || name.includes('apt29'))) return matchesSearch;
      if (selectedTag === 'China' && (name.includes('apt41') || name.includes('volt'))) return matchesSearch;
      if (selectedTag === 'Iran' && (name.includes('apt33') || name.includes('muddywater'))) return matchesSearch;
      if (selectedTag === 'DPRK' && (name.includes('lazarus') || name.includes('kimsuky'))) return matchesSearch;
      
      return false;
    });
  }, [adversaries, searchQuery, selectedTag]);

  // Featured adversaries (APT29 VCD campaigns)
  const featuredAdversaries = filteredAdversaries.filter(a => 
    a.name.includes('APT29') && a.name.includes('VCD')
  );
  const otherAdversaries = filteredAdversaries.filter(a => 
    !(a.name.includes('APT29') && a.name.includes('VCD'))
  );

  if (authLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <RefreshCw className="w-8 h-8 animate-spin text-primary" />
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
              <Cloud className="w-8 h-8 text-primary" />
              <div className="flex flex-col">
                <span className="font-display text-xl tracking-wider">ACE OF CLOUD</span>
                <span className="text-xs text-muted-foreground">Caldera Command</span>
              </div>
            </Link>
          </div>

          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity />} label="DASHBOARD" />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" active />
            <NavItem href="/agents" icon={<Cpu />} label="AGENTS" />
            <NavItem href="/campaigns" icon={<Zap />} label="CAMPAIGNS" />
            <NavItem href="/team" icon={<Users />} label="TEAM" />
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
            <p className="text-sm text-muted-foreground">
              {loading ? 'Loading...' : `${adversaries.length} threat group profiles from DigitalOcean Caldera`}
            </p>
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
                className="pl-10 font-mono bg-card border-2 border-border focus:border-primary"
              />
            </div>
            <div className="flex gap-2 flex-wrap">
              <Button
                variant={selectedTag === null ? "default" : "outline"}
                size="sm"
                className="font-display tracking-wider"
                onClick={() => setSelectedTag(null)}
              >
                ALL
              </Button>
              {allTags.map(tag => (
                <Button
                  key={tag}
                  variant={selectedTag === tag ? "default" : "outline"}
                  size="sm"
                  className="font-display tracking-wider"
                  onClick={() => setSelectedTag(tag)}
                >
                  {tag.toUpperCase()}
                </Button>
              ))}
            </div>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-20">
              <RefreshCw className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : (
            <>
              {/* Featured Adversaries */}
              {featuredAdversaries.length > 0 && (
                <section>
                  <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
                    <Zap className="w-6 h-6 text-primary" />
                    FEATURED CAMPAIGNS
                  </h2>
                  <div className="grid md:grid-cols-2 gap-4">
                    {featuredAdversaries.map(adversary => (
                      <AdversaryCard key={adversary.adversary_id} adversary={adversary} featured />
                    ))}
                  </div>
                </section>
              )}

              {featuredAdversaries.length > 0 && otherAdversaries.length > 0 && (
                <div className="w-full h-0.5 bg-primary" />
              )}

              {/* All Adversaries */}
              {otherAdversaries.length > 0 && (
                <section>
                  <h2 className="font-display text-2xl mb-4 flex items-center gap-2">
                    <Globe className="w-6 h-6 text-primary" />
                    ALL THREAT GROUPS ({otherAdversaries.length})
                  </h2>
                  <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {otherAdversaries.slice(0, 50).map(adversary => (
                      <AdversaryCard key={adversary.adversary_id} adversary={adversary} />
                    ))}
                  </div>
                  {otherAdversaries.length > 50 && (
                    <p className="text-center text-muted-foreground mt-4">
                      Showing 50 of {otherAdversaries.length} adversaries. Use search to find specific groups.
                    </p>
                  )}
                </section>
              )}

              {filteredAdversaries.length === 0 && (
                <div className="text-center py-20">
                  <Target className="w-16 h-16 mx-auto text-muted-foreground mb-4" />
                  <p className="text-xl font-display">NO ADVERSARIES FOUND</p>
                  <p className="text-muted-foreground">Try adjusting your search or filter</p>
                </div>
              )}
            </>
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

function AdversaryCard({ adversary, featured }: { adversary: Adversary; featured?: boolean }) {
  return (
    <Link href={`/adversaries/${adversary.adversary_id}`}>
      <div className={`bg-card border-2 ${featured ? 'border-primary' : 'border-border'} p-4 hover:border-primary transition-colors cursor-pointer group`}>
        <div className="flex items-start justify-between mb-2">
          <h3 className={`font-display ${featured ? 'text-lg' : 'text-base'} group-hover:text-primary transition-colors truncate flex-1`}>
            {adversary.name}
          </h3>
          <ChevronRight className="w-5 h-5 text-muted-foreground group-hover:text-primary transition-colors shrink-0" />
        </div>
        <p className="text-sm text-muted-foreground mb-3 line-clamp-2">
          {adversary.description || 'No description available'}
        </p>
        <div className="flex items-center gap-4 text-xs">
          <span className="flex items-center gap-1">
            <Zap className="w-3 h-3 text-primary" />
            {adversary.atomic_ordering?.length || 0} abilities
          </span>
          {featured && (
            <span className="bg-primary/20 text-primary px-2 py-0.5 font-display tracking-wider">
              FEATURED
            </span>
          )}
        </div>
      </div>
    </Link>
  );
}
