import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
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
  Plus,
  Play,
  Pause,
  CheckCircle,
  Clock,
  Crosshair,
  ChevronRight,
  Zap
} from "lucide-react";
import { useState, useEffect } from "react";

const STATUS_STYLES: Record<string, { bg: string; text: string; icon: React.ReactNode }> = {
  draft: { bg: 'bg-gray-500/20 border-gray-500', text: 'text-gray-400', icon: <FileText className="w-4 h-4" /> },
  ready: { bg: 'bg-blue-500/20 border-blue-500', text: 'text-blue-400', icon: <CheckCircle className="w-4 h-4" /> },
  active: { bg: 'bg-green-500/20 border-green-500', text: 'text-green-400', icon: <Play className="w-4 h-4" /> },
  paused: { bg: 'bg-yellow-500/20 border-yellow-500', text: 'text-yellow-400', icon: <Pause className="w-4 h-4" /> },
  completed: { bg: 'bg-primary/20 border-primary', text: 'text-primary', icon: <CheckCircle className="w-4 h-4" /> },
};

export default function Campaigns() {
  const { user, logout, isAuthenticated, loading: authLoading } = useAuth();
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);

  const { data: campaigns, isLoading, refetch } = trpc.campaign.list.useQuery();
  const createCampaign = trpc.campaign.create.useMutation({
    onSuccess: (data) => {
      toast.success('Campaign created successfully');
      setShowCreateModal(false);
      refetch();
      navigate(`/campaigns/${data.id}`);
    },
    onError: (error) => {
      toast.error(`Failed to create campaign: ${error.message}`);
    },
  });

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate('/');
    }
  }, [authLoading, isAuthenticated, navigate]);

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  const handleCreateCampaign = (data: { name: string; description: string; targetEnvironment: string }) => {
    createCampaign.mutate(data);
  };

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
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" />
            <NavItem href="/campaigns" icon={<Crosshair />} label="CAMPAIGNS" active />
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
          <div className="px-6 py-4 flex items-center justify-between">
            <div>
              <h1 className="font-display text-3xl md:text-4xl">CAMPAIGNS</h1>
              <p className="text-sm text-muted-foreground">Red team exercise campaigns and operations</p>
            </div>
            <Button 
              className="font-display tracking-wider bg-primary hover:bg-primary/90"
              onClick={() => setShowCreateModal(true)}
            >
              <Plus className="w-4 h-4 mr-2" />
              NEW CAMPAIGN
            </Button>
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="w-8 h-8 border-2 border-primary border-t-transparent animate-spin" />
            </div>
          ) : campaigns && campaigns.length > 0 ? (
            <div className="grid gap-4">
              {campaigns.map((campaign) => {
                const statusStyle = STATUS_STYLES[campaign.status] || STATUS_STYLES.draft;
                return (
                  <Link key={campaign.id} href={`/campaigns/${campaign.id}`}>
                    <div className="bg-card border-2 border-border hover:border-primary transition-colors p-6 cursor-pointer">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-3 mb-2">
                            <Crosshair className="w-5 h-5 text-primary" />
                            <h3 className="font-display text-xl truncate">{campaign.name}</h3>
                            <span className={`px-2 py-1 text-xs font-display border ${statusStyle.bg} ${statusStyle.text} flex items-center gap-1`}>
                              {statusStyle.icon}
                              {campaign.status.toUpperCase()}
                            </span>
                          </div>
                          {campaign.description && (
                            <p className="text-sm text-muted-foreground mb-3 line-clamp-2">{campaign.description}</p>
                          )}
                          <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                            {campaign.adversaryName && (
                              <span className="flex items-center gap-1">
                                <Target className="w-3 h-3" />
                                {campaign.adversaryName}
                              </span>
                            )}
                            {campaign.targetEnvironment && (
                              <span className="flex items-center gap-1">
                                <Zap className="w-3 h-3" />
                                {campaign.targetEnvironment}
                              </span>
                            )}
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {new Date(campaign.createdAt).toLocaleDateString()}
                            </span>
                          </div>
                        </div>
                        <ChevronRight className="w-5 h-5 text-muted-foreground" />
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-12 bg-card border-2 border-border">
              <Crosshair className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="font-display text-xl mb-2">NO CAMPAIGNS YET</h3>
              <p className="text-muted-foreground mb-6">Create your first red team campaign to get started</p>
              <Button 
                className="font-display tracking-wider bg-primary hover:bg-primary/90"
                onClick={() => setShowCreateModal(true)}
              >
                <Plus className="w-4 h-4 mr-2" />
                CREATE CAMPAIGN
              </Button>
            </div>
          )}
        </div>
      </main>

      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/50 z-40 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      {/* Create Campaign Modal */}
      {showCreateModal && (
        <CreateCampaignModal 
          onClose={() => setShowCreateModal(false)} 
          onCreate={handleCreateCampaign}
          isLoading={createCampaign.isPending}
        />
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

function CreateCampaignModal({ 
  onClose, 
  onCreate,
  isLoading 
}: { 
  onClose: () => void; 
  onCreate: (data: { name: string; description: string; targetEnvironment: string }) => void;
  isLoading: boolean;
}) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [targetEnvironment, setTargetEnvironment] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      toast.error('Campaign name is required');
      return;
    }
    onCreate({ name, description, targetEnvironment });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/80" onClick={onClose} />
      <div className="relative bg-card border-2 border-border w-full max-w-lg">
        <div className="p-6 border-b border-border">
          <h2 className="font-display text-2xl">CREATE CAMPAIGN</h2>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
              CAMPAIGN NAME *
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-secondary border-2 border-border px-4 py-3 font-display focus:border-primary outline-none"
              placeholder="e.g., Databank Red Team Exercise"
            />
          </div>
          <div>
            <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
              DESCRIPTION
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full bg-secondary border-2 border-border px-4 py-3 font-display focus:border-primary outline-none resize-none h-24"
              placeholder="Describe the campaign objectives..."
            />
          </div>
          <div>
            <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
              TARGET ENVIRONMENT
            </label>
            <input
              type="text"
              value={targetEnvironment}
              onChange={(e) => setTargetEnvironment(e.target.value)}
              className="w-full bg-secondary border-2 border-border px-4 py-3 font-display focus:border-primary outline-none"
              placeholder="e.g., VMware Cloud Director (VCD)"
            />
          </div>
          <div className="flex gap-4 pt-4">
            <Button 
              type="button" 
              variant="outline" 
              className="flex-1 font-display tracking-wider"
              onClick={onClose}
            >
              CANCEL
            </Button>
            <Button 
              type="submit" 
              className="flex-1 font-display tracking-wider bg-primary hover:bg-primary/90"
              disabled={isLoading}
            >
              {isLoading ? 'CREATING...' : 'CREATE'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
