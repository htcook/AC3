import { Button } from "@/components/ui/button";
import { Link, useLocation, useParams } from "wouter";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
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
  Plus,
  Play,
  Pause,
  CheckCircle,
  ChevronLeft,
  Crosshair,
  Zap,
  Trash2,
  Server,
  Code,
  ExternalLink,
  Cpu,
  Briefcase,
  FlaskConical,
  ShieldOff,
  Shield,
  Loader2,
  AlertTriangle,
  XCircle,
  BarChart3,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import { useState, useEffect, useMemo } from "react";

import AppShell from "@/components/AppShell";
// APT29 VCD Enhanced abilities for pre-population
const APT29_VCD_ABILITIES = [
  { abilityId: 'apt29-vcd-1', abilityName: 'Cloud Infrastructure Discovery', technique: 'T1580', tactic: 'Reconnaissance', description: 'Enumerate VCD API endpoints and version information' },
  { abilityId: 'apt29-vcd-2', abilityName: 'Gather Victim Identity - Credentials', technique: 'T1589.001', tactic: 'Reconnaissance', description: 'OSINT gathering for VCD admin credentials' },
  { abilityId: 'apt29-vcd-3', abilityName: 'IP Address Discovery', technique: 'T1590.004', tactic: 'Reconnaissance', description: 'Identify VCD management interfaces' },
  { abilityId: 'apt29-vcd-4', abilityName: 'Network Topology Discovery', technique: 'T1591.004', tactic: 'Reconnaissance', description: 'Map VCD organization structure' },
  { abilityId: 'apt29-vcd-5', abilityName: 'Spearphishing Link', technique: 'T1566.002', tactic: 'Initial Access', description: 'Phishing campaign targeting VCD administrators' },
  { abilityId: 'apt29-vcd-6', abilityName: 'Exploit Public-Facing Application', technique: 'T1190', tactic: 'Initial Access', description: 'CVE-2023-34060 VCD authentication bypass' },
  { abilityId: 'apt29-vcd-7', abilityName: 'Valid Cloud Accounts', technique: 'T1078.004', tactic: 'Initial Access', description: 'Use compromised VCD credentials' },
  { abilityId: 'apt29-vcd-8', abilityName: 'Trusted Relationship', technique: 'T1199', tactic: 'Initial Access', description: 'Abuse VCD provider-tenant trust' },
  { abilityId: 'apt29-vcd-9', abilityName: 'Cloud API Execution', technique: 'T1059.009', tactic: 'Execution', description: 'Execute commands via VCD REST API' },
  { abilityId: 'apt29-vcd-10', abilityName: 'PowerShell in vApp', technique: 'T1059.001', tactic: 'Execution', description: 'Execute PowerShell in deployed VMs' },
  { abilityId: 'apt29-vcd-11', abilityName: 'Native API', technique: 'T1106', tactic: 'Execution', description: 'Direct VCD API calls for VM manipulation' },
  { abilityId: 'apt29-vcd-12', abilityName: 'Additional Cloud Credentials', technique: 'T1098.001', tactic: 'Persistence', description: 'Create backdoor VCD admin account' },
  { abilityId: 'apt29-vcd-13', abilityName: 'Create Cloud Account', technique: 'T1136.003', tactic: 'Persistence', description: 'Add service account with elevated privileges' },
  { abilityId: 'apt29-vcd-14', abilityName: 'Event Triggered Execution', technique: 'T1546', tactic: 'Persistence', description: 'VCD event subscription for persistence' },
  { abilityId: 'apt29-vcd-15', abilityName: 'Valid Cloud Accounts Persistence', technique: 'T1078.004', tactic: 'Persistence', description: 'Maintain access via legitimate credentials' },
  { abilityId: 'apt29-vcd-16', abilityName: 'Abuse Elevation Control', technique: 'T1548', tactic: 'Privilege Escalation', description: 'Escalate to VCD System Organization' },
  { abilityId: 'apt29-vcd-17', abilityName: 'Provider Admin Escalation', technique: 'T1078.004', tactic: 'Privilege Escalation', description: 'Elevate to provider administrator role' },
  { abilityId: 'apt29-vcd-18', abilityName: 'Access Token Manipulation', technique: 'T1134', tactic: 'Privilege Escalation', description: 'Forge VCD API tokens' },
  { abilityId: 'apt29-vcd-19', abilityName: 'Disable Audit Logging', technique: 'T1562.001', tactic: 'Defense Evasion', description: 'Disable VCD audit and event logging' },
  { abilityId: 'apt29-vcd-20', abilityName: 'Clear Event Logs', technique: 'T1070.001', tactic: 'Defense Evasion', description: 'Remove VCD event history' },
  { abilityId: 'apt29-vcd-21', abilityName: 'Timestomping', technique: 'T1070.006', tactic: 'Defense Evasion', description: 'Modify VCD object timestamps' },
  { abilityId: 'apt29-vcd-22', abilityName: 'Application Access Token', technique: 'T1550.001', tactic: 'Defense Evasion', description: 'Use stolen API tokens' },
  { abilityId: 'apt29-vcd-23', abilityName: 'Credentials in Files', technique: 'T1552.001', tactic: 'Credential Access', description: 'Extract VCD configuration files' },
  { abilityId: 'apt29-vcd-24', abilityName: 'Private Keys', technique: 'T1552.004', tactic: 'Credential Access', description: 'Extract SSL/TLS private keys' },
  { abilityId: 'apt29-vcd-25', abilityName: 'Password Spraying', technique: 'T1110.003', tactic: 'Credential Access', description: 'Spray common passwords against VCD' },
  { abilityId: 'apt29-vcd-26', abilityName: 'SAML Token Forgery', technique: 'T1606.002', tactic: 'Credential Access', description: 'Golden SAML attack on VCD SSO' },
  { abilityId: 'apt29-vcd-27', abilityName: 'Cloud Account Discovery', technique: 'T1087.004', tactic: 'Discovery', description: 'Enumerate VCD organizations and users' },
  { abilityId: 'apt29-vcd-28', abilityName: 'Cloud Infrastructure Discovery', technique: 'T1580', tactic: 'Discovery', description: 'Map VCD vApps and VMs' },
  { abilityId: 'apt29-vcd-29', abilityName: 'Cloud Service Discovery', technique: 'T1526', tactic: 'Discovery', description: 'Identify VCD services and capabilities' },
  { abilityId: 'apt29-vcd-30', abilityName: 'Cloud Service Dashboard', technique: 'T1538', tactic: 'Discovery', description: 'Access VCD management console' },
  { abilityId: 'apt29-vcd-31', abilityName: 'Domain Trust Discovery', technique: 'T1482', tactic: 'Discovery', description: 'Map VCD federation trusts' },
  { abilityId: 'apt29-vcd-32', abilityName: 'Remote Desktop Protocol', technique: 'T1021.001', tactic: 'Lateral Movement', description: 'RDP to VCD-hosted VMs' },
  { abilityId: 'apt29-vcd-33', abilityName: 'API Token Abuse', technique: 'T1550.001', tactic: 'Lateral Movement', description: 'Pivot using VCD API tokens' },
  { abilityId: 'apt29-vcd-34', abilityName: 'Cross-Org Movement', technique: 'T1021', tactic: 'Lateral Movement', description: 'Move between VCD organizations' },
  { abilityId: 'apt29-vcd-35', abilityName: 'Archive via Utility', technique: 'T1560.001', tactic: 'Collection', description: 'Compress VCD configuration data' },
  { abilityId: 'apt29-vcd-36', abilityName: 'Data from Cloud Storage', technique: 'T1530', tactic: 'Collection', description: 'Access VCD catalog and storage' },
  { abilityId: 'apt29-vcd-37', abilityName: 'Data from Information Repositories', technique: 'T1213', tactic: 'Collection', description: 'Export vApp templates' },
  { abilityId: 'apt29-vcd-38', abilityName: 'Remote Data Staging', technique: 'T1074.002', tactic: 'Collection', description: 'Stage data in VCD storage' },
  { abilityId: 'apt29-vcd-39', abilityName: 'Web Protocols', technique: 'T1071.001', tactic: 'Command and Control', description: 'HTTPS C2 beacon' },
  { abilityId: 'apt29-vcd-40', abilityName: 'Dynamic Resolution', technique: 'T1568', tactic: 'Command and Control', description: 'DNS-based C2 resolution' },
  { abilityId: 'apt29-vcd-41', abilityName: 'Web Service', technique: 'T1102', tactic: 'Command and Control', description: 'Use legitimate cloud services for C2' },
  { abilityId: 'apt29-vcd-42', abilityName: 'Exfiltration Over C2', technique: 'T1041', tactic: 'Exfiltration', description: 'Exfiltrate via HTTPS C2 channel' },
  { abilityId: 'apt29-vcd-43', abilityName: 'Exfiltration Over Asymmetric Encrypted', technique: 'T1048.002', tactic: 'Exfiltration', description: 'Encrypted data exfiltration' },
  { abilityId: 'apt29-vcd-44', abilityName: 'Exfiltration to Cloud Storage', technique: 'T1567.002', tactic: 'Exfiltration', description: 'Upload to attacker cloud storage' },
  { abilityId: 'apt29-vcd-45', abilityName: 'Data Destruction', technique: 'T1485', tactic: 'Impact', description: 'Delete VCD resources (optional)' },
  { abilityId: 'apt29-vcd-46', abilityName: 'Service Stop', technique: 'T1489', tactic: 'Impact', description: 'Disrupt VCD services (optional)' },
];

const STATUS_STYLES: Record<string, { bg: string; text: string }> = {
  draft: { bg: 'bg-gray-500/20 border-gray-500', text: 'text-gray-400' },
  ready: { bg: 'bg-blue-500/20 border-blue-500', text: 'text-blue-400' },
  active: { bg: 'bg-green-500/20 border-green-500', text: 'text-green-400' },
  paused: { bg: 'bg-yellow-500/20 border-yellow-500', text: 'text-yellow-400' },
  completed: { bg: 'bg-primary/20 border-primary', text: 'text-primary' },
};

const ABILITY_STATUS_STYLES: Record<string, { bg: string; text: string }> = {
  pending: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  running: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  completed: { bg: 'bg-green-500/20', text: 'text-green-400' },
  failed: { bg: 'bg-red-500/20', text: 'text-red-400' },
  skipped: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
};

export default function CampaignDetail() {
  const [, navigate] = useLocation();
  const params = useParams<{ id: string }>();
  const [showAddAgentModal, setShowAddAgentModal] = useState(false);
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [showMutationTest, setShowMutationTest] = useState(false);
  const [mutationSigmaYaml, setMutationSigmaYaml] = useState('');
  const [mutationCommand, setMutationCommand] = useState('');
  const [siemCorrelation, setSiemCorrelation] = useState<any>(null);

  const campaignId = parseInt(params.id || '0');
  const { data: campaign, isLoading, refetch } = trpc.campaign.get.useQuery(
    { id: campaignId },
    { enabled: campaignId > 0 }
  );

  const updateCampaign = trpc.campaign.update.useMutation({
    onSuccess: () => {
      toast.success('Campaign updated');
      refetch();
    },
  });

  const addAgent = trpc.campaign.addAgent.useMutation({
    onSuccess: () => {
      toast.success('Agent added');
      setShowAddAgentModal(false);
      refetch();
    },
  });

  const removeAgent = trpc.campaign.removeAgent.useMutation({
    onSuccess: () => {
      toast.success('Agent removed');
      refetch();
    },
  });

  const addAbilities = trpc.campaign.addAbilities.useMutation({
    onSuccess: () => {
      toast.success('Abilities added');
      refetch();
    },
  });

  const removeAbility = trpc.campaign.removeAbility.useMutation({
    onSuccess: () => {
      toast.success('Ability removed');
      refetch();
    },
  });

  const handleStatusChange = (status: string) => {
    updateCampaign.mutate({ id: campaignId, status: status as any });
  };

  // ── Mutation Test ──────────────────────────────────────────────────
  const runMutationTest = trpc.evasionEngine.testSigmaRule.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Mutation test complete — robustness ${data.robustnessScore}%`);
    },
    onError: (err: any) => toast.error(`Mutation test failed: ${err.message}`),
  });

  const runBatchMutation = trpc.evasionEngine.batchTest.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Batch test complete — ${data.summary.totalTests} rules tested`);
    },
    onError: (err: any) => toast.error(`Batch test failed: ${err.message}`),
  });

  // ── SIEM Correlation ─────────────────────────────────────────────
  const correlateDetections = trpc.siemConnectors.correlateWithCampaign.useMutation({
    onSuccess: (data: any) => {
      setSiemCorrelation(data);
      toast.success(`SIEM correlation complete — ${data.stats.coveragePercent}% detection coverage`);
    },
    onError: (err: any) => toast.error(`SIEM correlation failed: ${err.message}`),
  });

  const campaignTechniques = useMemo(() => {
    return campaign?.abilities?.map((a: any) => a.technique).filter(Boolean) || [];
  }, [campaign?.abilities]);

  const handleRunMutationTest = () => {
    if (!mutationCommand.trim()) {
      toast.error('Enter a command to test');
      return;
    }
    if (!mutationSigmaYaml.trim()) {
      toast.error('Enter Sigma rule YAML');
      return;
    }
    runMutationTest.mutate({ command: mutationCommand, sigmaYaml: mutationSigmaYaml });
  };

  const handleCorrelateWithSiem = () => {
    const techs = campaignTechniques;
    if (techs.length === 0) {
      toast.error('No techniques in this campaign to correlate');
      return;
    }
    correlateDetections.mutate({ techniques: techs });
  };

  const handleLoadAPT29Abilities = () => {
    addAbilities.mutate({
      campaignId,
      abilities: APT29_VCD_ABILITIES.map((a, i) => ({ ...a, executionOrder: i })),
    });
    updateCampaign.mutate({
      id: campaignId,
      adversaryId: 'apt29-vcd-enhanced',
      adversaryName: 'APT29_VCD_Cloud_Compromise_Enhanced',
    });
  };

  const handleAddAgent = (data: { agentName: string; platform: string; hostname: string }) => {
    addAgent.mutate({ campaignId, ...data });
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-primary border-t-transparent animate-spin" />
      </div>
    );
  }

  if (!campaign) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <h2 className="font-display text-2xl mb-4">CAMPAIGN NOT FOUND</h2>
          <Link href="/campaigns">
            <Button variant="outline" className="font-display">BACK TO CAMPAIGNS</Button>
          </Link>
        </div>
      </div>
    );
  }

  const statusStyle = STATUS_STYLES[campaign.status] || STATUS_STYLES.draft;
  const tactics = Array.from(new Set(campaign.abilities?.map((a: any) => a.tactic).filter(Boolean))) as string[];
  const filteredAbilities = selectedTactic
    ? campaign.abilities?.filter((a: any) => a.tactic === selectedTactic)
    : campaign.abilities;

  return (
    <AppShell activePath="/campaigns">
{/* Sidebar */}
<header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4">
            <Link href="/campaigns" className="inline-flex items-center gap-2 text-muted-foreground hover:text-white mb-2">
              <ChevronLeft className="w-4 h-4" />
              <span className="text-sm">Back to Campaigns</span>
            </Link>
            <div className="flex items-center gap-4">
              <h1 className="font-display text-3xl md:text-2xl sm:text-3xl lg:text-4xl">{campaign.name}</h1>
              <span className={`px-3 py-1 text-xs font-display border ${statusStyle.bg} ${statusStyle.text}`}>
                {campaign.status.toUpperCase()}
              </span>
            </div>
          </div>
          <div className="w-full h-1 bg-primary" />
        </header>

        <div className="p-6 space-y-8">
          {/* Campaign Overview */}
          <section className="bg-card border-2 border-border p-6">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h3 className="font-display text-lg mb-2 text-muted-foreground">DESCRIPTION</h3>
                <p>{campaign.description || 'No description provided'}</p>
              </div>
              <div>
                <h3 className="font-display text-lg mb-2 text-muted-foreground">TARGET ENVIRONMENT</h3>
                <p>{campaign.targetEnvironment || 'Not specified'}</p>
              </div>
            </div>
            <div className="mt-6 pt-6 border-t border-border flex flex-wrap gap-4">
              <div>
                <span className="text-xs text-muted-foreground">ADVERSARY</span>
                <p className="font-display">{campaign.adversaryName || 'Not selected'}</p>
              </div>
              <div>
                <span className="text-xs text-muted-foreground">AGENTS</span>
                <p className="font-display">{campaign.agents?.length || 0}</p>
              </div>
              <div>
                <span className="text-xs text-muted-foreground">ABILITIES</span>
                <p className="font-display">{campaign.abilities?.length || 0}</p>
              </div>
            </div>
            <div className="mt-6 flex flex-wrap gap-2">
              <Button
                variant={campaign.status === 'draft' ? 'default' : 'outline'}
                size="sm"
                className="font-display"
                onClick={() => handleStatusChange('draft')}
              >
                DRAFT
              </Button>
              <Button
                variant={campaign.status === 'ready' ? 'default' : 'outline'}
                size="sm"
                className="font-display"
                onClick={() => handleStatusChange('ready')}
              >
                READY
              </Button>
              <Button
                variant={campaign.status === 'active' ? 'default' : 'outline'}
                size="sm"
                className="font-display"
                onClick={() => handleStatusChange('active')}
              >
                <Play className="w-3 h-3 mr-1" />
                ACTIVE
              </Button>
              <Button
                variant={campaign.status === 'paused' ? 'default' : 'outline'}
                size="sm"
                className="font-display"
                onClick={() => handleStatusChange('paused')}
              >
                <Pause className="w-3 h-3 mr-1" />
                PAUSED
              </Button>
              <Button
                variant={campaign.status === 'completed' ? 'default' : 'outline'}
                size="sm"
                className="font-display"
                onClick={() => handleStatusChange('completed')}
              >
                <CheckCircle className="w-3 h-3 mr-1" />
                COMPLETED
              </Button>
            </div>
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* Agents Section */}
          <section>
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-display text-2xl flex items-center gap-2">
                <Server className="w-6 h-6 text-primary" />
                AGENTS ({campaign.agents?.length || 0})
              </h2>
              <Button 
                variant="outline" 
                size="sm" 
                className="font-display"
                onClick={() => setShowAddAgentModal(true)}
              >
                <Plus className="w-4 h-4 mr-2" />
                ADD AGENT
              </Button>
            </div>
            {campaign.agents && campaign.agents.length > 0 ? (
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                {campaign.agents.map((agent: any) => (
                  <div key={agent.id} className="bg-card border-2 border-border p-4">
                    <div className="flex items-start justify-between">
                      <div>
                        <h4 className="font-display">{agent.agentName}</h4>
                        <p className="text-xs text-muted-foreground">{agent.platform || 'Unknown'} • {agent.hostname || 'N/A'}</p>
                      </div>
                      <button 
                        onClick={() => removeAgent.mutate({ id: agent.id })}
                        className="text-muted-foreground hover:text-red-500"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="bg-card border-2 border-border p-6 text-center">
                <Server className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-muted-foreground">No agents assigned</p>
              </div>
            )}
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* Abilities Section */}
          <section>
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-display text-2xl flex items-center gap-2">
                <Code className="w-6 h-6 text-primary" />
                ABILITIES ({campaign.abilities?.length || 0})
              </h2>
              {(!campaign.abilities || campaign.abilities.length === 0) && (
                <Button 
                  className="font-display bg-primary hover:bg-primary/90"
                  onClick={handleLoadAPT29Abilities}
                  disabled={addAbilities.isPending}
                >
                  <Zap className="w-4 h-4 mr-2" />
                  LOAD APT29-VCD ENHANCED
                </Button>
              )}
            </div>

            {campaign.abilities && campaign.abilities.length > 0 && (
              <>
                {/* Tactic Filter */}
                <div className="flex flex-wrap gap-2 mb-4">
                  <button
                    onClick={() => setSelectedTactic(null)}
                    className={`px-3 py-2 text-xs font-display tracking-wider border-2 transition-colors ${!selectedTactic ? 'bg-primary border-primary' : 'border-border hover:border-primary'}`}
                  >
                    ALL
                  </button>
                  {tactics.map((tactic) => (
                    <button
                      key={tactic}
                      onClick={() => setSelectedTactic(selectedTactic === tactic ? null : tactic)}
                      className={`px-3 py-2 text-xs font-display tracking-wider border-2 transition-colors ${selectedTactic === tactic ? 'bg-primary border-primary' : 'border-border hover:border-primary'}`}
                    >
                      {tactic.toUpperCase()}
                    </button>
                  ))}
                </div>

                <div className="bg-card border-2 border-border overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-border bg-secondary/50">
                          <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground w-12">#</th>
                          <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">TECHNIQUE</th>
                          <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">TACTIC</th>
                          <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">NAME</th>
                          <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground">STATUS</th>
                          <th className="px-4 py-3 text-left text-xs font-display tracking-wider text-muted-foreground w-12"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredAbilities?.map((ability: any, index: number) => {
                          const abilityStatus = ABILITY_STATUS_STYLES[ability.status] || ABILITY_STATUS_STYLES.pending;
                          return (
                            <tr key={ability.id} className={`border-b border-border/50 hover:bg-secondary/30 ${index % 2 === 0 ? '' : 'bg-secondary/10'}`}>
                              <td className="px-4 py-3 text-muted-foreground">{ability.executionOrder + 1}</td>
                              <td className="px-4 py-3">
                                <a 
                                  href={`https://attack.mitre.org/techniques/${ability.technique?.replace('.', '/')}/`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="font-mono text-primary hover:underline"
                                >
                                  {ability.technique}
                                </a>
                              </td>
                              <td className="px-4 py-3">
                                <span className="px-2 py-1 bg-secondary text-xs">{ability.tactic}</span>
                              </td>
                              <td className="px-4 py-3 font-medium">{ability.abilityName}</td>
                              <td className="px-4 py-3">
                                <span className={`px-2 py-1 text-xs ${abilityStatus.bg} ${abilityStatus.text}`}>
                                  {(ability.status || 'pending').toUpperCase()}
                                </span>
                              </td>
                              <td className="px-4 py-3">
                                <button 
                                  onClick={() => removeAbility.mutate({ id: ability.id })}
                                  className="text-muted-foreground hover:text-red-500"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            )}

            {(!campaign.abilities || campaign.abilities.length === 0) && (
              <div className="bg-card border-2 border-border p-6 text-center">
                <Code className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-muted-foreground mb-4">No abilities loaded</p>
                <p className="text-sm text-muted-foreground">
                  Click "Load APT29-VCD Enhanced" to populate with 46 abilities for VMware Cloud Director environments
                </p>
              </div>
            )}
          </section>

          <div className="w-full h-0.5 bg-primary" />

          {/* ═══════════════════════════════════════════════════════════════ */}
          {/* MUTATION TEST & SIEM CORRELATION SECTION                      */}
          {/* ═══════════════════════════════════════════════════════════════ */}
          <section>
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-display text-2xl flex items-center gap-2">
                <FlaskConical className="w-6 h-6 text-primary" />
                EVASION TESTING
              </h2>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="font-display"
                  onClick={() => setShowMutationTest(!showMutationTest)}
                >
                  <FlaskConical className="w-4 h-4 mr-2" />
                  RUN MUTATION TEST
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="font-display"
                  onClick={handleCorrelateWithSiem}
                  disabled={correlateDetections.isPending || campaignTechniques.length === 0}
                >
                  {correlateDetections.isPending ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Shield className="w-4 h-4 mr-2" />
                  )}
                  SIEM CORRELATION
                </Button>
              </div>
            </div>

            {/* Mutation Test Panel */}
            {showMutationTest && (
              <div className="bg-card border-2 border-border p-6 mb-4">
                <h3 className="font-display text-lg mb-4 flex items-center gap-2">
                  <ShieldOff className="w-5 h-5 text-yellow-500" />
                  SIGMA RULE MUTATION TEST
                </h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Test a command against a Sigma rule to see how many mutation variants evade detection.
                  Use this before launching an engagement to validate your evasion posture.
                </p>
                <div className="grid md:grid-cols-2 gap-4 mb-4">
                  <div>
                    <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
                      COMMAND TO TEST
                    </label>
                    <Textarea
                      value={mutationCommand}
                      onChange={(e: any) => setMutationCommand(e.target.value)}
                      placeholder="e.g., powershell.exe -enc SQBFAFgAIAAoA..."
                      className="font-mono text-sm min-h-[100px] bg-secondary border-border"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
                      SIGMA RULE (YAML)
                    </label>
                    <Textarea
                      value={mutationSigmaYaml}
                      onChange={(e: any) => setMutationSigmaYaml(e.target.value)}
                      placeholder={`title: Suspicious PowerShell Execution\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - '-enc'\n      - '-encodedcommand'\n  condition: selection`}
                      className="font-mono text-sm min-h-[100px] bg-secondary border-border"
                    />
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button
                    className="font-display bg-primary hover:bg-primary/90"
                    onClick={handleRunMutationTest}
                    disabled={runMutationTest.isPending}
                  >
                    {runMutationTest.isPending ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Play className="w-4 h-4 mr-2" />
                    )}
                    RUN TEST
                  </Button>
                </div>

                {/* Mutation Test Results */}
                {runMutationTest.data && (
                  <div className="mt-4 border-t border-border pt-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                      <div className="bg-secondary/50 p-3">
                        <div className="text-xs text-muted-foreground font-display">ROBUSTNESS</div>
                        <div className="text-2xl font-display">{runMutationTest.data.robustnessScore}%</div>
                        <Badge variant={runMutationTest.data.robustnessScore >= 70 ? 'default' : 'destructive'} className="mt-1">
                          {runMutationTest.data.robustnessClass?.toUpperCase()}
                        </Badge>
                      </div>
                      <div className="bg-secondary/50 p-3">
                        <div className="text-xs text-muted-foreground font-display">TOTAL VARIANTS</div>
                        <div className="text-2xl font-display">{runMutationTest.data.totalVariants}</div>
                      </div>
                      <div className="bg-secondary/50 p-3">
                        <div className="text-xs text-muted-foreground font-display">DETECTED</div>
                        <div className="text-2xl font-display text-green-400">{runMutationTest.data.detectedCount}</div>
                      </div>
                      <div className="bg-secondary/50 p-3">
                        <div className="text-xs text-muted-foreground font-display">EVADED</div>
                        <div className="text-2xl font-display text-red-400">{runMutationTest.data.evadedCount}</div>
                      </div>
                    </div>
                    {runMutationTest.data.hardeningTips && runMutationTest.data.hardeningTips.length > 0 && (
                      <div className="bg-yellow-500/10 border border-yellow-500/30 p-3">
                        <div className="text-xs font-display text-yellow-500 mb-2 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" /> HARDENING TIPS
                        </div>
                        <ul className="text-sm space-y-1">
                          {runMutationTest.data.hardeningTips.map((tip: string, i: number) => (
                            <li key={i} className="text-muted-foreground">• {tip}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* SIEM Correlation Results */}
            {siemCorrelation && (
              <div className="bg-card border-2 border-border p-6">
                <h3 className="font-display text-lg mb-4 flex items-center gap-2">
                  <BarChart3 className="w-5 h-5 text-primary" />
                  LIVE SIEM DETECTION CORRELATION
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div className="bg-secondary/50 p-3">
                    <div className="text-xs text-muted-foreground font-display">COVERAGE</div>
                    <div className="text-2xl font-display">{siemCorrelation.stats.coveragePercent}%</div>
                    <Progress value={siemCorrelation.stats.coveragePercent} className="mt-2 h-1" />
                  </div>
                  <div className="bg-secondary/50 p-3">
                    <div className="text-xs text-muted-foreground font-display">DETECTED</div>
                    <div className="text-2xl font-display text-green-400">{siemCorrelation.stats.detectedTechniques}</div>
                  </div>
                  <div className="bg-secondary/50 p-3">
                    <div className="text-xs text-muted-foreground font-display">UNDETECTED</div>
                    <div className="text-2xl font-display text-red-400">{siemCorrelation.stats.undetectedTechniques}</div>
                  </div>
                  <div className="bg-secondary/50 p-3">
                    <div className="text-xs text-muted-foreground font-display">TOTAL ALERTS</div>
                    <div className="text-2xl font-display">{siemCorrelation.totalAlerts}</div>
                  </div>
                </div>

                {/* Detection gaps */}
                {siemCorrelation.stats.detectionGaps.length > 0 && (
                  <div className="bg-red-500/10 border border-red-500/30 p-3 mb-4">
                    <div className="text-xs font-display text-red-400 mb-2 flex items-center gap-1">
                      <XCircle className="w-3 h-3" /> DETECTION GAPS ({siemCorrelation.stats.detectionGaps.length} techniques)
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {siemCorrelation.stats.detectionGaps.map((tech: string) => (
                        <Badge key={tech} variant="outline" className="font-mono text-red-400 border-red-500/30">
                          {tech}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Per-technique correlation table */}
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border bg-secondary/50">
                        <th className="px-3 py-2 text-left text-xs font-display text-muted-foreground">TECHNIQUE</th>
                        <th className="px-3 py-2 text-left text-xs font-display text-muted-foreground">DETECTED</th>
                        <th className="px-3 py-2 text-left text-xs font-display text-muted-foreground">ALERTS</th>
                        <th className="px-3 py-2 text-left text-xs font-display text-muted-foreground">MAX SEVERITY</th>
                        <th className="px-3 py-2 text-left text-xs font-display text-muted-foreground">DETECTION RULES</th>
                      </tr>
                    </thead>
                    <tbody>
                      {siemCorrelation.correlations.slice(0, 20).map((c: any) => (
                        <tr key={c.techniqueId} className="border-b border-border/50 hover:bg-secondary/30">
                          <td className="px-3 py-2 font-mono text-primary">{c.techniqueId}</td>
                          <td className="px-3 py-2">
                            {c.detected ? (
                              <CheckCircle className="w-4 h-4 text-green-400" />
                            ) : (
                              <XCircle className="w-4 h-4 text-red-400" />
                            )}
                          </td>
                          <td className="px-3 py-2">{c.alertCount}</td>
                          <td className="px-3 py-2">
                            <Badge variant={c.maxSeverity === 'critical' ? 'destructive' : c.maxSeverity === 'high' ? 'destructive' : 'secondary'} className="text-xs">
                              {c.maxSeverity.toUpperCase()}
                            </Badge>
                          </td>
                          <td className="px-3 py-2 text-xs text-muted-foreground truncate max-w-[200px]">
                            {c.detectionRules.join(', ') || '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Empty state when no tests run yet */}
            {!showMutationTest && !siemCorrelation && (
              <div className="bg-card border-2 border-border p-6 text-center">
                <FlaskConical className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-muted-foreground mb-2">No evasion tests run for this campaign yet</p>
                <p className="text-sm text-muted-foreground">
                  Use "Run Mutation Test" to validate Sigma rules or "SIEM Correlation" to check live detection coverage
                </p>
              </div>
            )}
          </section>
        </div>
      {/* Add Agent Modal */}
      {showAddAgentModal && (
        <AddAgentModal 
          onClose={() => setShowAddAgentModal(false)} 
          onAdd={handleAddAgent}
          isLoading={addAgent.isPending}
        />
      )}
    </AppShell>
  );
}

function AddAgentModal({ 
  onClose, 
  onAdd,
  isLoading 
}: { 
  onClose: () => void; 
  onAdd: (data: { agentName: string; platform: string; hostname: string }) => void;
  isLoading: boolean;
}) {
  const [agentName, setAgentName] = useState('');
  const [platform, setPlatform] = useState('windows');
  const [hostname, setHostname] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!agentName.trim()) {
      toast.error('Agent name is required');
      return;
    }
    onAdd({ agentName, platform, hostname });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/80" onClick={onClose} />
      <div className="relative bg-card border-2 border-border w-full max-w-lg">
        <div className="p-6 border-b border-border">
          <h2 className="font-display text-2xl">ADD AGENT</h2>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
              AGENT NAME *
            </label>
            <input
              type="text"
              value={agentName}
              onChange={(e) => setAgentName(e.target.value)}
              className="w-full bg-secondary border-2 border-border px-4 py-3 font-display focus:border-primary outline-none"
              placeholder="e.g., Sandcat-VCD-01"
            />
          </div>
          <div>
            <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
              PLATFORM
            </label>
            <select
              value={platform}
              onChange={(e) => setPlatform(e.target.value)}
              className="w-full bg-secondary border-2 border-border px-4 py-3 font-display focus:border-primary outline-none"
            >
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="darwin">macOS</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
              HOSTNAME
            </label>
            <input
              type="text"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              className="w-full bg-secondary border-2 border-border px-4 py-3 font-display focus:border-primary outline-none"
              placeholder="e.g., vcd-admin-01.msp-target.com"
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
              {isLoading ? 'ADDING...' : 'ADD AGENT'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
