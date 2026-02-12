import { useState, useMemo } from 'react';
import { Link, useLocation } from 'wouter';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { trpc } from '@/lib/trpc';
import {
  Activity, Users, Key, Menu, X, Zap, Target, FileText, Cloud,
  Cpu, BookOpen, Download, Eye, Calendar, Building, User, Shield,
  CheckCircle, XCircle, AlertTriangle, Clock, Loader2, BarChart3,
  Mail, MousePointerClick, UserCheck, PieChart, TrendingUp, Lock,
  FileDown, Printer,
  Layers
} from 'lucide-react';

function NavItem({ href, icon, label, active }: { href: string; icon: React.ReactNode; label: string; active?: boolean }) {
  return (
    <Link href={href}>
      <div className={`flex items-center gap-3 px-4 py-3 font-display tracking-wider text-sm transition-colors ${active ? 'bg-primary/20 text-primary border-l-2 border-primary' : 'hover:bg-secondary'}`}>
        {icon} {label}
      </div>
    </Link>
  );
}

interface ReportConfig {
  customerName: string;
  engagementName: string;
  startDate: string;
  endDate: string;
  scope: string;
  tester: string;
  includePhishing: boolean;
  includeRedTeam: boolean;
  includeRecommendations: boolean;
  includeExecutiveSummary: boolean;
  includeMitreMapping: boolean;
  includeTimeline: boolean;
}

function getRiskRating(successRate: number): { label: string; color: string; description: string } {
  if (successRate === 0) return { label: 'LOW', color: 'text-green-400', description: 'All attack techniques were blocked or failed. Security posture is strong.' };
  if (successRate < 0.3) return { label: 'MEDIUM', color: 'text-yellow-400', description: 'Most techniques were blocked, but some gaps exist requiring attention.' };
  if (successRate < 0.6) return { label: 'HIGH', color: 'text-orange-400', description: 'Significant number of techniques succeeded. Immediate remediation recommended.' };
  return { label: 'CRITICAL', color: 'text-red-400', description: 'Majority of techniques succeeded. Critical security gaps identified.' };
}

function getPhishingRiskRating(clickRate: number): { label: string; color: string; description: string } {
  if (clickRate < 0.1) return { label: 'LOW', color: 'text-green-400', description: 'Employees demonstrated strong phishing awareness.' };
  if (clickRate < 0.25) return { label: 'MEDIUM', color: 'text-yellow-400', description: 'Some employees fell for phishing. Targeted training recommended.' };
  if (clickRate < 0.5) return { label: 'HIGH', color: 'text-orange-400', description: 'Significant phishing susceptibility. Organization-wide training needed.' };
  return { label: 'CRITICAL', color: 'text-red-400', description: 'Majority of employees fell for phishing. Immediate security awareness intervention required.' };
}

export default function SecurityReport() {
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [previewMode, setPreviewMode] = useState(false);
  const [config, setConfig] = useState<ReportConfig>({
    customerName: '',
    engagementName: 'Cyber Campaign Command Security Assessment',
    startDate: new Date().toISOString().split('T')[0],
    endDate: new Date().toISOString().split('T')[0],
    scope: '',
    tester: 'Harrison Cook',
    includePhishing: true,
    includeRedTeam: true,
    includeRecommendations: true,
    includeExecutiveSummary: true,
    includeMitreMapping: true,
    includeTimeline: true,
  });

  // Fetch live data from GoPhish
  const { data: gophishCampaigns, isLoading: loadingCampaigns } = trpc.gophishProxy.getCampaigns.useQuery();
  const { data: gophishStatus } = trpc.gophishProxy.getStatus.useQuery();

  // Fetch live data from Caldera
  const { data: calderaOperations, isLoading: loadingOps } = trpc.calderaProxy.getOperations.useQuery();
  const { data: calderaStats } = trpc.calderaProxy.getStats.useQuery();
  const { data: calderaAdversaries } = trpc.calderaProxy.getAdversaries.useQuery();
  const { data: calderaAgents } = trpc.calderaProxy.getAgents.useQuery();

  // Compute phishing metrics from live GoPhish data
  const phishingMetrics = useMemo(() => {
    if (!gophishCampaigns || !Array.isArray(gophishCampaigns)) {
      return { totalSent: 0, totalOpened: 0, totalClicked: 0, totalSubmitted: 0, totalReported: 0, campaigns: [] };
    }
    let totalSent = 0, totalOpened = 0, totalClicked = 0, totalSubmitted = 0, totalReported = 0;
    const campaigns = gophishCampaigns.map((c: any) => {
      const results = c.results || [];
      const sent = results.length;
      const opened = results.filter((r: any) => r.status === 'Email Opened' || r.status === 'Clicked Link' || r.status === 'Submitted Data').length;
      const clicked = results.filter((r: any) => r.status === 'Clicked Link' || r.status === 'Submitted Data').length;
      const submitted = results.filter((r: any) => r.status === 'Submitted Data').length;
      const reported = results.filter((r: any) => r.status === 'Email Reported').length;
      totalSent += sent;
      totalOpened += opened;
      totalClicked += clicked;
      totalSubmitted += submitted;
      totalReported += reported;
      return {
        name: c.name,
        status: c.status,
        sent, opened, clicked, submitted, reported,
        launchDate: c.launch_date,
        completedDate: c.completed_date,
      };
    });
    return { totalSent, totalOpened, totalClicked, totalSubmitted, totalReported, campaigns };
  }, [gophishCampaigns]);

  // Compute red team metrics from live Caldera data
  const redTeamMetrics = useMemo(() => {
    if (!calderaOperations || !Array.isArray(calderaOperations)) {
      return { totalOperations: 0, totalAbilities: 0, successCount: 0, failedCount: 0, operations: [], tacticCoverage: {} as Record<string, { attempted: number; success: number }> };
    }
    let totalAbilities = 0, successCount = 0, failedCount = 0;
    const tacticCoverage: Record<string, { attempted: number; success: number }> = {};
    
    const operations = calderaOperations.map((op: any) => {
      const chain = op.chain || [];
      const abilities = chain.length;
      const success = chain.filter((l: any) => l.status === 0).length;
      const failed = chain.filter((l: any) => l.status !== 0 && l.status !== -3).length;
      const collected = chain.filter((l: any) => l.status === -3).length;
      
      chain.forEach((link: any) => {
        const tactic = link.tactic || link.ability?.tactic || 'unknown';
        if (!tacticCoverage[tactic]) tacticCoverage[tactic] = { attempted: 0, success: 0 };
        tacticCoverage[tactic].attempted++;
        if (link.status === 0 || link.status === -3) tacticCoverage[tactic].success++;
      });
      
      totalAbilities += abilities;
      successCount += success + collected;
      failedCount += failed;
      
      return {
        name: op.name,
        state: op.state,
        adversary: op.adversary?.name || 'Unknown',
        abilities, success, failed, collected,
        startTime: op.start,
      };
    });
    
    return { totalOperations: operations.length, totalAbilities, successCount, failedCount, operations, tacticCoverage };
  }, [calderaOperations]);

  const overallRisk = getRiskRating(
    redTeamMetrics.totalAbilities > 0 ? redTeamMetrics.successCount / redTeamMetrics.totalAbilities : 0
  );
  const phishingRisk = getPhishingRiskRating(
    phishingMetrics.totalSent > 0 ? phishingMetrics.totalClicked / phishingMetrics.totalSent : 0
  );

  const generateMarkdownReport = () => {
    const now = new Date().toISOString();
    const customerName = config.customerName || '[CUSTOMER NAME]';
    
    let report = `# Security Assessment Report

---

**Prepared by:** ${config.tester}
**Organization:** Ace of Cloud — Cutting-Edge Cybersecurity Solutions
**Prepared for:** ${customerName}
**Engagement:** ${config.engagementName}
**Date Range:** ${config.startDate} to ${config.endDate}
**Report Generated:** ${now}
**Classification:** CONFIDENTIAL

---

`;

    if (config.includeExecutiveSummary) {
      report += `## Executive Summary

This report documents the findings from the comprehensive security assessment conducted against ${customerName}'s infrastructure. The assessment combined phishing simulation testing with adversary emulation to evaluate the organization's security posture against real-world attack scenarios.

### Overall Risk Assessment

| Assessment Area | Risk Level | Key Finding |
|----------------|------------|-------------|
| **Phishing Resilience** | **${phishingRisk.label}** | ${phishingRisk.description} |
| **Red Team / Adversary Emulation** | **${overallRisk.label}** | ${overallRisk.description} |

### Key Metrics at a Glance

| Metric | Value |
|--------|-------|
| Phishing Emails Sent | ${phishingMetrics.totalSent} |
| Phishing Click Rate | ${phishingMetrics.totalSent > 0 ? Math.round((phishingMetrics.totalClicked / phishingMetrics.totalSent) * 100) : 0}% |
| Credential Submissions | ${phishingMetrics.totalSubmitted} |
| Red Team Techniques Attempted | ${redTeamMetrics.totalAbilities} |
| Techniques Successful | ${redTeamMetrics.successCount} (${redTeamMetrics.totalAbilities > 0 ? Math.round((redTeamMetrics.successCount / redTeamMetrics.totalAbilities) * 100) : 0}%) |
| Techniques Failed/Blocked | ${redTeamMetrics.failedCount} (${redTeamMetrics.totalAbilities > 0 ? Math.round((redTeamMetrics.failedCount / redTeamMetrics.totalAbilities) * 100) : 0}%) |
| Active Caldera Operations | ${redTeamMetrics.totalOperations} |
| Adversary Profiles Available | ${calderaStats?.totalAdversaries || 0} |
| MITRE ATT&CK Techniques Covered | ${Object.keys(redTeamMetrics.tacticCoverage).length} tactics |

---

`;
    }

    report += `## Scope and Methodology

### Scope
${config.scope || '[Define in-scope systems, networks, and applications]'}

### Methodology
This assessment utilized the **Cyber Campaign Command** integrated red team platform, combining:

1. **GoPhish** — Phishing simulation platform for testing employee security awareness
2. **MITRE Caldera** — Adversary emulation framework for automated red team operations
3. **Cyber Campaign Command Dashboard** — Unified command and control interface

### Assessment Tools
- **Caldera Server:** ${calderaStats?.totalAdversaries || 0} adversary profiles, ${calderaStats?.totalAbilities || 0} abilities
- **GoPhish Server:** ${gophishStatus?.templates || 0} email templates, ${gophishStatus?.landingPages || 0} landing pages
- **Active Agents:** ${calderaStats?.totalAgents || 0}

---

`;

    if (config.includePhishing) {
      report += `## Phishing Campaign Results

### Campaign Summary

${phishingMetrics.campaigns.length > 0 ? `| Campaign | Status | Sent | Opened | Clicked | Submitted | Click Rate |
|----------|--------|------|--------|---------|-----------|------------|
${phishingMetrics.campaigns.map((c: any) => 
  `| ${c.name} | ${c.status} | ${c.sent} | ${c.opened} | ${c.clicked} | ${c.submitted} | ${c.sent > 0 ? Math.round((c.clicked / c.sent) * 100) : 0}% |`
).join('\n')}` : '| No campaigns found | - | - | - | - | - | - |'}

### Phishing Funnel Analysis

| Stage | Count | Rate |
|-------|-------|------|
| Emails Sent | ${phishingMetrics.totalSent} | 100% |
| Emails Opened | ${phishingMetrics.totalOpened} | ${phishingMetrics.totalSent > 0 ? Math.round((phishingMetrics.totalOpened / phishingMetrics.totalSent) * 100) : 0}% |
| Links Clicked | ${phishingMetrics.totalClicked} | ${phishingMetrics.totalSent > 0 ? Math.round((phishingMetrics.totalClicked / phishingMetrics.totalSent) * 100) : 0}% |
| Credentials Submitted | ${phishingMetrics.totalSubmitted} | ${phishingMetrics.totalSent > 0 ? Math.round((phishingMetrics.totalSubmitted / phishingMetrics.totalSent) * 100) : 0}% |
| Emails Reported | ${phishingMetrics.totalReported} | ${phishingMetrics.totalSent > 0 ? Math.round((phishingMetrics.totalReported / phishingMetrics.totalSent) * 100) : 0}% |

### Phishing Risk Assessment: **${phishingRisk.label}**

${phishingRisk.description}

${phishingMetrics.totalSubmitted > 0 ? `> **Critical Finding:** ${phishingMetrics.totalSubmitted} employee(s) submitted credentials to the simulated phishing page. These credentials could have been used by an attacker to gain unauthorized access to organizational systems.` : '> **Positive Finding:** No employees submitted credentials to the simulated phishing pages.'}

---

`;
    }

    if (config.includeRedTeam) {
      report += `## Red Team / Adversary Emulation Results

### Operation Summary

${redTeamMetrics.operations.length > 0 ? `| Operation | Adversary Profile | State | Abilities | Successful | Failed |
|-----------|-------------------|-------|-----------|------------|--------|
${redTeamMetrics.operations.map((op: any) => 
  `| ${op.name} | ${op.adversary} | ${op.state} | ${op.abilities} | ${op.success + op.collected} | ${op.failed} |`
).join('\n')}` : '| No operations found | - | - | - | - | - |'}

### Technique Execution Results

| Metric | Count | Percentage |
|--------|-------|------------|
| Total Techniques Attempted | ${redTeamMetrics.totalAbilities} | 100% |
| Successful Executions | ${redTeamMetrics.successCount} | ${redTeamMetrics.totalAbilities > 0 ? Math.round((redTeamMetrics.successCount / redTeamMetrics.totalAbilities) * 100) : 0}% |
| Failed / Blocked | ${redTeamMetrics.failedCount} | ${redTeamMetrics.totalAbilities > 0 ? Math.round((redTeamMetrics.failedCount / redTeamMetrics.totalAbilities) * 100) : 0}% |
| Detection Rate | ${redTeamMetrics.failedCount} | ${redTeamMetrics.totalAbilities > 0 ? Math.round((redTeamMetrics.failedCount / redTeamMetrics.totalAbilities) * 100) : 0}% |

### Red Team Risk Assessment: **${overallRisk.label}**

${overallRisk.description}

---

`;
    }

    if (config.includeMitreMapping) {
      const tactics = [
        'reconnaissance', 'resource-development', 'initial-access', 'execution',
        'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
        'discovery', 'lateral-movement', 'collection', 'command-and-control',
        'exfiltration', 'impact'
      ];
      
      report += `## MITRE ATT&CK Coverage

### Tactic Coverage Matrix

| Tactic | Techniques Attempted | Successful | Detection Rate |
|--------|---------------------|------------|----------------|
${tactics.map(tactic => {
  const coverage = redTeamMetrics.tacticCoverage[tactic];
  if (!coverage) return `| ${tactic.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())} | 0 | 0 | N/A |`;
  const rate = coverage.attempted > 0 ? Math.round(((coverage.attempted - coverage.success) / coverage.attempted) * 100) : 0;
  return `| ${tactic.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())} | ${coverage.attempted} | ${coverage.success} | ${rate}% |`;
}).join('\n')}

### Adversary Profiles Used

${calderaAdversaries && Array.isArray(calderaAdversaries) ? 
  calderaAdversaries.slice(0, 10).map((a: any) => `- **${a.name}** (${a.adversary_id}) — ${a.atomic_ordering?.length || 0} abilities`).join('\n') 
  : '- No adversary profiles loaded'}

---

`;
    }

    if (config.includeRecommendations) {
      report += `## Recommendations

### Critical Priority (Immediate Action Required)

${phishingMetrics.totalSubmitted > 0 ? `1. **Implement mandatory phishing awareness training** — ${phishingMetrics.totalSubmitted} employees submitted credentials during the assessment. Deploy organization-wide security awareness training within 30 days.
2. **Enable multi-factor authentication (MFA)** — Even when credentials are compromised, MFA prevents unauthorized access. Enforce MFA on all critical systems.
3. **Deploy email security gateway** — Implement advanced email filtering to detect and block phishing attempts before they reach employee inboxes.` : 
`1. **Maintain current security awareness program** — Employees demonstrated strong phishing awareness. Continue regular training to maintain this posture.`}

${redTeamMetrics.successCount > 0 ? `4. **Remediate successful attack vectors** — ${redTeamMetrics.successCount} adversary techniques succeeded during testing. Review and patch the specific security gaps identified.
5. **Enhance endpoint detection** — Deploy or tune EDR solutions to detect the techniques that bypassed current controls.` : 
`4. **Maintain endpoint security posture** — All adversary techniques were blocked. Continue monitoring and updating security controls.`}

### High Priority

1. Review and tune EDR/endpoint protection policies based on assessment findings
2. Implement network segmentation to limit lateral movement opportunities
3. Deploy credential protection mechanisms (Credential Guard, LSASS protection)
4. Enhance security monitoring and alerting for the techniques tested

### Medium Priority

1. Conduct follow-up assessment in 90 days to measure improvement
2. Implement security awareness training program with regular phishing simulations
3. Review and update incident response procedures based on findings
4. Deploy deception technology (honeypots, honey tokens) for early threat detection

### Low Priority

1. Document lessons learned and update security policies
2. Evaluate additional security tools for identified gaps
3. Schedule annual comprehensive security assessments
4. Develop red team exercise playbooks for ongoing testing

---

`;
    }

    if (config.includeTimeline) {
      report += `## Assessment Timeline

| Date | Activity | Details |
|------|----------|---------|
| ${config.startDate} | Assessment Started | Initial scoping and tool configuration |
${phishingMetrics.campaigns.map((c: any) => 
  `| ${c.launchDate ? new Date(c.launchDate).toISOString().split('T')[0] : config.startDate} | Phishing Campaign: ${c.name} | ${c.sent} emails sent, ${c.clicked} clicks, ${c.submitted} submissions |`
).join('\n')}
${redTeamMetrics.operations.map((op: any) => 
  `| ${op.startTime ? new Date(op.startTime).toISOString().split('T')[0] : config.startDate} | Red Team Operation: ${op.name} | ${op.abilities} techniques, ${op.success + op.collected} successful |`
).join('\n')}
| ${config.endDate} | Assessment Completed | Report generation and findings documentation |

---

`;
    }

    report += `## Appendix A: Platform Details

| Component | Details |
|-----------|---------|
| Platform | Cyber Campaign Command by Ace of Cloud |
| Caldera Version | 5.3.0 |
| Total Adversary Profiles | ${calderaStats?.totalAdversaries || 0} |
| Total Abilities | ${calderaStats?.totalAbilities || 0} |
| Active Agents | ${calderaStats?.totalAgents || 0} |
| GoPhish Templates | ${gophishStatus?.templates || 0} |
| GoPhish Landing Pages | ${gophishStatus?.landingPages || 0} |
| GoPhish Sending Profiles | ${gophishStatus?.sendingProfiles || 0} |

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | ${new Date().toISOString().split('T')[0]} | ${config.tester} | Initial assessment report |

---

**CONFIDENTIAL — FOR AUTHORIZED RECIPIENTS ONLY**

This document contains sensitive security assessment findings. Distribution is limited to authorized personnel of ${customerName} and Ace of Cloud assessment team members.

© ${new Date().getFullYear()} Ace of Cloud — Cutting-Edge Cybersecurity Solutions
*Report generated using the Cyber Campaign Command Integrated Red Team Platform*
`;

    return report;
  };

  const downloadReport = (format: 'md' | 'json') => {
    setIsGenerating(true);
    setTimeout(() => {
      if (format === 'md') {
        const report = generateMarkdownReport();
        const blob = new Blob([report], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${config.customerName || 'Security'}_Assessment_Report_${new Date().toISOString().split('T')[0]}.md`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const jsonReport = {
          metadata: {
            customer: config.customerName,
            engagement: config.engagementName,
            dateRange: { start: config.startDate, end: config.endDate },
            tester: config.tester,
            generatedAt: new Date().toISOString(),
            platform: 'Cyber Campaign Command by Ace of Cloud',
          },
          riskAssessment: {
            phishing: phishingRisk,
            redTeam: overallRisk,
          },
          phishingResults: {
            summary: {
              totalSent: phishingMetrics.totalSent,
              totalOpened: phishingMetrics.totalOpened,
              totalClicked: phishingMetrics.totalClicked,
              totalSubmitted: phishingMetrics.totalSubmitted,
              totalReported: phishingMetrics.totalReported,
              clickRate: phishingMetrics.totalSent > 0 ? (phishingMetrics.totalClicked / phishingMetrics.totalSent) : 0,
              submissionRate: phishingMetrics.totalSent > 0 ? (phishingMetrics.totalSubmitted / phishingMetrics.totalSent) : 0,
            },
            campaigns: phishingMetrics.campaigns,
          },
          redTeamResults: {
            summary: {
              totalOperations: redTeamMetrics.totalOperations,
              totalAbilities: redTeamMetrics.totalAbilities,
              successCount: redTeamMetrics.successCount,
              failedCount: redTeamMetrics.failedCount,
              successRate: redTeamMetrics.totalAbilities > 0 ? (redTeamMetrics.successCount / redTeamMetrics.totalAbilities) : 0,
            },
            operations: redTeamMetrics.operations,
            tacticCoverage: redTeamMetrics.tacticCoverage,
          },
          calderaStats: calderaStats,
          gophishStatus: gophishStatus,
        };
        const blob = new Blob([JSON.stringify(jsonReport, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${config.customerName || 'Security'}_Assessment_Data_${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
      setIsGenerating(false);
    }, 1000);
  };

  const isLoading = loadingCampaigns || loadingOps;

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-card border-r border-border transform transition-transform duration-200 lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex flex-col h-full">
          <div className="p-4 border-b border-border">
            <Link href="/">
              <h1 className="font-display text-xl tracking-widest text-primary cursor-pointer">CYBER CAMPAIGN COMMAND</h1>
            </Link>
            <p className="text-xs text-muted-foreground tracking-wider mt-1">REPORT GENERATOR</p>
          </div>
          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity className="w-4 h-4" />} label="DASHBOARD" />
            <NavItem href="/credentials" icon={<Key className="w-4 h-4" />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target className="w-4 h-4" />} label="ADVERSARIES" />
            <NavItem href="/agents" icon={<Cpu className="w-4 h-4" />} label="AGENTS" />
            <NavItem href="/campaigns" icon={<Zap className="w-4 h-4" />} label="CAMPAIGNS" />
            <NavItem href="/gophish" icon={<Zap className="w-4 h-4" />} label="GOPHISH" />
            <NavItem href="/team" icon={<Users className="w-4 h-4" />} label="TEAM" />
            <NavItem href="/activity" icon={<FileText className="w-4 h-4" />} label="ACTIVITY" />
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">GUIDES</p>
              <NavItem href="/guide/gophish" icon={<BookOpen className="w-4 h-4" />} label="GOPHISH GUIDE" />
              <NavItem href="/guide/caldera" icon={<BookOpen className="w-4 h-4" />} label="CALDERA GUIDE" />
            </div>
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">REPORTS</p>
              <NavItem href="/reports/security" icon={<FileDown className="w-4 h-4" />} label="SECURITY REPORT" active />
            </div>
          </nav>
        </div>
      </aside>

      {/* Mobile sidebar toggle */}
      <button className="fixed top-4 left-4 z-50 lg:hidden p-2 bg-card border border-border" onClick={() => setSidebarOpen(!sidebarOpen)}>
        {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      {/* Main Content */}
      <main className="flex-1 lg:ml-64 p-6 lg:p-10">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-8 h-8 text-primary" />
            <h1 className="font-display text-3xl tracking-wider">SECURITY ASSESSMENT REPORT</h1>
          </div>
          <p className="text-muted-foreground text-lg">Generate branded customer-facing security assessment reports with live data from GoPhish and Caldera.</p>
          <p className="text-xs text-muted-foreground mt-2">By Harrison Cook — AceofCloud</p>
        </div>

        {/* Data Status Indicators */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Mail className="w-5 h-5 text-primary" />
              <span className="font-display text-xs tracking-wider">GOPHISH DATA</span>
            </div>
            {loadingCampaigns ? (
              <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
            ) : (
              <div className="space-y-1">
                <p className="text-2xl font-bold">{phishingMetrics.campaigns.length}</p>
                <p className="text-xs text-muted-foreground">campaigns loaded</p>
              </div>
            )}
          </div>
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Target className="w-5 h-5 text-primary" />
              <span className="font-display text-xs tracking-wider">CALDERA DATA</span>
            </div>
            {loadingOps ? (
              <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
            ) : (
              <div className="space-y-1">
                <p className="text-2xl font-bold">{redTeamMetrics.totalOperations}</p>
                <p className="text-xs text-muted-foreground">operations loaded</p>
              </div>
            )}
          </div>
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <BarChart3 className="w-5 h-5 text-primary" />
              <span className="font-display text-xs tracking-wider">PHISHING RISK</span>
            </div>
            <p className={`text-2xl font-bold ${phishingRisk.color}`}>{phishingRisk.label}</p>
            <p className="text-xs text-muted-foreground">
              {phishingMetrics.totalSent > 0 ? `${Math.round((phishingMetrics.totalClicked / phishingMetrics.totalSent) * 100)}% click rate` : 'No data'}
            </p>
          </div>
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-5 h-5 text-primary" />
              <span className="font-display text-xs tracking-wider">RED TEAM RISK</span>
            </div>
            <p className={`text-2xl font-bold ${overallRisk.color}`}>{overallRisk.label}</p>
            <p className="text-xs text-muted-foreground">
              {redTeamMetrics.totalAbilities > 0 ? `${Math.round((redTeamMetrics.successCount / redTeamMetrics.totalAbilities) * 100)}% success rate` : 'No data'}
            </p>
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-8">
          {/* Configuration Panel */}
          <div className="space-y-6">
            <div className="bg-card border-2 border-border rounded-lg p-6">
              <h2 className="font-display text-lg mb-4 tracking-wider">REPORT CONFIGURATION</h2>
              <div className="space-y-4">
                <div>
                  <label className="text-sm text-muted-foreground block mb-1">Customer Name *</label>
                  <input
                    type="text"
                    value={config.customerName}
                    onChange={(e) => setConfig({ ...config, customerName: e.target.value })}
                    placeholder="Enter customer name"
                    className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div>
                  <label className="text-sm text-muted-foreground block mb-1">Engagement Name</label>
                  <input
                    type="text"
                    value={config.engagementName}
                    onChange={(e) => setConfig({ ...config, engagementName: e.target.value })}
                    className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm text-muted-foreground block mb-1">Start Date</label>
                    <input
                      type="date"
                      value={config.startDate}
                      onChange={(e) => setConfig({ ...config, startDate: e.target.value })}
                      className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                  </div>
                  <div>
                    <label className="text-sm text-muted-foreground block mb-1">End Date</label>
                    <input
                      type="date"
                      value={config.endDate}
                      onChange={(e) => setConfig({ ...config, endDate: e.target.value })}
                      className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                  </div>
                </div>
                <div>
                  <label className="text-sm text-muted-foreground block mb-1">Tester Name</label>
                  <input
                    type="text"
                    value={config.tester}
                    onChange={(e) => setConfig({ ...config, tester: e.target.value })}
                    className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div>
                  <label className="text-sm text-muted-foreground block mb-1">Scope Description</label>
                  <textarea
                    value={config.scope}
                    onChange={(e) => setConfig({ ...config, scope: e.target.value })}
                    placeholder="Define in-scope systems and networks..."
                    rows={3}
                    className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>
            </div>

            <div className="bg-card border-2 border-border rounded-lg p-6">
              <h2 className="font-display text-lg mb-4 tracking-wider">REPORT SECTIONS</h2>
              <div className="space-y-3">
                {[
                  { key: 'includeExecutiveSummary', icon: <BarChart3 className="w-4 h-4 text-primary" />, label: 'Executive Summary & Risk Assessment' },
                  { key: 'includePhishing', icon: <Mail className="w-4 h-4 text-blue-400" />, label: 'Phishing Campaign Results (GoPhish)' },
                  { key: 'includeRedTeam', icon: <Target className="w-4 h-4 text-red-400" />, label: 'Red Team Operation Results (Caldera)' },
                  { key: 'includeMitreMapping', icon: <Layers className="w-4 h-4 text-yellow-400" />, label: 'MITRE ATT&CK Coverage Matrix' },
                  { key: 'includeRecommendations', icon: <CheckCircle className="w-4 h-4 text-green-400" />, label: 'Security Recommendations' },
                  { key: 'includeTimeline', icon: <Clock className="w-4 h-4 text-purple-400" />, label: 'Assessment Timeline' },
                ].map(({ key, icon, label }) => (
                  <label key={key} className="flex items-center gap-3 cursor-pointer group">
                    <input
                      type="checkbox"
                      checked={(config as any)[key]}
                      onChange={(e) => setConfig({ ...config, [key]: e.target.checked })}
                      className="rounded accent-primary"
                    />
                    {icon}
                    <span className="text-sm group-hover:text-foreground transition-colors">{label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Live Data Summary */}
            <div className="bg-card border-2 border-primary/50 rounded-lg p-6">
              <h2 className="font-display text-lg mb-4 tracking-wider flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-primary" />
                LIVE DATA SUMMARY
              </h2>
              <div className="space-y-4">
                <div>
                  <p className="text-xs text-muted-foreground font-display tracking-wider mb-2">PHISHING (GOPHISH)</p>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="bg-secondary rounded p-2 text-center">
                      <p className="text-lg font-bold">{phishingMetrics.totalSent}</p>
                      <p className="text-[10px] text-muted-foreground">SENT</p>
                    </div>
                    <div className="bg-secondary rounded p-2 text-center">
                      <p className="text-lg font-bold text-blue-400">{phishingMetrics.totalClicked}</p>
                      <p className="text-[10px] text-muted-foreground">CLICKED</p>
                    </div>
                    <div className="bg-secondary rounded p-2 text-center">
                      <p className="text-lg font-bold text-red-400">{phishingMetrics.totalSubmitted}</p>
                      <p className="text-[10px] text-muted-foreground">SUBMITTED</p>
                    </div>
                    <div className="bg-secondary rounded p-2 text-center">
                      <p className="text-lg font-bold text-green-400">{phishingMetrics.totalReported}</p>
                      <p className="text-[10px] text-muted-foreground">REPORTED</p>
                    </div>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground font-display tracking-wider mb-2">RED TEAM (CALDERA)</p>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="bg-secondary rounded p-2 text-center">
                      <p className="text-lg font-bold">{redTeamMetrics.totalAbilities}</p>
                      <p className="text-[10px] text-muted-foreground">TECHNIQUES</p>
                    </div>
                    <div className="bg-secondary rounded p-2 text-center">
                      <p className="text-lg font-bold text-green-400">{redTeamMetrics.successCount}</p>
                      <p className="text-[10px] text-muted-foreground">SUCCESS</p>
                    </div>
                    <div className="bg-secondary rounded p-2 text-center">
                      <p className="text-lg font-bold text-red-400">{redTeamMetrics.failedCount}</p>
                      <p className="text-[10px] text-muted-foreground">FAILED</p>
                    </div>
                    <div className="bg-secondary rounded p-2 text-center">
                      <p className="text-lg font-bold">{redTeamMetrics.totalOperations}</p>
                      <p className="text-[10px] text-muted-foreground">OPERATIONS</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Download Buttons */}
            <div className="space-y-2">
              <Button
                className="w-full font-display tracking-wider"
                onClick={() => downloadReport('md')}
                disabled={isGenerating || isLoading}
              >
                {isGenerating ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Download className="w-4 h-4 mr-2" />
                )}
                DOWNLOAD MARKDOWN REPORT
              </Button>
              <Button
                variant="outline"
                className="w-full font-display tracking-wider"
                onClick={() => downloadReport('json')}
                disabled={isGenerating || isLoading}
              >
                <FileDown className="w-4 h-4 mr-2" />
                DOWNLOAD JSON DATA
              </Button>
              <Button
                variant="outline"
                className="w-full font-display tracking-wider"
                onClick={() => setPreviewMode(!previewMode)}
              >
                <Eye className="w-4 h-4 mr-2" />
                {previewMode ? 'VISUAL PREVIEW' : 'RAW MARKDOWN'}
              </Button>
            </div>
          </div>

          {/* Preview Panel */}
          <div className="lg:col-span-2">
            <div className="bg-card border-2 border-border rounded-lg">
              <div className="p-4 border-b border-border bg-secondary/30 flex items-center justify-between">
                <h2 className="font-display tracking-wider">REPORT PREVIEW</h2>
                <div className="flex items-center gap-2">
                  {isLoading && (
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <Loader2 className="w-3 h-3 animate-spin" />
                      Loading live data...
                    </div>
                  )}
                  <Badge variant="outline" className="font-display text-[10px]">LIVE DATA</Badge>
                </div>
              </div>
              <div className="p-6 max-h-[900px] overflow-y-auto">
                {previewMode ? (
                  <pre className="text-xs whitespace-pre-wrap bg-black/50 p-4 rounded overflow-x-auto font-mono text-green-400">
                    {generateMarkdownReport()}
                  </pre>
                ) : (
                  <div className="space-y-8">
                    {/* Report Header */}
                    <div className="text-center border-b border-border pb-8">
                      <div className="flex items-center justify-center gap-2 mb-4">
                        <Cloud className="w-8 h-8 text-primary" />
                        <span className="font-display text-2xl tracking-widest text-primary">ACE OF CLOUD</span>
                      </div>
                      <h1 className="text-3xl font-display tracking-wider mb-2">SECURITY ASSESSMENT REPORT</h1>
                      <p className="text-xl text-muted-foreground">{config.customerName || '[CUSTOMER NAME]'}</p>
                      <p className="text-sm text-muted-foreground mt-1">{config.engagementName}</p>
                      <p className="text-xs text-muted-foreground mt-2">{config.startDate} to {config.endDate}</p>
                    </div>

                    {/* Executive Summary */}
                    {config.includeExecutiveSummary && (
                      <div>
                        <h2 className="font-display text-xl mb-6 tracking-wider flex items-center gap-2">
                          <BarChart3 className="w-6 h-6 text-primary" />
                          EXECUTIVE SUMMARY
                        </h2>
                        
                        {/* Risk Assessment Cards */}
                        <div className="grid grid-cols-2 gap-4 mb-6">
                          <div className={`border-2 rounded-lg p-5 ${phishingRisk.label === 'LOW' ? 'border-green-500/30 bg-green-500/5' : phishingRisk.label === 'MEDIUM' ? 'border-yellow-500/30 bg-yellow-500/5' : phishingRisk.label === 'HIGH' ? 'border-orange-500/30 bg-orange-500/5' : 'border-red-500/30 bg-red-500/5'}`}>
                            <div className="flex items-center gap-2 mb-2">
                              <Mail className="w-5 h-5 text-primary" />
                              <span className="font-display text-xs tracking-wider">PHISHING RISK</span>
                            </div>
                            <p className={`text-3xl font-bold ${phishingRisk.color}`}>{phishingRisk.label}</p>
                            <p className="text-xs text-muted-foreground mt-1">{phishingRisk.description}</p>
                          </div>
                          <div className={`border-2 rounded-lg p-5 ${overallRisk.label === 'LOW' ? 'border-green-500/30 bg-green-500/5' : overallRisk.label === 'MEDIUM' ? 'border-yellow-500/30 bg-yellow-500/5' : overallRisk.label === 'HIGH' ? 'border-orange-500/30 bg-orange-500/5' : 'border-red-500/30 bg-red-500/5'}`}>
                            <div className="flex items-center gap-2 mb-2">
                              <Target className="w-5 h-5 text-primary" />
                              <span className="font-display text-xs tracking-wider">RED TEAM RISK</span>
                            </div>
                            <p className={`text-3xl font-bold ${overallRisk.color}`}>{overallRisk.label}</p>
                            <p className="text-xs text-muted-foreground mt-1">{overallRisk.description}</p>
                          </div>
                        </div>

                        {/* Key Metrics */}
                        <div className="grid grid-cols-4 gap-3">
                          <div className="bg-secondary rounded-lg p-3 text-center">
                            <p className="text-2xl font-bold">{phishingMetrics.totalSent}</p>
                            <p className="text-[10px] text-muted-foreground font-display tracking-wider">EMAILS SENT</p>
                          </div>
                          <div className="bg-secondary rounded-lg p-3 text-center">
                            <p className="text-2xl font-bold text-blue-400">
                              {phishingMetrics.totalSent > 0 ? Math.round((phishingMetrics.totalClicked / phishingMetrics.totalSent) * 100) : 0}%
                            </p>
                            <p className="text-[10px] text-muted-foreground font-display tracking-wider">CLICK RATE</p>
                          </div>
                          <div className="bg-secondary rounded-lg p-3 text-center">
                            <p className="text-2xl font-bold">{redTeamMetrics.totalAbilities}</p>
                            <p className="text-[10px] text-muted-foreground font-display tracking-wider">TECHNIQUES</p>
                          </div>
                          <div className="bg-secondary rounded-lg p-3 text-center">
                            <p className="text-2xl font-bold text-green-400">
                              {redTeamMetrics.totalAbilities > 0 ? Math.round((redTeamMetrics.successCount / redTeamMetrics.totalAbilities) * 100) : 0}%
                            </p>
                            <p className="text-[10px] text-muted-foreground font-display tracking-wider">SUCCESS RATE</p>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Phishing Results */}
                    {config.includePhishing && (
                      <div>
                        <h2 className="font-display text-xl mb-6 tracking-wider flex items-center gap-2">
                          <Mail className="w-6 h-6 text-blue-400" />
                          PHISHING CAMPAIGN RESULTS
                        </h2>

                        {/* Phishing Funnel */}
                        <div className="space-y-2 mb-6">
                          {[
                            { label: 'Emails Sent', value: phishingMetrics.totalSent, color: 'bg-primary', pct: 100 },
                            { label: 'Emails Opened', value: phishingMetrics.totalOpened, color: 'bg-blue-500', pct: phishingMetrics.totalSent > 0 ? (phishingMetrics.totalOpened / phishingMetrics.totalSent) * 100 : 0 },
                            { label: 'Links Clicked', value: phishingMetrics.totalClicked, color: 'bg-yellow-500', pct: phishingMetrics.totalSent > 0 ? (phishingMetrics.totalClicked / phishingMetrics.totalSent) * 100 : 0 },
                            { label: 'Credentials Submitted', value: phishingMetrics.totalSubmitted, color: 'bg-red-500', pct: phishingMetrics.totalSent > 0 ? (phishingMetrics.totalSubmitted / phishingMetrics.totalSent) * 100 : 0 },
                          ].map(({ label, value, color, pct }) => (
                            <div key={label} className="flex items-center gap-3">
                              <span className="text-xs text-muted-foreground w-40 text-right font-display tracking-wider">{label}</span>
                              <div className="flex-1 bg-secondary rounded-full h-6 overflow-hidden">
                                <div className={`${color} h-full rounded-full flex items-center justify-end pr-2 transition-all duration-500`} style={{ width: `${Math.max(pct, 2)}%` }}>
                                  <span className="text-[10px] font-bold text-white">{value}</span>
                                </div>
                              </div>
                              <span className="text-xs text-muted-foreground w-12">{Math.round(pct)}%</span>
                            </div>
                          ))}
                        </div>

                        {/* Campaign Table */}
                        {phishingMetrics.campaigns.length > 0 && (
                          <div className="overflow-x-auto">
                            <table className="w-full text-sm">
                              <thead>
                                <tr className="bg-secondary">
                                  <th className="px-3 py-2 text-left font-display text-xs tracking-wider">Campaign</th>
                                  <th className="px-3 py-2 text-center font-display text-xs tracking-wider">Sent</th>
                                  <th className="px-3 py-2 text-center font-display text-xs tracking-wider">Opened</th>
                                  <th className="px-3 py-2 text-center font-display text-xs tracking-wider">Clicked</th>
                                  <th className="px-3 py-2 text-center font-display text-xs tracking-wider">Submitted</th>
                                  <th className="px-3 py-2 text-center font-display text-xs tracking-wider">Click Rate</th>
                                </tr>
                              </thead>
                              <tbody>
                                {phishingMetrics.campaigns.map((c: any, i: number) => (
                                  <tr key={i} className="border-b border-border">
                                    <td className="px-3 py-2 text-muted-foreground">{c.name}</td>
                                    <td className="px-3 py-2 text-center">{c.sent}</td>
                                    <td className="px-3 py-2 text-center text-blue-400">{c.opened}</td>
                                    <td className="px-3 py-2 text-center text-yellow-400">{c.clicked}</td>
                                    <td className="px-3 py-2 text-center text-red-400">{c.submitted}</td>
                                    <td className="px-3 py-2 text-center font-bold">
                                      {c.sent > 0 ? Math.round((c.clicked / c.sent) * 100) : 0}%
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Red Team Results */}
                    {config.includeRedTeam && (
                      <div>
                        <h2 className="font-display text-xl mb-6 tracking-wider flex items-center gap-2">
                          <Target className="w-6 h-6 text-red-400" />
                          RED TEAM OPERATION RESULTS
                        </h2>

                        {/* Operation Cards */}
                        {redTeamMetrics.operations.map((op: any, i: number) => (
                          <div key={i} className="bg-secondary/30 border border-border rounded-lg p-4 mb-4">
                            <div className="flex items-center justify-between mb-3">
                              <div>
                                <h3 className="font-display tracking-wider">{op.name}</h3>
                                <p className="text-xs text-muted-foreground">Adversary: {op.adversary}</p>
                              </div>
                              <Badge variant="outline" className={`font-display text-[10px] ${op.state === 'running' ? 'border-green-500 text-green-400' : 'border-muted-foreground'}`}>
                                {op.state?.toUpperCase() || 'UNKNOWN'}
                              </Badge>
                            </div>
                            <div className="grid grid-cols-4 gap-2">
                              <div className="bg-background rounded p-2 text-center">
                                <p className="text-lg font-bold">{op.abilities}</p>
                                <p className="text-[10px] text-muted-foreground">TOTAL</p>
                              </div>
                              <div className="bg-background rounded p-2 text-center">
                                <p className="text-lg font-bold text-green-400">{op.success + op.collected}</p>
                                <p className="text-[10px] text-muted-foreground">SUCCESS</p>
                              </div>
                              <div className="bg-background rounded p-2 text-center">
                                <p className="text-lg font-bold text-red-400">{op.failed}</p>
                                <p className="text-[10px] text-muted-foreground">FAILED</p>
                              </div>
                              <div className="bg-background rounded p-2 text-center">
                                <p className="text-lg font-bold text-blue-400">{op.collected}</p>
                                <p className="text-[10px] text-muted-foreground">COLLECTED</p>
                              </div>
                            </div>
                          </div>
                        ))}

                        {redTeamMetrics.operations.length === 0 && (
                          <div className="text-center py-8 text-muted-foreground">
                            <Target className="w-12 h-12 mx-auto mb-2 opacity-30" />
                            <p>No operations data available. Run Caldera operations to populate this section.</p>
                          </div>
                        )}
                      </div>
                    )}

                    {/* MITRE ATT&CK Coverage */}
                    {config.includeMitreMapping && (
                      <div>
                        <h2 className="font-display text-xl mb-6 tracking-wider flex items-center gap-2">
                          <Layers className="w-6 h-6 text-yellow-400" />
                          MITRE ATT&CK COVERAGE
                        </h2>
                        <div className="grid grid-cols-2 gap-2">
                          {[
                            'reconnaissance', 'resource-development', 'initial-access', 'execution',
                            'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
                            'discovery', 'lateral-movement', 'collection', 'command-and-control',
                            'exfiltration', 'impact'
                          ].map((tactic) => {
                            const coverage = redTeamMetrics.tacticCoverage[tactic];
                            const attempted = coverage?.attempted || 0;
                            const success = coverage?.success || 0;
                            const hasData = attempted > 0;
                            return (
                              <div key={tactic} className={`rounded-lg p-3 border ${hasData ? 'border-primary/30 bg-primary/5' : 'border-border bg-secondary/20'}`}>
                                <p className="font-display text-[10px] tracking-wider mb-1">
                                  {tactic.replace(/-/g, ' ').toUpperCase()}
                                </p>
                                {hasData ? (
                                  <div className="flex items-center gap-2">
                                    <span className="text-sm font-bold">{attempted}</span>
                                    <span className="text-[10px] text-muted-foreground">attempted</span>
                                    <span className="text-sm font-bold text-green-400">{success}</span>
                                    <span className="text-[10px] text-muted-foreground">success</span>
                                  </div>
                                ) : (
                                  <p className="text-[10px] text-muted-foreground">Not tested</p>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Recommendations Preview */}
                    {config.includeRecommendations && (
                      <div>
                        <h2 className="font-display text-xl mb-6 tracking-wider flex items-center gap-2">
                          <CheckCircle className="w-6 h-6 text-green-400" />
                          RECOMMENDATIONS
                        </h2>
                        <div className="space-y-3">
                          {phishingMetrics.totalSubmitted > 0 && (
                            <div className="flex gap-3 p-4 rounded-lg border border-red-500/30 bg-red-500/5">
                              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
                              <div>
                                <p className="font-display text-xs tracking-wider text-red-400 mb-1">CRITICAL</p>
                                <p className="text-sm text-muted-foreground">Implement mandatory phishing awareness training. {phishingMetrics.totalSubmitted} employees submitted credentials during the assessment.</p>
                              </div>
                            </div>
                          )}
                          {redTeamMetrics.successCount > 0 && (
                            <div className="flex gap-3 p-4 rounded-lg border border-orange-500/30 bg-orange-500/5">
                              <AlertTriangle className="w-5 h-5 text-orange-400 shrink-0" />
                              <div>
                                <p className="font-display text-xs tracking-wider text-orange-400 mb-1">HIGH</p>
                                <p className="text-sm text-muted-foreground">Remediate successful attack vectors. {redTeamMetrics.successCount} adversary techniques succeeded during testing.</p>
                              </div>
                            </div>
                          )}
                          <div className="flex gap-3 p-4 rounded-lg border border-yellow-500/30 bg-yellow-500/5">
                            <Shield className="w-5 h-5 text-yellow-400 shrink-0" />
                            <div>
                              <p className="font-display text-xs tracking-wider text-yellow-400 mb-1">MEDIUM</p>
                              <p className="text-sm text-muted-foreground">Conduct follow-up assessment in 90 days to measure improvement and validate remediation effectiveness.</p>
                            </div>
                          </div>
                          <div className="flex gap-3 p-4 rounded-lg border border-blue-500/30 bg-blue-500/5">
                            <Lock className="w-5 h-5 text-blue-400 shrink-0" />
                            <div>
                              <p className="font-display text-xs tracking-wider text-blue-400 mb-1">STANDARD</p>
                              <p className="text-sm text-muted-foreground">Enable multi-factor authentication on all critical systems. Deploy advanced email filtering and endpoint detection solutions.</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Footer */}
                    <div className="border-t border-border pt-8 text-center">
                      <div className="flex items-center justify-center gap-2 mb-2">
                        <Cloud className="w-5 h-5 text-primary" />
                        <span className="font-display tracking-widest text-primary">ACE OF CLOUD</span>
                      </div>
                      <p className="text-sm text-muted-foreground">Report prepared by {config.tester}</p>
                      <p className="text-xs text-muted-foreground mt-1">© {new Date().getFullYear()} Ace of Cloud — Cutting-Edge Cybersecurity Solutions</p>
                      <p className="text-[10px] text-muted-foreground mt-2">CONFIDENTIAL — FOR AUTHORIZED RECIPIENTS ONLY</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && <div className="fixed inset-0 bg-black/50 z-40 lg:hidden" onClick={() => setSidebarOpen(false)} />}
    </div>
  );
}

