import { useState } from 'react';
import { Link } from 'wouter';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { trpc } from '@/lib/trpc';
import {
  FileText,
  ChevronLeft,
  Download,
  Eye,
  Calendar,
  Building,
  User,
  Shield,
  Target,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  FileJson,
  FileCode,
  Loader2
} from 'lucide-react';

const CALDERA_SERVER = '137.184.7.224';

interface ReportConfig {
  customerName: string;
  engagementName: string;
  startDate: string;
  endDate: string;
  scope: string;
  tester: string;
  includeFailures: boolean;
  includeBlocked: boolean;
  includeEvidence: boolean;
  includeRecommendations: boolean;
}

interface AbilityResult {
  ability_id: string;
  ability_name: string;
  technique_id: string;
  tactic: string;
  status: 'success' | 'failed' | 'blocked' | 'timeout';
  timestamp: string;
  agent: string;
  output: string;
  error_message: string | null;
  blocked_by: string | null;
  detection_details: string | null;
  duration_seconds: number;
}

// Sample data structure for demonstration
const SAMPLE_RESULTS: AbilityResult[] = [
  {
    ability_id: 'abc123',
    ability_name: 'PowerShell Download Cradle',
    technique_id: 'T1059.001',
    tactic: 'Execution',
    status: 'blocked',
    timestamp: new Date().toISOString(),
    agent: 'WORKSTATION-01',
    output: '',
    error_message: null,
    blocked_by: 'CrowdStrike Falcon',
    detection_details: 'Suspicious PowerShell execution detected. Process terminated. Alert ID: CS-2025-00142',
    duration_seconds: 0.5
  },
  {
    ability_id: 'def456',
    ability_name: 'AMSI Bypass',
    technique_id: 'T1562.001',
    tactic: 'Defense Evasion',
    status: 'success',
    timestamp: new Date().toISOString(),
    agent: 'WORKSTATION-01',
    output: 'AMSI context patched successfully',
    error_message: null,
    blocked_by: null,
    detection_details: null,
    duration_seconds: 1.2
  },
  {
    ability_id: 'ghi789',
    ability_name: 'Credential Dumping via LSASS',
    technique_id: 'T1003.001',
    tactic: 'Credential Access',
    status: 'blocked',
    timestamp: new Date().toISOString(),
    agent: 'WORKSTATION-01',
    output: '',
    error_message: null,
    blocked_by: 'Windows Defender Credential Guard',
    detection_details: 'Access to LSASS process denied. Protected process violation detected.',
    duration_seconds: 0.1
  }
];

export default function ReportGenerator() {
  const [config, setConfig] = useState<ReportConfig>({
    customerName: '',
    engagementName: 'Databank Red Team Exercise',
    startDate: new Date().toISOString().split('T')[0],
    endDate: new Date().toISOString().split('T')[0],
    scope: '',
    tester: 'Harrison Cook',
    includeFailures: true,
    includeBlocked: true,
    includeEvidence: true,
    includeRecommendations: true
  });
  const [isGenerating, setIsGenerating] = useState(false);
  const [previewMode, setPreviewMode] = useState(false);
  const [results] = useState<AbilityResult[]>(SAMPLE_RESULTS);

  // Fetch operations from Caldera
  const { data: operations } = trpc.calderaProxy.getOperations.useQuery();
  const { data: adversaries } = trpc.calderaProxy.getAdversaries.useQuery();

  const generateMarkdownReport = () => {
    const successCount = results.filter(r => r.status === 'success').length;
    const failedCount = results.filter(r => r.status === 'failed').length;
    const blockedCount = results.filter(r => r.status === 'blocked').length;
    const totalCount = results.length;

    const report = `# Red Team Exercise Report

![Ace of Cloud Logo](https://aceofcloud.com/logo.png)

**Prepared by:** ${config.tester}  
**Prepared for:** ${config.customerName || '[CUSTOMER NAME]'}  
**Engagement:** ${config.engagementName}  
**Date Range:** ${config.startDate} to ${config.endDate}  
**Report Generated:** ${new Date().toISOString()}

---

## Executive Summary

This report documents the findings from the ${config.engagementName} conducted against ${config.customerName || '[CUSTOMER NAME]'}'s infrastructure. The assessment evaluated the effectiveness of security controls against advanced persistent threat (APT) techniques.

### Key Metrics

| Metric | Value |
|--------|-------|
| Total Techniques Attempted | ${totalCount} |
| Successful Executions | ${successCount} (${totalCount > 0 ? Math.round((successCount/totalCount)*100) : 0}%) |
| Blocked by Security Controls | ${blockedCount} (${totalCount > 0 ? Math.round((blockedCount/totalCount)*100) : 0}%) |
| Failed Executions | ${failedCount} (${totalCount > 0 ? Math.round((failedCount/totalCount)*100) : 0}%) |
| Detection Rate | ${totalCount > 0 ? Math.round((blockedCount/totalCount)*100) : 0}% |
| Prevention Rate | ${totalCount > 0 ? Math.round(((blockedCount + failedCount)/totalCount)*100) : 0}% |

### Risk Rating

${successCount === 0 ? '**LOW** - All attack techniques were successfully blocked or failed.' :
  successCount < totalCount * 0.3 ? '**MEDIUM** - Most attack techniques were blocked, but some gaps exist.' :
  successCount < totalCount * 0.6 ? '**HIGH** - Significant number of techniques succeeded. Immediate remediation recommended.' :
  '**CRITICAL** - Majority of attack techniques succeeded. Critical security gaps identified.'}

---

## Scope and Objectives

### In-Scope Assets
${config.scope || '[Define in-scope systems, networks, and applications]'}

### Objectives
1. Evaluate effectiveness of endpoint detection and response (EDR) solutions
2. Test network security controls and segmentation
3. Assess credential protection mechanisms
4. Validate security monitoring and alerting capabilities

---

## Methodology

The assessment utilized MITRE Caldera adversary emulation platform with the following adversary profiles:
${adversaries?.slice(0, 5).map((a: any) => `- **${a.name}** (${a.adversary_id})`).join('\n') || '- APT29 VCD Cloud Compromise\n- CrowdStrike Falcon Bypass'}

### Attack Chain
The operation followed the MITRE ATT&CK framework, executing techniques across the following tactics:
1. Initial Access
2. Execution
3. Persistence
4. Privilege Escalation
5. Defense Evasion
6. Credential Access
7. Discovery
8. Lateral Movement
9. Collection
10. Command and Control
11. Exfiltration

---

## Detailed Findings

${config.includeBlocked ? `### Blocked Attacks (Security Controls Working)

The following techniques were successfully blocked by security controls:

| Technique | Tactic | Blocked By | Detection Details | Timestamp |
|-----------|--------|------------|-------------------|-----------|
${results.filter(r => r.status === 'blocked').map(r => 
  `| ${r.technique_id} - ${r.ability_name} | ${r.tactic} | ${r.blocked_by || 'Unknown'} | ${r.detection_details || 'N/A'} | ${new Date(r.timestamp).toLocaleString()} |`
).join('\n') || '| No blocked attacks recorded | - | - | - | - |'}

` : ''}

### Successful Attacks (Security Gaps)

The following techniques successfully bypassed security controls:

| Technique | Tactic | Agent | Output Summary | Duration |
|-----------|--------|-------|----------------|----------|
${results.filter(r => r.status === 'success').map(r => 
  `| ${r.technique_id} - ${r.ability_name} | ${r.tactic} | ${r.agent} | ${r.output?.substring(0, 50) || 'N/A'}... | ${r.duration_seconds}s |`
).join('\n') || '| No successful attacks recorded | - | - | - | - |'}

${config.includeFailures ? `### Failed Attacks

The following techniques failed during execution:

| Technique | Tactic | Error Message | Timestamp |
|-----------|--------|---------------|-----------|
${results.filter(r => r.status === 'failed' || r.status === 'timeout').map(r => 
  `| ${r.technique_id} - ${r.ability_name} | ${r.tactic} | ${r.error_message || 'Execution timeout'} | ${new Date(r.timestamp).toLocaleString()} |`
).join('\n') || '| No failed attacks recorded | - | - | - |'}

` : ''}

---

## Security Control Effectiveness Assessment

### EDR/Endpoint Protection
${blockedCount > 0 ? 
  `**Effectiveness: ${Math.round((blockedCount/totalCount)*100)}%**\n\nThe endpoint protection solution successfully detected and blocked ${blockedCount} out of ${totalCount} attempted techniques.` :
  '**Effectiveness: Not Tested**\n\nNo techniques were blocked by endpoint protection during this assessment.'}

### Blocked Technique Categories
${results.filter(r => r.status === 'blocked').reduce((acc: Record<string, number>, r) => {
  acc[r.blocked_by || 'Unknown'] = (acc[r.blocked_by || 'Unknown'] || 0) + 1;
  return acc;
}, {} as Record<string, number>)}

---

## MITRE ATT&CK Mapping

### Techniques Attempted vs. Successful

| Tactic | Attempted | Successful | Blocked | Detection Rate |
|--------|-----------|------------|---------|----------------|
${['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration'].map(tactic => {
  const tacticResults = results.filter(r => r.tactic === tactic);
  const attempted = tacticResults.length;
  const successful = tacticResults.filter(r => r.status === 'success').length;
  const blocked = tacticResults.filter(r => r.status === 'blocked').length;
  const rate = attempted > 0 ? Math.round((blocked/attempted)*100) : 0;
  return `| ${tactic} | ${attempted} | ${successful} | ${blocked} | ${rate}% |`;
}).join('\n')}

---

${config.includeRecommendations ? `## Recommendations

### Critical (Immediate Action Required)
${successCount > 0 ? results.filter(r => r.status === 'success').slice(0, 3).map((r, i) => 
  `${i + 1}. **${r.technique_id}**: Implement controls to detect and prevent ${r.ability_name}`
).join('\n') : '1. Continue monitoring and maintaining current security posture'}

### High Priority
1. Review and tune EDR policies based on blocked technique patterns
2. Implement additional logging for techniques that succeeded
3. Conduct follow-up testing after remediation

### Medium Priority
1. Update security awareness training based on successful attack vectors
2. Review network segmentation effectiveness
3. Enhance credential protection mechanisms

### Low Priority
1. Document lessons learned from this engagement
2. Update incident response procedures
3. Schedule follow-up assessment in 90 days

` : ''}

---

## Appendix A: Operation Details

**Operation ID:** ${operations?.[0]?.id || 'databank-complete-001'}  
**Adversary Profile:** Databank_Complete_APT29_VCD_CrowdStrike  
**Total Abilities:** 59  
**Caldera Server:** ${CALDERA_SERVER}  

---

## Appendix B: Timeline of Events

| Timestamp | Event | Status | Details |
|-----------|-------|--------|---------|
${results.map(r => 
  `| ${new Date(r.timestamp).toLocaleString()} | ${r.ability_name} | ${r.status.toUpperCase()} | ${r.status === 'blocked' ? r.blocked_by : r.status === 'success' ? 'Executed successfully' : r.error_message || 'Failed'} |`
).join('\n')}

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | ${new Date().toISOString().split('T')[0]} | ${config.tester} | Initial report |

---

**CONFIDENTIAL - FOR AUTHORIZED RECIPIENTS ONLY**

© ${new Date().getFullYear()} Ace of Cloud - Cutting-Edge Cybersecurity Solutions

*This report was generated using the Ace of Cloud Caldera Command Dashboard.*
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
        a.download = `${config.customerName || 'RedTeam'}_Exercise_Report_${new Date().toISOString().split('T')[0]}.md`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const jsonReport = {
          metadata: {
            customer: config.customerName,
            engagement: config.engagementName,
            date_range: { start: config.startDate, end: config.endDate },
            tester: config.tester,
            generated_at: new Date().toISOString()
          },
          summary: {
            total_techniques: results.length,
            successful: results.filter(r => r.status === 'success').length,
            blocked: results.filter(r => r.status === 'blocked').length,
            failed: results.filter(r => r.status === 'failed').length
          },
          results: results,
          operations: operations,
          adversaries: adversaries?.slice(0, 10)
        };
        const blob = new Blob([JSON.stringify(jsonReport, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${config.customerName || 'RedTeam'}_Exercise_Data_${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
      setIsGenerating(false);
    }, 1000);
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="container py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Link href="/dashboard">
                <Button variant="ghost" size="sm" className="font-display">
                  <ChevronLeft className="w-4 h-4 mr-1" />
                  DASHBOARD
                </Button>
              </Link>
              <div className="h-6 w-px bg-border" />
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-primary" />
                <h1 className="font-display text-xl tracking-wider">REPORT GENERATOR</h1>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPreviewMode(!previewMode)}
              >
                <Eye className="w-4 h-4 mr-1" />
                {previewMode ? 'Edit' : 'Preview'}
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="container py-8">
        <div className="grid lg:grid-cols-3 gap-8">
          {/* Configuration Panel */}
          <div className="space-y-6">
            <div className="bg-card border-2 border-border p-6">
              <h2 className="font-display text-lg mb-4">REPORT CONFIGURATION</h2>
              
              <div className="space-y-4">
                <div>
                  <label className="text-sm text-muted-foreground block mb-1">Customer Name</label>
                  <input
                    type="text"
                    value={config.customerName}
                    onChange={(e) => setConfig({ ...config, customerName: e.target.value })}
                    placeholder="Enter customer name"
                    className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm"
                  />
                </div>

                <div>
                  <label className="text-sm text-muted-foreground block mb-1">Engagement Name</label>
                  <input
                    type="text"
                    value={config.engagementName}
                    onChange={(e) => setConfig({ ...config, engagementName: e.target.value })}
                    className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm text-muted-foreground block mb-1">Start Date</label>
                    <input
                      type="date"
                      value={config.startDate}
                      onChange={(e) => setConfig({ ...config, startDate: e.target.value })}
                      className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm"
                    />
                  </div>
                  <div>
                    <label className="text-sm text-muted-foreground block mb-1">End Date</label>
                    <input
                      type="date"
                      value={config.endDate}
                      onChange={(e) => setConfig({ ...config, endDate: e.target.value })}
                      className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-sm text-muted-foreground block mb-1">Tester Name</label>
                  <input
                    type="text"
                    value={config.tester}
                    onChange={(e) => setConfig({ ...config, tester: e.target.value })}
                    className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm"
                  />
                </div>

                <div>
                  <label className="text-sm text-muted-foreground block mb-1">Scope Description</label>
                  <textarea
                    value={config.scope}
                    onChange={(e) => setConfig({ ...config, scope: e.target.value })}
                    placeholder="Define in-scope systems and networks..."
                    rows={3}
                    className="w-full px-3 py-2 bg-secondary border border-border rounded text-sm"
                  />
                </div>
              </div>
            </div>

            <div className="bg-card border-2 border-border p-6">
              <h2 className="font-display text-lg mb-4">INCLUDE SECTIONS</h2>
              
              <div className="space-y-3">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.includeBlocked}
                    onChange={(e) => setConfig({ ...config, includeBlocked: e.target.checked })}
                    className="rounded"
                  />
                  <Shield className="w-4 h-4 text-yellow-500" />
                  <span className="text-sm">Blocked Attacks (Security Controls)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.includeFailures}
                    onChange={(e) => setConfig({ ...config, includeFailures: e.target.checked })}
                    className="rounded"
                  />
                  <XCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm">Failed Attacks (Errors/Timeouts)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.includeEvidence}
                    onChange={(e) => setConfig({ ...config, includeEvidence: e.target.checked })}
                    className="rounded"
                  />
                  <FileCode className="w-4 h-4 text-blue-500" />
                  <span className="text-sm">Evidence & Output</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.includeRecommendations}
                    onChange={(e) => setConfig({ ...config, includeRecommendations: e.target.checked })}
                    className="rounded"
                  />
                  <Target className="w-4 h-4 text-green-500" />
                  <span className="text-sm">Recommendations</span>
                </label>
              </div>
            </div>

            {/* Quick Stats */}
            <div className="bg-card border-2 border-primary p-6">
              <h2 className="font-display text-lg mb-4">OPERATION SUMMARY</h2>
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Total Techniques</span>
                  <span className="font-bold">{results.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground flex items-center gap-1">
                    <CheckCircle className="w-3 h-3 text-green-500" /> Successful
                  </span>
                  <span className="font-bold text-green-500">{results.filter(r => r.status === 'success').length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground flex items-center gap-1">
                    <Shield className="w-3 h-3 text-yellow-500" /> Blocked
                  </span>
                  <span className="font-bold text-yellow-500">{results.filter(r => r.status === 'blocked').length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground flex items-center gap-1">
                    <XCircle className="w-3 h-3 text-red-500" /> Failed
                  </span>
                  <span className="font-bold text-red-500">{results.filter(r => r.status === 'failed').length}</span>
                </div>
              </div>
            </div>

            {/* Download Buttons */}
            <div className="space-y-2">
              <Button
                className="w-full font-display"
                onClick={() => downloadReport('md')}
                disabled={isGenerating}
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
                className="w-full font-display"
                onClick={() => downloadReport('json')}
                disabled={isGenerating}
              >
                <FileJson className="w-4 h-4 mr-2" />
                DOWNLOAD JSON DATA
              </Button>
            </div>
          </div>

          {/* Preview Panel */}
          <div className="lg:col-span-2">
            <div className="bg-card border-2 border-border">
              <div className="p-4 border-b border-border bg-secondary/30">
                <h2 className="font-display">REPORT PREVIEW</h2>
              </div>
              <div className="p-6 max-h-[800px] overflow-y-auto">
                {previewMode ? (
                  <div className="prose prose-invert max-w-none">
                    <pre className="text-xs whitespace-pre-wrap bg-black/50 p-4 rounded overflow-x-auto">
                      {generateMarkdownReport()}
                    </pre>
                  </div>
                ) : (
                  <div className="space-y-6">
                    {/* Report Header Preview */}
                    <div className="text-center border-b border-border pb-6">
                      <h1 className="text-2xl font-display mb-2">RED TEAM EXERCISE REPORT</h1>
                      <p className="text-muted-foreground">{config.customerName || '[CUSTOMER NAME]'}</p>
                      <p className="text-sm text-muted-foreground">{config.engagementName}</p>
                    </div>

                    {/* Executive Summary Preview */}
                    <div>
                      <h2 className="font-display text-lg mb-4">EXECUTIVE SUMMARY</h2>
                      <div className="grid grid-cols-4 gap-4">
                        <div className="bg-secondary p-4 text-center">
                          <div className="text-2xl font-bold">{results.length}</div>
                          <div className="text-xs text-muted-foreground">TOTAL</div>
                        </div>
                        <div className="bg-green-500/20 p-4 text-center">
                          <div className="text-2xl font-bold text-green-500">
                            {results.filter(r => r.status === 'success').length}
                          </div>
                          <div className="text-xs text-muted-foreground">SUCCESS</div>
                        </div>
                        <div className="bg-yellow-500/20 p-4 text-center">
                          <div className="text-2xl font-bold text-yellow-500">
                            {results.filter(r => r.status === 'blocked').length}
                          </div>
                          <div className="text-xs text-muted-foreground">BLOCKED</div>
                        </div>
                        <div className="bg-red-500/20 p-4 text-center">
                          <div className="text-2xl font-bold text-red-500">
                            {results.filter(r => r.status === 'failed').length}
                          </div>
                          <div className="text-xs text-muted-foreground">FAILED</div>
                        </div>
                      </div>
                    </div>

                    {/* Blocked Attacks Preview */}
                    {config.includeBlocked && (
                      <div>
                        <h2 className="font-display text-lg mb-4 flex items-center gap-2">
                          <Shield className="w-5 h-5 text-yellow-500" />
                          BLOCKED ATTACKS
                        </h2>
                        <div className="space-y-2">
                          {results.filter(r => r.status === 'blocked').map((r, i) => (
                            <div key={i} className="bg-yellow-500/10 border border-yellow-500/30 p-3 rounded">
                              <div className="flex items-center justify-between mb-2">
                                <span className="font-medium">{r.technique_id} - {r.ability_name}</span>
                                <Badge className="bg-yellow-500/20 text-yellow-500">BLOCKED</Badge>
                              </div>
                              <div className="text-sm text-muted-foreground">
                                <strong>Blocked by:</strong> {r.blocked_by}
                              </div>
                              {r.detection_details && (
                                <div className="text-sm text-yellow-500 mt-1">
                                  {r.detection_details}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Successful Attacks Preview */}
                    <div>
                      <h2 className="font-display text-lg mb-4 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-red-500" />
                        SUCCESSFUL ATTACKS (SECURITY GAPS)
                      </h2>
                      <div className="space-y-2">
                        {results.filter(r => r.status === 'success').map((r, i) => (
                          <div key={i} className="bg-red-500/10 border border-red-500/30 p-3 rounded">
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-medium">{r.technique_id} - {r.ability_name}</span>
                              <Badge className="bg-red-500/20 text-red-500">SUCCESS</Badge>
                            </div>
                            <div className="text-sm text-muted-foreground">
                              <strong>Agent:</strong> {r.agent} | <strong>Duration:</strong> {r.duration_seconds}s
                            </div>
                            {r.output && (
                              <div className="text-sm text-green-500 mt-1 font-mono">
                                {r.output}
                              </div>
                            )}
                          </div>
                        ))}
                        {results.filter(r => r.status === 'success').length === 0 && (
                          <div className="text-center py-8 text-muted-foreground">
                            <CheckCircle className="w-12 h-12 mx-auto mb-2 text-green-500" />
                            <p>No successful attacks - all techniques were blocked or failed!</p>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Footer */}
                    <div className="border-t border-border pt-6 text-center text-sm text-muted-foreground">
                      <p>Report prepared by {config.tester}</p>
                      <p>© {new Date().getFullYear()} Ace of Cloud - Cutting-Edge Cybersecurity Solutions</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
