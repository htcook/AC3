import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useMemo } from 'react';
import { Link } from 'wouter';
import AppShell from "@/components/AppShell";
import { Button } from '@/components/ui/button';
import { trpc } from '@/lib/trpc';
import { toast } from 'sonner';
import {
  FileText, Download, Eye, Calendar, Building, User, Shield, Target,
  CheckCircle, XCircle, AlertTriangle, Clock, Loader2, ChevronDown,
  ChevronUp, Sparkles, Globe, Mail, Lock, BarChart3, Briefcase,
  Server, Cloud, Network, Copy, ExternalLink, RefreshCw, Zap, Trash2
} from 'lucide-react';
import { Streamdown } from 'streamdown';

const CLIENT_TYPES = [
  { value: 'msp', label: 'Managed Service Provider (MSP)', icon: <Server className="w-4 h-4" />, desc: 'Multi-tenant security assessments for MSP client portfolios' },
  { value: 'enterprise', label: 'Enterprise Organization', icon: <Building className="w-4 h-4" />, desc: 'Corporate security posture and compliance reporting' },
  { value: 'saas', label: 'SaaS Provider', icon: <Cloud className="w-4 h-4" />, desc: 'Application security, API exposure, and data protection' },
  { value: 'paas', label: 'PaaS Provider', icon: <Network className="w-4 h-4" />, desc: 'Platform security, container isolation, and tenant boundaries' },
  { value: 'iaas', label: 'IaaS Provider', icon: <Server className="w-4 h-4" />, desc: 'Infrastructure security, hypervisor hardening, and network segmentation' },
  { value: 'mixed_hosting', label: 'Mixed Hosting Provider', icon: <Globe className="w-4 h-4" />, desc: 'Combined hosting environments with shared and dedicated resources' },
  { value: 'other', label: 'Other Organization', icon: <Briefcase className="w-4 h-4" />, desc: 'Custom security assessment reporting' },
] as const;

const REPORT_TYPES = [
  { value: 'executive_summary', label: 'Executive Summary', icon: <BarChart3 className="w-4 h-4" />, desc: 'High-level findings for C-level stakeholders', color: 'text-blue-400 border-blue-500/30' },
  { value: 'technical_detail', label: 'Technical Detail', icon: <Shield className="w-4 h-4" />, desc: 'Full technical findings with remediation steps', color: 'text-red-400 border-red-500/30' },
  { value: 'compliance', label: 'Compliance Report', icon: <CheckCircle className="w-4 h-4" />, desc: 'NIST, ISO 27001, SOC 2, HIPAA, PCI DSS mapping', color: 'text-green-400 border-green-500/30' },
  { value: 'phishing_results', label: 'Phishing Results', icon: <Mail className="w-4 h-4" />, desc: 'Campaign metrics, click rates, and credential captures', color: 'text-orange-400 border-orange-500/30' },
  { value: 'osint_assessment', label: 'OSINT Assessment', icon: <Globe className="w-4 h-4" />, desc: 'Domain security, typosquats, and attack surface', color: 'text-cyan-400 border-cyan-500/30' },
  { value: 'full_engagement', label: 'Full Engagement', icon: <FileText className="w-4 h-4" />, desc: 'Comprehensive report covering all assessment areas', color: 'text-purple-400 border-purple-500/30' },
  { value: 'purple_team', label: 'Purple Team Exercise', icon: <Target className="w-4 h-4" />, desc: 'Adversary emulation results, detection coverage, and SOC performance', color: 'text-violet-400 border-violet-500/30' },
  { value: 'red_team_assessment', label: 'Red Team Assessment', icon: <Zap className="w-4 h-4" />, desc: 'Attack paths, kill chain analysis, and remediation steps', color: 'text-rose-400 border-rose-500/30' },
  { value: 'detection_gap_analysis', label: 'Detection Gap Analysis', icon: <Lock className="w-4 h-4" />, desc: 'MITRE ATT&CK technique coverage with Sigma/YARA rules for gaps', color: 'text-amber-400 border-amber-500/30' },
  { value: 'pentest_assessment', label: 'Pentest Assessment (Pipeline)', icon: <Shield className="w-4 h-4" />, desc: '13-section structured report with CVSS vectors, MITRE/NIST/OWASP mapping, Mermaid diagrams, and detection rules', color: 'text-emerald-400 border-emerald-500/30' },
] as const;

const BRANDING_COLORS = [
  { value: '#213555', label: 'Ace of Cloud Navy', className: 'bg-[#213555]' },
  { value: '#2563eb', label: 'Corporate Blue', className: 'bg-blue-600' },
  { value: '#059669', label: 'Security Green', className: 'bg-emerald-600' },
  { value: '#7c3aed', label: 'Purple', className: 'bg-violet-600' },
  { value: '#ea580c', label: 'Orange', className: 'bg-orange-600' },
  { value: '#0891b2', label: 'Cyan', className: 'bg-cyan-600' },
];

export default function ReportGenerator() {
  const [step, setStep] = useState<'select' | 'configure' | 'generating' | 'preview'>('select');
  const [selectedEngagement, setSelectedEngagement] = useState<number | null>(null);
  const [reportType, setReportType] = useState<string>('full_engagement');
  const [clientType, setClientType] = useState<string>('enterprise');
  const [title, setTitle] = useState('');
  const [preparedFor, setPreparedFor] = useState('');
  const [preparedBy, setPreparedBy] = useState('');
  const [brandingColor, setBrandingColor] = useState('#dc2626');
  const [generatedReport, setGeneratedReport] = useState<{ id: number; url: string | null; content: string } | null>(null);
  const [expandedReport, setExpandedReport] = useState<number | null>(null);

  // Data queries
  const { data: engagements } = trpc.engagements.list.useQuery();
  const { data: existingReports, refetch: refetchReports } = trpc.reports.list.useQuery({});
  const generateReport = trpc.reports.generate.useMutation();
  const deleteReportMut = trpc.reports.delete.useMutation({
    onSuccess: () => { toast.success('Report deleted'); refetchReports(); },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const selectedEng = useMemo(() => {
    if (!selectedEngagement || !engagements) return null;
    return engagements.find((e: any) => e.id === selectedEngagement);
  }, [selectedEngagement, engagements]);

  const handleGenerate = async () => {
    if (!selectedEngagement) { toast.error('Select an engagement first'); return; }
    if (!title.trim()) { toast.error('Enter a report title'); return; }

    setStep('generating');
    try {
      const result = await generateReport.mutateAsync({
        engagementId: selectedEngagement,
        reportType: reportType as any,
        clientType: clientType as any,
        title: title.trim(),
        preparedFor: preparedFor || undefined,
        preparedBy: preparedBy || undefined,
        brandingColor,
      });
      setGeneratedReport(result);
      setStep('preview');
      refetchReports();
      toast.success('Report generated successfully!');
    } catch (err: any) {
      toast.error(sanitizeErrorForToast(err));
      setStep('configure');
    }
  };

  // Track which report is currently exporting PDF (per-report state)
  const [exportingPdfId, setExportingPdfId] = useState<number | null>(null);
  const [exportingDocxId, setExportingDocxId] = useState<number | null>(null);

  const exportDocxMut = trpc.reports.exportDocx.useMutation({
    onSuccess: (data) => {
      setExportingDocxId(null);
      if (data.url) {
        const a = document.createElement('a');
        a.href = data.url;
        a.download = data.filename || 'report.docx';
        a.target = '_blank';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        toast.success('DOCX report downloaded');
      }
    },
    onError: (err) => {
      setExportingDocxId(null);
      toast.error('DOCX export failed: ' + err.message);
    },
  });

  const handleExportDocx = (reportId: number) => {
    setExportingDocxId(reportId);
    exportDocxMut.mutate({ reportId });
  };

  const exportPdfMut = trpc.reports.exportPdf.useMutation({
    onSuccess: (data) => {
      setExportingPdfId(null);
      if (data.url) {
        // Direct download via anchor element — no popup blocker issues
        const a = document.createElement('a');
        a.href = data.url;
        a.download = data.filename || 'report.pdf';
        a.target = '_blank';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        const isPdf = data.filename?.endsWith('.pdf') || data.url.endsWith('.pdf');
        toast.success(isPdf ? 'PDF report downloaded' : 'Report downloaded (HTML fallback)');
      }
    },
    onError: (err) => {
      setExportingPdfId(null);
      toast.error('Export failed: ' + err.message);
    },
  });

  const handleExportPdf = (reportId: number) => {
    setExportingPdfId(reportId);
    exportPdfMut.mutate({ reportId });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  return (
    <AppShell>
      <div className="p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-xl sm:text-2xl font-display tracking-wider">REPORT GENERATOR</h1>
            <p className="text-sm text-muted-foreground mt-1">Generate branded security assessment reports for any client type</p>
          </div>
          <div className="flex gap-2">
            {step !== 'select' && step !== 'generating' && (
              <Button variant="outline" size="sm" className="font-display tracking-wider" onClick={() => setStep('select')}>
                NEW REPORT
              </Button>
            )}
          </div>
        </div>

        {/* Step 1: Select Engagement & Report Type */}
        {step === 'select' && (
          <div className="space-y-6">
            {/* Engagement Selection */}
            <div className="bg-card border-2 border-border p-4 sm:p-6">
              <h2 className="font-display tracking-wider text-sm text-muted-foreground mb-4">SELECT ENGAGEMENT</h2>
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {engagements?.filter((e: any) => e.status === 'active' || e.status === 'completed' || e.status === 'planning').map((eng: any) => (
                  <button
                    key={eng.id}
                    onClick={() => {
                      setSelectedEngagement(eng.id);
                      setPreparedFor(eng.customerName);
                      setTitle(`${eng.name} - Security Assessment Report`);
                    }}
                    className={`text-left p-3 border-2 transition-all ${
                      selectedEngagement === eng.id
                        ? 'border-primary bg-primary/10'
                        : 'border-border hover:border-primary/50'
                    }`}
                  >
                    <div className="font-display text-sm tracking-wider truncate">{eng.name}</div>
                    <div className="text-xs text-muted-foreground mt-1">{eng.customerName}</div>
                    <div className="flex items-center gap-2 mt-2">
                      <span className={`text-[10px] px-2 py-0.5 font-display tracking-wider ${
                        eng.status === 'active' ? 'bg-green-500/20 text-green-400' :
                        eng.status === 'completed' ? 'bg-blue-500/20 text-blue-400' :
                        'bg-gray-500/20 text-gray-400'
                      }`}>{eng.status?.toUpperCase()}</span>
                      {eng.targetDomain && (
                        <span className="text-[10px] text-muted-foreground font-mono">{eng.targetDomain}</span>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Client Type Selection */}
            <div className="bg-card border-2 border-border p-4 sm:p-6">
              <h2 className="font-display tracking-wider text-sm text-muted-foreground mb-4">CLIENT TYPE</h2>
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                {CLIENT_TYPES.map(ct => (
                  <button
                    key={ct.value}
                    onClick={() => setClientType(ct.value)}
                    className={`text-left p-3 border-2 transition-all ${
                      clientType === ct.value
                        ? 'border-primary bg-primary/10'
                        : 'border-border hover:border-primary/50'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      {ct.icon}
                      <span className="font-display text-xs tracking-wider">{ct.label}</span>
                    </div>
                    <p className="text-[10px] text-muted-foreground">{ct.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* Report Type Selection */}
            <div className="bg-card border-2 border-border p-4 sm:p-6">
              <h2 className="font-display tracking-wider text-sm text-muted-foreground mb-4">REPORT TYPE</h2>
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {REPORT_TYPES.map(rt => (
                  <button
                    key={rt.value}
                    onClick={() => setReportType(rt.value)}
                    className={`text-left p-4 border-2 transition-all ${
                      reportType === rt.value
                        ? `${rt.color} bg-primary/5`
                        : 'border-border hover:border-primary/50'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      {rt.icon}
                      <span className="font-display text-sm tracking-wider">{rt.label}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">{rt.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            <div className="flex justify-end">
              <Button
                className="font-display tracking-wider bg-primary hover:bg-primary/90"
                onClick={() => {
                  if (!selectedEngagement) { toast.error('Select an engagement first'); return; }
                  setStep('configure');
                }}
                disabled={!selectedEngagement}
              >
                CONFIGURE REPORT <ChevronDown className="w-4 h-4 ml-2" />
              </Button>
            </div>
          </div>
        )}

        {/* Step 2: Configure Report Details */}
        {step === 'configure' && (
          <div className="space-y-6">
            <div className="bg-card border-2 border-border p-4 sm:p-6 space-y-4">
              <h2 className="font-display tracking-wider text-sm text-muted-foreground mb-2">REPORT CONFIGURATION</h2>

              {/* Selected engagement summary */}
              {selectedEng && (
                <div className="bg-background border border-border p-3 flex flex-wrap items-center gap-4 text-xs">
                  <div><span className="text-muted-foreground">Engagement:</span> <span className="font-display">{selectedEng.name}</span></div>
                  <div><span className="text-muted-foreground">Client:</span> <span>{selectedEng.customerName}</span></div>
                  <div><span className="text-muted-foreground">Domain:</span> <span className="font-mono">{selectedEng.targetDomain || 'N/A'}</span></div>
                  <div><span className="text-muted-foreground">Type:</span> <span className="font-display">{CLIENT_TYPES.find(c => c.value === clientType)?.label}</span></div>
                  <div><span className="text-muted-foreground">Report:</span> <span className="font-display">{REPORT_TYPES.find(r => r.value === reportType)?.label}</span></div>
                </div>
              )}

              <div className="grid sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">REPORT TITLE</label>
                  <input
                    value={title}
                    onChange={e => setTitle(e.target.value)}
                    className="w-full px-3 py-2 bg-background border-2 border-border text-sm focus:border-primary outline-none"
                    placeholder="Security Assessment Report"
                  />
                </div>
                <div>
                  <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">PREPARED FOR</label>
                  <input
                    value={preparedFor}
                    onChange={e => setPreparedFor(e.target.value)}
                    className="w-full px-3 py-2 bg-background border-2 border-border text-sm focus:border-primary outline-none"
                    placeholder="Client Organization Name"
                  />
                </div>
                <div>
                  <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">PREPARED BY</label>
                  <input
                    value={preparedBy}
                    onChange={e => setPreparedBy(e.target.value)}
                    className="w-full px-3 py-2 bg-background border-2 border-border text-sm focus:border-primary outline-none"
                    placeholder="Your Name"
                  />
                </div>
                <div>
                  <label className="text-xs font-display tracking-wider text-muted-foreground mb-1 block">BRANDING COLOR</label>
                  <div className="flex gap-2 flex-wrap">
                    {BRANDING_COLORS.map(c => (
                      <button
                        key={c.value}
                        onClick={() => setBrandingColor(c.value)}
                        className={`w-8 h-8 ${c.className} border-2 transition-all ${
                          brandingColor === c.value ? 'border-white scale-110' : 'border-transparent'
                        }`}
                        title={c.label}
                      />
                    ))}
                  </div>
                </div>
              </div>
            </div>

            <div className="flex justify-between">
              <Button variant="outline" className="font-display tracking-wider" onClick={() => setStep('select')}>
                BACK
              </Button>
              <Button
                className="font-display tracking-wider bg-primary hover:bg-primary/90"
                onClick={handleGenerate}
                disabled={generateReport.isPending}
              >
                <Sparkles className="w-4 h-4 mr-2" />
                GENERATE REPORT
              </Button>
            </div>
          </div>
        )}

        {/* Step 3: Generating */}
        {step === 'generating' && (
          <div className="bg-card border-2 border-border p-8 sm:p-12 text-center">
            <Loader2 className="w-12 h-12 animate-spin text-primary mx-auto mb-4" />
            <h2 className="font-display tracking-wider text-lg mb-2">GENERATING REPORT</h2>
            <p className="text-sm text-muted-foreground">
              AI is analyzing engagement data, OSINT findings, campaign results, and generating a comprehensive
              {' '}{REPORT_TYPES.find(r => r.value === reportType)?.label.toLowerCase()} for your
              {' '}{CLIENT_TYPES.find(c => c.value === clientType)?.label.toLowerCase()} client...
            </p>
            <div className="mt-6 flex justify-center gap-2 flex-wrap">
              {(reportType === 'pentest_assessment'
                ? ['Ingesting recon data', 'Translating signals (CVSS/MITRE/NIST)', 'Generating exploit narratives', 'Calculating risk matrix', 'Producing finding cards', 'Building visualizations']
                : ['Gathering data', 'Analyzing findings', 'Writing report', 'Formatting output']
              ).map((s, i) => (
                <div key={i} className="flex items-center gap-1 text-[10px] text-muted-foreground">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" style={{ animationDelay: `${i * 0.3}s` }} />
                  {s}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Step 4: Preview */}
        {step === 'preview' && generatedReport && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-green-400" />
                <span className="font-display tracking-wider text-sm">REPORT GENERATED SUCCESSFULLY</span>
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="font-display tracking-wider"
                  onClick={() => copyToClipboard(generatedReport.content)}
                >
                  <Copy className="w-4 h-4 mr-2" /> COPY
                </Button>
                {generatedReport.url && (
                  <a href={generatedReport.url} target="_blank" rel="noopener noreferrer">
                    <Button variant="outline" size="sm" className="font-display tracking-wider">
                      <Download className="w-4 h-4 mr-2" /> MARKDOWN
                    </Button>
                  </a>
                )}
                {generatedReport.id && (
                  <Button
                    size="sm"
                    className="font-display tracking-wider bg-primary hover:bg-primary/90"
                    onClick={() => handleExportPdf(generatedReport.id)}
                    disabled={exportingPdfId === generatedReport.id}
                  >
                    {exportingPdfId === generatedReport.id ? (
                      <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> EXPORTING...</>
                    ) : (
                      <><FileText className="w-4 h-4 mr-2" /> EXPORT PDF</>
                    )}
                  </Button>
                )}
                {generatedReport.id && (
                  <Button
                    size="sm"
                    variant="outline"
                    className="font-display tracking-wider"
                    onClick={() => handleExportDocx(generatedReport.id)}
                    disabled={exportingDocxId === generatedReport.id}
                  >
                    {exportingDocxId === generatedReport.id ? (
                      <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> EXPORTING...</>
                    ) : (
                      <><FileText className="w-4 h-4 mr-2" /> EXPORT DOCX</>
                    )}
                  </Button>
                )}
              </div>
            </div>
            <div className="bg-card border-2 border-border p-4 sm:p-6 max-h-[70vh] overflow-y-auto">
              <div className="prose prose-invert prose-sm max-w-none">
                <Streamdown>{generatedReport.content}</Streamdown>
              </div>
            </div>
          </div>
        )}

        {/* Previous Reports */}
        {existingReports && existingReports.length > 0 && (
          <div className="bg-card border-2 border-border p-4 sm:p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-display tracking-wider text-sm text-muted-foreground">PREVIOUS REPORTS</h2>
              <Button variant="ghost" size="sm" onClick={() => refetchReports()}>
                <RefreshCw className="w-4 h-4" />
              </Button>
            </div>
            <div className="space-y-2">
              {existingReports.map((report: any) => (
                <div key={report.id} className="border border-border p-3 hover:border-primary/30 transition-colors">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-display text-sm tracking-wider truncate">{report.title}</span>
                        <span className={`text-[10px] px-2 py-0.5 font-display tracking-wider ${
                          report.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                          report.status === 'generating' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-red-500/20 text-red-400'
                        }`}>{report.status?.toUpperCase()}</span>
                        <span className="text-[10px] px-2 py-0.5 bg-accent/50 text-muted-foreground font-display">
                          {report.reportType?.replace(/_/g, ' ').toUpperCase()}
                        </span>
                        <span className="text-[10px] px-2 py-0.5 bg-accent/50 text-muted-foreground font-display">
                          {report.clientType?.toUpperCase()}
                        </span>
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">
                        {report.preparedFor && <span>For: {report.preparedFor} · </span>}
                        {report.preparedBy && <span>By: {report.preparedBy} · </span>}
                        {report.generatedAt && <span>{new Date(report.generatedAt).toLocaleDateString()}</span>}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      {report.reportUrl && (
                        <a href={report.reportUrl} target="_blank" rel="noopener noreferrer">
                          <Button variant="ghost" size="sm" className="h-7 text-[10px] font-display">
                            <Download className="w-3.5 h-3.5 mr-1" /> MD
                          </Button>
                        </a>
                      )}
                      {report.status === 'completed' && report.reportUrl && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-[10px] font-display"
                          onClick={() => handleExportPdf(report.id)}
                          disabled={exportingPdfId === report.id}
                        >
                          {exportingPdfId === report.id ? (
                            <><Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" /> PDF</>
                          ) : (
                            <><FileText className="w-3.5 h-3.5 mr-1" /> PDF</>
                          )}
                        </Button>
                      )}
                      {report.status === 'completed' && report.reportUrl && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-[10px] font-display"
                          onClick={() => handleExportDocx(report.id)}
                          disabled={exportingDocxId === report.id}
                        >
                          {exportingDocxId === report.id ? (
                            <><Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" /> DOCX</>
                          ) : (
                            <><FileText className="w-3.5 h-3.5 mr-1" /> DOCX</>
                          )}
                        </Button>
                      )}
                      {report.status === 'completed' && !report.reportUrl && (
                        <>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-[10px] font-display text-yellow-400 hover:text-yellow-300"
                            onClick={() => {
                              toast.info('Content was lost during generation. Please delete and regenerate.');
                            }}
                          >
                            <AlertTriangle className="w-3.5 h-3.5 mr-1" /> No Content
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-[10px] font-display text-red-400 hover:text-red-300"
                            onClick={() => {
                              if (confirm('Delete this orphaned report?')) {
                                deleteReportMut.mutate({ id: report.id });
                              }
                            }}
                          >
                            <Trash2 className="w-3.5 h-3.5 mr-1" /> Delete
                          </Button>
                        </>
                      )}
                      {report.status === 'failed' && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-[10px] font-display text-red-400 hover:text-red-300"
                          onClick={() => {
                            if (confirm('Delete this failed report?')) {
                              deleteReportMut.mutate({ id: report.id });
                            }
                          }}
                          disabled={deleteReportMut.isPending}
                        >
                          <XCircle className="w-3.5 h-3.5 mr-1" /> DELETE
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 text-[10px] font-display"
                        onClick={() => setExpandedReport(expandedReport === report.id ? null : report.id)}
                      >
                        <Eye className="w-3.5 h-3.5 mr-1" /> {expandedReport === report.id ? 'HIDE' : 'PREVIEW'}
                      </Button>
                    </div>
                  </div>
                  {expandedReport === report.id && report.reportUrl && (
                    <div className="mt-3 p-3 bg-background border border-border text-xs">
                      <p className="text-muted-foreground">Report available at: <a href={report.reportUrl} className="text-primary hover:underline" target="_blank" rel="noopener noreferrer">{report.reportUrl}</a></p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
