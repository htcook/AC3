import { useState, useEffect, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { useRoute, useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  ArrowLeft, Save, Eye, Palette, Code, Type, Image,
  Plus, Trash2, GripVertical, Copy, ChevronDown, ChevronUp,
  FileText, Shield, Target, Globe, Loader2, Wand2
} from "lucide-react";
import AppShell from "@/components/AppShell";

// Available template variables by report type
const TEMPLATE_VARIABLES: Record<string, Array<{ key: string; label: string; description: string }>> = {
  common: [
    { key: "client_name", label: "Client Name", description: "Name of the client organization" },
    { key: "report_date", label: "Report Date", description: "Date the report was generated" },
    { key: "report_title", label: "Report Title", description: "Title of the report" },
    { key: "assessor_name", label: "Assessor Name", description: "Name of the security assessor" },
    { key: "engagement_id", label: "Engagement ID", description: "Unique engagement identifier" },
    { key: "scope", label: "Scope", description: "Engagement scope description" },
    { key: "executive_summary", label: "Executive Summary", description: "High-level findings summary" },
    { key: "methodology", label: "Methodology", description: "Testing methodology used" },
    { key: "recommendations", label: "Recommendations", description: "Remediation recommendations" },
  ],
  di: [
    { key: "domain", label: "Target Domain", description: "Primary domain scanned" },
    { key: "total_assets", label: "Total Assets", description: "Number of assets discovered" },
    { key: "risk_score", label: "Risk Score", description: "Overall risk score (0-100)" },
    { key: "critical_findings", label: "Critical Findings", description: "Number of critical findings" },
    { key: "high_findings", label: "High Findings", description: "Number of high findings" },
    { key: "medium_findings", label: "Medium Findings", description: "Number of medium findings" },
    { key: "low_findings", label: "Low Findings", description: "Number of low findings" },
    { key: "subdomains_table", label: "Subdomains Table", description: "HTML table of discovered subdomains" },
    { key: "technologies_table", label: "Technologies Table", description: "HTML table of detected technologies" },
    { key: "certificates_table", label: "Certificates Table", description: "HTML table of SSL certificates" },
    { key: "dns_records_table", label: "DNS Records Table", description: "HTML table of DNS records" },
    { key: "recon_coverage", label: "Recon Coverage", description: "Percentage of recon coverage" },
  ],
  vulnerability: [
    { key: "total_vulns", label: "Total Vulnerabilities", description: "Total number of vulnerabilities found" },
    { key: "critical_count", label: "Critical Count", description: "Number of critical vulnerabilities" },
    { key: "high_count", label: "High Count", description: "Number of high vulnerabilities" },
    { key: "medium_count", label: "Medium Count", description: "Number of medium vulnerabilities" },
    { key: "low_count", label: "Low Count", description: "Number of low vulnerabilities" },
    { key: "cvss_avg", label: "CVSS Average", description: "Average CVSS score" },
    { key: "cvss_max", label: "CVSS Maximum", description: "Maximum CVSS score" },
    { key: "vulnerabilities_table", label: "Vulnerabilities Table", description: "HTML table of all vulnerabilities" },
    { key: "affected_hosts_table", label: "Affected Hosts Table", description: "HTML table of affected hosts" },
    { key: "remediation_priority", label: "Remediation Priority", description: "Prioritized remediation list" },
  ],
  pentest: [
    { key: "total_vulns", label: "Total Vulnerabilities", description: "Total vulnerabilities found" },
    { key: "exploits_attempted", label: "Exploits Attempted", description: "Number of exploits attempted" },
    { key: "exploits_successful", label: "Exploits Successful", description: "Number of successful exploits" },
    { key: "credentials_found", label: "Credentials Found", description: "Number of credentials discovered" },
    { key: "attack_path", label: "Attack Path", description: "Description of the attack path" },
    { key: "initial_access", label: "Initial Access", description: "How initial access was obtained" },
    { key: "privilege_escalation", label: "Privilege Escalation", description: "Privilege escalation details" },
    { key: "lateral_movement", label: "Lateral Movement", description: "Lateral movement details" },
    { key: "data_exfiltration", label: "Data Exfiltration", description: "Data exfiltration details" },
    { key: "findings_table", label: "Findings Table", description: "HTML table of all findings" },
    { key: "timeline_table", label: "Timeline Table", description: "HTML table of attack timeline" },
  ],
  redteam: [
    { key: "objectives", label: "Objectives", description: "Red team objectives" },
    { key: "objectives_achieved", label: "Objectives Achieved", description: "Number of objectives achieved" },
    { key: "detection_rate", label: "Detection Rate", description: "Percentage of actions detected by blue team" },
    { key: "dwell_time", label: "Dwell Time", description: "Average dwell time before detection" },
    { key: "ttps_used", label: "TTPs Used", description: "MITRE ATT&CK TTPs employed" },
    { key: "initial_access_vector", label: "Initial Access Vector", description: "How initial access was gained" },
    { key: "persistence_mechanisms", label: "Persistence Mechanisms", description: "Persistence methods used" },
    { key: "c2_infrastructure", label: "C2 Infrastructure", description: "Command and control details" },
    { key: "evasion_techniques", label: "Evasion Techniques", description: "Detection evasion methods" },
    { key: "impact_assessment", label: "Impact Assessment", description: "Business impact assessment" },
    { key: "blue_team_response", label: "Blue Team Response", description: "Blue team response analysis" },
    { key: "attack_narrative", label: "Attack Narrative", description: "Full attack narrative" },
  ],
};

// Report type to variable category mapping
const TYPE_TO_CATEGORY: Record<string, string> = {
  engagement: "pentest",
  executive: "common",
  compliance: "common",
  vulnerability: "vulnerability",
  custom: "common",
};

export default function ReportTemplateEditor() {
  const [, params] = useRoute("/report-templates/:id/edit");
  const [, setLocation] = useLocation();
  const templateId = params?.id ? parseInt(params.id) : null;

  // Editor state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [templateType, setTemplateType] = useState<string>("custom");
  const [templateContent, setTemplateContent] = useState("");
  const [headerHtml, setHeaderHtml] = useState("");
  const [footerHtml, setFooterHtml] = useState("");
  const [cssOverrides, setCssOverrides] = useState("");
  const [logoUrl, setLogoUrl] = useState("");
  const [primaryColor, setPrimaryColor] = useState("#00E5CC");
  const [isDefault, setIsDefault] = useState(false);
  const [activeTab, setActiveTab] = useState("content");
  const [showPreview, setShowPreview] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [previewSource, setPreviewSource] = useState<string>("sample");
  const [realData, setRealData] = useState<Record<string, string> | null>(null);

  // Load template data
  const templateQuery = trpc.reportTemplates.get.useQuery(
    { id: templateId! },
    { enabled: !!templateId }
  );

  const utils = trpc.useUtils();

  const updateMutation = trpc.reportTemplates.update.useMutation({
    onSuccess: () => {
      toast.success("Template saved successfully");
      utils.reportTemplates.list.invalidate();
      setIsSaving(false);
    },
    onError: (err) => {
      toast.error(`Failed to save: ${err.message}`);
      setIsSaving(false);
    },
  });

  const createMutation = trpc.reportTemplates.create.useMutation({
    onSuccess: (data) => {
      toast.success("Template created successfully");
      utils.reportTemplates.list.invalidate();
      setIsSaving(false);
      setLocation(`/report-templates/${data.id}/edit`);
    },
    onError: (err) => {
      toast.error(`Failed to create: ${err.message}`);
      setIsSaving(false);
    },
  });

  // Populate form when template loads
  useEffect(() => {
    if (templateQuery.data) {
      const t = templateQuery.data;
      setName(t.name || "");
      setDescription(t.description || "");
      setTemplateType(t.templateType || "custom");
      setTemplateContent(t.templateContent || "");
      setHeaderHtml(t.headerHtml || "");
      setFooterHtml(t.footerHtml || "");
      setCssOverrides(t.cssOverrides || "");
      setLogoUrl(t.logoUrl || "");
      setPrimaryColor(t.primaryColor || "#00E5CC");
      setIsDefault(t.isDefault || false);
    }
  }, [templateQuery.data]);

  // Get available variables for current template type
  const availableVariables = useMemo(() => {
    const category = TYPE_TO_CATEGORY[templateType] || "common";
    const commonVars = TEMPLATE_VARIABLES.common;
    const typeVars = TEMPLATE_VARIABLES[category] || [];
    // Deduplicate
    const seen = new Set(commonVars.map(v => v.key));
    const unique = [...commonVars, ...typeVars.filter(v => !seen.has(v.key))];
    return unique;
  }, [templateType]);

  // Insert variable at cursor position
  const insertVariable = useCallback((key: string) => {
    const textarea = document.getElementById("template-content-editor") as HTMLTextAreaElement;
    if (textarea) {
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const text = templateContent;
      const before = text.substring(0, start);
      const after = text.substring(end);
      const newContent = `${before}{{${key}}}${after}`;
      setTemplateContent(newContent);
      // Restore cursor position
      setTimeout(() => {
        textarea.focus();
        textarea.selectionStart = textarea.selectionEnd = start + key.length + 4;
      }, 0);
    } else {
      setTemplateContent(prev => prev + `{{${key}}}`);
    }
    toast.success(`Inserted {{${key}}}`);
  }, [templateContent]);

  // Save handler
  const handleSave = () => {
    setIsSaving(true);
    const data = {
      name,
      description,
      templateType: templateType as any,
      templateContent,
      headerHtml: headerHtml || undefined,
      footerHtml: footerHtml || undefined,
      cssOverrides: cssOverrides || undefined,
      logoUrl: logoUrl || undefined,
      primaryColor: primaryColor || undefined,
      isDefault,
    };

    if (templateId) {
      updateMutation.mutate({ id: templateId, ...data });
    } else {
      createMutation.mutate(data);
    }
  };

  // Generate preview HTML
  const previewHtml = useMemo(() => {
    let html = templateContent;
    // Replace variables with real data or sample data
    const sampleData: Record<string, string> = realData || {
      client_name: "AceofCloud Security",
      report_date: new Date().toLocaleDateString(),
      report_title: `${name || "Sample Report"}`,
      assessor_name: "Security Analyst",
      engagement_id: "AC3-2024-001",
      scope: "External network penetration test of *.example.com",
      executive_summary: "During the assessment, several critical vulnerabilities were identified that could allow unauthorized access to sensitive systems.",
      methodology: "OWASP Testing Guide v4, PTES, NIST SP 800-115",
      recommendations: "Implement input validation, patch outdated software, enable MFA on all admin accounts.",
      domain: "example.com",
      total_assets: "47",
      risk_score: "72",
      critical_findings: "3",
      high_findings: "7",
      medium_findings: "12",
      low_findings: "5",
      total_vulns: "27",
      critical_count: "3",
      high_count: "7",
      medium_count: "12",
      low_count: "5",
      cvss_avg: "6.8",
      cvss_max: "9.8",
      exploits_attempted: "15",
      exploits_successful: "8",
      credentials_found: "4",
      objectives: "Gain domain admin access, exfiltrate PII data, establish persistent C2",
      objectives_achieved: "2/3",
      detection_rate: "33%",
      dwell_time: "72 hours",
      recon_coverage: "87%",
    };

    for (const [key, value] of Object.entries(sampleData)) {
      html = html.replace(new RegExp(`\\{\\{\\s*${key}\\s*\\}\\}`, "g"), value);
    }

    // Wrap with CSS overrides and branding
    const fullHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: 'Inter', sans-serif; margin: 0; padding: 20px; background: #fff; color: #1a1a2e; }
          .report-header { border-bottom: 3px solid ${primaryColor}; padding-bottom: 16px; margin-bottom: 24px; }
          .report-header .logo { max-height: 40px; }
          h1, h2, h3 { color: #1a1a2e; }
          h1 { border-bottom: 2px solid ${primaryColor}; padding-bottom: 8px; }
          table { width: 100%; border-collapse: collapse; margin: 16px 0; }
          th { background: ${primaryColor}20; color: #1a1a2e; padding: 8px 12px; text-align: left; font-weight: 600; }
          td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }
          .stat-box { display: inline-block; padding: 12px 20px; margin: 4px; border-radius: 8px; background: #f8fafc; border: 1px solid #e2e8f0; text-align: center; }
          .stat-value { font-size: 24px; font-weight: 700; color: ${primaryColor}; }
          .stat-label { font-size: 11px; color: #64748b; text-transform: uppercase; }
          .severity-critical { color: #dc2626; font-weight: 600; }
          .severity-high { color: #ea580c; font-weight: 600; }
          .severity-medium { color: #ca8a04; font-weight: 600; }
          .severity-low { color: #2563eb; font-weight: 600; }
          ${cssOverrides}
        </style>
      </head>
      <body>
        ${headerHtml ? `<div class="report-header">${headerHtml}</div>` : ""}
        ${html}
        ${footerHtml ? `<div class="report-footer">${footerHtml}</div>` : ""}
      </body>
      </html>
    `;
    return fullHtml;
  }, [templateContent, headerHtml, footerHtml, cssOverrides, primaryColor, name, realData]);

  if (templateId && templateQuery.isLoading) {
    return (
      <AppShell activePath="/report-templates">
        <div className="flex items-center justify-center h-64">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell activePath="/report-templates">
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="icon" onClick={() => setLocation("/report-templates")}>
              <ArrowLeft className="w-4 h-4" />
            </Button>
            <div>
              <h1 className="text-xl font-bold">
                {templateId ? "Edit Template" : "New Template"}
              </h1>
              <p className="text-sm text-muted-foreground">
                {name || "Untitled template"}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={() => setShowPreview(!showPreview)}
            >
              <Eye className="w-4 h-4 mr-2" />
              {showPreview ? "Hide Preview" : "Show Preview"}
            </Button>
            <Button onClick={handleSave} disabled={isSaving || !name}>
              {isSaving ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Save className="w-4 h-4 mr-2" />
              )}
              Save Template
            </Button>
          </div>
        </div>

        {/* Main Editor Layout */}
        <div className={`grid gap-4 ${showPreview ? "grid-cols-2" : "grid-cols-1"}`}>
          {/* Editor Panel */}
          <div className="space-y-4">
            {/* Template Metadata */}
            <Card className="bg-card/50 border-border/50">
              <CardContent className="pt-4 space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label className="text-xs">Template Name</Label>
                    <Input
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g., Penetration Test Report"
                    />
                  </div>
                  <div>
                    <Label className="text-xs">Report Type</Label>
                    <Select value={templateType} onValueChange={setTemplateType}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="engagement">Engagement / Pentest</SelectItem>
                        <SelectItem value="executive">Executive Summary</SelectItem>
                        <SelectItem value="compliance">Compliance</SelectItem>
                        <SelectItem value="vulnerability">Vulnerability Assessment</SelectItem>
                        <SelectItem value="custom">Custom</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <Label className="text-xs">Description</Label>
                  <Input
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="Brief description of when to use this template"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <Switch checked={isDefault} onCheckedChange={setIsDefault} />
                  <Label className="text-xs">Set as default for this report type</Label>
                </div>
              </CardContent>
            </Card>

            {/* Editor Tabs */}
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList className="w-full">
                <TabsTrigger value="content" className="flex-1">
                  <Code className="w-3 h-3 mr-1.5" />Content
                </TabsTrigger>
                <TabsTrigger value="branding" className="flex-1">
                  <Palette className="w-3 h-3 mr-1.5" />Branding
                </TabsTrigger>
                <TabsTrigger value="variables" className="flex-1">
                  <Wand2 className="w-3 h-3 mr-1.5" />Variables
                </TabsTrigger>
                <TabsTrigger value="header-footer" className="flex-1">
                  <FileText className="w-3 h-3 mr-1.5" />Header/Footer
                </TabsTrigger>
              </TabsList>

              {/* Content Tab */}
              <TabsContent value="content" className="mt-3">
                <Card className="bg-card/50 border-border/50">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm">Template HTML Content</CardTitle>
                      <Badge variant="outline" className="text-[10px]">
                        Use {"{{variable_name}}"} for dynamic content
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <textarea
                      id="template-content-editor"
                      value={templateContent}
                      onChange={(e) => setTemplateContent(e.target.value)}
                      className="w-full min-h-[500px] p-3 font-mono text-xs bg-[#0D1117] text-gray-200 border border-border rounded-md resize-y focus:outline-none focus:ring-1 focus:ring-primary"
                      placeholder="<h1>{{report_title}}</h1>&#10;<p>Prepared for: {{client_name}}</p>&#10;<p>Date: {{report_date}}</p>&#10;&#10;<h2>Executive Summary</h2>&#10;<p>{{executive_summary}}</p>"
                      spellCheck={false}
                    />
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Branding Tab */}
              <TabsContent value="branding" className="mt-3">
                <Card className="bg-card/50 border-border/50">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Branding & Styling</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label className="text-xs">Primary Color</Label>
                        <div className="flex items-center gap-2 mt-1">
                          <input
                            type="color"
                            value={primaryColor}
                            onChange={(e) => setPrimaryColor(e.target.value)}
                            className="w-10 h-10 rounded border border-border cursor-pointer"
                          />
                          <Input
                            value={primaryColor}
                            onChange={(e) => setPrimaryColor(e.target.value)}
                            placeholder="#00E5CC"
                            className="font-mono text-xs"
                          />
                        </div>
                      </div>
                      <div>
                        <Label className="text-xs">Logo URL</Label>
                        <Input
                          value={logoUrl}
                          onChange={(e) => setLogoUrl(e.target.value)}
                          placeholder="https://example.com/logo.png"
                          className="mt-1"
                        />
                        {logoUrl && (
                          <div className="mt-2 p-2 bg-muted rounded">
                            <img src={logoUrl} alt="Logo preview" className="max-h-8" onError={(e) => (e.currentTarget.style.display = "none")} />
                          </div>
                        )}
                      </div>
                    </div>
                    <div>
                      <Label className="text-xs">CSS Overrides</Label>
                      <textarea
                        value={cssOverrides}
                        onChange={(e) => setCssOverrides(e.target.value)}
                        className="w-full min-h-[200px] p-3 font-mono text-xs bg-[#0D1117] text-gray-200 border border-border rounded-md resize-y mt-1 focus:outline-none focus:ring-1 focus:ring-primary"
                        placeholder="/* Custom CSS overrides */&#10;h1 { font-size: 28px; }&#10;.report-header { background: #f8fafc; padding: 20px; }&#10;table th { background: #1e293b; color: white; }"
                        spellCheck={false}
                      />
                    </div>
                    <div className="p-3 bg-muted/50 rounded-md">
                      <p className="text-xs text-muted-foreground">
                        <strong>Tip:</strong> The primary color is automatically applied to headings, table headers, and accent elements.
                        Use CSS overrides for fine-grained control over fonts, spacing, and layout.
                      </p>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Variables Tab */}
              <TabsContent value="variables" className="mt-3">
                <Card className="bg-card/50 border-border/50">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm">Available Variables</CardTitle>
                      <Badge variant="outline" className="text-[10px]">
                        Click to insert at cursor position
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {/* Common Variables */}
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">Common Variables</h4>
                        <div className="grid grid-cols-2 gap-1.5">
                          {TEMPLATE_VARIABLES.common.map((v) => (
                            <button
                              key={v.key}
                              onClick={() => insertVariable(v.key)}
                              className="flex items-center gap-2 p-2 text-left rounded border border-border/50 hover:border-primary/50 hover:bg-primary/5 transition-colors"
                            >
                              <code className="text-[10px] font-mono text-primary bg-primary/10 px-1.5 py-0.5 rounded">
                                {`{{${v.key}}}`}
                              </code>
                              <span className="text-[10px] text-muted-foreground truncate">{v.description}</span>
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* Type-specific Variables */}
                      {templateType !== "custom" && (
                        <div>
                          <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                            {templateType === "engagement" ? "Penetration Test" :
                             templateType === "vulnerability" ? "Vulnerability Scan" :
                             templateType} Variables
                          </h4>
                          <div className="grid grid-cols-2 gap-1.5">
                            {(TEMPLATE_VARIABLES[TYPE_TO_CATEGORY[templateType] || "common"] || [])
                              .filter(v => !TEMPLATE_VARIABLES.common.some(c => c.key === v.key))
                              .map((v) => (
                                <button
                                  key={v.key}
                                  onClick={() => insertVariable(v.key)}
                                  className="flex items-center gap-2 p-2 text-left rounded border border-border/50 hover:border-primary/50 hover:bg-primary/5 transition-colors"
                                >
                                  <code className="text-[10px] font-mono text-primary bg-primary/10 px-1.5 py-0.5 rounded">
                                    {`{{${v.key}}}`}
                                  </code>
                                  <span className="text-[10px] text-muted-foreground truncate">{v.description}</span>
                                </button>
                              ))}
                          </div>
                        </div>
                      )}

                      {/* DI-specific variables */}
                      {(templateType === "custom") && (
                        <>
                          <div>
                            <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">Domain Intelligence Variables</h4>
                            <div className="grid grid-cols-2 gap-1.5">
                              {TEMPLATE_VARIABLES.di.map((v) => (
                                <button
                                  key={v.key}
                                  onClick={() => insertVariable(v.key)}
                                  className="flex items-center gap-2 p-2 text-left rounded border border-border/50 hover:border-primary/50 hover:bg-primary/5 transition-colors"
                                >
                                  <code className="text-[10px] font-mono text-primary bg-primary/10 px-1.5 py-0.5 rounded">
                                    {`{{${v.key}}}`}
                                  </code>
                                  <span className="text-[10px] text-muted-foreground truncate">{v.description}</span>
                                </button>
                              ))}
                            </div>
                          </div>
                          <div>
                            <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">Penetration Test Variables</h4>
                            <div className="grid grid-cols-2 gap-1.5">
                              {TEMPLATE_VARIABLES.pentest.map((v) => (
                                <button
                                  key={v.key}
                                  onClick={() => insertVariable(v.key)}
                                  className="flex items-center gap-2 p-2 text-left rounded border border-border/50 hover:border-primary/50 hover:bg-primary/5 transition-colors"
                                >
                                  <code className="text-[10px] font-mono text-primary bg-primary/10 px-1.5 py-0.5 rounded">
                                    {`{{${v.key}}}`}
                                  </code>
                                  <span className="text-[10px] text-muted-foreground truncate">{v.description}</span>
                                </button>
                              ))}
                            </div>
                          </div>
                          <div>
                            <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">Red Team Variables</h4>
                            <div className="grid grid-cols-2 gap-1.5">
                              {TEMPLATE_VARIABLES.redteam.map((v) => (
                                <button
                                  key={v.key}
                                  onClick={() => insertVariable(v.key)}
                                  className="flex items-center gap-2 p-2 text-left rounded border border-border/50 hover:border-primary/50 hover:bg-primary/5 transition-colors"
                                >
                                  <code className="text-[10px] font-mono text-primary bg-primary/10 px-1.5 py-0.5 rounded">
                                    {`{{${v.key}}}`}
                                  </code>
                                  <span className="text-[10px] text-muted-foreground truncate">{v.description}</span>
                                </button>
                              ))}
                            </div>
                          </div>
                        </>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Header/Footer Tab */}
              <TabsContent value="header-footer" className="mt-3 space-y-4">
                <Card className="bg-card/50 border-border/50">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Report Header</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <textarea
                      value={headerHtml}
                      onChange={(e) => setHeaderHtml(e.target.value)}
                      className="w-full min-h-[120px] p-3 font-mono text-xs bg-[#0D1117] text-gray-200 border border-border rounded-md resize-y focus:outline-none focus:ring-1 focus:ring-primary"
                      placeholder='<div style="display:flex;justify-content:space-between;align-items:center">&#10;  <img src="{{logo_url}}" class="logo" />&#10;  <div style="text-align:right">&#10;    <div style="font-weight:600">CONFIDENTIAL</div>&#10;    <div style="font-size:11px;color:#64748b">{{report_date}}</div>&#10;  </div>&#10;</div>'
                      spellCheck={false}
                    />
                  </CardContent>
                </Card>
                <Card className="bg-card/50 border-border/50">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Report Footer</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <textarea
                      value={footerHtml}
                      onChange={(e) => setFooterHtml(e.target.value)}
                      className="w-full min-h-[120px] p-3 font-mono text-xs bg-[#0D1117] text-gray-200 border border-border rounded-md resize-y focus:outline-none focus:ring-1 focus:ring-primary"
                      placeholder='<div style="border-top:1px solid #e2e8f0;padding-top:12px;margin-top:32px;font-size:11px;color:#64748b;text-align:center">&#10;  CONFIDENTIAL — {{client_name}} — Page {{page_number}}&#10;</div>'
                      spellCheck={false}
                    />
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>

          {/* Preview Panel */}
          {showPreview && (
            <PreviewPanel
              previewHtml={previewHtml}
              previewSource={previewSource}
              setPreviewSource={setPreviewSource}
              templateContent={templateContent}
              headerHtml={headerHtml}
              footerHtml={footerHtml}
              cssOverrides={cssOverrides}
              primaryColor={primaryColor}
              setRealData={setRealData}
            />
          )}
        </div>
      </div>
    </AppShell>
  );
}

// Preview Panel with data source selector
function PreviewPanel({
  previewHtml,
  previewSource,
  setPreviewSource,
  templateContent,
  headerHtml,
  footerHtml,
  cssOverrides,
  primaryColor,
  setRealData,
}: {
  previewHtml: string;
  previewSource: string;
  setPreviewSource: (v: string) => void;
  templateContent: string;
  headerHtml: string;
  footerHtml: string;
  cssOverrides: string;
  primaryColor: string;
  setRealData: (data: Record<string, string> | null) => void;
}) {
  const [selectedSourceId, setSelectedSourceId] = useState<number | null>(null);
  const [selectedSourceType, setSelectedSourceType] = useState<"di" | "engagement">("di");
  const [isLoadingData, setIsLoadingData] = useState(false);

  // Fetch available data sources
  const sourcesQuery = trpc.reportTemplates.getPreviewSources.useQuery(undefined, {
    enabled: previewSource !== "sample",
  });

  // Fetch real data when a source is selected
  const previewDataQuery = trpc.reportTemplates.getPreviewData.useQuery(
    { sourceType: selectedSourceType, sourceId: selectedSourceId! },
    { enabled: !!selectedSourceId && previewSource !== "sample" }
  );

  // Update real data when query resolves
  useEffect(() => {
    if (previewDataQuery.data) {
      setRealData(previewDataQuery.data as Record<string, string>);
      setIsLoadingData(false);
    }
  }, [previewDataQuery.data, setRealData]);

  const handleSourceChange = (value: string) => {
    setPreviewSource(value);
    if (value === "sample") {
      setRealData(null);
      setSelectedSourceId(null);
    }
  };

  const handleDataSourceSelect = (value: string) => {
    const [type, id] = value.split(":");
    setSelectedSourceType(type as "di" | "engagement");
    setSelectedSourceId(parseInt(id));
    setIsLoadingData(true);
  };

  return (
    <div className="sticky top-4">
      <Card className="bg-white border-border/50 h-[calc(100vh-120px)]">
        <CardHeader className="pb-2 border-b">
          <div className="flex items-center justify-between gap-2">
            <CardTitle className="text-sm text-gray-900">Live Preview</CardTitle>
            <div className="flex items-center gap-2">
              <Select value={previewSource} onValueChange={handleSourceChange}>
                <SelectTrigger className="h-7 text-[11px] w-[120px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="sample">Sample Data</SelectItem>
                  <SelectItem value="real">Real Data</SelectItem>
                </SelectContent>
              </Select>
              {previewSource === "real" && (
                <Select onValueChange={handleDataSourceSelect}>
                  <SelectTrigger className="h-7 text-[11px] w-[200px]">
                    <SelectValue placeholder="Select source..." />
                  </SelectTrigger>
                  <SelectContent>
                    {sourcesQuery.data?.diScans.map((s) => (
                      <SelectItem key={`di:${s.id}`} value={`di:${s.id}`}>
                        <span className="text-[11px]">{s.label}</span>
                      </SelectItem>
                    ))}
                    {sourcesQuery.data?.engagements.map((e) => (
                      <SelectItem key={`engagement:${e.id}`} value={`engagement:${e.id}`}>
                        <span className="text-[11px]">{e.label}</span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
              <Badge variant="outline" className="text-[10px]">
                {previewSource === "sample" ? "Sample" : isLoadingData ? "Loading..." : "Live"}
              </Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0 h-[calc(100%-60px)]">
          {isLoadingData ? (
            <div className="flex items-center justify-center h-full">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <iframe
              srcDoc={previewHtml}
              className="w-full h-full border-0"
              title="Template Preview"
              sandbox="allow-same-origin"
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
