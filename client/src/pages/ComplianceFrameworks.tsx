import { useState, useMemo } from "react";
import {
  Shield, CheckCircle2, AlertTriangle, XCircle,
  ChevronDown, ChevronUp, Copy, Download, Search,
  BarChart3, Target, Lock, Eye, RotateCcw, Layers,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import {
  FEDRAMP_CONTROLS, FEDRAMP_REQUIREMENTS, CMMC_LEVELS, CMMC_REPORT_MAPPING,
  IMPERSONATION_MATRIX, IMPERSONATION_CONTROLS, SUPPORTED_INDUSTRIES, GOPHISH_POLICY_TEMPLATE
} from "@/data/compliance-data";
import {
  NIST_CSF_CATEGORIES, CIS_CONTROLS, ISO_27001_CATEGORIES,
  type FrameworkCategory, type FrameworkControl,
  calculateComplianceGrade, calculateComplianceStatus,
} from "@/data/compliance-mappings";

type Tab = "nist_csf" | "cis_controls" | "iso_27001" | "fedramp" | "cmmc" | "impersonation" | "template";

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  GV: <Shield className="w-4 h-4" />,
  ID: <Search className="w-4 h-4" />,
  PR: <Lock className="w-4 h-4" />,
  DE: <Eye className="w-4 h-4" />,
  RS: <Target className="w-4 h-4" />,
  RC: <RotateCcw className="w-4 h-4" />,
  IG1: <Shield className="w-4 h-4" />,
  IG2: <Layers className="w-4 h-4" />,
  IG3: <Target className="w-4 h-4" />,
  A5: <Shield className="w-4 h-4" />,
  A6: <Shield className="w-4 h-4" />,
  A7: <Lock className="w-4 h-4" />,
  A8: <Layers className="w-4 h-4" />,
};

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "text-red-400 bg-red-500/10 border-red-500/30",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
    low: "text-green-400 bg-green-500/10 border-green-500/30",
  };
  return (
    <span className={`px-2 py-0.5 text-[10px] font-display tracking-wider border ${colors[severity] || colors.medium}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function FrameworkDashboard({ categories, accentColor, frameworkName }: {
  categories: FrameworkCategory[];
  accentColor: string;
  frameworkName: string;
}) {
  const [expandedCats, setExpandedCats] = useState<Record<string, boolean>>({});
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const toggleCat = (id: string) => {
    setExpandedCats(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const expandAll = () => {
    const all: Record<string, boolean> = {};
    categories.forEach(c => { all[c.id] = true; });
    setExpandedCats(all);
  };

  const collapseAll = () => setExpandedCats({});

  const stats = useMemo(() => {
    let total = 0, critical = 0, high = 0, medium = 0, low = 0;
    categories.forEach(cat => {
      cat.controls.forEach(ctrl => {
        total++;
        if (ctrl.severity === "critical") critical++;
        else if (ctrl.severity === "high") high++;
        else if (ctrl.severity === "medium") medium++;
        else low++;
      });
    });
    return { total, critical, high, medium, low };
  }, [categories]);

  const filteredCategories = useMemo(() => {
    return categories.map(cat => ({
      ...cat,
      controls: cat.controls.filter(ctrl => {
        const matchesSearch = searchQuery === "" ||
          (ctrl.id || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
          (ctrl.name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
          (ctrl.description || '').toLowerCase().includes(searchQuery.toLowerCase());
        const matchesSeverity = severityFilter === "all" || ctrl.severity === severityFilter;
        return matchesSearch && matchesSeverity;
      }),
    })).filter(cat => cat.controls.length > 0);
  }, [categories, searchQuery, severityFilter]);

  const exportFramework = () => {
    const data = categories.map(cat => ({
      category: cat.name,
      controls: cat.controls.map(ctrl => ({
        id: ctrl.id,
        name: ctrl.name,
        description: ctrl.description,
        severity: ctrl.severity,
        findingTypes: ctrl.findingTypes,
      })),
    }));
    const blob = new Blob([JSON.stringify({ framework: frameworkName, categories: data }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${frameworkName.toLowerCase().replace(/\s+/g, "_")}_controls.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`${frameworkName} controls exported`);
  };

  return (
    <div className="space-y-6">
      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className={`bg-card border-2 border-${accentColor}-500/30 p-4 text-center`}>
          <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">TOTAL CONTROLS</p>
          <p className={`text-2xl font-display text-${accentColor}-400`}>{stats.total}</p>
        </div>
        <div className="bg-card border-2 border-red-500/30 p-4 text-center">
          <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">CRITICAL</p>
          <p className="text-2xl font-display text-red-400">{stats.critical}</p>
        </div>
        <div className="bg-card border-2 border-orange-500/30 p-4 text-center">
          <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">HIGH</p>
          <p className="text-2xl font-display text-orange-400">{stats.high}</p>
        </div>
        <div className="bg-card border-2 border-yellow-500/30 p-4 text-center">
          <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">MEDIUM</p>
          <p className="text-2xl font-display text-yellow-400">{stats.medium}</p>
        </div>
        <div className="bg-card border-2 border-green-500/30 p-4 text-center">
          <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">LOW</p>
          <p className="text-2xl font-display text-green-400">{stats.low}</p>
        </div>
      </div>

      {/* Search + Filter + Actions */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search controls by ID, name, or description..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-card border-2 border-border text-sm focus:outline-none focus:border-primary/50"
          />
        </div>
        <div className="flex gap-2">
          {["all", "critical", "high", "medium", "low"].map(sev => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-2 text-xs font-display tracking-wider border transition-colors ${
                severityFilter === sev
                  ? `text-${accentColor}-400 border-${accentColor}-500/50 bg-${accentColor}-500/10`
                  : "text-muted-foreground border-border hover:bg-secondary/30"
              }`}
            >
              {sev.toUpperCase()}
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="text-xs" onClick={expandAll}>EXPAND ALL</Button>
          <Button variant="outline" size="sm" className="text-xs" onClick={collapseAll}>COLLAPSE ALL</Button>
          <Button variant="outline" size="sm" className="text-xs" onClick={exportFramework}>
            <Download className="w-3 h-3 mr-1" />EXPORT
          </Button>
        </div>
      </div>

      {/* Categories */}
      {filteredCategories.map(cat => {
        const isExpanded = expandedCats[cat.id] ?? false;
        const critCount = cat.controls.filter(c => c.severity === "critical").length;
        const highCount = cat.controls.filter(c => c.severity === "high").length;

        return (
          <div key={cat.id} className={`bg-card border-2 border-${cat.color}-500/30`}>
            <button
              onClick={() => toggleCat(cat.id)}
              className="w-full flex items-center justify-between px-5 py-4 hover:bg-secondary/30 transition-colors"
            >
              <div className="flex items-center gap-3">
                <span className={`text-${cat.color}-400`}>{CATEGORY_ICONS[cat.id] || <Shield className="w-4 h-4" />}</span>
                <div className="text-left">
                  <h3 className={`font-display text-sm tracking-wider text-${cat.color}-400`}>{cat.name}</h3>
                  <p className="text-xs text-muted-foreground mt-0.5">{cat.description}</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-muted-foreground">{cat.controls.length} controls</span>
                {critCount > 0 && <span className="px-2 py-0.5 text-[10px] font-display text-red-400 bg-red-500/10 border border-red-500/30">{critCount} CRIT</span>}
                {highCount > 0 && <span className="px-2 py-0.5 text-[10px] font-display text-orange-400 bg-orange-500/10 border border-orange-500/30">{highCount} HIGH</span>}
                {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </div>
            </button>
            {isExpanded && (
              <div className="border-t border-border/30">
                <table className="w-full">
                  <thead>
                    <tr className="bg-secondary/30">
                      <th className="text-left text-[10px] font-display tracking-wider text-muted-foreground px-5 py-2 w-24">ID</th>
                      <th className="text-left text-[10px] font-display tracking-wider text-muted-foreground px-5 py-2 w-48">CONTROL</th>
                      <th className="text-left text-[10px] font-display tracking-wider text-muted-foreground px-5 py-2">DESCRIPTION</th>
                      <th className="text-left text-[10px] font-display tracking-wider text-muted-foreground px-5 py-2 w-20">SEVERITY</th>
                      <th className="text-left text-[10px] font-display tracking-wider text-muted-foreground px-5 py-2 w-56">FINDING TYPES</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cat.controls.map(ctrl => (
                      <tr key={ctrl.id} className="border-t border-border/20 hover:bg-secondary/20 transition-colors">
                        <td className={`px-5 py-3 text-xs font-mono text-${cat.color}-400`}>{ctrl.id}</td>
                        <td className="px-5 py-3 text-sm font-medium">{ctrl.name}</td>
                        <td className="px-5 py-3 text-xs text-muted-foreground">{ctrl.description}</td>
                        <td className="px-5 py-3"><SeverityBadge severity={ctrl.severity} /></td>
                        <td className="px-5 py-3">
                          <div className="flex flex-wrap gap-1">
                            {ctrl.findingTypes.slice(0, 3).map(ft => (
                              <span key={ft} className="px-1.5 py-0.5 text-[9px] font-mono text-muted-foreground bg-secondary/50 border border-border/50">
                                {ft}
                              </span>
                            ))}
                            {ctrl.findingTypes.length > 3 && (
                              <span className="px-1.5 py-0.5 text-[9px] font-mono text-muted-foreground bg-secondary/50 border border-border/50">
                                +{ctrl.findingTypes.length - 3}
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })}

      {filteredCategories.length === 0 && (
        <div className="text-center py-12 text-muted-foreground">
          <Search className="w-8 h-8 mx-auto mb-3 opacity-50" />
          <p className="text-sm">No controls match your search criteria</p>
        </div>
      )}
    </div>
  );
}

export default function ComplianceFrameworks() {
  const [activeTab, setActiveTab] = useState<Tab>("nist_csf");
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({});

  const toggleSection = (key: string) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const copyTemplate = () => {
    navigator.clipboard.writeText(GOPHISH_POLICY_TEMPLATE.body);
    toast.success("Template copied to clipboard");
  };

  const tabs: { id: Tab; label: string; color: string }[] = [
    { id: "nist_csf", label: "NIST CSF 2.0", color: "text-blue-400" },
    { id: "cis_controls", label: "CIS CONTROLS", color: "text-emerald-400" },
    { id: "iso_27001", label: "ISO 27001", color: "text-cyan-400" },
    { id: "fedramp", label: "FEDRAMP", color: "text-indigo-400" },
    { id: "cmmc", label: "CMMC 2.0", color: "text-purple-400" },
    { id: "impersonation", label: "IMPERSONATION", color: "text-yellow-400" },
    { id: "template", label: "TEMPLATE", color: "text-pink-400" },
  ];

  return (
    <AppShell activePath="/compliance">
      <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="px-6 py-4">
          <div className="flex items-center gap-3 mb-1">
            <Shield className="w-6 h-6 text-primary" />
            <h1 className="font-display text-2xl lg:text-3xl">COMPLIANCE FRAMEWORKS</h1>
          </div>
          <p className="text-sm text-muted-foreground">Map engagement findings to NIST CSF 2.0, CIS Controls v8, ISO 27001:2022, FedRAMP, and CMMC 2.0. Export compliance reports for regulatory assessments.</p>
        </div>
        <div className="flex overflow-x-auto border-t border-border">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`whitespace-nowrap px-4 py-3 font-display text-xs tracking-wider transition-colors border-b-2 ${
                activeTab === tab.id
                  ? `${tab.color} border-current bg-secondary/30`
                  : 'text-muted-foreground border-transparent hover:bg-secondary/20'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </header>

      <div className="p-6 space-y-8">

        {/* NIST CSF 2.0 Tab */}
        {activeTab === "nist_csf" && (
          <>
            <div className="bg-blue-500/5 border-2 border-blue-500/20 p-4">
              <h2 className="font-display text-lg text-blue-400 mb-1">NIST CYBERSECURITY FRAMEWORK 2.0</h2>
              <p className="text-xs text-muted-foreground">The NIST CSF 2.0 provides a comprehensive taxonomy of cybersecurity outcomes organized into six functions: Govern, Identify, Protect, Detect, Respond, and Recover. Each control maps to specific finding types from red team engagements, enabling automated compliance gap analysis.</p>
            </div>
            <FrameworkDashboard categories={NIST_CSF_CATEGORIES} accentColor="blue" frameworkName="NIST CSF 2.0" />
          </>
        )}

        {/* CIS Controls Tab */}
        {activeTab === "cis_controls" && (
          <>
            <div className="bg-emerald-500/5 border-2 border-emerald-500/20 p-4">
              <h2 className="font-display text-lg text-emerald-400 mb-1">CIS CONTROLS v8</h2>
              <p className="text-xs text-muted-foreground">The CIS Controls are a prioritized set of actions organized into three Implementation Groups (IGs). IG1 represents basic cyber hygiene, IG2 adds foundational controls for enterprises with sensitive data, and IG3 covers organizational-level security for enterprises with dedicated security teams. Red team findings map directly to these controls for gap identification.</p>
            </div>
            <FrameworkDashboard categories={CIS_CONTROLS} accentColor="emerald" frameworkName="CIS Controls v8" />
          </>
        )}

        {/* ISO 27001 Tab */}
        {activeTab === "iso_27001" && (
          <>
            <div className="bg-cyan-500/5 border-2 border-cyan-500/20 p-4">
              <h2 className="font-display text-lg text-cyan-400 mb-1">ISO/IEC 27001:2022 — ANNEX A CONTROLS</h2>
              <p className="text-xs text-muted-foreground">ISO 27001:2022 Annex A provides 93 controls across four themes: Organizational (A.5), People (A.6), Physical (A.7), and Technological (A.8). Red team engagement findings are mapped to relevant Annex A controls to support certification audits and continuous improvement programs.</p>
            </div>
            <FrameworkDashboard categories={ISO_27001_CATEGORIES} accentColor="cyan" frameworkName="ISO 27001:2022" />
          </>
        )}

        {/* FedRAMP Tab */}
        {activeTab === "fedramp" && (
          <>
            <section>
              <h2 className="font-display text-2xl mb-4 text-indigo-400">FEDRAMP CONTROL COMPARISON</h2>
              <p className="text-sm text-muted-foreground mb-4">Moderate vs High impact baseline comparison for red team engagement scoping.</p>
              <div className="bg-card border-2 border-indigo-500/30 overflow-hidden">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border bg-secondary/50">
                      <th className="text-left text-xs font-display tracking-wider text-muted-foreground px-5 py-3">CONTROL FAMILY</th>
                      <th className="text-left text-xs font-display tracking-wider text-indigo-400 px-5 py-3">MODERATE</th>
                      <th className="text-left text-xs font-display tracking-wider text-red-400 px-5 py-3">HIGH</th>
                    </tr>
                  </thead>
                  <tbody>
                    {FEDRAMP_CONTROLS.map((ctrl) => (
                      <tr key={ctrl.family} className="border-b border-border/30 hover:bg-secondary/30 transition-colors">
                        <td className="px-5 py-3 text-sm font-medium">{ctrl.family}</td>
                        <td className="px-5 py-3 text-sm text-indigo-400">{ctrl.moderate}</td>
                        <td className="px-5 py-3 text-sm text-red-400">{ctrl.high}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <div className="w-full h-0.5 bg-indigo-500/30" />

            <section>
              <h2 className="font-display text-2xl mb-4 text-indigo-400">FEDRAMP GOVERNANCE REQUIREMENTS</h2>
              {Object.entries(FEDRAMP_REQUIREMENTS).map(([key, items]) => {
                const labels: Record<string, string> = {
                  authorization: "AUTHORIZATION", dataHandling: "DATA HANDLING",
                  infraIsolation: "INFRASTRUCTURE ISOLATION", auditReporting: "AUDIT & REPORTING",
                  postEngagement: "POST-ENGAGEMENT",
                };
                const isExpanded = expandedSections[key] !== false;
                return (
                  <div key={key} className="bg-card border-2 border-indigo-500/30 mb-3">
                    <button onClick={() => toggleSection(key)} className="w-full flex items-center justify-between px-5 py-3 hover:bg-secondary/30 transition-colors">
                      <span className="font-display text-sm tracking-wider text-indigo-400">{labels[key] || key.toUpperCase()}</span>
                      {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                    </button>
                    {isExpanded && (
                      <div className="px-5 pb-4 space-y-2">
                        {items.map((item, i) => (
                          <div key={i} className="flex items-start gap-3">
                            <CheckCircle2 className="w-4 h-4 text-indigo-400 mt-0.5 shrink-0" />
                            <span className="text-sm text-muted-foreground">{item}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </section>
          </>
        )}

        {/* CMMC Tab */}
        {activeTab === "cmmc" && (
          <>
            <section>
              <h2 className="font-display text-2xl mb-4 text-purple-400">CMMC 2.0 MATURITY LEVELS</h2>
              <p className="text-sm text-muted-foreground mb-4">Cybersecurity Maturity Model Certification alignment for defense contractor engagements.</p>
              <div className="grid md:grid-cols-3 gap-4">
                {CMMC_LEVELS.map((level) => (
                  <div key={level.level} className="bg-card border-2 border-purple-500/30 p-5">
                    <div className="flex items-center gap-2 mb-3">
                      <Shield className="w-5 h-5 text-purple-500" />
                      <div>
                        <h3 className="font-display text-lg text-purple-400">{level.level}</h3>
                        <p className="text-xs text-muted-foreground">{level.name}</p>
                      </div>
                    </div>
                    <p className="text-sm text-muted-foreground mb-4">{level.description}</p>
                    <div className="space-y-2 mb-4">
                      {level.requirements.map((req, i) => (
                        <div key={i} className="flex items-start gap-2">
                          <CheckCircle2 className="w-3 h-3 text-purple-400 mt-1 shrink-0" />
                          <span className="text-xs text-muted-foreground">{req}</span>
                        </div>
                      ))}
                    </div>
                    <div className="bg-secondary/50 p-2">
                      <p className="text-[10px] font-display tracking-wider text-muted-foreground mb-1">CONTROL FAMILIES</p>
                      <div className="flex flex-wrap gap-1">
                        {level.controlFamilies.map(cf => (
                          <span key={cf} className="px-2 py-0.5 text-[10px] font-display tracking-wider text-purple-400 bg-purple-500/10 border border-purple-500/20">
                            {cf}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <div className="w-full h-0.5 bg-purple-500/30" />

            <section>
              <h2 className="font-display text-2xl mb-4 text-purple-400">REPORT MAPPING REQUIREMENTS</h2>
              <div className="bg-card border-2 border-purple-500/30 p-5">
                <p className="text-sm text-muted-foreground mb-4">Red team reporting must map findings to the following control families:</p>
                <div className="grid grid-cols-2 gap-3">
                  {CMMC_REPORT_MAPPING.map((mapping) => (
                    <div key={mapping} className="flex items-center gap-3 bg-secondary/50 p-3">
                      <CheckCircle2 className="w-4 h-4 text-purple-400 shrink-0" />
                      <span className="text-sm font-display tracking-wider">{mapping}</span>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <section>
              <h2 className="font-display text-2xl mb-4 text-purple-400">SUPPORTED INDUSTRIES</h2>
              <div className="flex flex-wrap gap-3">
                {SUPPORTED_INDUSTRIES.map(ind => (
                  <div key={ind} className="bg-card border-2 border-purple-500/30 px-6 py-3 font-display tracking-wider text-purple-400">
                    {ind.toUpperCase()}
                  </div>
                ))}
              </div>
            </section>
          </>
        )}

        {/* Impersonation Matrix Tab */}
        {activeTab === "impersonation" && (
          <>
            <section>
              <h2 className="font-display text-2xl mb-2 text-yellow-400">DEFENSE-SECTOR IMPERSONATION MATRIX</h2>
              <p className="text-sm text-muted-foreground mb-4">Defines impersonation boundaries for DoD and defense-sector engagements.</p>
              <div className="bg-card border-2 border-yellow-500/30 overflow-hidden">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border bg-secondary/50">
                      <th className="text-left text-xs font-display tracking-wider text-muted-foreground px-5 py-3">THEME</th>
                      <th className="text-center text-xs font-display tracking-wider text-muted-foreground px-5 py-3">ALLOWED</th>
                      <th className="text-center text-xs font-display tracking-wider text-muted-foreground px-5 py-3">REQUIRES APPROVAL</th>
                      <th className="text-center text-xs font-display tracking-wider text-muted-foreground px-5 py-3">PROHIBITED</th>
                      <th className="text-left text-xs font-display tracking-wider text-muted-foreground px-5 py-3">NOTES</th>
                    </tr>
                  </thead>
                  <tbody>
                    {IMPERSONATION_MATRIX.map((rule) => (
                      <tr key={rule.theme} className="border-b border-border/30 hover:bg-secondary/30 transition-colors">
                        <td className="px-5 py-3 text-sm font-medium">{rule.theme}</td>
                        <td className="px-5 py-3 text-center">
                          {rule.allowed === "Yes" ? <CheckCircle2 className="w-5 h-5 text-green-400 mx-auto" /> : <XCircle className="w-5 h-5 text-red-400/30 mx-auto" />}
                        </td>
                        <td className="px-5 py-3 text-center">
                          {rule.requiresApproval === "Yes" ? <AlertTriangle className="w-5 h-5 text-yellow-400 mx-auto" /> : <span className="text-muted-foreground/30">—</span>}
                        </td>
                        <td className="px-5 py-3 text-center">
                          {rule.prohibited === "Yes" ? <XCircle className="w-5 h-5 text-red-500 mx-auto" /> : <span className="text-muted-foreground/30">—</span>}
                        </td>
                        <td className="px-5 py-3 text-xs text-muted-foreground">{rule.notes}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <div className="w-full h-0.5 bg-yellow-500/30" />

            <section>
              <h2 className="font-display text-2xl mb-4 text-yellow-400">MANDATORY CONTROLS</h2>
              <div className="bg-card border-2 border-yellow-500/30 p-5">
                <div className="grid md:grid-cols-2 gap-3">
                  {IMPERSONATION_CONTROLS.map((ctrl, i) => (
                    <div key={i} className="flex items-start gap-3 bg-secondary/50 p-3">
                      <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5 shrink-0" />
                      <span className="text-sm text-muted-foreground">{ctrl}</span>
                    </div>
                  ))}
                </div>
              </div>
            </section>
          </>
        )}

        {/* Phishing Template Tab */}
        {activeTab === "template" && (
          <>
            <section>
              <h2 className="font-display text-2xl mb-4 text-pink-400">APPROVED PHISHING TEMPLATE</h2>
              <p className="text-sm text-muted-foreground mb-4">Pre-approved neutral template for governance-themed phishing campaigns.</p>

              <div className="grid md:grid-cols-3 gap-4 mb-6">
                <div className="bg-card border-2 border-pink-500/30 p-4 text-center">
                  <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">CATEGORY</p>
                  <p className="text-lg font-display text-pink-400">{(GOPHISH_POLICY_TEMPLATE.category || '').toUpperCase()}</p>
                </div>
                <div className="bg-card border-2 border-pink-500/30 p-4 text-center">
                  <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">RISK LEVEL</p>
                  <p className="text-lg font-display text-green-400">{(GOPHISH_POLICY_TEMPLATE.riskLevel || '').toUpperCase()}</p>
                </div>
                <div className="bg-card border-2 border-pink-500/30 p-4 text-center">
                  <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">INDUSTRIES</p>
                  <p className="text-lg font-display text-pink-400">ALL</p>
                </div>
              </div>

              <div className="bg-card border-2 border-pink-500/30 p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-display text-lg text-pink-400">TEMPLATE PREVIEW</h3>
                  <Button variant="outline" size="sm" className="text-xs border-pink-500/50 text-pink-400" onClick={copyTemplate}>
                    <Copy className="w-3 h-3 mr-1" />COPY
                  </Button>
                </div>

                <div className="bg-white/5 border border-border p-6">
                  <div className="border-b border-border pb-3 mb-4">
                    <p className="text-xs text-muted-foreground mb-1">SUBJECT</p>
                    <p className="text-sm font-medium">{GOPHISH_POLICY_TEMPLATE.subject}</p>
                  </div>
                  <div className="whitespace-pre-wrap text-sm text-muted-foreground leading-relaxed font-mono">
                    {GOPHISH_POLICY_TEMPLATE.body}
                  </div>
                </div>

                <div className="mt-4 bg-secondary/30 p-3">
                  <p className="text-xs text-muted-foreground">
                    <span className="font-display tracking-wider text-yellow-400">NOTE:</span> {GOPHISH_POLICY_TEMPLATE.notes}
                  </p>
                </div>

                <div className="mt-4">
                  <a href="https://gophish.aceofcloud.io/templates" target="_blank" rel="noopener noreferrer">
                    <Button variant="outline" size="sm" className="w-full font-display tracking-wider border-pink-500/50 text-pink-400 hover:bg-pink-500/10">
                      IMPORT TO PHISHING TEMPLATES
                    </Button>
                  </a>
                </div>
              </div>
            </section>
          </>
        )}

      </div>
    </AppShell>
  );
}
