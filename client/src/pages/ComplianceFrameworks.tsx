import { Link, useLocation } from "wouter";
import { useState } from "react";
import {
  Cloud, Activity, Key, Target, Cpu, Zap, Users, FileText, BookOpen, Fish,
  Menu, X, LogOut, Shield, Globe2, CheckCircle2, AlertTriangle, XCircle,
  ChevronDown, ChevronUp, Download, Copy,
  Briefcase,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  FEDRAMP_CONTROLS, FEDRAMP_REQUIREMENTS, CMMC_LEVELS, CMMC_REPORT_MAPPING,
  IMPERSONATION_MATRIX, IMPERSONATION_CONTROLS, SUPPORTED_INDUSTRIES, GOPHISH_POLICY_TEMPLATE
} from "@/data/compliance-data";

type Tab = "fedramp" | "cmmc" | "impersonation" | "template";

export default function ComplianceFrameworks() {
  const [, navigate] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>("fedramp");
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({});

  const toggleSection = (key: string) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const copyTemplate = () => {
    navigator.clipboard.writeText(GOPHISH_POLICY_TEMPLATE.body);
    toast.success("Template copied to clipboard");
  };

  const tabs: { id: Tab; label: string; color: string }[] = [
    { id: "fedramp", label: "FEDRAMP", color: "text-blue-400" },
    { id: "cmmc", label: "CMMC 2.0", color: "text-emerald-400" },
    { id: "impersonation", label: "IMPERSONATION MATRIX", color: "text-yellow-400" },
    { id: "template", label: "PHISHING TEMPLATE", color: "text-purple-400" },
  ];

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
                <span className="text-xs text-muted-foreground tracking-widest">C3 — <span className="text-primary/70">CYBER CAMPAIGN COMMAND</span></span>
              </div>
            </Link>
          </div>
          <nav className="flex-1 p-4 space-y-2">
            <NavItem href="/dashboard" icon={<Activity />} label="DASHBOARD" />
            <NavItem href="/engagements" icon={<Briefcase />} label="ENGAGEMENTS" />
            <NavItem href="/credentials" icon={<Key />} label="CREDENTIALS" />
            <NavItem href="/adversaries" icon={<Target />} label="ADVERSARIES" />
            <NavItem href="/agents" icon={<Cpu />} label="AGENTS" />
            <NavItem href="/campaigns" icon={<Zap />} label="CAMPAIGNS" />
            <NavItem href="/gophish" icon={<Fish />} label="GOPHISH" />
            <NavItem href="/team" icon={<Users />} label="TEAM" />
            <NavItem href="/activity" icon={<FileText />} label="ACTIVITY" />
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">THREAT INTEL</p>
              <NavItem href="/apt-library" icon={<Shield />} label="APT SCENARIOS" />
              <NavItem href="/compliance" icon={<FileText />} label="COMPLIANCE" active />
              <NavItem href="/infra-reference" icon={<Globe2 />} label="INFRASTRUCTURE" />
            </div>
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">GUIDES</p>
              <NavItem href="/guide/gophish" icon={<BookOpen />} label="GOPHISH GUIDE" />
              <NavItem href="/guide/caldera" icon={<BookOpen />} label="CALDERA GUIDE" />
            </div>
            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">REPORTS</p>
              <NavItem href="/reports/security" icon={<FileText />} label="SECURITY REPORT" />
            </div>
          </nav>
          <div className="p-4 border-t border-border">
            <Link href="/"><Button variant="outline" size="sm" className="w-full font-display tracking-wider"><LogOut className="w-4 h-4 mr-2" />EXIT</Button></Link>
          </div>
        </div>
      </aside>

      <button className="fixed top-4 left-4 z-50 lg:hidden p-2 bg-card border border-border" onClick={() => setSidebarOpen(!sidebarOpen)}>
        {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      <main className="flex-1 lg:ml-64">
        <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
          <div className="px-6 py-4">
            <h1 className="font-display text-3xl md:text-4xl">COMPLIANCE FRAMEWORKS</h1>
            <p className="text-sm text-muted-foreground">FedRAMP governance, CMMC 2.0 alignment, defense impersonation controls, and approved phishing templates for regulated-sector engagements.</p>
          </div>
          {/* Tab bar */}
          <div className="flex border-t border-border">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex-1 px-4 py-3 font-display text-xs tracking-wider transition-colors border-b-2 ${
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

          {/* FedRAMP Tab */}
          {activeTab === "fedramp" && (
            <>
              <section>
                <h2 className="font-display text-2xl mb-4 text-blue-400">FEDRAMP CONTROL COMPARISON</h2>
                <p className="text-sm text-muted-foreground mb-4">Moderate vs High impact baseline comparison for red team engagement scoping. High Impact Systems require increased logging granularity, enhanced encryption controls, and more frequent security assessments.</p>
                <div className="bg-card border-2 border-blue-500/30 overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border bg-secondary/50">
                        <th className="text-left text-xs font-display tracking-wider text-muted-foreground px-5 py-3">CONTROL FAMILY</th>
                        <th className="text-left text-xs font-display tracking-wider text-blue-400 px-5 py-3">MODERATE</th>
                        <th className="text-left text-xs font-display tracking-wider text-red-400 px-5 py-3">HIGH</th>
                      </tr>
                    </thead>
                    <tbody>
                      {FEDRAMP_CONTROLS.map((ctrl) => (
                        <tr key={ctrl.family} className="border-b border-border/30 hover:bg-secondary/30 transition-colors">
                          <td className="px-5 py-3 text-sm font-medium">{ctrl.family}</td>
                          <td className="px-5 py-3 text-sm text-blue-400">{ctrl.moderate}</td>
                          <td className="px-5 py-3 text-sm text-red-400">{ctrl.high}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <div className="w-full h-0.5 bg-blue-500/30" />

              <section>
                <h2 className="font-display text-2xl mb-4 text-blue-400">FEDRAMP GOVERNANCE REQUIREMENTS</h2>
                {Object.entries(FEDRAMP_REQUIREMENTS).map(([key, items]) => {
                  const labels: Record<string, string> = {
                    authorization: "AUTHORIZATION",
                    dataHandling: "DATA HANDLING",
                    infraIsolation: "INFRASTRUCTURE ISOLATION",
                    auditReporting: "AUDIT & REPORTING",
                    postEngagement: "POST-ENGAGEMENT",
                  };
                  const isExpanded = expandedSections[key] !== false; // default open
                  return (
                    <div key={key} className="bg-card border-2 border-blue-500/30 mb-3">
                      <button
                        onClick={() => toggleSection(key)}
                        className="w-full flex items-center justify-between px-5 py-3 hover:bg-secondary/30 transition-colors"
                      >
                        <span className="font-display text-sm tracking-wider text-blue-400">{labels[key] || key.toUpperCase()}</span>
                        {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                      </button>
                      {isExpanded && (
                        <div className="px-5 pb-4 space-y-2">
                          {items.map((item, i) => (
                            <div key={i} className="flex items-start gap-3">
                              <CheckCircle2 className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
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
                <h2 className="font-display text-2xl mb-4 text-emerald-400">CMMC 2.0 MATURITY LEVELS</h2>
                <p className="text-sm text-muted-foreground mb-4">Cybersecurity Maturity Model Certification alignment for defense contractor engagements. Red team findings must map to the control families listed below.</p>
                <div className="grid md:grid-cols-3 gap-4">
                  {CMMC_LEVELS.map((level) => (
                    <div key={level.level} className="bg-card border-2 border-emerald-500/30 p-5">
                      <div className="flex items-center gap-2 mb-3">
                        <Shield className="w-5 h-5 text-emerald-500" />
                        <div>
                          <h3 className="font-display text-lg text-emerald-400">{level.level}</h3>
                          <p className="text-xs text-muted-foreground">{level.name}</p>
                        </div>
                      </div>
                      <p className="text-sm text-muted-foreground mb-4">{level.description}</p>
                      <div className="space-y-2 mb-4">
                        {level.requirements.map((req, i) => (
                          <div key={i} className="flex items-start gap-2">
                            <CheckCircle2 className="w-3 h-3 text-emerald-400 mt-1 shrink-0" />
                            <span className="text-xs text-muted-foreground">{req}</span>
                          </div>
                        ))}
                      </div>
                      <div className="bg-secondary/50 p-2">
                        <p className="text-[10px] font-display tracking-wider text-muted-foreground mb-1">CONTROL FAMILIES</p>
                        <div className="flex flex-wrap gap-1">
                          {level.controlFamilies.map(cf => (
                            <span key={cf} className="px-2 py-0.5 text-[10px] font-display tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/20">
                              {cf}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <div className="w-full h-0.5 bg-emerald-500/30" />

              <section>
                <h2 className="font-display text-2xl mb-4 text-emerald-400">REPORT MAPPING REQUIREMENTS</h2>
                <div className="bg-card border-2 border-emerald-500/30 p-5">
                  <p className="text-sm text-muted-foreground mb-4">Red team reporting must map findings to the following control families:</p>
                  <div className="grid grid-cols-2 gap-3">
                    {CMMC_REPORT_MAPPING.map((mapping) => (
                      <div key={mapping} className="flex items-center gap-3 bg-secondary/50 p-3">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span className="text-sm font-display tracking-wider">{mapping}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              <section>
                <h2 className="font-display text-2xl mb-4 text-emerald-400">SUPPORTED INDUSTRIES</h2>
                <div className="flex flex-wrap gap-3">
                  {SUPPORTED_INDUSTRIES.map(ind => (
                    <div key={ind} className="bg-card border-2 border-emerald-500/30 px-6 py-3 font-display tracking-wider text-emerald-400">
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
                <p className="text-sm text-muted-foreground mb-4">Defines impersonation boundaries for DoD and defense-sector engagements. All themes must be reviewed and approved before deployment in phishing campaigns.</p>
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
                <h2 className="font-display text-2xl mb-4 text-purple-400">APPROVED PHISHING TEMPLATE</h2>
                <p className="text-sm text-muted-foreground mb-4">Pre-approved neutral template for governance-themed phishing campaigns. Suitable for all supported industries. Requires approval workflow before deployment.</p>

                <div className="grid md:grid-cols-3 gap-4 mb-6">
                  <div className="bg-card border-2 border-purple-500/30 p-4 text-center">
                    <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">CATEGORY</p>
                    <p className="text-lg font-display text-purple-400">{GOPHISH_POLICY_TEMPLATE.category.toUpperCase()}</p>
                  </div>
                  <div className="bg-card border-2 border-purple-500/30 p-4 text-center">
                    <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">RISK LEVEL</p>
                    <p className="text-lg font-display text-green-400">{GOPHISH_POLICY_TEMPLATE.riskLevel.toUpperCase()}</p>
                  </div>
                  <div className="bg-card border-2 border-purple-500/30 p-4 text-center">
                    <p className="text-xs font-display tracking-wider text-muted-foreground mb-1">INDUSTRIES</p>
                    <p className="text-lg font-display text-purple-400">ALL</p>
                  </div>
                </div>

                <div className="bg-card border-2 border-purple-500/30 p-5">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-display text-lg text-purple-400">TEMPLATE PREVIEW</h3>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" className="text-xs border-purple-500/50 text-purple-400" onClick={copyTemplate}>
                        <Copy className="w-3 h-3 mr-1" />COPY
                      </Button>
                    </div>
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
                      <Button variant="outline" size="sm" className="w-full font-display tracking-wider border-purple-500/50 text-purple-400 hover:bg-purple-500/10">
                        IMPORT TO GOPHISH TEMPLATES
                      </Button>
                    </a>
                  </div>
                </div>
              </section>
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
