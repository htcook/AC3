import { useState } from "react";
import {
  Shield, Building2, ChevronRight, CheckCircle2, AlertTriangle,
  Layers, Lock, Eye, Server, Users, BookOpen, RefreshCw,
  FileText, Radar, Target, Zap, Brain, ShieldCheck, BarChart3,
  Monitor, Fingerprint, Network, Clock, ArrowRight
} from "lucide-react";

// ─── KSI Theme Data ─────────────────────────────────────────────────

type KSITheme = {
  id: string;
  name: string;
  abbrev: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  totalKSIs: number;
  directCoverage: number;
  supportingCoverage: number;
  description: string;
  cspValue: string;
  agencyValue: string;
  ksis: {
    id: string;
    name: string;
    status: "direct" | "supporting" | "planned";
    aceModules: string[];
  }[];
};

const KSI_THEMES: KSITheme[] = [
  {
    id: "vdr",
    name: "Vulnerability Detection & Response",
    abbrev: "VDR",
    icon: Target,
    color: "text-red-400",
    totalKSIs: 3,
    directCoverage: 3,
    supportingCoverage: 0,
    description: "Continuous vulnerability scanning, remediation within SLA, and annual penetration testing across all 6 FedRAMP attack vectors.",
    cspValue: "ACE C3 executes real penetration tests across all 6 mandatory attack vectors — external, internal, web app, API, mobile, and social engineering — with evidence capture proving exploitability.",
    agencyValue: "Monitor each CSP's vulnerability posture in real-time. Track remediation SLA compliance (30/90/180 days) and view penetration test evidence across your entire CSP portfolio.",
    ksis: [
      { id: "KSI-AFR-VDR", name: "Vulnerability Detection & Response", status: "direct", aceModules: ["Domain Intel", "Vuln Intel", "Validation Engine", "DAST Scanner"] },
      { id: "KSI-AFR-PTG", name: "Penetration Testing", status: "direct", aceModules: ["Exploit Arsenal", "Red Team Ops", "Phishing Ops", "DAST Scanner", "Post-Engagement Report"] },
      { id: "KSI-AFR-PVA", name: "Persistent Validation & Assessment", status: "direct", aceModules: ["Validation Scheduler", "Agentless BAS", "ATT&CK Validation Tests"] },
    ],
  },
  {
    id: "pva",
    name: "Persistent Validation & Assessment",
    abbrev: "PVA",
    icon: ShieldCheck,
    color: "text-emerald-400",
    totalKSIs: 4,
    directCoverage: 3,
    supportingCoverage: 1,
    description: "Machine-based validation at 3-day/7-day cadence, authorization data sharing via trust centers, and ongoing assessment reports.",
    cspValue: "Automated KSI validation at FedRAMP-mandated frequencies. Generate machine-readable OSCAL evidence packages and publish to your trust center automatically.",
    agencyValue: "Aggregate trust center data from all your authorized CSPs. Compare validation frequencies, identify CSPs falling behind on assessment cadence, and receive alerts on significant changes.",
    ksis: [
      { id: "KSI-AFR-ADS", name: "Authorization Data Sharing", status: "direct", aceModules: ["Trust Center Portal", "OSCAL Export Engine"] },
      { id: "KSI-AFR-OAR", name: "Ongoing Assessment Reports", status: "direct", aceModules: ["OAR Generator", "Evidence Chain", "Report Generator"] },
      { id: "KSI-AFR-SCN", name: "Significant Change Notification", status: "direct", aceModules: ["Change Monitor", "Trust Center Portal"] },
      { id: "KSI-AFR-FBM", name: "Feedback Mechanism", status: "supporting", aceModules: ["Agency Feedback Hub", "Trust Center Portal"] },
    ],
  },
  {
    id: "iam",
    name: "Identity & Access Management",
    abbrev: "IAM",
    icon: Fingerprint,
    color: "text-blue-400",
    totalKSIs: 7,
    directCoverage: 4,
    supportingCoverage: 2,
    description: "Phishing-resistant MFA, privileged access management, least privilege enforcement, and account lifecycle controls.",
    cspValue: "Validate IAM configurations across AWS, Azure, and GCP. Test MFA bypass resistance, audit privileged access, and verify least privilege with automated IAM policy analysis.",
    agencyValue: "Verify each CSP enforces phishing-resistant MFA, PAM controls, and least privilege. Cross-CSP IAM posture comparison identifies which providers have the strongest identity controls.",
    ksis: [
      { id: "KSI-IAM-MFA", name: "Phishing-Resistant MFA", status: "direct", aceModules: ["IAM Auditor", "Phishing Ops (MFA bypass testing)"] },
      { id: "KSI-IAM-PAM", name: "Privileged Access Management", status: "direct", aceModules: ["IAM Auditor", "AD Attack Simulation"] },
      { id: "KSI-IAM-ALC", name: "Account Lifecycle", status: "direct", aceModules: ["IAM Auditor", "AD Domain Connector"] },
      { id: "KSI-IAM-LPR", name: "Least Privilege", status: "direct", aceModules: ["IAM Auditor", "Cloud Attack Paths"] },
      { id: "KSI-IAM-JIT", name: "Just-in-Time Access", status: "supporting", aceModules: ["IAM Auditor"] },
      { id: "KSI-IAM-SSO", name: "Single Sign-On", status: "supporting", aceModules: ["IAM Auditor"] },
      { id: "KSI-IAM-NAC", name: "Network Access Control", status: "planned", aceModules: ["Config Baseline Engine"] },
    ],
  },
  {
    id: "cmt",
    name: "Change Management",
    abbrev: "CMT",
    icon: RefreshCw,
    color: "text-amber-400",
    totalKSIs: 4,
    directCoverage: 2,
    supportingCoverage: 2,
    description: "Automated configuration management, configuration databases, documented changes, and deployment validation.",
    cspValue: "Detect configuration drift from baselines, validate changes through deployment with automated testing, and maintain a complete audit trail of all security-relevant changes.",
    agencyValue: "Track configuration change velocity across CSPs. Verify each provider validates changes before deployment and maintains tamper-resistant change documentation.",
    ksis: [
      { id: "KSI-CMT-ACM", name: "Automate Configuration Management", status: "supporting", aceModules: ["Config Baseline Engine", "Validation Scheduler"] },
      { id: "KSI-CMT-CDB", name: "Configuration Database", status: "supporting", aceModules: ["Config Baseline Engine", "Domain Intel"] },
      { id: "KSI-CMT-DCH", name: "Document Changes", status: "direct", aceModules: ["Evidence Chain", "RoE Version History", "Audit Log"] },
      { id: "KSI-CMT-VTD", name: "Validate Through Deployment", status: "direct", aceModules: ["Validation Scheduler", "Agentless BAS", "ATT&CK Validation"] },
    ],
  },
  {
    id: "cna",
    name: "Cloud Native Architecture",
    abbrev: "CNA",
    icon: Server,
    color: "text-cyan-400",
    totalKSIs: 8,
    directCoverage: 2,
    supportingCoverage: 4,
    description: "Minimal attack surface, logical network segmentation, DoS protection, high availability, resilience, and container security.",
    cspValue: "Continuously scan for exposed attack surface, test network segmentation with real exploit attempts, validate container image security, and verify resilience configurations.",
    agencyValue: "Assess each CSP's architecture maturity. Compare attack surface sizes, segmentation strength, and container security posture across your authorized providers.",
    ksis: [
      { id: "KSI-CNA-MAS", name: "Minimal Attack Surface", status: "direct", aceModules: ["Domain Intel", "DAST Scanner", "Vulnerability Scanner"] },
      { id: "KSI-CNA-DFP", name: "Define Functionality/Privileges", status: "direct", aceModules: ["IAM Auditor", "Cloud Attack Paths"] },
      { id: "KSI-CNA-LNS", name: "Logical Network Segmentation", status: "supporting", aceModules: ["Config Baseline Engine", "NGFW Validation"] },
      { id: "KSI-CNA-CIS", name: "Container/Image Security", status: "supporting", aceModules: ["Config Baseline Engine", "Nuclei Scanner"] },
      { id: "KSI-CNA-DOS", name: "DoS Protection", status: "supporting", aceModules: ["Config Baseline Engine"] },
      { id: "KSI-CNA-HAV", name: "High Availability", status: "supporting", aceModules: ["Recovery Validation Module"] },
      { id: "KSI-CNA-RES", name: "Resilience", status: "planned", aceModules: ["Recovery Validation Module"] },
      { id: "KSI-CNA-SSM", name: "Secure Software Management", status: "planned", aceModules: ["Config Baseline Engine"] },
    ],
  },
  {
    id: "mla",
    name: "Monitoring, Logging & Alerting",
    abbrev: "MLA",
    icon: Eye,
    color: "text-violet-400",
    totalKSIs: 5,
    directCoverage: 3,
    supportingCoverage: 2,
    description: "Centralized logging, event type catalogs, tamper-resistant logs, log archival, and security monitoring.",
    cspValue: "Validate SIEM coverage against executed TTPs. Auto-generate detection rules from red team findings and measure detection gaps with coverage matrix analysis.",
    agencyValue: "Verify each CSP maintains centralized, tamper-resistant logging with adequate retention. Compare detection coverage across providers and identify monitoring blind spots.",
    ksis: [
      { id: "KSI-MLA-CLG", name: "Centralized Logging", status: "direct", aceModules: ["SIEM Connector", "Evidence Chain"] },
      { id: "KSI-MLA-ETC", name: "Event Type Catalog", status: "direct", aceModules: ["SIEM Connector", "Detection Rule Generator"] },
      { id: "KSI-MLA-MON", name: "Security Monitoring", status: "direct", aceModules: ["SIEM Connector", "Continuous Validation"] },
      { id: "KSI-MLA-TRL", name: "Tamper-Resistant Logging", status: "supporting", aceModules: ["SIEM Connector", "Config Baseline Engine"] },
      { id: "KSI-MLA-ARC", name: "Log Archival", status: "supporting", aceModules: ["Config Baseline Engine"] },
    ],
  },
  {
    id: "svc",
    name: "Service Configuration & Vaulting",
    abbrev: "SVC",
    icon: Lock,
    color: "text-pink-400",
    totalKSIs: 7,
    directCoverage: 2,
    supportingCoverage: 3,
    description: "Encryption at rest and in transit, data handling restrictions, key management, API security, and secure configuration guides.",
    cspValue: "Validate TLS configurations, test API security with DAST scanning, verify encryption implementations, and auto-generate secure configuration guides for customers.",
    agencyValue: "Audit encryption standards across CSPs. Verify API security posture, review secure configuration guides, and ensure data handling meets FedRAMP requirements.",
    ksis: [
      { id: "KSI-SVC-API", name: "API Security", status: "direct", aceModules: ["DAST Scanner", "API Security Testing", "OpenAPI Import"] },
      { id: "KSI-SVC-EIT", name: "Encryption in Transit", status: "direct", aceModules: ["Encryption Validator", "Email Security Analyzer"] },
      { id: "KSI-SVC-EAR", name: "Encryption at Rest", status: "supporting", aceModules: ["Encryption Validator", "Config Baseline Engine"] },
      { id: "KSI-SVC-KMG", name: "Key Management", status: "supporting", aceModules: ["Encryption Validator", "Config Baseline Engine"] },
      { id: "KSI-SVC-SCG", name: "Secure Configuration Guide", status: "supporting", aceModules: ["SCG Generator"] },
      { id: "KSI-SVC-DHR", name: "Data Handling Restrictions", status: "planned", aceModules: ["Encryption Validator"] },
      { id: "KSI-SVC-TPA", name: "Third-Party Access", status: "planned", aceModules: ["Config Baseline Engine"] },
    ],
  },
  {
    id: "rpl",
    name: "Resilience, Planning & Logistics",
    abbrev: "RPL",
    icon: RefreshCw,
    color: "text-orange-400",
    totalKSIs: 4,
    directCoverage: 1,
    supportingCoverage: 2,
    description: "Backup alignment, recovery validation testing, RTO/RPO objectives, and disaster recovery planning.",
    cspValue: "Automate recovery validation testing — trigger backup restores, measure actual RTO/RPO against targets, and generate evidence of successful recovery exercises.",
    agencyValue: "Verify each CSP regularly tests recovery procedures. Compare RTO/RPO targets vs. actuals and ensure disaster recovery plans are validated, not just documented.",
    ksis: [
      { id: "KSI-RPL-RVT", name: "Recovery Validation Testing", status: "direct", aceModules: ["Recovery Validation Module"] },
      { id: "KSI-RPL-RTO", name: "RTO/RPO Objectives", status: "supporting", aceModules: ["Recovery Validation Module", "BIA Report"] },
      { id: "KSI-RPL-BAL", name: "Backup Alignment", status: "supporting", aceModules: ["Recovery Validation Module", "Config Baseline"] },
      { id: "KSI-RPL-DRP", name: "Disaster Recovery Plan", status: "planned", aceModules: ["Recovery Validation Module"] },
    ],
  },
  {
    id: "ced",
    name: "Cybersecurity Education",
    abbrev: "CED",
    icon: BookOpen,
    color: "text-teal-400",
    totalKSIs: 4,
    directCoverage: 1,
    supportingCoverage: 1,
    description: "Security awareness training, developer training, incident response training, and privileged user training.",
    cspValue: "Run realistic phishing simulations with 17 exploit techniques to measure security awareness. Track click rates, credential capture, and improvement over time.",
    agencyValue: "Review CSP training program effectiveness through phishing simulation results. Compare awareness metrics across providers and verify training frequency compliance.",
    ksis: [
      { id: "KSI-CED-SAT", name: "Security Awareness Training", status: "direct", aceModules: ["Phishing Ops", "Campaign Wizard", "Template Generator"] },
      { id: "KSI-CED-IRT", name: "Incident Response Training", status: "supporting", aceModules: ["Red Team Ops", "Purple Team Exercises"] },
      { id: "KSI-CED-DVT", name: "Developer Training", status: "planned", aceModules: ["Evidence Chain (manual)"] },
      { id: "KSI-CED-PRT", name: "Privileged User Training", status: "planned", aceModules: ["Evidence Chain (manual)"] },
    ],
  },
];

// ─── Summary Stats ──────────────────────────────────────────────────

const TOTAL_KSIS = 55;
const DIRECT = KSI_THEMES.reduce((sum, t) => sum + t.directCoverage, 0);
const SUPPORTING = KSI_THEMES.reduce((sum, t) => sum + t.supportingCoverage, 0);
const PLANNED = TOTAL_KSIS - DIRECT - SUPPORTING;
const COVERAGE_PCT = Math.round(((DIRECT + SUPPORTING) / TOTAL_KSIS) * 100);

// ─── Component ──────────────────────────────────────────────────────

export default function FedRAMPKSIMap() {
  const [activeView, setActiveView] = useState<"csp" | "agency">("csp");
  const [expandedTheme, setExpandedTheme] = useState<string | null>(null);

  return (
    <section id="fedramp-20x" className="py-20">
      <div className="container">
        {/* Header */}
        <div className="mb-12">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-8 h-8 text-primary" />
            <span className="font-display text-xs tracking-[0.3em] text-primary">COMPLIANCE ENABLEMENT</span>
          </div>
          <h2 className="text-4xl sm:text-5xl font-display mb-4">FEDRAMP 20x KSI MAP</h2>
          <p className="text-lg text-muted-foreground max-w-3xl">
            How ACE C3 maps to all 55 FedRAMP Key Security Indicators across 9 compliance themes — 
            enabling cloud service providers to achieve authorization and federal agencies to monitor their CSP portfolio.
          </p>
        </div>

        {/* Coverage Summary Bar */}
        <div className="mb-10 p-6 border-2 border-primary/30 bg-primary/5">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div>
              <div className="font-display text-5xl text-primary mb-1">{COVERAGE_PCT}%</div>
              <div className="text-sm text-muted-foreground">KSI COVERAGE</div>
            </div>
            <div className="flex-1 max-w-xl w-full">
              <div className="h-4 bg-card border border-border overflow-hidden flex">
                <div
                  className="h-full bg-primary transition-all duration-1000"
                  style={{ width: `${(DIRECT / TOTAL_KSIS) * 100}%` }}
                />
                <div
                  className="h-full bg-primary/40 transition-all duration-1000"
                  style={{ width: `${(SUPPORTING / TOTAL_KSIS) * 100}%` }}
                />
              </div>
              <div className="flex items-center gap-6 mt-3 text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-primary" />
                  <span className="text-muted-foreground">{DIRECT} Direct ({Math.round((DIRECT / TOTAL_KSIS) * 100)}%)</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-primary/40" />
                  <span className="text-muted-foreground">{SUPPORTING} Supporting ({Math.round((SUPPORTING / TOTAL_KSIS) * 100)}%)</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-muted border border-border" />
                  <span className="text-muted-foreground">{PLANNED} Planned</span>
                </div>
              </div>
            </div>
            <div className="text-right">
              <div className="font-display text-2xl">{TOTAL_KSIS}</div>
              <div className="text-xs text-muted-foreground">TOTAL KSIs</div>
            </div>
          </div>
        </div>

        {/* CSP / Agency Toggle */}
        <div className="flex items-center gap-2 mb-8">
          <button
            onClick={() => setActiveView("csp")}
            className={`flex items-center gap-2 px-5 py-3 font-display text-sm tracking-wider border-2 transition-all ${
              activeView === "csp"
                ? "border-primary bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:border-primary/50 hover:text-foreground"
            }`}
          >
            <Building2 className="w-4 h-4" />
            FOR CLOUD SERVICE PROVIDERS
          </button>
          <button
            onClick={() => setActiveView("agency")}
            className={`flex items-center gap-2 px-5 py-3 font-display text-sm tracking-wider border-2 transition-all ${
              activeView === "agency"
                ? "border-primary bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:border-primary/50 hover:text-foreground"
            }`}
          >
            <Layers className="w-4 h-4" />
            FOR FEDERAL AGENCIES
          </button>
        </div>

        {/* View Description */}
        <div className="mb-8 p-4 border border-border/50 bg-card/30">
          {activeView === "csp" ? (
            <p className="text-sm text-muted-foreground leading-relaxed">
              <span className="text-primary font-display tracking-wider">CSP VIEW</span> — ACE C3 helps cloud service providers achieve and maintain FedRAMP authorization by providing automated KSI validation, evidence generation, penetration testing across all 6 mandatory attack vectors, and machine-readable OSCAL export for direct submission to the FedRAMP PMO.
            </p>
          ) : (
            <p className="text-sm text-muted-foreground leading-relaxed">
              <span className="text-primary font-display tracking-wider">AGENCY VIEW</span> — ACE C3 helps federal agencies monitor their authorized CSP portfolio through aggregated trust center data, cross-CSP vulnerability correlation, real-time KSI compliance dashboards, and structured feedback mechanisms aligned to FedRAMP's Collaborative Continuous Monitoring requirements.
            </p>
          )}
        </div>

        {/* KSI Theme Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {KSI_THEMES.map((theme) => {
            const isExpanded = expandedTheme === theme.id;
            const coveragePct = Math.round(((theme.directCoverage + theme.supportingCoverage) / theme.totalKSIs) * 100);

            return (
              <div
                key={theme.id}
                className={`border-2 transition-all cursor-pointer ${
                  isExpanded
                    ? "border-primary bg-primary/5 md:col-span-2 lg:col-span-3"
                    : "border-border hover:border-primary/50 bg-card/30"
                }`}
                onClick={() => setExpandedTheme(isExpanded ? null : theme.id)}
              >
                {/* Theme Header */}
                <div className="p-5">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <theme.icon className={`w-5 h-5 ${theme.color}`} />
                      <div>
                        <span className="font-display text-[10px] tracking-[0.2em] text-muted-foreground">{theme.abbrev}</span>
                        <h3 className="font-display text-sm tracking-wider leading-tight">{theme.name}</h3>
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0 ml-3">
                      <div className={`font-display text-xl ${coveragePct === 100 ? 'text-emerald-400' : coveragePct >= 75 ? 'text-primary' : 'text-amber-400'}`}>
                        {coveragePct}%
                      </div>
                      <div className="text-[10px] text-muted-foreground">{theme.totalKSIs} KSIs</div>
                    </div>
                  </div>

                  {/* Mini coverage bar */}
                  <div className="h-1.5 bg-card border border-border/50 overflow-hidden flex mb-3">
                    <div className="h-full bg-primary" style={{ width: `${(theme.directCoverage / theme.totalKSIs) * 100}%` }} />
                    <div className="h-full bg-primary/40" style={{ width: `${(theme.supportingCoverage / theme.totalKSIs) * 100}%` }} />
                  </div>

                  <p className="text-xs text-muted-foreground leading-relaxed">{theme.description}</p>

                  {!isExpanded && (
                    <div className="flex items-center gap-1 mt-3 text-xs text-primary font-display tracking-wider">
                      VIEW DETAILS <ChevronRight className="w-3 h-3" />
                    </div>
                  )}
                </div>

                {/* Expanded Detail */}
                {isExpanded && (
                  <div className="border-t border-border/50 p-5">
                    {/* Value Proposition */}
                    <div className="mb-6 p-4 bg-card/50 border border-border/30">
                      <div className="flex items-center gap-2 mb-2">
                        {activeView === "csp" ? (
                          <Building2 className="w-4 h-4 text-primary" />
                        ) : (
                          <Layers className="w-4 h-4 text-primary" />
                        )}
                        <span className="font-display text-xs tracking-wider text-primary">
                          {activeView === "csp" ? "HOW ACE C3 HELPS CSPs" : "HOW ACE C3 HELPS AGENCIES"}
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground leading-relaxed">
                        {activeView === "csp" ? theme.cspValue : theme.agencyValue}
                      </p>
                    </div>

                    {/* Individual KSIs */}
                    <div className="space-y-2">
                      <div className="font-display text-xs tracking-[0.2em] text-muted-foreground mb-3">
                        INDIVIDUAL KEY SECURITY INDICATORS
                      </div>
                      {theme.ksis.map((ksi) => (
                        <div
                          key={ksi.id}
                          className="flex items-start gap-3 p-3 bg-card/30 border border-border/20"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <div className="flex-shrink-0 mt-0.5">
                            {ksi.status === "direct" ? (
                              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                            ) : ksi.status === "supporting" ? (
                              <CheckCircle2 className="w-4 h-4 text-primary/60" />
                            ) : (
                              <Clock className="w-4 h-4 text-amber-400/60" />
                            )}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-display text-xs tracking-wider">{ksi.name}</span>
                              <span className={`text-[9px] px-1.5 py-0.5 font-display tracking-wider ${
                                ksi.status === "direct"
                                  ? "bg-emerald-400/10 text-emerald-400 border border-emerald-400/20"
                                  : ksi.status === "supporting"
                                  ? "bg-primary/10 text-primary border border-primary/20"
                                  : "bg-amber-400/10 text-amber-400 border border-amber-400/20"
                              }`}>
                                {ksi.status === "direct" ? "DIRECT" : ksi.status === "supporting" ? "SUPPORTING" : "PLANNED"}
                              </span>
                            </div>
                            <div className="flex flex-wrap gap-1.5">
                              {ksi.aceModules.map((mod) => (
                                <span key={mod} className="text-[10px] text-muted-foreground bg-background/50 border border-border/30 px-1.5 py-0.5">
                                  {mod}
                                </span>
                              ))}
                            </div>
                          </div>
                          <span className="text-[9px] text-muted-foreground font-mono flex-shrink-0">{ksi.id}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Bottom CTA */}
        <div className="mt-10 p-6 border-2 border-border bg-card/30 flex flex-col md:flex-row items-center justify-between gap-6">
          <div>
            <h3 className="font-display text-xl tracking-wider mb-2">
              {activeView === "csp"
                ? "READY TO ACHIEVE FEDRAMP 20x AUTHORIZATION?"
                : "READY TO MONITOR YOUR CSP PORTFOLIO?"}
            </h3>
            <p className="text-sm text-muted-foreground">
              {activeView === "csp"
                ? "ACE C3 covers 87% of all 55 KSIs today — with automated validation, evidence generation, and OSCAL export for direct FedRAMP submission."
                : "ACE C3 provides a unified view across all your authorized CSPs — with real-time KSI monitoring, cross-CSP vulnerability correlation, and compliance trending."}
            </p>
          </div>
          <a href="mailto:info@aceofcloud.com" className="flex-shrink-0">
            <button className="flex items-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 text-white font-display text-sm tracking-wider transition-colors">
              CONTACT US <ArrowRight className="w-4 h-4" />
            </button>
          </a>
        </div>

        {/* Compliance References */}
        <div className="mt-6 flex flex-wrap items-center gap-x-6 gap-y-2 text-[10px] text-muted-foreground/60 font-display tracking-wider">
          <span>ALIGNED TO:</span>
          <span>NIST SP 800-53 Rev 5</span>
          <span>•</span>
          <span>NIST SP 800-115</span>
          <span>•</span>
          <span>FEDRAMP 20x FRAMEWORK</span>
          <span>•</span>
          <span>NIST OSCAL</span>
          <span>•</span>
          <span>CISA KEV CATALOG</span>
          <span>•</span>
          <span>MITRE ATT&CK v15</span>
        </div>
      </div>
    </section>
  );
}
