import { useState } from "react";
import FedRAMPKSIMap from "@/components/FedRAMPKSIMap";
import {
  Shield, CheckCircle2, ChevronRight, Target, BarChart3,
  AlertTriangle, X, Info, Landmark, ArrowRight, ChevronDown, ChevronUp, FileText
} from "lucide-react";
import { Button } from "@/components/ui/button";

// ─── Collapsible Section (local) ─────────────────────────────────
function CollapsibleSection({ title, defaultOpen = false, children }: {
  title: string; defaultOpen?: boolean; children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-border/50 bg-card/30">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between text-left p-6 group hover:bg-card/50 transition-colors"
      >
        <h3 className="font-display text-lg tracking-wider group-hover:text-primary transition-colors">{title}</h3>
        <div className="flex-shrink-0 ml-4 w-8 h-8 flex items-center justify-center border border-border group-hover:border-primary transition-colors">
          {open ? <ChevronUp className="w-4 h-4 text-muted-foreground group-hover:text-primary" /> : <ChevronDown className="w-4 h-4 text-muted-foreground group-hover:text-primary" />}
        </div>
      </button>
      <div className={`overflow-hidden transition-all duration-500 ease-in-out ${open ? 'max-h-[10000px] opacity-100' : 'max-h-0 opacity-0'}`}>
        <div className="px-6 pb-6">
          {children}
        </div>
      </div>
    </div>
  );
}

export default function FedRAMP20xReadiness() {
  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-3">
          <Landmark className="w-7 h-7 text-primary" />
          <span className="font-display text-xs tracking-[0.3em] text-primary">FEDRAMP 20x READINESS</span>
        </div>
        <h2 className="text-2xl font-display mb-2">FedRAMP 20x Framework &amp; KSI Coverage</h2>
        <p className="text-muted-foreground max-w-3xl">
          Understand the FedRAMP 20x modernization, how Key Security Indicators (KSIs) work, and how Ace C3 maps to
          all 13 security themes with 75 KSIs — providing 88% coverage through real security testing and evidence generation.
        </p>
      </div>

      {/* ─── What Is FedRAMP 20x ─────────────────────────────── */}
      <CollapsibleSection title="WHAT IS FEDRAMP 20x?" defaultOpen={true}>
        <div className="grid md:grid-cols-2 gap-10">
          <div>
            <p className="text-sm text-muted-foreground leading-relaxed mb-5">
              FedRAMP 20x is the modernized Federal Risk and Authorization Management Program, replacing the traditional
              control-by-control audit approach with <strong className="text-foreground">outcome-based security validation</strong>.
              Instead of documenting hundreds of individual controls in static spreadsheets, cloud service providers now
              demonstrate security through measurable, continuously monitored indicators that prove their systems
              actually work as intended.
            </p>
            <p className="text-sm text-muted-foreground leading-relaxed">
              The shift is fundamental: FedRAMP 20x moves from <strong className="text-foreground">"describe what you plan to do"</strong> to
              <strong className="text-foreground"> "prove what you actually do."</strong> This means automated evidence collection,
              real penetration testing, and continuous monitoring replace the paper-heavy assessment process that
              previously took 12-18 months and cost millions of dollars.
            </p>
          </div>
          <div>
            <div className="border-2 border-primary/30 bg-primary/5 p-5">
              <h4 className="font-display text-sm tracking-wider text-primary mb-4">KEY CHANGES IN 20x</h4>
              <div className="space-y-3">
                {[
                  { title: "OUTCOME-BASED VALIDATION", desc: "Security is measured by what systems actually do, not what documentation says they should do" },
                  { title: "CONTINUOUS MONITORING", desc: "Ongoing automated evidence collection replaces point-in-time annual assessments" },
                  { title: "MACHINE-READABLE EVIDENCE", desc: "OSCAL-formatted packages enable automated review instead of manual document analysis" },
                  { title: "FASTER AUTHORIZATION", desc: "Target timeline reduced from 12-18 months to weeks through automation and standardized evidence" },
                ].map((item) => (
                  <div key={item.title} className="flex items-start gap-3">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="font-display text-xs tracking-wider mb-0.5">{item.title}</div>
                      <p className="text-xs text-muted-foreground">{item.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </CollapsibleSection>

      {/* ─── What Are KSIs ───────────────────────────────────── */}
      <CollapsibleSection title="WHAT ARE KEY SECURITY INDICATORS?" defaultOpen={true}>
        <div className="grid md:grid-cols-3 gap-6 mb-6">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Shield className="w-5 h-5 text-primary" />
              <span className="font-display text-xs tracking-wider">13 SECURITY THEMES</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Key Security Indicators (KSIs) are organized into 13 themes that cover the full spectrum of cloud security:
              from identity and access management to incident response, from vulnerability management to supply chain risk.
              Each theme contains specific, measurable indicators that CSPs must demonstrate.
            </p>
          </div>
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Target className="w-5 h-5 text-primary" />
              <span className="font-display text-xs tracking-wider">MEASURABLE OUTCOMES</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Unlike the old control catalog, KSIs require evidence that the security function works, not just that a policy
              document exists. Each KSI requires evidence that the security function works, not just that a policy document exists.
            </p>
          </div>
          <div>
            <div className="flex items-center gap-2 mb-3">
              <BarChart3 className="w-5 h-5 text-primary" />
              <span className="font-display text-xs tracking-wider">CONTINUOUS PROOF</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              KSIs are not one-time checkboxes. They require ongoing evidence that security controls remain effective.
              This means automated scanning, regular penetration testing, continuous vulnerability monitoring,
              and real-time incident detection — all producing machine-readable evidence for FedRAMP review.
            </p>
          </div>
        </div>

        {/* 13 Theme Quick Reference */}
        <div className="p-5 border border-border bg-card/30">
          <div className="font-display text-xs tracking-[0.2em] text-muted-foreground mb-4">THE 13 FEDRAMP 20x KSI THEMES</div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
            {[
              { code: "AFR", name: "Authorization by FedRAMP", desc: "Data sharing, security inbox, continuous reporting" },
              { code: "CMT", name: "Configuration Management", desc: "Baselines, change control, inventory" },
              { code: "CNA", name: "Cloud Native Architecture", desc: "Zero trust, microsegmentation, high availability" },
              { code: "CED", name: "Cybersecurity Education", desc: "Phishing resistance, security training" },
              { code: "IAM", name: "Identity & Access Management", desc: "MFA, privileged access, authentication" },
              { code: "INR", name: "Incident Response", desc: "Detection, containment, after-action analysis" },
              { code: "MLA", name: "Monitoring, Logging & Auditing", desc: "SIEM, log integrity, alerting" },
              { code: "PIY", name: "Plan, Policy & Procedure", desc: "Security plans, risk assessment, governance" },
              { code: "RPL", name: "Resilience Planning", desc: "Disaster recovery, backup, business continuity" },
              { code: "SVC", name: "Vulnerability & Config Scanning", desc: "Vuln management, patching, remediation" },
              { code: "SCR", name: "Supply Chain Risk", desc: "Third-party risk, software composition" },
              { code: "SDE", name: "Secure Development", desc: "Secure SDLC, code security testing" },
              { code: "PPM", name: "Policy & Procedure Management", desc: "Policy review, compliance tracking" },
            ].map((t) => (
              <div key={t.code} className="p-2.5 border border-border/50 bg-background/30">
                <div className="font-display text-xs tracking-wider text-primary mb-0.5">{t.code}</div>
                <div className="text-xs font-medium mb-0.5">{t.name}</div>
                <div className="text-[10px] text-muted-foreground">{t.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </CollapsibleSection>

      {/* ─── Ace C3's Role ───────────────────────────────────── */}
      <CollapsibleSection title="ACE C3'S ROLE IN FEDRAMP 20x" defaultOpen={true}>
        <div className="grid md:grid-cols-2 gap-6 mb-6">
          <div className="border-2 border-emerald-400/30 bg-emerald-400/5 p-5">
            <div className="flex items-center gap-2 mb-4">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <span className="font-display text-xs tracking-wider text-emerald-400">WHAT ACE C3 DOES</span>
            </div>
            <ul className="space-y-3 text-sm text-muted-foreground">
              {[
                { bold: "Generates real evidence", rest: " through penetration testing, adversary emulation, DAST scanning, and vulnerability assessment — not simulated results" },
                { bold: "Validates security controls", rest: " by running actual attacks against your infrastructure and measuring detection, prevention, and response capabilities" },
                { bold: "Maps findings to NIST SP 800-53", rest: " controls with 142 traceable control mappings across all 75 KSIs for FedRAMP traceability" },
                { bold: "Provides continuous monitoring", rest: " with automated evidence collection, scheduled validation, and SHA-256 hash-chained evidence for tamper resistance" },
                { bold: "Tests all 6 mandatory attack vectors", rest: " required by FedRAMP: external, internal, social engineering, cloud-specific, API, and supply chain" },
              ].map((item, i) => (
                <li key={i} className="flex items-start gap-2">
                  <ChevronRight className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                  <span><strong className="text-foreground">{item.bold}</strong>{item.rest}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <div className="border-2 border-amber-400/30 bg-amber-400/5 p-5">
              <div className="flex items-center gap-2 mb-4">
                <AlertTriangle className="w-5 h-5 text-amber-400" />
                <span className="font-display text-xs tracking-wider text-amber-400">WHAT ACE C3 IS NOT</span>
              </div>
              <ul className="space-y-3 text-sm text-muted-foreground">
                {[
                  { bold: "Not a compliance certifier", rest: " — Ace C3 does not grant FedRAMP authorization. Authorization is issued by the FedRAMP PMO after review by a 3PAO" },
                  { bold: "Not a GRC platform", rest: " — Ace C3 focuses on technical security validation, not governance documentation management or policy authoring" },
                  { bold: "Not a replacement for 3PAO assessment", rest: " — Ace C3 produces the evidence that 3PAOs review; it does not replace the independent assessment requirement" },
                  { bold: "Not a checkbox tool", rest: " — Ace C3 runs real attacks and produces real evidence. If your controls fail, the platform reports failures honestly" },
                ].map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <X className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                    <span><strong className="text-foreground">{item.bold}</strong>{item.rest}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="mt-4 p-4 border border-primary/30 bg-primary/5">
              <div className="flex items-start gap-2">
                <Info className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
                <p className="text-xs text-muted-foreground leading-relaxed">
                  <strong className="text-foreground">In practice:</strong> Ace C3 is the technical engine that generates the evidence your 3PAO needs to see.
                  It runs the penetration tests, validates the controls, monitors for drift, and packages the results.
                  Your 3PAO reviews this evidence as part of the FedRAMP authorization process.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Download Readiness Guide */}
        <div className="p-4 border border-primary/30 bg-primary/5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <FileText className="w-5 h-5 text-primary" />
            <div>
              <div className="font-display text-xs tracking-wider">FEDRAMP 20x READINESS GUIDE</div>
              <p className="text-xs text-muted-foreground">Comprehensive PDF covering SaaS/PaaS breakdowns and full KSI-to-capability mapping</p>
            </div>
          </div>
          <a href="/FedRAMP_20x_Readiness_Guide.pdf" download>
            <Button variant="outline" size="sm" className="font-display tracking-wider text-xs">
              <ArrowRight className="w-3 h-3 mr-1" />
              DOWNLOAD PDF
            </Button>
          </a>
        </div>
      </CollapsibleSection>

      {/* ─── Full KSI Coverage Map ───────────────────────────── */}
      <div>
        <FedRAMPKSIMap embedded />
      </div>
    </div>
  );
}
