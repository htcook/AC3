import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

// ─── Test: Report DOCX generation includes all required sections ───

describe('AC3 Report DOCX Generation', () => {
  const reportFile = path.join(__dirname, 'routers', 'ac3-reports.ts');
  let reportCode: string;

  it('ac3-reports.ts exists and is readable', () => {
    expect(fs.existsSync(reportFile)).toBe(true);
    reportCode = fs.readFileSync(reportFile, 'utf-8');
    expect(reportCode.length).toBeGreaterThan(1000);
  });

  // ── Executive Summary Section ──
  describe('Executive Summary', () => {
    it('includes Overall Risk Level badge', () => {
      reportCode = fs.readFileSync(reportFile, 'utf-8');
      expect(reportCode).toContain("'Overall Risk Level: '");
      expect(reportCode).toContain('overallRisk.toUpperCase()');
    });

    it('includes severity breakdown table', () => {
      expect(reportCode).toContain("'Vulnerability Severity Distribution:'");
      expect(reportCode).toContain("'Critical'");
      expect(reportCode).toContain("'High'");
      expect(reportCode).toContain("'Moderate'");
      expect(reportCode).toContain("'Low'");
      expect(reportCode).toContain("'Informational'");
      expect(reportCode).toContain("'Total'");
    });

    it('includes risk statement section', () => {
      expect(reportCode).toContain("'Risk Assessment: '");
      expect(reportCode).toContain('rptExecRiskStatement');
    });

    it('includes key strengths and gaps', () => {
      expect(reportCode).toContain("'Key Strengths:'");
      expect(reportCode).toContain("'Key Gaps:'");
    });
  });

  // ── Methodology Section ──
  describe('Test Methodology & Approach', () => {
    it('includes methodology section in DOCX', () => {
      reportCode = fs.readFileSync(reportFile, 'utf-8');
      expect(reportCode).toContain("'3. Test Methodology & Approach'");
    });

    it('includes PTES and NIST 800-115 references', () => {
      expect(reportCode).toContain('Penetration Testing Execution Standard (PTES)');
      expect(reportCode).toContain('NIST SP 800-115');
      expect(reportCode).toContain('OWASP Testing Guide');
    });

    it('includes testing phases', () => {
      expect(reportCode).toContain("'Testing Phases:'");
      expect(reportCode).toContain('Reconnaissance & OSINT');
      expect(reportCode).toContain('Vulnerability Detection');
      expect(reportCode).toContain('Exploitation & Validation');
    });

    it('includes tools used section', () => {
      expect(reportCode).toContain("'Tools & Technologies Used:'");
      expect(reportCode).toContain('toolDescriptions');
      expect(reportCode).toContain("'nuclei'");
      expect(reportCode).toContain("'nikto'");
      expect(reportCode).toContain("'zap'");
    });

    it('includes approach description', () => {
      expect(reportCode).toContain("'Approach:'");
      expect(reportCode).toContain('passive reconnaissance');
      expect(reportCode).toContain('Active enumeration');
    });

    it('includes compliance framework reference', () => {
      expect(reportCode).toContain("'Compliance Framework: '");
      expect(reportCode).toContain('nist_800_53_r5');
    });

    it('methodology section is included in document assembly', () => {
      expect(reportCode).toContain('...methodologySection,');
    });
  });

  // ── Section Numbering ──
  describe('Section Numbering', () => {
    it('has correct section numbers after methodology insertion', () => {
      reportCode = fs.readFileSync(reportFile, 'utf-8');
      expect(reportCode).toContain("'1. Executive Summary'");
      expect(reportCode).toContain("'2. Scope & Methodology'");
      expect(reportCode).toContain("'3. Test Methodology & Approach'");
      expect(reportCode).toContain("'4. Findings Summary'");
      expect(reportCode).toContain("'5. Detailed Findings'");
      expect(reportCode).toContain("'6. Appendix");
    });
  });

  // ── Evidence Enrichment ──
  describe('Evidence Enrichment from Scan Results', () => {
    it('queries scan_results table for real tool output', () => {
      reportCode = fs.readFileSync(reportFile, 'utf-8');
      expect(reportCode).toContain('scanResultRows');
      expect(reportCode).toContain('.from(scanResults)');
    });

    it('builds target-to-scan evidence index', () => {
      expect(reportCode).toContain('scanEvidenceByTarget');
      expect(reportCode).toContain('normalizedTargets');
    });

    it('enriches findings with real scan output', () => {
      expect(reportCode).toContain("type: 'scan_output'");
      expect(reportCode).toContain('tool: scan.tool');
      expect(reportCode).toContain('Raw Output');
    });

    it('truncates large raw output', () => {
      expect(reportCode).toContain('rawOutput.length > 2000');
      expect(reportCode).toContain('[truncated]');
    });

    it('adds fallback note when no evidence found', () => {
      expect(reportCode).toContain("type: 'note'");
      expect(reportCode).toContain('Evidence was collected via automated scanning tools');
    });
  });

  // ── DOCX Evidence Rendering ──
  describe('DOCX Evidence Rendering', () => {
    it('renders evidence with proper headings', () => {
      reportCode = fs.readFileSync(reportFile, 'utf-8');
      expect(reportCode).toContain("'Evidence & Supporting Data'");
    });

    it('renders scan_output in code-block style', () => {
      expect(reportCode).toContain("font: 'Courier New'");
      expect(reportCode).toContain("e.type === 'scan_output'");
    });

    it('includes evidence timestamps', () => {
      expect(reportCode).toContain('e.timestamp');
      expect(reportCode).toContain('toISOString()');
    });

    it('includes evidence references', () => {
      expect(reportCode).toContain('e.reference');
    });

    it('shows note when no evidence exists', () => {
      expect(reportCode).toContain('No automated evidence captured');
      expect(reportCode).toContain('Manual validation recommended');
    });
  });

  // ── Methodology Data Storage ──
  describe('Methodology Data Storage', () => {
    it('collects tools from scan results', () => {
      reportCode = fs.readFileSync(reportFile, 'utf-8');
      expect(reportCode).toContain('methodologyTools');
      expect(reportCode).toContain('methodologyTools.add(sr.tool)');
    });

    it('stores toolsUsed and testPhases on report', () => {
      expect(reportCode).toContain('scopeUpdates.toolsUsed');
      expect(reportCode).toContain('scopeUpdates.testPhases');
    });
  });

  // ── Document Assembly ──
  describe('Document Assembly', () => {
    it('includes all sections in correct order', () => {
      reportCode = fs.readFileSync(reportFile, 'utf-8');
      const assemblyMatch = reportCode.match(/children:\s*\[\s*\.\.\.titleSection[\s\S]*?\]/);
      expect(assemblyMatch).toBeTruthy();
      const assembly = assemblyMatch![0];
      expect(assembly).toContain('titleSection');
      expect(assembly).toContain('execSection');
      expect(assembly).toContain('scopeSection');
      expect(assembly).toContain('methodologySection');
      expect(assembly).toContain('summarySection');
      expect(assembly).toContain('findingsSection');
      expect(assembly).toContain('appendixSection');
      expect(assembly).toContain('chainOfCustodySealSection');

      // Verify order
      const titleIdx = assembly.indexOf('titleSection');
      const execIdx = assembly.indexOf('execSection');
      const scopeIdx = assembly.indexOf('scopeSection');
      const methIdx = assembly.indexOf('methodologySection');
      const summaryIdx = assembly.indexOf('summarySection');
      const findingsIdx = assembly.indexOf('findingsSection');
      const appendixIdx = assembly.indexOf('appendixSection');
      expect(titleIdx).toBeLessThan(execIdx);
      expect(execIdx).toBeLessThan(scopeIdx);
      expect(scopeIdx).toBeLessThan(methIdx);
      expect(methIdx).toBeLessThan(summaryIdx);
      expect(summaryIdx).toBeLessThan(findingsIdx);
      expect(findingsIdx).toBeLessThan(appendixIdx);
    });
  });
});

// ─── Test: Frontend Methodology Tab ───

describe('Frontend Methodology Tab', () => {
  const reportPage = path.join(__dirname, '..', 'client', 'src', 'pages', 'Ac3Reports.tsx');
  let pageCode: string;

  it('Ac3Reports.tsx exists', () => {
    expect(fs.existsSync(reportPage)).toBe(true);
    pageCode = fs.readFileSync(reportPage, 'utf-8');
  });

  it('has Methodology tab trigger', () => {
    pageCode = fs.readFileSync(reportPage, 'utf-8');
    expect(pageCode).toContain('value="methodology"');
    expect(pageCode).toContain('Methodology');
  });

  it('has MethodologyTab component', () => {
    expect(pageCode).toContain('function MethodologyTab');
    expect(pageCode).toContain('<MethodologyTab');
  });

  it('MethodologyTab shows standards and approach', () => {
    expect(pageCode).toContain('Standards & Approach');
    expect(pageCode).toContain('PTES');
    expect(pageCode).toContain('NIST SP 800-115');
    expect(pageCode).toContain('OWASP Testing Guide');
  });

  it('MethodologyTab shows testing phases', () => {
    expect(pageCode).toContain('Testing Phases');
    expect(pageCode).toContain('Reconnaissance & OSINT');
    expect(pageCode).toContain('Exploitation & Validation');
  });

  it('MethodologyTab shows tools used', () => {
    expect(pageCode).toContain('Tools & Technologies');
    expect(pageCode).toContain('toolDescriptions');
  });

  it('MethodologyTab shows assessment details', () => {
    expect(pageCode).toContain('Assessment Details');
    expect(pageCode).toContain('Assessment Type');
    expect(pageCode).toContain('Compliance Framework');
  });

  it('imports Wrench icon for methodology tab', () => {
    expect(pageCode).toContain('Wrench');
  });
});

// ─── Test: Five Rings Removal Verification ───

describe('Five Rings Removal', () => {
  const homePage = path.join(__dirname, '..', 'client', 'src', 'pages', 'Home.tsx');

  it('Home.tsx does not contain Five Rings references', () => {
    const homeCode = fs.readFileSync(homePage, 'utf-8');
    expect(homeCode).not.toContain('FIVE_RINGS_DATA');
    expect(homeCode).not.toContain('Five Rings');
    expect(homeCode).not.toContain('Go Rin No Sho');
    expect(homeCode).not.toContain('AnimatedRingCard');
    expect(homeCode).not.toContain('selectedRing');
  });
});
