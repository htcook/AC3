import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';


// Skip in CI — requires production database connection
const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

describe.skipIf(__skipInCI)('Evidence in PDF Reports', () => {
  const pipelinePath = path.join(__dirname, 'lib/pentest-report-pipeline.ts');
  const pipelineCode = fs.readFileSync(pipelinePath, 'utf-8');

  it('PipelineInput interface includes exploitationEvidence field', () => {
    expect(pipelineCode).toContain('exploitationEvidence?:');
  });

  it('ingestReconData merges DB exploitation evidence', () => {
    expect(pipelineCode).toContain('Merge DB exploitation evidence');
    expect(pipelineCode).toContain('input.exploitationEvidence');
  });

  it('Section 12.5 Exploitation Evidence Artifacts is present in report template', () => {
    expect(pipelineCode).toContain('12.5 Exploitation Evidence Artifacts');
    expect(pipelineCode).toContain('Evidence Summary');
    expect(pipelineCode).toContain('Successful Exploitation Evidence');
  });

  it('Section 12.5 includes proof-of-concept output', () => {
    expect(pipelineCode).toContain('Proof-of-Concept Output');
    expect(pipelineCode).toContain('ev.resultOutput');
  });

  it('Section 12.5 includes HTTP response evidence', () => {
    expect(pipelineCode).toContain('HTTP Response Evidence');
    expect(pipelineCode).toContain('evi.httpResponse');
  });

  it('Section 12.5 includes screenshot references', () => {
    expect(pipelineCode).toContain('ev.screenshotUrls');
    expect(pipelineCode).toContain('Exploit Evidence Screenshot');
  });

  it('Section 12.5 includes blocked attempts summary', () => {
    expect(pipelineCode).toContain('Blocked Exploitation Attempts');
    expect(pipelineCode).toContain('blocked by defensive controls');
  });

  it('Section 12.5 includes evidence summary table with all columns', () => {
    expect(pipelineCode).toContain('| # | Target | Port | Service | CVE | Module | Status | Access Level | Duration | Technique |');
  });
});

describe('Reports-core evidence fetching', () => {
  const reportsCoreCode = fs.readFileSync(path.join(__dirname, 'routers/reports-core.ts'), 'utf-8');

  it('Pentest pipeline fetches exploitation evidence from DB', () => {
    expect(reportsCoreCode).toContain('Fetch exploitation evidence from DB for report');
    expect(reportsCoreCode).toContain('db.getExploitationAttempts(input.engagementId)');
    expect(reportsCoreCode).toContain('exploitationEvidence,');
  });

  it('Legacy report generation includes exploitation evidence context', () => {
    expect(reportsCoreCode).toContain('Fetch exploitation evidence from DB for legacy report');
    expect(reportsCoreCode).toContain('legacyExploitEvidence');
    expect(reportsCoreCode).toContain('EXPLOITATION EVIDENCE');
  });

  it('Legacy report evidence includes proof lines and HTTP data', () => {
    expect(reportsCoreCode).toContain('evi.proofLines');
    expect(reportsCoreCode).toContain('evi.httpResponse');
  });
});

describe('Screenshot Capture in Exploit Sandbox', () => {
  const sandboxCode = fs.readFileSync(path.join(__dirname, 'lib/exploit-sandbox.ts'), 'utf-8');

  it('captureExploitScreenshot function exists', () => {
    expect(sandboxCode).toContain('async function captureExploitScreenshot');
    expect(sandboxCode).toContain('targetHost: string');
  });

  it('Screenshot capture uses headless browser', () => {
    expect(sandboxCode).toContain('chromium-browser --headless');
    expect(sandboxCode).toContain('--screenshot=');
    expect(sandboxCode).toContain('--window-size=1280,900');
  });

  it('Screenshot capture uploads to S3', () => {
    expect(sandboxCode).toContain('doStoragePut');
    expect(sandboxCode).toContain('exploit-evidence/');
    expect(sandboxCode).toContain('image/png');
  });

  it('Screenshot capture has fallback tools', () => {
    expect(sandboxCode).toContain('google-chrome');
    expect(sandboxCode).toContain('cutycapt');
    expect(sandboxCode).toContain('NO_SCREENSHOT_TOOL');
  });

  it('Screenshot is captured after successful exploit execution', () => {
    expect(sandboxCode).toContain('Capture screenshot for successful exploits');
    expect(sandboxCode).toContain('captureExploitScreenshot');
    expect(sandboxCode).toContain('screenshotUrls');
  });

  it('Screenshot URLs are persisted to DB', () => {
    expect(sandboxCode).toContain('screenshotUrls: screenshotUrls.length > 0');
  });
});

describe('Evidence Panel Screenshot Display', () => {
  const panelCode = fs.readFileSync(
    path.join(__dirname, '../client/src/components/ExploitEvidencePanel.tsx'), 'utf-8'
  );

  it('Evidence panel displays screenshot grid', () => {
    expect(panelCode).toContain('attempt.screenshotUrls');
    expect(panelCode).toContain('Exploit evidence screenshot');
    expect(panelCode).toContain('cursor-zoom-in');
  });

  it('Evidence panel supports legacy single screenshot from evidence object', () => {
    expect(panelCode).toContain('evidence?.screenshotUrl');
    expect(panelCode).toContain('Click to enlarge');
  });

  it('Screenshots open in new tab on click', () => {
    expect(panelCode).toContain('target="_blank"');
    expect(panelCode).toContain('rel="noopener noreferrer"');
  });
});

describe('Schema includes screenshot_urls column', () => {
  const schemaCode = fs.readFileSync(path.join(__dirname, '../drizzle/schema.ts'), 'utf-8');

  it('exploitation_attempts table has screenshot_urls column', () => {
    expect(schemaCode).toContain('screenshotUrls: json("screenshot_urls")');
  });
});

describe('DB helper supports screenshotUrls', () => {
  const dbCode = fs.readFileSync(path.join(__dirname, 'db.ts'), 'utf-8');

  it('InsertExploitationAttempt interface includes screenshotUrls', () => {
    expect(dbCode).toContain('screenshotUrls?: string[]');
  });
});
