import { describe, it, expect } from 'vitest';

// ─── POA&M Export Helper Tests ──────────────────────────────────────────────

const FEDRAMP_SLA: Record<string, number> = {
  critical: 30, high: 30, moderate: 90, low: 180, informational: 365,
};

const RISK_LABELS: Record<string, string> = {
  critical: 'Very High', high: 'High', moderate: 'Moderate', low: 'Low', informational: 'Very Low',
};

function generatePoamId(idx: number): string {
  return `V-${String(idx + 1).padStart(5, '0')}`;
}

function calculateDueDate(createdAt: Date, severity: string): Date {
  const slaDays = FEDRAMP_SLA[severity] || 180;
  const dueDate = new Date(createdAt);
  dueDate.setDate(dueDate.getDate() + slaDays);
  return dueDate;
}

function generateMilestones(slaDays: number): string {
  return `M1: Identify fix (${Math.round(slaDays * 0.25)}d) | M2: Implement (${Math.round(slaDays * 0.6)}d) | M3: Verify (${slaDays}d)`;
}

function formatControlsList(controls: Array<{ id: string; family?: string }>): string {
  return controls.map(c => c.id).join(', ') || 'RA-5';
}

function determineDetector(sourceAgentId: string | null): string {
  return sourceAgentId ? 'Automated Scan' : 'Manual Penetration Test';
}

describe('POA&M ID Generation', () => {
  it('generates zero-padded POA&M IDs', () => {
    expect(generatePoamId(0)).toBe('V-00001');
    expect(generatePoamId(9)).toBe('V-00010');
    expect(generatePoamId(99)).toBe('V-00100');
    expect(generatePoamId(999)).toBe('V-01000');
  });

  it('handles large indices', () => {
    expect(generatePoamId(9999)).toBe('V-10000');
    expect(generatePoamId(99999)).toBe('V-100000');
  });
});

describe('Due Date Calculation', () => {
  const baseDate = new Date('2026-01-15');

  it('calculates critical/high due date as 30 days', () => {
    const due = calculateDueDate(baseDate, 'critical');
    expect(due.toISOString().split('T')[0]).toBe('2026-02-14');
  });

  it('calculates high due date as 30 days', () => {
    const due = calculateDueDate(baseDate, 'high');
    expect(due.toISOString().split('T')[0]).toBe('2026-02-14');
  });

  it('calculates moderate due date as 90 days', () => {
    const due = calculateDueDate(baseDate, 'moderate');
    const expected = new Date(baseDate);
    expected.setDate(expected.getDate() + 90);
    expect(due.toISOString().split('T')[0]).toBe(expected.toISOString().split('T')[0]);
  });

  it('calculates low due date as 180 days', () => {
    const due = calculateDueDate(baseDate, 'low');
    const expected = new Date(baseDate);
    expected.setDate(expected.getDate() + 180);
    expect(due.toISOString().split('T')[0]).toBe(expected.toISOString().split('T')[0]);
  });

  it('calculates informational due date as 365 days', () => {
    const due = calculateDueDate(baseDate, 'informational');
    const expected = new Date(baseDate);
    expected.setDate(expected.getDate() + 365);
    expect(due.toISOString().split('T')[0]).toBe(expected.toISOString().split('T')[0]);
  });

  it('defaults to 180 days for unknown severity', () => {
    const due = calculateDueDate(baseDate, 'unknown');
    const expected = new Date(baseDate);
    expected.setDate(expected.getDate() + 180);
    expect(due.toISOString().split('T')[0]).toBe(expected.toISOString().split('T')[0]);
  });
});

describe('Risk Labels', () => {
  it('maps severity to FedRAMP risk labels', () => {
    expect(RISK_LABELS['critical']).toBe('Very High');
    expect(RISK_LABELS['high']).toBe('High');
    expect(RISK_LABELS['moderate']).toBe('Moderate');
    expect(RISK_LABELS['low']).toBe('Low');
    expect(RISK_LABELS['informational']).toBe('Very Low');
  });
});

describe('Milestone Generation', () => {
  it('generates milestones for 30-day SLA', () => {
    const ms = generateMilestones(30);
    expect(ms).toContain('M1: Identify fix (8d)');
    expect(ms).toContain('M2: Implement (18d)');
    expect(ms).toContain('M3: Verify (30d)');
  });

  it('generates milestones for 90-day SLA', () => {
    const ms = generateMilestones(90);
    expect(ms).toContain('M1: Identify fix (23d)');
    expect(ms).toContain('M2: Implement (54d)');
    expect(ms).toContain('M3: Verify (90d)');
  });

  it('generates milestones for 180-day SLA', () => {
    const ms = generateMilestones(180);
    expect(ms).toContain('M1: Identify fix (45d)');
    expect(ms).toContain('M2: Implement (108d)');
    expect(ms).toContain('M3: Verify (180d)');
  });
});

describe('Controls Formatting', () => {
  it('formats controls list from array', () => {
    const controls = [
      { id: 'SI-10', family: 'System and Information Integrity' },
      { id: 'AC-3', family: 'Access Control' },
    ];
    expect(formatControlsList(controls)).toBe('SI-10, AC-3');
  });

  it('returns RA-5 fallback for empty controls', () => {
    expect(formatControlsList([])).toBe('RA-5');
  });

  it('handles single control', () => {
    expect(formatControlsList([{ id: 'CM-6' }])).toBe('CM-6');
  });
});

describe('Detector Source', () => {
  it('returns Automated Scan when sourceAgentId is present', () => {
    expect(determineDetector('agent-123')).toBe('Automated Scan');
  });

  it('returns Manual Penetration Test when sourceAgentId is null', () => {
    expect(determineDetector(null)).toBe('Manual Penetration Test');
  });
});

describe('FedRAMP SLA Constants', () => {
  it('has all severity levels defined', () => {
    expect(Object.keys(FEDRAMP_SLA)).toEqual(['critical', 'high', 'moderate', 'low', 'informational']);
  });

  it('critical and high share the same 30-day SLA', () => {
    expect(FEDRAMP_SLA['critical']).toBe(FEDRAMP_SLA['high']);
    expect(FEDRAMP_SLA['critical']).toBe(30);
  });

  it('SLAs are in ascending order', () => {
    expect(FEDRAMP_SLA['critical']).toBeLessThan(FEDRAMP_SLA['moderate']);
    expect(FEDRAMP_SLA['moderate']).toBeLessThan(FEDRAMP_SLA['low']);
    expect(FEDRAMP_SLA['low']).toBeLessThan(FEDRAMP_SLA['informational']);
  });
});

describe('ExcelJS POA&M Workbook Structure', () => {
  it('can create a workbook with expected sheets', async () => {
    const ExcelJS = await import('exceljs');
    const workbook = new ExcelJS.default.Workbook();
    workbook.addWorksheet('POA&M');
    workbook.addWorksheet('Summary');
    workbook.addWorksheet('ConMon SLAs');

    expect(workbook.worksheets.length).toBe(3);
    expect(workbook.getWorksheet('POA&M')).toBeDefined();
    expect(workbook.getWorksheet('Summary')).toBeDefined();
    expect(workbook.getWorksheet('ConMon SLAs')).toBeDefined();
  });

  it('can write and read POA&M columns', async () => {
    const ExcelJS = await import('exceljs');
    const workbook = new ExcelJS.default.Workbook();
    const ws = workbook.addWorksheet('POA&M');
    ws.columns = [
      { header: 'POA&M ID', key: 'poamId', width: 14 },
      { header: 'Weakness Name', key: 'weakness', width: 40 },
      { header: 'Risk Rating', key: 'risk', width: 14 },
      { header: 'NIST Controls', key: 'controls', width: 30 },
      { header: 'Status', key: 'status', width: 14 },
    ];

    ws.addRow({
      poamId: 'V-00001',
      weakness: 'SQL Injection in Login Form',
      risk: 'Very High',
      controls: 'SI-10, AC-3',
      status: 'Open',
    });

    const row = ws.getRow(2);
    expect(row.getCell('poamId').value).toBe('V-00001');
    expect(row.getCell('weakness').value).toBe('SQL Injection in Login Form');
    expect(row.getCell('risk').value).toBe('Very High');
    expect(row.getCell('controls').value).toBe('SI-10, AC-3');
    expect(row.getCell('status').value).toBe('Open');
  });

  it('can generate buffer from workbook', async () => {
    const ExcelJS = await import('exceljs');
    const workbook = new ExcelJS.default.Workbook();
    workbook.addWorksheet('POA&M');
    const buffer = await workbook.xlsx.writeBuffer();
    expect(buffer).toBeDefined();
    expect(buffer.byteLength).toBeGreaterThan(0);
  });
});
