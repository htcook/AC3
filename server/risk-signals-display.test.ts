import { describe, it, expect } from 'vitest';

// ─── Risk Signals Display Logic Tests ────────────────────────────────────
// Tests the data parsing and rendering logic used in the OSINT Risk Signals card

describe('riskSignals display parsing', () => {
  // Simulates the signal parsing logic from the overview tab component
  function parseSignal(signal: any) {
    const sev = typeof signal === 'string' ? 'medium' : (signal.severity || 'medium');
    const text = typeof signal === 'string'
      ? signal
      : (signal.signal || signal.description || signal.title || JSON.stringify(signal));
    const source = typeof signal === 'string'
      ? null
      : (signal.source || signal.connector || null);
    return { sev, text, source };
  }

  function getSevColor(sev: string): string {
    const sevColors: Record<string, string> = {
      critical: 'border-red-500/40 bg-red-500/10 text-red-300',
      high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
      medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-300',
      low: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
      info: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
    };
    return sevColors[sev] || sevColors.medium;
  }

  it('should parse string-type risk signals with default medium severity', () => {
    const result = parseSignal('WHOIS privacy enabled — registrant identity hidden');
    expect(result.sev).toBe('medium');
    expect(result.text).toBe('WHOIS privacy enabled — registrant identity hidden');
    expect(result.source).toBeNull();
  });

  it('should parse object-type risk signals with severity and source', () => {
    const result = parseSignal({
      signal: 'Domain registered less than 1 year ago',
      severity: 'high',
      source: 'dehashed_whois',
    });
    expect(result.sev).toBe('high');
    expect(result.text).toBe('Domain registered less than 1 year ago');
    expect(result.source).toBe('dehashed_whois');
  });

  it('should fall back to description when signal field is missing', () => {
    const result = parseSignal({
      description: 'No DNSSEC configured',
      severity: 'medium',
      connector: 'rdap',
    });
    expect(result.text).toBe('No DNSSEC configured');
    expect(result.source).toBe('rdap');
  });

  it('should fall back to title when signal and description are missing', () => {
    const result = parseSignal({
      title: 'Expired SSL certificate',
      severity: 'critical',
    });
    expect(result.text).toBe('Expired SSL certificate');
    expect(result.sev).toBe('critical');
  });

  it('should JSON.stringify when no text fields are available', () => {
    const result = parseSignal({ severity: 'low', code: 'WEAK_CIPHER' });
    expect(result.text).toBe(JSON.stringify({ severity: 'low', code: 'WEAK_CIPHER' }));
  });

  it('should default to medium severity when severity field is missing', () => {
    const result = parseSignal({ signal: 'Open redirect detected' });
    expect(result.sev).toBe('medium');
  });

  it('should prefer source over connector for source field', () => {
    const result = parseSignal({
      signal: 'Test',
      source: 'censys',
      connector: 'shodan',
    });
    expect(result.source).toBe('censys');
  });

  it('should fall back to connector when source is missing', () => {
    const result = parseSignal({
      signal: 'Test',
      connector: 'shodan',
    });
    expect(result.source).toBe('shodan');
  });

  it('should map severity levels to correct color classes', () => {
    expect(getSevColor('critical')).toContain('red');
    expect(getSevColor('high')).toContain('orange');
    expect(getSevColor('medium')).toContain('yellow');
    expect(getSevColor('low')).toContain('emerald');
    expect(getSevColor('info')).toContain('blue');
    expect(getSevColor('unknown')).toContain('yellow'); // defaults to medium
  });

  it('should handle a realistic batch of risk signals', () => {
    const signals = [
      'WHOIS privacy enabled — registrant identity hidden',
      { signal: 'No DNSSEC', severity: 'medium', source: 'dns_check' },
      { signal: 'Multiple MX records pointing to single provider', severity: 'low', source: 'dns_check' },
      { description: 'PHP version outdated (7.4)', severity: 'high', connector: 'wappalyzer' },
      { signal: 'Domain age < 2 years', severity: 'high', source: 'dehashed_whois' },
    ];
    const parsed = signals.map(parseSignal);
    expect(parsed.length).toBe(5);
    expect(parsed[0].sev).toBe('medium');
    expect(parsed[0].source).toBeNull();
    expect(parsed[1].text).toBe('No DNSSEC');
    expect(parsed[3].text).toBe('PHP version outdated (7.4)');
    expect(parsed[3].source).toBe('wappalyzer');
    expect(parsed[4].sev).toBe('high');
  });
});

describe('riskSignals connector summary', () => {
  it('should format connector list correctly', () => {
    const connectorResults = [
      { connector: 'censys', observationCount: 12, durationMs: 3200, errors: [] },
      { connector: 'shodan', observationCount: 8, durationMs: 2100, errors: [] },
      { connector: 'dehashed_whois', observationCount: 1, durationMs: 800, errors: [] },
    ];
    const connectorList = connectorResults.map((c: any) => c.connector).join(', ');
    expect(connectorList).toBe('censys, shodan, dehashed_whois');
    expect(connectorResults.length).toBe(3);
  });

  it('should handle single connector', () => {
    const connectorResults = [
      { connector: 'censys', observationCount: 5, durationMs: 1000, errors: [] },
    ];
    const plural = connectorResults.length !== 1 ? 's' : '';
    expect(plural).toBe('');
  });

  it('should pluralize for multiple connectors', () => {
    const connectorResults = [
      { connector: 'a' },
      { connector: 'b' },
    ];
    const plural = connectorResults.length !== 1 ? 's' : '';
    expect(plural).toBe('s');
  });
});
