import { describe, it, expect, vi } from 'vitest';

// We test the rule-validator module's static analysis functions
// by importing and calling validateRule with useLLM=false to avoid network calls

describe('Rule Validation Engine', () => {
  // Helper to dynamically import
  async function getValidator() {
    return import('./lib/rule-validator');
  }

  describe('Sigma Rule Validation', () => {
    it('should validate a well-formed Sigma rule', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'sigma',
        ruleContent: `title: Test Rule
status: experimental
description: Test detection rule
author: AceofCloud
date: 2026/02/14
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: '-EncodedCommand'
    filter:
        ParentImage|endswith: '\\\\msiexec.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate admin scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001`,
        ruleName: 'Test Sigma Rule',
        techniqueId: 'T1059.001',
      }, false);

      expect(result.valid).toBe(true);
      expect(result.effectivenessScore).toBeGreaterThan(50);
      expect(result.coverage.techniquesCovered).toContain('T1059.001');
      expect(result.coverage.platformCompatibility).toContain('Windows');
      expect(result.falsePositiveRisk).toBeDefined();
    });

    it('should detect missing required fields in Sigma rule', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'sigma',
        ruleContent: `title: Incomplete Rule
status: test`,
        ruleName: 'Incomplete Sigma',
      }, false);

      expect(result.valid).toBe(false);
      const errorMessages = result.syntaxErrors
        .filter(e => e.severity === 'error')
        .map(e => e.message);
      expect(errorMessages.some(m => m.includes('logsource'))).toBe(true);
      expect(errorMessages.some(m => m.includes('detection'))).toBe(true);
    });

    it('should warn about missing recommended fields', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'sigma',
        ruleContent: `title: Minimal Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine: test
    condition: selection`,
        ruleName: 'Minimal Sigma',
      }, false);

      // Should have warnings for missing recommended fields
      const warnings = result.syntaxErrors.filter(e => e.severity === 'warning');
      expect(warnings.length).toBeGreaterThan(0);
    });

    it('should detect semantic issues like missing filters', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'sigma',
        ruleContent: `title: No Filter Rule
status: experimental
description: Rule without filter
author: test
date: 2026/01/01
logsource:
    category: process_creation
detection:
    selection:
        CommandLine: '*'
    condition: selection
level: high`,
        ruleName: 'No Filter',
      }, false);

      // Should warn about missing filter and broad wildcard
      const semanticWarnings = result.semanticWarnings;
      expect(semanticWarnings.length).toBeGreaterThan(0);
    });
  });

  describe('YARA Rule Validation', () => {
    it('should validate a well-formed YARA rule', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'yara',
        ruleContent: `rule Test_Detection
{
    meta:
        author = "AceofCloud"
        description = "Test YARA rule"
        date = "2026-02-14"
        reference = "https://attack.mitre.org/techniques/T1071/"

    strings:
        $s1 = "malicious_string" ascii
        $s2 = "another_pattern" wide

    condition:
        any of them and filesize < 1MB
}`,
        ruleName: 'Test YARA',
        techniqueId: 'T1071',
      }, false);

      expect(result.valid).toBe(true);
      expect(result.effectivenessScore).toBeGreaterThan(50);
      expect(result.coverage.platformCompatibility).toContain('Cross-platform');
    });

    it('should detect missing condition in YARA rule', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'yara',
        ruleContent: `rule Broken_Rule
{
    strings:
        $s1 = "test"
}`,
        ruleName: 'Broken YARA',
      }, false);

      expect(result.valid).toBe(false);
      const errors = result.syntaxErrors.filter(e => e.severity === 'error');
      expect(errors.some(e => e.message.includes('condition'))).toBe(true);
    });

    it('should detect unbalanced braces', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'yara',
        ruleContent: `rule Unbalanced
{
    strings:
        $s1 = "test"
    condition:
        $s1`,
        ruleName: 'Unbalanced YARA',
      }, false);

      expect(result.valid).toBe(false);
      const errors = result.syntaxErrors.filter(e => e.severity === 'error');
      expect(errors.some(e => e.message.includes('brace'))).toBe(true);
    });

    it('should warn about missing meta section', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'yara',
        ruleContent: `rule No_Meta
{
    strings:
        $s1 = "test"
    condition:
        $s1
}`,
        ruleName: 'No Meta YARA',
      }, false);

      const warnings = result.semanticWarnings;
      expect(warnings.some(w => w.message.includes('meta'))).toBe(true);
    });
  });

  describe('Suricata Rule Validation', () => {
    it('should validate a well-formed Suricata rule', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'suricata',
        ruleContent: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Test C2 Detection"; flow:established,to_server; content:"POST"; http_method; sid:1000001; rev:1;)`,
        ruleName: 'Test Suricata',
        techniqueId: 'T1071.001',
      }, false);

      expect(result.valid).toBe(true);
    });

    it('should detect missing action in Suricata rule', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'suricata',
        ruleContent: `http $HOME_NET any -> $EXTERNAL_NET any (msg:"Bad rule"; sid:1;)`,
        ruleName: 'Bad Suricata',
      }, false);

      expect(result.valid).toBe(false);
    });

    it('should detect missing sid', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'suricata',
        ruleContent: `alert tcp any any -> any any (msg:"No SID";)`,
        ruleName: 'No SID Suricata',
      }, false);

      expect(result.valid).toBe(false);
      const errors = result.syntaxErrors.filter(e => e.severity === 'error');
      expect(errors.some(e => e.message.includes('sid'))).toBe(true);
    });
  });

  describe('Splunk SPL Validation', () => {
    it('should validate a well-formed SPL query', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'splunk',
        ruleContent: `index=windows sourcetype=WinEventLog:Security EventCode=4688
| where match(CommandLine, "(?i)powershell")
| stats count by Computer, Account_Name`,
        ruleName: 'Test SPL',
      }, false);

      expect(result.valid).toBe(true);
    });

    it('should detect unbalanced quotes in SPL', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'splunk',
        ruleContent: `index=windows "unbalanced quote`,
        ruleName: 'Bad SPL',
      }, false);

      expect(result.valid).toBe(false);
    });
  });

  describe('KQL Validation', () => {
    it('should validate a well-formed KQL query', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'kql',
        ruleContent: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("procdump.exe", "mimikatz.exe")
| project Timestamp, DeviceName, AccountName, FileName`,
        ruleName: 'Test KQL',
        techniqueId: 'T1003',
      }, false);

      expect(result.valid).toBe(true);
      expect(result.coverage.platformCompatibility).toContain('Microsoft Sentinel');
    });

    it('should detect unbalanced parentheses in KQL', async () => {
      const { validateRule } = await getValidator();
      const result = await validateRule({
        ruleType: 'kql',
        ruleContent: `SecurityEvent | where (EventID == 4688`,
        ruleName: 'Bad KQL',
      }, false);

      expect(result.valid).toBe(false);
    });
  });

  describe('Sample Log Data Generation', () => {
    it('should generate sample data for known techniques', async () => {
      const { generateSampleLogData } = await getValidator();
      
      const psLog = generateSampleLogData('T1059.001');
      expect(psLog).toContain('powershell');
      
      const lsassLog = generateSampleLogData('T1003.001');
      expect(lsassLog).toContain('lsass');
      
      const c2Log = generateSampleLogData('T1071.001');
      expect(c2Log).toContain('beacon');
    });

    it('should generate generic data for unknown techniques', async () => {
      const { generateSampleLogData } = await getValidator();
      const log = generateSampleLogData('T9999');
      expect(log).toContain('T9999');
      expect(log).toContain('EventID');
    });

    it('should fall back to parent technique', async () => {
      const { generateSampleLogData } = await getValidator();
      // T1059.003 should fall back to T1059.003 (exact match) or T1059 (parent)
      const log = generateSampleLogData('T1059.003');
      expect(log).toContain('cmd.exe');
    });
  });

  describe('Batch Validation', () => {
    it('should validate multiple rules in batch', async () => {
      const { validateRuleBatch } = await getValidator();
      const result = await validateRuleBatch([
        {
          ruleType: 'sigma',
          ruleContent: `title: Good Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine: test
    condition: selection`,
          ruleName: 'Good Sigma',
        },
        {
          ruleType: 'yara',
          ruleContent: `rule Bad_Rule { strings: $s1 = "test" }`,
          ruleName: 'Bad YARA',
        },
      ], false);

      expect(result.totalRules).toBe(2);
      expect(result.validRules).toBe(1);
      expect(result.invalidRules).toBe(1);
      expect(result.averageEffectiveness).toBeGreaterThan(0);
    });
  });

  describe('Effectiveness Scoring', () => {
    it('should score rules with good practices higher', async () => {
      const { validateRule } = await getValidator();
      
      const goodRule = await validateRule({
        ruleType: 'sigma',
        ruleContent: `title: Well-Documented Rule
status: experimental
description: A well-documented detection rule
author: AceofCloud
date: 2026/02/14
references:
    - https://attack.mitre.org/techniques/T1059/
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: '-EncodedCommand'
    filter:
        ParentImage|endswith: '\\\\msiexec.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate admin scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001`,
        ruleName: 'Good Rule',
      }, false);

      const badRule = await validateRule({
        ruleType: 'sigma',
        ruleContent: `title: Minimal Rule
logsource:
    category: test
detection:
    selection:
        test: value
    condition: selection`,
        ruleName: 'Bad Rule',
      }, false);

      expect(goodRule.effectivenessScore).toBeGreaterThan(badRule.effectivenessScore);
    });
  });
});
