# FP/FN Prevention Research Findings

## Key Techniques from Production Scanners

### 1. Proof-Based Scanning (Invicti/Nuclei)
- **Core principle**: Don't just detect — PROVE exploitability
- Safely exploit vulns in controlled, non-destructive way
- Return concrete evidence: request/response pairs, extracted data
- Only report confirmed, exploitable issues
- Nuclei: multi-layer matchers (application ID + version + exploit proof)
- Template review requires testing against 3+ non-vulnerable similar apps

### 2. Multi-Layer Matcher Framework (Nuclei)
- Layer 1: Identify specific application (word match)
- Layer 2: Confirm vulnerable version range (regex)
- Layer 3: Verify exploit success (unique payload response)
- All layers must match (AND condition) to reduce FP
- Use unique random strings in payloads to confirm execution

### 3. Confidence Rating System (Acunetix)
- 100%: Confirmed via safe exploitation — relay directly to dev team
- 95%: High confidence but couldn't fully confirm — may need manual check
- 80%: Detection method is FP-prone — requires manual verification
- NEVER report below 80% confidence
- Factors: detection technique accuracy, vuln nature, sensor-based vs heuristic

### 4. Environmental Context Analysis (Algomox/AI-based)
- Network topology mapping (internet-facing vs internal)
- Asset criticality assessment
- Existing security controls evaluation (WAF, IDS, firewall rules)
- Business impact analysis
- Compensating controls detection (backports, patches, config mitigations)
- Attack path simulation — can the vuln actually be reached?

### 5. Ecosystem-Aware Matching (Grype/Anchore)
- CPE-based matching causes cross-ecosystem confusion (Go vs C++ protobuf)
- Shift to ecosystem-specific databases (GHSA) reduced FP by 2000+ with only 11 FN
- Version string normalization across package managers
- Symlink and binary-to-package association

### 6. Multi-Scanner Correlation (ServiceNow/Strobes)
- Deduplicate findings across scanners (Nuclei, ZAP, custom)
- Corroboration: finding confirmed by 2+ scanners = higher confidence
- Normalize finding identifiers (CVE, CWE, custom IDs)
- Merge evidence from multiple sources

## FP Prevention Strategies to Implement

1. **Multi-Signal Validation Pipeline**
   - Each finding must pass through multiple validation layers
   - Banner/version check → protocol probe → exploit verification
   - Minimum 2 independent signals required for "confirmed" status

2. **Confidence Scoring Algorithm**
   - Base confidence from detection method (heuristic=60%, version=70%, probe=85%, exploit=95%)
   - Modifiers: +10% if corroborated by 2nd scanner, +5% if TI confirms active exploitation
   - Modifiers: -15% if target has compensating controls, -10% if version backported
   - Threshold: Only report findings >= 70% confidence
   - Tag findings: "confirmed" (>=90%), "probable" (>=80%), "possible" (>=70%)

3. **Evidence Quality Scoring**
   - Require minimum evidence artifacts per severity level
   - Critical: exploit proof + request/response + version confirmation
   - High: version confirmation + protocol response anomaly
   - Medium: version match + service identification
   - Low: service identification only

4. **Secondary Verification (Re-scan)**
   - Findings above threshold but below "confirmed" get automatic re-scan
   - Use different detection technique on re-scan
   - Transient findings (network glitch) eliminated by temporal consistency

5. **FN Prevention: Coverage Gap Detection**
   - Track which protocols/ports were actually tested vs expected
   - Scan completeness score: % of target surface covered
   - Missing scanner alerts: "No MQTT scanner available for IoT target"
   - Version coverage: flag if scanner templates are outdated for target version

6. **Adaptive Thresholds by Environment**
   - Cloud: higher FP tolerance (fast remediation possible)
   - ICS/OT: lower FP tolerance (false alarms cause operational disruption)
   - Production: balanced approach
   - Development: lower threshold (catch more, accept more noise)

7. **LLM-Powered Validation**
   - Use LLM to analyze finding context and evidence quality
   - Cross-reference with known FP patterns
   - Generate human-readable confidence explanation
   - Suggest additional verification steps for borderline findings
