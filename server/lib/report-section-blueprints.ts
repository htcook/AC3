/**
 * Report Section Blueprints — Type-Specific Report Structures
 *
 * Each engagement/assessment type requires different report sections
 * tailored to its purpose, audience, and deliverables.
 *
 * Blueprints define:
 *   - Which sections appear in the report
 *   - Section ordering and hierarchy
 *   - LLM prompt guidance per section
 *   - Required vs optional sections
 *   - Data sources each section pulls from
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export type AssessmentType =
  | 'penetration_test'
  | 'red_team'
  | 'purple_team'
  | 'vulnerability_assessment'
  | 'phishing_campaign'
  | 'tabletop_exercise'
  | 'hybrid';

export interface SectionBlueprint {
  id: string;
  title: string;
  required: boolean;
  /** LLM prompt guidance for narrative generation */
  promptGuidance: string;
  /** Data sources this section draws from */
  dataSources: string[];
  /** Sub-sections within this section */
  subsections?: Array<{ id: string; title: string; promptGuidance: string }>;
}

export interface ReportBlueprint {
  assessmentType: AssessmentType;
  displayName: string;
  description: string;
  sections: SectionBlueprint[];
  /** Compliance frameworks commonly associated with this type */
  defaultFrameworks: string[];
  /** Primary audience for this report type */
  audience: string;
}

// ─── Shared Sections (reused across types) ──────────────────────────────────

const DOCUMENT_CONTROL: SectionBlueprint = {
  id: 'document_control',
  title: 'Document Control',
  required: true,
  promptGuidance: 'Generate document metadata including version, classification, distribution list, and revision history.',
  dataSources: ['report_metadata'],
  subsections: [
    { id: 'doc_info', title: 'Document Information', promptGuidance: 'Report title, version, date, classification, author.' },
    { id: 'revision_history', title: 'Revision History', promptGuidance: 'Version changelog with dates and authors.' },
    { id: 'confidentiality', title: 'Confidentiality Notice', promptGuidance: 'Standard confidentiality and distribution notice.' },
  ],
};

const EXECUTIVE_SUMMARY: SectionBlueprint = {
  id: 'executive_summary',
  title: 'Executive Summary',
  required: true,
  promptGuidance: 'Write a 3-5 paragraph executive summary for C-suite and board-level stakeholders. Include overall risk posture, key findings themes, strengths observed, critical gaps, and prioritized strategic recommendations. Avoid technical jargon. Focus on business risk and organizational impact.',
  dataSources: ['findings_summary', 'risk_ratings', 'compliance_scores'],
  subsections: [
    { id: 'risk_statement', title: 'Risk Statement', promptGuidance: 'One-paragraph overall risk assessment with severity rating.' },
    { id: 'key_findings', title: 'Key Findings', promptGuidance: 'Top 3-5 findings by business impact, not just severity.' },
    { id: 'strengths', title: 'Strengths Observed', promptGuidance: 'Positive security controls and practices identified.' },
    { id: 'recommendations', title: 'Strategic Recommendations', promptGuidance: 'Prioritized action items for leadership.' },
  ],
};

const SCOPE_AND_ROE: SectionBlueprint = {
  id: 'scope_and_roe',
  title: 'Scope and Rules of Engagement',
  required: true,
  promptGuidance: 'Document the assessment scope including in-scope assets, domains, IP ranges, approved attack vectors, out-of-scope items, and any deviations from the original test plan.',
  dataSources: ['scope_domains', 'scope_assets', 'approved_vectors', 'out_of_scope', 'roe_data'],
  subsections: [
    { id: 'engagement_details', title: 'Engagement Details', promptGuidance: 'Client, system, assessment window, assessor organization.' },
    { id: 'in_scope', title: 'In-Scope Targets', promptGuidance: 'Domains, IPs, assets, and application URLs tested.' },
    { id: 'approved_vectors', title: 'Approved Attack Vectors', promptGuidance: 'Authorized testing methods and techniques.' },
    { id: 'out_of_scope', title: 'Out of Scope', promptGuidance: 'Explicitly excluded targets and techniques.' },
    { id: 'deviations', title: 'Deviations from Plan', promptGuidance: 'Any changes to scope during the assessment.' },
  ],
};

const METHODOLOGY: SectionBlueprint = {
  id: 'methodology',
  title: 'Methodology',
  required: true,
  promptGuidance: 'Describe the testing methodology, standards followed, and compliance frameworks applied.',
  dataSources: ['methodology_standards', 'compliance_framework'],
  subsections: [
    { id: 'standards', title: 'Standards and Frameworks', promptGuidance: 'NIST SP 800-115, OWASP, PTES, MITRE ATT&CK as applicable.' },
    { id: 'testing_phases', title: 'Testing Phases', promptGuidance: 'Describe each phase of the assessment lifecycle.' },
    { id: 'tools_used', title: 'Tools and Techniques', promptGuidance: 'Catalog of tools used with purpose and version.' },
  ],
};

const FINDINGS_SUMMARY: SectionBlueprint = {
  id: 'findings_summary',
  title: 'Findings Summary',
  required: true,
  promptGuidance: 'Provide a severity distribution table and high-level overview of all findings. Include CVSS score ranges, affected asset counts, and finding categories.',
  dataSources: ['findings', 'severity_counts'],
};

const RISK_MATRIX: SectionBlueprint = {
  id: 'risk_matrix',
  title: 'Risk Matrix',
  required: true,
  promptGuidance: 'Present a likelihood × impact risk matrix mapping each finding to its risk rating. Include CVSS base scores, environmental adjustments, and business context modifiers.',
  dataSources: ['findings', 'risk_ratings'],
};

const REMEDIATION_ROADMAP: SectionBlueprint = {
  id: 'remediation_roadmap',
  title: 'Remediation Roadmap',
  required: true,
  promptGuidance: 'Provide a prioritized remediation plan with immediate (0-30 days), short-term (30-90 days), and long-term (90+ days) actions. Include effort estimates and responsible parties where possible.',
  dataSources: ['findings', 'remediation_data'],
  subsections: [
    { id: 'immediate', title: 'Immediate Actions (0-30 Days)', promptGuidance: 'Critical and high severity remediations.' },
    { id: 'short_term', title: 'Short-Term Actions (30-90 Days)', promptGuidance: 'Moderate severity and architectural improvements.' },
    { id: 'long_term', title: 'Long-Term Actions (90+ Days)', promptGuidance: 'Strategic security program improvements.' },
  ],
};

const APPENDIX: SectionBlueprint = {
  id: 'appendix',
  title: 'Appendix',
  required: false,
  promptGuidance: 'Supporting artifacts, evidence catalog, tool execution logs, and supplementary data.',
  dataSources: ['artifacts', 'tool_results', 'audit_log'],
  subsections: [
    { id: 'testing_personnel', title: 'Testing Personnel', promptGuidance: 'Assessor names, roles, and certifications.' },
    { id: 'tools_catalog', title: 'Tools Catalog', promptGuidance: 'Complete list of tools with versions and purposes.' },
    { id: 'evidence_catalog', title: 'Evidence Catalog', promptGuidance: 'Index of all supporting artifacts with cross-references.' },
    { id: 'compliance_mapping', title: 'Compliance Control Mapping', promptGuidance: 'Detailed mapping of findings to compliance controls.' },
  ],
};

// ─── Penetration Test Blueprint ─────────────────────────────────────────────

const PENTEST_BLUEPRINT: ReportBlueprint = {
  assessmentType: 'penetration_test',
  displayName: 'Penetration Test Report',
  description: 'Full-scope penetration test with exploitation, post-exploitation, and compliance mapping.',
  audience: 'Security leadership, compliance officers, auditors, engineering teams',
  defaultFrameworks: ['NIST SP 800-53', 'FedRAMP', 'PCI-DSS', 'OWASP'],
  sections: [
    DOCUMENT_CONTROL,
    EXECUTIVE_SUMMARY,
    SCOPE_AND_ROE,
    {
      id: 'assessment_timeline',
      title: 'Assessment Timeline',
      required: true,
      promptGuidance: 'Document the chronological timeline of all testing activity with precise timestamps, phases, and key milestones.',
      dataSources: ['engagement_timeline', 'phase_timestamps'],
    },
    METHODOLOGY,
    {
      id: 'threat_models',
      title: 'Threat Models Applied',
      required: true,
      promptGuidance: 'Describe the threat models used: internet-based untrusted threats, insider threats, and any threat actor intelligence applied.',
      dataSources: ['threat_actors', 'carver_data'],
      subsections: [
        { id: 'external_threats', title: 'External Threat Model', promptGuidance: 'Internet-based attack scenarios and threat actor profiles.' },
        { id: 'insider_threats', title: 'Insider Threat Model', promptGuidance: 'Authenticated user and privileged access scenarios.' },
      ],
    },
    {
      id: 'attack_vectors',
      title: 'Attack Vectors Assessed',
      required: true,
      promptGuidance: 'Describe each attack vector tested with techniques used and results. Include MITRE ATT&CK tactic and technique coverage.',
      dataSources: ['attack_techniques', 'mitre_mapping'],
    },
    {
      id: 'attack_surface',
      title: 'Attack Surface Overview',
      required: true,
      promptGuidance: 'Summarize the discovered attack surface: hosts, ports, services, technologies, and exposure analysis.',
      dataSources: ['assets', 'recon_data'],
    },
    FINDINGS_SUMMARY,
    {
      id: 'detailed_findings',
      title: 'Detailed Findings',
      required: true,
      promptGuidance: 'For each finding: title, CVSS v3.1 vector with per-metric justification, description, business impact, technical details with reproduction steps, evidence artifacts (labeled E-1 through E-N), and specific remediation. Reference supporting artifacts by label.',
      dataSources: ['findings', 'evidence', 'artifacts'],
    },
    {
      id: 'exploitation_narrative',
      title: 'Exploitation Results and Access Paths',
      required: true,
      promptGuidance: 'Document all exploitation attempts with risk ratings. For successful exploits: CVSS scoring, evidence chain (exploit plan, execution output, session details, C2 callbacks), timeline with timestamps, and risk justification table. For access paths: show how multiple vulnerabilities chain together.',
      dataSources: ['exploit_attempts', 'sessions', 'c2_data', 'attack_chains'],
      subsections: [
        { id: 'exploit_results', title: 'Exploitation Attempts and Results', promptGuidance: 'Table of all exploit attempts with success/fail, risk rating, and evidence.' },
        { id: 'evidence_chain', title: 'Supporting Evidence Chain', promptGuidance: 'Labeled evidence artifacts (E-1 through E-N) with descriptions.' },
        { id: 'kill_chains', title: 'Kill Chain Analysis', promptGuidance: 'Attack chains showing multi-step exploitation paths.' },
        { id: 'access_paths', title: 'Access Paths', promptGuidance: 'Diagrams and descriptions of how access was obtained and escalated.' },
      ],
    },
    {
      id: 'post_exploitation',
      title: 'Post-Exploitation Assessment',
      required: false,
      promptGuidance: 'Document post-exploitation activities: C2 deployment, adversary simulation, lateral movement attempts, persistence mechanisms, and data access achieved.',
      dataSources: ['c2_data', 'adversary_ops', 'caldera_results'],
      subsections: [
        { id: 'c2_deployment', title: 'C2 Infrastructure', promptGuidance: 'C2 agents deployed, callback protocols, and session management.' },
        { id: 'adversary_simulation', title: 'Adversary Simulation', promptGuidance: 'Adversary profile emulated, techniques executed, and outcomes.' },
        { id: 'lateral_movement', title: 'Lateral Movement', promptGuidance: 'Attempts to move between systems and escalate privileges.' },
      ],
    },
    {
      id: 'credential_exposure',
      title: 'Credential Exposure Assessment',
      required: false,
      promptGuidance: 'Document breach-sourced credentials discovered during OSINT reconnaissance. Include total credentials harvested, breakdown by source, plaintext vs hashed passwords, credential spray testing results, and remediation guidance. If confirmed valid credentials were found, flag as critical with immediate action items.',
      dataSources: ['credential_exposure', 'breach_data'],
    },
    RISK_MATRIX,
    REMEDIATION_ROADMAP,
    {
      id: 'detection_recommendations',
      title: 'Detection and Monitoring Recommendations',
      required: true,
      promptGuidance: 'For each finding, provide specific detection rules, monitoring recommendations, and alerting thresholds.',
      dataSources: ['findings', 'detection_rules'],
    },
    APPENDIX,
  ],
};

// ─── Red Team Assessment Blueprint ──────────────────────────────────────────

const RED_TEAM_BLUEPRINT: ReportBlueprint = {
  assessmentType: 'red_team',
  displayName: 'Red Team Assessment Report',
  description: 'Adversary simulation focused on initial access, persistence, lateral movement, and objective achievement.',
  audience: 'CISO, security operations, incident response teams, executive leadership',
  defaultFrameworks: ['MITRE ATT&CK', 'NIST SP 800-53', 'NIST CSF'],
  sections: [
    DOCUMENT_CONTROL,
    EXECUTIVE_SUMMARY,
    SCOPE_AND_ROE,
    {
      id: 'adversary_profile',
      title: 'Adversary Profile and Objectives',
      required: true,
      promptGuidance: 'Describe the threat actor profile emulated, their known TTPs, motivation, and the specific objectives the red team was tasked to achieve (e.g., access crown jewels, exfiltrate data, establish persistence).',
      dataSources: ['threat_actors', 'engagement_objectives'],
      subsections: [
        { id: 'threat_actor', title: 'Threat Actor Emulated', promptGuidance: 'Name, motivation, known campaigns, and TTPs of the emulated adversary.' },
        { id: 'objectives', title: 'Red Team Objectives', promptGuidance: 'Specific goals: data access, persistence, lateral movement targets.' },
        { id: 'success_criteria', title: 'Success Criteria', promptGuidance: 'How objective achievement was measured.' },
      ],
    },
    {
      id: 'attack_narrative',
      title: 'Attack Narrative',
      required: true,
      promptGuidance: 'Write a chronological narrative of the entire attack operation from initial reconnaissance through objective achievement. Written in past tense, describing each phase as it was executed. Include decision points, pivots, and adaptations made during the operation.',
      dataSources: ['engagement_timeline', 'attack_chains', 'exploit_attempts', 'c2_data'],
      subsections: [
        { id: 'initial_access', title: 'Initial Access', promptGuidance: 'How the red team gained initial foothold. Include techniques, tools, and time to access.' },
        { id: 'execution_persistence', title: 'Execution and Persistence', promptGuidance: 'Code execution methods and persistence mechanisms established.' },
        { id: 'privilege_escalation', title: 'Privilege Escalation', promptGuidance: 'How privileges were elevated from initial access to target level.' },
        { id: 'lateral_movement', title: 'Lateral Movement', promptGuidance: 'Movement between systems, credential harvesting, and network traversal.' },
        { id: 'objective_achievement', title: 'Objective Achievement', promptGuidance: 'How each red team objective was achieved or why it was not.' },
        { id: 'exfiltration', title: 'Data Access and Exfiltration', promptGuidance: 'What data was accessed, how it was staged, and exfiltration methods used.' },
      ],
    },
    {
      id: 'detection_analysis',
      title: 'Detection and Response Analysis',
      required: true,
      promptGuidance: 'Analyze the defender response: which actions were detected, response times, escalation effectiveness, and gaps in detection coverage.',
      dataSources: ['detection_events', 'soc_metrics', 'alert_data'],
      subsections: [
        { id: 'detection_timeline', title: 'Detection Timeline', promptGuidance: 'When each red team action was detected (or not) with timestamps.' },
        { id: 'soc_response', title: 'SOC Response Assessment', promptGuidance: 'How the security team responded to detected activity.' },
        { id: 'detection_gaps', title: 'Detection Gaps', promptGuidance: 'Techniques that evaded detection entirely, with recommendations.' },
      ],
    },
    {
      id: 'mitre_attack_mapping',
      title: 'MITRE ATT&CK Mapping',
      required: true,
      promptGuidance: 'Map every technique used to MITRE ATT&CK with detection status (detected/partially detected/evaded). Include a coverage heatmap summary.',
      dataSources: ['attack_techniques', 'mitre_mapping', 'detection_events'],
    },
    FINDINGS_SUMMARY,
    {
      id: 'detailed_findings',
      title: 'Detailed Findings',
      required: true,
      promptGuidance: 'For each finding: CVSS scoring with vector breakdown, attack narrative context, evidence artifacts, business impact in terms of adversary objectives, and remediation. Findings should be ordered by attack chain position, not just severity.',
      dataSources: ['findings', 'evidence', 'artifacts'],
    },
    {
      id: 'credential_exposure',
      title: 'Credential Exposure Assessment',
      required: false,
      promptGuidance: 'Document breach-sourced credentials discovered during OSINT reconnaissance. Include total credentials harvested, breakdown by source, plaintext vs hashed passwords, credential spray testing results, and remediation guidance.',
      dataSources: ['credential_exposure', 'breach_data'],
    },
    RISK_MATRIX,
    {
      id: 'resilience_assessment',
      title: 'Organizational Resilience Assessment',
      required: true,
      promptGuidance: 'Assess the organization\'s overall resilience: detection maturity, response capability, security architecture effectiveness, and people/process gaps.',
      dataSources: ['detection_events', 'findings', 'soc_metrics'],
      subsections: [
        { id: 'detection_maturity', title: 'Detection Maturity', promptGuidance: 'Rate detection capability across ATT&CK tactics.' },
        { id: 'response_capability', title: 'Response Capability', promptGuidance: 'Incident response speed, accuracy, and escalation.' },
        { id: 'architecture_review', title: 'Security Architecture', promptGuidance: 'Network segmentation, access controls, and defense-in-depth.' },
      ],
    },
    REMEDIATION_ROADMAP,
    APPENDIX,
  ],
};

// ─── Purple Team Exercise Blueprint ─────────────────────────────────────────

const PURPLE_TEAM_BLUEPRINT: ReportBlueprint = {
  assessmentType: 'purple_team',
  displayName: 'Purple Team Exercise Report',
  description: 'Collaborative adversary emulation with real-time detection validation and SOC performance metrics.',
  audience: 'SOC analysts, detection engineers, security architects, CISO',
  defaultFrameworks: ['MITRE ATT&CK', 'NIST SP 800-53', 'NIST CSF'],
  sections: [
    DOCUMENT_CONTROL,
    EXECUTIVE_SUMMARY,
    SCOPE_AND_ROE,
    METHODOLOGY,
    {
      id: 'adversary_emulation',
      title: 'Adversary Emulation Plan',
      required: true,
      promptGuidance: 'Describe the adversary profile emulated, the technique selection rationale, and the expected detection coverage baseline.',
      dataSources: ['threat_actors', 'attack_techniques'],
      subsections: [
        { id: 'adversary_profile', title: 'Adversary Profile', promptGuidance: 'Threat actor emulated and their known TTPs.' },
        { id: 'technique_selection', title: 'Technique Selection', promptGuidance: 'Why these specific techniques were chosen for testing.' },
        { id: 'expected_baseline', title: 'Expected Detection Baseline', promptGuidance: 'What the organization expected to detect before testing.' },
      ],
    },
    {
      id: 'technique_results',
      title: 'Technique-by-Technique Results',
      required: true,
      promptGuidance: 'For each MITRE ATT&CK technique tested: technique ID and name, execution method, detection status (detected/partially detected/missed), time to detect, alert fidelity, and specific detection rule that fired (or should have).',
      dataSources: ['attack_techniques', 'detection_events', 'caldera_results'],
    },
    {
      id: 'detection_coverage',
      title: 'Detection Coverage Analysis',
      required: true,
      promptGuidance: 'Comprehensive detection coverage analysis: overall detection rate, per-tactic detection rates, detection latency distribution, false positive rates, and coverage gaps.',
      dataSources: ['detection_events', 'coverage_data'],
      subsections: [
        { id: 'coverage_heatmap', title: 'ATT&CK Coverage Heatmap', promptGuidance: 'Visual representation of detection coverage across ATT&CK matrix.' },
        { id: 'detection_rates', title: 'Detection Rates by Tactic', promptGuidance: 'Percentage detected per ATT&CK tactic with trend analysis.' },
        { id: 'latency_analysis', title: 'Detection Latency', promptGuidance: 'Time from execution to alert for each detected technique.' },
        { id: 'false_positives', title: 'False Positive Analysis', promptGuidance: 'False positive rates and tuning recommendations.' },
      ],
    },
    {
      id: 'soc_performance',
      title: 'SOC Performance Metrics',
      required: true,
      promptGuidance: 'Evaluate SOC team performance: mean time to detect (MTTD), mean time to respond (MTTR), escalation accuracy, analyst decision quality, and playbook adherence.',
      dataSources: ['soc_metrics', 'detection_events'],
      subsections: [
        { id: 'mttd_mttr', title: 'MTTD and MTTR', promptGuidance: 'Mean time to detect and respond with breakdowns by severity.' },
        { id: 'analyst_performance', title: 'Analyst Performance', promptGuidance: 'Decision accuracy, escalation quality, and triage speed.' },
        { id: 'playbook_adherence', title: 'Playbook Adherence', promptGuidance: 'How well analysts followed established response procedures.' },
      ],
    },
    {
      id: 'detection_engineering',
      title: 'Detection Engineering Recommendations',
      required: true,
      promptGuidance: 'Provide specific detection rules (Sigma, YARA, Suricata) for each gap identified. Include rule logic, data source requirements, and expected false positive rates.',
      dataSources: ['detection_rules', 'coverage_gaps'],
      subsections: [
        { id: 'new_rules', title: 'New Detection Rules', promptGuidance: 'Sigma/YARA/Suricata rules to close coverage gaps.' },
        { id: 'rule_tuning', title: 'Rule Tuning Recommendations', promptGuidance: 'Existing rules that need threshold or logic adjustments.' },
        { id: 'data_source_gaps', title: 'Data Source Gaps', promptGuidance: 'Missing telemetry sources that prevent detection.' },
      ],
    },
    FINDINGS_SUMMARY,
    {
      id: 'detailed_findings',
      title: 'Detailed Findings',
      required: true,
      promptGuidance: 'For each finding: CVSS scoring, detection status, evidence, business impact focused on detection gap risk, and remediation including specific detection rules to implement.',
      dataSources: ['findings', 'evidence', 'artifacts'],
    },
    REMEDIATION_ROADMAP,
    APPENDIX,
  ],
};

// ─── Phishing Campaign Blueprint ────────────────────────────────────────────

const PHISHING_BLUEPRINT: ReportBlueprint = {
  assessmentType: 'phishing_campaign',
  displayName: 'Phishing Campaign Assessment Report',
  description: 'Social engineering campaign results with user behavior analysis, risk metrics, and awareness recommendations.',
  audience: 'CISO, HR leadership, security awareness team, compliance officers',
  defaultFrameworks: ['NIST SP 800-53', 'NIST CSF', 'SOC 2'],
  sections: [
    DOCUMENT_CONTROL,
    EXECUTIVE_SUMMARY,
    SCOPE_AND_ROE,
    {
      id: 'campaign_overview',
      title: 'Campaign Overview',
      required: true,
      promptGuidance: 'Describe the phishing campaign design: pretext used, delivery method, target selection criteria, campaign duration, and threat actor emulated.',
      dataSources: ['campaign_data', 'threat_actors'],
      subsections: [
        { id: 'pretext', title: 'Pretext and Social Engineering Approach', promptGuidance: 'The social engineering narrative and why it was chosen.' },
        { id: 'delivery', title: 'Delivery Method', promptGuidance: 'Email, SMS, voice, or multi-channel approach used.' },
        { id: 'target_selection', title: 'Target Selection', promptGuidance: 'How targets were selected: department, role, access level.' },
        { id: 'threat_simulation', title: 'Threat Actor Simulation', promptGuidance: 'Which threat actor TTPs were emulated in the campaign.' },
      ],
    },
    {
      id: 'campaign_results',
      title: 'Campaign Results',
      required: true,
      promptGuidance: 'Present comprehensive campaign metrics with visual breakdowns. Include delivery rates, open rates, click rates, credential submission rates, and reporting rates.',
      dataSources: ['campaign_metrics'],
      subsections: [
        { id: 'delivery_metrics', title: 'Delivery and Open Metrics', promptGuidance: 'Emails sent, delivered, bounced, opened with rates.' },
        { id: 'interaction_metrics', title: 'User Interaction Metrics', promptGuidance: 'Click rates, credential submissions, file downloads with breakdowns.' },
        { id: 'reporting_metrics', title: 'Reporting Metrics', promptGuidance: 'How many users reported the phishing attempt and response time.' },
        { id: 'department_breakdown', title: 'Department Breakdown', promptGuidance: 'Performance by department, role, and seniority level.' },
        { id: 'time_analysis', title: 'Time-Based Analysis', promptGuidance: 'When users interacted — time to click, time to submit, peak activity.' },
      ],
    },
    {
      id: 'risk_assessment',
      title: 'Risk Assessment',
      required: true,
      promptGuidance: 'Assess organizational risk from phishing based on campaign results. Include risk score calculation, comparison to industry benchmarks, and trend analysis if previous campaigns exist.',
      dataSources: ['campaign_metrics', 'risk_ratings'],
      subsections: [
        { id: 'risk_score', title: 'Risk Score', promptGuidance: 'Calculated risk score with methodology explanation.' },
        { id: 'benchmarking', title: 'Industry Benchmarking', promptGuidance: 'How results compare to industry averages.' },
        { id: 'trend_analysis', title: 'Trend Analysis', promptGuidance: 'Improvement or regression compared to previous campaigns.' },
      ],
    },
    {
      id: 'post_exploitation',
      title: 'Post-Exploitation Impact',
      required: false,
      promptGuidance: 'If post-exploitation was performed after credential capture: document what access was gained, data exposed, and systems compromised through harvested credentials.',
      dataSources: ['exploit_attempts', 'c2_data', 'caldera_results'],
      subsections: [
        { id: 'credential_impact', title: 'Credential Impact Assessment', promptGuidance: 'What systems the captured credentials provide access to.' },
        { id: 'lateral_access', title: 'Lateral Access Achieved', promptGuidance: 'Systems and data accessible through compromised accounts.' },
      ],
    },
    {
      id: 'user_behavior',
      title: 'User Behavior Analysis',
      required: true,
      promptGuidance: 'Analyze user behavior patterns: who is most susceptible, what factors correlate with susceptibility, and behavioral indicators that distinguish reporters from clickers.',
      dataSources: ['campaign_metrics', 'user_data'],
    },
    {
      id: 'technical_controls',
      title: 'Technical Controls Assessment',
      required: true,
      promptGuidance: 'Evaluate email security controls: SPF/DKIM/DMARC effectiveness, email gateway filtering, URL rewriting, sandbox detonation, and MFA coverage for credential-based attacks.',
      dataSources: ['technical_findings'],
      subsections: [
        { id: 'email_security', title: 'Email Security Controls', promptGuidance: 'SPF, DKIM, DMARC, gateway filtering effectiveness.' },
        { id: 'mfa_coverage', title: 'MFA Coverage', promptGuidance: 'Multi-factor authentication coverage for compromised accounts.' },
        { id: 'url_protection', title: 'URL and Link Protection', promptGuidance: 'URL rewriting, sandboxing, and click-time protection.' },
      ],
    },
    {
      id: 'awareness_recommendations',
      title: 'Security Awareness Recommendations',
      required: true,
      promptGuidance: 'Provide specific, actionable security awareness training recommendations based on the campaign results. Include targeted training for high-risk groups, general awareness improvements, and phishing simulation cadence recommendations.',
      dataSources: ['campaign_metrics', 'user_data'],
      subsections: [
        { id: 'targeted_training', title: 'Targeted Training', promptGuidance: 'Specific training for high-risk departments and roles.' },
        { id: 'general_awareness', title: 'General Awareness Program', promptGuidance: 'Organization-wide awareness improvements.' },
        { id: 'simulation_cadence', title: 'Simulation Cadence', promptGuidance: 'Recommended frequency and variety of future simulations.' },
      ],
    },
    REMEDIATION_ROADMAP,
    APPENDIX,
  ],
};

// ─── Vulnerability Assessment Blueprint ─────────────────────────────────────

const VULN_ASSESSMENT_BLUEPRINT: ReportBlueprint = {
  assessmentType: 'vulnerability_assessment',
  displayName: 'Vulnerability Assessment Report',
  description: 'Systematic vulnerability identification and risk rating without active exploitation.',
  audience: 'Security engineers, system administrators, compliance officers, CISO',
  defaultFrameworks: ['NIST SP 800-53', 'PCI-DSS', 'CIS Controls'],
  sections: [
    DOCUMENT_CONTROL,
    EXECUTIVE_SUMMARY,
    SCOPE_AND_ROE,
    METHODOLOGY,
    {
      id: 'asset_inventory',
      title: 'Asset Inventory and Discovery',
      required: true,
      promptGuidance: 'Document all discovered assets: hosts, services, technologies, and their exposure level. Include asset classification and criticality ratings.',
      dataSources: ['assets', 'recon_data'],
      subsections: [
        { id: 'host_inventory', title: 'Host Inventory', promptGuidance: 'All discovered hosts with IPs, hostnames, and operating systems.' },
        { id: 'service_inventory', title: 'Service Inventory', promptGuidance: 'All discovered services with ports, versions, and configurations.' },
        { id: 'technology_stack', title: 'Technology Stack', promptGuidance: 'Web frameworks, databases, middleware, and third-party components.' },
      ],
    },
    {
      id: 'scan_results',
      title: 'Scan Results',
      required: true,
      promptGuidance: 'Present results from all vulnerability scanners used. Include scanner name, scan date, target, and finding counts by severity.',
      dataSources: ['scan_reports', 'tool_results'],
      subsections: [
        { id: 'scanner_summary', title: 'Scanner Summary', promptGuidance: 'Which scanners were used and their coverage.' },
        { id: 'cross_validation', title: 'Cross-Validation Results', promptGuidance: 'Findings confirmed by multiple scanners vs single-source.' },
        { id: 'false_positive_analysis', title: 'False Positive Analysis', promptGuidance: 'Findings identified as false positives with justification.' },
      ],
    },
    FINDINGS_SUMMARY,
    {
      id: 'detailed_findings',
      title: 'Detailed Findings',
      required: true,
      promptGuidance: 'For each vulnerability: CVE ID, CVSS v3.1 vector with justification, affected assets, description, proof of concept (if safe to demonstrate), business impact, and specific remediation steps with vendor references.',
      dataSources: ['findings', 'evidence', 'artifacts'],
    },
    {
      id: 'patch_status',
      title: 'Patch and Configuration Status',
      required: true,
      promptGuidance: 'Assess patch currency across all assets. Identify missing patches, end-of-life software, and configuration weaknesses.',
      dataSources: ['findings', 'asset_data'],
      subsections: [
        { id: 'missing_patches', title: 'Missing Patches', promptGuidance: 'Critical and high patches not applied with age.' },
        { id: 'eol_software', title: 'End-of-Life Software', promptGuidance: 'Software no longer receiving security updates.' },
        { id: 'misconfigurations', title: 'Configuration Weaknesses', promptGuidance: 'Default credentials, weak ciphers, unnecessary services.' },
      ],
    },
    RISK_MATRIX,
    REMEDIATION_ROADMAP,
    APPENDIX,
  ],
};

// ─── Tabletop Exercise Blueprint ────────────────────────────────────────────

const TABLETOP_BLUEPRINT: ReportBlueprint = {
  assessmentType: 'tabletop_exercise',
  displayName: 'Tabletop Exercise Report',
  description: 'Scenario-based discussion exercise evaluating incident response procedures, decision-making, and communication.',
  audience: 'Executive leadership, incident response team, legal, communications, HR',
  defaultFrameworks: ['NIST SP 800-61', 'NIST CSF', 'ISO 27035'],
  sections: [
    DOCUMENT_CONTROL,
    EXECUTIVE_SUMMARY,
    {
      id: 'exercise_overview',
      title: 'Exercise Overview',
      required: true,
      promptGuidance: 'Describe the exercise scenario, objectives, participants, and format (facilitated discussion, inject-based, etc.).',
      dataSources: ['exercise_data'],
      subsections: [
        { id: 'scenario', title: 'Scenario Description', promptGuidance: 'The incident scenario presented to participants.' },
        { id: 'objectives', title: 'Exercise Objectives', promptGuidance: 'What the exercise was designed to test.' },
        { id: 'participants', title: 'Participants', promptGuidance: 'Roles and departments represented.' },
        { id: 'format', title: 'Exercise Format', promptGuidance: 'How the exercise was conducted (duration, inject schedule, facilitation).' },
      ],
    },
    {
      id: 'scenario_walkthrough',
      title: 'Scenario Walkthrough',
      required: true,
      promptGuidance: 'Walk through each inject/phase of the exercise chronologically. Document what information was presented, what decisions were made, and how participants responded.',
      dataSources: ['exercise_injects', 'participant_responses'],
      subsections: [
        { id: 'inject_timeline', title: 'Inject Timeline', promptGuidance: 'Chronological list of scenario injects with participant responses.' },
        { id: 'decision_points', title: 'Key Decision Points', promptGuidance: 'Critical decisions made and their rationale.' },
        { id: 'communication_flow', title: 'Communication Flow', promptGuidance: 'How information flowed between teams and stakeholders.' },
      ],
    },
    {
      id: 'performance_assessment',
      title: 'Performance Assessment',
      required: true,
      promptGuidance: 'Evaluate participant performance against exercise objectives. Assess decision quality, response speed, communication effectiveness, and procedural adherence.',
      dataSources: ['exercise_scores', 'participant_responses'],
      subsections: [
        { id: 'objective_achievement', title: 'Objective Achievement', promptGuidance: 'How well each exercise objective was met.' },
        { id: 'strengths', title: 'Strengths Demonstrated', promptGuidance: 'What went well during the exercise.' },
        { id: 'gaps_identified', title: 'Gaps Identified', promptGuidance: 'Weaknesses in procedures, communication, or decision-making.' },
      ],
    },
    {
      id: 'ir_plan_assessment',
      title: 'Incident Response Plan Assessment',
      required: true,
      promptGuidance: 'Evaluate the organization\'s incident response plan based on exercise observations. Identify plan gaps, outdated procedures, and missing escalation paths.',
      dataSources: ['ir_plan_data', 'exercise_observations'],
      subsections: [
        { id: 'plan_gaps', title: 'Plan Gaps', promptGuidance: 'Missing procedures or scenarios not covered by the IR plan.' },
        { id: 'escalation_paths', title: 'Escalation Paths', promptGuidance: 'Whether escalation procedures were clear and followed.' },
        { id: 'external_comms', title: 'External Communications', promptGuidance: 'Readiness for regulatory notification, media, and customer communication.' },
      ],
    },
    {
      id: 'lessons_learned',
      title: 'Lessons Learned',
      required: true,
      promptGuidance: 'Summarize key lessons learned from the exercise. Include what worked, what didn\'t, and what surprised participants.',
      dataSources: ['exercise_observations', 'participant_feedback'],
    },
    REMEDIATION_ROADMAP,
    APPENDIX,
  ],
};

// ─── Hybrid Assessment Blueprint ────────────────────────────────────────────

const HYBRID_BLUEPRINT: ReportBlueprint = {
  assessmentType: 'hybrid',
  displayName: 'Hybrid Assessment Report',
  description: 'Combined assessment incorporating multiple testing methodologies (pentest + red team + phishing).',
  audience: 'CISO, security leadership, compliance officers, board of directors',
  defaultFrameworks: ['NIST SP 800-53', 'MITRE ATT&CK', 'FedRAMP', 'PCI-DSS'],
  sections: [
    DOCUMENT_CONTROL,
    EXECUTIVE_SUMMARY,
    SCOPE_AND_ROE,
    METHODOLOGY,
    {
      id: 'assessment_components',
      title: 'Assessment Components',
      required: true,
      promptGuidance: 'Describe each component of the hybrid assessment: which methodologies were used, their scope, and how they interconnect.',
      dataSources: ['engagement_data'],
    },
    {
      id: 'attack_surface',
      title: 'Attack Surface Overview',
      required: true,
      promptGuidance: 'Combined attack surface from all assessment components.',
      dataSources: ['assets', 'recon_data'],
    },
    FINDINGS_SUMMARY,
    {
      id: 'detailed_findings',
      title: 'Detailed Findings',
      required: true,
      promptGuidance: 'For each finding: source assessment component, CVSS scoring, evidence, business impact, and remediation. Group by assessment component then by severity.',
      dataSources: ['findings', 'evidence', 'artifacts'],
    },
    {
      id: 'cross_component_analysis',
      title: 'Cross-Component Analysis',
      required: true,
      promptGuidance: 'Analyze how findings from different assessment components relate to each other. Identify attack paths that span multiple components (e.g., phishing → credential access → lateral movement).',
      dataSources: ['findings', 'attack_chains'],
    },
    RISK_MATRIX,
    REMEDIATION_ROADMAP,
    APPENDIX,
  ],
};

// ─── Blueprint Registry ─────────────────────────────────────────────────────

export const REPORT_BLUEPRINTS: Record<AssessmentType, ReportBlueprint> = {
  penetration_test: PENTEST_BLUEPRINT,
  red_team: RED_TEAM_BLUEPRINT,
  purple_team: PURPLE_TEAM_BLUEPRINT,
  phishing_campaign: PHISHING_BLUEPRINT,
  vulnerability_assessment: VULN_ASSESSMENT_BLUEPRINT,
  tabletop_exercise: TABLETOP_BLUEPRINT,
  hybrid: HYBRID_BLUEPRINT,
};

/**
 * Get the report blueprint for a given assessment type.
 * Falls back to penetration_test if type is unknown.
 */
export function getReportBlueprint(assessmentType: string): ReportBlueprint {
  const normalized = assessmentType.toLowerCase().replace(/[\s-]/g, '_') as AssessmentType;
  // Map engagement types to assessment types
  const typeMap: Record<string, AssessmentType> = {
    red_team: 'red_team',
    phishing: 'phishing_campaign',
    pentest: 'penetration_test',
    purple_team: 'purple_team',
    tabletop: 'tabletop_exercise',
    penetration_test: 'penetration_test',
    vulnerability_assessment: 'vulnerability_assessment',
    phishing_campaign: 'phishing_campaign',
    tabletop_exercise: 'tabletop_exercise',
    hybrid: 'hybrid',
  };
  const mapped = typeMap[normalized] || 'penetration_test';
  return REPORT_BLUEPRINTS[mapped];
}

/**
 * Get the section titles for a given assessment type (for UI display).
 */
export function getReportSectionTitles(assessmentType: string): Array<{ id: string; title: string; required: boolean }> {
  const blueprint = getReportBlueprint(assessmentType);
  return blueprint.sections.map(s => ({ id: s.id, title: s.title, required: s.required }));
}

/**
 * Get the LLM prompt guidance for a specific section.
 */
export function getSectionPromptGuidance(assessmentType: string, sectionId: string): string | null {
  const blueprint = getReportBlueprint(assessmentType);
  const section = blueprint.sections.find(s => s.id === sectionId);
  return section?.promptGuidance ?? null;
}

/**
 * Build the full section outline for LLM narrative generation.
 * Returns a formatted string that can be injected into LLM prompts.
 */
export function buildSectionOutline(assessmentType: string): string {
  const blueprint = getReportBlueprint(assessmentType);
  let outline = `## Report Structure: ${blueprint.displayName}\n\n`;
  outline += `**Audience:** ${blueprint.audience}\n`;
  outline += `**Frameworks:** ${blueprint.defaultFrameworks.join(', ')}\n\n`;
  outline += `### Sections\n\n`;

  blueprint.sections.forEach((section, i) => {
    const num = i + 1;
    outline += `**${num}. ${section.title}** ${section.required ? '(Required)' : '(Optional)'}\n`;
    outline += `   ${section.promptGuidance}\n`;
    if (section.subsections) {
      section.subsections.forEach((sub, j) => {
        outline += `   ${num}.${j + 1} ${sub.title}: ${sub.promptGuidance}\n`;
      });
    }
    outline += '\n';
  });

  return outline;
}
