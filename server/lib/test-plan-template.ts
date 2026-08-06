/**
 * Red Team Exercise Test Plan & ROE Template
 * 
 * This template is auto-populated from DI scan results + engagement data.
 * Variables use {{handlebars}} syntax and are replaced at render time.
 * 
 * Data sources:
 * - Engagement record (customer info, scope, personnel)
 * - DI scan results (discovered assets, ports, services, technologies)
 * - Threat actor matching (based on customer sector/industry)
 */

export const TEST_PLAN_CSS = `
@page {
  size: letter;
  margin: 1in 0.85in;
  @top-center {
    content: element(page-header);
  }
  @bottom-center {
    content: element(page-footer);
  }
}
@page :first {
  margin: 0;
  @top-center { content: none; }
  @bottom-center { content: none; }
}

:root {
  --primary: {{primary_color}};
  --primary-dark: {{primary_dark}};
  --primary-light: {{primary_light}};
  --text-dark: #1a202c;
  --text-muted: #4a5568;
  --border: #e2e8f0;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Inter', 'Segoe UI', sans-serif; font-size: 10pt; line-height: 1.6; color: var(--text-dark); }

.page-header {
  position: running(page-header);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding-bottom: 8px;
  border-bottom: 2.5px solid var(--primary);
  font-size: 8pt;
  font-weight: 600;
  color: var(--primary-dark);
  letter-spacing: 0.5px;
}
.page-header img { height: 18px; }

.page-footer {
  position: running(page-footer);
  text-align: center;
  font-size: 7.5pt;
  color: var(--text-muted);
  border-top: 1px solid var(--border);
  padding-top: 8px;
}
.page-footer::after { content: "Page " counter(page) " of " counter(pages); }

.cover-page {
  page: cover;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100vh;
  background: linear-gradient(135deg, var(--primary-dark) 0%, #0f1a2e 100%);
  color: #ffffff;
  text-align: center;
  padding: 40px;
}
.cover-logo { margin-bottom: 44px; }
.cover-logo img { height: 50px; }
.cover-title { font-size: 28pt; font-weight: 700; line-height: 1.2; margin-bottom: 16px; }
.cover-subtitle { font-size: 12pt; opacity: 0.85; margin-bottom: 60px; letter-spacing: 0.5px; }
.cover-meta-grid { display: flex; gap: 48px; width: 680px; max-width: 100%; justify-content: center; text-align: left; }
.cover-meta-block { flex: 1 1 0; min-width: 0; }
.cover-meta-block h4 { font-size: 8pt; text-transform: uppercase; letter-spacing: 1.5px; opacity: 0.6; margin-bottom: 8px; }
.cover-meta-block p { font-size: 10pt; line-height: 1.5; }
.cover-badge { margin-top: 50px; border: 1px solid rgba(255,255,255,0.3); padding: 8px 24px; font-size: 8pt; letter-spacing: 2px; text-transform: uppercase; }

h1 { font-size: 20pt; color: var(--primary-dark); margin-top: 30px; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 3px solid var(--primary); }
h2 { font-size: 14pt; color: var(--primary-dark); margin-top: 24px; margin-bottom: 10px; }
h3 { font-size: 11pt; color: var(--primary-dark); margin-top: 18px; margin-bottom: 8px; }
p { margin-bottom: 10px; text-align: justify; }
ul, ol { margin-left: 20px; margin-bottom: 10px; }
li { margin-bottom: 4px; }
strong { color: var(--primary-dark); }

table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 9pt; }
thead th { background: var(--primary-dark); color: #ffffff; padding: 10px 12px; text-align: left; font-weight: 600; font-size: 8pt; text-transform: uppercase; letter-spacing: 0.5px; }
tbody td { padding: 9px 12px; border-bottom: 1px solid var(--border); }
tbody tr:nth-child(even) { background: #f7fafc; }

.callout { background: #f0f7ff; border-left: 4px solid var(--primary); padding: 14px 18px; margin: 14px 0; border-radius: 0 4px 4px 0; }
.callout strong { display: block; margin-bottom: 4px; }

.page-break { page-break-before: always; }

.toc { margin: 20px 0; }
.toc-item { display: flex; align-items: baseline; padding: 8px 0; border-bottom: 1px dotted var(--border); }
.toc-item span:first-child { font-weight: 500; }

.signature-block { margin-top: 30px; display: grid; grid-template-columns: 1fr 1fr; gap: 40px; }
.sig-box { border-top: 2px solid var(--primary-dark); padding-top: 8px; }
.sig-box .sig-label { font-size: 8pt; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
.sig-box .sig-name { font-weight: 600; margin-top: 4px; }
`;

export const TEST_PLAN_HEADER_HTML = `
<div class="page-header">
  <img src="{{client_logo_url}}" alt="{{client_name}}">
  <span>{{client_name}} RED TEAM EXERCISE TEST PLAN & ROE</span>
</div>
`;

export const TEST_PLAN_FOOTER_HTML = `
<div class="page-footer">
  CONFIDENTIAL — {{client_name}} Red Team Exercise — {{assessor_company}}, LLC &nbsp;|&nbsp;
</div>
`;

export const TEST_PLAN_TEMPLATE_CONTENT = `
<!-- COVER PAGE -->
<div class="cover-page">
  <div class="cover-logo">
    <img src="{{client_logo_url}}" alt="{{client_name}}" style="height: 50px; filter: brightness(0) invert(1);">
  </div>
  <div class="cover-title">Red Team Exercise<br>Test Plan & Rules of Engagement</div>
  <div class="cover-subtitle">{{client_name}} — {{platform_name}}<br>{{compliance_framework}}</div>
  <div class="cover-meta-grid">
    <div class="cover-meta-block">
      <h4>Prepared For</h4>
      <p>{{client_poc_name}}<br>{{client_poc_title}}<br>{{client_name}}</p>
    </div>
    <div class="cover-meta-block">
      <h4>Prepared By</h4>
      <p>{{assessor_name}}<br>{{assessor_title}}<br>{{assessor_company}}</p>
    </div>
  </div>
  <div class="cover-badge">CONFIDENTIAL</div>
</div>

<!-- TABLE OF CONTENTS -->
<div class="page-break"></div>
<h1 style="border-bottom: none; margin-top: 40px; font-size: 22pt;">Table of Contents</h1>
<div class="toc">
  <div class="toc-item"><span>1. Purpose</span></div>
  <div class="toc-item"><span>2. Scope of Work</span></div>
  <div class="toc-item"><span>3. Logistics</span></div>
  <div class="toc-item"><span>&nbsp;&nbsp;&nbsp;&nbsp;3.1 Personnel</span></div>
  <div class="toc-item"><span>&nbsp;&nbsp;&nbsp;&nbsp;3.2 Project Schedule</span></div>
  <div class="toc-item"><span>&nbsp;&nbsp;&nbsp;&nbsp;3.3 Test Site</span></div>
  <div class="toc-item"><span>&nbsp;&nbsp;&nbsp;&nbsp;3.4 Test Equipment</span></div>
  <div class="toc-item"><span>4. Communications Strategy</span></div>
  <div class="toc-item"><span>&nbsp;&nbsp;&nbsp;&nbsp;4.1 General Communication</span></div>
  <div class="toc-item"><span>&nbsp;&nbsp;&nbsp;&nbsp;4.2 Incident Handling and Response</span></div>
  <div class="toc-item"><span>5. Methodology</span></div>
  <div class="toc-item"><span>6. APT Group Simulation</span></div>
  <div class="toc-item"><span>7. Threat Emulation Scenarios</span></div>
  <div class="toc-item"><span>&nbsp;&nbsp;&nbsp;&nbsp;7.1 External Testing</span></div>
  <div class="toc-item"><span>&nbsp;&nbsp;&nbsp;&nbsp;7.2 Internal Testing</span></div>
  <div class="toc-item"><span>8. Findings and Recommendations</span></div>
  <div class="toc-item"><span>9. Conclusion</span></div>
  <div class="toc-item"><span>10. Signatures</span></div>
</div>

<!-- SECTION 1: PURPOSE -->
<div class="page-break"></div>
<h1>1. Purpose</h1>
<p>The purpose of this Red Team Exercise is to assess the security posture of {{client_name}}'s {{compliance_framework}}-authorized cloud service offering (CSO) and its supporting corporate infrastructure. This test adheres to FedRAMP Penetration Testing Requirements as outlined in the FedRAMP Security Assessment Framework (SAF) and satisfies the requirements of NIST SP 800-53 Revision 5 control CA-8(2) for Red Team Exercises.</p>

<p>The exercise will emulate Advanced Persistent Threats (APT) tactics, techniques, and procedures to simulate realistic attack scenarios that target government data and systems hosted within {{client_name}}'s {{cloud_environment}} environment.</p>

<p>FedRAMP requires that all CSPs or their selected Third-Party Assessment Organizations (3PAOs) perform comprehensive Penetration Testing and Red Team Exercises to:</p>
<ul>
  <li>Identify weaknesses and vulnerabilities in FedRAMP-authorized systems.</li>
  <li>Validate an organization's security controls for their ability to defend against real-world adversarial behaviors.</li>
  <li>Test the organization's detection, incident response, and mitigation capabilities.</li>
</ul>

<p>This exercise leverages the MITRE ATT&CK Framework to align with real-world adversarial techniques and ensures that simulated APT scenarios align with known methods targeting {{target_sector}} platforms, defense industrial base (DIB) contractors, and cloud infrastructure.</p>

<p>This document serves as both the Red Team Exercise Test Plan and the Rules of Engagement (ROE). {{assessor_name}}, as an Independent Assessor, is required to develop the ROE as part of the Test Plan, based on the parameters and system information provided by {{client_name}}.</p>

<div class="callout">
  <strong>Initial Access Model:</strong> {{initial_access_description}}
</div>

<!-- SECTION 2: SCOPE -->
<div class="page-break"></div>
<h1>2. Scope of Work</h1>
<p>The scope of this Red Team Exercise encompasses the following {{client_name}} systems, networks, and applications as defined in the approved scoping document:</p>

<h2>In-Scope Assets</h2>
{{in_scope_assets_table}}

<h2>Discovered Services (DI Scan Results)</h2>
{{discovered_services_table}}

<h2>Out-of-Scope / Exclusions</h2>
{{out_of_scope_list}}

<h2>Compliance Alignment</h2>
<table>
  <thead><tr><th>Framework</th><th>Control</th><th>Requirement</th></tr></thead>
  <tbody>
    <tr><td>FedRAMP</td><td>CA-8(2)</td><td>Red Team Exercises</td></tr>
    <tr><td>NIST 800-53 Rev 5</td><td>CA-8</td><td>Penetration Testing</td></tr>
    <tr><td>NIST 800-53 Rev 5</td><td>RA-5</td><td>Vulnerability Monitoring and Scanning</td></tr>
    <tr><td>{{additional_framework}}</td><td>{{additional_control}}</td><td>{{additional_requirement}}</td></tr>
  </tbody>
</table>

<!-- SECTION 3: LOGISTICS -->
<div class="page-break"></div>
<h1>3. Logistics</h1>

<h2>3.1 Personnel</h2>
<p>Identifies by name all personnel assigned to the security testing task, as well as key personnel from the organization being tested.</p>
{{personnel_table}}

<h2>3.2 Project Schedule</h2>
<p>This proposed schedule can be adjusted forward or backward at the client's request. Once dates are mutually agreed upon, we will prepare a final plan. The Red Team Tester will be able to extend testing to three (3) weeks at no additional cost, if required to meet client needs.</p>
{{schedule_table}}

<h2>3.3 Test Site</h2>
<p>{{test_site_description}}</p>

<h2>3.4 Test Equipment</h2>
<p>Any testing will be performed per the terms and conditions and will be designed to minimize risk exposure that can occur during security testing. All scans and penetration test activities performed by {{assessor_name}} will originate from the following IP address(es):</p>
{{test_equipment_table}}

<!-- SECTION 4: COMMUNICATIONS -->
<div class="page-break"></div>
<h1>4. Communications Strategy</h1>

<h2>4.1 General Communication</h2>
<p>Email and reports on all security testing will be encrypted and uploaded into {{client_name}}'s secure file share or sent encrypted within a compressed and password-protected file.</p>
<p>Red Team testing results will be sent and disclosed to the individuals at {{client_name}} within 14 days after security testing has been completed.</p>
{{communications_recipients_table}}

<h2>4.2 Incident Handling and Response</h2>
<p>If an incident occurs on the network while testing is in progress, the Red Team will immediately halt all testing activities and notify the {{client_name}} Security TPM and ISSO. Criteria for halting information security testing include:</p>
<ul>
  <li>Discovery of an active, non-exercise compromise of the environment</li>
  <li>Unintended disruption to production services or tenant data availability</li>
  <li>Request from {{client_name}} personnel to cease testing</li>
  <li>Discovery of {{sensitive_data_type}} exposure that requires immediate remediation</li>
</ul>
<p>The Red Team will coordinate with {{client_name}}'s incident response team and provide all relevant artifacts to support triage. A process for reinstating the test team and resuming testing will be agreed upon before the engagement begins.</p>

<!-- SECTION 5: METHODOLOGY -->
<div class="page-break"></div>
<h1>5. Methodology</h1>
<p>The Red Team exercise methodology aligns with the MITRE ATT&CK Framework, ensuring all phases of an attack lifecycle are emulated to reflect realistic adversary behavior.</p>

<h2>MITRE ATT&CK Framework</h2>
<p>The framework is used to map adversary behaviors to their technical objectives across the following phases:</p>
<ol>
  <li><strong>Reconnaissance (TA0043):</strong> Identify vulnerabilities and weak points in both the external-facing and internal environments.</li>
  <li><strong>Initial Access (TA0001):</strong> {{initial_access_method}}</li>
  <li><strong>Command and Control (TA0011):</strong> Use MITRE Caldera to establish encrypted communication channels for maintaining access.</li>
  <li><strong>Lateral Movement (TA0008):</strong> Move across the network using stolen credentials, {{lateral_movement_methods}}.</li>
  <li><strong>Credential Access (TA0006):</strong> Extract credentials from {{credential_sources}}.</li>
  <li><strong>Persistence (TA0003):</strong> Deploy {{persistence_mechanisms}}.</li>
  <li><strong>Privilege Escalation (TA0004):</strong> Exploit misconfigurations in {{privilege_escalation_targets}}.</li>
  <li><strong>Exfiltration (TA0010):</strong> Transfer sensitive files and data to a controlled external server over encrypted channels.</li>
</ol>

<h2>Testing Approach</h2>
<table>
  <thead><tr><th>Phase</th><th>Activity</th><th>Duration</th><th>Tools</th></tr></thead>
  <tbody>
    <tr><td>Phase I</td><td>Reconnaissance & Enumeration</td><td>2 Weeks</td><td>Naabu, RustScan, Nuclei, Subfinder, httpx</td></tr>
    <tr><td>Phase II</td><td>Active Testing ({{initial_access_model}})</td><td>2 Weeks</td><td>MITRE Caldera, Cobalt Strike, custom tooling</td></tr>
    <tr><td>Phase III</td><td>Post-Exploitation & Reporting</td><td>1 Week</td><td>BloodHound, Impacket, custom scripts</td></tr>
  </tbody>
</table>

<!-- SECTION 6: APT SIMULATION -->
<div class="page-break"></div>
<h1>6. APT Group Simulation</h1>
<p>The following threat actors have been selected based on their known targeting of {{target_sector}} organizations, cloud infrastructure, and government systems. Their tactics, techniques, and procedures (TTPs) will be emulated during this exercise.</p>

{{apt_groups_table}}

<!-- SECTION 7: THREAT EMULATION -->
<div class="page-break"></div>
<h1>7. Threat Emulation Scenarios</h1>

<h2>7.1 External Testing</h2>
<p>External testing simulates an adversary with no prior internal access attempting to compromise {{client_name}}'s perimeter defenses and externally-facing services.</p>

{{external_testing_scenarios}}

<h2>7.2 Internal Testing</h2>
<p>Internal testing begins with the {{initial_access_model}} model. The Red Team will use provided credentials to simulate post-compromise activity within the {{client_name}} environment.</p>

{{internal_testing_scenarios}}

<!-- SECTION 8: FINDINGS -->
<div class="page-break"></div>
<h1>8. Findings and Recommendations</h1>
<p><em>This section will be populated upon completion of the Red Team Exercise. Findings will be categorized by severity (Critical, High, Medium, Low, Informational) and mapped to MITRE ATT&CK techniques and relevant NIST SP 800-53 controls.</em></p>

<table>
  <thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>ATT&CK Technique</th><th>Affected Asset</th><th>Recommendation</th></tr></thead>
  <tbody>
    <tr><td colspan="6" style="text-align: center; font-style: italic; padding: 20px;">To be completed after exercise execution</td></tr>
  </tbody>
</table>

<!-- SECTION 9: CONCLUSION -->
<div class="page-break"></div>
<h1>9. Conclusion</h1>
<p>This Red Team Exercise Test Plan and Rules of Engagement document establishes the framework for conducting a comprehensive security assessment of {{client_name}}'s {{compliance_framework}} environment. The exercise will leverage real-world APT tactics aligned with the MITRE ATT&CK Framework to evaluate the organization's defensive capabilities.</p>

<p>Upon completion, a detailed findings report will be provided with prioritized remediation recommendations mapped to applicable compliance controls. The {{assessor_company}} team is committed to conducting this exercise professionally, ethically, and within the boundaries established in this document.</p>

<!-- SECTION 10: SIGNATURES -->
<div class="page-break"></div>
<h1>10. Signatures</h1>
<p>By signing below, both parties acknowledge and agree to the terms, scope, and rules of engagement defined in this document.</p>

<div class="signature-block">
  <div class="sig-box">
    <div class="sig-label">Client Representative</div>
    <div class="sig-name">{{client_poc_name}}</div>
    <p style="font-size: 8pt; color: var(--text-muted);">{{client_poc_title}}, {{client_name}}</p>
    <p style="margin-top: 30px; font-size: 8pt;">Signature: ___________________________</p>
    <p style="font-size: 8pt;">Date: ___________________________</p>
  </div>
  <div class="sig-box">
    <div class="sig-label">Red Team Lead</div>
    <div class="sig-name">{{assessor_name}}</div>
    <p style="font-size: 8pt; color: var(--text-muted);">{{assessor_title}}, {{assessor_company}}</p>
    <p style="margin-top: 30px; font-size: 8pt;">Signature: ___________________________</p>
    <p style="font-size: 8pt;">Date: ___________________________</p>
  </div>
</div>
`;

/**
 * Variables available for template population:
 * 
 * From Engagement Record:
 * - client_name, client_poc_name, client_poc_title
 * - platform_name, compliance_framework, cloud_environment
 * - target_sector, sensitive_data_type
 * - assessor_name, assessor_title, assessor_company
 * 
 * From DI Scan Results:
 * - in_scope_assets_table (HTML table of discovered assets)
 * - discovered_services_table (HTML table of ports/services)
 * 
 * From Threat Actor Matching:
 * - apt_groups_table (HTML table of matched APT groups + TTPs)
 * - external_testing_scenarios (HTML steps for external testing)
 * - internal_testing_scenarios (HTML steps for internal testing)
 * 
 * Configurable:
 * - primary_color, primary_dark, primary_light
 * - client_logo_url
 * - initial_access_model (e.g., "Assumed Breach")
 * - initial_access_description
 * - initial_access_method
 * - lateral_movement_methods
 * - credential_sources
 * - persistence_mechanisms
 * - privilege_escalation_targets
 * - out_of_scope_list
 * - personnel_table, schedule_table, test_equipment_table
 * - communications_recipients_table
 * - test_site_description
 * - additional_framework, additional_control, additional_requirement
 */
export const TEST_PLAN_TEMPLATE_VARIABLES = [
  // Client info
  'client_name', 'client_poc_name', 'client_poc_title', 'client_logo_url',
  'platform_name', 'compliance_framework', 'cloud_environment', 'target_sector',
  'sensitive_data_type',
  // Assessor info
  'assessor_name', 'assessor_title', 'assessor_company',
  // Colors
  'primary_color', 'primary_dark', 'primary_light',
  // Access model
  'initial_access_model', 'initial_access_description', 'initial_access_method',
  // Methodology details
  'lateral_movement_methods', 'credential_sources', 'persistence_mechanisms',
  'privilege_escalation_targets',
  // Tables (auto-generated from scan data)
  'in_scope_assets_table', 'discovered_services_table', 'out_of_scope_list',
  'personnel_table', 'schedule_table', 'test_equipment_table',
  'communications_recipients_table', 'test_site_description',
  'apt_groups_table', 'external_testing_scenarios', 'internal_testing_scenarios',
  // Compliance
  'additional_framework', 'additional_control', 'additional_requirement',
] as const;
